# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Docker Virtual Wi-Fi wlan0 TAP/veth + L2 Switch & D-Bus socket bridge.

Coordinates container-level virtual Wi-Fi plumbing without requiring host
kernel modules (`mac80211_hwsim`):
  1. Generates the `fi.w1.wpa_supplicant1.conf` D-Bus system bus security policy
     so the host-side `WpaSupplicantDbusService` can own `fi.w1.wpa_supplicant1`
     inside each container's isolated `/run/dbus/system_bus_socket`.
  2. Exposes Unix domain socket proxies (`control.sock`, `data.sock`) mounted
     at `/dev/virtual_wifi` inside each container.
  3. Provisions a real `wlan0` veth/TAP pair inside the container and spawns
     `vwifi_l2_agent.py` to bridge `wlan0` frames to
     `/dev/virtual_wifi/data.sock`.
"""

import json
import logging
import os
import select
import socket
import struct
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple, Union

from cirque.common.docker_transport import (
    UnixToTcpProxy,
    prepare_container_dbus_dir,
    write_executable_script,
)
from cirque.virtual_wifi.server import VirtualWiFiServer
from cirque.virtual_wifi.wpa2_supplicant_sm import Wpa2SupplicantStateMachine

logger = logging.getLogger('VirtualWiFiDockerBridge')


def _recv_exact(sock: socket.socket, num_bytes: int) -> Optional[bytes]:
  """Reads exactly num_bytes from sock, returning None on EOF or timeout."""
  buf = bytearray()
  while len(buf) < num_bytes:
    try:
      chunk = sock.recv(num_bytes - len(buf))
    except (socket.timeout, OSError):
      return None
    if not chunk:
      return None
    buf.extend(chunk)
  return bytes(buf)


def _ones_complement_checksum(data: bytes) -> int:
  """Computes RFC 1071 one's complement Internet checksum."""
  if len(data) % 2 == 1:
    data += b'\x00'
  word_count = len(data) // 2
  total = sum(struct.unpack(f'!{word_count}H', data))
  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)
  return (~total) & 0xFFFF


def _write_pcap_frames(
    pcap_path: str, frames: List[Tuple[float, bytes]]
) -> None:
  """Writes a list of (timestamp, raw_ethernet_bytes) tuples to a PCAP file.

  NOTE: This is a self-recorded host-side TAP capturing EAPOL and L2 frames
  processed by the virtual Wi-Fi bridge, rather than an in-kernel network
  interface packet capture.
  """
  from cirque.capabilities.pcapcapability import DLT_EN10MB, PcapWriter

  with PcapWriter(pcap_path, dlt=DLT_EN10MB) as writer:
    for ts, pkt in frames:
      writer.write_frame(pkt, ts=ts)


class VirtualDhcpServer:
  """RFC 2131 userspace DHCP server connected to VirtualWiFiServer data_port.

  Acts as an AP-side DHCP service listening on virtual L2 broadcast traffic:
    - Listens for DHCPDISCOVER / DHCPREQUEST frames (UDP dst port 67).
    - Responds with DHCPOFFER / DHCPACK frames (UDP dst port 68).
    - Allocates dynamic leases in 10.0.1.10 - 10.0.1.50 range.
    - Sets Server ID (10.0.1.1), Router (10.0.1.1), Subnet Mask (255.255.255.0).
    - Does NOT emit Option 6 (DNS); the virtual AP has no DNS resolver.
  """

  def __init__(
      self,
      server_host: str,
      data_port: int,
      server: Optional[VirtualWiFiServer] = None,
      server_ip: str = '10.0.1.1',
      server_mac: str = '02:00:00:00:01:01',
      start_ip: int = 10,
      end_ip: int = 50,
  ):
    self.server_host = server_host
    self.data_port = data_port
    self.server = server
    self.server_ip = server_ip
    self.server_mac_bytes = bytes.fromhex(server_mac.replace(':', ''))
    self.server_ip_bytes = socket.inet_aton(server_ip)
    self.start_ip = start_ip
    self.end_ip = end_ip
    self.next_ip = start_ip
    self.leases: Dict[str, str] = {}  # mac_hex -> ip_str
    self.offers: Dict[str, str] = {}  # mac_hex -> ip_str
    self._sock: Optional[socket.socket] = None
    self._thread: Optional[threading.Thread] = None
    self._running = False
    self._lock = threading.RLock()

  def start(self) -> None:
    with self._lock:
      if self._running:
        return
      # SIMULATION-DISCLOSURE: The dhcp_server is a privileged infrastructure
      # pseudo-station running on the distribution system (DS) side of the AP.
      # It is pre-marked as completed to allow DHCP relaying over the virtual
      # switch before client stations authenticate. Regular wireless client
      # stations cannot bypass the WPA2 4-way handshake, and any unauthenticated
      # data frame from client station IDs is dropped by the L2 port security gate.
      if self.server is not None:
        self.server.register_station('dhcp_server', is_ap_bridge=True)
      self._running = True
      self._thread = threading.Thread(
          target=self._run_loop, name='vwifi-dhcp-server', daemon=True
      )
      self._thread.start()

  def stop(self) -> None:
    with self._lock:
      self._running = False
      if self._sock is not None:
        try:
          self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
          pass
        try:
          self._sock.close()
        except OSError:
          pass
        self._sock = None

  def _recv_exact(self, sock: socket.socket, num_bytes: int) -> Optional[bytes]:
    return _recv_exact(sock, num_bytes)

  @staticmethod
  def lease_key(mac: str) -> str:
    """Canonical lease/offer key: lower-case, colon-separated MAC."""
    hex_digits = mac.replace(':', '').replace('-', '').lower()
    return ':'.join(hex_digits[i : i + 2] for i in range(0, len(hex_digits), 2))

  def reserve_lease(self, mac: str, ip: str) -> None:
    """Reserves a static IP for mac (may lie outside the dynamic pool)."""
    with self._lock:
      self.leases[self.lease_key(mac)] = ip

  def _allocate_ip(self, mac_hex: str) -> str:
    if mac_hex in self.leases:
      return self.leases[mac_hex]
    if mac_hex in self.offers:
      return self.offers[mac_hex]
    assigned = f'10.0.1.{self.next_ip}'
    self.next_ip += 1
    if self.next_ip > self.end_ip:
      self.next_ip = self.start_ip
    self.offers[mac_hex] = assigned
    return assigned

  def _connect_and_handshake(self) -> Optional[socket.socket]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect((self.server_host, self.data_port))
    with self._lock:
      if not self._running:
        sock.close()
        return None
      self._sock = sock
    sid = b'dhcp_server'
    sock.sendall(struct.pack('!H', len(sid)) + sid)
    if self.server is not None:
      st = self.server.get_station('dhcp_server')
      if st is not None:
        st.state = 'completed'
    return sock

  def _run_loop(self) -> None:
    while self._running:
      try:
        sock = self._connect_and_handshake()
        if sock is None:
          return
        while self._running:
          hdr = self._recv_exact(sock, 2)
          if not hdr:
            break
          flen = struct.unpack('!H', hdr)[0]
          frame = self._recv_exact(sock, flen)
          if not frame:
            break
          self._handle_frame(frame)
      except Exception as exc:
        if not self._running:
          break
        logger.warning('VirtualDhcpServer loop encountered error: %s', exc)
        time.sleep(0.5)

  def _handle_frame(self, frame: bytes) -> None:
    if len(frame) < 14 + 20 + 8 + 240:
      return
    # Check EtherType == IPv4 (0x0800)
    ethertype = struct.unpack('!H', frame[12:14])[0]
    if ethertype != 0x0800:
      return
    # Check IP protocol == UDP (17)
    if frame[23] != 17:
      return
    ihl = (frame[14] & 0x0F) * 4
    if len(frame) < 14 + ihl + 8 + 240:
      return
    src_port, dst_port = struct.unpack('!HH', frame[14 + ihl : 14 + ihl + 4])
    if dst_port != 67:
      return

    dhcp_payload = frame[14 + ihl + 8 :]
    op, htype, hlen, hops = struct.unpack('!BBBB', dhcp_payload[:4])
    if op != 1:  # BOOTREQUEST
      return
    xid = dhcp_payload[4:8]
    chaddr = dhcp_payload[28 : 28 + hlen]
    chaddr_hex = ':'.join(f'{b:02x}' for b in chaddr)

    # Magic cookie: 99, 130, 83, 99 (0x63825363)
    if len(dhcp_payload) < 240 or dhcp_payload[236:240] != b'\x63\x82\x53\x63':
      return

    # Parse options
    options = dhcp_payload[240:]
    msg_type = None
    requested_ip = None
    server_id = None
    idx = 0
    while idx < len(options):
      opt = options[idx]
      if opt == 255:  # End
        break
      if opt == 0:  # Pad
        idx += 1
        continue
      if idx + 1 >= len(options):
        break
      opt_len = options[idx + 1]
      val = options[idx + 2 : idx + 2 + opt_len]
      if opt == 53 and opt_len == 1:
        msg_type = val[0]
      elif opt == 50 and opt_len == 4:
        requested_ip = socket.inet_ntoa(val)
      elif opt == 54 and opt_len == 4:
        server_id = socket.inet_ntoa(val)
      idx += 2 + opt_len

    if msg_type == 1:  # DHCPDISCOVER
      with self._lock:
        offer_ip = self._allocate_ip(chaddr_hex)
      self._send_reply(
          client_mac=chaddr,
          xid=xid,
          assigned_ip=offer_ip,
          msg_type=2,  # DHCPOFFER
      )
    elif msg_type == 3:  # DHCPREQUEST per RFC 2131 Section 4.3.2
      # 1. Silently drop if server-id is specified and does not match our server IP
      if server_id is not None and server_id != self.server_ip:
        return

      # 2. Determine target IP: requested_ip (opt 50), or ciaddr if renewing
      ciaddr_bytes = dhcp_payload[12:16]
      ciaddr_str = (
          socket.inet_ntoa(ciaddr_bytes)
          if ciaddr_bytes != b'\x00\x00\x00\x00'
          else None
      )
      target_ip = requested_ip or ciaddr_str or self.offers.get(chaddr_hex)

      def _is_in_pool(ip_str: Optional[str]) -> bool:
        if not ip_str or not ip_str.startswith('10.0.1.'):
          return False
        try:
          octets = [int(p) for p in ip_str.split('.')]
          return (
              len(octets) == 4
              and octets[:3] == [10, 0, 1]
              and self.start_ip <= octets[3] <= self.end_ip
          )
        except ValueError:
          return False

      send_nak = False
      with self._lock:
        current_lease = self.leases.get(chaddr_hex)
        # Requested IP must be in the dynamic pool or be this client's own
        # (possibly static, out-of-pool) reservation.
        if not _is_in_pool(target_ip) and target_ip != current_lease:
          send_nak = True
        else:
          # Check if requested IP is already leased to another MAC
          existing_chaddr = next(
              (m for m, ip in self.leases.items() if ip == target_ip), None
          )
          if existing_chaddr is not None and existing_chaddr != chaddr_hex:
            send_nak = True
          else:
            # Check if client has no prior offer or existing lease for this IP
            offered = self.offers.get(chaddr_hex)
            if target_ip != offered and target_ip != current_lease:
              send_nak = True
            else:
              # Valid request: commit lease
              self.leases[chaddr_hex] = target_ip
              self.offers.pop(chaddr_hex, None)

      if send_nak:
        self._send_reply(
            client_mac=chaddr,
            xid=xid,
            assigned_ip='0.0.0.0',
            msg_type=6,  # DHCPNAK
        )
        return

      self._send_reply(
          client_mac=chaddr,
          xid=xid,
          assigned_ip=target_ip,
          msg_type=5,  # DHCPACK
      )

  def _build_reply(
      self,
      client_mac: bytes,
      xid: Union[bytes, int],
      assigned_ip: str,
      msg_type: int,
  ) -> bytes:
    # Build DHCP payload (BOOTREPLY = 2)
    yiaddr = socket.inet_aton(assigned_ip)
    dhcp_fixed = bytearray(240)
    dhcp_fixed[0] = 2  # BOOTREPLY
    dhcp_fixed[1] = 1  # Ethernet
    dhcp_fixed[2] = 6  # 6-byte MAC
    dhcp_fixed[3] = 0  # Hops
    if isinstance(xid, int):
      xid_bytes = struct.pack('!I', xid)
    else:
      xid_bytes = bytes(xid)
    dhcp_fixed[4:8] = xid_bytes
    dhcp_fixed[8:10] = b'\x00\x00'  # Secs
    dhcp_fixed[10:12] = b'\x80\x00'  # Broadcast flag
    dhcp_fixed[12:16] = b'\x00\x00\x00\x00'  # ciaddr
    dhcp_fixed[16:20] = yiaddr  # yiaddr
    dhcp_fixed[20:24] = self.server_ip_bytes  # siaddr
    dhcp_fixed[24:28] = b'\x00\x00\x00\x00'  # giaddr
    dhcp_fixed[28 : 28 + len(client_mac)] = client_mac
    dhcp_fixed[236:240] = b'\x63\x82\x53\x63'  # Magic cookie

    # Options per RFC 2131
    options = bytearray()
    options.extend(struct.pack('!BBB', 53, 1, msg_type))
    options.extend(b'\x36\x04' + self.server_ip_bytes)
    if msg_type != 6:  # DHCPNAK does not include lease or config parameters
      options.extend(struct.pack('!BBI', 51, 4, 86400))
      options.extend(b'\x01\x04\xff\xff\xff\x00')
      options.extend(b'\x03\x04' + self.server_ip_bytes)
      # DNS server (option 6): Android guests need a resolver from DHCP
      # before they bring the Wi-Fi network up.
      options.extend(b'\x06\x04' + self.server_ip_bytes)
    options.append(255)

    dhcp_msg = bytes(dhcp_fixed) + bytes(options)
    if len(dhcp_msg) < 300:
      dhcp_msg += b'\x00' * (300 - len(dhcp_msg))

    udp_len = 8 + len(dhcp_msg)
    udp_hdr = struct.pack('!HHHH', 67, 68, udp_len, 0)

    ip_len = 20 + udp_len
    ip_hdr_no_csum = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,
        0,
        ip_len,
        0,
        0,
        64,
        17,
        0,
        self.server_ip_bytes,
        socket.inet_aton('255.255.255.255'),
    )
    ip_csum = _ones_complement_checksum(ip_hdr_no_csum)
    ip_hdr = (
        ip_hdr_no_csum[:10] + struct.pack('!H', ip_csum) + ip_hdr_no_csum[12:]
    )

    pseudo = (
        self.server_ip_bytes
        + socket.inet_aton('255.255.255.255')
        + struct.pack('!BBH', 0, 17, udp_len)
    )
    udp_csum = _ones_complement_checksum(pseudo + udp_hdr + dhcp_msg)
    if udp_csum == 0:
      udp_csum = 0xFFFF
    udp_hdr_final = struct.pack('!HHHH', 67, 68, udp_len, udp_csum)

    # Deliver unicast Ethernet frame directly to client_mac (RFC 2131 Sec 4.1)
    eth_hdr = (
        client_mac
        + self.server_mac_bytes
        + struct.pack('!H', 0x0800)
    )
    return eth_hdr + ip_hdr + udp_hdr_final + dhcp_msg

  def _send_reply(
      self,
      client_mac: bytes,
      xid: bytes,
      assigned_ip: str,
      msg_type: int,
  ) -> None:
    full_frame = self._build_reply(client_mac, xid, assigned_ip, msg_type)
    with self._lock:
      if self._sock is not None and self._running:
        pkt = struct.pack('!H', len(full_frame)) + full_frame
        try:
          self._sock.sendall(pkt)
        except OSError:
          pass


class VirtualRaServer:
  """RFC 4861 userspace Router Advertisement server on VirtualWiFiServer data_port.

  Acts as an AP-side IPv6 router advertisement service listening on virtual L2 traffic:
    - Listens on data_port for Router Solicitations (RS, ICMPv6 type 133).
    - Periodically transmits unsolicited Router Advertisements (RA, ICMPv6 type 134)
      with Prefix Information Option (PIO) for SLAAC autoconfiguration.
    - Uses prefix 'fd11:22::/64' with L=1 (on-link) and A=1 (autonomous SLAAC).
    - Sets Hop Limit = 255 (RFC 4861 requirement for valid RAs).
  """

  def __init__(
      self,
      server_host: str,
      data_port: int,
      server: Optional[VirtualWiFiServer] = None,
      ap_mac: str = '02:00:00:00:01:01',
      prefix: str = 'fd11:22::',
      prefix_len: int = 64,
      interval: float = 1.5,
  ):
    self.server_host = server_host
    self.data_port = data_port
    self.server = server
    self.ap_mac = ap_mac
    self.ap_mac_bytes = bytes.fromhex(ap_mac.replace(':', ''))
    self.prefix = prefix
    self.prefix_len = prefix_len
    self.interval = interval
    self._sock: Optional[socket.socket] = None
    self._rx_thread: Optional[threading.Thread] = None
    self._tx_thread: Optional[threading.Thread] = None
    self._running = False
    self._lock = threading.RLock()
    self._send_lock = threading.Lock()
    self.advertised_count = 0
    self.solicitation_count = 0

  def start(self) -> None:
    with self._lock:
      if self._running:
        return
      # SIMULATION-DISCLOSURE: ra_server is an AP-side infrastructure pseudo-station
      # running on the distribution system (DS). It is pre-marked as completed to allow
      # IPv6 router advertisements across the virtual switch.
      if self.server is not None:
        self.server.register_station('ra_server', is_ap_bridge=True)
      self._running = True
      self._rx_thread = threading.Thread(
          target=self._run_rx_loop, name='vwifi-ra-server-rx', daemon=True
      )
      self._tx_thread = threading.Thread(
          target=self._run_periodic_tx, name='vwifi-ra-server-tx', daemon=True
      )
      self._rx_thread.start()
      self._tx_thread.start()

  def stop(self) -> None:
    with self._lock:
      self._running = False
      if self._sock is not None:
        try:
          self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
          pass
        try:
          self._sock.close()
        except OSError:
          pass
        self._sock = None

  def build_ra_packet(self) -> bytes:
    dst_mac = bytes.fromhex('333300000001')
    src_mac = self.ap_mac_bytes
    eth_hdr = dst_mac + src_mac + struct.pack('!H', 0x86DD)

    src_ip = socket.inet_pton(socket.AF_INET6, 'fe80::ff:fe00:101')
    dst_ip = socket.inet_pton(socket.AF_INET6, 'ff02::1')

    # ICMPv6 RA Body:
    # Type(1)=134, Code(1)=0, Cksum(2)=0, CurHopLimit(1)=64, Flags(1)=0x00,
    # RouterLifetime(2)=1800, ReachableTime(4)=0, RetransTimer(4)=0
    icmp_header_no_cksum = struct.pack(
        '!BBHBBHII', 134, 0, 0, 64, 0x00, 1800, 0, 0
    )

    # Prefix Information Option (Type 3, Length 4 = 32 bytes)
    # Type(1)=3, Len(1)=4, PrefixLen(1)=prefix_len, Flags(1, L=1, A=1 -> 0xC0),
    # ValidLifetime(4)=86400, PreferredLifetime(4)=14400, Reserved(4)=0, Prefix(16)
    prefix_bytes = socket.inet_pton(socket.AF_INET6, self.prefix)
    opt_pio = (
        struct.pack('!BBBBIII', 3, 4, self.prefix_len, 0xC0, 86400, 14400, 0)
        + prefix_bytes
    )

    # Source Link-Layer Address Option (Type 1, Length 1 = 8 bytes)
    opt_slla = struct.pack('!BB', 1, 1) + src_mac

    icmp_payload = icmp_header_no_cksum + opt_pio + opt_slla
    payload_len = len(icmp_payload)

    # IPv6 Pseudo-header for ICMPv6 checksum:
    pseudo_hdr = (
        src_ip
        + dst_ip
        + struct.pack('!I', payload_len)
        + b'\x00\x00\x00'
        + bytes([58])
    )
    cksum = _ones_complement_checksum(pseudo_hdr + icmp_payload)
    if cksum == 0:
      cksum = 0xFFFF

    icmp_payload_final = (
        struct.pack('!BBHBBHII', 134, 0, cksum, 64, 0x00, 1800, 0, 0)
        + opt_pio
        + opt_slla
    )

    # IPv6 Header (40 bytes)
    # Version=6, Traffic Class=0, Flow Label=0 -> 0x60000000
    # Payload Length=payload_len, Next Header=58 (ICMPv6), Hop Limit=255 (RFC 4861)
    ip6_hdr = (
        struct.pack('!IHBB', 0x60000000, payload_len, 58, 255)
        + src_ip
        + dst_ip
    )

    return eth_hdr + ip6_hdr + icmp_payload_final

  def is_router_solicitation(self, frame: bytes) -> bool:
    if len(frame) < 62:
      return False
    if struct.unpack('!H', frame[12:14])[0] != 0x86DD:
      return False
    if frame[20] != 58:
      return False
    if frame[54] != 133:
      return False
    return True

  def _send_ra(self) -> None:
    with self._lock:
      sock = self._sock
      running = self._running
    if sock is None or not running:
      return
    ra_pkt = self.build_ra_packet()
    wire_pkt = struct.pack('!H', len(ra_pkt)) + ra_pkt
    try:
      with self._send_lock:
        sock.sendall(wire_pkt)
      self.advertised_count += 1
    except OSError:
      pass

  def _run_rx_loop(self) -> None:
    while self._running:
      try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((self.server_host, self.data_port))
        with self._lock:
          if not self._running:
            sock.close()
            return
          self._sock = sock
        # Handshake with VirtualWiFiServer data_port: 'ra_server'
        sid = b'ra_server'
        sock.sendall(struct.pack('!H', len(sid)) + sid)
        if self.server is not None:
          st = self.server.get_station('ra_server')
          if st is not None:
            st.state = 'completed'
        while self._running:
          hdr = _recv_exact(sock, 2)
          if not hdr:
            break
          flen = struct.unpack('!H', hdr)[0]
          frame = _recv_exact(sock, flen)
          if not frame:
            break
          if self.is_router_solicitation(frame):
            self.solicitation_count += 1
            self._send_ra()
      except Exception as exc:
        if not self._running:
          break
        logger.warning('VirtualRaServer rx loop encountered error: %s', exc)
        time.sleep(0.5)

  def _run_periodic_tx(self) -> None:
    time.sleep(0.2)
    while self._running:
      self._send_ra()
      time.sleep(self.interval)


_WPA_DBUS_CONF_XML = (
    '<!DOCTYPE busconfig PUBLIC\n'
    ' "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"\n'
    ' "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">\n'
    '<busconfig>\n'
    '  <policy context="default">\n'
    '    <allow own="fi.w1.wpa_supplicant1"/>\n'
    '    <allow send_destination="fi.w1.wpa_supplicant1"/>\n'
    '    <allow send_interface="fi.w1.wpa_supplicant1"/>\n'
    '    <allow send_interface="fi.w1.wpa_supplicant1.Interface"/>\n'
    '    <allow send_interface="fi.w1.wpa_supplicant1.BSS"/>\n'
    '    <allow send_interface="fi.w1.wpa_supplicant1.Network"/>\n'
    '    <allow send_interface="org.freedesktop.DBus.Properties"/>\n'
    '    <allow send_interface="org.freedesktop.DBus.Introspectable"/>\n'
    '    <allow send_interface="org.freedesktop.DBus.ObjectManager"/>\n'
    '  </policy>\n'
    '</busconfig>\n'
)

_L2_AGENT_SCRIPT = """#!/usr/bin/env python3
import collections
import select
import socket
import struct
import sys
import time

# Linux AF_PACKET `sll_pkttype` constant (`<linux/if_packet.h>`):
# Frames injected into `vwifi_phy` by `raw_sock.send(frame)` are echoed back
# on `wlan0`, while frames transmitted out of `vwifi_phy` itself have
# `addr[2] == PACKET_OUTGOING (4)`. Filtering out `PACKET_OUTGOING` prevents
# infinite L2 broadcast reflection loops across the virtual switch.
PACKET_OUTGOING = 4

# Ring buffer of recently injected frames from unix socket to suppress
# veth bridge loop reflections.
_recent_injected = collections.deque(maxlen=64)

def recv_exact(sock, num_bytes):
    buf = bytearray()
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def _forward_from_raw(raw_sock, usock):
    frame, addr = raw_sock.recvfrom(65535)
    if len(addr) >= 3 and addr[2] == PACKET_OUTGOING:
        return
    # Check if this frame is an echo reflection of a recently injected frame
    now = time.monotonic()
    while _recent_injected and now - _recent_injected[0][0] > 1.0:
        _recent_injected.popleft()
    for _, injected in _recent_injected:
        if frame == injected:
            return
    usock.sendall(struct.pack('!H', len(frame)) + frame)


def _forward_from_unix(raw_sock, usock):
    hdr = recv_exact(usock, 2)
    if not hdr:
        raise ConnectionError('EOF')
    frame = recv_exact(usock, struct.unpack('!H', hdr)[0])
    if not frame:
        raise ConnectionError('EOF')
    if len(frame) < 14:
        return
    _recent_injected.append((time.monotonic(), frame))
    try:
        raw_sock.send(frame)
    except (BlockingIOError, InterruptedError):
        pass



def pump_once(raw_sock, usock):
    rlist, _, _ = select.select([raw_sock, usock], [], [], 1.0)
    for ready in rlist:
        if ready is raw_sock:
            _forward_from_raw(raw_sock, usock)
        else:
            _forward_from_unix(raw_sock, usock)


def _run_bridge_session(station_id, unix_sock_path, raw_sock):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as usock:
        usock.connect(unix_sock_path)
        sid_bytes = station_id.encode('utf-8')
        usock.sendall(struct.pack('!H', len(sid_bytes)) + sid_bytes)
        while True:
            pump_once(raw_sock, usock)


def main():
    if len(sys.argv) < 4:
        return 1
    station_id, ifname, unix_sock_path = sys.argv[1], sys.argv[2], sys.argv[3]
    import fcntl
    lock_file = open(f'/tmp/vwifi_agent_{station_id}.lock', 'w')
    try:
        fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        return 0
    raw_sock = socket.socket(
        socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)
    )
    raw_sock.bind((ifname, 0))
    raw_sock.setblocking(False)
    while True:
        try:
            _run_bridge_session(station_id, unix_sock_path, raw_sock)
        except Exception as exc:
            sys.stderr.write(
                f'vwifi_l2_agent[{station_id}] session error: {exc}\\n'
            )
            sys.stderr.flush()
            time.sleep(0.2)


if __name__ == '__main__':
    sys.exit(main())
"""

class DockerVirtualWiFiManager:
  """Manages container wlan0 interfaces, L2 switch sockets, and D-Bus."""

  def __init__(
      self,
      server: VirtualWiFiServer,
      runtime_dir: Optional[str] = None,
  ):
    if not runtime_dir:
      runtime_dir = os.environ.get(
          'CIRQUE_VIRTUAL_WIFI_RUNTIME_DIR', '/tmp/cirque_virtual_wifi'
      )
    self.server = server
    self.host = server.host
    self.control_port = server.control_port
    self.mgmt_port = server.mgmt_port
    self.data_port = server.data_port
    self.runtime_dir = runtime_dir
    self.containers_dir = os.path.join(runtime_dir, 'containers')
    self.bin_dir = os.path.join(runtime_dir, 'bin')
    self.control_sock_path = os.path.join(runtime_dir, 'control.sock')
    self.data_sock_path = os.path.join(runtime_dir, 'data.sock')
    self.wpa_conf_path = os.path.join(runtime_dir, 'fi.w1.wpa_supplicant1.conf')
    self.l2_agent_path = os.path.join(self.bin_dir, 'vwifi_l2_agent.py')
    self.iwlist_path = os.path.join(self.bin_dir, 'iwlist')
    self.dhcp_server = VirtualDhcpServer(
        server_host=self.host,
        data_port=self.data_port,
        server=self.server,
        server_ip='10.0.1.1',
        server_mac='02:00:00:00:01:01',
        start_ip=20,
    )
    self.ra_server = VirtualRaServer(
        server_host=self.host,
        data_port=self.data_port,
        server=self.server,
        ap_mac='02:00:00:00:01:01',
        prefix='fd11:22::',
        prefix_len=64,
    )
    self._lock = threading.RLock()
    self._station_nodes: Dict[str, object] = {}
    self._station_ips: Dict[str, Tuple[str, str]] = {}
    self._station_is_ap: Dict[str, bool] = {}
    self._deferred_auto_connect: Dict[str, Dict[str, object]] = {}
    if hasattr(self.server, 'add_ap_registered_callback'):
      self.server.add_ap_registered_callback(self._on_ap_registered)
    self._control_proxy = UnixToTcpProxy(
        self.control_sock_path,
        self.host,
        self.control_port,
        backlog=32,
        name='vwifi-unix-ctrl',
    )
    self._data_proxy = UnixToTcpProxy(
        self.data_sock_path,
        self.host,
        self.data_port,
        bidirectional=True,
        io_timeout_s=None,
        backlog=32,
        name='vwifi-unix-data',
    )
    self._ensure_support_files()
    self._control_proxy.start()
    try:
      self._data_proxy.start()
    except BaseException:
      self._control_proxy.stop()
      raise

  def _ensure_support_files(self) -> None:
    os.makedirs(self.runtime_dir, exist_ok=True)
    os.makedirs(self.containers_dir, exist_ok=True)
    os.makedirs(self.bin_dir, exist_ok=True)
    self._generate_wpa_dbus_conf()
    self._write_script(self.l2_agent_path, _L2_AGENT_SCRIPT)
    self._generate_iwlist_shim()

  def _write_script(self, path: str, content: str) -> None:
    write_executable_script(path, content, mode=0o755)

  def _generate_wpa_dbus_conf(self) -> str:
    with open(self.wpa_conf_path, 'w', encoding='utf-8') as conf_file:
      conf_file.write(_WPA_DBUS_CONF_XML)
    os.chmod(self.wpa_conf_path, 0o644)
    return self.wpa_conf_path

  def _generate_iwlist_shim(self) -> None:
    iwlist_script = (
        '#!/usr/bin/env python3\n'
        'import json, os, socket, sys\n'
        "SOCK_PATHS = ['/dev/virtual_wifi/control.sock',"
        f" '{self.control_sock_path}']\n"
        f"HOST, PORT = '{self.host}', {self.control_port}\n"
        'def query_aps():\n'
        '    req = (json.dumps({"cmd": "list_aps"}) + "\\n").encode("utf-8")\n'
        '    for p in SOCK_PATHS:\n'
        '        if os.path.exists(p):\n'
        '            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as'
        ' s:\n'
        '                s.settimeout(3.0)\n'
        '                s.connect(p)\n'
        '                s.sendall(req)\n'
        '                return'
        ' json.loads(s.makefile("r").readline()).get("aps", [])\n'
        '    with socket.create_connection((HOST, PORT), timeout=3.0) as s:\n'
        '        s.sendall(req)\n'
        '        return json.loads(s.makefile("r").readline()).get("aps", [])\n'
        'def main():\n'
        '    aps = query_aps()\n'
        '    target_essid = None\n'
        '    if len(sys.argv) >= 3 and sys.argv[1] == "wlan0" and sys.argv[2] =='
        ' "essid":\n'
        '        target_essid = sys.argv[3] if len(sys.argv) > 3 else ""\n'
        '        aps = [ap for ap in aps if ap.get("ssid") == target_essid]\n'
        '    if not aps:\n'
        '        print("wlan0     No scan results")\n'
        '        return 0\n'
        '    print("wlan0     Scan completed :")\n'
        '    for idx, ap in enumerate(aps, 1):\n'
        '        sig = int(ap.get("signal", -40))\n'
        '        quality = max(0, min(70, int((sig + 100) * 70 / 50)))\n'
        '        print(f"          Cell {idx:02d} - Address:'
        " {ap.get('bssid')}\")\n"
        "        print(f\"                    Channel:{ap.get('channel',"
        ' 6)}")\n'
        '        print(f"                    Quality={quality}/70  Signal'
        ' level={sig} dBm")\n'
        '        print("                    Encryption key:on")\n'
        '        print(f\'                    ESSID:"{ap.get("ssid")}"\')\n'
        '    return 0\n'
        'if __name__ == "__main__":\n'
        '    sys.exit(main())\n'
    )
    self._write_script(self.iwlist_path, iwlist_script)

  def get_container_dbus_dir(self, station_id: str) -> str:
    """Returns a dedicated /run/dbus host directory for a Wi-Fi container."""
    return prepare_container_dbus_dir(
        os.path.join(self.containers_dir, station_id, 'dbus')
    )

  def register_station(
      self,
      station_id: str,
      idx: int,
      is_ap: bool = False,
  ) -> Tuple[str, str, str]:
    """Allocates MAC, IPv4, and IPv6 addresses for a virtual Wi-Fi interface."""
    with self._lock:
      if is_ap:
        mac = f'02:00:00:00:01:{idx + 1:02x}'
        ipv4 = '10.0.1.1'
        ipv6 = 'fd11:22::1'
        self.dhcp_server.start()
        self.ra_server.start()
      else:
        host_num = 10 + idx
        mac = f'02:00:00:00:02:{host_num:02x}'
        ipv4 = f'10.0.1.{host_num}'
        ipv6 = ''
        self.dhcp_server.reserve_lease(mac, ipv4)
      self._station_ips[station_id] = (ipv4, ipv6)
      self._station_is_ap[station_id] = is_ap
      self.server.register_station(
          station_id=station_id,
          ifname='wlan0',
          mac_addr=mac,
          ipv4_addr=ipv4,
          ipv6_addr=ipv6,
          is_ap_bridge=is_ap,
      )
      return mac, ipv4, ipv6

  def setup_container_interface(
      self,
      station_id: str,
      docker_node: object,
      mac_addr: str,
      ipv4_addr: str = '',
      ipv6_addr: str = '',
      auto_connect: bool = False,
  ) -> None:
    """Creates wlan0<->vwifi_phy veth inside container and starts L2 relay."""
    with self._lock:
      self._station_nodes[station_id] = docker_node
      is_ap = self._station_is_ap.get(station_id, False) or (
          getattr(docker_node, 'type', '') == 'wifi_ap'
      ) or (ipv4_addr == '10.0.1.1')
      if station_id not in self._station_ips:
        self._station_ips[station_id] = (
            ipv4_addr or '10.0.1.5',
            ipv6_addr or '',
        )
      elif ipv4_addr or ipv6_addr:
        old_v4, old_v6 = self._station_ips[station_id]
        self._station_ips[station_id] = (
            ipv4_addr or old_v4,
            ipv6_addr or old_v6,
        )
      reg_v4, reg_v6 = self._station_ips[station_id]
    if hasattr(self.server, 'register_station'):
      self.server.register_station(
          station_id=station_id,
          ifname='wlan0',
          mac_addr=mac_addr,
          ipv4_addr=reg_v4,
          ipv6_addr=reg_v6,
          is_ap_bridge=is_ap,
      )
    container = getattr(docker_node, 'container', None)
    if container is None:
      return

    tap_dev = getattr(docker_node, 'tap_interface', None)
    if tap_dev or getattr(docker_node, 'is_tap_station', False):
      tap_dev = tap_dev or 'cirque_tap0'
      # Keep IPv6 enabled with its fe80 link-local address: QEMU resolves its
      # ::1 chardevs with AI_ADDRCONFIG, and Docker disables IPv6 on eth0 of
      # IPv4-only networks. Silence autoconf/RA to keep the kernel quiet on TAP.
      cmd = (
          f'ip link set dev {tap_dev} up 2>/dev/null || '
          f'(ip tuntap add dev {tap_dev} mode tap && '
          f'ip link set dev {tap_dev} up);'
          f' ip link set dev {tap_dev} promisc on 2>/dev/null || true;'
          f' sysctl -w net.ipv6.conf.{tap_dev}.accept_ra=0'
          f' net.ipv6.conf.{tap_dev}.autoconf=0'
          f' net.ipv6.conf.{tap_dev}.router_solicitations=0'
          ' >/dev/null 2>&1 || true;'
          f' ethtool -K {tap_dev} tx off rx off >/dev/null 2>&1 || true'
      )
      container.exec_run(f'sh -c "{cmd}"')
      container.exec_run(
          'sh -c "pkill -9 -f \\"[v]wifi_l2_agent.py\\" || true"'
      )
      time.sleep(0.2)
      container.exec_run(
          'python3 /dev/virtual_wifi/bin/vwifi_l2_agent.py '
          f'{station_id} {tap_dev} /dev/virtual_wifi/data.sock',
          detach=True,
      )
      if auto_connect:
        self._handle_auto_connect(
            station_id=station_id,
            docker_node=docker_node,
            container=None,
        )
      return

    peer_mac = '02:00:00:00:fe:' + mac_addr.split(':')[-1]
    cmds = [
        'chmod 0666 /run/dbus/system_bus_socket 2>/dev/null || true',
        (
            'mkdir -p /etc/wpa_supplicant && touch'
            ' /etc/wpa_supplicant/wpa_supplicant.conf'
        ),
        'ip link del wlan0 2>/dev/null || true',
        'ip link add wlan0 type veth peer name vwifi_phy',
        f'ip link set dev wlan0 address {mac_addr}',
        f'ip link set dev vwifi_phy address {peer_mac}',
        'ip link set dev wlan0 multicast on',
        'ip link set dev vwifi_phy promisc on up',
        'ip link set dev wlan0 up',
        'sysctl -w net.ipv6.conf.wlan0.disable_ipv6=0 >/dev/null 2>&1 || true',
        'sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true',
        (
            'sysctl -w net.ipv6.conf.vwifi_phy.disable_ipv6=1 '
            '>/dev/null 2>&1 || true'
        ),
        'ip addr flush dev vwifi_phy 2>/dev/null || true',
        'sysctl -w net.ipv6.conf.wlan0.forwarding=0 >/dev/null 2>&1 || true',
        'sysctl -w net.ipv6.conf.wlan0.accept_ra=2 >/dev/null 2>&1 || true',
        'sysctl -w net.ipv6.conf.wlan0.autoconf=1 >/dev/null 2>&1 || true',
        'sysctl -w net.ipv6.conf.all.accept_ra=2 >/dev/null 2>&1 || true',
        'ethtool -K wlan0 tx off rx off >/dev/null 2>&1 || true',
        'ethtool -K vwifi_phy tx off rx off >/dev/null 2>&1 || true',
    ]
    with self._lock:
      is_ap = self._station_is_ap.get(station_id, False) or (
          getattr(docker_node, 'type', '') == 'wifi_ap'
      ) or (ipv4_addr == '10.0.1.1')
    if is_ap:
      if ipv4_addr:
        cmds.append(f'ip addr replace {ipv4_addr}/24 dev wlan0')
      if ipv6_addr:
        cmds.append(f'ip -6 addr replace {ipv6_addr}/64 dev wlan0 nodad')
    else:
      cmds.append(
          'which dhcpcd >/dev/null 2>&1 && '
          'dhcpcd -b -4 --noipv4ll --nohook resolv.conf wlan0 || true'
      )
    container.exec_run('sh -c "' + ' && '.join(cmds) + '"')
    container.exec_run(
        'python3 /dev/virtual_wifi/bin/vwifi_l2_agent.py '
        f'{station_id} vwifi_phy /dev/virtual_wifi/data.sock',
        detach=True,
    )
    if auto_connect and not is_ap:
      self._handle_auto_connect(
          station_id=station_id,
          docker_node=docker_node,
          container=container,
      )

  def _handle_auto_connect(
      self,
      station_id: str,
      docker_node: object,
      container: Optional[object] = None,
  ) -> None:
    """Connects station to target AP, or defers until an AP registers.

    # SIMULATION-DISCLOSURE: auto_connect retrieves the station's configured
    # SSID/PSK from the node configuration when present. If the target AP is not
    # yet registered, auto_connect defers association and registers a listener
    # that fires as soon as the matching AP is registered on VirtualWiFiServer.
    """
    node_ssid = getattr(docker_node, 'wifi_ssid', None) or getattr(
        docker_node, 'ssid', None
    )
    node_psk = getattr(docker_node, 'wifi_psk', None) or getattr(
        docker_node, 'psk', None
    )
    aps = self.server.list_aps()
    matching_ap = None
    if node_ssid:
      matching_ap = next((ap for ap in aps if ap.ssid == node_ssid), None)
    elif aps:
      matching_ap = aps[0]

    if matching_ap is not None:
      target_ssid = matching_ap.ssid
      target_psk = node_psk if node_psk is not None else matching_ap.psk
      res = self.connect_station_to_ap(station_id, target_ssid, target_psk)
      if res.get('ok') and container is not None:
        try:
          container.exec_run(
              '/usr/sbin/dhcpcd -1 -4 --noipv4ll --nohook resolv.conf wlan0',
              detach=True,
          )
        except Exception as e:
          logger.warning('Failed to run dhcpcd on %s: %s', station_id, e)
    else:
      logger.info(
          'auto-connect deferred for station %s (ssid: %s)',
          station_id,
          node_ssid or '<any>',
      )
      with self._lock:
        self._deferred_auto_connect[station_id] = {
            'ssid': node_ssid,
            'psk': node_psk,
            'container': container,
        }

  def _on_ap_registered(self, ap_state: object) -> None:
    """Fires deferred auto-connect when a matching AP is registered."""
    with self._lock:
      deferred_entries = list(self._deferred_auto_connect.items())
    for station_id, entry in deferred_entries:
      req_ssid = entry.get('ssid')
      if req_ssid and req_ssid != getattr(ap_state, 'ssid', ''):
        continue
      actual_ssid = getattr(ap_state, 'ssid', '')
      req_psk = entry.get('psk')
      target_psk = (
          req_psk
          if req_psk is not None
          else getattr(ap_state, 'psk', '')
      )
      logger.info(
          'auto-connect fired for station %s (ssid: %s)',
          station_id,
          actual_ssid,
      )
      res = self.connect_station_to_ap(station_id, actual_ssid, target_psk)
      container = entry.get('container')
      if res.get('ok') and container is not None:
        try:
          container.exec_run(
              '/usr/sbin/dhcpcd -1 -4 --noipv4ll --nohook resolv.conf wlan0',
              detach=True,
          )
        except Exception as e:
          logger.warning('Failed to run dhcpcd on %s: %s', station_id, e)
      with self._lock:
        self._deferred_auto_connect.pop(station_id, None)

  def register_ap(
      self,
      ssid: str,
      psk: str,
      ap_id: Optional[str] = None,
      *,
      frequency: int = 2437,
      channel: int = 6,
      signal: int = -40,
      bssid: Optional[str] = None,
  ) -> object:
    """Registers an AP on the underlying VirtualWiFiServer."""
    return self.server.register_ap(
        ssid,
        psk,
        ap_id=ap_id,
        frequency=frequency,
        channel=channel,
        signal=signal,
        bssid=bssid,
    )

  def connect_station_to_ap(
      self,
      station_id: str,
      ssid: str,
      psk: str,
      on_state_change: Optional[Callable[[str], None]] = None,
  ) -> Dict[str, object]:
    """Drives genuine WPA2 4-way EAPOL handshake to authenticate station.

    # SIMULATION-DISCLOSURE: The WPA2 supplicant state machine runs in the
    # host-side manager rather than inside the container. EAPOL-Key frames
    # (0x888E) are exchanged over the TCP data socket directly between the
    # host-side supplicant and the VirtualWiFiServer AP authenticator, rather
    # than crossing container wlan0. The container wlan0 interface receives
    # standard L2 data frames once authentication completes.
    """
    with self._lock:
      docker_node = self._station_nodes.get(station_id)
      station_ips = self._station_ips.get(station_id)
      if not station_ips:
        return {
            'ok': False,
            'reason': f'station_{station_id}_not_registered',
            'status_code': 1,
        }
      ipv4_addr, ipv6_addr = station_ips
    st = self.server.get_station(station_id)
    if st is None:
      st = self.server.register_station(station_id)
    station_mac = st.mac_addr

    container = (
        getattr(docker_node, 'container', None) if docker_node else None
    )
    if container is not None and isinstance(
        getattr(container, 'id', None), str
    ):
      try:
        container.exec_run(
            'sh -c "pkill -9 -f \\"[v]wifi_l2_agent.py\\" || true"'
        )
        time.sleep(0.05)
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.debug('Cleanup of prior vwifi_l2_agent encountered: %s', e)

    # Step 1: Connect data socket and send greeting for station_id
    try:
      data_sock = socket.create_connection(
          (self.host, self.data_port), timeout=3.0
      )
      data_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      sid_bytes = station_id.encode('utf-8')
      data_sock.sendall(struct.pack('!H', len(sid_bytes)) + sid_bytes)
      time.sleep(0.02)
    except OSError as e:
      logger.error('Failed to connect to data port for %s: %s', station_id, e)
      return {'ok': False, 'reason': 'data_socket_failed', 'status_code': 1}

    # Step 2: Send CONNECT RPC on control_port (zero PSK leakage)
    try:
      with socket.create_connection(
          (self.host, self.control_port), timeout=3.0
      ) as ctrl_sock:
        req = {'cmd': 'CONNECT', 'station_id': station_id, 'ssid': ssid}
        ctrl_sock.sendall((json.dumps(req) + '\n').encode('utf-8'))
        resp_line = ctrl_sock.makefile('r', encoding='utf-8').readline()
        if not resp_line:
          data_sock.close()
          return {
              'ok': False,
              'reason': 'control_socket_eof',
              'status_code': 1,
          }
        ctrl_resp = json.loads(resp_line)
    except Exception as e:
      data_sock.close()
      logger.error('Failed to send CONNECT RPC for %s: %s', station_id, e)
      return {'ok': False, 'reason': 'control_rpc_failed', 'status_code': 1}

    if not ctrl_resp.get('ok'):
      data_sock.close()
      return {
          'ok': False,
          'reason': ctrl_resp.get('reason', 'connect_rejected'),
          'status_code': 1,
      }

    target_ap = ctrl_resp.get('ap', {})
    ap_bssid = target_ap.get('bssid', '')
    if not ap_bssid:
      data_sock.close()
      return {'ok': False, 'reason': 'missing_ap_bssid', 'status_code': 1}

    # Step 3: Initialize station-side Wpa2SupplicantStateMachine
    supplicant_frames: List[bytes] = []

    def _supplicant_state_cb(new_state: str) -> None:
      if on_state_change and new_state != 'completed':
        on_state_change(new_state)

    supplicant = Wpa2SupplicantStateMachine(
        station_mac=station_mac,
        on_send_frame=supplicant_frames.append,
        on_state_change=_supplicant_state_cb,
    )
    supplicant.start_association(ssid=ssid, passphrase=psk, ap_bssid=ap_bssid)

    ap_mac_bytes = bytes.fromhex(ap_bssid.replace(':', ''))
    sta_mac_bytes = bytes.fromhex(station_mac.replace(':', ''))

    def _recv_next_eapol(
        sock: socket.socket, timeout: float = 2.0
    ) -> Optional[bytes]:
      sock.settimeout(timeout)
      deadline = time.monotonic() + timeout
      while time.monotonic() < deadline:
        hdr = _recv_exact(sock, 2)
        if not hdr:
          return None
        flen = struct.unpack('!H', hdr)[0]
        if flen == 0:
          continue
        frame = _recv_exact(sock, flen)
        if not frame:
          return None
        if len(frame) >= 14 and frame[12:14] == b'\x88\x8e':
          return frame[14:]
      return None

    eapol_captured_frames: List[Tuple[float, bytes]] = []
    try:
      # Step 4: Receive Msg1 and send Msg2
      msg1_eapol = _recv_next_eapol(data_sock, timeout=2.0)
      if (
          not msg1_eapol
          or not supplicant.handle_eapol_frame(msg1_eapol)
          or not supplicant_frames
      ):
        data_sock.close()
        if on_state_change:
          on_state_change('disconnected')
        return {
            'ok': False,
            'reason': 'msg1_processing_failed',
            'status_code': 15,
        }

      eth_msg1 = (
          sta_mac_bytes
          + ap_mac_bytes
          + struct.pack('!H', 0x888E)
          + msg1_eapol
      )
      eapol_captured_frames.append((time.time(), eth_msg1))

      msg2_bytes = supplicant_frames.pop(0)
      eth_msg2 = (
          ap_mac_bytes
          + sta_mac_bytes
          + struct.pack('!H', 0x888E)
          + msg2_bytes
      )
      eapol_captured_frames.append((time.time(), eth_msg2))
      data_sock.sendall(struct.pack('!H', len(eth_msg2)) + eth_msg2)

      # Step 5: Receive Msg3 and send Msg4
      msg3_eapol = _recv_next_eapol(data_sock, timeout=1.5)
      if (
          not msg3_eapol
          or not supplicant.handle_eapol_frame(msg3_eapol)
          or not supplicant_frames
      ):
        data_sock.close()
        if on_state_change:
          on_state_change('disconnected')
        return {'ok': False, 'reason': 'auth_failed', 'status_code': 15}

      eth_msg3 = (
          sta_mac_bytes
          + ap_mac_bytes
          + struct.pack('!H', 0x888E)
          + msg3_eapol
      )
      eapol_captured_frames.append((time.time(), eth_msg3))

      msg4_bytes = supplicant_frames.pop(0)
      eth_msg4 = (
          ap_mac_bytes
          + sta_mac_bytes
          + struct.pack('!H', 0x888E)
          + msg4_bytes
      )
      eapol_captured_frames.append((time.time(), eth_msg4))
      data_sock.sendall(struct.pack('!H', len(eth_msg4)) + eth_msg4)

      # Step 6: Verify station-side supplicant reached completed state
      if supplicant.state != 'completed':
        data_sock.close()
        if on_state_change:
          on_state_change('disconnected')
        return {
            'ok': False,
            'reason': 'handshake_incomplete',
            'status_code': 15,
        }

      # Wait up to 1.0s for AP server thread to process Msg4 from the socket
      # and transition station.state to 'completed'.
      ap_completed = False
      deadline = time.monotonic() + 1.0
      while time.monotonic() < deadline:
        st = self.server.get_station(station_id)
        if st is not None and st.state == 'completed':
          ap_completed = True
          break
        time.sleep(0.01)

      if not ap_completed:
        data_sock.close()
        if on_state_change:
          on_state_change('disconnected')
        return {
            'ok': False,
            'reason': 'ap_handshake_incomplete',
            'status_code': 15,
        }

      eapol_tap_path = os.environ.get('CIRQUE_EAPOL_TAP_PATH')
      if not eapol_tap_path:
        evidence_dir = os.environ.get('CIRQUE_EVIDENCE_DIR')
        if evidence_dir and os.path.isdir(evidence_dir):
          eapol_tap_path = os.path.join(evidence_dir, 'oracle_b_eapol.pcap')
      if eapol_tap_path:
        try:
          os.makedirs(
              os.path.dirname(os.path.abspath(eapol_tap_path)), exist_ok=True
          )
          _write_pcap_frames(eapol_tap_path, eapol_captured_frames)
        except Exception as pcap_err:
          logger.warning('Failed to write EAPOL TAP pcap: %s', pcap_err)
    finally:
      try:
        data_sock.close()
      except OSError:
        pass

    # Step 7: Configure container link and restart vwifi_l2_agent.py
    if container is not None:
      tap_dev = getattr(docker_node, 'tap_interface', None)
      is_tap = bool(tap_dev or getattr(docker_node, 'is_tap_station', False))
      if is_tap:
        tap_dev = tap_dev or 'cirque_tap0'
        container.exec_run(
            f'sh -c "ip link set dev {tap_dev} up 2>/dev/null || true"'
        )
        container.exec_run(
            'sh -c "pkill -9 -f \\"[v]wifi_l2_agent.py\\" || true"'
        )
        time.sleep(0.2)
        container.exec_run(
            'python3 /dev/virtual_wifi/bin/vwifi_l2_agent.py '
            f'{station_id} {tap_dev} /dev/virtual_wifi/data.sock',
            detach=True,
        )
      else:
        ula_ipv6 = (
            ipv6_addr
            or f'fd11:22::ff:fe00:2{station_mac.split(":")[-1]}'
        )
        cmds = [
            'sysctl -w net.ipv6.conf.vwifi_phy.disable_ipv6=1'
            ' >/dev/null 2>&1 || true',
            'ip addr flush dev vwifi_phy 2>/dev/null || true',
            'ip link set dev vwifi_phy up',
            'ip link set dev wlan0 up',
            f'ip -6 addr replace {ula_ipv6}/64 dev wlan0 nodad',
            'ip -6 route replace fd11:22::/64 dev wlan0'
            ' 2>/dev/null || true',
        ]
        container.exec_run('sh -c "' + ' && '.join(cmds) + '"')
        container.exec_run(
            'sh -c "pkill -9 -f \\"[v]wifi_l2_agent.py\\" || true"'
        )
        time.sleep(0.2)
        container.exec_run(
            'python3 /dev/virtual_wifi/bin/vwifi_l2_agent.py '
            f'{station_id} vwifi_phy /dev/virtual_wifi/data.sock',
            detach=True,
        )
      if (
          getattr(self.server, '_running', False)
          and isinstance(getattr(container, 'id', None), str)
      ):
        wait_deadline = time.monotonic() + 1.5
        while time.monotonic() < wait_deadline:
          if station_id in getattr(self.server, '_data_clients', {}):
            break
          time.sleep(0.02)
      if not is_tap:
        self.start_station_dhcpcd(station_id)

    if on_state_change:
      on_state_change('completed')

    return {
        'ok': True,
        'status': 'completed',
        'ap': target_ap,
        'station': {
            'station_id': station_id,
            'state': 'completed',
            'associated_ssid': ssid,
            'associated_bssid': ap_bssid,
        },
    }

  def disconnect_station(self, station_id: str) -> None:
    self.server.disconnect_station(station_id)
    with self._lock:
      docker_node = self._station_nodes.get(station_id)
    container = getattr(docker_node, 'container', None) if docker_node else None
    if container is not None:
      container.exec_run(
          'sh -c "ip -4 addr flush dev wlan0 || true; ip -6 addr flush dev'
          ' wlan0 scope global || true"'
      )

  def unregister_station(self, station_id: str) -> None:
    with self._lock:
      self._station_nodes.pop(station_id, None)
      self._station_ips.pop(station_id, None)
      self._station_is_ap.pop(station_id, None)
    self.server.unregister_station(station_id)

  def start_station_dhcpcd(self, station_id: str) -> bool:
    """Starts/signals dhcpcd on wlan0 for the given station container."""
    with self._lock:
      docker_node = self._station_nodes.get(station_id)
    container = getattr(docker_node, 'container', None) if docker_node else None
    if container is None:
      return False
    cmd = (
        'sh -c "dhcpcd -n -4 wlan0 2>/dev/null || '
        'dhcpcd -1 -4 --noipv4ll --nohook resolv.conf wlan0 2>/dev/null || '
        'dhcpcd -b -4 --noipv4ll --nohook resolv.conf wlan0 2>/dev/null || '
        'true"'
    )
    container.exec_run(cmd, detach=True)
    return True

  def stop_all(self) -> None:
    if hasattr(self.server, 'remove_ap_registered_callback'):
      self.server.remove_ap_registered_callback(self._on_ap_registered)
    self.dhcp_server.stop()
    self.ra_server.stop()
    self._control_proxy.stop()
    self._data_proxy.stop()
