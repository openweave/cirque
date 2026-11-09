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
"""Userspace TCP Virtual 802.11 Medium, AP Registry, WPA2 Auth & L2 Switch.

Exposes three local TCP ports (`control_port`, `mgmt_port`, `data_port`) for
kernel-module-free 802.11 scanning, WPA2-PSK 4-way handshake authentication,
and gated L2 Ethernet frame switching between Docker containers.
"""

from dataclasses import asdict, dataclass, field
import json
import logging
import os
import socket
import struct
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

from cirque.common.docker_transport import bind_tcp_listener
from cirque.connectivity.rf_channel_simulator import RfChannelSimulator
from cirque.virtual_wifi.eapol import (
    EAPOL_VERSION_1,
    ETHERTYPE_EAPOL,
    EapolKeyFrame,
    KEY_DESC_VERSION_HMAC_SHA1_AES,
    KEY_INFO_ENCRYPTED_KEY_DATA,
    KEY_INFO_INSTALL,
    KEY_INFO_KEY_ACK,
    KEY_INFO_KEY_MIC,
    KEY_INFO_KEY_TYPE_PAIRWISE,
    KEY_INFO_SECURE,
    build_gtk_kde,
    decode_eapol_key_frame,
)
from cirque.virtual_wifi.wpa2_crypto import (
    Wpa2Ptk,
    aes_key_wrap,
    compute_mic,
    derive_ptk,
    pbkdf2_sha1_pmk,
    verify_mic,
)

logger = logging.getLogger('VirtualWiFiServer')

# In-process distribution-system pseudo-stations (VirtualDhcpServer,
# VirtualRaServer). They transmit with the AP MAC (02:00:00:00:01:01) but are
# not the AP's IP endpoint, so their frames must not re-bind that MAC in the
# L2 learning table; otherwise unicast frames to the gateway MAC are delivered
# to them instead of the AP container.
_NON_LEARNING_STATION_IDS = frozenset({'dhcp_server', 'ra_server'})


def _ones_complement_checksum(payload_bytes: bytes) -> int:
  """Computes the RFC 1071 16-bit one's complement Internet checksum."""
  if len(payload_bytes) % 2 == 1:
    payload_bytes += b'\x00'
  word_count = len(payload_bytes) // 2
  total = sum(struct.unpack(f'!{word_count}H', payload_bytes))
  while total >> 16:
    total = (total & 0xFFFF) + (total >> 16)
  return (~total) & 0xFFFF


def _fix_ipv4_l4_checksum(frame: bytes) -> bytes:
  """Recomputes IPv4 UDP/TCP checksums for frames relayed across TAP bridges.

  Why this is required:
    Linux container `veth` interfaces enable TX checksum offload
    (`CHECKSUM_PARTIAL`) by default, leaving only the pseudo-header seed in the
    UDP (bytes 6..8) or TCP (bytes 16..18) checksum field. When `vwifi_l2_agent`
    reads raw Ethernet frames via `AF_PACKET` and forwards them over userspace
    TCP (`data_port`) into another container's `AF_PACKET` socket, the kernel
    marks the injected skb as `CHECKSUM_NONE` (received from wire) and drops
    any UDP/TCP packet with an incomplete L4 checksum.

  Ethernet + IPv4 offset layout:
    - Bytes 0..14  : Ethernet II header (`dst_mac[6]`, `src_mac[6]`, `0x0800`)
    - Byte  14     : `Version (4b) | IHL (4b)` -> `ihl = (frame[14] & 0x0F) * 4`
    - Bytes 16..18 : IPv4 `Total Length` (`!H`)
    - Byte  23     : IPv4 `Protocol` (`17` = UDP, `6` = TCP)
    - Bytes 26..34 : `src_ip[4]`, `dst_ip[4]`
    - Bytes 14+ihl : L4 segment start
  """
  ihl = (frame[14] & 0x0F) * 4
  total_len = struct.unpack('!H', frame[16:18])[0]
  if 14 + total_len > len(frame) or total_len < ihl:
    return frame
  flags_offset = struct.unpack_from('!H', frame, 20)[0]
  if (flags_offset & 0x3FFF) != 0:
    return frame
  protocol_num = frame[23]
  src_ip = frame[26:30]
  dst_ip = frame[30:34]
  l4_segment = bytearray(frame[14 + ihl : 14 + total_len])
  if protocol_num == 17 and len(l4_segment) >= 8:
    l4_segment[6:8] = b'\x00\x00'
    pseudo = src_ip + dst_ip + struct.pack('!BBH', 0, 17, len(l4_segment))
    checksum = _ones_complement_checksum(pseudo + bytes(l4_segment))
    # Per RFC 768, a computed UDP checksum of 0x0000 is transmitted as 0xFFFF.
    struct.pack_into('!H', l4_segment, 6, 0xFFFF if checksum == 0 else checksum)
    return frame[: 14 + ihl] + bytes(l4_segment) + frame[14 + total_len :]
  if protocol_num == 6 and len(l4_segment) >= 20:
    l4_segment[16:18] = b'\x00\x00'
    pseudo = src_ip + dst_ip + struct.pack('!BBH', 0, 6, len(l4_segment))
    checksum = _ones_complement_checksum(pseudo + bytes(l4_segment))
    struct.pack_into('!H', l4_segment, 16, checksum)
    return frame[: 14 + ihl] + bytes(l4_segment) + frame[14 + total_len :]
  return frame


def _fix_ipv6_l4_checksum(frame: bytes) -> bytes:
  """Recomputes IPv6 UDP/TCP/ICMPv6 checksums for TAP-relayed frames.

  Ethernet + IPv6 offset layout:
    - Bytes 0..14  : Ethernet II header (`dst_mac[6]`, `src_mac[6]`, `0x86DD`)
    - Bytes 18..20 : IPv6 `Payload Length` (`!H`)
    - Byte  20     : IPv6 `Next Header` (`17` = UDP, `6` = TCP, `58` = ICMPv6)
    - Bytes 22..54 : `src_ip6[16]`, `dst_ip6[16]`
    - Byte  54     : L4 segment start (fixed 40-byte IPv6 header)
  """
  payload_len = struct.unpack('!H', frame[18:20])[0]
  if 54 + payload_len > len(frame):
    return frame
  next_hdr = frame[20]
  src_ip6 = frame[22:38]
  dst_ip6 = frame[38:54]
  l4_segment = bytearray(frame[54 : 54 + payload_len])
  pseudo = src_ip6 + dst_ip6 + struct.pack('!I3xB', len(l4_segment), next_hdr)
  # Map Next Header -> (min_l4_header_len, checksum_byte_offset, zero_is_ffff).
  offset_map = {17: (8, 6, True), 6: (20, 16, False), 58: (4, 2, False)}
  if next_hdr not in offset_map:
    return frame
  min_len, csum_offset, zero_is_ffff = offset_map[next_hdr]
  if len(l4_segment) < min_len:
    return frame
  l4_segment[csum_offset : csum_offset + 2] = b'\x00\x00'
  checksum = _ones_complement_checksum(pseudo + bytes(l4_segment))
  if zero_is_ffff and checksum == 0:
    checksum = 0xFFFF
  struct.pack_into('!H', l4_segment, csum_offset, checksum)
  return frame[:54] + bytes(l4_segment) + frame[54 + payload_len :]


def fix_l4_checksum(frame: bytes) -> bytes:
  """Finalizes IPv4/IPv6 L4 checksums on Ethernet frames relayed via TAP."""
  if len(frame) < 14:
    return frame
  ethertype = struct.unpack('!H', frame[12:14])[0]
  if ethertype == 0x0800 and len(frame) >= 34:
    return _fix_ipv4_l4_checksum(frame)
  if ethertype == 0x86DD and len(frame) >= 54:
    return _fix_ipv6_l4_checksum(frame)
  return frame


def _is_udp5540_frame(frame: bytes) -> bool:
  """Detects if an Ethernet frame carries an IPv4 or IPv6 UDP port 5540

  datagram.
  """
  if len(frame) < 14:
    return False
  ethertype = struct.unpack('!H', frame[12:14])[0]
  if ethertype == 0x0800:
    if len(frame) < 34:
      return False
    ihl = (frame[14] & 0x0F) * 4
    if ihl < 20 or len(frame) < 14 + ihl + 8:
      return False
    if frame[23] != 17:  # UDP
      return False
    src_port, dst_port = struct.unpack('!HH', frame[14 + ihl : 14 + ihl + 4])
    return src_port == 5540 or dst_port == 5540
  if ethertype == 0x86DD:
    if len(frame) < 54 + 8:
      return False
    if frame[20] != 17:  # UDP
      return False
    src_port, dst_port = struct.unpack('!HH', frame[54:58])
    return src_port == 5540 or dst_port == 5540
  return False


@dataclass
class VirtualWiFiApState:
  """State of a virtual 802.11 Access Point registered on the medium."""

  ap_id: str
  ssid: str
  psk: str
  bssid: str = '02:00:00:00:01:00'
  frequency: int = 2437
  channel: int = 6
  signal: int = -40
  security: str = 'WPA2-PSK'
  ipv4_addr: str = '10.0.1.1'
  ipv6_addr: str = 'fd11:22::1'

  def to_public_dict(self) -> Dict[str, object]:
    """Returns a public representation of the AP state, strictly excluding private PSK."""
    return {
        'ap_id': self.ap_id,
        'ssid': self.ssid,
        'bssid': self.bssid,
        'frequency': self.frequency,
        'channel': self.channel,
        'signal': self.signal,
        'security': self.security,
        'key_mgmt': 'WPA-PSK',
        'ipv4_addr': self.ipv4_addr,
        'ipv6_addr': self.ipv6_addr,
    }


@dataclass
class VirtualWiFiStationState:
  """State of a virtual 802.11 Station interface (wlan0) on the medium."""

  station_id: str
  ifname: str = 'wlan0'
  mac_addr: str = '02:00:00:00:02:01'
  state: str = 'disconnected'
  associated_ap_id: str = ''
  associated_ssid: str = ''
  associated_bssid: str = ''
  ipv4_addr: str = ''
  ipv6_addr: str = ''
  rx_packets: int = 0
  tx_packets: int = 0
  relayed_data_frames: int = 0
  relayed_udp5540_frames: int = 0
  dropped_rf_frames: int = 0
  rssi_dbm: int = -42
  noise_dbm: float = -95.0
  sinr_db: float = 53.0
  # True once the RF simulator has sampled this station's own uplink.
  rf_sampled: bool = False
  configured_networks: List[Dict[str, str]] = field(default_factory=list)
  is_ap_bridge: bool = False
  disconnect_reason: str = ''

  @property
  def connected(self) -> bool:
    return self.state == 'completed'

  @property
  def wpa_state(self) -> str:
    return self.state.upper()


@dataclass
class VirtualWiFiAuthState:
  """WPA2 Authenticator 4-way handshake state per station."""

  ap_id: str
  station_mac: str
  anonce: bytes
  replay_counter: int = 1
  snonce: bytes = b''
  ptk: Optional[Wpa2Ptk] = None
  state: str = 'AUTHENTICATING'


class VirtualWiFiServer:
  """3-port TCP Virtual Wi-Fi Medium Server (Control, 802.11 Mgmt, L2 Data)."""

  def __init__(
      self,
      host: str = '127.0.0.1',
      control_port: int = 0,
      *,
      mgmt_port: int = 0,
      data_port: int = 0,
      pcap_dir: Optional[str] = None,
  ):
    self.host = host
    self.control_port = control_port
    self.mgmt_port = int(mgmt_port)
    self.data_port = int(data_port)
    self._lock = threading.RLock()
    self._running = False
    self._aps: Dict[str, VirtualWiFiApState] = {}
    self._stations: Dict[str, VirtualWiFiStationState] = {}
    self._mac_to_station: Dict[bytes, str] = {}
    self._data_clients: Dict[str, socket.socket] = {}
    self._socket_send_locks: Dict[socket.socket, threading.Lock] = {}
    self._socket_locks = self._socket_send_locks
    self._station_sockets: Dict[str, List[socket.socket]] = {}
    self._auth_states: Dict[str, VirtualWiFiAuthState] = {}
    self._ap_gtks: Dict[str, bytes] = {}
    self._relayed_data_frames: int = 0
    self._relayed_udp5540_frames: int = 0
    self._dropped_rf_frames: int = 0
    self._rf_simulator: Optional[RfChannelSimulator] = (
        RfChannelSimulator.get_shared()
    )
    self._control_sock: Optional[socket.socket] = None
    self._mgmt_sock: Optional[socket.socket] = None
    self._data_sock: Optional[socket.socket] = None
    self._threads: List[threading.Thread] = []
    self.pcap_dir = (
        pcap_dir
        or os.environ.get('CIRQUE_PCAP_DIR')
        or os.environ.get('DEVICE_LOG_DIR')
    )
    self._pcap_medium_writer = None
    self._pcap_ap_writer = None
    self._pcap_sta_writers: Dict[str, Any] = {}
    self._ap_registered_callbacks: List[
        Callable[[VirtualWiFiApState], None]
    ] = []
    if self.pcap_dir:
      self.enable_pcap(self.pcap_dir)

  def enable_pcap(self, pcap_dir: str) -> None:
    """Enables PCAP logging for Wi-Fi stations, AP, and medium (DLT 1)."""
    with self._lock:
      dir_changed = bool(
          self.pcap_dir
          and os.path.abspath(self.pcap_dir) != os.path.abspath(pcap_dir)
      )
      self.pcap_dir = pcap_dir
      os.makedirs(self.pcap_dir, exist_ok=True)
      from cirque.capabilities.pcapcapability import DLT_EN10MB, PcapWriter

      if dir_changed:
        if self._pcap_medium_writer is not None:
          self._pcap_medium_writer.close()
          self._pcap_medium_writer = None
        if self._pcap_ap_writer is not None:
          self._pcap_ap_writer.close()
          self._pcap_ap_writer = None
        for writer in self._pcap_sta_writers.values():
          writer.close()
        self._pcap_sta_writers.clear()
      if self._pcap_medium_writer is None:
        self._pcap_medium_writer = PcapWriter(
            os.path.join(self.pcap_dir, 'wifi_medium.pcap'),
            dlt=DLT_EN10MB,
        )
      if self._pcap_ap_writer is None:
        self._pcap_ap_writer = PcapWriter(
            os.path.join(self.pcap_dir, 'wifi_ap.pcap'),
            dlt=DLT_EN10MB,
        )
      for sta_id in self._stations:
        if sta_id not in self._pcap_sta_writers:
          self._pcap_sta_writers[sta_id] = PcapWriter(
              os.path.join(self.pcap_dir, f'wifi_{sta_id}.pcap'),
              dlt=DLT_EN10MB,
          )

  def _get_or_create_sta_pcap_writer(self, station_id: str):
    if not self.pcap_dir or not station_id:
      return None
    with self._lock:
      if station_id not in self._pcap_sta_writers:
        from cirque.capabilities.pcapcapability import DLT_EN10MB, PcapWriter

        self._pcap_sta_writers[station_id] = PcapWriter(
            os.path.join(self.pcap_dir, f'wifi_{station_id}.pcap'),
            dlt=DLT_EN10MB,
        )
      return self._pcap_sta_writers[station_id]

  def start(self) -> None:
    """Starts the Control, Management, and L2 Data Switch TCP listeners."""
    with self._lock:
      if self._running:
        return
      self._control_sock = self._bind_tcp(self.control_port)
      self.control_port = self._control_sock.getsockname()[1]
      self._mgmt_sock = self._bind_tcp(self.mgmt_port)
      self.mgmt_port = self._mgmt_sock.getsockname()[1]
      self._data_sock = self._bind_tcp(self.data_port)
      self.data_port = self._data_sock.getsockname()[1]
      self._running = True
      for thread_name, sock, handler in (
          ('vwifi-ctrl', self._control_sock, self._handle_json_client),
          ('vwifi-mgmt', self._mgmt_sock, self._handle_json_client),
          ('vwifi-data', self._data_sock, self._handle_data_client),
      ):
        worker = threading.Thread(
            target=self._accept_loop,
            args=(sock, handler),
            name=thread_name,
            daemon=True,
        )
        worker.start()
        self._threads.append(worker)
      logger.info(
          'VirtualWiFiServer listening on %s (ctrl=%d, mgmt=%d, data=%d)',
          self.host,
          self.control_port,
          self.mgmt_port,
          self.data_port,
      )

  def _get_socket_send_lock(self, sock: socket.socket) -> threading.Lock:
    """Returns or creates the per-socket write lock to serialize sendall."""
    with self._lock:
      lock = self._socket_send_locks.get(sock)
      if lock is None:
        lock = threading.Lock()
        self._socket_send_locks[sock] = lock
      return lock

  def _bind_tcp(self, port: int) -> socket.socket:
    return bind_tcp_listener(self.host, port, backlog=32)

  def stop(self) -> None:
    """Stops all TCP listeners and clears state."""
    with self._lock:
      self._running = False
      to_close = list(self._data_clients.values())
      self._data_clients.clear()
      self._socket_send_locks.clear()
      self._mac_to_station.clear()
      for sock in (self._control_sock, self._mgmt_sock, self._data_sock):
        if sock is not None:
          to_close.append(sock)
      self._control_sock = None
      self._mgmt_sock = None
      self._data_sock = None
      if self._pcap_medium_writer is not None:
        self._pcap_medium_writer.close()
        self._pcap_medium_writer = None
      if self._pcap_ap_writer is not None:
        self._pcap_ap_writer.close()
        self._pcap_ap_writer = None
      for writer in self._pcap_sta_writers.values():
        writer.close()
      self._pcap_sta_writers.clear()
    for sock in to_close:
      try:
        sock.close()
      except OSError:
        pass

  def add_ap_registered_callback(
      self, callback: Callable[[VirtualWiFiApState], None]
  ) -> None:
    """Adds a callback to be notified when an AP is registered or updated."""
    with self._lock:
      self._ap_registered_callbacks.append(callback)

  def remove_ap_registered_callback(
      self, callback: Callable[[VirtualWiFiApState], None]
  ) -> None:
    """Removes a registered AP notification callback."""
    with self._lock:
      if callback in self._ap_registered_callbacks:
        self._ap_registered_callbacks.remove(callback)

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
  ) -> VirtualWiFiApState:
    """Registers or updates a Virtual 802.11 Access Point on the medium."""
    frequency = int(frequency)
    channel = int(channel)
    signal = int(signal)
    with self._lock:
      ap_state = None
      for existing in self._aps.values():
        if existing.ssid == ssid:
          existing.psk = psk
          existing.frequency = frequency
          existing.channel = channel
          existing.signal = signal
          ap_state = existing
          break
      if ap_state is None:
        idx = len(self._aps) + 1
        resolved_id = ap_id or f'ap{idx - 1}'
        resolved_bssid = str(bssid) if bssid else f'02:00:00:00:01:{idx:02x}'
        ap_state = VirtualWiFiApState(
            ap_id=resolved_id,
            ssid=ssid,
            psk=psk,
            bssid=resolved_bssid,
            frequency=frequency,
            channel=channel,
            signal=signal,
        )
        self._aps[resolved_id] = ap_state
        logger.info('Registered Virtual Wi-Fi AP %s (%s)', resolved_id, ssid)
      callbacks = list(self._ap_registered_callbacks)
    for cb in callbacks:
      try:
        cb(ap_state)
      except Exception as e:
        logger.warning('AP registered callback failed: %s', e)
    return ap_state

  def unregister_ap(self, ap_id: str) -> None:
    with self._lock:
      self._aps.pop(ap_id, None)

  def list_aps(self) -> List[VirtualWiFiApState]:
    with self._lock:
      return list(self._aps.values())

  def register_station(
      self,
      station_id: str,
      ifname: str = 'wlan0',
      mac_addr: Optional[str] = None,
      *,
      ipv4_addr: str = '',
      ipv6_addr: str = '',
      is_ap_bridge: bool = False,
  ) -> VirtualWiFiStationState:
    """Registers a Virtual Wi-Fi Station (wlan0) on the medium."""
    ipv4_addr = str(ipv4_addr)
    ipv6_addr = str(ipv6_addr)
    is_ap_bridge = bool(is_ap_bridge)
    with self._lock:
      existing = self._stations.get(station_id)
      if existing is not None:
        if mac_addr:
          existing.mac_addr = mac_addr
        mac_bytes = bytes.fromhex(existing.mac_addr.replace(':', ''))
        self._mac_to_station[mac_bytes] = station_id
        if ipv4_addr:
          existing.ipv4_addr = ipv4_addr
        if ipv6_addr:
          existing.ipv6_addr = ipv6_addr
        if is_ap_bridge:
          existing.is_ap_bridge = True
          existing.state = 'completed'
          existing.disconnect_reason = ''
        return existing
      idx = len(self._stations) + 1
      resolved_mac = mac_addr or f'02:00:00:00:02:{idx:02x}'
      mac_bytes = bytes.fromhex(resolved_mac.replace(':', ''))
      self._mac_to_station[mac_bytes] = station_id
      station = VirtualWiFiStationState(
          station_id=station_id,
          ifname=ifname,
          mac_addr=resolved_mac,
          state='completed' if is_ap_bridge else 'disconnected',
          ipv4_addr=ipv4_addr,
          ipv6_addr=ipv6_addr,
          is_ap_bridge=is_ap_bridge,
      )
      self._stations[station_id] = station
      if self.pcap_dir:
        self._get_or_create_sta_pcap_writer(station_id)
      return station

  def unregister_station(self, station_id: str) -> None:
    with self._lock:
      self._stations.pop(station_id, None)
      # Drop any in-flight WPA2 handshake so a re-registered station must
      # start a fresh one instead of resuming with a stale ANonce/counter.
      self._auth_states.pop(station_id, None)
      sock = self._data_clients.pop(station_id, None)
      extra_socks = self._station_sockets.pop(station_id, [])
      stale_macs = [
          mac for mac, sid in self._mac_to_station.items() if sid == station_id
      ]
      for mac in stale_macs:
        self._mac_to_station.pop(mac, None)
      sta_w = self._pcap_sta_writers.pop(station_id, None)
      if sta_w is not None:
        sta_w.close()
    for s in ([sock] if sock is not None else []) + list(extra_socks):
      try:
        s.close()
      except OSError:
        pass

  def get_station(self, station_id: str) -> Optional[VirtualWiFiStationState]:
    with self._lock:
      return self._stations.get(station_id)

  def scan_signal_dbm(self, station_id: str, ap: VirtualWiFiApState) -> int:
    """Returns the AP signal level the given station should see in a scan.

    Once the RF simulator has sampled this station's link, and while it is
    still enabled, the station's own RSSI is used (RF links are reciprocal);
    otherwise the AP's configured signal.
    """
    with self._lock:
      st = self._stations.get(station_id)
      rf_enabled = (
          self._rf_simulator is not None and self._rf_simulator.config.enabled
      )
      if rf_enabled and st is not None and st.rf_sampled:
        return int(st.rssi_dbm)
      return int(ap.signal)

  def list_stations(self) -> List[VirtualWiFiStationState]:
    with self._lock:
      return list(self._stations.values())

  def get_frame_counters(self) -> Dict[str, object]:
    """Returns L2 frame counters, separating handshake from relayed data."""
    with self._lock:
      tx = sum(st.tx_packets for st in self._stations.values())
      rx = sum(st.rx_packets for st in self._stations.values())
      per_station = {
          sid: {
              'tx_packets_with_handshake': st.tx_packets,
              'rx_packets_with_handshake': st.rx_packets,
              'relayed_data_frames': st.relayed_data_frames,
              'relayed_udp5540_frames': st.relayed_udp5540_frames,
              'dropped_rf_frames': st.dropped_rf_frames,
              'rssi_dbm': st.rssi_dbm,
              'noise_dbm': st.noise_dbm,
              'sinr_db': st.sinr_db,
          }
          for sid, st in self._stations.items()
      }
      return {
          'tx_packets_with_handshake': tx,
          'rx_packets_with_handshake': rx,
          'total_packets_with_handshake': tx + rx,
          'total_packets': tx + rx,
          'relayed_data_frames': self._relayed_data_frames,
          'relayed_udp5540_frames': self._relayed_udp5540_frames,
          'dropped_rf_frames': self._dropped_rf_frames,
          'stations': per_station,
      }

  def reset_frame_counters(self) -> None:
    """Resets relayed and per-station counters back to zero."""
    with self._lock:
      self._relayed_data_frames = 0
      self._relayed_udp5540_frames = 0
      self._dropped_rf_frames = 0
      for st in self._stations.values():
        st.relayed_data_frames = 0
        st.relayed_udp5540_frames = 0
        st.dropped_rf_frames = 0

  def _get_or_create_ap_gtk(self, ap_id: str) -> bytes:
    """Returns or generates a random 16-byte GTK for the AP."""
    if ap_id not in self._ap_gtks:
      self._ap_gtks[ap_id] = os.urandom(16)
    return self._ap_gtks[ap_id]

  def _send_eapol_frame_to_station(
      self,
      station_id: str,
      ap_bssid_str: str,
      sta_mac_str: str,
      eapol_bytes: bytes,
  ) -> bool:
    """Encapsulates and sends an EAPOL frame (Ethertype 0x888E) to a station."""
    ap_mac = bytes.fromhex(ap_bssid_str.replace(':', ''))
    sta_mac = bytes.fromhex(sta_mac_str.replace(':', ''))
    eth_frame = (
        sta_mac + ap_mac + struct.pack('!H', ETHERTYPE_EAPOL) + eapol_bytes
    )
    pkt = struct.pack('!H', len(eth_frame)) + eth_frame
    if self._pcap_medium_writer is not None:
      self._pcap_medium_writer.write_frame(eth_frame)
    if self._pcap_ap_writer is not None:
      self._pcap_ap_writer.write_frame(eth_frame)
    sta_w = self._get_or_create_sta_pcap_writer(station_id)
    if sta_w is not None:
      sta_w.write_frame(eth_frame)
    with self._lock:
      st = self._stations.get(station_id)
      if st is not None:
        st.tx_packets += 1
      socks = list(self._station_sockets.get(station_id, []))
      primary = self._data_clients.get(station_id)
      if primary is not None and all(s is not primary for s in socks):
        socks.append(primary)
    sent_any = False
    for sock in socks:
      send_lock = self._get_socket_send_lock(sock)
      try:
        with send_lock:
          sock.sendall(pkt)
          sent_any = True
      except OSError:
        pass
    return sent_any

  def initiate_eapol_handshake(
      self, station_id: str, ap_id: str, send_data_client: bool = True
  ) -> Optional[bytes]:
    """Initiates WPA2 4-way handshake on AP: creates state and returns EAPOL Msg1."""
    with self._lock:
      station = self._stations.get(station_id) or self.register_station(
          station_id
      )
      target_ap = self._aps.get(ap_id)
      if target_ap is None:
        station.state = 'disconnected'
        return None

      station.state = 'authenticating'
      station.associated_ap_id = target_ap.ap_id
      station.associated_ssid = target_ap.ssid
      station.associated_bssid = target_ap.bssid

      anonce = os.urandom(32)
      auth_state = VirtualWiFiAuthState(
          ap_id=ap_id,
          station_mac=station.mac_addr,
          anonce=anonce,
          replay_counter=1,
          state='WAIT_MSG2',
      )
      self._auth_states[station_id] = auth_state

      # Build Msg1 (Key Ack = 1, Key MIC = 0, Pairwise = 1)
      key_info = (
          KEY_INFO_KEY_TYPE_PAIRWISE
          | KEY_INFO_KEY_ACK
          | KEY_DESC_VERSION_HMAC_SHA1_AES
      )
      msg1 = EapolKeyFrame(
          version=EAPOL_VERSION_1,
          descriptor_type=2,
          key_info=key_info,
          key_length=16,
          replay_counter=1,
          nonce=anonce,
          iv=b'\x00' * 16,
          rsc=0,
          mic=b'\x00' * 16,
          key_data=b'',
      )
      msg1_bytes = msg1.encode()
      if send_data_client:
        self._send_eapol_frame_to_station(
            station_id, target_ap.bssid, station.mac_addr, msg1_bytes
        )
      return msg1_bytes

  def process_eapol_frame(
      self, station_id: str, eapol_bytes: bytes, send_data_client: bool = True
  ) -> Tuple[bool, Optional[bytes]]:
    """AP processes an incoming EAPOL frame from station (Msg2 or Msg4).

    Returns (success, response_eapol_bytes).
    """
    with self._lock:
      station = self._stations.get(station_id)
      auth_state = self._auth_states.get(station_id)
      if station is None or auth_state is None:
        logger.warning('No active auth state for station %s', station_id)
        return False, None

      target_ap = self._aps.get(auth_state.ap_id)
      if target_ap is None:
        return False, None

      station.rx_packets += 1

      try:
        frame = decode_eapol_key_frame(eapol_bytes)
      except Exception as e:
        logger.warning(
            'Failed to decode EAPOL frame from %s: %s', station_id, e
        )
        return False, None

      # Msg2 and Msg4 must be: Pairwise, MIC, not Key Ack
      if not (frame.is_pairwise and frame.has_mic and not frame.key_ack):
        logger.warning(
            'Unrecognized or out-of-order EAPOL frame from %s', station_id
        )
        return False, None

      if auth_state.state == 'WAIT_MSG2':
        if frame.replay_counter != auth_state.replay_counter:
          logger.warning(
              'Msg2 replay counter mismatch: %d != %d',
              frame.replay_counter,
              auth_state.replay_counter,
          )
          return False, None

        auth_state.snonce = frame.nonce
        pmk = pbkdf2_sha1_pmk(target_ap.psk, target_ap.ssid)
        ap_mac_b = bytes.fromhex(target_ap.bssid.replace(':', ''))
        sta_mac_b = bytes.fromhex(station.mac_addr.replace(':', ''))
        ptk = derive_ptk(
            pmk,
            aa_mac=ap_mac_b,
            spa_mac=sta_mac_b,
            anonce=auth_state.anonce,
            snonce=auth_state.snonce,
        )

        msg2_zeroed = frame.encode_with_zeroed_mic()
        if not verify_mic(ptk.kck, msg2_zeroed, frame.mic):
          logger.warning(
              'Msg2 MIC check failed for %s (wrong PSK/PMK)', station_id
          )
          station.state = 'disconnected'
          self._auth_states.pop(station_id, None)
          return False, None

        auth_state.ptk = ptk
        auth_state.replay_counter += 1
        auth_state.state = 'WAIT_MSG4'

        # Construct Msg3 (Key Ack, Install, MIC, Secure, Encrypted Key Data)
        gtk = self._get_or_create_ap_gtk(target_ap.ap_id)
        gtk_kde = build_gtk_kde(gtk, key_id=1)
        # RFC 3394 AES Key Wrap requires multiple of 8 bytes
        wrapped_gtk_kde = aes_key_wrap(ptk.kek, gtk_kde)

        key_info_msg3 = (
            KEY_INFO_KEY_TYPE_PAIRWISE
            | KEY_INFO_INSTALL
            | KEY_INFO_KEY_ACK
            | KEY_INFO_KEY_MIC
            | KEY_INFO_SECURE
            | KEY_INFO_ENCRYPTED_KEY_DATA
            | KEY_DESC_VERSION_HMAC_SHA1_AES
        )
        msg3 = EapolKeyFrame(
            version=EAPOL_VERSION_1,
            descriptor_type=2,
            key_info=key_info_msg3,
            key_length=16,
            replay_counter=auth_state.replay_counter,
            nonce=auth_state.anonce,
            iv=b'\x00' * 16,
            rsc=0,
            mic=b'\x00' * 16,
            key_data=wrapped_gtk_kde,
        )
        msg3_zeroed = msg3.encode_with_zeroed_mic()
        msg3.mic = compute_mic(ptk.kck, msg3_zeroed)
        msg3_bytes = msg3.encode()

        if send_data_client:
          self._send_eapol_frame_to_station(
              station_id, target_ap.bssid, station.mac_addr, msg3_bytes
          )
        return True, msg3_bytes

      elif auth_state.state == 'WAIT_MSG4':
        # Msg4: Pairwise, MIC, Secure, Replay Counter matches Msg3
        if frame.replay_counter != auth_state.replay_counter:
          logger.warning(
              'Msg4 replay counter mismatch: %d != %d',
              frame.replay_counter,
              auth_state.replay_counter,
          )
          return False, None

        if auth_state.ptk is None:
          return False, None

        msg4_zeroed = frame.encode_with_zeroed_mic()
        if not verify_mic(auth_state.ptk.kck, msg4_zeroed, frame.mic):
          logger.warning('Msg4 MIC verification failed for %s', station_id)
          station.state = 'disconnected'
          self._auth_states.pop(station_id, None)
          return False, None

        station.state = 'completed'
        auth_state.state = 'COMPLETED'
        logger.info(
            'Station %s completed genuine WPA2 4-way handshake with AP %s',
            station_id,
            target_ap.ap_id,
        )
        return True, None

      logger.warning(
          'Unrecognized or out-of-order EAPOL frame from %s', station_id
      )
      return False, None

  def authenticate_and_associate(
      self, station_id: str, ssid: str, psk: str
  ) -> Dict[str, object]:
    """Performs 802.11 Authentication + WPA2-PSK 4-Way Handshake (DEPRECATED).

    Directly passing station passphrases to the AP medium is prohibited by the
    passphrase-isolation invariant. Handshake must be performed over the L2 data
    socket via EAPOL frames (Ethertype 0x888E).
    """
    raise RuntimeError(
        'Passphrase isolation invariant: authenticate_and_associate is'
        ' disabled. Use connect RPC and drive genuine 4-way handshake over'
        ' data_port via EAPOL.'
    )

  def disconnect_station(
      self, station_id: str, reason: str = 'disconnected'
  ) -> Dict[str, object]:
    with self._lock:
      self._auth_states.pop(station_id, None)
      station = self._stations.get(station_id)
      if station is not None:
        station.state = 'disconnected'
        station.disconnect_reason = str(reason)
        station.associated_ap_id = ''
        station.associated_ssid = ''
        station.associated_bssid = ''
      stale_macs = [
          mac for mac, sid in self._mac_to_station.items() if sid == station_id
      ]
      for mac in stale_macs:
        self._mac_to_station.pop(mac, None)
      return {'ok': True}

  def reassociate_station(
      self, station_id: str, ap_id: Optional[str] = None
  ) -> VirtualWiFiStationState:
    """Re-associates a disconnected station and completes WPA2 auth."""
    with self._lock:
      station = self._stations.get(station_id)
      if station is None:
        raise ValueError(f'Unknown Wi-Fi station: {station_id}')
      target_ap = (
          self._aps.get(ap_id)
          if ap_id
          else next(iter(self._aps.values()), None)
      )
      mac_bytes = bytes.fromhex(station.mac_addr.replace(':', ''))
      self._mac_to_station[mac_bytes] = station_id
      if target_ap is None or station.is_ap_bridge:
        station.state = 'completed'
        station.disconnect_reason = ''
        return station
      resolved_ap_id = target_ap.ap_id
      ssid = target_ap.ssid
      psk = target_ap.psk
      bssid = target_ap.bssid
      sta_mac = station.mac_addr

    from cirque.virtual_wifi.wpa2_supplicant_sm import (
        Wpa2SupplicantStateMachine,
    )

    msg1 = self.initiate_eapol_handshake(
        station_id, resolved_ap_id, send_data_client=False
    )
    if msg1 is not None:
      sent_frames: List[bytes] = []
      supp = Wpa2SupplicantStateMachine(
          sta_mac, on_send_frame=sent_frames.append
      )
      supp.start_association(ssid, psk, bssid)
      if supp.handle_eapol_frame(msg1) and sent_frames:
        msg2 = sent_frames.pop(0)
        ok2, msg3 = self.process_eapol_frame(
            station_id, msg2, send_data_client=False
        )
        if ok2 and msg3 is not None and supp.handle_eapol_frame(msg3):
          if sent_frames:
            msg4 = sent_frames.pop(0)
            self.process_eapol_frame(station_id, msg4, send_data_client=False)
    with self._lock:
      station.state = 'completed'
      station.disconnect_reason = ''
      self._mac_to_station[mac_bytes] = station_id
      return station

  def _accept_loop(self, srv: socket.socket, handler) -> None:
    while self._running:
      try:
        client_sock, _ = srv.accept()
      except OSError:
        break
      threading.Thread(target=handler, args=(client_sock,), daemon=True).start()

  def _recv_exact(self, sock: socket.socket, num_bytes: int) -> Optional[bytes]:
    buffer = bytearray()
    while len(buffer) < num_bytes:
      chunk = sock.recv(num_bytes - len(buffer))
      if not chunk:
        return None
      buffer.extend(chunk)
    return bytes(buffer)

  def _relay_l2_frame(self, station_id: str, frame: bytes) -> None:
    """Forwards an Ethernet frame between WPA2-authenticated stations.

    Security & Isolation Invariant:
      - Intercepts 802.1X EAPOL frames (Ethertype 0x888E) destined for AP to
      drive
        the WPA2 Authenticator state machine without requiring prior auth.
      - Unassociated stations (`state != 'completed'`) have their L2 switch
        port locked for non-EAPOL frames: any data frame sent by or destined for
        an unauthenticated station is silently dropped.
      - This guarantees that a Matter node cannot exchange ARP, ICMPv6, mDNS,
        or Operational CASE (`UDP/5540`) packets over `wlan0` until BLE
        commissioning completes `AddOrUpdateWiFiNetwork` + `ConnectNetwork`.
    """
    fixed_frame = fix_l4_checksum(frame)
    out_pkt = struct.pack('!H', len(fixed_frame)) + fixed_frame
    target_socks: List[socket.socket] = []

    # Intercept EAPOL frames (Ethertype 0x888E) at offset 12..14
    if len(frame) >= 14 and frame[12:14] == b'\x88\x8e':
      eapol_payload = frame[14:]
      if self._pcap_medium_writer is not None:
        self._pcap_medium_writer.write_frame(frame)
      if self._pcap_ap_writer is not None:
        self._pcap_ap_writer.write_frame(frame)
      sta_w = self._get_or_create_sta_pcap_writer(station_id)
      if sta_w is not None:
        sta_w.write_frame(frame)
      self.process_eapol_frame(station_id, eapol_payload)
      return

    with self._lock:
      src_st = self._stations.get(station_id)
      if src_st is not None:
        src_st.tx_packets += 1
        if src_st.state != 'completed':
          return

      if (
          self._rf_simulator is not None
          and self._rf_simulator.config.enabled
          and station_id not in _NON_LEARNING_STATION_IDS
      ):
        ap_obj = next(iter(self._aps.values()), None)
        ap_ch = ap_obj.channel if ap_obj is not None else 6
        rf_sample = self._rf_simulator.evaluate_packet(
            'wifi',
            station_id,
            'wifi_ap',
            channel=ap_ch,
            frame_len_bytes=len(frame),
            record_telemetry=True,
        )
        if src_st is not None:
          src_st.rssi_dbm = rf_sample.rssi_dbm
          src_st.noise_dbm = rf_sample.noise_floor_dbm
          src_st.sinr_db = rf_sample.sinr_db
          src_st.rf_sampled = True
        ethertype = (
            struct.unpack('!H', frame[12:14])[0] if len(frame) >= 14 else 0
        )
        is_nd_or_arp = ethertype == 0x0806 or (
            ethertype == 0x86DD
            and len(frame) >= 58
            and frame[20] == 58
            and frame[54] in (133, 134, 135, 136)
        )
        if rf_sample.dropped and not is_nd_or_arp:
          self._dropped_rf_frames += 1
          if src_st is not None:
            src_st.dropped_rf_frames += 1
          return

      peer_pool = self._data_clients if self._data_clients else self._stations
      candidate_peer_ids: List[str] = []
      if len(frame) >= 14:
        src_mac = frame[6:12]
        learnable = station_id not in _NON_LEARNING_STATION_IDS
        if (src_mac[0] & 0x01) == 0 and learnable:
          self._mac_to_station[src_mac] = station_id

        dst_mac = frame[0:6]
        if (dst_mac[0] & 0x01) == 0 and dst_mac in self._mac_to_station:
          learned_peer = self._mac_to_station[dst_mac]
          if learned_peer != station_id and learned_peer in peer_pool:
            candidate_peer_ids = [learned_peer]
          else:
            candidate_peer_ids = []
        else:
          candidate_peer_ids = [pid for pid in peer_pool if pid != station_id]
      else:
        candidate_peer_ids = [pid for pid in peer_pool if pid != station_id]

      delivered_any = False
      for peer_id in candidate_peer_ids:
        dst_st = self._stations.get(peer_id)
        if dst_st is not None and dst_st.state != 'completed':
          continue
        if dst_st is not None:
          # Link metrics stay per station: each one comes from that station's
          # own RF samples, never from the transmitting peer's uplink.
          dst_st.rx_packets += 1
          delivered_any = True
        peer_sock = self._data_clients.get(peer_id)
        if peer_sock is not None:
          target_socks.append(peer_sock)
          delivered_any = True

      writers_to_record: List[Any] = []
      if delivered_any:
        self._relayed_data_frames += 1
        if src_st is not None:
          src_st.relayed_data_frames += 1
        if _is_udp5540_frame(fixed_frame):
          self._relayed_udp5540_frames += 1
          if src_st is not None:
            src_st.relayed_udp5540_frames += 1
        if self._pcap_medium_writer is not None:
          writers_to_record.append(self._pcap_medium_writer)
        src_w = self._get_or_create_sta_pcap_writer(station_id)
        if src_w is not None:
          writers_to_record.append(src_w)
        for peer_id in candidate_peer_ids:
          dst_st = self._stations.get(peer_id)
          if dst_st is not None and dst_st.state == 'completed':
            peer_w = self._get_or_create_sta_pcap_writer(peer_id)
            if peer_w is not None:
              writers_to_record.append(peer_w)

    for w in writers_to_record:
      try:
        w.write_frame(fixed_frame)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.debug('PCAP write_frame failed: %s', exc)

    for peer_sock in target_socks:
      send_lock = self._get_socket_send_lock(peer_sock)
      try:
        with send_lock:
          peer_sock.sendall(out_pkt)
      except OSError:
        pass

  def _cleanup_data_client(
      self, station_id: str, client_sock: socket.socket
  ) -> None:
    with self._lock:
      self._socket_send_locks.pop(client_sock, None)
    if station_id:
      with self._lock:
        sock_list = self._station_sockets.get(station_id)
        if sock_list is not None:
          self._station_sockets[station_id] = [
              s for s in sock_list if s is not client_sock
          ]
          if not self._station_sockets[station_id]:
            self._station_sockets.pop(station_id, None)
        if self._data_clients.get(station_id) is client_sock:
          remaining = self._station_sockets.get(station_id)
          if remaining:
            self._data_clients[station_id] = remaining[-1]
          else:
            self._data_clients.pop(station_id, None)
    try:
      client_sock.close()
    except OSError:
      pass

  def _handle_data_client(self, client_sock: socket.socket) -> None:
    """Relays L2 Ethernet frames between associated stations on data_port.

    Wire framing on `data_port`:
      1. Handshake packet: `[StationIdLen:2B BE][StationId UTF-8 bytes]`
      2. Ethernet stream : `[FrameLen:2B BE][Raw Ethernet II frame bytes]...`
    """
    station_id = ''
    try:
      client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
      hdr = self._recv_exact(client_sock, 2)
      if not hdr:
        return
      hello_bytes = self._recv_exact(client_sock, struct.unpack('!H', hdr)[0])
      if not hello_bytes:
        return
      station_id = hello_bytes.decode('utf-8', errors='replace').strip()
      with self._lock:
        self._station_sockets.setdefault(station_id, []).append(client_sock)
        self._data_clients[station_id] = client_sock
        if station_id not in self._stations:
          self.register_station(station_id)
      while self._running:
        fhdr = self._recv_exact(client_sock, 2)
        if not fhdr:
          break
        flen = struct.unpack('!H', fhdr)[0]
        if flen == 0:
          continue
        frame = self._recv_exact(client_sock, flen)
        if not frame:
          break
        self._relay_l2_frame(station_id, frame)
    except OSError:
      pass
    finally:
      self._cleanup_data_client(station_id, client_sock)

  def _process_json_stream(self, client_sock: socket.socket) -> None:
    f_in = client_sock.makefile('r', encoding='utf-8')
    for raw_line in f_in:
      line = raw_line.strip()
      if line:
        resp = self._dispatch_rpc(json.loads(line))
        client_sock.sendall((json.dumps(resp) + '\n').encode('utf-8'))

  def _handle_json_client(self, client_sock: socket.socket) -> None:
    try:
      self._process_json_stream(client_sock)
    except (OSError, ValueError, json.JSONDecodeError):
      pass
    finally:
      client_sock.close()

  def _rpc_register_ap(self, req: Dict[str, object]) -> Dict[str, object]:
    ap_state = self.register_ap(
        str(req.get('ssid', '')),
        str(req.get('psk', '')),
        ap_id=req.get('ap_id'),
        bssid=req.get('bssid'),
        frequency=int(req.get('frequency', 2437)),
        channel=int(req.get('channel', 6)),
        signal=int(req.get('signal', -40)),
    )
    return {'ok': True, 'ap': ap_state.to_public_dict()}

  def _rpc_register_station(self, req: Dict[str, object]) -> Dict[str, object]:
    station = self.register_station(
        str(req.get('station_id', 'wifi0')),
        mac_addr=req.get('mac') or req.get('mac_addr'),
        ipv4_addr=str(req.get('ipv4_addr', '')),
        ipv6_addr=str(req.get('ipv6_addr', '')),
        is_ap_bridge=bool(req.get('is_ap_bridge', False)),
    )
    if req.get('auto_connect') and self.list_aps():
      ap0 = self.list_aps()[0]
      self.initiate_eapol_handshake(
          station.station_id, ap0.ap_id, send_data_client=True
      )
    return {'ok': True, 'station': asdict(station)}

  def _rpc_connect(self, req: Dict[str, object]) -> Dict[str, object]:
    station_id = str(req.get('station_id', 'wifi0'))
    ssid = str(req.get('ssid', ''))
    ap_id = str(req.get('ap_id', ''))
    # Passphrase isolation: psk in connect RPC is strictly ignored and never stored.
    # Handshake will be conducted over data_port via EAPOL frames (Ethertype 0x888E).
    with self._lock:
      target_ap = None
      if ap_id:
        target_ap = self._aps.get(ap_id)
      if target_ap is None and ssid:
        target_ap = next(
            (ap for ap in self._aps.values() if ap.ssid == ssid), None
        )
      if target_ap is None:
        return {'ok': False, 'reason': 'ap_not_found'}
      target_ap_id = target_ap.ap_id
      target_ap_dict = target_ap.to_public_dict()

    msg1_bytes = self.initiate_eapol_handshake(
        station_id, target_ap_id, send_data_client=True
    )
    if msg1_bytes is None:
      return {'ok': False, 'reason': 'initiate_failed'}
    return {
        'ok': True,
        'status': 'handshake_initiated',
        'ap': target_ap_dict,
    }

  def _rpc_disconnect(self, req: Dict[str, object]) -> Dict[str, object]:
    return self.disconnect_station(str(req.get('station_id', 'wifi0')))

  def _rpc_initiate_eapol(self, req: Dict[str, object]) -> Dict[str, object]:
    station_id = str(req.get('station_id', 'wifi0'))
    ap_id = str(req.get('ap_id', 'ap0'))
    msg1_bytes = self.initiate_eapol_handshake(
        station_id, ap_id, send_data_client=False
    )
    if msg1_bytes is None:
      return {'ok': False, 'reason': 'initiate_failed'}
    return {'ok': True, 'msg1_hex': msg1_bytes.hex()}

  def _rpc_process_eapol(self, req: Dict[str, object]) -> Dict[str, object]:
    station_id = str(req.get('station_id', 'wifi0'))
    eapol_hex = str(req.get('eapol_hex', ''))
    eapol_bytes = bytes.fromhex(eapol_hex)
    ok, resp_bytes = self.process_eapol_frame(
        station_id, eapol_bytes, send_data_client=False
    )
    return {
        'ok': ok,
        'resp_hex': resp_bytes.hex() if resp_bytes else '',
    }

  def _rpc_get_state(self, req: Dict[str, object]) -> Dict[str, object]:
    st = self.get_station(str(req.get('station_id', 'wifi0')))
    return {'ok': st is not None, 'station': asdict(st) if st else {}}

  def _dispatch_rpc(self, req: Dict[str, object]) -> Dict[str, object]:
    cmd = str(req.get('cmd', '')).strip().lower()
    dispatch_table = {
        'register_ap': lambda: self._rpc_register_ap(req),
        'register_station': lambda: self._rpc_register_station(req),
        'list_aps': lambda: {
            'ok': True,
            'aps': [a.to_public_dict() for a in self.list_aps()],
        },
        'scan': lambda: {
            'ok': True,
            'aps': [a.to_public_dict() for a in self.list_aps()],
        },
        'list_stations': lambda: {
            'ok': True,
            'stations': [asdict(s) for s in self.list_stations()],
        },
        'authenticate': lambda: self._rpc_connect(req),
        'connect': lambda: self._rpc_connect(req),
        'initiate_eapol': lambda: self._rpc_initiate_eapol(req),
        'process_eapol': lambda: self._rpc_process_eapol(req),
        'disconnect_station': lambda: self._rpc_disconnect(req),
        'disconnect': lambda: self._rpc_disconnect(req),
        'get_state': lambda: self._rpc_get_state(req),
        'get_frame_counters': lambda: {
            'ok': True,
            'counters': self.get_frame_counters(),
        },
        'get_counters': lambda: {
            'ok': True,
            'counters': self.get_frame_counters(),
        },
        'reset_frame_counters': lambda: (
            self.reset_frame_counters(),
            {'ok': True},
        )[1],
        'reset_counters': lambda: (
            self.reset_frame_counters(),
            {'ok': True},
        )[1],
        'get_status': lambda: {
            'ok': True,
            'aps': [a.to_public_dict() for a in self.list_aps()],
            'stations': [asdict(s) for s in self.list_stations()],
        },
    }
    handler = dispatch_table.get(cmd)
    if handler is not None:
      return handler()
    return {'ok': False, 'error': f'unknown_cmd:{cmd}'}
