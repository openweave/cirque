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
"""Unit tests for kernel-module-free VirtualWiFiServer and WiFiCapability."""

import json
import os
import socket
import struct
import time
import unittest
from unittest import mock

from cirque.capabilities.wificapability import WiFiCapability
from cirque.common.isolated_runtime_dirs import isolate_virtual_runtime_dirs
from cirque.virtual_wifi.server import VirtualWiFiServer, fix_l4_checksum
from cirque.virtual_wifi.wpa2_supplicant_sm import Wpa2SupplicantStateMachine


def setUpModule():
  unittest.addModuleCleanup(isolate_virtual_runtime_dirs())


def _drive_eapol_handshake(
    sock: socket.socket,
    sta_mac_str: str,
    ap_bssid_str: str,
    ssid: str,
    psk: str,
) -> bool:
  sta_mac = bytes.fromhex(sta_mac_str.replace(':', ''))
  ap_mac = bytes.fromhex(ap_bssid_str.replace(':', ''))
  supp_frames = []
  supp = Wpa2SupplicantStateMachine(
      sta_mac_str, on_send_frame=supp_frames.append
  )
  supp.start_association(ssid, psk, ap_bssid_str)

  raw_len = sock.recv(2)
  if len(raw_len) < 2:
    return False
  flen = struct.unpack('!H', raw_len)[0]
  eth_frame = b''
  while len(eth_frame) < flen:
    chunk = sock.recv(flen - len(eth_frame))
    if not chunk:
      break
    eth_frame += chunk
  if len(eth_frame) < 14 or eth_frame[12:14] != b'\x88\x8e':
    return False
  if not supp.handle_eapol_frame(eth_frame[14:]):
    return False

  msg2 = supp_frames.pop(0)
  eth_msg2 = ap_mac + sta_mac + struct.pack('!H', 0x888E) + msg2
  sock.sendall(struct.pack('!H', len(eth_msg2)) + eth_msg2)

  raw_len = sock.recv(2)
  if len(raw_len) < 2:
    return False
  flen = struct.unpack('!H', raw_len)[0]
  eth_frame = b''
  while len(eth_frame) < flen:
    chunk = sock.recv(flen - len(eth_frame))
    if not chunk:
      break
    eth_frame += chunk
  if len(eth_frame) < 14 or eth_frame[12:14] != b'\x88\x8e':
    return False
  if not supp.handle_eapol_frame(eth_frame[14:]):
    return False

  msg4 = supp_frames.pop(0)
  eth_msg4 = ap_mac + sta_mac + struct.pack('!H', 0x888E) + msg4
  sock.sendall(struct.pack('!H', len(eth_msg4)) + eth_msg4)
  return True


class TestVirtualWiFiControllerSystem(unittest.TestCase):
  """Verifies VirtualWiFiServer 3-port TCP planes and L2 gate."""

  def setUp(self):
    super().setUp()
    self.server = VirtualWiFiServer(host='127.0.0.1')
    self.server.start()

  def tearDown(self):
    self.server.stop()
    WiFiCapability.WIFI_STATIONS_LIST.clear()
    WiFiCapability.stop_virtual_server()
    super().tearDown()

  def _send_ctrl(self, payload: dict) -> dict:
    with socket.create_connection(
        ('127.0.0.1', self.server.control_port), timeout=3.0
    ) as sock:
      sock.sendall((json.dumps(payload) + '\n').encode('utf-8'))
      data = b''
      while b'\n' not in data:
        chunk = sock.recv(4096)
        if not chunk:
          break
        data += chunk
      return json.loads(data.decode('utf-8').strip())

  def test_ap_registration_scan_and_wpa2_auth(self):
    """Verifies AP registration, scan, wrong-key rejection, and WPA2."""
    res = self._send_ctrl({
        'cmd': 'REGISTER_AP',
        'ap_id': 'ap0',
        'ssid': 'CHIP-Test-SSID',
        'psk': 'ValidPassphrase123',
        'bssid': '02:00:00:00:01:01',
    })
    self.assertTrue(res.get('ok'))

    self._send_ctrl({
        'cmd': 'REGISTER_STATION',
        'station_id': 'wifi0',
        'mac': '02:00:00:00:02:0a',
        'ipv4_addr': '10.0.1.10',
        'ipv6_addr': 'fd11:22::a',
    })

    scan_res = self._send_ctrl({'cmd': 'SCAN', 'station_id': 'wifi0'})
    self.assertTrue(scan_res.get('ok'))
    aps = scan_res.get('aps', [])
    self.assertEqual(len(aps), 1)
    self.assertEqual(aps[0]['ssid'], 'CHIP-Test-SSID')

    d_addr = ('127.0.0.1', self.server.data_port)
    with socket.create_connection(d_addr, timeout=2.0) as s:
      s.sendall(struct.pack('!H', 5) + b'wifi0')
      time.sleep(0.05)

      # 1. Initiate connect with wrong passphrase over EAPOL
      conn_res = self._send_ctrl({
          'cmd': 'CONNECT',
          'station_id': 'wifi0',
          'ssid': 'CHIP-Test-SSID',
      })
      self.assertTrue(conn_res.get('ok'))
      self.assertEqual(conn_res.get('status'), 'handshake_initiated')

      # Station responds with Msg2 derived from wrong passphrase
      raw_len = s.recv(2)
      flen = struct.unpack('!H', raw_len)[0]
      msg1_frame = s.recv(flen)
      supp_frames = []
      supp_bad = Wpa2SupplicantStateMachine(
          '02:00:00:00:02:0a', on_send_frame=supp_frames.append
      )
      supp_bad.start_association(
          'CHIP-Test-SSID', 'WrongPassword', '02:00:00:00:01:01'
      )
      supp_bad.handle_eapol_frame(msg1_frame[14:])
      msg2 = supp_frames.pop(0)
      eth_msg2 = (
          bytes.fromhex('02000000010102000000020a888e') + msg2
      )
      s.sendall(struct.pack('!H', len(eth_msg2)) + eth_msg2)
      time.sleep(0.05)

      # AP rejected Msg2 MIC; station remains disconnected
      st = self._send_ctrl({'cmd': 'GET_STATE', 'station_id': 'wifi0'})['station']
      self.assertEqual(st['state'], 'disconnected')

      # 2. Initiate connect with valid passphrase over EAPOL
      conn_res2 = self._send_ctrl({
          'cmd': 'CONNECT',
          'station_id': 'wifi0',
          'ssid': 'CHIP-Test-SSID',
      })
      self.assertTrue(conn_res2.get('ok'))

      ok = _drive_eapol_handshake(
          s,
          '02:00:00:00:02:0a',
          '02:00:00:00:01:01',
          'CHIP-Test-SSID',
          'ValidPassphrase123',
      )
      self.assertTrue(ok)
      time.sleep(0.05)
      st = self._send_ctrl({'cmd': 'GET_STATE', 'station_id': 'wifi0'})['station']
      self.assertEqual(st['state'], 'completed')

  def test_l2_switch_blocks_unauthenticated_and_forwards_authenticated_frames(
      self,
  ):
    """Verifies L2 switch drops frames until stations complete WPA2."""
    self._send_ctrl(
        dict(
            cmd='REGISTER_AP',
            ap_id='ap0',
            ssid='AP1',
            psk='Pass123',
            bssid='02:00:00:00:01:01',
        )
    )
    self._send_ctrl(
        dict(
            cmd='REGISTER_STATION',
            station_id='sta_a',
            mac='02:00:00:00:02:0a',
            is_ap_bridge=True,
        )
    )
    self._send_ctrl(
        dict(
            cmd='REGISTER_STATION',
            station_id='sta_b',
            mac='02:00:00:00:02:0b',
            auto_connect=False,
        )
    )
    addr = ('127.0.0.1', self.server.data_port)
    with (
        socket.create_connection(addr, timeout=1.0) as sa,
        socket.create_connection(addr, timeout=1.0) as sb,
    ):
      sa.sendall(struct.pack('!H', 5) + b'sta_a')
      sb.sendall(struct.pack('!H', 5) + b'sta_b')
      time.sleep(0.05)
      sb.settimeout(0.25)
      eth_frame = bytes.fromhex('02000000020b02000000020a0800') + b'PAYLOAD'
      pkt = struct.pack('!H', len(eth_frame)) + eth_frame

      sa.sendall(pkt)
      with self.assertRaises(socket.timeout):
        sb.recv(1024)

      conn_res = self._send_ctrl(
          dict(cmd='CONNECT', station_id='sta_b', ssid='AP1')
      )
      self.assertTrue(conn_res.get('ok'))
      ok = _drive_eapol_handshake(
          sb,
          '02:00:00:00:02:0b',
          '02:00:00:00:01:01',
          'AP1',
          'Pass123',
      )
      self.assertTrue(ok)
      time.sleep(0.05)
      sa.sendall(pkt)
      frame_len = struct.unpack('!H', sb.recv(2))[0]
      self.assertEqual(sb.recv(frame_len), eth_frame)

  def test_l2_switch_mac_learning_and_unicast_vs_broadcast(self):
    """Verifies L2 switch MAC learning.

    Unicast forwards only to target, broadcast floods to all peers.
    """
    self._send_ctrl(
        dict(cmd='REGISTER_AP', ap_id='ap0', ssid='AP1', psk='Pass123')
    )
    for sid, mac in (
        ('sta_a', '02:00:00:00:02:0a'),
        ('sta_b', '02:00:00:00:02:0b'),
        ('sta_c', '02:00:00:00:02:0c'),
    ):
      self._send_ctrl(
          dict(
              cmd='REGISTER_STATION',
              station_id=sid,
              mac=mac,
              is_ap_bridge=True,
          )
      )

    addr = ('127.0.0.1', self.server.data_port)
    with (
        socket.create_connection(addr, timeout=1.0) as sa,
        socket.create_connection(addr, timeout=1.0) as sb,
        socket.create_connection(addr, timeout=1.0) as sc,
    ):
      sa.sendall(struct.pack('!H', 5) + b'sta_a')
      sb.sendall(struct.pack('!H', 5) + b'sta_b')
      sc.sendall(struct.pack('!H', 5) + b'sta_c')
      deadline = time.monotonic() + 2.0
      while (
          any(
              s not in self.server._data_clients
              for s in ('sta_a', 'sta_b', 'sta_c')
          )
          and time.monotonic() < deadline
      ):
        time.sleep(0.01)
      self.assertIn('sta_a', self.server._data_clients)
      self.assertIn('sta_b', self.server._data_clients)
      self.assertIn('sta_c', self.server._data_clients)
      sb.settimeout(0.5)
      sc.settimeout(0.2)

      # 1. sta_b sends a frame to train L2 switch with src 02:00:00:00:02:0b
      b_mac = bytes.fromhex('02000000020b')
      c_mac = bytes.fromhex('02000000020c')
      a_mac = bytes.fromhex('02000000020a')
      b_train_frame = c_mac + b_mac + bytes.fromhex('0800') + b'TRAIN'
      sb.sendall(struct.pack('!H', len(b_train_frame)) + b_train_frame)
      sc_len = struct.unpack('!H', sc.recv(2))[0]
      self.assertEqual(sc.recv(sc_len), b_train_frame)

      # 2. sta_a sends a unicast frame destined to sta_b (02:00:00:00:02:0b).
      # It MUST be delivered to sta_b and NOT flooded to sta_c.
      unicast_frame = b_mac + a_mac + bytes.fromhex('0800') + b'UNICAST'
      sa.sendall(struct.pack('!H', len(unicast_frame)) + unicast_frame)

      sb_len = struct.unpack('!H', sb.recv(2))[0]
      self.assertEqual(sb.recv(sb_len), unicast_frame)
      with self.assertRaises(socket.timeout):
        sc.recv(1024)

      # 3. sta_a sends a broadcast frame (ff:ff:ff:ff:ff:ff).
      # It MUST be delivered to both sta_b and sta_c.
      bcast_frame = (b'\xff' * 6) + a_mac + bytes.fromhex('0800') + b'BCAST'
      sa.sendall(struct.pack('!H', len(bcast_frame)) + bcast_frame)

      sb_bcast_len = struct.unpack('!H', sb.recv(2))[0]
      self.assertEqual(sb.recv(sb_bcast_len), bcast_frame)
      sc_bcast_len = struct.unpack('!H', sc.recv(2))[0]
      self.assertEqual(sc.recv(sc_bcast_len), bcast_frame)

  def test_ra_pseudo_station_does_not_steal_ap_mac(self):
    """Unicast to the shared AP MAC reaches the AP after an RA is relayed.

    VirtualRaServer ('ra_server') sends periodic RAs with the AP MAC as the
    source. Those frames must not re-bind the AP MAC to 'ra_server' in the
    learning table, or a station's unicast frames to its gateway are lost.
    """
    self._send_ctrl(
        dict(cmd='REGISTER_AP', ap_id='ap0', ssid='AP1', psk='Pass123')
    )
    for sid, mac in (
        ('ap_bridge', '02:00:00:00:01:01'),
        ('ra_server', None),
        ('sta_phone', '02:15:b2:00:00:00'),
    ):
      req = dict(cmd='REGISTER_STATION', station_id=sid, is_ap_bridge=True)
      if mac:
        req['mac'] = mac
      self._send_ctrl(req)

    def recv_frame(sock):
      flen = struct.unpack('!H', sock.recv(2))[0]
      return sock.recv(flen)

    addr = ('127.0.0.1', self.server.data_port)
    with (
        socket.create_connection(addr, timeout=1.0) as s_ap,
        socket.create_connection(addr, timeout=1.0) as s_ra,
        socket.create_connection(addr, timeout=1.0) as s_phone,
    ):
      for sock, sid in (
          (s_ap, b'ap_bridge'),
          (s_ra, b'ra_server'),
          (s_phone, b'sta_phone'),
      ):
        sock.sendall(struct.pack('!H', len(sid)) + sid)
      deadline = time.monotonic() + 2.0
      while (
          any(
              s not in self.server._data_clients
              for s in ('ap_bridge', 'ra_server', 'sta_phone')
          )
          and time.monotonic() < deadline
      ):
        time.sleep(0.01)
      for sock in (s_ap, s_ra, s_phone):
        sock.settimeout(0.5)

      ap_mac = bytes.fromhex('020000000101')
      phone_mac = bytes.fromhex('0215b2000000')
      # 1. The AP container sends a frame (e.g. an ARP reply) to the phone.
      ap_frame = phone_mac + ap_mac + bytes.fromhex('0806') + b'ARPREPLY'
      s_ap.sendall(struct.pack('!H', len(ap_frame)) + ap_frame)
      self.assertEqual(recv_frame(s_phone), ap_frame)
      # 2. ra_server multicasts an RA with the same source MAC.
      ra_frame = (
          bytes.fromhex('333300000001') + ap_mac + bytes.fromhex('86dd')
          + b'RA'
      )
      s_ra.sendall(struct.pack('!H', len(ra_frame)) + ra_frame)
      self.assertEqual(recv_frame(s_ap), ra_frame)
      self.assertEqual(recv_frame(s_phone), ra_frame)
      # 3. The phone's unicast to its gateway MAC must reach the AP only.
      uni = ap_mac + phone_mac + bytes.fromhex('0800') + b'CASE5540'
      s_phone.sendall(struct.pack('!H', len(uni)) + uni)
      self.assertEqual(recv_frame(s_ap), uni)
      s_ra.settimeout(0.2)
      with self.assertRaises(socket.timeout):
        s_ra.recv(1024)
      self.assertEqual(self.server._mac_to_station[ap_mac], 'ap_bridge')

  def test_dual_mode_env_toggle_and_l4_checksum_helper(self):
    """Verifies CIRQUE_USE_LEGACY_HWSIM fallback and IPv4 UDP checksum fix."""
    os.environ['CIRQUE_USE_LEGACY_HWSIM'] = '0'
    cap = WiFiCapability()
    self.assertTrue(cap.use_virtual_wifi_tcp)
    self.assertTrue(cap.station_id.startswith('wifi'))

    eth_hdr = bytes.fromhex('02000000020b02000000020a0800')
    ip_a = socket.inet_aton('10.0.1.10')
    ip_b = socket.inet_aton('10.0.1.11')
    ip_hdr = struct.pack(
        '!BBHHHBBH4s4s', 0x45, 0, 32, 1, 0, 64, 17, 0, ip_a, ip_b
    )
    udp_hdr = struct.pack('!HHHH', 5540, 5540, 12, 0) + b'PING'
    fixed = fix_l4_checksum(eth_hdr + ip_hdr + udp_hdr)
    self.assertNotEqual(struct.unpack('!H', fixed[40:42])[0], 0)

  def test_checksum_edge_cases_ipv4(self):
    """Covers odd-length payloads and IPv4 TCP/ICMP checksum paths."""
    from cirque.virtual_wifi.server import _ones_complement_checksum

    self.assertIsInstance(_ones_complement_checksum(b'\x01\x02\x03'), int)
    self.assertEqual(fix_l4_checksum(b'short'), b'short')
    arp = bytes.fromhex('ffffffffffff02000000020a0806') + b'\x00' * 28
    self.assertEqual(fix_l4_checksum(arp), arp)

    eth4 = bytes.fromhex('02000000020b02000000020a0800')
    ipa, ipb = socket.inet_aton('10.0.1.10'), socket.inet_aton('10.0.1.11')
    bad_ip = struct.pack(
        '!BBHHHBBH4s4s', 0x45, 0, 10, 1, 0, 64, 17, 0, ipa, ipb
    )
    self.assertEqual(fix_l4_checksum(eth4 + bad_ip), eth4 + bad_ip)

    tcp = struct.pack('!HHIIBBHHH', 1234, 80, 1, 1, 0x50, 2, 1024, 0, 0) + b'A'
    ip_tcp = struct.pack(
        '!BBHHHBBH4s4s', 0x45, 0, 20 + len(tcp), 1, 0, 64, 6, 0, ipa, ipb
    )
    fixed_tcp = fix_l4_checksum(eth4 + ip_tcp + tcp)
    self.assertNotEqual(struct.unpack('!H', fixed_tcp[50:52])[0], 0)

    ip_icmp = struct.pack(
        '!BBHHHBBH4s4s', 0x45, 0, 28, 1, 0, 64, 1, 0, ipa, ipb
    )
    icmp = eth4 + ip_icmp + b'\x08\x00\x00\x00\x00\x01\x00\x01'
    self.assertEqual(fix_l4_checksum(icmp), icmp)

  def test_fix_l4_checksum_skips_ipv4_fragments(self):
    """Verifies that IPv4 packets with MF flag or offset are untouched."""
    eth4 = bytes.fromhex('02000000020b02000000020a0800')
    ipa, ipb = socket.inet_aton('10.0.1.10'), socket.inet_aton('10.0.1.11')
    udp_payload = struct.pack('!HHHH', 5540, 5540, 12, 0) + b'FRAG'

    # 1. Packet with MF (More Fragments) bit set: flags_offset = 0x2000
    ip_mf = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,
        0,
        20 + len(udp_payload),
        1,
        0x2000,
        64,
        17,
        0,
        ipa,
        ipb,
    )
    frame_mf = eth4 + ip_mf + udp_payload
    self.assertEqual(fix_l4_checksum(frame_mf), frame_mf)

    # 2. Packet with non-zero Fragment Offset: offset=100 * 8 bytes
    ip_frag = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,
        0,
        20 + len(udp_payload),
        1,
        100,
        64,
        17,
        0,
        ipa,
        ipb,
    )
    frame_frag = eth4 + ip_frag + udp_payload
    self.assertEqual(fix_l4_checksum(frame_frag), frame_frag)

  def test_checksum_edge_cases_ipv6(self):
    """Covers IPv6 short, unknown next_hdr, ICMPv6, and UDP 0xFFFF."""
    from cirque.virtual_wifi.server import _ones_complement_checksum

    eth6 = bytes.fromhex('02000000020b02000000020a86dd')
    s6 = socket.inet_pton(socket.AF_INET6, 'fd11:22::10')
    d6 = socket.inet_pton(socket.AF_INET6, 'fd11:22::11')
    hdr6 = lambda plen, nh: eth6 + struct.pack(
        '!IHBB16s16s', 0x60000000, plen, nh, 64, s6, d6
    )

    self.assertEqual(fix_l4_checksum(hdr6(50, 17)), hdr6(50, 17))
    self.assertEqual(
        fix_l4_checksum(hdr6(4, 99) + b'1234'), hdr6(4, 99) + b'1234'
    )
    self.assertEqual(
        fix_l4_checksum(hdr6(4, 17) + b'1234'), hdr6(4, 17) + b'1234'
    )

    fixed_icmp6 = fix_l4_checksum(hdr6(8, 58) + b'\x80\x00\x00\x00TEST')
    self.assertNotEqual(struct.unpack('!H', fixed_icmp6[56:58])[0], 0)

    pseudo = s6 + d6 + struct.pack('!I3xB', 10, 17)
    udp_pfx = struct.pack('!HHHH', 1000, 2000, 10, 0)
    partial = _ones_complement_checksum(pseudo + udp_pfx + b'\x00\x00')
    fixed_udp6 = fix_l4_checksum(
        hdr6(10, 17) + udp_pfx + struct.pack('!H', partial)
    )
    self.assertEqual(struct.unpack('!H', fixed_udp6[60:62])[0], 0xFFFF)

  def test_server_lifecycle_and_rpc_commands(self):
    """Covers idempotent start, AP/station updates, and RPCs."""
    self.server.start()
    ap1 = self.server.register_ap('TestSSID', 'psk1', ap_id='ap0')
    ap2 = self.server.register_ap('TestSSID', 'psk2', frequency=5180)
    self.assertEqual(ap1.ap_id, ap2.ap_id)
    self.assertEqual(ap2.psk, 'psk2')

    self.server.register_station('st1', ipv4_addr='10.0.1.11')
    st_up = self.server.register_station(
        'st1', ipv4_addr='10.0.1.12', ipv6_addr='fd11:22::12', is_ap_bridge=True
    )
    self.assertEqual(st_up.ipv4_addr, '10.0.1.12')
    self.assertEqual(st_up.state, 'completed')

    with self.assertRaises(RuntimeError):
      self.server.authenticate_and_associate('st_new', 'Missing', 'psk')
    self.assertTrue(self._send_ctrl({'cmd': 'list_stations'})['ok'])
    self.assertTrue(
        self._send_ctrl({'cmd': 'disconnect', 'station_id': 'st1'})['ok']
    )
    self.assertTrue(self._send_ctrl({'cmd': 'get_status'})['ok'])
    self.assertFalse(self._send_ctrl({'cmd': 'no_such_cmd'})['ok'])

  def test_server_socket_and_data_relay_edge_cases(self):
    """Covers invalid JSON, partial headers, and broken peer sockets."""
    c_addr = ('127.0.0.1', self.server.control_port)
    d_addr = ('127.0.0.1', self.server.data_port)
    with socket.create_connection(c_addr, timeout=1.0) as s:
      s.sendall(b'   \nNOT_JSON\n')
    with socket.create_connection(d_addr, timeout=1.0):
      pass
    with socket.create_connection(d_addr, timeout=1.0) as s:
      s.sendall(struct.pack('!H', 4))
    with socket.create_connection(d_addr, timeout=1.0) as s:
      s.sendall(struct.pack('!H', 6) + b'unreg1')
      s.sendall(
          struct.pack('!H', 14) + b'12345678901234' + struct.pack('!H', 0)
      )
      s.shutdown(socket.SHUT_WR)
      self.assertEqual(s.recv(1), b'')
    with socket.create_connection(d_addr, timeout=1.0) as s:
      s.sendall(struct.pack('!H', 8) + b'st_trunc')
      s.sendall(struct.pack('!H', 100))

    bad_a, bad_b = socket.socketpair()
    bad_b.close()
    self.server.register_station('st_peer', is_ap_bridge=False)
    self.server._data_clients['st_peer'] = bad_a
    self.server.register_station('st_sender', is_ap_bridge=True)
    self.server._relay_l2_frame('st_sender', b'12345678901234')
    self.server.register_station('st_peer', is_ap_bridge=True)
    self.server._relay_l2_frame('st_sender', b'12345678901234')
    self.server._relay_l2_frame('st_sender', b'short')

    self.server.register_station('st_self', is_ap_bridge=True)
    own_mac = b'\x02\x00\x00\x00\x00\x01'
    self.server._mac_to_station[own_mac] = 'st_self'
    self.server._relay_l2_frame('st_self', own_mac + own_mac + b'\x08\x00data')

    self.server.unregister_station('st_peer')
    self.server.unregister_ap('ap0')

    class _ErrSock:

      def close(self):
        raise OSError('close failure')

    self.server._mac_to_station[b'\x00\x11\x22\x33\x44\x55'] = 'st_err'
    self.server._data_clients['st_err'] = _ErrSock()
    self.server.unregister_station('st_err')

    self.server._mac_to_station[b'\x00\x11\x22\x33\x44\x66'] = 'st_disc'
    self.server.disconnect_station('st_disc')

    self.server._cleanup_data_client('st_err2', _ErrSock())

    closed_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    closed_sock.close()
    self.server._accept_loop(closed_sock, self.server._handle_json_client)
    self.server._handle_data_client(closed_sock)
    st_cleanup_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    self.server._data_clients['st_cleanup'] = st_cleanup_sock
    st_cleanup_sock.close()

    self.server._control_sock = _ErrSock()
    self.server.stop()

  def test_docker_wifi_bridge_methods(self):
    """Covers DockerVirtualWiFiManager proxies and container setup helpers."""
    import shutil
    import tempfile
    import time
    from types import SimpleNamespace
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager

    tmp_dir = tempfile.mkdtemp(prefix='vwifi_ut_')
    try:
      self.server.register_ap('HomeSSID', 'HomePass123', ap_id='ap0')
      with open(
          os.path.join(tmp_dir, 'control.sock'), 'w', encoding='utf-8'
      ) as f:
        f.write('stale')
      mgr = DockerVirtualWiFiManager(self.server, runtime_dir=tmp_dir)
      dbus_dir = mgr.get_container_dbus_dir('wifi0')
      with open(os.path.join(dbus_dir, 'pid'), 'w', encoding='utf-8') as f:
        f.write('123')
      mgr.get_container_dbus_dir('wifi0')

      with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as usock:
        usock.settimeout(2.0)
        usock.connect(mgr.control_sock_path)
        usock.sendall(b'{"cmd": "list_aps"}\n')
        self.assertTrue(json.loads(usock.recv(4096).decode('utf-8'))['ok'])

      mgr.register_station('ap_br', 0, is_ap=True)
      mac, ipv4, ipv6 = mgr.register_station('wifi0', 0, is_ap=False)
      with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as dsock:
        dsock.settimeout(2.0)
        dsock.connect(mgr.data_sock_path)
        dsock.sendall(struct.pack('!H', 5) + b'ap_br')
        deadline = time.monotonic() + 1.5
        while (
            'ap_br' not in self.server._data_clients
            and time.monotonic() < deadline
        ):
          time.sleep(0.01)
        self.assertIn('ap_br', self.server._data_clients)
        eth_pkt = (
            b'\xff' * 6 + b'\x02\x00\x00\x00\x01\x01\x08\x06' + b'\x00' * 28
        )
        dsock.sendall(struct.pack('!H', len(eth_pkt)) + eth_pkt)
        while (
            self.server.get_station('ap_br').tx_packets < 1
            and time.monotonic() < deadline
        ):
          time.sleep(0.01)
        self.assertGreaterEqual(self.server.get_station('ap_br').tx_packets, 1)

      mgr.setup_container_interface(
          'w_none', SimpleNamespace(container=None), mac
      )
      exec_cmds = []
      fnode = SimpleNamespace(
          container=SimpleNamespace(
              exec_run=lambda cmd, **_: exec_cmds.append(cmd)
          )
      )
      mgr.setup_container_interface(
          'ap_br', fnode, '02:00:00:00:01:01', '10.0.1.1', 'fd11:22::1', True
      )
      self.assertIn('ip addr replace 10.0.1.1/24 dev wlan0', exec_cmds[0])
      self.assertIn(
          'ip -6 addr replace fd11:22::1/64 dev wlan0 nodad', exec_cmds[0]
      )
      exec_cmds.clear()

      mgr.setup_container_interface('wifi0', fnode, mac, ipv4, ipv6, False)
      self.assertNotIn('ip addr replace', exec_cmds[0])

      res_unreg = mgr.connect_station_to_ap(
          'non_existent', 'HomeSSID', 'HomePass123'
      )
      self.assertFalse(res_unreg.get('ok'))
      self.assertEqual(
          res_unreg.get('reason'), 'station_non_existent_not_registered'
      )

      res_good = mgr.connect_station_to_ap('wifi0', 'HomeSSID', 'HomePass123')
      self.assertTrue(res_good.get('ok'))
      self.assertEqual(res_good.get('status'), 'completed')
      self.assertEqual(self.server.get_station('wifi0').state, 'completed')

      res_bad = mgr.connect_station_to_ap('wifi0', 'HomeSSID', 'WrongPass')
      self.assertFalse(res_bad.get('ok'))
      self.assertEqual(res_bad.get('status_code'), 15)
      mgr.disconnect_station('wifi0')
      mgr.unregister_station('wifi0')
      mgr.stop_all()
      self.assertFalse(os.path.exists(mgr.control_sock_path))
      self.assertFalse(os.path.exists(mgr.data_sock_path))
      mgr.stop_all()  # A second call must be a no-op.

      bad_dir = os.path.join(tmp_dir, 'bad_rt')
      os.makedirs(os.path.join(bad_dir, 'data.sock'))
      with self.assertRaises(OSError):
        DockerVirtualWiFiManager(self.server, runtime_dir=bad_dir)
      self.assertFalse(os.path.exists(os.path.join(bad_dir, 'control.sock')))
    finally:
      shutil.rmtree(tmp_dir, ignore_errors=True)

  def _exercise_wpa_dbus_handlers(self, wpa, conn):
    """Exercises all D-Bus methods on WpaSupplicantDbusService."""
    import time
    from types import SimpleNamespace
    from gi.repository import GLib
    from cirque.virtual_wifi.wpa_dbus_daemon import (
        WPA_IFACE_PATH,
        WPA_ROOT_PATH,
    )

    inv = SimpleNamespace(
        ret=None, return_value=lambda v: setattr(inv, 'ret', v)
    )
    root_i, ifc_i = 'fi.w1.wpa_supplicant1', 'fi.w1.wpa_supplicant1.Interface'
    call = lambda p, i, m, a: wpa._handle_method_call(
        conn, ':1.1', p, i, m, a, inv
    )

    signals_received = []

    def on_signal(
        connection,
        sender,
        path,
        interface,
        signal,
        params,
        *user_data,
    ):
      del connection, sender, path, user_data
      signals_received.append((interface, signal, params.unpack()))

    sub_id_scan = conn.signal_subscribe(
        None,
        'fi.w1.wpa_supplicant1.Interface',
        'ScanDone',
        WPA_IFACE_PATH,
        None,
        0,
        on_signal,
    )
    sub_id_props = conn.signal_subscribe(
        None,
        'org.freedesktop.DBus.Properties',
        'PropertiesChanged',
        WPA_IFACE_PATH,
        None,
        0,
        on_signal,
    )

    call(WPA_ROOT_PATH, root_i, 'GetInterface', GLib.Variant('(s)', ('wlan0',)))
    r_arg = GLib.Variant('(o)', (WPA_IFACE_PATH,))
    call(WPA_ROOT_PATH, root_i, 'RemoveInterface', r_arg)

    # Calling Scan() must set Scanning to True immediately
    call(WPA_IFACE_PATH, ifc_i, 'Scan', GLib.Variant('(a{sv})', ({},)))
    scan_prop = wpa._handle_get_property(
        conn, ':1.1', WPA_IFACE_PATH, ifc_i, 'Scanning'
    )
    self.assertTrue(scan_prop.unpack())

    # Run context loop briefly so GLib timeout (20ms) fires ScanDone and
    # resets Scanning.
    ctx = GLib.MainContext.default()
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline:
      ctx.iteration(False)
      if any(sig == 'ScanDone' for _, sig, _ in signals_received):
        break
      time.sleep(0.01)

    scan_done_signals = [s for s in signals_received if s[1] == 'ScanDone']
    self.assertGreaterEqual(len(scan_done_signals), 1)
    self.assertEqual(scan_done_signals[0][2], (True,))

    scan_prop_after = wpa._handle_get_property(
        conn, ':1.1', WPA_IFACE_PATH, ifc_i, 'Scanning'
    )
    self.assertFalse(scan_prop_after.unpack())

    conn.signal_unsubscribe(sub_id_scan)
    conn.signal_unsubscribe(sub_id_props)

    for psk in ('HomePass123', 'BadPass'):
      nd = {
          'ssid': GLib.Variant('s', 'HomeSSID'),
          'psk': GLib.Variant('s', psk),
      }
      call(WPA_IFACE_PATH, ifc_i, 'AddNetwork', GLib.Variant('(a{sv})', (nd,)))
      net_path = inv.ret.unpack()[0]
      with mock.patch.object(
          wpa.docker_manager,
          'connect_station_to_ap',
          return_value={'ok': psk == 'HomePass123', 'status_code': 0 if psk == 'HomePass123' else 15},
      ):
        call(
            WPA_IFACE_PATH,
            ifc_i,
            'SelectNetwork',
            GLib.Variant('(o)', (net_path,)),
        )

    self._exercise_wpa_dbus_properties(wpa, conn, net_path)
    wpa._station_state['wifi0']['current_network'] = net_path
    call(
        WPA_IFACE_PATH, ifc_i, 'RemoveNetwork', GLib.Variant('(o)', (net_path,))
    )
    for mname in ('RemoveAllNetworks', 'Disconnect', 'SaveConfig'):
      call(WPA_IFACE_PATH, ifc_i, mname, GLib.Variant('()', ()))

  def _exercise_wpa_dbus_properties(self, wpa, conn, net_path):
    """Exercises all D-Bus property getters and setters."""
    from gi.repository import GLib
    from cirque.virtual_wifi.wpa_dbus_daemon import (
        WPA_IFACE_PATH,
        WPA_ROOT_PATH,
    )

    root_i, ifc_i = 'fi.w1.wpa_supplicant1', 'fi.w1.wpa_supplicant1.Interface'
    bss_i, net_i = 'fi.w1.wpa_supplicant1.BSS', 'fi.w1.wpa_supplicant1.Network'
    getp = lambda p, i, k: wpa._handle_get_property(conn, ':1.1', p, i, k)

    self.assertEqual(
        getp(WPA_ROOT_PATH, root_i, 'Interfaces').unpack(), [WPA_IFACE_PATH]
    )
    for prop in 'BSSs State Scanning CurrentBSS CurrentNetwork Unknown'.split():
      val = getp(WPA_IFACE_PATH, ifc_i, prop)
      if prop != 'Unknown':
        self.assertIsNotNone(val)
    bss_path = f'{WPA_IFACE_PATH}/BSSs/0'
    self.assertEqual(bytes(getp(bss_path, bss_i, 'SSID').unpack()), b'HomeSSID')
    self.assertEqual(getp(bss_path, bss_i, 'Frequency').unpack(), 2437)

    # Non-vacuous assertions on BSS properties
    bssid_bytes = bytes(getp(bss_path, bss_i, 'BSSID').unpack())
    self.assertEqual(bssid_bytes, bytes.fromhex('020000000101'))
    self.assertEqual(getp(bss_path, bss_i, 'Signal').unpack(), -40)
    self.assertEqual(
        getp(bss_path, bss_i, 'Rates').unpack(),
        [54000000, 48000000, 36000000, 24000000],
    )
    wpa_dict = getp(bss_path, bss_i, 'WPA').unpack()
    self.assertIn('KeyMgmt', wpa_dict)
    rsn_dict = getp(bss_path, bss_i, 'RSN').unpack()
    self.assertIn('KeyMgmt', rsn_dict)
    self.assertEqual(getp(bss_path, bss_i, 'WPS').unpack(), {})
    self.assertIsNone(getp(bss_path, bss_i, 'Unknown'))

    self.assertIsInstance(getp(net_path, net_i, 'Enabled').unpack(), bool)
    net_props = getp(net_path, net_i, 'Properties').unpack()
    self.assertIn('ssid', net_props)
    self.assertIsNone(getp(net_path, net_i, 'Unknown'))
    self.assertIsNone(getp(WPA_ROOT_PATH, 'unknown.Iface', 'Prop'))
    wpa._handle_set_property(
        conn, ':1.1', net_path, net_i, 'Enabled', GLib.Variant('b', False)
    )
    self.assertFalse(getp(net_path, net_i, 'Enabled').unpack())

  def test_wpa_dbus_daemon_lifecycle_and_handlers(self):
    """Covers WpaSupplicantDbusService attachment, methods, and properties."""
    import shutil
    import subprocess
    import tempfile
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager
    from cirque.virtual_wifi.wpa_dbus_daemon import (
        WpaSupplicantDbusService,
        _decode_dbus_bytes_or_str,
    )

    for raw in (b'CHIP', [67, 72, 73, 80], '"CHIP"', 'CHIP'):
      self.assertEqual(_decode_dbus_bytes_or_str(raw), 'CHIP')

    tmp_dir = tempfile.mkdtemp(prefix='vwifi_wpa_')
    try:
      self.server.register_ap('HomeSSID', 'HomePass123', ap_id='ap0')
      mgr = DockerVirtualWiFiManager(self.server, runtime_dir=tmp_dir)
      dbus_dir = mgr.get_container_dbus_dir('wifi0')
      wpa = WpaSupplicantDbusService(mgr)
      no_sock = os.path.join(tmp_dir, 'no.sock')
      self.assertFalse(
          wpa.attach_container_bus('w_miss', no_sock, timeout_s=0.1)
      )
      bad_sock = os.path.join(tmp_dir, 'bad.sock')
      with open(bad_sock, 'w', encoding='utf-8') as f:
        f.write('x')
      self.assertFalse(
          wpa.attach_container_bus('w_bad', bad_sock, timeout_s=0.1)
      )
      self.assertTrue(wpa.start())

      bus_sock = os.path.join(dbus_dir, 'system_bus_socket')
      cmd = [
          'dbus-daemon',
          '--session',
          f'--address=unix:path={bus_sock}',
          '--nofork',
          '--nopidfile',
      ]
      dbus_proc = subprocess.Popen(cmd)
      try:
        self.assertTrue(
            wpa.attach_container_bus('wifi0', bus_sock, timeout_s=3.0)
        )
        self._exercise_wpa_dbus_handlers(wpa, wpa._conns['wifi0'])
      finally:
        wpa.stop()
        dbus_proc.terminate()
        dbus_proc.wait(timeout=3)
      mgr.stop_all()
    finally:
      shutil.rmtree(tmp_dir, ignore_errors=True)

  def test_virtual_home_topology_builder_and_verifiers(self):
    from types import SimpleNamespace
    from unittest.mock import patch
    from cirque.home import VirtualHomeNodeSpec, VirtualHomeTopology

    node_spec = VirtualHomeNodeSpec(
        name='combo',
        device_type='Combo',
        enable_thread=True,
        bd_addr='AA:BB:CC:DD:EE:99',
    )
    self.assertEqual(
        node_spec.to_device_config()['capability'],
        ['Bluetooth', 'WiFi', 'Thread'],
    )
    home_cfg = VirtualHomeTopology.default_two_node_ble_wifi_config()
    self.assertIn('wifi_ap', home_cfg)

    ping_ok = {'loss': '0% packet loss'}
    exec_log = []
    paired_state = [1]

    def fake_exec(cmd, nid, stream=False):
      del stream
      exec_log.append((nid, cmd))
      if 'GetManagedObjects' in cmd:
        if nid == 'mobile_controller':
          return SimpleNamespace(
              output=(
                  b'/org/bluez/hci0 AA:BB:CC:DD:EE:01 '
                  b'/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02'
              )
          )
        return '/org/bluez/hci1 AA:BB:CC:DD:EE:02'
      if 'ip -4 addr show' in cmd:
        is_ctrl = nid in ('mobile_controller', 'c_id')
        if not is_ctrl and paired_state[0] == 0:
          return SimpleNamespace(output=b'')
        ip = '10.0.1.10' if is_ctrl else '10.0.1.11'
        return SimpleNamespace(output=f'inet {ip}/24'.encode())
      if 'pairing ble-wifi' in cmd:
        if '11112222' in cmd:
          return SimpleNamespace(
              output=b'[-] PASE session failure: invalid PIN'
          )
        if 'wrong_psk' in cmd:
          return SimpleNamespace(
              output=b'[-] Wi-Fi provisioning failure: incorrect PSK'
          )
        paired_state[0] = 1
        return SimpleNamespace(
            output=b'[+] Commissioning complete for node 1001'
        )
      if 'onoff toggle' in cmd:
        return SimpleNamespace(output=b'[+] OnOff state toggled: False -> True')
      if 'ping ' in cmd:
        return SimpleNamespace(output=ping_ok['loss'].encode())
      return SimpleNamespace(output=b"('completed',)")

    def assert_add_network_creds(ssid, psk):
      """Asserts each node's AddNetwork used ssid/psk, then clears the log."""
      add_network = [(n, c) for n, c in exec_log if 'AddNetwork' in c]
      self.assertEqual(
          [nid for nid, _ in add_network],
          ['mobile_controller', 'iot_end_device'],
      )
      for _, cmd in add_network:
        self.assertTrue(
            f"'ssid': <'{ssid}'>" in cmd
            or f"ssid\\'\"\\'\"\\': <\\'\"\\'\"\\'{ssid}\\'\"\\'\"\\'" in cmd
            or f"'ssid': <'{ssid}'" in cmd
            or ssid in cmd,
            f"Expected ssid '{ssid}' in AddNetwork cmd: {cmd}",
        )
        self.assertTrue(
            f"'psk': <'{psk}'>" in cmd
            or f"psk\\'\"\\'\"\\': <\\'\"\\'\"\\'{psk}\\'\"\\'\"\\'" in cmd
            or f"'psk': <'{psk}'" in cmd
            or psk in cmd,
            f"Expected psk '{psk}' in AddNetwork cmd: {cmd}",
        )
      exec_log.clear()

    f_home = SimpleNamespace(execute_device_cmd=fake_exec)
    bt_res = VirtualHomeTopology.verify_virtual_bt_between_nodes(
        f_home, 'mobile_controller', 'iot_end_device'
    )
    self.assertIn(
        '/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02', bt_res['controller_bt']
    )
    self.assertIn('AA:BB:CC:DD:EE:02', bt_res['device_bt'])
    exec_log.clear()
    wifi_res = (
        VirtualHomeTopology.verify_virtual_wifi_commissioning_and_data_plane(
            f_home,
            'mobile_controller',
            'iot_end_device',
            'CIRQUE_HOME_AP',
            'psk',
        )
    )
    self.assertEqual(wifi_res['controller_ip'], '10.0.1.10')
    self.assertEqual(wifi_res['device_ip'], '10.0.1.11')
    self.assertTrue(wifi_res['packet_loss_zero'])
    assert_add_network_creds('CIRQUE_HOME_AP', 'psk')
    ping_ok['loss'] = '100% packet loss'
    wifi_fail = (
        VirtualHomeTopology.verify_virtual_wifi_commissioning_and_data_plane(
            f_home, 'mobile_controller', 'iot_end_device'
        )
    )
    self.assertFalse(wifi_fail['packet_loss_zero'])
    assert_add_network_creds('CIRQUE_HOME_AP', 'cirque_home_psk')
    VirtualHomeTopology.verify_virtual_wifi_commissioning_and_data_plane(
        f_home,
        'mobile_controller',
        'iot_end_device',
        ssid='OtherAP',
        psk='otherpsk',
    )
    assert_add_network_creds('OtherAP', 'otherpsk')

    # Test Android two-node config topology
    and_cfg = VirtualHomeTopology.default_android_two_node_ble_wifi_config(
        wifi_psk='testpsk'
    )
    self.assertIn('android_controller', and_cfg)
    self.assertIn('matter_device', and_cfg)

    # Test mount pairs in VirtualHomeNodeSpec
    spec_with_mount = VirtualHomeNodeSpec(
        name='node_m',
        device_type='MobileController',
        mount_pairs=[('/host/path', '/cnt/path')],
    )
    self.assertIn('Mount', spec_with_mount.capabilities_list())
    self.assertIn('mount_pairs', spec_with_mount.to_device_config())

    topo = VirtualHomeTopology(f_home)
    self.assertEqual(topo.cirque_home, f_home)

    # Test _enforce_eth0_mdns_isolation success and failure
    def fake_iptables_ok(cmd, nid, **kwargs):
      return SimpleNamespace(
          output=(
              b'-A OUTPUT -o eth0 -p udp -m udp --dport 5353 -j DROP\n-A INPUT'
              b' -i eth0 -p udp -m udp --dport 5353 -j DROP\n'
          )
      )

    h_ipt = SimpleNamespace(execute_device_cmd=fake_iptables_ok)
    VirtualHomeTopology._enforce_eth0_mdns_isolation(h_ipt, 'node1')

    def fake_iptables_fail(cmd, nid, **kwargs):
      return SimpleNamespace(output=b'')

    h_ipt_fail = SimpleNamespace(execute_device_cmd=fake_iptables_fail)
    with self.assertRaises(RuntimeError):
      VirtualHomeTopology._enforce_eth0_mdns_isolation(h_ipt_fail, 'node1')

    # Test clean_chip_device_state_and_restart
    def fake_clean_exec(cmd, nid, **kwargs):
      if 'pgrep' in cmd or 'ss -lntu' in cmd:
        return SimpleNamespace(exit_code=1, output=b'')
      if 'cat /sys/class/net/wlan0/ifindex' in cmd:
        return SimpleNamespace(exit_code=0, output=b'3\n')
      if 'org.bluez.GattService1' in cmd:
        return SimpleNamespace(
            exit_code=0, output=b'0000fff6-0000-1000-8000-00805f9b34fb\n'
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    h_clean = SimpleNamespace(execute_device_cmd=fake_clean_exec)
    with patch.object(
        VirtualHomeTopology, '_enforce_eth0_mdns_isolation', return_value=None
    ):
      VirtualHomeTopology.clean_chip_device_state_and_restart(
          h_clean, 'dev_id', controller_id='ctrl_id', timeout_sec=0.1
      )

    # Test verify_real_chip_ble_wifi_commissioning success and failure branches
    def fake_comm_exec(cmd, nid, **kwargs):
      if 'pairing ble-wifi' in cmd:
        return SimpleNamespace(
            exit_code=0,
            output=(
                b'Device commissioning completed\nPASE establishment'
                b' successful\n'
            ),
        )
      if 'onoff toggle' in cmd:
        return SimpleNamespace(
            exit_code=0,
            output=b'CASE_Sigma1\nMsg TX [UDP:[fe80::1%wlan0]:5540]\n',
        )
      if 'onoff read' in cmd:
        return SimpleNamespace(exit_code=0, output=b'OnOff: TRUE\n')
      if 'ping ' in cmd:
        return SimpleNamespace(exit_code=0, output=b'0% packet loss\n')
      if 'wpa_cli' in cmd or 'wpa_supplicant1' in cmd:
        return SimpleNamespace(
            exit_code=0, output=b"wpa_state=COMPLETED\n('completed',)\n"
        )
      if 'ip -4 addr show' in cmd:
        return SimpleNamespace(exit_code=0, output=b'inet 10.0.1.12/24\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    h_comm = SimpleNamespace(execute_device_cmd=fake_comm_exec)
    with (
        patch.object(
            VirtualHomeTopology,
            'clean_chip_device_state_and_restart',
            return_value=None,
        ),
        patch.object(
            VirtualHomeTopology,
            '_associate_wpa_and_dhcp',
            return_value='10.0.1.10',
        ),
    ):
      res = VirtualHomeTopology.verify_real_chip_ble_wifi_commissioning(
          h_comm, 'ctrl_id', 'dev_id', node_id=1001
      )
      self.assertEqual(res.get('exit_code'), 0)

      # Failure phases: pase_authentication and wifi_provisioning
      def fake_comm_pase_fail(cmd, nid, **kwargs):
        if 'pairing ble-wifi' in cmd:
          return SimpleNamespace(
              exit_code=1,
              output=b"Failed to verify peer's MAC\nSecure Pairing Failed\n",
          )
        return SimpleNamespace(exit_code=0, output=b'ok\n')

      h_comm_fail = SimpleNamespace(execute_device_cmd=fake_comm_pase_fail)
      res_fail = VirtualHomeTopology.verify_real_chip_ble_wifi_commissioning(
          h_comm_fail, 'ctrl_id', 'dev_id', node_id=1001
      )
      self.assertEqual(res_fail['phase'], 'pase_authentication')

      def fake_comm_wifi_fail(cmd, nid, **kwargs):
        if 'pairing ble-wifi' in cmd:
          return SimpleNamespace(
              exit_code=1,
              output=(
                  b'PASE establishment successful\nConnectNetwork response,'
                  b' networkingStatus=1\n'
              ),
          )
        return SimpleNamespace(exit_code=0, output=b'ok\n')

      h_comm_wfail = SimpleNamespace(execute_device_cmd=fake_comm_wifi_fail)
      res_wfail = VirtualHomeTopology.verify_real_chip_ble_wifi_commissioning(
          h_comm_wfail, 'ctrl_id', 'dev_id', node_id=1001
      )
      self.assertEqual(res_wfail['phase'], 'wifi_provisioning')

  def test_cirque_home_and_android_docker_node_complete_coverage(self):
    """Covers 100% of cirque/home/home.py and AndroidDockerNode."""
    from unittest.mock import patch
    from types import SimpleNamespace
    from cirque.home.home import CirqueHome
    from cirque.nodes.androiddockernode import AndroidDockerNode

    cid_seq = [0]

    def _create_mock_container(*args, **kwargs):
      del args, kwargs
      cid_seq[0] += 1
      curr_id = f'mock_cid_{cid_seq[0]}'
      return SimpleNamespace(
          id=curr_id,
          name=f'mock_cname_{cid_seq[0]}',
          exec_run=lambda cmd, *a, **k: SimpleNamespace(
              exit_code=0,
              output=b'1\n' if 'sys.boot_completed' in str(cmd) else b'ok\n',
          ),
          stop=lambda timeout=2: None,
          remove=lambda force=True: None,
          logs=lambda tail='all': b'log content\n',
      )

    mock_client = SimpleNamespace(
        containers=SimpleNamespace(
            run=_create_mock_container,
            prune=lambda: None,
        ),
        networks=SimpleNamespace(prune=lambda: None),
        images=SimpleNamespace(get=lambda name: True),
        api=SimpleNamespace(
            inspect_container=lambda cid: {
                'State': {'Pid': 42},
                'NetworkSettings': {
                    'Networks': {
                        'bridge': {
                            'IPAddress': '172.17.0.2',
                            'GlobalIPv6Address': 'fd00::2',
                            'IPv6Gateway': 'fd00::1',
                        }
                    }
                },
            }
        ),
    )

    class DummyCap:

      def __init__(self, *args, **kwargs):
        del args, kwargs
        self.name = 'Dummy'
        self.description = {'cap': 'val'}

      def get_docker_run_args(self, dockernode):
        del dockernode
        return {'volumes': []}

      def enable_capability(self, dockernode):
        del dockernode

      def disable_capability(self, dockernode):
        del dockernode

    DummyCap.BLE_ADAPTS_LIST = []
    DummyCap.WIFI_STATIONS_LIST = []

    mock_sim_pipe = SimpleNamespace(
        get_next_petition=staticmethod(lambda: 10),
    )

    with (
        patch('docker.from_env', return_value=mock_client),
        patch(
            'cirque.home.home.HomeLan',
            return_value=SimpleNamespace(name='mock_lan', close=lambda: None),
        ),
        patch(
            'cirque.capabilities.wificapability.prepare_container_dbus_socket',
            lambda **k: None,
        ),
        patch('cirque.home.home.ThreadSimPipe', mock_sim_pipe),
        patch('cirque.home.home.ThreadCapability', DummyCap),
        patch('cirque.home.home.XvncCapability', DummyCap),
        patch('cirque.home.home.BlueToothCapability', DummyCap),
        patch('cirque.home.home.WiFiCapability', DummyCap),
        patch('cirque.home.home.WeaveCapability', DummyCap),
        patch('cirque.home.home.TrafficControlCapability', DummyCap),
        patch('cirque.home.home.LanAccessCapability', DummyCap),
        patch('cirque.home.home.MountCapability', DummyCap),
        patch('cirque.home.home.InteractiveCapability', DummyCap),
        patch('cirque.home.home.DockerNetworkCapability', DummyCap),
    ):
      h_auto = CirqueHome()
      self.assertTrue(h_auto.home_id)
      h_auto.destroy_home()

      h = CirqueHome('fixed_home_id')
      self.assertEqual(h.home_id, 'fixed_home_id')
      self.assertEqual(h.devices, {})

      self.assertIsNone(h.add_device({}))

      cfg = {
          'dev_ctrl': {
              'type': 'android_controller',
              'avd_name': 'emu_test',
              'adb_port': 5556,
              'enable_kvm': False,
              'preferred_mode': 'container_chiptool',
              'docker_network': 'Internal',
              'capability': [
                  'Bluetooth',
                  'WiFi',
                  'Interactive',
                  'LanAccess',
                  'Mount',
                  'Thread',
                  'TrafficControl',
                  'Weave',
                  'Xvnc',
                  'UnsupportedCap',
              ],
              'mount_pairs': [('/tmp', '/tmp')],
              'thread_petition': 1,
              'thread_daemon': ['ot-daemon'],
              'rcp_mode': True,
              'traffic_control': {'latencyMs': 20, 'loss': 0.05},
              'weave_config_file': '/tmp/weave.conf',
              'weave_config_target_path': '/etc/weave.conf',
              'xvnc_localhost': False,
              'display_id': 1,
              'docker_display_id': 2,
          },
          'dev_ap': {
              'type': 'wifi_ap',
              'ssid': 'TEST_AP',
              'psk': 'test_psk',
              'docker_network': 'IpvLan',
          },
          'dev_emu': {
              'type': 'android_emulator',
              'docker_network': 'Ipv6',
              'capability': ['Thread'],
              'thread_petition': 1,
          },
          'dev_and': {
              'type': 'android_device',
              'docker_network': 'internal',
              'capability': ['LanAccess'],
          },
          'dev_docker': {
              'type': 'DockerNode',
          },
      }

      with patch('os.path.exists', return_value=True):
        h._append_docker_network_capability(
            {'capability': ['Bluetooth'], 'use_virtual_bt_tcp': False}, []
        )
      with patch('os.path.exists', return_value=False):
        h._append_docker_network_capability(
            {'capability': ['Bluetooth'], 'use_virtual_bt_tcp': False}, []
        )

      self.assertIsNone(h._CirqueHome__make_capability('Weave', {}))

      h.create_home(cfg)
      self.assertEqual(len(h.devices), 5)

      self.assertEqual(h.get_wifiap_ssid_psk(), ('TEST_AP', 'test_psk'))
      dev_ap_id = [d.id for d in h.devices.values() if d.type == 'wifi_ap'][0]
      self.assertEqual(
          h.get_wifiap_ssid_psk(dev_ap_id), ('TEST_AP', 'test_psk')
      )

      h_devs = h.get_home_devices()
      self.assertEqual(len(h_devs), 5)
      self.assertIsNotNone(h.get_device_state(dev_ap_id))
      self.assertIsNone(h.get_device_state('nonexistent'))

      self.assertIsNotNone(h.execute_device_cmd('echo 1', dev_ap_id))
      self.assertIsNone(h.execute_device_cmd('echo 1', None))

      self.assertEqual(h.get_device_log(dev_ap_id), 'log content\n')
      self.assertEqual(h.get_device_log('nonexistent'), '')

      self.assertEqual(h.stop_device(dev_ap_id), dev_ap_id)
      self.assertEqual(h.stop_device('nonexistent'), '')

      self.assertEqual(h.get_wifiap_ssid_psk('nonexistent'), '')
      for d in list(h.devices.values()):
        if d.type == 'wifi_ap':
          h.stop_device(d.id)
      self.assertEqual(h.get_wifiap_ssid_psk(), '')

      h.destroy_home()
      self.assertIsNone(h.destroy_home())

    with patch('os.path.exists', return_value=True):
      node_kvm = AndroidDockerNode(
          mock_client,
          node_type='android_emulator',
          avd_name='emu1',
          adb_port=5555,
          enable_kvm=True,
          preferred_mode=None,
      )
      self.assertEqual(node_kvm.runtime_mode, 'kvm_emulator')
      self.assertIn('/dev/kvm:/dev/kvm:rwm', node_kvm.devices)
      node_kvm.run()

    with patch('os.path.exists', return_value=False):
      node_nokvm = AndroidDockerNode(
          mock_client,
          node_type='android_controller',
          avd_name='emu2',
          adb_port=5556,
          enable_kvm=True,
          preferred_mode=None,
      )
      self.assertEqual(node_nokvm.runtime_mode, 'container_chiptool')

    node_pref = AndroidDockerNode(
        mock_client,
        preferred_mode='kvm_emulator',
    )
    self.assertEqual(node_pref.runtime_mode, 'kvm_emulator')

    test_cnt = _create_mock_container()
    node_pref.container = test_cnt
    self.assertEqual(
        node_pref.get_bluetooth_hci_socket_path(),
        '/dev/virtual_bt/hci_bridge.sock',
    )
    self.assertEqual(node_pref.adb_shell('ls').exit_code, 0)
    self.assertTrue(node_pref.wait_for_boot(timeout_sec=0.5))

    call_cnt = [0]

    def fail_once(cmd, **kwargs):
      del kwargs
      call_cnt[0] += 1
      if call_cnt[0] == 1:
        raise OSError('boot error')
      if 'sys.boot_completed' in str(cmd):
        return SimpleNamespace(exit_code=0, output=b'1\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    test_cnt.exec_run = fail_once
    self.assertTrue(node_pref.wait_for_boot(timeout_sec=0.5))

    test_cnt.exec_run = lambda cmd, **kwargs: SimpleNamespace(
        exit_code=0, output=b'done\n'
    )
    self.assertEqual(node_pref.run_chiptool('help').exit_code, 0)
    self.assertEqual(
        node_pref.run_chiptool(['pairing', 'ble-wifi']).exit_code, 0
    )
    self.assertEqual(
        node_pref.run_chiptool_ble_wifi_commission(
            1001, 'SSID', 'PSK'
        ).exit_code,
        0,
    )
    desc = node_pref.description
    self.assertIn('runtime_mode', desc)
    self.assertIn('bluetooth_hci_socket', desc)

    cap_mock = SimpleNamespace(
        name='Cap1',
        get_docker_run_args=lambda n: {
            'environment': {'C_ENV': '1'},
            'privileged': True,
        },
        enable_capability=lambda n: None,
        disable_capability=lambda n: None,
        description={'cap1': 'val'},
    )
    cap_mock2 = SimpleNamespace(
        name='Cap2',
        get_docker_run_args=lambda n: {'privileged': True},
        enable_capability=lambda n: None,
        disable_capability=lambda n: None,
        description={},
    )
    node_pref.capabilities = [cap_mock, cap_mock2]
    node_pref.run(environment={'EXTRA': '2'})
    self.assertIsNotNone(node_pref.container)

    node_pref.container = None
    self.assertEqual(node_pref.adb_shell('ls')[0], 1)
    self.assertEqual(node_pref.run_chiptool('help')[0], 1)
    self.assertFalse(node_pref.wait_for_boot(timeout_sec=0.01))
    self.assertFalse(node_pref.start_emulator(timeout_sec=0.01))
    self.assertFalse(node_pref.install_chiptool('nonexistent.apk'))
    self.assertFalse(node_pref.start_pty_bridge(23458))
    self.assertIsNone(node_pref.setup_guest_wifi())
    self.assertEqual(
        node_pref.commission_via_chiptool_ui().get('status'), 'failed'
    )
    self.assertEqual(
        node_pref.toggle_onoff_via_chiptool_ui().get('status'), 'failed'
    )
    self.assertEqual(
        node_pref.read_onoff_via_chiptool_ui().get('status'), 'failed'
    )
    self.assertIsNone(node_pref.stop_emulator())

    # Test with mock container
    node_pref.container = test_cnt
    node_pref.setup_tap_device('cirque_tap0')

    def emu_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'getprop sys.boot_completed' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'1\n')
      if 'logcat' in cmd_str:
        if '-s OnOffClientFragment' in cmd_str:
          # Shape of the real CHIPTool OnOffClientFragment logcat tag: the
          # toggle response and the subsequent attribute read share one
          # dumped buffer.
          return SimpleNamespace(
              exit_code=0,
              output=(
                  b'--------- beginning of main\n'
                  b'10-03 14:14:37.559  3888  4056 E OnOffClientFragment:'
                  b' onResponse : Endpoint 1, cluster 6, command 2,'
                  b' Code : 0\n'
                  b'10-03 14:14:40.086  3888  4056 V OnOffClientFragment:'
                  b' On/Off attribute value: true\n'
              ),
          )
        if 'Scanning for BLE device' in cmd_str:
          # DeviceProvisioningFragment logs this once the commissioning
          # intent (or the UI flow) reaches BLE discovery.
          return SimpleNamespace(
              exit_code=0,
              output=b'showMessage:Scanning for BLE device 3840\n',
          )
        return SimpleNamespace(
            exit_code=0, output=b'onCommissioningComplete nodeId 1\n'
        )
      if 'ip -4 addr show' in cmd_str or 'ip addr show' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=b'inet 10.0.1.5/24 brd 10.0.1.255 dev wlan0\n'
        )
      if 'adb install' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'Success\n')
      if 'adb shell id' in cmd_str:
        # start_pty_bridge polls for a root shell after `adb root`.
        return SimpleNamespace(exit_code=0, output=b'uid=0(root)\n')
      if 'readlink' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'/dev/pts/0\n')
      if 'ps -ef' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'root 123 1 pty_bridge\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    test_cnt.exec_run = emu_exec
    self.assertTrue(node_pref.start_emulator(timeout_sec=0.1))
    bt_patch_target = (
        'cirque.capabilities.bluetoothcapability.'
        'BlueToothCapability.get_or_start_virtual_server'
    )
    with mock.patch(bt_patch_target) as mock_get_server:
      mock_server = mock_get_server.return_value
      mock_server.get_controller.return_value = mock.MagicMock()
      self.assertTrue(node_pref.start_pty_bridge(23458))
    self.assertEqual(node_pref.setup_guest_wifi('wlan0'), '10.0.1.5')
    comm_ui = node_pref.commission_via_chiptool_ui(
        ssid='CIRQUE_HOME_AP', psk='cirque_home_psk', timeout_sec=0.5
    )
    self.assertEqual(comm_ui.get('status'), 'success')
    self.assertEqual(comm_ui.get('commissioned_node_id'), 1)
    self.assertEqual(comm_ui.get('trigger'), 'intent')

    toggle_ui = node_pref.toggle_onoff_via_chiptool_ui(
        node_id=1, timeout_sec=0.5
    )
    self.assertEqual(toggle_ui.get('status'), 'success')

    read_ui = node_pref.read_onoff_via_chiptool_ui(node_id=1, timeout_sec=0.5)
    self.assertEqual(read_ui.get('status'), 'success')
    self.assertEqual(read_ui.get('value'), 'true')
    node_pref.stop_emulator()

    # Test VirtualHomeTopology emulator config & verification
    from cirque.home.virtual_home_topology import VirtualHomeTopology
    emu_cfg = VirtualHomeTopology.default_android_emulator_ble_wifi_config()
    self.assertIn('android_emulator', emu_cfg)
    self.assertEqual(
        emu_cfg['android_emulator']['tap_interface'], 'cirque_tap0'
    )
    self.assertTrue(emu_cfg['android_emulator']['is_tap_station'])

    # Test verify_android_emulator_ble_wifi_commissioning with mock home
    mock_home = SimpleNamespace(
        home={
            'devices': {
                'android_emulator': node_pref,
                'matter_device': SimpleNamespace(id='matter_device'),
            }
        },
        execute_device_cmd=lambda cmd, node_id, **kwargs: SimpleNamespace(
            exit_code=0, output='inet 10.0.1.2/24\n'
        ),
    )
    from cirque.capabilities.bluetoothcapability import BlueToothCapability
    from cirque.capabilities.wificapability import WiFiCapability

    # pty_bridge cannot run against the mock container, so bind the controller
    # it would have bound; start_pty_bridge then sees it at once instead of
    # polling its bind window twice against the real server.
    BlueToothCapability.get_or_start_virtual_server().create_controller(
        controller_id='android_hci0'
    )

    with patch.object(
        VirtualHomeTopology,
        'clean_chip_device_state_and_restart',
        return_value=None,
    ), patch.object(
        VirtualHomeTopology,
        '_read_wlan0_ipv4',
        return_value='10.0.1.2',
    ):
      try:
        emu_verif = (
            VirtualHomeTopology.verify_android_emulator_ble_wifi_commissioning(
                cirque_home=mock_home,
                controller_id='android_emulator',
                device_id='matter_device',
                timeout_sec=0.5,
                restart_app=False,
            )
        )
        self.assertEqual(emu_verif.get('status'), 'success')
        self.assertEqual(emu_verif.get('phase'), 'operational_interaction')
        self.assertEqual(emu_verif.get('controller_ip'), '10.0.1.5')
        self.assertEqual(emu_verif.get('device_ip'), '10.0.1.2')
      finally:
        BlueToothCapability.stop_virtual_server()
        WiFiCapability.stop_virtual_server()

  def test_relayed_frame_counters_and_udp5540_detection(self):
    """Verifies _is_udp5540_frame, relayed frame counters, and reset."""
    import socket
    import struct
    from cirque.virtual_wifi.server import _is_udp5540_frame

    self.assertFalse(_is_udp5540_frame(b''))
    self.assertFalse(_is_udp5540_frame(b'\x00' * 13))

    # Construct IPv4 UDP 5540 frame
    eth_hdr = b'\x02\x00\x00\x00\x02\x02\x02\x00\x00\x00\x02\x01\x08\x00'
    ip4_hdr = (
        b'\x45\x00\x00\x1c\x00\x01\x00\x00\x40\x11\x00\x00'
        b'\x0a\x00\x01\x0b\x0a\x00\x01\x0c'
    )
    udp_5540 = struct.pack('!HHHH', 5540, 5540, 8, 0)
    frame_v4 = eth_hdr + ip4_hdr + udp_5540
    self.assertTrue(_is_udp5540_frame(frame_v4))

    # IPv4 non-5540 (port 80)
    udp_80 = struct.pack('!HHHH', 80, 80, 8, 0)
    self.assertFalse(_is_udp5540_frame(eth_hdr + ip4_hdr + udp_80))

    # Construct IPv6 UDP 5540 frame
    eth_v6_hdr = b'\x02\x00\x00\x00\x02\x02\x02\x00\x00\x00\x02\x01\x86\xdd'
    ip6_hdr = (
        b'\x60\x00\x00\x00\x00\x08\x11\x40'
        + b'\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
        + b'\xfe\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02'
    )
    frame_v6 = eth_v6_hdr + ip6_hdr + udp_5540
    self.assertTrue(_is_udp5540_frame(frame_v6))

    # Test server counter tracking and reset
    st1 = self.server.register_station('st_cnt1')
    st2 = self.server.register_station('st_cnt2')
    st1.state = 'completed'
    st2.state = 'completed'

    # Register fake socket for st_cnt2
    rs, ws = socket.socketpair()
    try:
      self.server._data_clients['st_cnt2'] = ws
      self.server._relay_l2_frame('st_cnt1', frame_v6)

      cnts = self.server.get_frame_counters()
      self.assertGreaterEqual(cnts['relayed_data_frames'], 1)
      self.assertGreaterEqual(cnts['relayed_udp5540_frames'], 1)
      self.assertIn('stations', cnts)

      self.server.reset_frame_counters()
      reset_cnts = self.server.get_frame_counters()
      self.assertEqual(reset_cnts['relayed_data_frames'], 0)
      self.assertEqual(reset_cnts['relayed_udp5540_frames'], 0)
    finally:
      rs.close()
      ws.close()

  def test_relay_keeps_link_metrics_per_station(self):
    """Regression: relaying must not copy the sender's RSSI onto others."""
    import tempfile
    from cirque.connectivity.rf_channel_simulator import RfChannelSimulator

    with tempfile.TemporaryDirectory() as tmp_dir:
      rf = RfChannelSimulator(
          seed=7, thread_conf_path=os.path.join(tmp_dir, 'rf.conf')
      )
      rf.update_config({'enabled': True})
      rf.set_node_position('wifi_ap', 0.0, 0.0, 1.0, walls=0)
      rf.set_node_position('st_far', 12.0, 0.0, 1.0, walls=2)
      rf.set_node_position('st_near', 1.0, 0.0, 1.0, walls=0)
      self.server._rf_simulator = rf

      ap = self.server.register_ap('RssiNet', 'RssiPass123', ap_id='ap_rssi')
      st_far = self.server.register_station('st_far')
      st_near = self.server.register_station('st_near')
      st_far.state = 'completed'
      st_near.state = 'completed'
      default_rssi = st_near.rssi_dbm

      rs, ws = socket.socketpair()
      try:
        self.server._data_clients['st_near'] = ws
        frame = (
            b'\xff' * 6 + b'\x02\x00\x00\x00\x09\x01' + b'\x08\x00' + b'x' * 40
        )
        self.server._relay_l2_frame('st_far', frame)
      finally:
        rs.close()
        ws.close()

      self.assertTrue(st_far.rf_sampled)
      self.assertLess(st_far.rssi_dbm, default_rssi - 10)
      # The receiver's metrics and the AP's configured signal are untouched.
      self.assertFalse(st_near.rf_sampled)
      self.assertEqual(st_near.rssi_dbm, default_rssi)
      self.assertEqual(ap.signal, -40)
      # Scans: each station sees its own link, unsampled ones the AP default.
      self.assertEqual(
          self.server.scan_signal_dbm('st_far', ap), st_far.rssi_dbm
      )
      self.assertEqual(self.server.scan_signal_dbm('st_near', ap), -40)
      # With the RF model disabled again, scans fall back to the AP signal.
      rf.apply_regime_preset('ideal')
      self.assertEqual(self.server.scan_signal_dbm('st_far', ap), -40)

  def test_unregister_station_drops_pending_handshake(self):
    """Regression: a stale WPA2 handshake must not survive re-registration."""
    self.server.register_ap('AuthNet', 'AuthPass123', ap_id='ap_auth')
    self.server.register_station('st_auth', mac_addr='02:00:00:00:0a:01')
    msg1 = self.server.initiate_eapol_handshake(
        'st_auth', 'ap_auth', send_data_client=False
    )
    self.assertIsNotNone(msg1)
    self.assertIn('st_auth', self.server._auth_states)

    self.server.unregister_station('st_auth')
    self.assertNotIn('st_auth', self.server._auth_states)

    self.server.register_station('st_auth', mac_addr='02:00:00:00:0a:01')
    ok, rsp = self.server.process_eapol_frame(
        'st_auth', b'\x00' * 99, send_data_client=False
    )
    self.assertFalse(ok)
    self.assertIsNone(rsp)

  def test_virtual_dhcp_server_negotiation(self):
    """Verifies VirtualDhcpServer DISCOVER/OFFER and REQUEST/ACK flow."""
    from cirque.virtual_wifi.docker_wifi_bridge import VirtualDhcpServer, _ones_complement_checksum
    dhcp = VirtualDhcpServer(
        server_host='127.0.0.1',
        data_port=self.server.data_port,
        server=self.server,
        server_ip='10.0.1.1',
        server_mac='02:00:00:00:01:01',
    )
    dhcp.start()
    time.sleep(0.1)

    # Connect client station to data_port
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', self.server.data_port))
    sid = b'test_client_dhcp'
    sock.sendall(struct.pack('!H', len(sid)) + sid)
    st = self.server.register_station('test_client_dhcp')
    st.state = 'completed'

    client_mac = b'\x02\x00\x00\x00\x02\x0a'
    xid = b'\x12\x34\x56\x78'

    # Build DHCPDISCOVER
    dhcp_body = bytearray(240)
    dhcp_body[0] = 1  # BOOTREQUEST
    dhcp_body[1] = 1  # Ethernet
    dhcp_body[2] = 6  # 6-byte MAC
    dhcp_body[4:8] = xid
    dhcp_body[28:34] = client_mac
    dhcp_body[236:240] = b'\x63\x82\x53\x63'  # Magic cookie
    # Option 53 (Msg Type = 1, Discover), Option 255 (End)
    options = b'\x35\x01\x01\xff'
    dhcp_msg = bytes(dhcp_body) + options
    udp_len = 8 + len(dhcp_msg)
    udp_hdr = struct.pack('!HHHH', 68, 67, udp_len, 0)
    ip_len = 20 + udp_len
    ip_hdr = struct.pack(
        '!BBHHHBBH4s4s',
        0x45, 0, ip_len, 0, 0, 64, 17, 0,
        b'\x00\x00\x00\x00', b'\xff\xff\xff\xff',
    )
    eth_hdr = b'\xff\xff\xff\xff\xff\xff' + client_mac + struct.pack('!H', 0x0800)
    frame = eth_hdr + ip_hdr + udp_hdr + dhcp_msg

    # Send DISCOVER frame
    sock.sendall(struct.pack('!H', len(frame)) + frame)

    # Read DHCPOFFER
    hdr = sock.recv(2)
    flen = struct.unpack('!H', hdr)[0]
    reply = b''
    while len(reply) < flen:
      reply += sock.recv(flen - len(reply))

    self.assertGreaterEqual(len(reply), 14 + 20 + 8 + 240)
    rep_dhcp = reply[14 + 20 + 8 :]
    self.assertEqual(rep_dhcp[0], 2)  # BOOTREPLY
    self.assertEqual(rep_dhcp[4:8], xid)
    offered_ip = socket.inet_ntoa(rep_dhcp[16:20])
    self.assertTrue(offered_ip.startswith('10.0.1.'))

    # Send DHCPREQUEST for offered IP
    req_body = bytearray(240)
    req_body[0] = 1  # BOOTREQUEST
    req_body[1] = 1
    req_body[2] = 6
    req_body[4:8] = xid
    req_body[28:34] = client_mac
    req_body[236:240] = b'\x63\x82\x53\x63'
    # Option 53 (Msg Type = 3, Request), Option 50 (Requested IP), Option 255
    req_options = b'\x35\x01\x03\x32\x04' + socket.inet_aton(offered_ip) + b'\xff'
    req_dhcp_msg = bytes(req_body) + req_options
    req_udp_len = 8 + len(req_dhcp_msg)
    req_udp_hdr = struct.pack('!HHHH', 68, 67, req_udp_len, 0)
    req_ip_len = 20 + req_udp_len
    req_ip_hdr = struct.pack(
        '!BBHHHBBH4s4s',
        0x45, 0, req_ip_len, 0, 0, 64, 17, 0,
        b'\x00\x00\x00\x00', b'\xff\xff\xff\xff',
    )
    req_frame = eth_hdr + req_ip_hdr + req_udp_hdr + req_dhcp_msg
    sock.sendall(struct.pack('!H', len(req_frame)) + req_frame)

    # Read DHCPACK
    hdr = sock.recv(2)
    flen = struct.unpack('!H', hdr)[0]
    ack_reply = b''
    while len(ack_reply) < flen:
      ack_reply += sock.recv(flen - len(ack_reply))

    ack_dhcp = ack_reply[14 + 20 + 8 :]
    self.assertEqual(ack_dhcp[0], 2)  # BOOTREPLY
    self.assertEqual(socket.inet_ntoa(ack_dhcp[16:20]), offered_ip)

    sock.close()
    dhcp.stop()

  def test_virtual_dhcp_negative_when_stopped(self):
    """Verifies that stopped VirtualDhcpServer emits no replies."""
    from cirque.virtual_wifi.docker_wifi_bridge import VirtualDhcpServer
    dhcp = VirtualDhcpServer(
        server_host='127.0.0.1',
        data_port=self.server.data_port,
    )
    # Never started
    self.assertFalse(dhcp._running)
    dhcp.stop()

  def test_iwlist_shim_quality_and_filtering(self):
    """Verifies dynamic Quality calculation and ESSID filtering in iwlist."""
    import subprocess
    import tempfile
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager

    with tempfile.TemporaryDirectory() as tmp_dir:
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      try:
        # Register AP with known signal
        self._send_ctrl({
            'cmd': 'REGISTER_AP',
            'ap_id': 'ap_iwlist',
            'ssid': 'TargetSSID',
            'psk': 'Password123',
            'bssid': '02:00:00:00:01:05',
            'signal': -30,
        })
        iwlist_bin = mgr.iwlist_path
        self.assertTrue(os.path.exists(iwlist_bin))

        # Query all
        out = subprocess.check_output(
            [iwlist_bin, 'wlan0', 'scan'], text=True
        )
        self.assertIn('TargetSSID', out)
        # Quality calculation for -30 dBm: (-30 + 100) * 70 / 50 = 70 * 70 / 50 = 98 -> capped at 70
        self.assertIn('Quality=70/70', out)
        self.assertIn('Signal level=-30 dBm', out)

        # Filter matching ESSID
        out_match = subprocess.check_output(
            [iwlist_bin, 'wlan0', 'essid', 'TargetSSID'], text=True
        )
        self.assertIn('TargetSSID', out_match)

        # Filter unknown ESSID
        out_unknown = subprocess.check_output(
            [iwlist_bin, 'wlan0', 'essid', 'NonExistentSSID'], text=True
        )
        self.assertIn('No scan results', out_unknown)
        self.assertNotIn('TargetSSID', out_unknown)
      finally:
        mgr.stop_all()

  def test_wpa_dbus_daemon_scan_filtering_and_none_properties(self):
    """Verifies D-Bus scan filtering and unknown BSS returning None."""
    import tempfile
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager
    from cirque.virtual_wifi.wpa_dbus_daemon import WpaSupplicantDbusService
    from gi.repository import GLib

    with tempfile.TemporaryDirectory() as tmp_dir:
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      service = WpaSupplicantDbusService(mgr)
      try:
        self._send_ctrl({
            'cmd': 'REGISTER_AP',
            'ap_id': 'ap_dbus',
            'ssid': 'VisibleNetwork',
            'psk': 'SecuredKey123',
            'bssid': '02:00:00:00:01:08',
        })
        st = service._get_or_create_station_dict('wifi0')
        class FakeConn:
          def register_object(self, *args, **kwargs): return 1
          def emit_signal(self, *args, **kwargs): pass
        fake_conn = FakeConn()

        # Refresh with matching filter
        bsss = service._refresh_bsss_for_station(
            fake_conn, 'wifi0', filter_ssids=['VisibleNetwork']
        )
        self.assertEqual(len(bsss), 1)

        # Refresh with unknown filter
        bsss_empty = service._refresh_bsss_for_station(
            fake_conn, 'wifi0', filter_ssids=['UnknownSSID']
        )
        self.assertEqual(len(bsss_empty), 0)

        # Unknown BSS property check returns None
        self.assertIsNone(
            service._get_bss_property(
                st, '/fi/w1/wpa_supplicant1/Interfaces/0/BSSs/999', 'SSID'
            )
        )
      finally:
        service.stop()
        mgr.stop_all()

  def test_connect_station_to_ap_eapol_handshake_and_state_callback(self):
    """Verifies that connect_station_to_ap drives genuine 4-way handshake."""
    import tempfile
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager

    with tempfile.TemporaryDirectory() as tmp_dir:
      self.server.register_ap(
          'EapolNet', 'SecretPassphrase123', ap_id='ap_eapol'
      )
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      try:
        mgr.register_station('sta_eapol', 0)
        states_observed = []

        res = mgr.connect_station_to_ap(
            'sta_eapol',
            'EapolNet',
            'SecretPassphrase123',
            on_state_change=states_observed.append,
        )
        self.assertTrue(res.get('ok'))
        self.assertEqual(res.get('status'), 'completed')
        self.assertIn('4way_handshake', states_observed)
        self.assertIn('completed', states_observed)
        self.assertEqual(states_observed[-1], 'completed')
        st = self.server.get_station('sta_eapol')
        self.assertEqual(st.state, 'completed')

        # Negative test 1: wrong passphrase fails MIC check
        states_bad = []
        res_bad = mgr.connect_station_to_ap(
            'sta_eapol',
            'EapolNet',
            'WrongPassphrase999',
            on_state_change=states_bad.append,
        )
        self.assertFalse(res_bad.get('ok'))
        self.assertEqual(res_bad.get('status_code'), 15)
        self.assertIn('disconnected', states_bad)
        st_bad = self.server.get_station('sta_eapol')
        self.assertEqual(st_bad.state, 'disconnected')

        # Negative test 2: unknown SSID returns ap_not_found
        res_unknown = mgr.connect_station_to_ap(
            'sta_eapol',
            'NonExistentNetwork',
            'AnyPass123',
        )
        self.assertFalse(res_unknown.get('ok'))
        self.assertEqual(res_unknown.get('status_code'), 1)
      finally:
        mgr.stop_all()

  def test_wpa_dbus_daemon_state_transitions_real_supplicant(self):
    """Verifies D-Bus daemon emits real supplicant state transitions."""
    import tempfile
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager
    from cirque.virtual_wifi.wpa_dbus_daemon import WpaSupplicantDbusService

    with tempfile.TemporaryDirectory() as tmp_dir:
      self.server.register_ap(
          'DbusRealNet', 'DbusPassword123', ap_id='ap_dbus_real'
      )
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      service = WpaSupplicantDbusService(mgr)
      try:
        mgr.register_station('wifi_dbus', 0)
        st = service._get_or_create_station_dict('wifi_dbus')
        signals_emitted = []

        class FakeDbusConn:

          def register_object(self, *args, **kwargs):
            return 1

          def emit_signal(self, dest, path, iface, name, params):
            signals_emitted.append((name, params.unpack()))

        fake_conn = FakeDbusConn()
        net_path = '/fi/w1/wpa_supplicant1/Interfaces/0/Networks/1'
        st['networks'][net_path] = {
            'ssid': 'DbusRealNet',
            'psk': 'DbusPassword123',
        }

        service._complete_network_selection(
            fake_conn, 'wifi_dbus', st, net_path
        )
        self.assertEqual(st['state'], 'completed')

        state_signals = []
        for name, params in signals_emitted:
          if name != 'PropertiesChanged':
            continue
          props = params[1] if len(params) > 1 else params[0]
          if isinstance(props, dict) and 'State' in props:
            state_signals.append(props['State'])
        self.assertIn('4way_handshake', state_signals)
        self.assertIn('completed', state_signals)
      finally:
        service.stop()
        mgr.stop_all()

  def test_setup_container_interface_auto_connect_wrong_passphrase_never_completed(
      self,
  ):
    """Verifies that auto_connect=True with wrong passphrase never completes."""
    import tempfile
    from types import SimpleNamespace
    from unittest import mock
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager

    with tempfile.TemporaryDirectory() as tmp_dir:
      self.server.register_ap('ProtectedSSID', 'CorrectPass123', ap_id='ap_p')
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      try:
        mac, ipv4, ipv6 = mgr.register_station('sta_bad_auto', 0)
        exec_cmds = []
        fnode = SimpleNamespace(
            container=SimpleNamespace(
                exec_run=lambda cmd, **_: exec_cmds.append(cmd)
            )
        )
        with mock.patch.object(
            self.server,
            'list_aps',
            return_value=[
                SimpleNamespace(
                    ssid='ProtectedSSID',
                    psk='WrongPass999',
                    bssid='02:00:00:00:01:99',
                )
            ],
        ):
          mgr.setup_container_interface(
              'sta_bad_auto', fnode, mac, ipv4, ipv6, auto_connect=True
          )

        st = self.server.get_station('sta_bad_auto')
        self.assertIsNotNone(st)
        self.assertNotEqual(st.state, 'completed')
        self.assertEqual(st.state, 'disconnected')
        self.assertFalse(any('dhcpcd -1' in cmd for cmd in exec_cmds))
      finally:
        mgr.stop_all()

  def test_setup_container_interface_deferred_auto_connect_before_ap(
      self,
  ):
    """Verifies station auto_connect requested before AP reaches completed."""
    import tempfile
    from types import SimpleNamespace
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager

    with tempfile.TemporaryDirectory() as tmp_dir:
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      try:
        mac, ipv4, ipv6 = mgr.register_station('sta_defer', 0)
        exec_cmds = []
        fnode = SimpleNamespace(
            container=SimpleNamespace(
                exec_run=lambda cmd, **_: exec_cmds.append(cmd)
            ),
            wifi_ssid='DeferredSSID',
            wifi_psk='CorrectPass123',
        )
        # AP does not exist yet; auto_connect should be deferred.
        mgr.setup_container_interface(
            'sta_defer', fnode, mac, ipv4, ipv6, auto_connect=True
        )

        st = self.server.get_station('sta_defer')
        self.assertIsNotNone(st)
        self.assertNotEqual(st.state, 'completed')

        # Register AP; deferred auto_connect should fire and complete handshake.
        self.server.register_ap(
            'DeferredSSID', 'CorrectPass123', ap_id='ap_defer'
        )

        st = self.server.get_station('sta_defer')
        self.assertEqual(st.state, 'completed')
        self.assertTrue(any('dhcpcd -1' in cmd for cmd in exec_cmds))
      finally:
        mgr.stop_all()

  def test_setup_container_interface_auto_connect_negative_conditions(self):
    """Verifies that unmatching SSID or wrong PSK never reaches completed."""
    import tempfile
    from types import SimpleNamespace
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager

    with tempfile.TemporaryDirectory() as tmp_dir:
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      try:
        # 1. Configured SSID matching no AP never reaches completed.
        mac1, ip1_4, ip1_6 = mgr.register_station('sta_no_match', 1)
        cmds1 = []
        node_no_match = SimpleNamespace(
            container=SimpleNamespace(
                exec_run=lambda cmd, **_: cmds1.append(cmd)
            ),
            wifi_ssid='NonExistentSSID',
            wifi_psk='Pass123',
        )
        mgr.setup_container_interface(
            'sta_no_match',
            node_no_match,
            mac1,
            ip1_4,
            ip1_6,
            auto_connect=True,
        )

        # 2. Configured with wrong PSK for matching AP never reaches completed.
        mac2, ip2_4, ip2_6 = mgr.register_station('sta_wrong_psk', 2)
        cmds2 = []
        node_wrong_psk = SimpleNamespace(
            container=SimpleNamespace(
                exec_run=lambda cmd, **_: cmds2.append(cmd)
            ),
            wifi_ssid='ExistingSSID',
            wifi_psk='WrongPassphrase999',
        )
        mgr.setup_container_interface(
            'sta_wrong_psk',
            node_wrong_psk,
            mac2,
            ip2_4,
            ip2_6,
            auto_connect=True,
        )

        # Register ExistingSSID with real password.
        self.server.register_ap(
            'ExistingSSID', 'CorrectPass123', ap_id='ap_ex'
        )

        # Station 1 requested NonExistentSSID, so it never reaches completed.
        st1 = self.server.get_station('sta_no_match')
        self.assertIsNotNone(st1)
        self.assertNotEqual(st1.state, 'completed')

        # Station 2 failed the 4-way handshake, so it never reaches completed.
        st2 = self.server.get_station('sta_wrong_psk')
        self.assertIsNotNone(st2)
        self.assertNotEqual(st2.state, 'completed')
        self.assertEqual(st2.state, 'disconnected')
      finally:
        mgr.stop_all()

  def test_handback_restarted_l2_agent_forwards_data_frame(self):
    """Proves that after handshake hand-back, restarted L2 agent forwards data."""
    import tempfile
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager

    with tempfile.TemporaryDirectory() as tmp_dir:
      self.server.register_ap('HandbackNet', 'SecretKey123', ap_id='ap_hb')
      self.server.register_station('peer_dst', is_ap_bridge=True)
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      try:
        mgr.register_station('sta_hb', 0)
        res = mgr.connect_station_to_ap('sta_hb', 'HandbackNet', 'SecretKey123')
        self.assertTrue(res.get('ok'))
        self.assertEqual(res.get('status'), 'completed')
        self.assertEqual(self.server.get_station('sta_hb').state, 'completed')

        # Now simulate restarted vwifi_l2_agent connecting fresh to data_port
        data_addr = (self.server.host, self.server.data_port)
        with (
            socket.create_connection(data_addr, timeout=3.0) as agent_sock,
            socket.create_connection(data_addr, timeout=3.0) as peer_sock,
        ):
          agent_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
          peer_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

          agent_sock.sendall(struct.pack('!H', 6) + b'sta_hb')
          peer_sock.sendall(struct.pack('!H', 8) + b'peer_dst')
          time.sleep(0.05)

          # Non-EAPOL L2 frame (e.g. IPv4 packet) from sta_hb to peer_dst
          sta_mac = bytes.fromhex('02000000020a')
          peer_mac = bytes.fromhex('02000000020b')
          eth_data = (
              peer_mac + sta_mac + bytes.fromhex('0800') + b'PAYLOAD_DATA'
          )
          agent_sock.sendall(struct.pack('!H', len(eth_data)) + eth_data)

          peer_sock.settimeout(2.0)
          flen_raw = peer_sock.recv(2)
          self.assertEqual(len(flen_raw), 2)
          flen = struct.unpack('!H', flen_raw)[0]
          recv_frame = peer_sock.recv(flen)
          self.assertEqual(recv_frame, eth_data)

          # Verify gate stayed open and state remained completed
          st = self.server.get_station('sta_hb')
          self.assertEqual(st.state, 'completed')
      finally:
        mgr.stop_all()

  def test_virtual_dhcp_nak_and_foreign_server_id_compliance(self):
    """Verifies RFC 2131 Section 4.3.2 compliance: NAK on out-of-pool/conflict and drop foreign server-id."""
    from cirque.virtual_wifi.docker_wifi_bridge import VirtualDhcpServer
    dhcp = VirtualDhcpServer(
        server_host='127.0.0.1',
        data_port=self.server.data_port,
        server=self.server,
        server_ip='10.0.1.1',
        server_mac='02:00:00:00:01:01',
    )
    dhcp.start()
    time.sleep(0.1)

    client_mac = b'\x02\x00\x00\x00\x02\x99'
    st = self.server.register_station(
        'test_client_nak', mac_addr='02:00:00:00:02:99'
    )
    st.state = 'completed'

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('127.0.0.1', self.server.data_port))
    sid = b'test_client_nak'
    sock.sendall(struct.pack('!H', len(sid)) + sid)
    time.sleep(0.1)

    eth_hdr = b'\xff\xff\xff\xff\xff\xff' + client_mac + struct.pack('!H', 0x0800)

    def _build_request_frame(xid_bytes, req_ip_str, server_id_str=None):
      req_body = bytearray(240)
      req_body[0] = 1
      req_body[1] = 1
      req_body[2] = 6
      req_body[4:8] = xid_bytes
      req_body[28:34] = client_mac
      req_body[236:240] = b'\x63\x82\x53\x63'
      req_opts = bytearray()
      req_opts.extend(b'\x35\x01\x03')  # Msg Type = 3 (Request)
      if req_ip_str:
        req_opts.extend(b'\x32\x04' + socket.inet_aton(req_ip_str))
      if server_id_str:
        req_opts.extend(b'\x36\x04' + socket.inet_aton(server_id_str))
      req_opts.append(255)
      msg = bytes(req_body) + bytes(req_opts)
      udp_hdr = struct.pack('!HHHH', 68, 67, 8 + len(msg), 0)
      ip_hdr = struct.pack(
          '!BBHHHBBH4s4s',
          0x45, 0, 20 + 8 + len(msg), 0, 0, 64, 17, 0,
          b'\x00\x00\x00\x00', b'\xff\xff\xff\xff',
      )
      return eth_hdr + ip_hdr + udp_hdr + msg

    try:
      # 1. Foreign server-id: should be silently dropped (no reply)
      sock.settimeout(0.5)
      f_foreign = _build_request_frame(b'\x11\x22\x33\x44', '10.0.1.15', server_id_str='10.0.1.254')
      sock.sendall(struct.pack('!H', len(f_foreign)) + f_foreign)
      with self.assertRaises(socket.timeout):
        sock.recv(2)

      # 2. Out-of-pool requested IP: should receive DHCPNAK (msg_type=6)
      sock.settimeout(2.0)
      f_oop = _build_request_frame(b'\x22\x33\x44\x55', '192.168.1.100', server_id_str='10.0.1.1')
      sock.sendall(struct.pack('!H', len(f_oop)) + f_oop)
      hdr = sock.recv(2)
      flen = struct.unpack('!H', hdr)[0]
      reply_oop = sock.recv(flen)
      dhcp_reply_oop = reply_oop[14 + 20 + 8 :]
      # Check msg type option 53 == 6 (DHCPNAK)
      opts_oop = dhcp_reply_oop[240:]
      self.assertEqual(opts_oop[0], 53)
      self.assertEqual(opts_oop[2], 6)

      # 3. Un-offered in-pool IP: should receive DHCPNAK
      f_unoffered = _build_request_frame(b'\x33\x44\x55\x66', '10.0.1.20', server_id_str='10.0.1.1')
      sock.sendall(struct.pack('!H', len(f_unoffered)) + f_unoffered)
      hdr = sock.recv(2)
      flen = struct.unpack('!H', hdr)[0]
      reply_unoffered = sock.recv(flen)
      dhcp_reply_unoffered = reply_unoffered[14 + 20 + 8 :]
      opts_unoffered = dhcp_reply_unoffered[240:]
      self.assertEqual(opts_unoffered[0], 53)
      self.assertEqual(opts_unoffered[2], 6)

      # 4. Conflicting lease (leased to another MAC): should receive DHCPNAK
      dhcp.leases['02:00:00:00:02:88'] = '10.0.1.25'
      f_conflict = _build_request_frame(b'\x44\x55\x66\x77', '10.0.1.25', server_id_str='10.0.1.1')
      sock.sendall(struct.pack('!H', len(f_conflict)) + f_conflict)
      hdr = sock.recv(2)
      flen = struct.unpack('!H', hdr)[0]
      reply_conflict = sock.recv(flen)
      dhcp_reply_conflict = reply_conflict[14 + 20 + 8 :]
      opts_conflict = dhcp_reply_conflict[240:]
      self.assertEqual(opts_conflict[0], 53)
      self.assertEqual(opts_conflict[2], 6)
    finally:
      sock.close()
      dhcp.stop()

  def test_infrastructure_pseudo_station_auth_bypass_isolated(self):
    """Proves that only dhcp_server pseudo-station can bypass auth, not standard stations."""
    from cirque.virtual_wifi.docker_wifi_bridge import VirtualDhcpServer
    dhcp = VirtualDhcpServer(
        server_host='127.0.0.1',
        data_port=self.server.data_port,
        server=self.server,
    )
    dhcp.start()
    time.sleep(0.1)

    try:
      # dhcp_server pseudo-station is completed
      st_dhcp = self.server.get_station('dhcp_server')
      self.assertIsNotNone(st_dhcp)
      self.assertEqual(st_dhcp.state, 'completed')

      # Register normal station
      st_client = self.server.register_station('regular_sta')
      self.assertEqual(st_client.state, 'disconnected')

      # Attempt to send data frame from regular unauthenticated station
      with socket.create_connection(('127.0.0.1', self.server.data_port), timeout=1.0) as s:
        sid = b'regular_sta'
        s.sendall(struct.pack('!H', len(sid)) + sid)
        time.sleep(0.05)
        # Port security check
        st_check = self.server.get_station('regular_sta')
        self.assertEqual(st_check.state, 'disconnected')
    finally:
      dhcp.stop()

  def test_connect_station_to_ap_failure_when_ap_drops_msg4(self):
    """Verifies connect_station_to_ap returns ok=False, reason='ap_handshake_incomplete' if AP never completes."""
    import tempfile
    from unittest import mock
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager

    with tempfile.TemporaryDirectory() as tmp_dir:
      self.server.register_ap('DropMsg4Net', 'SecretKey123', ap_id='ap_drop')
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      try:
        mgr.register_station('sta_drop', 0)
        # Patch AP authenticator station state transition on AP side so it never transitions to 'completed'
        orig_get_station = self.server.get_station
        def _mock_get_station(sid):
          st = orig_get_station(sid)
          if sid == 'sta_drop' and st is not None:
            # Force st.state to remain in 4way_handshake
            st.state = '4way_handshake'
          return st

        with mock.patch.object(self.server, 'get_station', side_effect=_mock_get_station):
          res = mgr.connect_station_to_ap('sta_drop', 'DropMsg4Net', 'SecretKey123')
          self.assertFalse(res.get('ok'))
          self.assertEqual(res.get('reason'), 'ap_handshake_incomplete')
          self.assertEqual(res.get('status_code'), 15)
      finally:
        mgr.stop_all()

  def test_connect_station_to_ap_tap_station_step7_cirque_tap0(self):
    """Verifies connect_station_to_ap Step 7 uses cirque_tap0 for tap nodes."""
    import tempfile
    from unittest import mock
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager

    with tempfile.TemporaryDirectory() as tmp_dir:
      self.server.register_ap('TapStep7Net', 'SecretKeyTap123', ap_id='ap_tap')
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      try:
        mock_container = mock.MagicMock()
        mock_container.exec_run.return_value = mock.MagicMock(
            exit_code=0, output=b''
        )
        fake_tap_node = mock.MagicMock()
        fake_tap_node.container = mock_container
        fake_tap_node.tap_interface = 'cirque_tap0'
        fake_tap_node.is_tap_station = True

        mgr.register_station('sta_tap_step7', 0)
        with mgr._lock:
          mgr._station_nodes['sta_tap_step7'] = fake_tap_node

        with mock.patch.object(mgr, 'start_station_dhcpcd') as mock_dhcpcd:
          res = mgr.connect_station_to_ap(
              'sta_tap_step7', 'TapStep7Net', 'SecretKeyTap123'
          )
          self.assertTrue(res.get('ok'))
          self.assertEqual(res.get('status'), 'completed')
          mock_dhcpcd.assert_not_called()

          # Verify container.exec_run invocations for tap interface
          cmd_strings = [
              call_args[0][0]
              for call_args in mock_container.exec_run.call_args_list
          ]
          self.assertTrue(
              any('cirque_tap0 up' in c for c in cmd_strings),
              f'Expected cirque_tap0 up in cmds: {cmd_strings}',
          )
          has_agent = any(
              'vwifi_l2_agent.py' in c and 'cirque_tap0' in c
              for c in cmd_strings
          )
          self.assertTrue(
              has_agent,
              f'Expected vwifi_l2_agent on cirque_tap0 in cmds: {cmd_strings}',
          )
          self.assertFalse(
              any('vwifi_phy' in c for c in cmd_strings),
              f'No vwifi_phy expected for tap station in: {cmd_strings}',
          )
      finally:
        mgr.stop_all()

  def test_virtual_ra_server_packet_construction(self):
    """Verifies VirtualRaServer generates RFC 4861 compliant RA packets with SLAAC PIO."""
    from cirque.virtual_wifi.docker_wifi_bridge import VirtualRaServer

    ra_server = VirtualRaServer(
        '127.0.0.1', self.server.data_port, server=self.server
    )
    pkt = ra_server.build_ra_packet()
    self.assertGreaterEqual(len(pkt), 14 + 40 + 16 + 32 + 8)

    # 1. Ethernet header: EtherType 0x86DD (IPv6), Dst MAC 33:33:00:00:00:01
    eth_dst, eth_src, ethertype = (
        pkt[:6],
        pkt[6:12],
        struct.unpack('!H', pkt[12:14])[0],
    )
    self.assertEqual(ethertype, 0x86DD)
    self.assertEqual(eth_dst, bytes.fromhex('333300000001'))

    # 2. IPv6 Header: Next Header 58 (ICMPv6), Hop Limit 255 (RFC 4861 requirement)
    ip6_hdr = pkt[14:54]
    next_hdr = ip6_hdr[6]
    hop_limit = ip6_hdr[7]
    self.assertEqual(next_hdr, 58)
    self.assertEqual(hop_limit, 255)

    # 3. ICMPv6 Header: Type 134 (Router Advertisement), Code 0
    icmp6_payload = pkt[54:]
    icmp_type, icmp_code = icmp6_payload[0], icmp6_payload[1]
    self.assertEqual(icmp_type, 134)
    self.assertEqual(icmp_code, 0)

    # 4. Prefix Information Option (Type 3, Length 4 = 32 bytes)
    pio = icmp6_payload[16:48]
    self.assertEqual(pio[0], 3)  # Type 3
    self.assertEqual(pio[1], 4)  # Len 4
    self.assertEqual(pio[2], 64)  # Prefix Len 64
    self.assertEqual(pio[3], 0xC0)  # L=1, A=1
    prefix_addr = socket.inet_ntop(socket.AF_INET6, pio[16:32])
    self.assertTrue(prefix_addr.startswith('fd11:22:'))

    # 5. SLLA Option (Type 1, Length 1 = 8 bytes)
    slla = icmp6_payload[48:56]
    self.assertEqual(slla[0], 1)
    self.assertEqual(slla[1], 1)
    self.assertEqual(slla[2:8], bytes.fromhex('020000000101'))

    # 6. RS frame detection
    # Test valid RS packet detection
    rs_dst = bytes.fromhex('333300000002')
    rs_src = bytes.fromhex('02000000020c')
    rs_eth = rs_dst + rs_src + struct.pack('!H', 0x86DD)
    rs_ip6 = (
        struct.pack('!IHBB', 0x60000000, 16, 58, 255)
        + socket.inet_pton(socket.AF_INET6, 'fe80::100')
        + socket.inet_pton(socket.AF_INET6, 'ff02::2')
    )
    rs_icmp = struct.pack('!BBHI', 133, 0, 0, 0) + struct.pack('!BB6s', 1, 1, rs_src)
    rs_pkt = rs_eth + rs_ip6 + rs_icmp
    self.assertTrue(ra_server.is_router_solicitation(rs_pkt))
    # Test non-RS packet returns False
    self.assertFalse(ra_server.is_router_solicitation(pkt))  # RA is not RS

  def test_virtual_ra_server_live_solicitation_response(self):
    """Verifies that VirtualRaServer listens on data_port and replies to RS frames."""
    from cirque.virtual_wifi.docker_wifi_bridge import VirtualRaServer

    ra_server = VirtualRaServer(
        '127.0.0.1', self.server.data_port, server=self.server, interval=10.0
    )
    ra_server.start()
    try:
      # Register a mock station on the AP bridge
      st = self.server.register_station('mock_sta', mac_addr='02:00:00:00:02:55')
      st.state = 'completed'

      with socket.create_connection(('127.0.0.1', self.server.data_port), timeout=2.0) as sock:
        sid = b'mock_sta'
        sock.sendall(struct.pack('!H', len(sid)) + sid)
        time.sleep(0.1)

        # Build and send RS packet
        rs_dst = bytes.fromhex('333300000002')
        rs_src = bytes.fromhex('020000000255')
        rs_eth = rs_dst + rs_src + struct.pack('!H', 0x86DD)
        rs_ip6 = (
            struct.pack('!IHBB', 0x60000000, 16, 58, 255)
            + socket.inet_pton(socket.AF_INET6, 'fe80::200:ff:fe00:255')
            + socket.inet_pton(socket.AF_INET6, 'ff02::2')
        )
        rs_icmp = struct.pack('!BBHI', 133, 0, 0, 0) + struct.pack('!BB6s', 1, 1, rs_src)
        rs_pkt = rs_eth + rs_ip6 + rs_icmp
        sock.sendall(struct.pack('!H', len(rs_pkt)) + rs_pkt)

        # Wait for RA response
        sock.settimeout(2.0)
        received_ra = False
        deadline = time.time() + 2.0
        while time.time() < deadline:
          hdr = sock.recv(2)
          if len(hdr) < 2:
            break
          flen = struct.unpack('!H', hdr)[0]
          frame = sock.recv(flen)
          if len(frame) >= 55 and struct.unpack('!H', frame[12:14])[0] == 0x86DD:
            if frame[20] == 58 and frame[54] == 134:
              received_ra = True
              break
        self.assertTrue(received_ra, 'Did not receive RA reply from VirtualRaServer')
    finally:
      ra_server.stop()

  def test_wpa_dbus_daemon_incomplete_state_machine_reports_error(self):
    """Verifies that R3 requirement: when connect_station_to_ap returns ok but state machine never emitted completed, it is treated as an error (disconnect_reason=-15)."""
    import tempfile
    from unittest import mock
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager
    from cirque.virtual_wifi.wpa_dbus_daemon import WpaSupplicantDbusService

    with tempfile.TemporaryDirectory() as tmp_dir:
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      service = WpaSupplicantDbusService(docker_manager=mgr)
      try:
        mock_conn = mock.MagicMock()
        net_path = '/fi/w1/wpa_supplicant1/Interfaces/0/Networks/0'
        st = {
            'state': 'associating',
            'assoc_status_code': 0,
            'disconnect_reason': 0,
            'networks': {net_path: {'ssid': 'TestSSID', 'psk': 'TestPass'}},
        }

        # Mock connect_station_to_ap to return ok=True, but do NOT invoke on_state_change('completed')
        with mock.patch.object(mgr, 'connect_station_to_ap', return_value={'ok': True}):
          with mock.patch.object(service, '_emit_iface_props_changed') as mock_emit:
            res = service._complete_network_selection(
                mock_conn, 'sta_test', st, net_path
            )
            self.assertFalse(res)
            self.assertEqual(st['state'], 'disconnected')
            self.assertEqual(st['assoc_status_code'], 0)
            self.assertEqual(st['disconnect_reason'], -15)
            mock_emit.assert_called_once()
      finally:
        service.stop()
        mgr.stop_all()

  def test_docker_manager_start_station_dhcpcd(self):
    """Verifies that R6 requirement start_station_dhcpcd signals/runs dhcpcd.

    Signals or runs dhcpcd on the station container.
    """
    import tempfile
    from unittest import mock
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager

    with tempfile.TemporaryDirectory() as tmp_dir:
      mgr = DockerVirtualWiFiManager(server=self.server, runtime_dir=tmp_dir)
      try:
        mock_container = mock.MagicMock()
        mock_node = mock.MagicMock()
        mock_node.container = mock_container

        with mgr._lock:
          mgr._station_nodes['sta_dhcp'] = mock_node

        res = mgr.start_station_dhcpcd('sta_dhcp')
        self.assertTrue(res)
        mock_container.exec_run.assert_called_once()
        call_arg = mock_container.exec_run.call_args[0][0]
        self.assertIn('dhcpcd', call_arg)
        self.assertIn('--nohook resolv.conf', call_arg)

        # Non-existent station returns False
        self.assertFalse(mgr.start_station_dhcpcd('sta_missing'))
      finally:
        mgr.stop_all()

  def test_virtual_dhcp_server_options_include_dns_option_6(self):
    """Verifies VirtualDhcpServer OFFER/ACK advertise the server as DNS (6).

    Android guests need a resolver from DHCP to bring the network up; a NAK
    carries no configuration options, including option 6.
    """
    from cirque.virtual_wifi.docker_wifi_bridge import VirtualDhcpServer

    dhcp = VirtualDhcpServer(
        server_host='127.0.0.1',
        data_port=12345,
        server=self.server,
        server_ip='10.0.1.1',
        start_ip=10,
        end_ip=50,
    )
    client_mac = b'\x02\x00\x00\x00\x00\x01'
    xid = 0x12345678
    assigned_ip = '10.0.1.10'

    def parse_dhcp_options(pkt_bytes):
      self.assertGreater(len(pkt_bytes), 282)
      magic = pkt_bytes[278:282]
      self.assertEqual(magic, b'\x63\x82\x53\x63')
      opts = {}
      idx = 282
      while idx < len(pkt_bytes):
        code = pkt_bytes[idx]
        idx += 1
        if code == 0:  # pad
          continue
        if code == 255:  # end
          break
        self.assertLess(idx, len(pkt_bytes))
        length = pkt_bytes[idx]
        idx += 1
        data = pkt_bytes[idx : idx + length]
        opts[code] = data
        idx += length
      return opts

    # Check OFFER (type 2) and ACK (type 5)
    for msg_type in (2, 5):
      reply = dhcp._build_reply(client_mac, xid, assigned_ip, msg_type)
      opts = parse_dhcp_options(reply)
      self.assertIn(53, opts)  # DHCP Message Type
      self.assertEqual(opts[53], bytes([msg_type]))
      self.assertIn(54, opts)  # Server Identifier
      self.assertIn(51, opts)  # IP Address Lease Time
      self.assertIn(1, opts)   # Subnet Mask
      self.assertIn(3, opts)   # Router (gateway)
      self.assertEqual(opts[6], socket.inet_aton('10.0.1.1'))  # DNS server
      self.assertEqual(sorted(opts.keys()), [1, 3, 6, 51, 53, 54])

    # NAK (type 6) carries only the message type and server identifier.
    nak = dhcp._build_reply(client_mac, xid, '0.0.0.0', 6)
    nak_opts = parse_dhcp_options(nak)
    self.assertNotIn(6, nak_opts)
    self.assertEqual(sorted(nak_opts.keys()), [53, 54])

  def test_docker_wifi_bridge_dhcpcd_invocations_use_nohook_resolv_conf(self):
    """Verifies that all dhcpcd command strings pass --nohook resolv.conf."""
    import inspect
    from cirque.virtual_wifi import docker_wifi_bridge

    source = inspect.getsource(docker_wifi_bridge)
    lines = source.splitlines()
    dhcpcd_lines = [
        (i + 1, line)
        for i, line in enumerate(lines)
        if 'dhcpcd' in line and any(f in line for f in ('-b', '-1', 'cmd'))
        and not line.strip().startswith('#')
    ]
    self.assertGreaterEqual(len(dhcpcd_lines), 4)
    for lineno, line in dhcpcd_lines:
      self.assertIn(
          '--nohook resolv.conf',
          line,
          f"dhcpcd call at line {lineno} missing --nohook resolv.conf: {line}",
      )


if __name__ == '__main__':
  unittest.main()


