# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Hermetic unit tests covering edge branches in VirtualWiFiServer.

Targets uncovered branches in cirque/virtual_wifi/server.py:
  - UDP port 5540 edge detection (_is_udp5540_frame)
  - AP registered callback exception handling
  - Disconnect station with station PCAP writer cleanup
  - EAPOL frame sending failure (broken socket) and PCAP logging
  - EAPOL handshake initiation with unknown AP
  - Process EAPOL frame edge cases (unknown station/auth, unknown AP,
    decode error, replay counter mismatch, missing PTK, invalid Msg4 MIC,
    unhandled frame)
  - Raw frame relaying EAPOL interception with PCAP writers enabled
  - Data frame relaying with PCAP writers (medium, src, peer writers)
  - RPC endpoints: auto_connect initiate, connect to unknown/known AP,
    initiate_eapol RPC, process_eapol RPC
  - Server start/stop with PCAP writers cleanup
"""

import json
import os
import shutil
import socket
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

from cirque.virtual_wifi.eapol import (
    EAPOL_VERSION_1,
    EapolKeyFrame,
    KEY_DESC_VERSION_HMAC_SHA1_AES,
    KEY_INFO_KEY_MIC,
    KEY_INFO_KEY_TYPE_PAIRWISE,
    KEY_INFO_SECURE,
    build_gtk_kde,
    decode_eapol_key_frame,
)
from cirque.virtual_wifi.server import (
    VirtualWiFiAuthState,
    VirtualWiFiServer,
    _is_udp5540_frame,
)
from cirque.virtual_wifi.wpa2_crypto import (
    compute_mic,
    derive_ptk,
    pbkdf2_sha1_pmk,
)


class TestVirtualWiFiServerEdges(unittest.TestCase):
  """Hermetic test cases targeting edge branches in VirtualWiFiServer."""

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp(prefix='vwifi_edge_test_')
    self.server = VirtualWiFiServer(pcap_dir=self.tmp_dir)

  def tearDown(self):
    self.server.stop()
    if os.path.exists(self.tmp_dir):
      shutil.rmtree(self.tmp_dir, ignore_errors=True)

  def test_is_udp5540_frame_edges(self):
    """Test _is_udp5540_frame with short frames, non-UDP protocols, and IPv6."""
    # Frame too short for Ethernet header
    self.assertFalse(_is_udp5540_frame(b'\x00' * 10))

    # IPv4 frame too short (< 34 bytes)
    eth_short_ip4 = b'\x00' * 12 + struct.pack('!H', 0x0800) + b'\x45\x00'
    self.assertFalse(_is_udp5540_frame(eth_short_ip4))

    # IPv4 frame with TCP (protocol 6) instead of UDP (17) -> L174
    ip_tcp = bytearray(34)
    ip_tcp[0] = 0x45
    ip_tcp[9] = 6  # TCP
    eth_tcp = b'\x00' * 12 + struct.pack('!H', 0x0800) + bytes(ip_tcp)
    self.assertFalse(_is_udp5540_frame(eth_tcp))

    # IPv6 frame too short (< 62 bytes) -> L179
    eth_short_ip6 = (
        b'\x00' * 12 + struct.pack('!H', 0x86DD) + bytes([0x60]) + b'\x00' * 40
    )
    self.assertFalse(_is_udp5540_frame(eth_short_ip6))

    # IPv6 with Next Header != UDP (e.g. TCP = 6)
    ip6_hdr = bytearray(40)
    ip6_hdr[0] = 0x60
    ip6_hdr[6] = 6  # Next Header TCP
    eth_ip6_tcp = (
        b'\x00' * 12 + struct.pack('!H', 0x86DD) + bytes(ip6_hdr) + b'\x00' * 10
    )
    self.assertFalse(_is_udp5540_frame(eth_ip6_tcp))

    # Valid IPv6 UDP frame to port 5540
    ip6_udp = bytearray(40)
    ip6_udp[0] = 0x60
    ip6_udp[6] = 17  # Next Header UDP
    udp_hdr = struct.pack('!HHHH', 12345, 5540, 8, 0)
    eth_ip6_udp5540 = (
        b'\x00' * 12 + struct.pack('!H', 0x86DD) + bytes(ip6_udp) + udp_hdr
    )
    self.assertTrue(_is_udp5540_frame(eth_ip6_udp5540))

  def test_ap_registered_callback_exception_handling(self):
    """Verify that exceptions raised in AP registered callbacks are caught."""

    def _exploding_callback(ap_state):
      raise RuntimeError('Simulated callback explosion')

    self.server.add_ap_registered_callback(_exploding_callback)
    # Registering AP triggers the callback -> L449-450
    ap = self.server.register_ap('TestSSID', 'TestPassword123')
    self.assertIsNotNone(ap)
    self.assertEqual(ap.ssid, 'TestSSID')

  def test_disconnect_station_with_pcap_writer(self):
    """Verify disconnect_station closes any open station PCAP writer."""
    self.server.register_station('sta1')
    writer = self.server._get_or_create_sta_pcap_writer('sta1')
    self.assertIsNotNone(writer)
    self.assertIn('sta1', self.server._pcap_sta_writers)

    # Unregistering sta1 should close and remove the pcap writer -> L517
    self.server.unregister_station('sta1')
    self.assertNotIn('sta1', self.server._pcap_sta_writers)

  def test_send_eapol_frame_with_closed_socket_and_pcap(self):
    """Verify _send_eapol_frame_to_station logs to PCAP and handles broken sock.
    """
    self.server.register_station('sta_sock')
    # Create a closed socket and place it in _data_clients
    s1, s2 = socket.socketpair()
    self.server._data_clients['sta_sock'] = s1
    s2.close()
    s1.close()  # socket is closed, sendall will raise OSError -> L596-597

    res = self.server._send_eapol_frame_to_station(
        'sta_sock', '02:00:00:00:01:00', '02:00:00:00:02:00', b'\x00' * 20
    )
    self.assertFalse(res)

  def test_initiate_eapol_handshake_unknown_ap(self):
    """Verify initiate_eapol_handshake returns None for unknown AP -> L608-609.
    """
    res = self.server.initiate_eapol_handshake('sta_x', 'ap_nonexistent')
    self.assertIsNone(res)
    sta = self.server.get_station('sta_x')
    self.assertIsNotNone(sta)
    self.assertEqual(sta.state, 'disconnected')

  def test_process_eapol_frame_edge_cases(self):
    """Verify process_eapol_frame failure branches."""
    # 1. No station or auth state -> L662-663
    ok, resp = self.server.process_eapol_frame('unknown_sta', b'\x00' * 20)
    self.assertFalse(ok)
    self.assertIsNone(resp)

    # 2. Station exists, but AP disappeared from _aps -> L667
    self.server.register_station('sta_eapol')
    self.server._auth_states['sta_eapol'] = VirtualWiFiAuthState(
        ap_id='ap_ghost',
        station_mac='02:00:00:00:02:01',
        anonce=b'\x01' * 32,
    )
    ok, resp = self.server.process_eapol_frame('sta_eapol', b'\x00' * 20)
    self.assertFalse(ok)
    self.assertIsNone(resp)

    # 3. Target AP exists, but eapol_bytes cannot be decoded -> L673-675
    ap = self.server.register_ap('MyAP', 'Password123', ap_id='ap_real')
    self.server._auth_states['sta_eapol'].ap_id = ap.ap_id
    ok, resp = self.server.process_eapol_frame('sta_eapol', b'invalid_eapol')
    self.assertFalse(ok)
    self.assertIsNone(resp)

    # 4. Msg2 replay counter mismatch -> L681-683
    msg1 = self.server.initiate_eapol_handshake(
        'sta_eapol', ap.ap_id, send_data_client=False
    )
    self.assertIsNotNone(msg1)
    auth_state = self.server._auth_states['sta_eapol']
    # Build Msg2 with wrong replay_counter
    key_info_msg2 = (
        KEY_INFO_KEY_TYPE_PAIRWISE
        | KEY_INFO_KEY_MIC
        | KEY_DESC_VERSION_HMAC_SHA1_AES
    )
    bad_msg2 = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=2,
        key_info=key_info_msg2,
        key_length=16,
        replay_counter=auth_state.replay_counter + 999,
        nonce=b'\x02' * 32,
        iv=b'\x00' * 16,
        rsc=0,
        mic=b'\x00' * 16,
        key_data=b'',
    )
    ok, resp = self.server.process_eapol_frame(
        'sta_eapol', bad_msg2.encode(), send_data_client=False
    )
    self.assertFalse(ok)
    self.assertIsNone(resp)

    # 5. WAIT_MSG4 state: replay counter mismatch -> L748-750
    auth_state.state = 'WAIT_MSG4'
    auth_state.replay_counter = 5
    key_info_msg4 = (
        KEY_INFO_KEY_TYPE_PAIRWISE
        | KEY_INFO_KEY_MIC
        | KEY_INFO_SECURE
        | KEY_DESC_VERSION_HMAC_SHA1_AES
    )
    msg4_wrong_replay = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=2,
        key_info=key_info_msg4,
        key_length=16,
        replay_counter=2,  # mismatch with 5
        nonce=b'\x00' * 32,
        iv=b'\x00' * 16,
        rsc=0,
        mic=b'\x00' * 16,
        key_data=b'',
    )
    ok, resp = self.server.process_eapol_frame(
        'sta_eapol', msg4_wrong_replay.encode(), send_data_client=False
    )
    self.assertFalse(ok)
    self.assertIsNone(resp)

    # 6. WAIT_MSG4 state: auth_state.ptk is None -> L753
    msg4_matched_replay = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=2,
        key_info=key_info_msg4,
        key_length=16,
        replay_counter=5,
        nonce=b'\x00' * 32,
        iv=b'\x00' * 16,
        rsc=0,
        mic=b'\x00' * 16,
        key_data=b'',
    )
    auth_state.ptk = None
    ok, resp = self.server.process_eapol_frame(
        'sta_eapol', msg4_matched_replay.encode(), send_data_client=False
    )
    self.assertFalse(ok)
    self.assertIsNone(resp)

    # 7. WAIT_MSG4 state: Msg4 MIC verification failed -> L757-760
    sta = self.server.get_station('sta_eapol')
    pmk = pbkdf2_sha1_pmk(ap.psk, ap.ssid)
    ptk = derive_ptk(
        pmk,
        aa_mac=bytes.fromhex(ap.bssid.replace(':', '')),
        spa_mac=bytes.fromhex(sta.mac_addr.replace(':', '')),
        anonce=auth_state.anonce,
        snonce=b'\x03' * 32,
    )
    auth_state.ptk = ptk
    # Provide bad MIC
    msg4_bad_mic = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=2,
        key_info=key_info_msg4,
        key_length=16,
        replay_counter=5,
        nonce=b'\x00' * 32,
        iv=b'\x00' * 16,
        rsc=0,
        mic=b'\xff' * 16,
        key_data=b'',
    )
    ok, resp = self.server.process_eapol_frame(
        'sta_eapol', msg4_bad_mic.encode(), send_data_client=False
    )
    self.assertFalse(ok)
    self.assertIsNone(resp)
    self.assertEqual(sta.state, 'disconnected')
    self.assertNotIn('sta_eapol', self.server._auth_states)

    # 8. Unrecognized or out-of-order EAPOL frame -> L771-772
    self.server._auth_states['sta_eapol'] = auth_state
    odd_frame = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=2,
        key_info=0,  # neither Msg2 nor Msg4
        key_length=16,
        replay_counter=1,
        nonce=b'\x00' * 32,
        iv=b'\x00' * 16,
        rsc=0,
        mic=b'\x00' * 16,
        key_data=b'',
    )
    ok, resp = self.server.process_eapol_frame(
        'sta_eapol', odd_frame.encode(), send_data_client=False
    )
    self.assertFalse(ok)
    self.assertIsNone(resp)

  def test_relay_eapol_and_data_frames_pcap_coverage(self):
    """Verify _relay_frame handles EAPOL intercept and data frame PCAP writers.
    """
    self.server.register_ap('TestAP', 'Password123', ap_id='ap0')
    sta1 = self.server.register_station('sta1')
    sta2 = self.server.register_station('sta2')
    sta1.state = 'completed'
    sta2.state = 'completed'

    # Set up client sockets
    s1_a, s1_b = socket.socketpair()
    s2_a, s2_b = socket.socketpair()
    self.server._data_clients['sta1'] = s1_a
    self.server._data_clients['sta2'] = s2_a

    # Ensure PCAP writers exist -> L843, 845, 848
    self.server._get_or_create_sta_pcap_writer('sta1')
    self.server._get_or_create_sta_pcap_writer('sta2')

    # Send EAPOL frame through _relay_frame -> L840-850
    eapol_frame = (
        b'\xff\xff\xff\xff\xff\xff'
        + b'\x02\x00\x00\x00\x01\x00'
        + struct.pack('!H', 0x888E)
        + b'\x01\x03\x00\x00'
    )
    self.server._relay_l2_frame('sta1', eapol_frame)

    # Send IPv4 broadcast data frame -> L900, 903, 909
    ip_hdr = struct.pack(
        '!BBHHHBBH4s4s',
        0x45,
        0,
        28,
        1,
        0,
        64,
        17,
        0,
        socket.inet_aton('10.0.1.2'),
        socket.inet_aton('255.255.255.255'),
    )
    udp_hdr = struct.pack('!HHHH', 5540, 5540, 8, 0)
    data_frame = (
        b'\xff\xff\xff\xff\xff\xff'
        + bytes.fromhex(sta1.mac_addr.replace(':', ''))
        + struct.pack('!H', 0x0800)
        + ip_hdr
        + udp_hdr
    )
    self.server._relay_l2_frame('sta1', data_frame)
    self.assertEqual(self.server._relayed_data_frames, 1)
    self.assertEqual(self.server._relayed_udp5540_frames, 1)

    s1_a.close()
    s1_b.close()
    s2_a.close()
    s2_b.close()

  def test_rpc_methods_coverage(self):
    """Verify _rpc_register_station, _rpc_connect, _rpc_initiate_eapol,
    and _rpc_process_eapol.
    """
    # 1. _rpc_register_station with auto_connect -> L1003-1004
    self.server.register_ap('APAuto', 'Password123', ap_id='ap_auto')
    reg_req = {
        'station_id': 'sta_auto',
        'auto_connect': True,
    }
    resp = self.server._rpc_register_station(reg_req)
    self.assertTrue(resp.get('ok'))
    sta = self.server.get_station('sta_auto')
    self.assertEqual(sta.state, 'authenticating')

    # 2. _rpc_connect by ap_id -> L1018, 1032
    # Successful connect
    conn_req = {'station_id': 'sta_conn', 'ap_id': 'ap_auto'}
    resp = self.server._rpc_connect(conn_req)
    self.assertTrue(resp.get('ok'))
    self.assertEqual(resp.get('status'), 'handshake_initiated')

    # Connect with unknown AP
    bad_conn = {'station_id': 'sta_conn2', 'ap_id': 'no_such_ap'}
    resp = self.server._rpc_connect(bad_conn)
    self.assertFalse(resp.get('ok'))
    self.assertEqual(resp.get('reason'), 'ap_not_found')

    # Connect when initiate_eapol_handshake returns None -> L1032
    with patch.object(
        self.server, 'initiate_eapol_handshake', return_value=None
    ):
      resp_init_fail = self.server._rpc_connect(conn_req)
      self.assertFalse(resp_init_fail.get('ok'))
      self.assertEqual(resp_init_fail.get('reason'), 'initiate_failed')

    # 3. _rpc_disconnect
    disc_req = {'station_id': 'sta_conn'}
    resp = self.server._rpc_disconnect(disc_req)
    self.assertTrue(resp.get('ok'))

    # 4. _rpc_initiate_eapol -> L1043-1048
    init_req = {'station_id': 'sta_rpc', 'ap_id': 'ap_auto'}
    resp = self.server._rpc_initiate_eapol(init_req)
    self.assertTrue(resp.get('ok'))
    self.assertIn('msg1_hex', resp)

    # Failed initiate_eapol (invalid AP)
    bad_init = {'station_id': 'sta_rpc', 'ap_id': 'ghost_ap'}
    resp = self.server._rpc_initiate_eapol(bad_init)
    self.assertFalse(resp.get('ok'))
    self.assertEqual(resp.get('reason'), 'initiate_failed')

    # 5. _rpc_process_eapol -> L1051-1055
    proc_req = {
        'station_id': 'sta_rpc',
        'eapol_hex': '01030000',
    }
    resp = self.server._rpc_process_eapol(proc_req)
    self.assertIn('ok', resp)
    self.assertIn('resp_hex', resp)

  def test_server_pcap_init_and_stop_cleanup(self):
    """Verify enable_pcap with pre-existing stations and stop cleanup."""
    srv = VirtualWiFiServer(pcap_dir=None)
    srv.register_station('sta_pre')
    pcap_test_dir = os.path.join(self.tmp_dir, 'dynamic_pcap')
    srv.enable_pcap(pcap_test_dir)  # L289, 293-312
    self.assertIn('sta_pre', srv._pcap_sta_writers)
    srv.stop()  # L376-383
    self.assertIsNone(srv._pcap_medium_writer)
    self.assertIsNone(srv._pcap_ap_writer)
    self.assertEqual(len(srv._pcap_sta_writers), 0)

  def test_checksum_helpers_and_frame_counters(self):
    """Verify fix_l4_checksum with TCP and frame counters reset."""
    # 1. IPv4 TCP frame checksum fix -> L106-112
    ip4_tcp = bytearray(40)
    ip4_tcp[0] = 0x45
    ip4_tcp[2:4] = struct.pack('!H', 40)
    ip4_tcp[9] = 6  # TCP
    ip4_tcp[12:16] = socket.inet_aton('10.0.1.2')
    ip4_tcp[16:20] = socket.inet_aton('10.0.1.3')
    # TCP header
    ip4_tcp[20:24] = struct.pack('!HH', 1234, 80)
    frame_ip4_tcp = (
        b'\x02\x00\x00\x00\x00\x02'
        + b'\x02\x00\x00\x00\x00\x01'
        + struct.pack('!H', 0x0800)
        + bytes(ip4_tcp)
    )
    fixed = self.server._relay_l2_frame('sta1', frame_ip4_tcp)

    # 2. IPv6 TCP frame checksum fix -> L125-145
    ip6_hdr = bytearray(40)
    ip6_hdr[0] = 0x60
    ip6_hdr[4:6] = struct.pack('!H', 20)  # payload len 20
    ip6_hdr[6] = 6  # TCP
    ip6_hdr[8:24] = socket.inet_pton(socket.AF_INET6, 'fd11:22::2')
    ip6_hdr[24:40] = socket.inet_pton(socket.AF_INET6, 'fd11:22::3')
    tcp_hdr = struct.pack('!HHIIHHHH', 1234, 80, 0, 0, 0x5000, 0, 0, 0)
    frame_ip6_tcp = (
        b'\x02\x00\x00\x00\x00\x02'
        + b'\x02\x00\x00\x00\x00\x01'
        + struct.pack('!H', 0x86DD)
        + bytes(ip6_hdr)
        + tcp_hdr
    )
    self.server._relay_l2_frame('sta1', frame_ip6_tcp)

    # 3. Frame counters and reset -> L535-564
    counters = self.server.get_frame_counters()
    self.assertIn('stations', counters)
    self.server.reset_frame_counters()
    counters_reset = self.server.get_frame_counters()
    self.assertEqual(counters_reset['relayed_data_frames'], 0)

  def test_server_station_and_ap_updates(self):
    """Verify register_ap update and register_station existing station update.
    """
    # 1. Update existing AP -> L423-429
    self.server.register_ap('UpdateAP', 'Pass1')
    ap_updated = self.server.register_ap(
        'UpdateAP', 'Pass2', frequency=5180, channel=36, signal=-50
    )
    self.assertEqual(ap_updated.psk, 'Pass2')
    self.assertEqual(ap_updated.channel, 36)

    # 2. Update existing station -> L478-488
    self.server.register_station('sta_up')
    sta_up = self.server.register_station(
        'sta_up',
        mac_addr='02:00:00:00:00:99',
        ipv4_addr='10.0.1.99',
        ipv6_addr='fd11:22::99',
        is_ap_bridge=True,
    )
    self.assertEqual(sta_up.mac_addr, '02:00:00:00:00:99')
    self.assertEqual(sta_up.state, 'completed')

    # 3. List stations -> L529-530
    stations = self.server.list_stations()
    self.assertGreater(len(stations), 0)

    # 4. authenticate_and_associate deprecated raises RuntimeError -> L783
    with self.assertRaises(RuntimeError):
      self.server.authenticate_and_associate('sta_up', 'UpdateAP', 'Pass2')

    # 5. _rpc_get_state with station and without station -> L1061-1062
    st_res = self.server._rpc_get_state({'station_id': 'sta_up'})
    self.assertTrue(st_res['ok'])
    st_none = self.server._rpc_get_state({'station_id': 'sta_ghost'})
    self.assertFalse(st_none['ok'])

  def test_json_and_data_client_handlers(self):
    """Verify _handle_json_client and _handle_data_client error handling."""
    # 1. _handle_json_client with malformed json -> L977-978
    s1, s2 = socket.socketpair()
    s2.sendall(b'invalid json string\n')
    self.server._handle_json_client(s1)
    s2.close()

    # 2. _handle_data_client handshake empty / short -> L941, 944
    d1, d2 = socket.socketpair()
    d2.close()
    self.server._handle_data_client(d1)

    # 3. _handle_data_client with valid hello then close -> L947-959
    d3, d4 = socket.socketpair()
    sid = b'sta_stream'
    d4.sendall(struct.pack('!H', len(sid)) + sid)
    # Send one zero-length frame then close -> L956
    d4.sendall(struct.pack('!H', 0))
    d4.close()
    self.server._running = True
    self.server._handle_data_client(d3)

  def test_concurrent_station_sockets_no_eapol_eviction(self):
    """Verify concurrent sockets for a station both receive EAPOL frames."""
    a1, a2 = socket.socketpair()
    b1, b2 = socket.socketpair()
    self.addCleanup(a1.close)
    self.addCleanup(a2.close)
    self.addCleanup(b1.close)
    self.addCleanup(b2.close)
    self.server.register_station('sta_multi', mac_addr='02:00:00:00:02:77')
    self.server._station_sockets['sta_multi'] = [a1, b1]
    self.server._data_clients['sta_multi'] = b1

    ok = self.server._send_eapol_frame_to_station(
        'sta_multi',
        '02:00:00:00:01:01',
        '02:00:00:00:02:77',
        b'\x02\x03\x00\x04test',
    )
    self.assertTrue(ok)
    pkt_a = a2.recv(256)
    pkt_b = b2.recv(256)
    self.assertEqual(pkt_a, pkt_b)
    self.assertGreater(len(pkt_a), 14)

    self.server._cleanup_data_client('sta_multi', b1)
    self.assertIs(self.server._data_clients.get('sta_multi'), a1)
    self.server._cleanup_data_client('sta_multi', a1)
    self.assertNotIn('sta_multi', self.server._data_clients)


if __name__ == '__main__':
  unittest.main()
