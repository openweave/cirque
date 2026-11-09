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

"""Hermetic unit tests covering edge branches in docker_wifi_bridge.py.

Targets uncovered branches:
  - _ones_complement_checksum odd byte length
  - _write_pcap_frames
  - VirtualDhcpServer: start idempotency, stop socket cleanup exceptions,
    lease allocation overflow, run loop exception handling, malformed frame
    branches
    (non-IPv4, non-UDP, bad ihl, wrong port, bad op, bad cookie, pad option,
    short option, unparseable IP), zero checksum branch in _build_reply, sendall
    failure
  - VirtualRaServer: start idempotency, stop socket cleanup exceptions,
    zero checksum branch in build_ra_packet, is_router_solicitation edge checks,
    sendall failure, rx loop exception handling, periodic tx
  - DockerVirtualWiFiManager: setup_container_interface tap branches,
    _handle_auto_connect/_on_ap_registered dhcpcd failure, register_ap
    passthrough,
    connect_station_to_ap edge cases (tap interface branch, data socket error,
    control socket EOF, control RPC failure, missing BSSID, EAPOL timeout,
    handshake incomplete, AP handshake incomplete, pcap writing error,
    socket close error, IPv6 nodad config).
"""

import os
import shutil
import socket
import struct
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from cirque.virtual_wifi.docker_wifi_bridge import (
    DockerVirtualWiFiManager,
    VirtualDhcpServer,
    VirtualRaServer,
    Wpa2SupplicantStateMachine,
    _ones_complement_checksum,
    _write_pcap_frames,
)
from cirque.virtual_wifi.server import VirtualWiFiServer


class TestDockerWiFiBridgeEdges(unittest.TestCase):
  """Hermetic test cases targeting edge branches in docker_wifi_bridge.py."""

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp(prefix='vwifi_bridge_test_')

  def tearDown(self):
    if os.path.exists(self.tmp_dir):
      shutil.rmtree(self.tmp_dir, ignore_errors=True)

  def test_ones_complement_checksum_odd_length(self):
    """Verify _ones_complement_checksum with odd byte length -> L66."""
    csum = _ones_complement_checksum(b'\x45\x00\x00')
    self.assertIsInstance(csum, int)
    self.assertGreaterEqual(csum, 0)
    self.assertLessEqual(csum, 0xFFFF)

  def test_write_pcap_frames(self):
    """Verify _write_pcap_frames writes raw ethernet frames -> L83-87."""
    pcap_file = os.path.join(self.tmp_dir, 'test.pcap')
    frames = [(time.time(), b'\xff' * 14 + b'\x00' * 20)]
    _write_pcap_frames(pcap_file, frames)
    self.assertTrue(os.path.exists(pcap_file))
    self.assertGreater(os.path.getsize(pcap_file), 0)

  def test_virtual_dhcp_server_start_stop_edges(self):
    """Verify VirtualDhcpServer start idempotency and stop error handling."""
    server = VirtualDhcpServer('127.0.0.1', 9999)
    # Start twice -> L130
    server._running = True
    server.start()

    # Stop with socket throwing OSError on shutdown and close ->
    # L151-152, 155-156
    mock_sock = MagicMock()
    mock_sock.shutdown.side_effect = OSError('shutdown failed')
    mock_sock.close.side_effect = OSError('close failed')
    server._sock = mock_sock
    server.stop()
    self.assertFalse(server._running)
    self.assertIsNone(server._sock)

  def test_virtual_dhcp_server_allocate_ip_overflow(self):
    """Verify IP allocation reuse and wrap-around -> L164, 166, 170."""
    server = VirtualDhcpServer('127.0.0.1', 9999)
    # Allocate initial offer
    ip1 = server._allocate_ip('02:00:00:00:00:01')
    self.assertEqual(ip1, '10.0.1.10')

    # Calling again returns offer -> L166
    ip1_cached = server._allocate_ip('02:00:00:00:00:01')
    self.assertEqual(ip1_cached, '10.0.1.10')

    # If already in leases -> L164
    server.leases['02:00:00:00:00:02'] = '10.0.1.99'
    self.assertEqual(server._allocate_ip('02:00:00:00:00:02'), '10.0.1.99')

    # Wrap around past end_ip -> L170
    server.next_ip = server.end_ip
    ip_end = server._allocate_ip('02:00:00:00:00:03')
    self.assertEqual(ip_end, f'10.0.1.{server.end_ip}')
    self.assertEqual(server.next_ip, server.start_ip)

  def test_virtual_dhcp_server_handle_frame_malformed_edges(self):
    """Verify _handle_frame edge filtering branches."""
    server = VirtualDhcpServer('127.0.0.1', 9999)

    # 1. Non-IPv4 ethertype (e.g. 0x86DD) -> L214
    non_ip4 = b'\x00' * 12 + struct.pack('!H', 0x86DD) + b'\x00' * 300
    server._handle_frame(non_ip4)

    # 2. IP protocol != 17 (e.g. TCP = 6) -> L217
    ip_tcp = bytearray(300)
    ip_tcp[0] = 0x45
    ip_tcp[9] = 6  # TCP
    frame_tcp = b'\x00' * 12 + struct.pack('!H', 0x0800) + bytes(ip_tcp)
    server._handle_frame(frame_tcp)

    # 3. IHL too large / truncated payload -> L220
    ip_big_ihl = bytearray(300)
    ip_big_ihl[0] = 0x4F  # IHL = 15 -> 60 bytes
    ip_big_ihl[9] = 17  # UDP
    frame_big_ihl = b'\x00' * 12 + struct.pack('!H', 0x0800) + bytes(ip_big_ihl)
    server._handle_frame(frame_big_ihl)

    # 4. dst_port != 67 (e.g. 80) -> L223
    ip_udp_80 = bytearray(300)
    ip_udp_80[0] = 0x45
    ip_udp_80[9] = 17  # UDP
    # UDP header at offset 20: src=68, dst=80
    struct.pack_into('!HH', ip_udp_80, 20, 68, 80)
    frame_udp_80 = b'\x00' * 12 + struct.pack('!H', 0x0800) + bytes(ip_udp_80)
    server._handle_frame(frame_udp_80)

    # 5. op != 1 (BOOTREQUEST), e.g. op = 2 (BOOTREPLY) -> L228
    ip_udp_67 = bytearray(300)
    ip_udp_67[0] = 0x45
    ip_udp_67[9] = 17
    struct.pack_into('!HH', ip_udp_67, 20, 68, 67)
    # DHCP payload at offset 28: op=2
    ip_udp_67[28] = 2
    frame_op2 = b'\x00' * 12 + struct.pack('!H', 0x0800) + bytes(ip_udp_67)
    server._handle_frame(frame_op2)

    # 6. Bad magic cookie (not 0x63825363) -> L235
    ip_udp_67[28] = 1  # op=1
    ip_udp_67[28 + 2] = 6  # hlen=6
    # Magic cookie at offset 28 + 236: bad cookie
    ip_udp_67[28 + 236 : 28 + 240] = b'\x00\x00\x00\x00'
    frame_bad_cookie = (
        b'\x00' * 12 + struct.pack('!H', 0x0800) + bytes(ip_udp_67)
    )
    server._handle_frame(frame_bad_cookie)

    # 7. Options with pad byte (opt == 0) and truncated option -> L248-249, 251
    ip_udp_67[28 + 236 : 28 + 240] = b'\x63\x82\x53\x63'  # good cookie
    # Options: pad(0), then an option without length byte (truncated at
    # end of buffer)
    opts = bytearray([0, 53])  # missing length and value for opt 53
    frame_opts = (
        b'\x00' * 12
        + struct.pack('!H', 0x0800)
        + bytes(ip_udp_67[: 28 + 240])
        + bytes(opts)
    )
    server._handle_frame(frame_opts)

    # 8. DHCPREQUEST with invalid IP in _is_in_pool -> L295-296
    # Build valid DHCPREQUEST with requested_ip = "10.0.1.invalid"
    opts_req = bytearray([
        53,
        1,
        3,  # DHCPREQUEST
        50,
        4,
        10,
        0,
        1,
        99,  # opt 50: 10.0.1.99 (in pool)
        255,  # End
    ])
    # Set chaddr
    ip_udp_67[28 + 28 : 28 + 34] = b'\x02\x00\x00\x00\x00\x05'
    frame_req = (
        b'\x00' * 12
        + struct.pack('!H', 0x0800)
        + bytes(ip_udp_67[: 28 + 240])
        + bytes(opts_req)
    )
    # Monkeypatch to test ValueError in _is_in_pool
    with patch.object(server, '_send_reply') as mock_reply:
      with patch('socket.inet_ntoa', return_value='10.0.1.notanumber'):
        server._handle_frame(frame_req)
        # Should send NAK (msg_type=6)
        mock_reply.assert_called()
        self.assertEqual(mock_reply.call_args[1].get('msg_type'), 6)

  def test_virtual_dhcp_server_build_reply_zero_checksum_and_sendall_error(
      self,
  ):
    """Verify _build_reply zero checksum branch and _send_reply OSError."""
    server = VirtualDhcpServer('127.0.0.1', 9999)
    # Mock _ones_complement_checksum to return 0 -> L408
    with patch(
        'cirque.virtual_wifi.docker_wifi_bridge._ones_complement_checksum',
        return_value=0,
    ):
      frame = server._build_reply(
          b'\x02\x00\x00\x00\x00\x01', b'\x12\x34\x56\x78', '10.0.1.10', 2
      )
      self.assertIsNotNone(frame)

    # _send_reply socket sendall raises OSError -> L432-433
    server._running = True
    mock_sock = MagicMock()
    mock_sock.sendall.side_effect = OSError('Network down')
    server._sock = mock_sock
    server._send_reply(
        b'\x02\x00\x00\x00\x00\x01', b'\x12\x34\x56\x78', '10.0.1.10', 2
    )

  def test_virtual_ra_server_edges(self):
    """Verify VirtualRaServer start, stop, checksum, RS parsing, and sendall
    error.
    """
    ra_server = VirtualRaServer('127.0.0.1', 9999)

    # 1. Start twice -> L476
    ra_server._running = True
    ra_server.start()

    # 2. Stop with socket errors -> L498-499, 502-503
    mock_sock = MagicMock()
    mock_sock.shutdown.side_effect = OSError('shutdown failed')
    mock_sock.close.side_effect = OSError('close failed')
    ra_server._sock = mock_sock
    ra_server.stop()
    self.assertFalse(ra_server._running)
    self.assertIsNone(ra_server._sock)

    # 3. build_ra_packet checksum 0 -> 0xFFFF -> L546
    with patch(
        'cirque.virtual_wifi.docker_wifi_bridge._ones_complement_checksum',
        return_value=0,
    ):
      ra_pkt = ra_server.build_ra_packet()
      self.assertIsNotNone(ra_pkt)

    # 4. is_router_solicitation edge checks -> L569, 571
    # Frame with non-IPv6 ethertype
    bad_eth = b'\x00' * 12 + struct.pack('!H', 0x0800) + b'\x00' * 60
    self.assertFalse(ra_server.is_router_solicitation(bad_eth))

    # Frame with IPv6 Next Header != 58 (e.g. 6)
    bad_nh = bytearray(70)
    struct.pack_into('!H', bad_nh, 12, 0x86DD)
    bad_nh[20] = 6  # Next Header TCP
    self.assertFalse(ra_server.is_router_solicitation(bytes(bad_nh)))

    # 5. _send_ra when not running or socket is None -> L581
    ra_server._sock = None
    ra_server._send_ra()

    # 6. _send_ra when sendall raises OSError -> L587-588
    ra_server._running = True
    mock_sock = MagicMock()
    mock_sock.sendall.side_effect = OSError('Send failed')
    ra_server._sock = mock_sock
    ra_server._send_ra()

  def test_docker_manager_auto_connect_and_dhcpcd_error(self):
    """Verify _handle_auto_connect and _on_ap_registered dhcpcd exception
    paths.
    """
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    manager = DockerVirtualWiFiManager(
        server=vwifi_server, runtime_dir=self.tmp_dir
    )
    self.addCleanup(manager.stop_all)

    # Mock container whose exec_run raises exception on dhcpcd -> L1067-1073
    mock_container = MagicMock()
    mock_container.exec_run.side_effect = RuntimeError('dhcpcd binary missing')
    mock_node = MagicMock()
    mock_node.wifi_ssid = 'HomeAP'
    mock_node.wifi_psk = 'SecretPass123'
    mock_node.container = mock_container
    mock_node.tap_interface = None
    mock_node.is_tap_station = False

    manager.server.register_ap('HomeAP', 'SecretPass123', ap_id='ap0')
    manager.register_station('sta_auto', idx=1, is_ap=False)
    manager._station_nodes['sta_auto'] = mock_node

    with patch.object(
        manager, 'connect_station_to_ap', return_value={'ok': True}
    ):
      manager._handle_auto_connect('sta_auto', mock_node, mock_container)
      mock_container.exec_run.assert_called()

    # Deferred auto-connect firing on AP registered -> L1115-1116
    manager._deferred_auto_connect['sta_def'] = {
        'ssid': 'DeferredAP',
        'psk': 'DefPass123',
        'container': mock_container,
    }
    mock_ap_state = MagicMock()
    mock_ap_state.ssid = 'DeferredAP'
    mock_ap_state.psk = 'DefPass123'
    with patch.object(
        manager, 'connect_station_to_ap', return_value={'ok': True}
    ):
      manager._on_ap_registered(mock_ap_state)

  def test_docker_manager_register_ap_passthrough(self):
    """Verify register_ap delegates to server.register_ap -> L1132."""
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    manager = DockerVirtualWiFiManager(
        server=vwifi_server, runtime_dir=self.tmp_dir
    )
    self.addCleanup(manager.stop_all)
    ap = manager.register_ap('DirectAP', 'Pass1234')
    self.assertIsNotNone(ap)
    self.assertEqual(ap.ssid, 'DirectAP')

  def test_docker_manager_connect_station_edges(self):
    """Verify connect_station_to_ap error branches and tap station handling."""
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    vwifi_server.start()
    manager = DockerVirtualWiFiManager(
        server=vwifi_server,
        runtime_dir=self.tmp_dir,
    )
    self.addCleanup(manager.stop_all)

    mock_node = MagicMock()
    mock_node.container = MagicMock()
    mock_node.tap_interface = 'cirque_tap0'
    mock_node.is_tap_station = True

    # Register station without station in vwifi_server to trigger
    # auto-registration -> L1170
    manager.register_station('sta_conn_test', idx=2, is_ap=False)
    manager._station_nodes['sta_conn_test'] = mock_node
    vwifi_server.unregister_station('sta_conn_test')

    # 1. Connect with unknown SSID -> control RPC returns ap_not_found ->
    # L1207-1213
    res = manager.connect_station_to_ap(
        'sta_conn_test', 'NonExistentSSID', 'pass'
    )
    self.assertFalse(res['ok'])
    self.assertEqual(res['reason'], 'ap_not_found')

    # 2. Data port connection failure -> L1182-1184
    manager.data_port = 59999  # closed port
    manager.register_station('sta_bad_data', idx=3, is_ap=False)
    manager._station_nodes['sta_bad_data'] = mock_node
    res = manager.connect_station_to_ap('sta_bad_data', 'SSID', 'pass')
    self.assertFalse(res['ok'])
    self.assertEqual(res['reason'], 'data_socket_failed')
    manager.data_port = vwifi_server.data_port

    # 3. Control socket EOF -> L1195-1196
    # 4. Control RPC exception -> L1202-1205
    # 5. Missing AP BSSID -> L1218-1219
    ap = manager.register_ap('ValidAP', 'GoodPassword123')
    with patch(
        'json.loads',
        return_value={'ok': True, 'ap': {'bssid': ''}},
    ):
      res = manager.connect_station_to_ap(
          'sta_conn_test', 'ValidAP', 'GoodPassword123'
      )
      self.assertFalse(res['ok'])
      self.assertEqual(res['reason'], 'missing_ap_bssid')

    # 6. EAPOL timeout / handle failure -> L1244, 1247, 1250, 1261-1264
    # Re-register AP with valid BSSID
    manager.server.unregister_ap(ap.ap_id)
    manager.register_ap('ValidAP', 'GoodPassword123', bssid='02:00:00:00:01:00')
    # Connect with invalid EAPOL reception simulated by closing server AP socket
    # or wrong PSK
    state_changes = []
    with patch(
        'cirque.virtual_wifi.docker_wifi_bridge._recv_exact',
        return_value=None,
    ):
      res = manager.connect_station_to_ap(
          'sta_conn_test',
          'ValidAP',
          'WrongPassphrase123',
          on_state_change=state_changes.append,
      )
      self.assertFalse(res['ok'])
      self.assertEqual(res['reason'], 'msg1_processing_failed')

    # 7. Tap station container configuration and IPv6 addr assignment ->
    # L1376-1389, 1396
    mock_node_tap = MagicMock()
    mock_container_tap = MagicMock()
    mock_node_tap.container = mock_container_tap
    mock_node_tap.tap_interface = 'cirque_tap0'
    mock_node_tap.is_tap_station = True
    manager.register_station('sta_tap', idx=4, is_ap=False)
    manager._station_nodes['sta_tap'] = mock_node_tap

    # Connect successfully by using the real password
    res = manager.connect_station_to_ap('sta_tap', 'ValidAP', 'GoodPassword123')
    self.assertTrue(res['ok'])
    # Assert tap interface was brought up -> L1376-1389
    mock_container_tap.exec_run.assert_called()

    # Non-tap station with IPv6 address -> L1396
    mock_node_phy = MagicMock()
    mock_container_phy = MagicMock()
    mock_node_phy.container = mock_container_phy
    mock_node_phy.tap_interface = None
    mock_node_phy.is_tap_station = False
    manager.register_station('sta_phy', idx=5, is_ap=False)
    manager._station_ips['sta_phy'] = ('10.0.1.23', 'fd11:22::23')
    manager._station_nodes['sta_phy'] = mock_node_phy
    res_phy = manager.connect_station_to_ap(
        'sta_phy', 'ValidAP', 'GoodPassword123'
    )
    self.assertTrue(res_phy['ok'])
    mock_container_phy.exec_run.assert_called()

    # 8. PCAP writing in connect_station_to_ap -> L1354, 1356-1362
    with tempfile.TemporaryDirectory() as pcap_tmp:
      pcap_path = os.path.join(pcap_tmp, 'eapol_test.pcap')
      with patch.dict(os.environ, {'CIRQUE_EAPOL_TAP_PATH': pcap_path}):
        res_pcap = manager.connect_station_to_ap(
            'sta_phy', 'ValidAP', 'GoodPassword123'
        )
        self.assertTrue(res_pcap['ok'])
        self.assertTrue(os.path.exists(pcap_path))

    # 9. Station not registered -> L1162
    bad_sta_res = manager.connect_station_to_ap(
        'nonexistent_sta', 'ValidAP', 'pass'
    )
    self.assertFalse(bad_sta_res['ok'])

    manager.stop_all()
    vwifi_server.stop()

  def test_docker_manager_lifecycle_and_station_ops(self):
    """Verify disconnect_station, unregister_station, stop_all, and dbus dir."""
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    manager = DockerVirtualWiFiManager(
        server=vwifi_server, runtime_dir=self.tmp_dir
    )

    mock_container = MagicMock()
    mock_node = MagicMock()
    mock_node.container = mock_container
    manager.register_station('sta_ops', idx=1, is_ap=False)
    manager._station_nodes['sta_ops'] = mock_node

    # 1. get_container_dbus_dir -> L897
    dbus_dir = manager.get_container_dbus_dir('sta_ops')
    self.assertTrue(os.path.exists(dbus_dir))

    # 2. disconnect_station with container flush -> L1422-1430
    manager.disconnect_station('sta_ops')
    mock_container.exec_run.assert_called()

    # 3. unregister_station -> L1433-1437
    manager.unregister_station('sta_ops')
    self.assertNotIn('sta_ops', manager._station_nodes)

    # 4. stop_all -> L1456-1461
    manager.stop_all()

  def test_docker_manager_setup_container_interface_tap(self):
    """Verify setup_container_interface with tap station and auto_connect ->
    L961-985.
    """
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    manager = DockerVirtualWiFiManager(
        server=vwifi_server, runtime_dir=self.tmp_dir
    )
    self.addCleanup(manager.stop_all)

    mock_container = MagicMock()
    mock_node = MagicMock()
    mock_node.container = mock_container
    mock_node.tap_interface = 'my_tap'
    mock_node.is_tap_station = True
    mock_node.wifi_ssid = 'TapSSID'
    mock_node.wifi_psk = 'TapPSK'

    with patch.object(manager, '_handle_auto_connect') as mock_auto:
      manager.setup_container_interface(
          'sta_tap_setup',
          mock_node,
          '02:00:00:00:00:55',
          auto_connect=True,
      )
      mock_auto.assert_called()
      mock_container.exec_run.assert_called()
      exec_cmds = [
          str(call[0][0]) for call in mock_container.exec_run.call_args_list
      ]
      tap_cmd = next(c for c in exec_cmds if 'my_tap' in c)
      self.assertIn('accept_ra=0', tap_cmd)
      self.assertIn('autoconf=0', tap_cmd)
      self.assertIn('router_solicitations=0', tap_cmd)
      self.assertNotIn('disable_ipv6=1', tap_cmd)
      self.assertNotIn('addr flush', tap_cmd)

  def test_docker_manager_data_proxy_startup_failure(self):
    """Verify data_proxy failure during init cleans up control proxy ->
    L825-827.
    """
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    with patch(
        'cirque.common.docker_transport.UnixToTcpProxy.start',
        side_effect=[None, RuntimeError('Data proxy bind failed')],
    ):
      with self.assertRaises(RuntimeError):
        DockerVirtualWiFiManager(server=vwifi_server, runtime_dir=self.tmp_dir)

  def test_dhcp_server_client_handling_flow(self):
    """Verify DHCP server leases conflict causing NAK and commit lease ->
    L305-335.
    """
    server = VirtualDhcpServer('127.0.0.1', 9999)
    server.server = VirtualWiFiServer(pcap_dir=None)

    # Pre-populate another lease on 10.0.1.25
    server.leases['02:00:00:00:00:99'] = '10.0.1.25'

    # Build DHCPREQUEST from a different MAC asking for 10.0.1.25 -> L305-309
    ip_udp_67 = bytearray(300)
    ip_udp_67[0] = 0x45
    ip_udp_67[9] = 17
    struct.pack_into('!HH', ip_udp_67, 20, 68, 67)
    ip_udp_67[28] = 1  # op=1
    ip_udp_67[28 + 2] = 6  # hlen=6
    ip_udp_67[28 + 28 : 28 + 34] = b'\x02\x00\x00\x00\x00\x88'  # client MAC
    ip_udp_67[28 + 236 : 28 + 240] = b'\x63\x82\x53\x63'  # cookie
    opts = bytearray([
        53,
        1,
        3,  # DHCPREQUEST
        50,
        4,
        10,
        0,
        1,
        25,  # opt 50: 10.0.1.25
        255,
    ])
    frame_conflict = (
        b'\x00' * 12
        + struct.pack('!H', 0x0800)
        + bytes(ip_udp_67[: 28 + 240])
        + bytes(opts)
    )
    with patch.object(server, '_send_reply') as mock_reply:
      server._handle_frame(frame_conflict)
      mock_reply.assert_called()
      self.assertEqual(mock_reply.call_args[1].get('msg_type'), 6)  # NAK

    # Now request with prior offer -> commit lease -> L318-335
    server.offers['02:00:00:00:00:88'] = '10.0.1.26'
    opts_valid = bytearray([
        53,
        1,
        3,  # DHCPREQUEST
        50,
        4,
        10,
        0,
        1,
        26,  # opt 50: 10.0.1.26
        255,
    ])
    frame_valid = (
        b'\x00' * 12
        + struct.pack('!H', 0x0800)
        + bytes(ip_udp_67[: 28 + 240])
        + bytes(opts_valid)
    )
    with patch.object(server, '_send_reply') as mock_reply:
      server._handle_frame(frame_valid)
      mock_reply.assert_called()
      self.assertEqual(mock_reply.call_args[1].get('msg_type'), 5)  # ACK
      self.assertEqual(server.leases.get('02:00:00:00:00:88'), '10.0.1.26')

  def test_dhcp_and_ra_server_run_loops(self):
    """Verify VirtualDhcpServer and VirtualRaServer run loop connections."""
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    vwifi_server.start()

    # 1. VirtualDhcpServer run loop connect, break, and exception ->
    # L182-183, 200, 202-206
    dhcp = VirtualDhcpServer(
        server_host='127.0.0.1',
        data_port=vwifi_server.data_port,
        server=vwifi_server,
    )
    dhcp.start()
    time.sleep(0.05)
    # Trigger exception in loop
    with patch.object(
        dhcp,
        '_recv_exact',
        side_effect=[b'\x00\x05', b'12345', RuntimeError('loop exc'), None],
    ):
      time.sleep(0.05)
    dhcp.stop()

    # 2. VirtualRaServer run loop connect, break, and exception ->
    # L598-599, 615, 619-623
    ra = VirtualRaServer(
        server_host='127.0.0.1',
        data_port=vwifi_server.data_port,
        server=vwifi_server,
        interval=0.1,
    )
    ra.start()
    time.sleep(0.05)
    with patch.object(
        ra, '_send_ra', side_effect=[RuntimeError('ra exc'), None]
    ):
      time.sleep(0.05)
    ra.stop()

    vwifi_server.stop()

  def test_connect_station_to_ap_edge_failures(self):
    """Verify control socket EOF/failure, ap_handshake_incomplete, and pcap
    error.
    """
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    vwifi_server.start()
    manager = DockerVirtualWiFiManager(
        server=vwifi_server, runtime_dir=self.tmp_dir
    )
    self.addCleanup(manager.stop_all)

    mock_node = MagicMock()
    mock_node.container = MagicMock()
    mock_node.tap_interface = None
    mock_node.is_tap_station = False
    manager.register_station('sta_edge', idx=1, is_ap=False)
    manager._station_nodes['sta_edge'] = mock_node
    manager.register_ap('EdgeAP', 'Password123')

    # 1. Control socket EOF -> L1195-1196
    with patch('socket.create_connection') as mock_conn:
      s_data_c = MagicMock()
      s_ctrl = MagicMock()
      s_ctrl.__enter__.return_value = s_ctrl
      mock_f = MagicMock()
      mock_f.readline.return_value = ''  # EOF
      s_ctrl.makefile.return_value = mock_f
      mock_conn.side_effect = [s_data_c, s_ctrl]
      res = manager.connect_station_to_ap('sta_edge', 'EdgeAP', 'Password123')
      self.assertFalse(res['ok'])
      self.assertEqual(res['reason'], 'control_socket_eof')

    # 2. Control RPC failure exception -> L1202-1205
    with patch('socket.create_connection') as mock_conn:
      s_data_c = MagicMock()
      s_ctrl = MagicMock()
      s_ctrl.sendall.side_effect = OSError('control send error')
      mock_conn.side_effect = [s_data_c, s_ctrl]
      res = manager.connect_station_to_ap('sta_edge', 'EdgeAP', 'Password123')
      self.assertFalse(res['ok'])
      self.assertEqual(res['reason'], 'control_rpc_failed')

    # 3. AP handshake incomplete timeout -> L1343-1348
    # Supplicant completes but server.get_station(sta).state never becomes
    # 'completed'
    state_changes = []
    with patch.object(vwifi_server, 'get_station') as mock_gst:
      fake_st = MagicMock()
      fake_st.mac_addr = '02:00:00:00:02:11'
      fake_st.state = 'authenticating'  # never completed
      mock_gst.return_value = fake_st
      with patch(
          'cirque.virtual_wifi.docker_wifi_bridge.Wpa2SupplicantStateMachine'
      ) as mock_supp_cls:
        mock_supp = MagicMock()
        mock_supp.handle_eapol_frame.return_value = True
        mock_supp.state = 'completed'
        mock_supp_cls.return_value = mock_supp
        # Return EAPOL bytes directly through _recv_next_eapol
        with patch.object(manager, 'connect_station_to_ap') as orig_conn:
          pass
        raw_eapol = b'\x00' * 100
        with patch('cirque.virtual_wifi.docker_wifi_bridge.time.sleep'):
          # Patch connect_station_to_ap internal _recv_next_eapol
          with patch(
              'cirque.virtual_wifi.docker_wifi_bridge._recv_exact',
              side_effect=[
                  struct.pack('!H', 114),
                  b'\x02\x00\x00\x00\x02\x11\x02\x00\x00\x00\x01\x00\x88\x8e'
                  + raw_eapol,
                  struct.pack('!H', 114),
                  b'\x02\x00\x00\x00\x02\x11\x02\x00\x00\x00\x01\x00\x88\x8e'
                  + raw_eapol,
                  None,
              ],
          ):
            mock_supp_frames = [b'msg2', b'msg4']
            with patch.object(
                Wpa2SupplicantStateMachine, 'start_association'
            ):
              with patch.object(
                  mock_supp, 'handle_eapol_frame', return_value=True
              ):
                mock_supp_cls.return_value = mock_supp
                # Manually invoke with mock_supp_frames
                res = manager.connect_station_to_ap(
                    'sta_edge',
                    'EdgeAP',
                    'Password123',
                    on_state_change=state_changes.append,
                )
                self.assertFalse(res['ok'])
                self.assertIn('disconnected', state_changes)

    # 4. PCAP write error handling -> L1361-1362
    with patch.dict(
        os.environ,
        {'CIRQUE_EAPOL_TAP_PATH': '/dev/null/impossible_dir/test.pcap'},
    ):
      with patch(
          'cirque.virtual_wifi.docker_wifi_bridge._write_pcap_frames',
          side_effect=OSError('pcap write fail'),
      ):
        # Connect successfully to hit pcap write
        res = manager.connect_station_to_ap('sta_edge', 'EdgeAP', 'Password123')
        self.assertTrue(res['ok'])

    # 5. Handshake incomplete (supplicant.state != 'completed') -> L1320-1323
    def _make_mock_supp(*args, **kwargs):
      on_send = kwargs.get('on_send_frame')
      mock_supp = MagicMock()

      def _fake_handle(frame):
        if on_send:
          on_send(b'mock_frame')
        return True

      mock_supp.handle_eapol_frame.side_effect = _fake_handle
      mock_supp.state = 'authenticating'  # Not 'completed'
      return mock_supp

    with patch(
        'cirque.virtual_wifi.docker_wifi_bridge.Wpa2SupplicantStateMachine',
        side_effect=_make_mock_supp,
    ):
      raw_eapol = b'\x00' * 100
      # Pass flen == 0 to hit L1244
      with patch(
          'cirque.virtual_wifi.docker_wifi_bridge._recv_exact',
          side_effect=[
              struct.pack('!H', 0),  # flen == 0 -> L1244
              struct.pack('!H', 114),
              b'\x02\x00\x00\x00\x02\x11\x02\x00\x00\x00\x01\x00\x88\x8e'
              + raw_eapol,
              struct.pack('!H', 114),
              b'\x02\x00\x00\x00\x02\x11\x02\x00\x00\x00\x01\x00\x88\x8e'
              + raw_eapol,
              None,
          ],
      ):
        state_changes_fail = []
        res = manager.connect_station_to_ap(
            'sta_edge',
            'EdgeAP',
            'Password123',
            on_state_change=state_changes_fail.append,
        )
        self.assertFalse(res['ok'])
        self.assertEqual(res['reason'], 'handshake_incomplete')
        self.assertIn('disconnected', state_changes_fail)

    vwifi_server.stop()

  def test_vwifi_phy_ipv6_disable_and_completed_callback_ordering(self):
    """Verify vwifi_phy IPv6 is disabled after all.disable_ipv6=0 and
    on_state_change('completed') fires after wlan0 ULA IPv6 configuration.
    """
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    vwifi_server.start()
    manager = DockerVirtualWiFiManager(
        server=vwifi_server, runtime_dir=self.tmp_dir
    )
    self.addCleanup(manager.stop_all)
    self.addCleanup(vwifi_server.stop)

    events = []
    mock_container = MagicMock()

    def record_exec(cmd, **kwargs):
      events.append(('exec', str(cmd)))
      return MagicMock(exit_code=0, output=b'')

    mock_container.exec_run.side_effect = record_exec
    mock_node = MagicMock()
    mock_node.container = mock_container
    mock_node.tap_interface = None
    mock_node.is_tap_station = False

    manager.setup_container_interface(
        'sta_order', mock_node, '02:00:00:00:02:0b', auto_connect=False
    )
    setup_cmd = events[0][1]
    idx_all = setup_cmd.find('net.ipv6.conf.all.disable_ipv6=0')
    idx_phy = setup_cmd.find('net.ipv6.conf.vwifi_phy.disable_ipv6=1')
    self.assertGreater(idx_all, -1)
    self.assertGreater(idx_phy, idx_all)

    events.clear()
    manager.register_ap('OrderAP', 'OrderPass123')
    res = manager.connect_station_to_ap(
        'sta_order',
        'OrderAP',
        'OrderPass123',
        on_state_change=lambda s: events.append(('state', s)),
    )
    self.assertTrue(res['ok'])
    ula_idx = next(
        i
        for i, (kind, val) in enumerate(events)
        if kind == 'exec' and 'fd11:22::ff:fe00:20b/64 dev wlan0' in val
    )
    completed_idx = next(
        i
        for i, (kind, val) in enumerate(events)
        if kind == 'state' and val == 'completed'
    )
    self.assertGreater(completed_idx, ula_idx)

  def test_dhcp_start_ip_and_ra_source_ip_no_collision(self):
    """Verify start_ip=20, static lease pre-population, and RA src IP."""
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    vwifi_server.start()
    manager = DockerVirtualWiFiManager(
        server=vwifi_server, runtime_dir=self.tmp_dir
    )
    self.addCleanup(manager.stop_all)
    self.addCleanup(vwifi_server.stop)
    self.assertEqual(manager.dhcp_server.start_ip, 20)
    mac, ipv4, _ = manager.register_station('sta_prelease', idx=1, is_ap=False)
    self.assertEqual(ipv4, '10.0.1.11')
    self.assertEqual(manager.dhcp_server.leases.get(mac), '10.0.1.11')
    ra_pkt = manager.ra_server.build_ra_packet()
    src_ip6 = socket.inet_ntop(socket.AF_INET6, ra_pkt[14 + 8 : 14 + 24])
    self.assertEqual(src_ip6, 'fe80::ff:fe00:101')

  def test_static_lease_is_offered_and_acked(self):
    """Regression: a pre-allocated (out-of-pool) lease must be honored.

    The manager reserves 10.0.1.10+idx for each station, below the dynamic
    pool (start_ip=20). DISCOVER must offer that address and REQUEST for it
    must be ACKed, not NAKed.
    """
    vwifi_server = VirtualWiFiServer(pcap_dir=None)
    vwifi_server.start()
    manager = DockerVirtualWiFiManager(
        server=vwifi_server, runtime_dir=self.tmp_dir
    )
    self.addCleanup(manager.stop_all)
    self.addCleanup(vwifi_server.stop)
    mac, ipv4, _ = manager.register_station('sta_static', idx=2, is_ap=False)
    mac_bytes = bytes.fromhex(mac.replace(':', ''))

    def dhcp_frame(msg_type, requested_ip=None):
      payload = bytearray(28 + 240)
      payload[0] = 0x45
      payload[9] = 17
      struct.pack_into('!HH', payload, 20, 68, 67)
      payload[28] = 1  # BOOTREQUEST
      payload[28 + 2] = 6  # hlen
      payload[28 + 28 : 28 + 34] = mac_bytes
      payload[28 + 236 : 28 + 240] = b'\x63\x82\x53\x63'
      opts = bytearray([53, 1, msg_type])
      if requested_ip:
        opts += bytes([50, 4]) + socket.inet_aton(requested_ip)
      opts.append(255)
      return b'\x00' * 12 + struct.pack('!H', 0x0800) + bytes(payload) + opts

    dhcp = manager.dhcp_server
    with patch.object(dhcp, '_send_reply') as mock_reply:
      dhcp._handle_frame(dhcp_frame(1))  # DISCOVER
      self.assertEqual(mock_reply.call_args[1].get('msg_type'), 2)  # OFFER
      self.assertEqual(mock_reply.call_args[1].get('assigned_ip'), ipv4)
    with patch.object(dhcp, '_send_reply') as mock_reply:
      dhcp._handle_frame(dhcp_frame(3, requested_ip=ipv4))  # REQUEST
      self.assertEqual(mock_reply.call_args[1].get('msg_type'), 5)  # ACK
    self.assertEqual(dhcp.leases.get(mac), ipv4)
    self.assertEqual(len(dhcp.leases), 1)


if __name__ == '__main__':
  unittest.main()
