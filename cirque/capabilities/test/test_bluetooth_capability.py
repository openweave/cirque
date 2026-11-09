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
"""Unit and E2E tests for the Cirque TCP/IP Virtual Bluetooth Controller."""

import ast
import glob
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import termios
import time
import unittest

from cirque.capabilities.bluetoothcapability import BlueToothCapability
from cirque.common.isolated_runtime_dirs import isolate_virtual_runtime_dirs
from cirque.virtual_bt import (
    H4Packet,
    H4PacketType,
    H4StreamParser,
    H4TcpClient,
    VirtualBluetoothServer,
    VirtualBtControlClient,
)
from cirque.virtual_bt.att_db import (
    ATT_ERR_ATTRIBUTE_NOT_FOUND,
    ATT_ERR_INVALID_HANDLE,
    ATT_OP_ERROR_RSP,
    ATT_OP_EXCHANGE_MTU_RSP,
    ATT_OP_FIND_BY_TYPE_VALUE_RSP,
    ATT_OP_FIND_INFO_RSP,
    ATT_OP_READ_BY_GROUP_TYPE_RSP,
    ATT_OP_READ_BY_TYPE_RSP,
    ATT_OP_WRITE_REQ,
    ATT_OP_WRITE_RSP,
    GATT_CHARACTERISTIC_UUID16,
    GATT_CLIENT_CHAR_CONFIG_UUID16,
    GATT_PRIMARY_SERVICE_UUID16,
    AttDatabase,
    AttServer,
    build_att_database_from_gatt_objects,
    decode_error_rsp,
    decode_find_by_type_value_rsp,
    decode_find_info_rsp,
    decode_read_by_group_type_rsp,
    decode_read_by_type_rsp,
    encode_exchange_mtu_req,
    encode_find_by_type_value_req,
    encode_find_info_req,
    encode_read_by_group_type_req,
    encode_read_by_type_req,
    encode_write_req,
)
from cirque.virtual_bt.bluez_dbus_daemon import BluezDbusVirtualService
from cirque.virtual_bt.docker_hci_bridge import DockerVirtualBtManager
from cirque.protocols.matter.ble_bridge import (
    MATTER_C1_UUID_STR,
    MATTER_C2_UUID_STR,
    MATTER_SERVICE_UUID_STR,
)
from cirque.virtual_bt.adapter_bridge import VirtualBluezAdapterBridge


def setUpModule():
  unittest.addModuleCleanup(isolate_virtual_runtime_dirs())


def create_test_matter_att_database(start_handle: int = 1) -> AttDatabase:
  """Test helper creating an AttDatabase for Matter commissioning."""
  db = AttDatabase(start_handle=start_handle)
  svc_h = db.add_primary_service(MATTER_SERVICE_UUID_STR)
  db.add_characteristic(svc_h, MATTER_C1_UUID_STR, properties=0x08)
  db.add_characteristic(svc_h, MATTER_C2_UUID_STR, properties=0x20)
  db.add_descriptor(
      svc_h, GATT_CLIENT_CHAR_CONFIG_UUID16, is_cccd=True
  )
  return db


class TestVirtualBluetoothControllerSystem(unittest.TestCase):
  """Tests Control, HCI (H4), Link Layer (PHY), and Docker HCI/BlueZ bridges."""

  def setUp(self):
    self.server = VirtualBluetoothServer(
        host='127.0.0.1', control_port=0, hci_port=0, phy_port=0
    )
    self.control_port, self.hci_port, self.phy_port = self.server.start()
    self.control_client = VirtualBtControlClient('127.0.0.1', self.control_port)

  def tearDown(self):
    self.server.stop()
    BlueToothCapability.stop_virtual_server()
    BlueToothCapability.BLE_ADAPTS_LIST.clear()

  def test_h4_stream_parser_fragmented_bytes(self):
    """Verifies H4StreamParser reassembles 1-byte TCP fragments accurately."""
    parser = H4StreamParser()
    pkt1 = H4Packet(H4PacketType.COMMAND, b'\x03\x0c\x00')  # HCI_Reset
    pkt2 = H4Packet(
        H4PacketType.ACL_DATA, b'\x40\x20\x06\x00\x02\x00\x04\x00\xaa\xbb'
    )
    combined = pkt1.to_bytes() + pkt2.to_bytes()

    recovered = []
    for i in range(len(combined)):
      recovered.extend(parser.feed(combined[i : i + 1]))

    self.assertEqual(len(recovered), 2)
    self.assertEqual(recovered[0].packet_type, H4PacketType.COMMAND)
    self.assertEqual(recovered[0].payload, b'\x03\x0c\x00')
    self.assertEqual(recovered[1].packet_type, H4PacketType.ACL_DATA)
    self.assertEqual(recovered[1].payload, pkt2.payload)

  def test_h4_client_survives_idle_longer_than_connect_timeout(self):
    """Regression: connect timeout must not kill the rx thread when idle.

    Previously BlueZ StartDiscovery failed with "HCI opcode 0x200B timed
    out" once the bridge link had been idle for more than 5 seconds.
    """
    ctrl = self.server.create_controller(dedicated_port=True)
    client = H4TcpClient('127.0.0.1', ctrl.dedicated_hci_port, timeout=0.2)
    try:
      time.sleep(0.6)
      client.start_scanning(active=True)
      self.assertEqual(client.read_bd_addr(), ctrl.state.bd_addr)
    finally:
      client.close()

  def test_docker_pty_is_raw_and_does_not_stall_bridge(self):
    """Verifies the HCI PTY does not echo and an unread PTY is harmless."""
    runtime_dir = tempfile.mkdtemp(prefix='cirque_vbt_test_')
    manager = DockerVirtualBtManager(
        '127.0.0.1',
        self.control_port,
        self.hci_port,
        self.phy_port,
        runtime_dir=runtime_dir,
    )
    try:
      ctrl = self.server.create_controller(dedicated_port=True)
      _, bridge = manager.register_controller(
          ctrl.state.controller_id,
          ctrl.state.bd_addr,
          ctrl.dedicated_hci_port,
      )
      pty_bridge = manager.pty_bridges[ctrl.state.controller_id]
      lflag = termios.tcgetattr(pty_bridge.slave_fd)[3]
      self.assertFalse(lflag & termios.ECHO)
      self.assertFalse(lflag & termios.ICANON)
      # Nobody reads the PTY slave; the D-Bus bridge must keep working.
      for _ in range(200):
        bridge.h4_client.read_bd_addr()
      bridge.h4_client.start_scanning(active=True)
    finally:
      manager.stop_all()
      shutil.rmtree(runtime_dir, ignore_errors=True)

  def test_control_channel_device_lifecycle_and_scenarios(self):
    """Verifies Control/Test TCP channel commands for device management."""
    ping = self.control_client.request({'cmd': 'ping'})
    self.assertEqual(ping['status'], 'ok')
    self.assertEqual(ping['hci_port'], self.hci_port)

    c0 = self.control_client.create_controller(
        controller_id='hci0', bd_addr='AA:BB:CC:11:22:01'
    )
    self.assertEqual(c0['status'], 'ok')
    self.assertEqual(c0['controller']['bd_addr'], 'AA:BB:CC:11:22:01')

    c1 = self.control_client.create_controller(
        controller_id='hci1', bd_addr='AA:BB:CC:11:22:02'
    )
    self.assertEqual(c1['status'], 'ok')

    ctrls = self.control_client.list_controllers()
    self.assertEqual(len(ctrls), 2)

    rssi_resp = self.control_client.set_rssi(
        -68, 'AA:BB:CC:11:22:01', 'AA:BB:CC:11:22:02'
    )
    self.assertEqual(rssi_resp['status'], 'ok')
    self.assertEqual(
        self.server.phy_hub.get_rssi('AA:BB:CC:11:22:01', 'AA:BB:CC:11:22:02'),
        -68,
    )

    del_resp = self.control_client.destroy_controller('hci0')
    self.assertTrue(del_resp['removed'])
    self.assertEqual(len(self.control_client.list_controllers()), 1)

  def test_e2e_ble_advertising_connection_and_matter_btp_data(self):
    """Verifies E2E BLE advertising, scanning, connection, and ACL/BTP."""
    peripheral = H4TcpClient('127.0.0.1', self.hci_port)
    central = H4TcpClient('127.0.0.1', self.hci_port)
    try:
      peripheral.reset()
      central.reset()

      periph_addr = peripheral.read_bd_addr()
      central_addr = central.read_bd_addr()
      self.assertNotEqual(periph_addr, central_addr)

      self.control_client.set_rssi(-52, periph_addr, central_addr)

      matter_adv_payload = bytes.fromhex('0201060b16f6ff00000f5a23010000')
      peripheral.start_advertising(matter_adv_payload)
      central.start_scanning(active=True)

      adv_report = central.wait_for_advertisement(target_bd_addr=periph_addr)
      self.assertEqual(adv_report['bd_addr'], periph_addr)
      self.assertEqual(adv_report['adv_data'], matter_adv_payload)
      self.assertEqual(adv_report['rssi'], -52)

      central_handle = central.connect(periph_addr)
      periph_handle = peripheral.wait_for_connection(central_addr)
      self.assertGreater(central_handle, 0)
      self.assertGreater(periph_handle, 0)

      btp_handshake_req = bytes.fromhex('656c04000000f40005')
      central.send_acl_l2cap(central_handle, 0x0004, btp_handshake_req)
      rx_handle, rx_cid, rx_payload = peripheral.receive_acl_l2cap()
      self.assertEqual(rx_handle, periph_handle)
      self.assertEqual(rx_cid, 0x0004)
      self.assertEqual(rx_payload, btp_handshake_req)

      btp_handshake_rsp = bytes.fromhex('656c0400f40005')
      peripheral.send_acl_l2cap(periph_handle, 0x0004, btp_handshake_rsp)
      c_handle, c_cid, c_payload = central.receive_acl_l2cap()
      self.assertEqual(c_handle, central_handle)
      self.assertEqual(c_cid, 0x0004)
      self.assertEqual(c_payload, btp_handshake_rsp)
    finally:
      peripheral.close()
      central.close()

  def test_cross_instance_link_layer_phy_tcp_bridge(self):
    """Verifies two VirtualBluetoothServer instances bridged via Link Layer."""
    server_b = VirtualBluetoothServer(
        host='127.0.0.1', control_port=0, hci_port=0, phy_port=0
    )
    _, hci_port_b, phy_port_b = server_b.start()
    try:
      bridge_res = self.control_client.bridge_remote_phy(
          '127.0.0.1', phy_port_b
      )
      self.assertEqual(bridge_res['status'], 'ok')

      host_on_a = H4TcpClient('127.0.0.1', self.hci_port)
      host_on_b = H4TcpClient('127.0.0.1', hci_port_b)
      try:
        host_on_a.reset()
        host_on_b.reset()
        addr_a = host_on_a.read_bd_addr()
        addr_b = host_on_b.read_bd_addr()

        host_on_a.start_advertising(b'\x02\x01\x06CrossHostBLE')
        host_on_b.start_scanning(active=True)

        report = host_on_b.wait_for_advertisement(target_bd_addr=addr_a)
        self.assertEqual(report['bd_addr'], addr_a)

        handle_b = host_on_b.connect(addr_a)
        handle_a = host_on_a.wait_for_connection(addr_b)

        host_on_b.send_acl_l2cap(handle_b, 0x0004, b'PING_ACROSS_PHY_TCP')
        _, cid, data = host_on_a.receive_acl_l2cap()
        self.assertEqual(cid, 0x0004)
        self.assertEqual(data, b'PING_ACROSS_PHY_TCP')
      finally:
        host_on_a.close()
        host_on_b.close()
    finally:
      server_b.stop()

  def test_cirque_bluetooth_capability_and_docker_hci_visibility(self):
    """Verifies BlueToothCapability exposes Docker HCI PTY and hciconfig."""
    cap0 = BlueToothCapability(use_virtual_bt_tcp=True)
    cap1 = BlueToothCapability(use_virtual_bt_tcp=True)
    try:
      self.assertEqual(cap0.name, 'Bluetooth')
      self.assertEqual(cap0.ble_adapt, 'hci0')
      self.assertEqual(cap0.ble_adapt_id, 0)
      self.assertEqual(cap1.ble_adapt, 'hci1')
      self.assertEqual(cap1.ble_adapt_id, 1)

      args0 = cap0.get_docker_run_args(None)
      self.assertEqual(args0['environment']['VIRTUAL_BT_ENABLED'], '1')
      self.assertEqual(args0['environment']['BLE_ADAPT'], 'hci0')
      self.assertEqual(args0['environment']['BLE_ADAPT_ID'], '0')
      self.assertTrue(os.path.exists(cap0.pty_device_path))
      self.assertTrue(os.path.exists(cap1.pty_device_path))

      # Verify inside-Docker hciconfig CLI reports hci0 and hci1 via Unix proxy
      hciconfig_bin = cap0.description['hciconfig_path']
      self.assertTrue(os.path.exists(hciconfig_bin))
      out = subprocess.check_output(
          [hciconfig_bin],
          text=True,
          env={**os.environ, 'VIRTUAL_BT_CONTROL_PORT': '1'},
      )
      self.assertIn('hci0:\tType: Primary  Bus: Virtual', out)
      self.assertIn('hci1:\tType: Primary  Bus: Virtual', out)
      self.assertIn('UP RUNNING', out)
      self.assertNotIn('PSCAN', out)
      self.assertNotIn('ISCAN', out)

      # Verify per-container D-Bus directory and org.bluez.conf are mounted
      # without forcing network_mode: host (preserving docker_network: Ipv6).
      rt_dir = os.environ.get('CIRQUE_VIRTUAL_BT_RUNTIME_DIR')
      if not rt_dir:
        rt_dir = '/tmp/cirque_virtual_bt'
        if os.path.lexists(rt_dir) and not os.access(rt_dir, os.W_OK):
          rt_dir = f'/tmp/cirque_virtual_bt_{os.getuid()}'
      self.assertIn(
          f'{rt_dir}/containers/hci0/dbus:/run/dbus',
          args0['volumes'],
      )
      expected_conf_mounts = {
          f'{rt_dir}/org.bluez.conf:/etc/dbus-1/system.d/org.bluez.conf:ro',
          f'/tmp/cirque_virtual_bt_{os.getuid()}/org.bluez.conf:'
          '/etc/dbus-1/system.d/org.bluez.conf:ro',
      }
      self.assertTrue(
          expected_conf_mounts.intersection(args0['volumes']),
          f'Missing org.bluez.conf mount in {args0["volumes"]}',
      )
      self.assertNotIn('network_mode', args0)
      dbus_svc = BlueToothCapability._SHARED_BLUEZ_DBUS
      self.assertIsNotNone(dbus_svc)
      managed = dbus_svc._build_managed_objects_dict()
      self.assertIn('/org/bluez/hci0', managed)
      self.assertIn('/org/bluez/hci1', managed)

      self._verify_matter_ble_over_docker_bridges(cap1.bd_addr)
    finally:
      cap0.disable_capability(None)
      cap1.disable_capability(None)

  def _verify_matter_ble_over_docker_bridges(self, cap1_bd_addr):
    """Verifies DockerVirtualBtManager bridges perform Matter 0xFFF6 BLE."""
    mgr = BlueToothCapability._SHARED_DOCKER_MANAGER
    bridge_central = mgr.adapter_bridges['hci0']
    bridge_periph = mgr.adapter_bridges['hci1']

    bridge_periph.set_att_database(create_test_matter_att_database())
    bridge_periph.start_profile_advertising(discriminator=3584)
    found_addr = bridge_central.scan_for_discriminator(
        discriminator=3584, timeout=3.0
    )
    self.assertEqual(found_addr, cap1_bd_addr)

    handle = bridge_central.connect_to_peripheral(found_addr)
    self.assertGreater(handle, 0)

    deadline = time.time() + 2.0
    while not bridge_periph.connected_handles and time.time() < deadline:
      time.sleep(0.05)
    self.assertTrue(bridge_periph.connected_handles)
    periph_handle = next(iter(bridge_periph.connected_handles.keys()))

    bridge_central.write_request(handle, b'\x65\x6c\x04\x00\x00\x00')
    deadline = time.time() + 2.0
    while not bridge_periph.rx_writes and time.time() < deadline:
      time.sleep(0.05)
    self.assertEqual(bridge_periph.rx_writes[0], b'\x65\x6c\x04\x00\x00\x00')

    ind_payload = b'\x65\x6c\x04\x00\xf4\x00'
    bridge_periph.send_indication(periph_handle, ind_payload)
    deadline = time.time() + 2.0
    while not bridge_central.rx_indications and time.time() < deadline:
      time.sleep(0.05)
    self.assertEqual(bridge_central.rx_indications[0], ind_payload)

  def test_android_hci_socket_and_cli_shims(self):
    """Verifies DockerVirtualBtManager mounts and proxies HCI socket."""
    runtime_dir = tempfile.mkdtemp(prefix='cirque_vbt_android_test_')
    manager = DockerVirtualBtManager(
        '127.0.0.1',
        self.control_port,
        self.hci_port,
        self.phy_port,
        runtime_dir=runtime_dir,
    )
    try:
      ctrl = self.server.create_controller(dedicated_port=True)
      _, _ = manager.register_controller(
          ctrl.state.controller_id,
          ctrl.state.bd_addr,
          ctrl.dedicated_hci_port,
      )
      mounts = manager.get_container_mounts(ctrl.state.controller_id)
      self.assertEqual(len(mounts), 1)
      self.assertTrue(
          any('/dev/virtual_bt/hci_bridge.sock' in m for m in mounts)
      )

      c_dir = os.path.join(manager.containers_dir, ctrl.state.controller_id)
      hci_sock_path = os.path.join(c_dir, 'hci_bridge.sock')
      self.assertTrue(os.path.exists(hci_sock_path))

      unix_client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
      unix_client.connect(hci_sock_path)
      try:
        reset_pkt = H4Packet(H4PacketType.COMMAND, b'\x03\x0c\x00').to_bytes()
        unix_client.sendall(reset_pkt)
        resp = unix_client.recv(1024)
        self.assertGreater(len(resp), 0)
        self.assertEqual(resp[0], H4PacketType.EVENT.value)
      finally:
        unix_client.close()

      manager.unregister_controller(ctrl.state.controller_id)
    finally:
      manager.stop_all()
      shutil.rmtree(runtime_dir, ignore_errors=True)

  def test_hciconfig_shim_dynamic_state_and_negative_failure(self):
    """Verifies hciconfig shim derives values over H4 and handles failures."""
    runtime_dir = tempfile.mkdtemp(prefix='cirque_vbt_hciconfig_test_')
    manager = DockerVirtualBtManager(
        '127.0.0.1',
        self.control_port,
        self.hci_port,
        self.phy_port,
        runtime_dir=runtime_dir,
    )
    try:
      ctrl = self.server.create_controller(
          controller_id='hci5',
          bd_addr='00:11:22:33:44:55',
          dedicated_port=True,
          acl_mtu=512,
          acl_max_pkt=32,
          sco_mtu=128,
          sco_max_pkt=4,
          manufacturer_id=0x004C,
      )
      manager.register_controller(
          ctrl.state.controller_id,
          ctrl.state.bd_addr,
          ctrl.dedicated_hci_port,
      )
      with ctrl._lock:
        ctrl.state.scan_enabled = True
        ctrl.state.adv_enabled = True
      hciconfig_bin = manager.hciconfig_path
      self.assertTrue(os.path.exists(hciconfig_bin))

      # 1. Non-default parameters and LE controller reporting UP RUNNING
      # (PSCAN/ISCAN are BR/EDR scan flags, absent on LE-only adapters even
      # when LE scan or advertising is active).
      res = subprocess.run(
          [hciconfig_bin, '-a', 'hci5'],
          capture_output=True,
          text=True,
          env={
              **os.environ,
              'VIRTUAL_BT_CONTROL_PORT': str(self.control_port),
          },
      )
      self.assertEqual(res.returncode, 0)
      self.assertIn('BD Address: 00:11:22:33:44:55', res.stdout)
      self.assertIn('ACL MTU: 512:32  SCO MTU: 128:4', res.stdout)
      self.assertIn('UP RUNNING', res.stdout)
      self.assertNotIn('PSCAN', res.stdout)
      self.assertNotIn('ISCAN', res.stdout)
      self.assertIn('Manufacturer: (76)', res.stdout)
      self.assertNotIn('Google LLC', res.stdout)
      self.assertRegex(res.stdout, r'RX acl:\d+ events:\d+')
      self.assertRegex(res.stdout, r'TX acl:\d+ commands:\d+')
      self.assertNotIn('RX bytes:', res.stdout)
      self.assertNotIn('TX bytes:', res.stdout)
      self.assertNotIn('errors:', res.stdout)
      self.assertNotIn('dropped:', res.stdout)
      self.assertNotIn('overruns:', res.stdout)
      self.assertNotIn('carrier:', res.stdout)

      # 2. Inactive scan/adv: flags remain UP RUNNING without PSCAN/ISCAN
      with ctrl._lock:
        ctrl.state.scan_enabled = False
        ctrl.state.adv_enabled = False
      res_inactive = subprocess.run(
          [hciconfig_bin, 'hci5'],
          capture_output=True,
          text=True,
          env={
              **os.environ,
              'VIRTUAL_BT_CONTROL_PORT': str(self.control_port),
          },
      )
      self.assertEqual(res_inactive.returncode, 0)
      self.assertIn('UP RUNNING', res_inactive.stdout)
      self.assertNotIn('PSCAN', res_inactive.stdout)
      self.assertNotIn('ISCAN', res_inactive.stdout)

      # 3. Known manufacturer 0x00E0 produces Google LLC
      with ctrl._lock:
        ctrl.state.manufacturer_id = 0x00E0
      res_google = subprocess.run(
          [hciconfig_bin, '-a', 'hci5'],
          capture_output=True,
          text=True,
          env={
              **os.environ,
              'VIRTUAL_BT_CONTROL_PORT': str(self.control_port),
          },
      )
      self.assertEqual(res_google.returncode, 0)
      self.assertIn('Manufacturer: Google LLC (224)', res_google.stdout)

      # 4. Negative test: unreachable H4 port yields non-zero exit and no canned
      # output.
      c_dir = os.path.join(manager.containers_dir, 'hci5')
      hci_sock = os.path.join(c_dir, 'hci_bridge.sock')
      if os.path.exists(hci_sock):
        os.remove(hci_sock)
      ctrl.dedicated_hci_port = 59997
      res_neg = subprocess.run(
          [hciconfig_bin, 'hci5'],
          capture_output=True,
          text=True,
          env={
              **os.environ,
              'VIRTUAL_BT_CONTROL_PORT': str(self.control_port),
          },
      )
      self.assertNotEqual(res_neg.returncode, 0)
      self.assertIn('H4 query failed', res_neg.stderr)
      self.assertNotIn('UP RUNNING', res_neg.stdout)
      self.assertNotIn('BD Address', res_neg.stdout)
      self.assertNotIn('PSCAN', res_neg.stdout)
      self.assertNotIn('ISCAN', res_neg.stdout)
      self.assertNotIn('1024:16', res_neg.stdout)
      self.assertNotIn('64:8', res_neg.stdout)
      self.assertNotIn('Google LLC', res_neg.stdout)
    finally:
      manager.stop_all()
      shutil.rmtree(runtime_dir, ignore_errors=True)


class TestGattDiscoveryAndAttDatabase(unittest.TestCase):
  """Comprehensive tests for genuine ATT/GATT discovery and dynamic handle database."""

  def setUp(self):
    self.server = VirtualBluetoothServer(
        host='127.0.0.1', control_port=0, hci_port=0, phy_port=0
    )
    self.control_port, self.hci_port, self.phy_port = self.server.start()

  def tearDown(self):
    self.server.stop()

  def test_oracle_a_peripheral_database_built_from_registered_gatt_objects(self):
    """Oracle (a): Peripheral database built dynamically from registered GATT objects.

    Handles are assigned sequentially from start_handle (e.g. 10), never fixed constants.
    ATT discovery queries return matching dynamic handles for service, characteristics,
    and CCCD descriptors.
    """
    objects = {
        '/org/bluez/app/service0': {
            'org.bluez.GattService1': {
                'UUID': '0000fff6-0000-1000-8000-00805f9b34fb',
                'Primary': True,
            }
        },
        '/org/bluez/app/service0/char0': {
            'org.bluez.GattCharacteristic1': {
                'UUID': '18ee2ef5-263d-4559-959f-4f9c429f9d11',
                'Service': '/org/bluez/app/service0',
                'Flags': ['write'],
            }
        },
        '/org/bluez/app/service0/char1': {
            'org.bluez.GattCharacteristic1': {
                'UUID': '18ee2ef5-263d-4559-959f-4f9c429f9d12',
                'Service': '/org/bluez/app/service0',
                'Flags': ['indicate'],
            }
        },
        '/org/bluez/app/service0/char1/cccd': {
            'org.bluez.GattDescriptor1': {
                'UUID': '00002902-0000-1000-8000-00805f9b34fb',
                'Characteristic': '/org/bluez/app/service0/char1',
                'Value': b'\x00\x00',
            }
        },
    }

    db = build_att_database_from_gatt_objects(objects, start_handle=10)
    self.assertEqual(db.start_handle, 10)
    self.assertIn(10, db.attributes)
    self.assertEqual(db.attributes[10].end_group_handle, 15)
    self.assertIn(11, db.attributes)
    self.assertIn(12, db.attributes)
    self.assertIn(13, db.attributes)
    self.assertIn(14, db.attributes)
    self.assertIn(15, db.attributes)

    server = AttServer(db)

    # 1. Exchange MTU Request (0x02) -> Response (0x03)
    mtu_req = encode_exchange_mtu_req(512)
    mtu_rsp = server.handle_pdu(mtu_req)
    self.assertEqual(mtu_rsp[0], ATT_OP_EXCHANGE_MTU_RSP)
    server_mtu = struct.unpack_from('<H', mtu_rsp, 1)[0]
    self.assertGreaterEqual(server_mtu, 23)

    # 2. Read By Group Type Request (0x10) for 0x2800 -> Primary Service Discovery
    group_req = encode_read_by_group_type_req(1, 0xFFFF, GATT_PRIMARY_SERVICE_UUID16)
    group_rsp = server.handle_pdu(group_req)
    self.assertEqual(group_rsp[0], ATT_OP_READ_BY_GROUP_TYPE_RSP)
    services = decode_read_by_group_type_rsp(group_rsp)
    self.assertEqual(len(services), 1)
    s_start, s_end, s_uuid = services[0]
    self.assertEqual(s_start, 10)
    self.assertEqual(s_end, 15)

    # 3. Read By Type Request (0x08) for 0x2803 -> Characteristic Discovery
    char_req = encode_read_by_type_req(s_start, s_end, GATT_CHARACTERISTIC_UUID16)
    char_rsp = server.handle_pdu(char_req)
    self.assertEqual(char_rsp[0], ATT_OP_READ_BY_TYPE_RSP)
    chars = decode_read_by_type_rsp(char_rsp)
    self.assertEqual(len(chars), 2)
    self.assertEqual(chars[0][0], 11)
    self.assertEqual(chars[0][2], 12)
    self.assertEqual(chars[1][0], 13)
    self.assertEqual(chars[1][2], 14)

    # 4. Find Information Request (0x04) -> Descriptor Discovery (CCCD after C2 value handle)
    desc_req = encode_find_info_req(15, 15)
    desc_rsp = server.handle_pdu(desc_req)
    self.assertEqual(desc_rsp[0], ATT_OP_FIND_INFO_RSP)
    descs = decode_find_info_rsp(desc_rsp)
    self.assertEqual(len(descs), 1)
    cccd_handle, cccd_uuid = descs[0]
    self.assertEqual(cccd_handle, 15)

  def test_oracle_b_negative_shifted_service_order_shifts_handles_discovery_finds_shifted(self):
    """Oracle (b) NEGATIVE: Shifted service order shifts handles; discovery finds shifted handles.

    Placing a dummy service before Matter shifts all Matter handles. Central discovery
    resolves the shifted handles dynamically and delivers BTP writes successfully.
    """
    ctrl0 = self.server.create_controller(dedicated_port=True)
    ctrl1 = self.server.create_controller(dedicated_port=True)

    bridge_central = VirtualBluezAdapterBridge(
        controller_id=ctrl0.state.controller_id,
        bd_addr=ctrl0.state.bd_addr,
        host='127.0.0.1',
        dedicated_hci_port=ctrl0.dedicated_hci_port,
    )
    bridge_periph = VirtualBluezAdapterBridge(
        controller_id=ctrl1.state.controller_id,
        bd_addr=ctrl1.state.bd_addr,
        host='127.0.0.1',
        dedicated_hci_port=ctrl1.dedicated_hci_port,
    )
    # Registered before start() so a failing start() of either bridge still
    # closes both H4 clients and stops their poll threads.
    self.addCleanup(bridge_periph.stop)
    self.addCleanup(bridge_central.stop)
    bridge_central.start()
    bridge_periph.start()
    try:
      shifted_db = AttDatabase(start_handle=1)
      dummy_svc_h = shifted_db.add_primary_service(0x180A)  # Device Info
      shifted_db.add_characteristic(dummy_svc_h, 0x2A29, properties=0x02)  # Read
      self.assertEqual(dummy_svc_h, 1)

      matter_svc_h = shifted_db.add_primary_service(MATTER_SERVICE_UUID_STR)
      c1_decl_h, c1_val_h = shifted_db.add_characteristic(
          matter_svc_h, MATTER_C1_UUID_STR, properties=0x08
      )
      c2_decl_h, c2_val_h = shifted_db.add_characteristic(
          matter_svc_h, MATTER_C2_UUID_STR, properties=0x20
      )
      cccd_h = shifted_db.add_descriptor(
          matter_svc_h, GATT_CLIENT_CHAR_CONFIG_UUID16, is_cccd=True
      )
      self.assertEqual(matter_svc_h, 4)
      self.assertEqual(c1_val_h, 6)
      self.assertEqual(c2_val_h, 8)
      self.assertEqual(cccd_h, 9)

      bridge_periph.att_server.database = shifted_db
      bridge_periph.start_profile_advertising(discriminator=3840)

      conn_handle = bridge_central.connect_to_peripheral(bridge_periph.bd_addr)
      self.assertGreater(conn_handle, 0)

      disc = bridge_central.discovered_gatt.get(conn_handle)
      self.assertIsNotNone(disc)
      self.assertEqual(disc.service_start_handle, 4)
      self.assertEqual(disc.service_end_handle, 9)
      self.assertEqual(disc.write_value_handle, 6)
      self.assertEqual(disc.indicate_value_handle, 8)
      self.assertEqual(disc.indicate_cccd_handle, 9)
      self.assertTrue(disc.indications_enabled)

      test_payload = b'\x65\x6c\x04\x00\xaa\xbb'
      bridge_central.write_request(conn_handle, test_payload)

      deadline = time.time() + 2.0
      while not bridge_periph.rx_writes and time.time() < deadline:
        time.sleep(0.05)
      self.assertEqual(bridge_periph.rx_writes, [test_payload])
    finally:
      bridge_central.stop()
      bridge_periph.stop()

  def test_oracle_c_negative_tampered_handle_write_gets_att_error_response(self):
    """Oracle (c) NEGATIVE: Tampered handle in write gets ATT Error Response (0x01).

    An ATT write request with an invalid/tampered handle is rejected with
    ATT_ERR_INVALID_HANDLE and is not delivered to the application layer.
    """
    db = create_test_matter_att_database(start_handle=1)
    server = AttServer(db)
    rx_writes = []
    server.on_write_callback = (
        lambda handle, val: rx_writes.append((handle, val))
    )

    tampered_handle = 0x9999
    write_pdu = encode_write_req(tampered_handle, b'\x01\x02\x03\x04')
    rsp_pdu = server.handle_pdu(write_pdu)

    self.assertIsNotNone(rsp_pdu)
    self.assertEqual(rsp_pdu[0], ATT_OP_ERROR_RSP)
    req_op, h_err, err_code = decode_error_rsp(rsp_pdu)
    self.assertEqual(req_op, ATT_OP_WRITE_REQ)
    self.assertEqual(h_err, tampered_handle)
    self.assertEqual(err_code, ATT_ERR_INVALID_HANDLE)
    self.assertEqual(rx_writes, [])

  def test_oracle_d_btp_handshake_travels_over_discovered_handles_after_cccd(
      self,
  ):
    """Oracle (d): BTP handshake over discovered handles after CCCD.

    Verifies Central runs discovery, writes 0x0002 to CCCD, verifies CCCD in
    peripheral DB, and conducts full BTP handshake over discovered C1/C2
    handles.
    """
    ctrl0 = self.server.create_controller(dedicated_port=True)
    ctrl1 = self.server.create_controller(dedicated_port=True)

    bridge_central = VirtualBluezAdapterBridge(
        controller_id=ctrl0.state.controller_id,
        bd_addr=ctrl0.state.bd_addr,
        host='127.0.0.1',
        dedicated_hci_port=ctrl0.dedicated_hci_port,
    )
    bridge_periph = VirtualBluezAdapterBridge(
        controller_id=ctrl1.state.controller_id,
        bd_addr=ctrl1.state.bd_addr,
        host='127.0.0.1',
        dedicated_hci_port=ctrl1.dedicated_hci_port,
    )
    # Registered before start() so a failing start() of either bridge still
    # closes both H4 clients and stops their poll threads.
    self.addCleanup(bridge_periph.stop)
    self.addCleanup(bridge_central.stop)
    bridge_central.start()
    bridge_periph.start()
    try:
      bridge_periph.att_server.database = create_test_matter_att_database(
          start_handle=20
      )
      bridge_periph.start_profile_advertising(discriminator=2048)

      conn_handle = bridge_central.connect_to_peripheral(bridge_periph.bd_addr)
      self.assertGreater(conn_handle, 0)

      disc = bridge_central.discovered_gatt.get(conn_handle)
      self.assertIsNotNone(disc)
      self.assertTrue(disc.indications_enabled)

      cccd_attr = (
          bridge_periph.att_server.database.attributes[disc.indicate_cccd_handle]
      )
      self.assertEqual(cccd_attr.value, b'\x02\x00')
      self.assertEqual(
          bridge_periph.att_server.cccd_states[disc.indicate_cccd_handle], 0x0002
      )

      btp_handshake_req = b'\x65\x6c\x04\x00\x00\x00'
      bridge_central.write_request(conn_handle, btp_handshake_req)

      deadline = time.time() + 2.0
      while not bridge_periph.rx_writes and time.time() < deadline:
        time.sleep(0.05)
      self.assertEqual(bridge_periph.rx_writes, [btp_handshake_req])

      periph_conn_handle = next(iter(bridge_periph.connected_handles.keys()))
      btp_handshake_rsp = b'\x65\x6c\x04\x00\xf4\x00'
      bridge_periph.send_indication(periph_conn_handle, btp_handshake_rsp)

      deadline = time.time() + 2.0
      while not bridge_central.rx_indications and time.time() < deadline:
        time.sleep(0.05)
      self.assertEqual(bridge_central.rx_indications, [btp_handshake_rsp])

      deadline = time.time() + 2.0
      while bridge_periph.att_confirmation_count == 0 and time.time() < deadline:
        time.sleep(0.05)
      self.assertGreater(bridge_periph.att_confirmation_count, 0)
    finally:
      bridge_central.stop()
      bridge_periph.stop()

  def test_oracle_e_ast_verification_zero_except_pass_and_zero_att_handle_constants(self):
    """Oracle (e): AST confirms 0 except Exception: pass and 0 ATT_HANDLE_C* in cirque/virtual_bt/."""
    repo_root = os.path.dirname(
        os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
    )
    vbt_dir = os.path.join(repo_root, 'cirque', 'virtual_bt')
    py_files = glob.glob(os.path.join(vbt_dir, '*.py'))
    self.assertGreater(len(py_files), 5)

    bare_pass_errors = []
    handle_constant_errors = []

    for fpath in py_files:
      fname = os.path.basename(fpath)
      with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()

      if 'ATT_HANDLE_C' in content:
        handle_constant_errors.append(f'{fname} contains ATT_HANDLE_C')

      tree = ast.parse(content, filename=fpath)
      for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
          continue
        is_broad_exc = node.type is None or (
            isinstance(node.type, ast.Name) and node.type.id == 'Exception'
        )
        if not is_broad_exc:
          continue
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
          bare_pass_errors.append(
              f'{fname}:{node.lineno} has unlogged except Exception: pass'
          )
        elif any(isinstance(s, ast.Pass) for s in node.body) and not any(
            isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
            for s in node.body
        ):
          bare_pass_errors.append(
              f'{fname}:{node.lineno} has unlogged pass in except Exception'
          )

    self.assertEqual(
        handle_constant_errors,
        [],
        f'Found ATT_HANDLE_C constants: {handle_constant_errors}',
    )
    self.assertEqual(
        bare_pass_errors,
        [],
        f'Found unlogged except Exception: pass: {bare_pass_errors}',
    )

  def test_oracle_f_negative_unregistered_peripheral_returns_att_error(self):
    """Oracle (f) NEGATIVE: Peripheral with no registered app fails discovery.

    Peripheral starts with empty AttDatabase. ATT Read By Group Type request
    returns ATT_ERR_ATTRIBUTE_NOT_FOUND (0x0A) and discover_gatt raises
    'service not found'.
    """
    ctrl0 = self.server.create_controller(dedicated_port=True)
    ctrl1 = self.server.create_controller(dedicated_port=True)

    bridge_central = VirtualBluezAdapterBridge(
        controller_id=ctrl0.state.controller_id,
        bd_addr=ctrl0.state.bd_addr,
        host='127.0.0.1',
        dedicated_hci_port=ctrl0.dedicated_hci_port,
    )
    # An empty AttDatabase leaves the ATT responder off by default; enable it
    # explicitly so the peripheral answers with ATT Error Responses.
    bridge_periph = VirtualBluezAdapterBridge(
        controller_id=ctrl1.state.controller_id,
        bd_addr=ctrl1.state.bd_addr,
        host='127.0.0.1',
        dedicated_hci_port=ctrl1.dedicated_hci_port,
        att_responder_enabled=True,
    )
    # Registered before start() so a failing start() of either bridge still
    # closes both H4 clients and stops their poll threads.
    self.addCleanup(bridge_periph.stop)
    self.addCleanup(bridge_central.stop)
    bridge_central.start()
    bridge_periph.start()
    try:
      # Initial database is empty
      self.assertEqual(len(bridge_periph.att_server.database.attributes), 0)

      # 1. Direct ATT PDU level verification
      empty_server = AttServer(AttDatabase())
      req = encode_read_by_group_type_req(
          1, 0xFFFF, GATT_PRIMARY_SERVICE_UUID16
      )
      rsp = empty_server.handle_pdu(req)
      self.assertEqual(rsp[0], ATT_OP_ERROR_RSP)
      req_op, h_err, err_code = decode_error_rsp(rsp)
      self.assertEqual(req_op, 0x10)  # ATT_OP_READ_BY_GROUP_TYPE_REQ
      self.assertEqual(err_code, ATT_ERR_ATTRIBUTE_NOT_FOUND)

      # 2. Bridge level: establish connection directly without auto-discovery
      conn_handle = bridge_central.connect_to_peripheral(
          bridge_periph.bd_addr, auto_discover=False
      )
      self.assertGreater(conn_handle, 0)

      with self.assertRaises(RuntimeError) as ctx:
        bridge_central.discover_gatt(conn_handle, timeout=2.0)
      self.assertIn('service not found', str(ctx.exception).lower())
    finally:
      bridge_central.stop()
      bridge_periph.stop()

  def test_oracle_g_negative_registration_failure_returns_dbus_error(self):
    """Oracle (g) NEGATIVE: Malformed GATT registration returns D-Bus error.

    When GattManager1.RegisterApplication is called with an invalid object
    tree (e.g. missing UUID or missing Flags), it returns an error
    (org.bluez.Error.Failed) and no Matter service is discoverable.
    """
    # 1. Test build_att_database_from_gatt_objects validation rejects bad inputs
    bad_objects_no_uuid = {
        '/org/bluez/app/service0': {
            'org.bluez.GattService1': {
                'Primary': True,
            }
        },
    }
    with self.assertRaises(ValueError) as ctx:
      build_att_database_from_gatt_objects(bad_objects_no_uuid)
    self.assertIn('UUID', str(ctx.exception))

    bad_objects_no_flags = {
        '/org/bluez/app/service0': {
            'org.bluez.GattService1': {
                'UUID': '0000fff6-0000-1000-8000-00805f9b34fb',
                'Primary': True,
            }
        },
        '/org/bluez/app/service0/char0': {
            'org.bluez.GattCharacteristic1': {
                'UUID': '18ee2ef5-263d-4559-959f-4f9c429f9d11',
                'Service': '/org/bluez/app/service0',
            }
        },
    }
    with self.assertRaises(ValueError) as ctx:
      build_att_database_from_gatt_objects(bad_objects_no_flags)
    self.assertIn('Flags', str(ctx.exception))

    # 2. Test mock D-Bus invocation receives org.bluez.Error.Failed
    runtime_dir = tempfile.mkdtemp(prefix='cirque_dbus_neg_test_')
    manager = DockerVirtualBtManager(
        '127.0.0.1',
        self.control_port,
        self.hci_port,
        self.phy_port,
        runtime_dir=runtime_dir,
    )
    ctrl = self.server.create_controller(dedicated_port=True)
    _, bridge = manager.register_controller(
        ctrl.state.controller_id,
        ctrl.state.bd_addr,
        ctrl.dedicated_hci_port,
    )
    try:
      dbus_svc = BluezDbusVirtualService(manager)

      class MockInvocation:

        def __init__(self):
          self.error_name = None
          self.error_msg = None
          self.returned_val = None

        def return_dbus_error(self, name, msg):
          self.error_name = name
          self.error_msg = msg

        def return_value(self, val):
          self.returned_val = val

      class MockParams:

        def unpack(self):
          return ('/org/bluez/bad_app', {})

      inv = MockInvocation()
      dbus_svc._handle_method_call(
          connection=None,
          sender=':1.99',
          object_path=f'/org/bluez/{ctrl.state.controller_id}',
          interface_name='org.bluez.GattManager1',
          method_name='RegisterApplication',
          parameters=MockParams(),
          invocation=inv,
      )
      self.assertEqual(inv.error_name, 'org.bluez.Error.Failed')
      self.assertIsNotNone(inv.error_msg)
      # Peripheral database remains empty and app is not recorded
      self.assertEqual(len(bridge.att_server.database.attributes), 0)
      self.assertNotIn(ctrl.state.controller_id, dbus_svc._registered_apps)
      self.assertNotIn(ctrl.state.controller_id, dbus_svc._registered_app_conns)
    finally:
      manager.stop_all()
      shutil.rmtree(runtime_dir, ignore_errors=True)

  def test_oracle_h_ast_verification_zero_create_matter_db_in_production(
      self,
  ):
    """Oracle (h) NEGATIVE: AST confirms 0 create_matter_att_database in vbt.

    Ensures production code under cirque/virtual_bt/ never references or calls
    the legacy create_matter_att_database helper.
    """
    repo_root = os.path.dirname(
        os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
    )
    vbt_dir = os.path.join(repo_root, 'cirque', 'virtual_bt')
    py_files = glob.glob(os.path.join(vbt_dir, '*.py'))
    self.assertGreater(len(py_files), 5)

    forbidden_refs = []
    for fpath in py_files:
      fname = os.path.basename(fpath)
      with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()

      if 'create_matter_att_database' in content:
        forbidden_refs.append(fname)

    self.assertEqual(
        forbidden_refs,
        [],
        f'Found create_matter_att_database in production: {forbidden_refs}',
    )

  def test_chip_build_and_binary_resolution(self):
    """Verifies default controller/device binary and build root resolution."""
    from cirque.home.virtual_home_topology import VirtualHomeTopology
    import tempfile

    # 1. Test default in-container paths
    orig_env = os.environ.copy()
    try:
      os.environ.pop('CIRQUE_CONTROLLER_BIN', None)
      os.environ.pop('CIRQUE_DEVICE_APP_BIN', None)
      os.environ.pop('CIRQUE_HOST_BUILD_DIR', None)
      os.environ.pop('CIRQUE_CONTAINER_MOUNT', None)
      os.environ.pop('CHIP_TOOL_BIN', None)
      os.environ.pop('CHIP_APP_BIN', None)
      os.environ.pop('CHIP_BUILD_ROOT', None)
      os.environ.pop('CHIP_VBT_PATH', None)

      self.assertEqual(
          VirtualHomeTopology.get_default_chip_tool_bin(),
          '/cirque-build/out/controller-cli',
      )
      self.assertEqual(
          VirtualHomeTopology.get_default_chip_app_bin(),
          '/cirque-build/out/device-app',
      )
      self.assertIsNone(VirtualHomeTopology.resolve_chip_build_mount())

      # 2. Test custom binary environment overrides
      os.environ['CHIP_TOOL_BIN'] = '/custom/bin/controller-cli'
      os.environ['CHIP_APP_BIN'] = '/custom/bin/device-app'
      self.assertEqual(
          VirtualHomeTopology.get_default_chip_tool_bin(),
          '/custom/bin/controller-cli',
      )
      self.assertEqual(
          VirtualHomeTopology.get_default_chip_app_bin(),
          '/custom/bin/device-app',
      )

      # 3. Test mount resolution with an out/ directory
      with tempfile.TemporaryDirectory() as tmp_root:
        out_dir = os.path.join(tmp_root, 'out')
        os.makedirs(os.path.join(out_dir, 'bin-subpath'))
        os.environ['CHIP_BUILD_ROOT'] = out_dir

        resolved = VirtualHomeTopology.resolve_chip_build_mount()
        self.assertIsNotNone(resolved)
        self.assertEqual(resolved[0], out_dir)
        self.assertEqual(resolved[1], '/cirque-build/out')

        # 4. Test mount resolution with repository root containing out/
        os.environ['CHIP_BUILD_ROOT'] = tmp_root
        resolved_repo = VirtualHomeTopology.resolve_chip_build_mount()
        self.assertIsNotNone(resolved_repo)
        self.assertEqual(resolved_repo[0], tmp_root)
        self.assertEqual(resolved_repo[1], '/cirque-build')

        # 5. Test fallback to CHIP_VBT_PATH
        os.environ.pop('CHIP_BUILD_ROOT', None)
        os.environ['CHIP_VBT_PATH'] = tmp_root
        resolved_vbt = VirtualHomeTopology.resolve_chip_build_mount()
        self.assertIsNotNone(resolved_vbt)
        self.assertEqual(resolved_vbt[0], tmp_root)
        self.assertEqual(resolved_vbt[1], '/chip-vbt')
    finally:
      os.environ.clear()
      os.environ.update(orig_env)

  def test_find_by_type_value_and_active_scan_zero_recursion(self):
    """Verifies ATT_OP_FIND_BY_TYPE_VALUE_REQ for 0xFFF6 and active scan zero recursion."""
    from cirque.virtual_bt.controller import VirtualBluetoothController, LinkLayerFrame, LinkLayerPduType

    # 1. Verify ATT_OP_FIND_BY_TYPE_VALUE_REQ on AttServer for Matter service 0xFFF6
    db = create_test_matter_att_database(start_handle=10)
    server = AttServer(db)
    find_req = encode_find_by_type_value_req(
        1, 0xFFFF, GATT_PRIMARY_SERVICE_UUID16, 0xFFF6
    )
    find_rsp = server.handle_pdu(find_req)
    self.assertEqual(find_rsp[0], ATT_OP_FIND_BY_TYPE_VALUE_RSP)
    matches = decode_find_by_type_value_rsp(find_rsp)
    self.assertEqual(len(matches), 1)
    found_handle, group_end_handle = matches[0]
    self.assertEqual(found_handle, 10)
    self.assertGreaterEqual(group_end_handle, 12)

    # 2. Verify active scan (unicast SCAN_REQ / SCAN_RSP) produces zero recursion
    from cirque.virtual_bt.link_layer import LinkLayerHub
    phy_hub = LinkLayerHub()
    ctrl_adv = VirtualBluetoothController('ctrl_adv', '11:22:33:44:55:66', phy_hub)
    ctrl_scan = VirtualBluetoothController('ctrl_scan', 'AA:BB:CC:DD:EE:FF', phy_hub)

    # Configure peripheral advertising
    ctrl_adv.state.adv_enabled = True
    ctrl_adv.state.adv_data = b'\x02\x01\x06'
    ctrl_adv.state.scan_rsp_data = b'\x07\x09Matter'

    # Unicast SCAN_REQ sent by active scanner in response to ADV_IND
    unicast_scan_req = LinkLayerFrame(
        pdu_type=LinkLayerPduType.SCAN_REQ.value,
        src_bd_addr='AA:BB:CC:DD:EE:FF',
        dst_bd_addr='11:22:33:44:55:66',
        src_addr_type=0x00,
    )

    # Delivering unicast SCAN_REQ to advertiser must not trigger broadcast_advertising_once
    # recursion loops
    handled = ctrl_adv._on_phy_adv_or_scan(unicast_scan_req)
    self.assertTrue(handled)

    # Broadcast SCAN_REQ from scanner startup triggers one broadcast_advertising_once safely
    bcast_scan_req = LinkLayerFrame(
        pdu_type=LinkLayerPduType.SCAN_REQ.value,
        src_bd_addr='AA:BB:CC:DD:EE:FF',
        dst_bd_addr='FF:FF:FF:FF:FF:FF',
        src_addr_type=0x00,
    )
    handled_bcast = ctrl_adv._on_phy_adv_or_scan(bcast_scan_req)
    self.assertTrue(handled_bcast)

    ctrl_adv.close()
    ctrl_scan.close()

  def test_att_server_resets_mtu_on_set_database_and_reconnect(self):
    """Verifies per-connection ATT MTU resets to 23 on set_database/reconnect.

    Bluetooth Core Spec Vol 3 Part F Section 3.2.8 requires every new LE
    connection to start at ATT_MTU = 23 until Exchange MTU is negotiated on
    that connection. If an earlier connection negotiated MTU 247, a second
    connection's pre-MTU Read By Type Request (0x2803) must still receive a
    <= 23-byte response (1 characteristic) rather than a 44-byte response.
    """
    db = create_test_matter_att_database(start_handle=1)
    server = AttServer(db, mtu=247)
    self.assertEqual(server.effective_mtu, 23)

    # First connection negotiates MTU 247 and enables CCCD
    mtu_rsp = server.handle_pdu(encode_exchange_mtu_req(247))
    self.assertEqual(mtu_rsp[0], ATT_OP_EXCHANGE_MTU_RSP)
    self.assertEqual(server.effective_mtu, 247)
    server.cccd_states[6] = 0x0002

    # At MTU 247, Read By Type for 0x2803 packs both 128-bit characteristics
    # into a single 44-byte PDU (2 + 2 * 21).
    char_req = encode_read_by_type_req(1, 0xFFFF, GATT_CHARACTERISTIC_UUID16)
    rsp_247 = server.handle_pdu(char_req)
    self.assertEqual(len(rsp_247), 44)

    # Re-registering database or resetting connection state restores MTU = 23
    server.set_database(create_test_matter_att_database(start_handle=1))
    self.assertEqual(server.effective_mtu, 23)
    self.assertEqual(server.cccd_states, {})

    # Pre-MTU Read By Type on the next connection must fit within 23 bytes
    rsp_23 = server.handle_pdu(char_req)
    self.assertLessEqual(len(rsp_23), 23)
    self.assertEqual(len(decode_read_by_type_rsp(rsp_23)), 1)

  def test_peripheral_c2_acquire_notify_waits_for_both_c1_and_cccd(self):
    """AcquireNotify must wait for both C1 write and C2 CCCD subscription."""
    from cirque.virtual_bt.bluez_gatt_mixin import BluezGattPeripheralMixin

    class _FakeAttServer:

      def __init__(self):
        self.cccd_states = {}

    class _FakeBridge:

      def __init__(self):
        self.bd_addr = 'AA:BB:CC:DD:EE:02'
        self.connected_handles = {0x0040: 'AA:BB:CC:DD:EE:01'}
        self.att_server = _FakeAttServer()

    class _FakeDockerManager:

      def __init__(self, bridge):
        self.adapter_bridges = {'hci0': bridge}

    class _Harness(BluezGattPeripheralMixin):

      def __init__(self, bridge):
        self.docker_manager = _FakeDockerManager(bridge)
        self._peripheral_c1_fds = {}
        self._peripheral_c2_fds = {}
        self._c1_written_controllers = set()
        self.c2_notify_calls = []

      def _acquire_peripheral_gatt_sockets(self, p_cid, peer_addr):
        r_fd, w_fd = os.pipe()
        self._peripheral_c1_fds[p_cid] = w_fd
        self._pipe_read_fd = r_fd

      def _acquire_peripheral_c2_notify(self, p_cid, peer_addr):
        self.c2_notify_calls.append((p_cid, peer_addr))

    # Case 1 (Android order): C1 write arrives before C2 CCCD write.
    bridge1 = _FakeBridge()
    h1 = _Harness(bridge1)
    try:
      h1._on_peripheral_c1_write('hci0', b'\x65\x6c\x04\x00\x00\xf7\x00\x05')
      time.sleep(0.1)
      self.assertEqual(h1.c2_notify_calls, [])

      bridge1.att_server.cccd_states[6] = 0x0002
      h1._on_peripheral_cccd_write('hci0', 6, 0x0002)
      time.sleep(0.1)
      self.assertEqual(
          h1.c2_notify_calls, [('hci0', 'AA:BB:CC:DD:EE:01')]
      )
    finally:
      h1._close_peripheral_fds('hci0')
      os.close(h1._pipe_read_fd)

    # Case 2 (Linux order): C2 CCCD write arrives before C1 write.
    bridge2 = _FakeBridge()
    h2 = _Harness(bridge2)
    try:
      bridge2.att_server.cccd_states[6] = 0x0002
      h2._on_peripheral_cccd_write('hci0', 6, 0x0002)
      time.sleep(0.1)
      self.assertEqual(h2.c2_notify_calls, [])

      h2._on_peripheral_c1_write('hci0', b'\x65\x6c\x04\x00\x00\xf7\x00\x05')
      time.sleep(0.1)
      self.assertEqual(
          h2.c2_notify_calls, [('hci0', 'AA:BB:CC:DD:EE:01')]
      )
    finally:
      h2._close_peripheral_fds('hci0')
      os.close(h2._pipe_read_fd)

  def test_android_emulator_node_skips_container_linux_dbus_polling(self):
    """AndroidDockerNode uses guest Binder/VHCI and tap, not container D-Bus."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch
    from cirque.capabilities.wificapability import WiFiCapability

    bt_cap = BlueToothCapability(use_virtual_bt_tcp=True)
    wifi_cap = WiFiCapability(use_virtual_wifi_tcp=True)
    android_node = SimpleNamespace(
        type='android_emulator',
        container=MagicMock(),
        capabilities=[bt_cap, wifi_cap],
    )
    with (
        patch.object(
            BlueToothCapability, '_prepare_container_dbus_socket'
        ) as mock_bt_dbus,
        patch.object(
            BlueToothCapability._SHARED_BLUEZ_DBUS, 'attach_container_bus'
        ) as mock_bt_attach,
        patch.object(
            WiFiCapability, '_prepare_container_dbus_socket'
        ) as mock_wifi_dbus,
    ):
      bt_cap.enable_capability(android_node)
      wifi_cap.enable_capability(android_node)
      mock_bt_dbus.assert_not_called()
      mock_bt_attach.assert_not_called()
      mock_wifi_dbus.assert_not_called()

  def test_docker_manager_runtime_dir_unwritable_fallback_and_env_override(
      self,
  ):
    """Unwritable /tmp/cirque_virtual_bt falls back to per-UID runtime_dir."""
    from unittest.mock import patch

    real_lexists = os.path.lexists
    real_access = os.access

    def _fake_lexists(path):
      if path == '/tmp/cirque_virtual_bt':
        return True
      return real_lexists(path)

    def _fake_access(path, mode):
      if path == '/tmp/cirque_virtual_bt' and (mode & os.W_OK):
        return False
      return real_access(path, mode)

    env_without_rt = {
        k: v
        for k, v in os.environ.items()
        if k != 'CIRQUE_VIRTUAL_BT_RUNTIME_DIR'
    }
    with (
        patch.dict(os.environ, env_without_rt, clear=True),
        patch('os.path.lexists', side_effect=_fake_lexists),
        patch('os.access', side_effect=_fake_access),
    ):
      mgr = DockerVirtualBtManager(
          '127.0.0.1', self.control_port, self.hci_port, self.phy_port
      )
      try:
        self.assertEqual(
            mgr.runtime_dir, f'/tmp/cirque_virtual_bt_{os.getuid()}'
        )
      finally:
        mgr.stop_all()

    explicit_dir = tempfile.mkdtemp(prefix='cirque_vbt_explicit_env_')
    try:
      with patch.dict(
          os.environ, {'CIRQUE_VIRTUAL_BT_RUNTIME_DIR': explicit_dir}
      ):
        mgr2 = DockerVirtualBtManager(
            '127.0.0.1', self.control_port, self.hci_port, self.phy_port
        )
        try:
          self.assertEqual(mgr2.runtime_dir, explicit_dir)
        finally:
          mgr2.stop_all()
    finally:
      shutil.rmtree(explicit_dir, ignore_errors=True)


if __name__ == '__main__':
  unittest.main(verbosity=2)
