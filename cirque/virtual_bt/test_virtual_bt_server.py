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
"""Unit tests for VirtualBluetoothServer and HCI controller commands."""

import socket
import struct
import time
import unittest

from cirque.virtual_bt.controller import VirtualBluetoothController
from cirque.virtual_bt.hci_h4 import (
    STATUS_ONLY_HCI_OPCODES,
    H4Packet,
    H4PacketType,
    HciOpcode,
    str_to_bdaddr_bytes,
)
from cirque.virtual_bt.link_layer import LinkLayerHub
from cirque.virtual_bt.server import VirtualBluetoothServer

# H4 HCI_Reset command (Vol 4 Part E 7.3.2) and its Command Complete event:
# packet type, event code, length, Num_HCI_Command_Packets, opcode, status.
_H4_HCI_RESET = b'\x01\x03\x0c\x00'
_H4_RESET_COMMAND_COMPLETE = b'\x04\x0e\x04\x01\x03\x0c\x00'


def _recv_exact(sock: socket.socket, size: int) -> bytes:
  buf = b''
  while len(buf) < size:
    chunk = sock.recv(size - len(buf))
    if not chunk:
      break
    buf += chunk
  return buf


class TestVirtualBtServer(unittest.TestCase):
  """Unit tests for VirtualBluetoothServer and HCI parameter validation."""

  def test_hci_0x2006_le_set_adv_params_15_bytes_required(self):
    """Verifies LE_Set_Advertising_Parameters enforces 15-byte parameters.

    Bluetooth Core Spec Vol 4 Part E Section 7.8.5 requires 15 parameter bytes:
    Adv_Interval_Min (2B), Adv_Interval_Max (2B), Adv_Type (1B),
    Own_Address_Type (1B), Peer_Address_Type (1B), Peer_Address (6B),
    Adv_Channel_Map (1B), and Adv_Filter_Policy (1B). Payloads < 15 bytes must
    return status 0x12 (Invalid HCI Command Parameters).
    """
    hub = LinkLayerHub()
    captured_raw = []
    ctrl = VirtualBluetoothController(
        'hci0',
        '00:11:22:33:44:55',
        hub,
    )
    ctrl.add_h4_sink(lambda raw: captured_raw.append(raw))

    # 1. 14-byte payload (missing 1 byte): must return status 0x12
    payload_14 = (
        struct.pack('<HB', HciOpcode.LE_SET_ADVERTISING_PARAMETERS, 14)
        + b'\x00' * 14
    )
    ctrl.process_h4_packet(H4Packet(H4PacketType.COMMAND, payload_14))
    self.assertTrue(len(captured_raw) >= 1)
    raw_evt = captured_raw[-1]
    # H4 Packet Type: 0x04 (EVENT)
    self.assertEqual(raw_evt[0], int(H4PacketType.EVENT))
    # Event Code: 0x0E (Command Complete)
    self.assertEqual(raw_evt[1], 0x0E)
    opcode_resp = struct.unpack_from('<H', raw_evt, 4)[0]
    self.assertEqual(opcode_resp, HciOpcode.LE_SET_ADVERTISING_PARAMETERS)
    status = raw_evt[6]
    self.assertEqual(status, 0x12)

    # 2. 15-byte payload (compliant with Core Spec): must return status 0x00
    captured_raw.clear()
    payload_15 = (
        struct.pack('<HB', HciOpcode.LE_SET_ADVERTISING_PARAMETERS, 15)
        + b'\x00' * 15
    )
    ctrl.process_h4_packet(H4Packet(H4PacketType.COMMAND, payload_15))
    self.assertTrue(len(captured_raw) >= 1)
    raw_evt = captured_raw[-1]
    self.assertEqual(raw_evt[0], int(H4PacketType.EVENT))
    self.assertEqual(raw_evt[1], 0x0E)
    opcode_resp = struct.unpack_from('<H', raw_evt, 4)[0]
    self.assertEqual(opcode_resp, HciOpcode.LE_SET_ADVERTISING_PARAMETERS)
    status = raw_evt[6]
    self.assertEqual(status, 0x00)

  def test_virtual_bt_server_lifecycle(self):
    server = VirtualBluetoothServer(host='127.0.0.1')
    server.start()
    try:
      ctrl = server.create_controller('test_hci0', dedicated_port=True)
      self.assertEqual(ctrl.state.controller_id, 'test_hci0')
      self.assertIsNotNone(server.get_controller('test_hci0'))
    finally:
      server.stop()

  def test_bind_preamble_split_across_tcp_segments_still_binds(self):
    """A BIND line delivered in two TCP segments binds the named controller.

    pty_bridge writes `BIND <id>\\n` in one call, but the emulator user-mode
    network and the container TCP-to-Unix relay re-segment the stream. A
    partial first segment must not be mistaken for raw H4, which would hand
    the Android stack an anonymous ephemeral controller and leave the named
    one unbound.
    """
    server = VirtualBluetoothServer(host='127.0.0.1')
    server.start()
    try:
      with socket.create_connection(
          ('127.0.0.1', server.hci_port), timeout=5.0
      ) as sock:
        sock.sendall(b'BIND andro')
        time.sleep(0.2)
        sock.sendall(b'id_hci9\n' + _H4_HCI_RESET)
        self.assertEqual(_recv_exact(sock, 7), _H4_RESET_COMMAND_COMPLETE)
        self.assertIsNotNone(server.get_controller('android_hci9'))
      # A BIND-created controller outlives its H4 connection.
      time.sleep(0.2)
      self.assertIsNotNone(server.get_controller('android_hci9'))
      self.assertEqual(
          [c['controller_id'] for c in server.list_controllers()],
          ['android_hci9'],
      )
    finally:
      server.stop()

  def test_h4_stream_without_bind_is_served_ephemerally_and_logged(self):
    """Raw H4 on the shared port gets a warning and a per-connection controller.

    Negative control for the BIND handshake: the stream still works (so a
    plain H4 client is not broken), but the controller is not findable by a
    name and vanishes when the connection closes, and the server says so.
    """
    server = VirtualBluetoothServer(host='127.0.0.1')
    server.start()
    try:
      with self.assertLogs('VirtualBtServer', level='WARNING') as logs:
        with socket.create_connection(
            ('127.0.0.1', server.hci_port), timeout=5.0
        ) as sock:
          sock.sendall(_H4_HCI_RESET)
          self.assertEqual(_recv_exact(sock, 7), _H4_RESET_COMMAND_COMPLETE)
          ids = [c['controller_id'] for c in server.list_controllers()]
          self.assertEqual(len(ids), 1)
          self.assertIsNone(server.get_controller('android_hci0'))
      joined = '\n'.join(logs.output)
      self.assertIn('sent no BIND preamble', joined)
      self.assertIn(repr(_H4_HCI_RESET), joined)
      self.assertIn(ids[0], joined)
      for _ in range(50):
        if not server.list_controllers():
          break
        time.sleep(0.1)
      self.assertEqual(server.list_controllers(), [])
    finally:
      server.stop()

  def test_informational_commands_return_well_formed_parameters(self):
    """Verifies codec and MWS reads carry their spec return parameters.

    Android host stacks send Read_Local_Supported_Codecs (0x100D, Vol 4
    Part E 7.4.8) and Get_MWS_Transport_Layer_Configuration (0x140C, 7.5.11)
    during bring-up. A status-only Command Complete is malformed for both,
    so the controller must answer with the counts set to zero.
    """
    hub = LinkLayerHub()
    captured_raw = []
    ctrl = VirtualBluetoothController('hci0', '00:11:22:33:44:55', hub)
    ctrl.add_h4_sink(lambda raw: captured_raw.append(raw))

    expected = {
        HciOpcode.READ_LOCAL_SUPPORTED_CODECS: b'\x00\x00',
        HciOpcode.GET_MWS_TRANSPORT_LAYER_CONFIGURATION: b'\x00',
    }
    for opcode, return_params in expected.items():
      captured_raw.clear()
      ctrl.process_h4_packet(
          H4Packet(H4PacketType.COMMAND, struct.pack('<HB', opcode, 0))
      )
      self.assertEqual(len(captured_raw), 1)
      raw_evt = captured_raw[0]
      self.assertEqual(raw_evt[0], int(H4PacketType.EVENT))
      self.assertEqual(raw_evt[1], 0x0E)
      # Parameter total length covers Num_HCI_Command_Packets (1), opcode
      # (2), status (1) and the return parameters.
      self.assertEqual(raw_evt[2], 4 + len(return_params))
      self.assertEqual(struct.unpack_from('<H', raw_evt, 4)[0], opcode)
      self.assertEqual(raw_evt[6], 0x00)
      self.assertEqual(raw_evt[7:], return_params)

    # Negative control: a status-only command (LE_Set_Default_PHY, 0x2031,
    # answered by the generic fallback) stays status-only.
    captured_raw.clear()
    ctrl.process_h4_packet(
        H4Packet(
            H4PacketType.COMMAND,
            struct.pack('<HB', 0x2031, 3) + b'\x00\x01\x01',
        )
    )
    self.assertEqual(captured_raw[0][2], 4)
    self.assertEqual(captured_raw[0][7:], b'')

  @staticmethod
  def _command_complete(ctrl, opcode, params=b''):
    """Sends one HCI command and returns (status, return_params)."""
    captured_raw = []
    ctrl.add_h4_sink(captured_raw.append)
    try:
      ctrl.process_h4_packet(
          H4Packet(
              H4PacketType.COMMAND,
              struct.pack('<HB', opcode, len(params)) + params,
          )
      )
    finally:
      ctrl.remove_h4_sink(captured_raw.append)
    events = [raw for raw in captured_raw if raw[0] == H4PacketType.EVENT]
    raw_evt = events[-1]
    if raw_evt[1] != 0x0E:
      raise AssertionError(f'expected Command Complete, got {raw_evt.hex()}')
    if struct.unpack_from('<H', raw_evt, 4)[0] != opcode:
      raise AssertionError(f'wrong opcode in {raw_evt.hex()}')
    if raw_evt[2] != len(raw_evt) - 3:
      raise AssertionError(f'bad parameter length in {raw_evt.hex()}')
    return raw_evt[6], raw_evt[7:]

  def test_status_only_opcodes_measured_from_android_host_succeed(self):
    """The status-only commands an Android host sends keep returning Success.

    The opcode list is the set that fell through to the generic fallback in
    the Android emulator HCI capture (bt_hci_android_hci0.pcap). Every one
    of them is defined by the Core Spec to return only a Status, so the
    allowlist must cover them and the reply must stay status-only.
    """
    measured = {
        0x080F, 0x0C18, 0x0C1A, 0x0C1C, 0x0C1E, 0x0C24, 0x0C26, 0x0C56,
        0x0C5B, 0x0C63, 0x0C84, 0x2024, 0x2029, 0x202E, 0x2031,
    }
    self.assertEqual(measured, set(int(op) for op in STATUS_ONLY_HCI_OPCODES))
    ctrl = VirtualBluetoothController(
        'hci0', '00:11:22:33:44:55', LinkLayerHub()
    )
    for opcode in sorted(STATUS_ONLY_HCI_OPCODES):
      status, return_params = self._command_complete(ctrl, opcode, b'\x00\x08')
      self.assertEqual((opcode, status), (opcode, 0x00))
      self.assertEqual(return_params, b'')

  def test_unimplemented_opcode_returns_unknown_hci_command(self):
    """Opcodes without a handler are rejected instead of faked as Success.

    Read_Loopback_Mode (0x1801, Vol 4 Part E 7.6.1) is a real command this
    controller does not implement, so it must get error code 0x01 (Unknown
    HCI Command). Vendor-specific opcodes keep the same answer, and an
    implemented read keeps returning Success with its parameters.
    """
    ctrl = VirtualBluetoothController(
        'hci0', '00:11:22:33:44:55', LinkLayerHub()
    )
    self.assertNotIn(0x1801, STATUS_ONLY_HCI_OPCODES)
    self.assertEqual(self._command_complete(ctrl, 0x1801), (0x01, b''))
    self.assertEqual(self._command_complete(ctrl, 0xFD53), (0x01, b''))
    status, return_params = self._command_complete(
        ctrl, HciOpcode.LE_READ_BUFFER_SIZE
    )
    self.assertEqual(status, 0x00)
    self.assertEqual(return_params, struct.pack('<HB', 251, 16))

  def test_le_set_data_length_returns_connection_handle(self):
    """LE_Set_Data_Length answers with Status and Connection_Handle.

    Vol 4 Part E 7.8.33 defines both return parameters; the Android host
    sends this command right after every connection. The connection is made
    for real between two in-process controllers on one LinkLayerHub.
    """
    hub = LinkLayerHub()
    central = VirtualBluetoothController('hci0', '00:11:22:33:44:55', hub)
    periph = VirtualBluetoothController('hci1', '66:77:88:99:AA:BB', hub)
    request = struct.pack('<HHH', 0x0040, 251, 2120)

    # Negative control: no connection exists yet, so the handle is unknown.
    self.assertEqual(
        self._command_complete(central, HciOpcode.LE_SET_DATA_LENGTH, request),
        (0x02, struct.pack('<H', 0x0040)),
    )
    # Negative control: truncated parameters are invalid, handle echoed.
    self.assertEqual(
        self._command_complete(
            central, HciOpcode.LE_SET_DATA_LENGTH, request[:2]
        ),
        (0x12, struct.pack('<H', 0x0040)),
    )

    create_conn = (
        struct.pack('<HHBB', 0x0060, 0x0030, 0x00, 0x00)
        + str_to_bdaddr_bytes(periph.state.bd_addr)
        + struct.pack('<BHHHHHH', 0x00, 24, 24, 0, 500, 0, 0)
    )
    central.process_h4_packet(
        H4Packet(
            H4PacketType.COMMAND,
            struct.pack('<HB', HciOpcode.LE_CREATE_CONNECTION, len(create_conn))
            + create_conn,
        )
    )
    self.assertIn(0x0040, central.state.connections)
    self.assertIn(0x0040, periph.state.connections)
    self.assertEqual(
        self._command_complete(central, HciOpcode.LE_SET_DATA_LENGTH, request),
        (0x00, struct.pack('<H', 0x0040)),
    )
    central.close()
    periph.close()


if __name__ == '__main__':
  unittest.main()
