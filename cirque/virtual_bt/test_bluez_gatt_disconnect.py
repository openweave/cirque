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
"""Unit tests verifying defect 4: HCI Disconnect on LE peripheral disconnect."""

import struct
import unittest

from cirque.virtual_bt.bluez_gatt_mixin import BluezGattPeripheralMixin
from cirque.virtual_bt.docker_hci_bridge import VirtualBluezAdapterBridge


class RecordingH4Client:
  """H4 client that records sent HCI commands."""

  def __init__(self):
    self.sent_commands = []

  def send_command(self, opcode: int, params: bytes = b'', timeout: float = 1.0):
    self.sent_commands.append({
        'opcode': opcode,
        'params': params,
        'timeout': timeout,
    })
    return b'\x00'


class DummyDockerManager:

  def __init__(self):
    self.adapter_bridges = {}


class DummyMixinHost(BluezGattPeripheralMixin):

  def __init__(self):
    self.docker_manager = DummyDockerManager()
    self.emitted_signals = []
    self.closed_fds = []

  def _close_peripheral_fds(self, p_cid: str):
    self.closed_fds.append(p_cid)

  def _emit_all(self, object_path: str, interface: str, signal: str, parameters):
    self.emitted_signals.append({
        'path': object_path,
        'interface': interface,
        'signal': signal,
        'params': parameters,
    })


class RecordingInvocation:
  """Records D-Bus method replies."""

  def __init__(self):
    self.returned = []

  def return_value(self, value):
    self.returned.append(value)


class TestBluezGattDisconnect(unittest.TestCase):
  """Tests for defect 4: HCI Disconnect (0x0406, reason 0x13) before clearing handles."""

  def test_disconnect_device_sends_hci_disconnect(self):
    host = DummyMixinHost()
    bridge = VirtualBluezAdapterBridge(
        controller_id='hci0',
        bd_addr='02:00:00:00:01:01',
        host='127.0.0.1',
        dedicated_hci_port=10001,
    )
    h4_client = RecordingH4Client()
    bridge.h4_client = h4_client
    bridge.connected_handles[0x0040] = '02:00:00:00:02:02'

    # Set up peer bridge
    peer_bridge = VirtualBluezAdapterBridge(
        controller_id='hci1',
        bd_addr='02:00:00:00:02:02',
        host='127.0.0.1',
        dedicated_hci_port=10002,
    )
    peer_h4 = RecordingH4Client()
    peer_bridge.h4_client = peer_h4
    peer_bridge.connected_handles[0x0041] = '02:00:00:00:01:01'
    host.docker_manager.adapter_bridges['hci1'] = peer_bridge

    dev_path = '/org/bluez/hci0/dev_02_00_00_00_02_02'
    invocation = RecordingInvocation()
    host._disconnect_device(bridge, dev_path, invocation)
    self.assertEqual(invocation.returned, [None])

    # 1. Verify HCI Disconnect (opcode 0x0406, reason 0x13) sent on bridge
    self.assertEqual(len(h4_client.sent_commands), 1)
    cmd = h4_client.sent_commands[0]
    self.assertEqual(cmd['opcode'], 0x0406)
    self.assertLessEqual(cmd['timeout'], 1.0)
    handle, reason = struct.unpack('<HB', cmd['params'])
    self.assertEqual(handle, 0x0040)
    self.assertEqual(reason, 0x13)
    self.assertEqual(len(bridge.connected_handles), 0)

    # 2. Verify HCI Disconnect sent on peer bridge
    self.assertEqual(len(peer_h4.sent_commands), 1)
    peer_cmd = peer_h4.sent_commands[0]
    self.assertEqual(peer_cmd['opcode'], 0x0406)
    self.assertLessEqual(peer_cmd['timeout'], 1.0)
    p_handle, p_reason = struct.unpack('<HB', peer_cmd['params'])
    self.assertEqual(p_handle, 0x0041)
    self.assertEqual(p_reason, 0x13)
    self.assertEqual(len(peer_bridge.connected_handles), 0)

  def test_disconnect_device_only_drops_that_peer(self):
    """Regression: disconnecting one peer must not drop other links."""
    host = DummyMixinHost()
    bridge = VirtualBluezAdapterBridge(
        controller_id='hci0',
        bd_addr='02:00:00:00:01:01',
        host='127.0.0.1',
        dedicated_hci_port=10001,
    )
    h4_client = RecordingH4Client()
    bridge.h4_client = h4_client
    bridge.connected_handles[0x0040] = '02:00:00:00:02:02'
    bridge.connected_handles[0x0042] = '02:00:00:00:03:03'
    bridge.discovered_gatt[0x0040] = object()
    bridge.discovered_gatt[0x0042] = object()

    host._disconnect_device(
        bridge, '/org/bluez/hci0/dev_02_00_00_00_02_02', RecordingInvocation()
    )

    self.assertEqual(
        [struct.unpack('<HB', c['params'])[0] for c in h4_client.sent_commands],
        [0x0040],
    )
    self.assertEqual(bridge.connected_handles, {0x0042: '02:00:00:00:03:03'})
    self.assertNotIn(0x0040, bridge.discovered_gatt)
    self.assertIn(0x0042, bridge.discovered_gatt)

  def test_disconnect_keeps_handle_reused_while_unlocked(self):
    """A handle reused during the HCI Disconnect wait is a new connection."""
    host = DummyMixinHost()
    bridge = VirtualBluezAdapterBridge(
        controller_id='hci0',
        bd_addr='02:00:00:00:01:01',
        host='127.0.0.1',
        dedicated_hci_port=10001,
    )
    peer = '02:00:00:00:02:02'

    class ReconnectingH4Client(RecordingH4Client):

      def send_command(self, opcode, params=b'', timeout=1.0):
        # The poll thread sees the old link drop and a new one on 0x0040.
        bridge.connected_handles.pop(0x0040)
        bridge.connected_handles[0x0040] = peer
        return super().send_command(opcode, params, timeout)

    bridge.h4_client = ReconnectingH4Client()
    bridge.connected_handles[0x0040] = peer
    old_gen = bridge._active_conn_generations[0x0040]

    self.assertTrue(host._disconnect_bridge_handles(bridge, peer))
    self.assertEqual(bridge.connected_handles, {0x0040: peer})
    self.assertGreater(bridge._active_conn_generations[0x0040], old_gen)

  def test_disconnect_device_skips_teardown_when_reused_while_unlocked(self):
    """_disconnect_device keeps p_bridge and FDs if peer reconnected."""
    host = DummyMixinHost()
    central_addr = '02:00:00:00:01:01'
    peer = '02:00:00:00:02:02'
    bridge = VirtualBluezAdapterBridge(
        controller_id='hci0',
        bd_addr=central_addr,
        host='127.0.0.1',
        dedicated_hci_port=10001,
    )
    peer_bridge = VirtualBluezAdapterBridge(
        controller_id='hci1',
        bd_addr=peer,
        host='127.0.0.1',
        dedicated_hci_port=10002,
    )
    peer_h4 = RecordingH4Client()
    peer_bridge.h4_client = peer_h4
    peer_bridge.connected_handles[0x0041] = central_addr
    host.docker_manager.adapter_bridges['hci1'] = peer_bridge

    class ReconnectingH4Client(RecordingH4Client):

      def send_command(self, opcode, params=b'', timeout=1.0):
        bridge.connected_handles.pop(0x0040)
        bridge.connected_handles[0x0040] = peer
        return super().send_command(opcode, params, timeout)

    bridge.h4_client = ReconnectingH4Client()
    bridge.connected_handles[0x0040] = peer
    invocation = RecordingInvocation()
    host._disconnect_device(
        bridge, '/org/bluez/hci0/dev_02_00_00_00_02_02', invocation
    )

    self.assertEqual(invocation.returned, [None])
    self.assertEqual(bridge.connected_handles, {0x0040: peer})
    self.assertEqual(peer_bridge.connected_handles, {0x0041: central_addr})
    self.assertEqual(peer_h4.sent_commands, [])
    self.assertEqual(host.closed_fds, [])
    self.assertEqual(host.emitted_signals, [])

  def test_disconnect_device_completes_when_poll_already_popped_handle(self):
    """Poll thread popping handle while unlocked still tears down p_bridge."""
    host = DummyMixinHost()
    central_addr = '02:00:00:00:01:01'
    peer = '02:00:00:00:02:02'
    bridge = VirtualBluezAdapterBridge(
        controller_id='hci0',
        bd_addr=central_addr,
        host='127.0.0.1',
        dedicated_hci_port=10001,
    )
    peer_bridge = VirtualBluezAdapterBridge(
        controller_id='hci1',
        bd_addr=peer,
        host='127.0.0.1',
        dedicated_hci_port=10002,
    )
    peer_h4 = RecordingH4Client()
    peer_bridge.h4_client = peer_h4
    peer_bridge.connected_handles[0x0041] = central_addr
    host.docker_manager.adapter_bridges['hci1'] = peer_bridge

    class PollPoppingH4Client(RecordingH4Client):

      def send_command(self, opcode, params=b'', timeout=1.0):
        bridge.connected_handles.pop(0x0040, None)
        return super().send_command(opcode, params, timeout)

    bridge.h4_client = PollPoppingH4Client()
    bridge.connected_handles[0x0040] = peer
    invocation = RecordingInvocation()
    host._disconnect_device(
        bridge, '/org/bluez/hci0/dev_02_00_00_00_02_02', invocation
    )

    self.assertEqual(invocation.returned, [None])
    self.assertEqual(bridge.connected_handles, {})
    self.assertEqual(peer_bridge.connected_handles, {})
    self.assertEqual(host.closed_fds, ['hci1'])
    self.assertEqual(len(host.emitted_signals), 2)


if __name__ == '__main__':
  unittest.main()
