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
"""Tests that Device1 objects are announced once, as real BlueZ does.

BlueZ emits InterfacesAdded for a Device1 object when it is created and
only PropertiesChanged afterwards. Re-announcing an existing Device1 makes
GDBusObjectManagerClient replace the client's Device1 proxy, dropping any
state the client attached to it.
"""

import threading
import types
import unittest
from unittest import mock

try:
  from gi.repository import GLib  # pylint: disable=unused-import

  HAVE_GI = True
except ImportError:
  HAVE_GI = False

from cirque.virtual_bt.bluez_gatt_mixin import BluezGattPeripheralMixin
from cirque.virtual_bt.docker_hci_bridge import VirtualBluezAdapterBridge

CENTRAL_CID = 'hci0'
CENTRAL_ADDR = '02:00:00:00:01:01'
PERIPH_CID = 'hci1'
PERIPH_ADDR = '02:00:00:00:02:02'
CENTRAL_DEV = f'/org/bluez/{CENTRAL_CID}/dev_02_00_00_00_02_02'
PERIPH_DEV = f'/org/bluez/{PERIPH_CID}/dev_02_00_00_00_01_01'
GATT_CHILDREN = [
    f'{CENTRAL_DEV}/service00',
    f'{CENTRAL_DEV}/service00/char00',
    f'{CENTRAL_DEV}/service00/char01',
]


class DummyDockerManager:

  def __init__(self):
    self.adapter_bridges = {}
    self._lock = threading.RLock()


class DummyMixinHost(BluezGattPeripheralMixin):
  """Mixin host recording emitted D-Bus signals instead of sending them."""

  def __init__(self):
    self.docker_manager = DummyDockerManager()
    self.emitted_signals = []
    self._running = True
    self._lock = threading.RLock()
    self._conn = None
    self._discovered_dev_paths = set()
    self._registered_apps = {}
    self._registered_app_conns = {}
    self._peripheral_c1_fds = {}
    self._peripheral_c2_fds = {}

  def _export_device_gatt_tree(self, controller_id: str, peer_addr: str) -> str:
    return f'/org/bluez/{controller_id}/dev_{peer_addr.replace(":", "_")}'

  def _emit_all(
      self, object_path: str, interface: str, signal: str, parameters
  ):
    self.emitted_signals.append({
        'path': object_path,
        'interface': interface,
        'signal': signal,
        'params': parameters,
    })

  def interfaces_added_paths(self):
    return [
        s['params'].unpack()[0]
        for s in self.emitted_signals
        if s['signal'] == 'InterfacesAdded'
    ]

  def clear_signals(self):
    self.emitted_signals = []


class RecordingInvocation:

  def __init__(self):
    self.returned = []
    self.errors = []

  def return_value(self, value):
    self.returned.append(value)

  def return_dbus_error(self, name, message):
    self.errors.append((name, message))


def _make_bridge(cid: str, addr: str, port: int) -> VirtualBluezAdapterBridge:
  return VirtualBluezAdapterBridge(
      controller_id=cid,
      bd_addr=addr,
      host='127.0.0.1',
      dedicated_hci_port=port,
  )


@unittest.skipUnless(HAVE_GI, 'PyGObject (gi) is required')
class TestBluezGattConnectSignals(unittest.TestCase):
  """Device1 InterfacesAdded must not be re-emitted for a known object."""

  def setUp(self):
    super().setUp()
    self.host = DummyMixinHost()
    self.central = _make_bridge(CENTRAL_CID, CENTRAL_ADDR, 10001)
    self.periph = _make_bridge(PERIPH_CID, PERIPH_ADDR, 10002)
    self.host.docker_manager.adapter_bridges[CENTRAL_CID] = self.central
    self.host.docker_manager.adapter_bridges[PERIPH_CID] = self.periph

    def _fake_connect(peer_addr):
      self.central.connected_handles[0x0040] = peer_addr

    self.central.connect_to_peripheral = _fake_connect
    patcher = mock.patch(
        'cirque.virtual_bt.bluez_gatt_mixin.acquire_gatt_characteristic_fd',
        return_value=None,
    )
    patcher.start()
    self.addCleanup(patcher.stop)

  def _discover_peripheral(self):
    self.central.discovered_peripherals[PERIPH_ADDR] = {
        'bd_addr': PERIPH_ADDR,
        'rssi': -40,
        'discriminator': 3840,
    }
    self.host._on_peripheral_discovered(CENTRAL_CID, PERIPH_ADDR, {})

  def _connect(self):
    invocation = RecordingInvocation()
    self.host._connect_device_worker(
        CENTRAL_CID, self.central, CENTRAL_DEV, invocation
    )
    self.assertEqual(invocation.errors, [])
    self.assertEqual(invocation.returned, [None])

  def _register_peripheral_app(self):
    self.host._registered_apps[PERIPH_CID] = (':1.42', '/chip/app')
    self.host._registered_app_conns[PERIPH_CID] = object()

  def test_connect_announces_only_gatt_children(self):
    self._discover_peripheral()
    self.assertEqual(self.host.interfaces_added_paths()[0], CENTRAL_DEV)

    self.host.clear_signals()
    self._connect()

    self.assertEqual(self.host.interfaces_added_paths(), GATT_CHILDREN)
    connected = [
        s
        for s in self.host.emitted_signals
        if s['path'] == CENTRAL_DEV and s['signal'] == 'PropertiesChanged'
    ]
    self.assertEqual(len(connected), 1)
    iface, changed, _ = connected[0]['params'].unpack()
    self.assertEqual(iface, 'org.bluez.Device1')
    self.assertEqual(changed, {'Connected': True, 'ServicesResolved': True})

  def test_device_announced_once_across_discovery_connect_reconnect(self):
    self._register_peripheral_app()
    self._discover_peripheral()
    # The peripheral side first learns about the central from the HCI
    # connection-complete callback, then from the Connect worker.
    self.periph.connected_handles[0x0041] = CENTRAL_ADDR
    self.host._acquire_peripheral_gatt_sockets(PERIPH_CID, CENTRAL_ADDR)
    self._connect()
    # Disconnect and reconnect.
    self.host._disconnect_device(self.central, CENTRAL_DEV, None)
    self.periph.connected_handles[0x0041] = CENTRAL_ADDR
    self.host._acquire_peripheral_gatt_sockets(PERIPH_CID, CENTRAL_ADDR)
    self._connect()

    added = self.host.interfaces_added_paths()
    self.assertEqual(added.count(CENTRAL_DEV), 1)
    self.assertEqual(added.count(PERIPH_DEV), 1)
    periph_connected = [
        s
        for s in self.host.emitted_signals
        if s['path'] == PERIPH_DEV
        and s['signal'] == 'PropertiesChanged'
        and 'Connected' in s['params'].unpack()[1]
        and s['params'].unpack()[1]['Connected']
    ]
    self.assertEqual(len(periph_connected), 4)

  def test_reset_connections_allows_announcing_again(self):
    # pylint: disable=g-import-not-at-top
    from cirque.virtual_bt.bluez_dbus_daemon import BluezDbusVirtualService

    manager = types.SimpleNamespace(
        dbus_dir='/nonexistent', adapter_bridges={}, _lock=threading.RLock()
    )
    service = BluezDbusVirtualService(manager)
    self.assertTrue(service._mark_device_announced(PERIPH_DEV))
    self.assertFalse(service._mark_device_announced(PERIPH_DEV))
    service.reset_connections()
    self.assertTrue(service._mark_device_announced(PERIPH_DEV))


if __name__ == '__main__':
  unittest.main()
