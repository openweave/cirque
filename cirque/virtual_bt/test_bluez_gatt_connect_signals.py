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

  def test_emit_gatt_tree_added_skips_when_already_announced(self):
    self.central.discovered_peripherals[PERIPH_ADDR] = {
        'bd_addr': PERIPH_ADDR,
        'rssi': -40,
        'discriminator': 3840,
    }
    objs = self.host._build_managed_objects_dict()
    # Marking happens only when base_path is present in objs.
    self.host._emit_gatt_tree_added(CENTRAL_DEV, {})
    self.assertEqual(self.host.interfaces_added_paths(), [])
    self.assertNotIn(
        CENTRAL_DEV, getattr(self.host, '_announced_dev_paths', set())
    )

    # First emit with base_path in objs announces Device1 and GATT children.
    self.host._emit_gatt_tree_added(CENTRAL_DEV, objs)
    self.assertEqual(
        self.host.interfaces_added_paths(), [CENTRAL_DEV] + GATT_CHILDREN
    )

    # Subsequent emit with include_device_path=True skips Device1 because
    # _mark_device_announced returns False, while still emitting GATT children.
    self.host.clear_signals()
    self.host._emit_gatt_tree_added(CENTRAL_DEV, objs)
    self.assertEqual(self.host.interfaces_added_paths(), GATT_CHILDREN)

  def test_rediscovery_after_start_discovery_does_not_reannounce_device(self):
    self._discover_peripheral()
    self.host._discovered_dev_paths.clear()
    self._discover_peripheral()
    self.assertEqual(self.host.interfaces_added_paths().count(CENTRAL_DEV), 1)

  def _make_service(self):
    # pylint: disable=g-import-not-at-top
    from cirque.virtual_bt.bluez_dbus_daemon import BluezDbusVirtualService

    manager = types.SimpleNamespace(
        dbus_dir='/nonexistent',
        adapter_bridges={CENTRAL_CID: self.central},
        _lock=threading.RLock(),
    )
    service = BluezDbusVirtualService(manager)
    service._running = True
    service._emit_all = self.host._emit_all
    self.central.h4_client = types.SimpleNamespace(
        _cv=threading.Condition(), _adv_reports=[]
    )
    return service

  def _service_discover(self, service):
    self.central.discovered_peripherals[PERIPH_ADDR] = {
        'bd_addr': PERIPH_ADDR,
        'rssi': -40,
        'discriminator': 3840,
    }
    service._on_peripheral_discovered(CENTRAL_CID, PERIPH_ADDR, {})

  def _remove_device(self, service, events=None):
    invocation = RecordingInvocation()
    if events is not None:
      orig_return = invocation.return_value

      def tracked_return(value):
        events.append(('reply', value))
        orig_return(value)

      invocation.return_value = tracked_return
    service._handle_adapter_method(
        self.central,
        'RemoveDevice',
        GLib.Variant('(o)', (CENTRAL_DEV,)),
        invocation,
    )
    self.assertEqual(invocation.returned, [None])

  def _interfaces_removed_paths(self):
    return [
        s['params'].unpack()[0]
        for s in self.host.emitted_signals
        if s['signal'] == 'InterfacesRemoved'
    ]

  def test_remove_device_allows_announcing_again(self):
    service = self._make_service()
    self._service_discover(service)
    events = []
    orig_emit = service._emit_all

    def tracked_emit(path, iface, sig, params):
      if sig == 'InterfacesRemoved':
        events.append(('removed', params.unpack()[0]))
      orig_emit(path, iface, sig, params)

    service._emit_all = tracked_emit
    self._remove_device(service, events=events)
    expected_removed = list(reversed(GATT_CHILDREN)) + [CENTRAL_DEV]
    self.assertEqual(self._interfaces_removed_paths(), expected_removed)
    self.assertEqual(
        events,
        [('removed', p) for p in expected_removed] + [('reply', None)],
    )

    # BlueZ exports a new Device1 when a removed device is seen again.
    self._service_discover(service)
    self.assertEqual(self.host.interfaces_added_paths().count(CENTRAL_DEV), 2)

  def test_remove_connected_device_keeps_it_announced(self):
    service = self._make_service()
    self._service_discover(service)
    self.central.connected_handles[0x0040] = PERIPH_ADDR
    self.central.h4_client._adv_reports.append({'bd_addr': PERIPH_ADDR})
    self._remove_device(service)
    # Still connected: adv cache clears, but cached Device1 props stay intact.
    self.assertEqual(self.central.h4_client._adv_reports, [])
    self.assertEqual(self._interfaces_removed_paths(), [])
    self.assertFalse(service._mark_device_announced(CENTRAL_DEV))
    objs_conn = service._build_managed_objects_dict()
    dev_props = objs_conn[CENTRAL_DEV]['org.bluez.Device1']
    self.assertEqual(dev_props['RSSI'].unpack(), -40)
    self.assertTrue(dev_props['Connected'].unpack())

    # Normal disconnect keeps Device1 in GetManagedObjects (cirque#70).
    service._disconnect_device(self.central, CENTRAL_DEV, None)
    objs_disc = service._build_managed_objects_dict()
    self.assertIn(CENTRAL_DEV, objs_disc)
    self.assertFalse(
        objs_disc[CENTRAL_DEV]['org.bluez.Device1']['Connected'].unpack()
    )
    self.assertEqual(self._interfaces_removed_paths(), [])

    # Subsequent RemoveDevice while disconnected emits InterfacesRemoved
    # before replying and allows rediscovery to announce Device1 again.
    events = []
    orig_emit = service._emit_all

    def tracked_emit(path, iface, sig, params):
      if sig == 'InterfacesRemoved':
        events.append(('removed', params.unpack()[0]))
      orig_emit(path, iface, sig, params)

    service._emit_all = tracked_emit
    self._remove_device(service, events=events)
    expected_removed = list(reversed(GATT_CHILDREN)) + [CENTRAL_DEV]
    self.assertNotIn(CENTRAL_DEV, service._build_managed_objects_dict())
    self.assertEqual(
        events,
        [('removed', p) for p in expected_removed] + [('reply', None)],
    )
    self._service_discover(service)
    self.assertEqual(self.host.interfaces_added_paths().count(CENTRAL_DEV), 2)


if __name__ == '__main__':
  unittest.main()
