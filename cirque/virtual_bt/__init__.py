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
"""Cirque TCP/IP Virtual Bluetooth Controller System."""

from cirque.virtual_bt.bluez_dbus_daemon import BluezDbusVirtualService
from cirque.virtual_bt.docker_hci_bridge import (
    DockerVirtualBtManager,
    VirtualBluezAdapterBridge,
    VirtualPtyHciBridge,
)
from cirque.virtual_bt.gatt_profile import (
    BleGattProfile,
    get_default_profile,
    set_default_profile,
)
from cirque.virtual_bt.hci_h4 import (
    H4Packet,
    H4PacketType,
    H4StreamParser,
    HciEventCode,
    HciOpcode,
    LeSubEventCode,
)
from cirque.virtual_bt.link_layer import (
    LinkLayerFrame,
    LinkLayerHub,
    LinkLayerPduType,
)
from cirque.virtual_bt.server import (
    H4TcpClient,
    VirtualBluetoothController,
    VirtualBluetoothServer,
    VirtualBtControlClient,
)

__all__ = [
    'BleGattProfile',
    'BluezDbusVirtualService',
    'DockerVirtualBtManager',
    'H4Packet',
    'H4PacketType',
    'H4StreamParser',
    'H4TcpClient',
    'HciEventCode',
    'HciOpcode',
    'LeSubEventCode',
    'LinkLayerFrame',
    'LinkLayerHub',
    'LinkLayerPduType',
    'VirtualBluetoothController',
    'VirtualBluetoothServer',
    'VirtualBluezAdapterBridge',
    'VirtualBtControlClient',
    'VirtualPtyHciBridge',
    'get_default_profile',
    'set_default_profile',
]


def __getattr__(name):
  # build_matter_ble_adv_payload / parse_matter_ble_service_data used to be
  # exported here; resolve them lazily so importing the package stays
  # independent of cirque.protocols.matter.
  if name in ('build_matter_ble_adv_payload', 'parse_matter_ble_service_data'):
    from cirque.protocols.matter import ble_bridge  # pylint: disable=g-import-not-at-top
    return getattr(ble_bridge, name)
  raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
