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
"""Userspace BlueZ-compatible D-Bus service helper (not bluetoothd).

Provides D-Bus introspection XML, ObjectManager dictionary builder, and GATT
helpers for userspace BlueZ emulation.
"""

import logging
import os
import time
from typing import Dict, Optional

from cirque.virtual_bt.adapter_bridge import VirtualBluezAdapterBridge
from cirque.virtual_bt.gatt_profile import BleGattProfile, get_default_profile

logger = logging.getLogger('VirtualBtBluezGattHelpers')

BLUEZ_INTROSPECT_XML = """
<node>
  <interface name="org.freedesktop.DBus.ObjectManager">
    <method name="GetManagedObjects">
      <arg name="objects" type="a{oa{sa{sv}}}" direction="out"/>
    </method>
    <signal name="InterfacesAdded">
      <arg name="object" type="o"/>
      <arg name="interfaces" type="a{sa{sv}}"/>
    </signal>
    <signal name="InterfacesRemoved">
      <arg name="object" type="o"/>
      <arg name="interfaces" type="as"/>
    </signal>
  </interface>
  <interface name="org.bluez.Adapter1">
    <method name="StartDiscovery"/>
    <method name="StopDiscovery"/>
    <method name="SetDiscoveryFilter">
      <arg name="properties" type="a{sv}" direction="in"/>
    </method>
    <method name="RemoveDevice">
      <arg name="device" type="o" direction="in"/>
    </method>
    <property name="Address" type="s" access="read"/>
    <property name="AddressType" type="s" access="read"/>
    <property name="Name" type="s" access="read"/>
    <property name="Alias" type="s" access="readwrite"/>
    <property name="Class" type="u" access="read"/>
    <property name="Powered" type="b" access="readwrite"/>
    <property name="Discoverable" type="b" access="readwrite"/>
    <property name="Discovering" type="b" access="read"/>
    <property name="UUIDs" type="as" access="read"/>
  </interface>
  <interface name="org.bluez.GattManager1">
    <method name="RegisterApplication">
      <arg name="application" type="o" direction="in"/>
      <arg name="options" type="a{sv}" direction="in"/>
    </method>
    <method name="UnregisterApplication">
      <arg name="application" type="o" direction="in"/>
    </method>
  </interface>
  <interface name="org.bluez.LEAdvertisingManager1">
    <method name="RegisterAdvertisement">
      <arg name="advertisement" type="o" direction="in"/>
      <arg name="options" type="a{sv}" direction="in"/>
    </method>
    <method name="UnregisterAdvertisement">
      <arg name="advertisement" type="o" direction="in"/>
    </method>
    <property name="ActiveInstances" type="y" access="read"/>
    <property name="SupportedInstances" type="y" access="read"/>
    <property name="SupportedIncludes" type="as" access="read"/>
  </interface>
  <interface name="org.bluez.Device1">
    <method name="Connect"/>
    <method name="Disconnect"/>
    <property name="Address" type="s" access="read"/>
    <property name="AddressType" type="s" access="read"/>
    <property name="Name" type="s" access="read"/>
    <property name="Alias" type="s" access="read"/>
    <property name="Paired" type="b" access="read"/>
    <property name="Trusted" type="b" access="readwrite"/>
    <property name="Blocked" type="b" access="readwrite"/>
    <property name="LegacyPairing" type="b" access="read"/>
    <property name="RSSI" type="n" access="read"/>
    <property name="Connected" type="b" access="read"/>
    <property name="UUIDs" type="as" access="read"/>
    <property name="Adapter" type="o" access="read"/>
    <property name="ServiceData" type="a{sv}" access="read"/>
    <property name="ServicesResolved" type="b" access="read"/>
  </interface>
  <interface name="org.bluez.GattService1">
    <property name="UUID" type="s" access="read"/>
    <property name="Device" type="o" access="read"/>
    <property name="Primary" type="b" access="read"/>
  </interface>
  <interface name="org.bluez.GattCharacteristic1">
    <method name="ReadValue">
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="value" type="ay" direction="out"/>
    </method>
    <method name="WriteValue">
      <arg name="value" type="ay" direction="in"/>
      <arg name="options" type="a{sv}" direction="in"/>
    </method>
    <method name="AcquireWrite">
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="fd" type="h" direction="out"/>
      <arg name="mtu" type="q" direction="out"/>
    </method>
    <method name="AcquireNotify">
      <arg name="options" type="a{sv}" direction="in"/>
      <arg name="fd" type="h" direction="out"/>
      <arg name="mtu" type="q" direction="out"/>
    </method>
    <method name="StartNotify"/>
    <method name="StopNotify"/>
    <method name="Confirm"/>
    <property name="UUID" type="s" access="read"/>
    <property name="Service" type="o" access="read"/>
    <property name="Value" type="ay" access="read"/>
    <property name="Notifying" type="b" access="read"/>
    <property name="Flags" type="as" access="read"/>
    <property name="WriteAcquired" type="b" access="read"/>
    <property name="NotifyAcquired" type="b" access="read"/>
  </interface>
</node>
"""


def build_dbus_bus_conf_xml(socket_path: str) -> str:
  """Returns the permissive D-Bus daemon configuration XML for socket_path."""
  doctype = (
      '<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus '
      'Configuration 1.0//EN"\n '
      '"http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">'
  )
  return f"""{doctype}
<busconfig>
  <type>system</type>
  <listen>unix:path={socket_path}</listen>
  <auth>EXTERNAL</auth>
  <auth>ANONYMOUS</auth>
  <allow_anonymous/>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_type="method_call"/>
    <allow send_type="signal"/>
    <allow send_type="method_return"/>
    <allow send_type="error"/>
    <allow receive_type="method_call"/>
    <allow receive_type="signal"/>
    <allow receive_type="method_return"/>
    <allow receive_type="error"/>
  </policy>
</busconfig>
"""


def _build_char_entry(
    uuid_str: str, svc_path: str, notifying: bool, flag: str
) -> dict:
  """Builds a single org.bluez.GattCharacteristic1 dictionary."""
  from gi.repository import GLib  # pylint: disable=g-import-not-at-top

  return {
      'org.bluez.GattCharacteristic1': {
          'UUID': GLib.Variant('s', uuid_str),
          'Service': GLib.Variant('o', svc_path),
          'Value': GLib.Variant('ay', []),
          'Notifying': GLib.Variant('b', notifying),
          'Flags': GLib.Variant('as', [flag]),
      }
  }


def _build_peripheral_gatt_entries(
    adapter_path: str,
    addr: str,
    pinfo: Dict[str, object],
    is_conn: bool,
    profile: Optional[BleGattProfile] = None,
) -> dict:
  """Builds Device1, GattService1, and write/indicate entries for a peripheral."""
  from gi.repository import GLib  # pylint: disable=g-import-not-at-top

  profile = profile or get_default_profile()
  dev_path = f'{adapter_path}/dev_{addr.replace(":", "_")}'
  svc_data = pinfo.get('service_data') or profile.default_service_data
  disc_val = pinfo.get('discriminator', profile.default_discriminator)
  if disc_val is None:
    disc_val = profile.default_discriminator
  dev_name = profile.local_name(disc_val)
  svc_path = f'{dev_path}/service00'
  return {
      dev_path: {
          'org.bluez.Device1': {
              'Address': GLib.Variant('s', addr),
              'AddressType': GLib.Variant('s', 'public'),
              'Name': GLib.Variant('s', dev_name),
              'Alias': GLib.Variant('s', dev_name),
              'Paired': GLib.Variant('b', False),
              'Trusted': GLib.Variant('b', True),
              'Blocked': GLib.Variant('b', False),
              'LegacyPairing': GLib.Variant('b', False),
              'RSSI': GLib.Variant('n', int(pinfo.get('rssi', -45))),
              'Connected': GLib.Variant('b', is_conn),
              'UUIDs': GLib.Variant('as', [profile.service_uuid]),
              'Adapter': GLib.Variant('o', adapter_path),
              'ServiceData': GLib.Variant(
                  'a{sv}',
                  {profile.service_uuid: GLib.Variant('ay', list(svc_data))},
              ),
              'ServicesResolved': GLib.Variant('b', True),
          }
      },
      svc_path: {
          'org.bluez.GattService1': {
              'UUID': GLib.Variant('s', profile.service_uuid),
              'Device': GLib.Variant('o', dev_path),
              'Primary': GLib.Variant('b', True),
          }
      },
      f'{svc_path}/char00': _build_char_entry(
          profile.write_char_uuid, svc_path, False, 'write'
      ),
      f'{svc_path}/char01': _build_char_entry(
          profile.indicate_char_uuid, svc_path, True, 'indicate'
      ),
  }


def build_managed_objects_dict(
    adapter_bridges: Dict[str, VirtualBluezAdapterBridge],
) -> dict:
  """Builds the GetManagedObjects dictionary for all virtual adapters."""
  from gi.repository import GLib  # pylint: disable=g-import-not-at-top

  objects = {}
  for cid, bridge in adapter_bridges.items():
    adapter_path = f'/org/bluez/{cid}'
    objects[adapter_path] = {
        'org.bluez.Adapter1': {
            'Address': GLib.Variant('s', bridge.bd_addr),
            'AddressType': GLib.Variant('s', 'public'),
            'Name': GLib.Variant('s', f'VirtualBT-{cid}'),
            'Alias': GLib.Variant('s', cid),
            'Class': GLib.Variant('u', 0x000104),
            'Powered': GLib.Variant('b', True),
            'Discoverable': GLib.Variant('b', False),
            'Discovering': GLib.Variant('b', False),
            'UUIDs': GLib.Variant('as', [bridge.profile.service_uuid]),
        },
        'org.bluez.GattManager1': {},
        'org.bluez.LEAdvertisingManager1': {
            'ActiveInstances': GLib.Variant('y', 1),
            'SupportedInstances': GLib.Variant('y', 5),
            'SupportedIncludes': GLib.Variant(
                'as', ['tx-power', 'appearance', 'local-name']
            ),
        },
    }
    conn_addrs = set(bridge.connected_handles.values())
    for addr, pinfo in bridge.discovered_peripherals.items():
      objects.update(
          _build_peripheral_gatt_entries(
              adapter_path, addr, pinfo, addr in conn_addrs, bridge.profile
          )
      )
    for addr in conn_addrs:
      if addr not in bridge.discovered_peripherals:
        objects.update(
            _build_peripheral_gatt_entries(
                adapter_path, addr, {}, True, bridge.profile
            )
        )
  return objects


def acquire_gatt_characteristic_fd(
    app_conn,
    sender: str,
    char_path: str,
    method_name: str,
    periph_dev_path: str,
) -> Optional[int]:
  """Calls AcquireWrite or AcquireNotify on a peripheral GATT characteristic."""
  from gi.repository import GLib  # pylint: disable=g-import-not-at-top

  opts = GLib.Variant(
      '(a{sv})',
      (
          {
              'device': GLib.Variant('o', periph_dev_path),
              'mtu': GLib.Variant('q', 247),
          },
      ),
  )
  for _ in range(30):
    try:
      _, fd_list = app_conn.call_with_unix_fd_list_sync(
          sender,
          char_path,
          'org.bluez.GattCharacteristic1',
          method_name,
          opts,
          GLib.VariantType('(hq)'),
          0,
          500,
          None,
          None,
      )
      if fd_list and fd_list.get_length() > 0:
        fd = fd_list.steal_fds()[0]
        try:
          os.set_blocking(fd, True)
        except OSError as exc:
          logger.debug('set_blocking failed on fd %d: %s', fd, exc)
        return fd
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.info(
          'acquire_gatt_characteristic_fd %s on %s failed: %s',
          method_name,
          char_path,
          exc,
      )
      if 'ServiceUnknown' in str(exc) or 'NameHasNoOwner' in str(exc):
        break
      time.sleep(0.05)
  return None


def query_advertisement_discriminator(
    connection,
    sender: str,
    adv_path: str,
    profile: Optional[BleGattProfile] = None,
) -> int:
  """Queries the profile discriminator from an LEAdvertisement1 object."""
  from gi.repository import GLib  # pylint: disable=g-import-not-at-top

  profile = profile or get_default_profile()
  try:
    res = connection.call_sync(
        sender,
        adv_path,
        'org.freedesktop.DBus.Properties',
        'Get',
        GLib.Variant('(ss)', ('org.bluez.LEAdvertisement1', 'ServiceData')),
        GLib.VariantType('(v)'),
        0,
        150,
        None,
    )
    sdata = res.unpack()[0]
    raw = b''
    for key in profile.service_data_keys():
      if sdata.get(key):
        raw = bytes(sdata[key])
        break
    disc = profile.discriminator_from_service_data(raw) if raw else None
    if disc is not None:
      return disc
  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.debug('query_advertisement_discriminator notice: %s', exc)
  return profile.default_discriminator


def query_app_managed_objects(connection, sender: str, app_path: str) -> dict:
  """Queries GetManagedObjects from registered GATT application via D-Bus."""
  from gi.repository import GLib  # pylint: disable=g-import-not-at-top

  if connection is None:
    return {}
  try:
    res = connection.call_sync(
        sender,
        app_path,
        'org.freedesktop.DBus.ObjectManager',
        'GetManagedObjects',
        None,
        GLib.VariantType('(a{oa{sa{sv}}})'),
        0,
        500,
        None,
    )
    if res is not None:
      return res.unpack()[0]
  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.debug('query_app_managed_objects failed: %s', exc)
  return {}


def handle_bluez_adapter_method(
    bridge: Optional[VirtualBluezAdapterBridge],
    method_name: str,
    parameters,
    invocation,
) -> None:
  """Handles org.bluez.Adapter1 D-Bus method calls."""
  if bridge is not None and bridge.h4_client is not None:
    if method_name == 'StartDiscovery':
      with bridge._lock:  # pylint: disable=protected-access
        bridge.discovered_peripherals.clear()
      with bridge.h4_client._cv:  # pylint: disable=protected-access
        bridge.h4_client._adv_reports.clear()  # pylint: disable=protected-access
      bridge.h4_client.start_scanning(active=True)
    elif method_name == 'StopDiscovery':
      bridge.h4_client.send_command(0x200C, b'\x00\x00')
    elif method_name == 'RemoveDevice':
      dev_part = parameters.unpack()[0].split('/')[-1]
      peer_addr = dev_part.replace('dev_', '').replace('_', ':').upper()
      with bridge._lock:  # pylint: disable=protected-access
        bridge.discovered_peripherals.pop(peer_addr, None)
      with bridge.h4_client._cv:  # pylint: disable=protected-access
        bridge.h4_client._adv_reports.clear()  # pylint: disable=protected-access
  invocation.return_value(None)
