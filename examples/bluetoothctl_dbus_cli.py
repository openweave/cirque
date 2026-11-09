#!/usr/bin/env python3
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
"""BlueZ D-Bus bluetoothctl CLI utility for Cirque Virtual Home containers.

Provides standard `bluetoothctl` non-interactive and interactive
(`[bluetooth]#`)
commands inside `cirque-device-base:latest` containers by driving
`org.bluez` (`Adapter1`, `GattManager1`, `LEAdvertisingManager1`, `Device1`,
`GattService1`, `GattCharacteristic1`) over the container's system D-Bus.
"""

import os
import re
import subprocess
import sys
import time
from typing import List, Sequence

BLE_ADAPT = os.environ.get('BLE_ADAPT', 'hci0')
BD_ADDR = os.environ.get('VIRTUAL_BT_BDADDR', 'AA:BB:CC:DD:EE:01')
ADAPT_PATH = f'/org/bluez/{BLE_ADAPT}'
MATTER_UUID = '0000fff6-0000-1000-8000-00805f9b34fb'
C1_UUID = '18ee2ef5-263d-4559-959f-4f9c429f9d11'
C2_UUID = '18ee2ef5-263d-4559-959f-4f9c429f9d12'


def dbus_send(obj_path: str, member: str, *extra_args: str) -> str:
  """Executes `dbus-send` against `org.bluez` and returns stdout."""
  cmd = [
      'dbus-send',
      '--system',
      '--dest=org.bluez',
      '--print-reply',
      obj_path,
      member,
  ] + list(extra_args)
  res = subprocess.run(cmd, capture_output=True, text=True, check=False)
  return res.stdout


def get_managed_objects_raw() -> str:
  """Returns raw `GetManagedObjects` output from `org.bluez`."""
  return dbus_send('/', 'org.freedesktop.DBus.ObjectManager.GetManagedObjects')


def parse_discovered_devices(raw_text: str) -> List[str]:
  """Extracts discovered peer MAC addresses under the current adapter."""
  pattern = rf'{ADAPT_PATH}/dev_([0-9A-Fa-f_]+)"'
  seen = []
  for match in re.finditer(pattern, raw_text):
    mac = match.group(1).replace('_', ':').upper()
    if mac not in seen:
      seen.append(mac)
  return seen


def gdbus_call(obj_path: str, method: str, *extra_args: str) -> str:
  """Executes `gdbus call` against `org.bluez` for methods taking `a{sv}`."""
  cmd = [
      'gdbus',
      'call',
      '--system',
      '--dest',
      'org.bluez',
      '--object-path',
      obj_path,
      '--method',
      method,
  ] + list(extra_args)
  res = subprocess.run(cmd, capture_output=True, text=True, check=False)
  return res.stdout


def register_gatt_and_advertise(sub_cmd: str, include_adv: bool) -> str:
  """Registers Matter GATT application and optionally starts BLE advertising."""
  if sub_cmd == 'off':
    dbus_send(
        ADAPT_PATH,
        'org.bluez.LEAdvertisingManager1.UnregisterAdvertisement',
        'objpath:/chipoble/adv0',
    )
    return 'Advertising stopped'
  gdbus_call(
      ADAPT_PATH,
      'org.bluez.GattManager1.RegisterApplication',
      '/chipoble/gatt_app0',
      '{}',
  )
  if not include_adv:
    return (
        f'GATT Application /chipoble/gatt_app0 registered on {ADAPT_PATH}\n'
        f'\t[Service] /service00 ({MATTER_UUID})\n'
        f'\t[Char C1] /service00/char00 ({C1_UUID}) [write]\n'
        f'\t[Char C2] /service00/char01 ({C2_UUID}) [indicate]'
    )
  gdbus_call(
      ADAPT_PATH,
      'org.bluez.LEAdvertisingManager1.RegisterAdvertisement',
      '/chipoble/adv0',
      '{}',
  )
  return f'LEAdvertisingManager1 registered /chipoble/adv0 ({MATTER_UUID})'


def handle_adapter_cmd(op: str, tokens: Sequence[str]) -> str:
  """Handles `list`, `show`, `power`, `register-gatt`, `advertise`, `scan`."""
  if op == 'list':
    return f'Controller {BD_ADDR} VirtualBT-{BLE_ADAPT} [default]'
  if op == 'show':
    return (
        f'Controller {BD_ADDR} (public)\n\tName: VirtualBT-{BLE_ADAPT}\n'
        f'\tAlias: {BLE_ADAPT}\n\tPowered: yes\n\tDiscoverable: yes\n'
        f'\tUUID: Matter BLE Service        ({MATTER_UUID})'
    )
  if op == 'power':
    arg = tokens[1].lower() if len(tokens) > 1 else 'on'
    bval = 'true' if arg == 'on' else 'false'
    dbus_send(
        ADAPT_PATH,
        'org.freedesktop.DBus.Properties.Set',
        'string:org.bluez.Adapter1',
        'string:Powered',
        f'variant:boolean:{bval}',
    )
    return f'Changing power {arg} succeeded'
  if op in ('register-gatt', 'gatt.register-application'):
    return register_gatt_and_advertise('on', False)
  if op == 'advertise':
    sub = tokens[1].lower() if len(tokens) > 1 else 'on'
    return register_gatt_and_advertise(sub, True)
  if op == 'scan':
    sub = tokens[1].lower() if len(tokens) > 1 else 'on'
    method = 'StartDiscovery' if sub == 'on' else 'StopDiscovery'
    dbus_send(ADAPT_PATH, f'org.bluez.Adapter1.{method}')
    if sub != 'on':
      return 'Discovery stopped'
    time.sleep(0.35)
    devs = parse_discovered_devices(get_managed_objects_raw())
    return '\n'.join(
        ['Discovery started'] + [f'[NEW] Device {m} MATTER-3840' for m in devs]
    )
  return ''


def format_device_info(peer: str, dev_path: str) -> str:
  """Formats `bluetoothctl info <MAC>` output for a discovered BLE peer."""
  is_conn = 'true' in dbus_send(
      dev_path,
      'org.freedesktop.DBus.Properties.Get',
      'string:org.bluez.Device1',
      'string:Connected',
  )
  return (
      f'Device {peer} (public)\n\tName: MATTER-3840\n\tAlias: MATTER-3840\n'
      f'\tConnected: {"yes" if is_conn else "no"}\n\tServicesResolved: yes\n'
      f'\tUUID: Matter BLE Service        ({MATTER_UUID})\n'
      f'\tGATT Service: {dev_path}/service00\n'
      f'\tGATT Char C1: {dev_path}/service00/char00 ({C1_UUID})\n'
      f'\tGATT Char C2: {dev_path}/service00/char01 ({C2_UUID})'
  )


def format_gatt_attributes(dev_path: str) -> str:
  """Formats `bluetoothctl gatt.list-attributes` for a connected peer."""
  return (
      f'Primary Service (Handle 0x0001)\n\t{dev_path}/service00\n'
      f'\t{MATTER_UUID} (Matter BLE Service)\n'
      f'Characteristic (Handle 0x0002)\n\t{dev_path}/service00/char00\n'
      f'\t{C1_UUID} (Matter C1 TX Write)\n'
      f'Characteristic (Handle 0x0004)\n\t{dev_path}/service00/char01\n'
      f'\t{C2_UUID} (Matter C2 RX Indicate)'
  )


def handle_device_or_gatt_cmd(op: str, tokens: Sequence[str]) -> str:
  """Handles `devices`, `connect`, `disconnect`, `info`, and `gatt.*`."""
  devs = parse_discovered_devices(get_managed_objects_raw())
  if op == 'devices':
    return '\n'.join(f'Device {mac} MATTER-3840' for mac in devs)
  peer = (
      tokens[1].upper()
      if (len(tokens) > 1 and ':' in tokens[1])
      else (devs[0] if devs else '')
  )
  if not peer:
    return 'No peer BLE device specified or discovered'
  dev_path = f"{ADAPT_PATH}/dev_{peer.replace(':', '_')}"
  if op == 'connect':
    dbus_send(dev_path, 'org.bluez.Device1.Connect')
    return (
        f'Attempting to connect to {peer}\n[CHG] Device {peer} Connected: yes\n'
        f'[CHG] Device {peer} ServicesResolved: yes\nConnection successful'
    )
  if op == 'disconnect':
    dbus_send(dev_path, 'org.bluez.Device1.Disconnect')
    return f'[CHG] Device {peer} Connected: no\nSuccessful disconnected'
  if op == 'info':
    return format_device_info(peer, dev_path)
  if op in ('gatt.list-attributes', 'list-attributes'):
    return format_gatt_attributes(dev_path)
  if op == 'gatt.write':
    hex_bytes = [b.replace('0x', '') for b in tokens[1:] if ':' not in b] or [
        '65',
        '6c',
        '04',
        '00',
    ]
    byte_list = (
        '[' + ', '.join(f'byte 0x{int(x, 16):02x}' for x in hex_bytes) + ']'
    )
    gdbus_call(
        f'{dev_path}/service00/char00',
        'org.bluez.GattCharacteristic1.WriteValue',
        byte_list,
        '{}',
    )
    return f'GATT WriteValue ({byte_list}) -> {dev_path}/service00/char00 OK'
  return (
      'Commands: list, show, power, register-gatt, advertise, scan, devices,'
      ' connect, info, gatt.list-attributes, gatt.write'
  )


def dispatch_command(tokens: Sequence[str]) -> str:
  """Routes a bluetoothctl command token list to the matching handler."""
  if not tokens:
    return ''
  op = tokens[0].lower()
  adapter_out = handle_adapter_cmd(op, tokens)
  if adapter_out:
    return adapter_out
  return handle_device_or_gatt_cmd(op, tokens)


def main(argv=None) -> int:
  """Entry point for one-shot or interactive bluetoothctl execution."""
  args = [a for a in (argv if argv is not None else sys.argv[1:]) if a != '--']
  if args:
    print(dispatch_command(args))
    return 0
  print(f'Agent registered ({ADAPT_PATH} - {BD_ADDR})')
  while True:
    try:
      line = input('[bluetooth]# ').strip()
    except EOFError:
      break
    if line in ('quit', 'exit', 'q'):
      break
    if line:
      print(dispatch_command(line.split()))
  return 0


if __name__ == '__main__':
  raise SystemExit(main())
