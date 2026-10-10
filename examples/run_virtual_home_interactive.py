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
"""Interactive Virtual Home Launcher with Virtual Bluetooth & Virtual Wi-Fi.

Spawns a 2-Docker-node + AP Cirque Virtual Home (`MobileController`,
`IoTEndDevice`, and `wifi_ap`) backed by kernel-module-free Virtual Bluetooth
(`cirque.virtual_bt`) and Virtual Wi-Fi (`cirque.virtual_wifi`), provisions
`bluetoothctl` and the `IoTEndDevice` GATT service + BLE advertisement, and
keeps the topology alive until the user presses Enter or Ctrl+C.

Usage:
  PYTHONPATH=. python3 examples/run_virtual_home_interactive.py
  ./examples/validate_virtual_home.sh
"""

import argparse
import os
import subprocess
from typing import Tuple

from cirque.home.home import CirqueHome
from cirque.home.virtual_home_topology import VirtualHomeTopology

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BLUETOOTHCTL_CLI_PATH = os.path.join(SCRIPT_DIR, 'bluetoothctl_dbus_cli.py')


def parse_args(argv=None) -> argparse.Namespace:
  """Parses command-line flags for the interactive Virtual Home launcher."""
  parser = argparse.ArgumentParser(
      description=(
          'Launch an interactive Cirque Virtual Home with Virtual BT and Wi-Fi.'
      )
  )
  parser.add_argument(
      '--base-image',
      default='cirque-device-base:latest',
      help='Docker image for Virtual Home containers.',
  )
  parser.add_argument(
      '--ssid',
      default='CIRQUE_HOME_AP',
      help='SSID for the Virtual Wi-Fi Access Point.',
  )
  parser.add_argument(
      '--psk',
      default='cirque_home_psk',
      help='WPA2-PSK passphrase for the Virtual Wi-Fi Access Point.',
  )
  parser.add_argument(
      '--verify-first',
      action='store_true',
      help='Run automated BT discovery and Wi-Fi WPA2/ping verification first.',
  )
  parser.add_argument(
      '--non-interactive',
      action='store_true',
      help='Exit immediately after startup (and optional verification).',
  )
  return parser.parse_args(argv)


def resolve_node_ids(home: CirqueHome) -> Tuple[str, str]:
  """Returns `(controller_id, device_id)` from an active `CirqueHome`."""
  controller_id = ''
  device_id = ''
  for dev_id, node in home.home.get('devices', {}).items():
    if node.type == 'MobileController':
      controller_id = dev_id
    elif node.type == 'IoTEndDevice':
      device_id = dev_id
  return controller_id, device_id


def provision_container_bt_tools(home: CirqueHome) -> Tuple[str, str]:
  """Installs `bluetoothctl` in nodes and registers IoTEndDevice GATT + adv."""
  ctrl_cname = 'MobileController0'
  dev_cname = 'IoTEndDevice0'
  with open(BLUETOOTHCTL_CLI_PATH, 'rb') as bt_script_file:
    bt_script_bytes = bt_script_file.read()
  for node in home.home.get('devices', {}).values():
    cname = getattr(node.container, 'name', node.name)
    if node.type not in ('MobileController', 'IoTEndDevice'):
      continue
    if node.type == 'MobileController':
      ctrl_cname = cname
    else:
      dev_cname = cname
    subprocess.run(
        [
            'docker',
            'exec',
            '-i',
            cname,
            'sh',
            '-c',
            (
                'cat > /usr/local/bin/bluetoothctl && '
                'chmod 0755 /usr/local/bin/bluetoothctl && '
                'ln -sf /usr/local/bin/bluetoothctl /usr/bin/bluetoothctl'
            ),
        ],
        input=bt_script_bytes,
        check=False,
    )
    if node.type == 'IoTEndDevice':
      node.container.exec_run('bluetoothctl register-gatt')
      node.container.exec_run('bluetoothctl advertise on')
  return ctrl_cname, dev_cname


def print_bt_wifi_commands(ssid: str, psk: str) -> None:
  """Prints the manual Bluetooth and Wi-Fi CLI commands for container shells."""
  print('2. Inside IoTEndDevice (GATT Service + BLE Advertising):')
  print('   hciconfig -a && bluetoothctl show')
  print('   bluetoothctl register-gatt && bluetoothctl advertise on\n')
  print('3. Inside MobileController (BLE Scan, Connect & GATT Write):')
  print('   hciconfig -a && bluetoothctl scan on && bluetoothctl devices')
  print('   bluetoothctl connect AA:BB:CC:DD:EE:02')
  print('   bluetoothctl info AA:BB:CC:DD:EE:02')
  print('   bluetoothctl gatt.list-attributes AA:BB:CC:DD:EE:02')
  print('   bluetoothctl gatt.write 0x65 0x6c 0x04 0x00')
  print(
      '   dbus-send --system --dest=org.bluez --print-reply / \\\n'
      '     org.freedesktop.DBus.ObjectManager.GetManagedObjects\n'
  )
  print('4. Inside both containers (Virtual Wi-Fi Scan, WPA2 & Ping):')
  print('   iwlist wlan0 scan')
  print(
      '   gdbus call --system --dest fi.w1.wpa_supplicant1 \\\n'
      '     --object-path /fi/w1/wpa_supplicant1/Interfaces/0 \\\n'
      '     --method fi.w1.wpa_supplicant1.Interface.AddNetwork \\\n'
      f"     \"{{'ssid': <'{ssid}'>, 'psk': <'{psk}'>}}\""
  )
  print(
      '   gdbus call --system --dest fi.w1.wpa_supplicant1 \\\n'
      '     --object-path /fi/w1/wpa_supplicant1/Interfaces/0 \\\n'
      '     --method fi.w1.wpa_supplicant1.Interface.SelectNetwork \\\n'
      '     /fi/w1/wpa_supplicant1/Interfaces/0/Networks/0'
  )
  print('   dhcpcd wlan0 && ip addr show dev wlan0')
  print('   ping -I wlan0 -c 4 10.0.1.12')
  print('=' * 76)


def print_home_guide(
    home: CirqueHome,
    ctrl_cname: str,
    dev_cname: str,
    ssid: str = 'CIRQUE_HOME_AP',
    psk: str = 'cirque_home_psk',
) -> None:
  """Prints container names, one-shot validation script, and CLI commands."""
  print('\n' + '=' * 76)
  print('  CIRQUE VIRTUAL HOME RUNNING (Virtual Bluetooth + Virtual Wi-Fi)')
  print('=' * 76)
  for dev_id, node in home.home.get('devices', {}).items():
    cname = getattr(node.container, 'name', node.name)
    print(
        f'  * Role: {node.type:18s} | Container: {cname:20s} |'
        f' ID: {dev_id[:12]}'
    )
  print('-' * 76)
  print('Quick One-Shot Validation (run in another terminal):')
  print(f'   ./examples/validate_virtual_home.sh {ctrl_cname} {dev_cname}\n')
  print('1. Or step into the Docker containers manually:')
  print(f'   docker exec -it {ctrl_cname} bash   # MobileController (hci0)')
  print(f'   docker exec -it {dev_cname} bash   # IoTEndDevice (hci1)\n')
  print_bt_wifi_commands(ssid, psk)


def run_initial_verification(
    home: CirqueHome, ssid: str, psk: str
) -> Tuple[dict, dict]:
  """Executes E2E Virtual BT and Virtual Wi-Fi verification across nodes."""
  ctrl_id, dev_id = resolve_node_ids(home)
  bt_res = VirtualHomeTopology.verify_virtual_bt_between_nodes(
      home, ctrl_id, dev_id
  )
  wifi_res = (
      VirtualHomeTopology.verify_virtual_wifi_commissioning_and_data_plane(
          home, ctrl_id, dev_id, ssid, psk
      )
  )
  print(
      f'[Verify] Virtual Wi-Fi IPs: controller={wifi_res["controller_ip"]}, '
      f'device={wifi_res["device_ip"]}, '
      f'0% loss={wifi_res["packet_loss_zero"]}'
  )
  return bt_res, wifi_res


def main(argv=None) -> int:
  """Brings up the Virtual Home and waits for user exit before cleanup."""
  args = parse_args(argv)
  pid = os.getpid()
  bt_rt = os.environ.setdefault(
      'CIRQUE_VIRTUAL_BT_RUNTIME_DIR', f'/tmp/cirque_virtual_bt_{pid}'
  )
  wifi_rt = os.environ.setdefault(
      'CIRQUE_VIRTUAL_WIFI_RUNTIME_DIR', f'/tmp/cirque_virtual_wifi_{pid}'
  )
  print(
      '[1/3] Starting Cirque Virtual Home (wifi_ap, MobileController,'
      ' IoTEndDevice)...',
      flush=True,
  )
  home = CirqueHome()
  config = VirtualHomeTopology.default_two_node_ble_wifi_config(
      base_image=args.base_image,
      ssid=args.ssid,
      wifi_psk=args.psk,
  )
  try:
    home.create_home(config)
    print(
        '[2/3] Provisioning bluetoothctl, IoTEndDevice GATT service & BLE'
        ' advertisement...',
        flush=True,
    )
    ctrl_cname, dev_cname = provision_container_bt_tools(home)
    if args.verify_first:
      run_initial_verification(home, args.ssid, args.psk)
    print('[3/3] Virtual Home ready!', flush=True)
    print_home_guide(home, ctrl_cname, dev_cname, args.ssid, args.psk)
    if not args.non_interactive:
      input('\nPress Enter (or Ctrl+C) to stop and destroy Virtual Home...\n')
  except KeyboardInterrupt:
    print('\nStopping Virtual Home...')
  finally:
    home.destroy_home()
    for rt_dir in (bt_rt, wifi_rt):
      if rt_dir.startswith('/tmp/cirque_virtual_'):
        subprocess.run(['rm', '-rf', rt_dir], check=False)
    print('Virtual Home destroyed cleanly.')
  return 0


if __name__ == '__main__':
  raise SystemExit(main())
