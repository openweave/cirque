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
"""End-to-End Virtual Home Test with 2 Docker Nodes (Virtual BT + Wi-Fi).

Spawns a Cirque Virtual Home with:
  - `mobile_controller`: Docker container with Virtual Bluetooth (`hci0` over
    TCP `VirtualBtControllerServer`) and Virtual Wi-Fi (`wlan0` over TCP
    `VirtualWiFiServer` + `fi.w1.wpa_supplicant1` D-Bus).
  - `iot_end_device`: Docker container with Virtual Bluetooth (`hci0`) and
    Virtual Wi-Fi (`wlan0`).
  - `wifi_ap`: Virtual Wi-Fi Access Point (`CIRQUE_HOME_AP`).

Verifies:
  1. Cross-container BLE discovery over BlueZ D-Bus (`org.bluez.Adapter1` &
     `org.bluez.Device1`) without `btvirt` or kernel `vhci`.
  2. Cross-container Wi-Fi scanning, WPA2-PSK 4-way handshake association
     (`State == 'completed'`), DHCP IPv4 lease assignment (`10.0.1.x/24`), and
     0% packet loss ICMP ping between `mobile_controller` and `iot_end_device`
     over `wlan0` without `mac80211_hwsim`.

Commissioning with real connectedhomeip binaries (chip-tool,
chip-all-clusters-app, Android CHIPTool) over this topology is tested in
connectedhomeip: src/test_driver/linux-cirque/
test_virtual_home_chip_ble_wifi_e2e.py.
"""

import os
import subprocess
import unittest

from cirque.common.isolated_runtime_dirs import isolate_virtual_runtime_dirs
from cirque.home.home import CirqueHome
from cirque.home.virtual_home_topology import VirtualHomeTopology

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
VALIDATE_SCRIPT_PATH = os.path.join(SCRIPT_DIR, 'validate_virtual_home.sh')


def setUpModule():
  unittest.addModuleCleanup(isolate_virtual_runtime_dirs())


class TestVirtualHomeBleWiFiE2E(unittest.TestCase):
  """E2E test for a 2-Docker-node + AP Virtual Home with Virtual BT & Wi-Fi."""

  @classmethod
  def setUpClass(cls):
    super().setUpClass()
    cls.base_image = os.environ.get(
        'CIRQUE_E2E_IMAGE', 'cirque-device-base:latest'
    )
    cls.ssid = 'CIRQUE_HOME_AP'
    cls.wifi_psk = 'cirque_home_psk'
    cls.home = CirqueHome()
    cls.home_config = VirtualHomeTopology.default_two_node_ble_wifi_config(
        base_image=cls.base_image,
        ssid=cls.ssid,
        wifi_psk=cls.wifi_psk,
    )
    try:
      cls.home.create_home(cls.home_config)
    except Exception:
      cls.home.destroy_home()
      raise
    cls.controller_id = ''
    cls.device_id = ''
    cls.controller_container = ''
    cls.device_container = ''
    for dev_id, node in cls.home.home['devices'].items():
      if node.type == 'MobileController':
        cls.controller_id = dev_id
        cls.controller_container = getattr(node.container, 'name', node.name)
      elif node.type == 'IoTEndDevice':
        cls.device_id = dev_id
        cls.device_container = getattr(node.container, 'name', node.name)

  @classmethod
  def tearDownClass(cls):
    if hasattr(cls, 'home') and cls.home is not None:
      cls.home.destroy_home()
    super().tearDownClass()

  def test_01_virtual_home_containers_created(self):
    self.assertTrue(self.controller_id, 'MobileController container missing')
    self.assertTrue(self.device_id, 'IoTEndDevice container missing')
    self.assertEqual(len(self.home.home['devices']), 3)

  def test_02_virtual_bluetooth_cross_container_discovery(self):
    bt_res = VirtualHomeTopology.verify_virtual_bt_between_nodes(
        self.home, self.controller_id, self.device_id
    )
    self.assertIn('AA:BB:CC:DD:EE:01', bt_res['controller_bt'])
    self.assertIn('AA:BB:CC:DD:EE:02', bt_res['device_bt'])
    self.assertIn(
        '/org/bluez/hci0/dev_AA_BB_CC_DD_EE_02', bt_res['controller_bt']
    )
    self.assertIn('AA:BB:CC:DD:EE:02', bt_res['controller_bt'])

  def test_03_virtual_wifi_wpa2_and_cross_container_data_plane(self):
    wifi_res = (
        VirtualHomeTopology.verify_virtual_wifi_commissioning_and_data_plane(
            self.home,
            self.controller_id,
            self.device_id,
            self.ssid,
            self.wifi_psk,
        )
    )
    self.assertIn('completed', wifi_res['controller_wpa'])
    self.assertIn('completed', wifi_res['device_wpa'])
    self.assertTrue(wifi_res['controller_ip'].startswith('10.0.1.'))
    self.assertTrue(wifi_res['device_ip'].startswith('10.0.1.'))
    self.assertNotEqual(wifi_res['controller_ip'], wifi_res['device_ip'])
    self.assertTrue(
        wifi_res['packet_loss_zero'],
        f"Cross-container wlan0 ping failed: {wifi_res['ping_output']}",
    )

  def test_04_validate_virtual_home_cli_script_gatt_ble_and_wifi(self):
    proc = subprocess.run(
        [
            VALIDATE_SCRIPT_PATH,
            self.controller_container,
            self.device_container,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    self.assertEqual(
        proc.returncode,
        0,
        f'validate_virtual_home.sh failed:\nSTDOUT:\n{proc.stdout}\n'
        f'STDERR:\n{proc.stderr}',
    )
    self.assertIn(
        'SUCCESS: Virtual Bluetooth (GATT + BLE) and Virtual Wi-Fi Validated!',
        proc.stdout,
    )
    self.assertIn('0000fff6-0000-1000-8000-00805f9b34fb', proc.stdout)
    self.assertIn('0% packet loss', proc.stdout)


if __name__ == '__main__':
  unittest.main()
