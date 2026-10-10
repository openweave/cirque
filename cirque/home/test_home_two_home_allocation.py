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
"""Unit tests verifying defect 5: two-home allocation and active server guards."""

import unittest
from unittest.mock import MagicMock, patch

from cirque.capabilities.bluetoothcapability import BlueToothCapability
from cirque.capabilities.wificapability import WiFiCapability
from cirque.home.home import CirqueHome


class TestTwoHomeAllocation(unittest.TestCase):
  """Tests for defect 5: preserve BLE_ADAPTS_LIST and WIFI_STATIONS_LIST across active homes."""

  def setUp(self):
    super().setUp()
    getattr(CirqueHome, '_ACTIVE_HOMES', set()).clear()
    BlueToothCapability.BLE_ADAPTS_LIST.clear()
    WiFiCapability.WIFI_STATIONS_LIST.clear()
    BlueToothCapability._SHARED_VIRTUAL_SERVER = None
    WiFiCapability._SHARED_VIRTUAL_SERVER = None

  def tearDown(self):
    getattr(CirqueHome, '_ACTIVE_HOMES', set()).clear()
    BlueToothCapability.BLE_ADAPTS_LIST.clear()
    WiFiCapability.WIFI_STATIONS_LIST.clear()
    BlueToothCapability._SHARED_VIRTUAL_SERVER = None
    WiFiCapability._SHARED_VIRTUAL_SERVER = None
    super().tearDown()

  @patch('docker.from_env')
  def test_two_home_allocation_preserves_lists(self, mock_docker):
    """Verifies creating home2 while home1 is active does not clear capability lists."""
    home1 = CirqueHome(home_id='home1')
    home1.create_home([])

    # Simulate home1 allocating an adapter and station
    BlueToothCapability.BLE_ADAPTS_LIST.append('hci0')
    WiFiCapability.WIFI_STATIONS_LIST.append('wifi0')

    # Now create home2 while home1 is still active
    home2 = CirqueHome(home_id='home2')
    home2.create_home([])

    # Verify home1's allocations were NOT wiped out
    self.assertIn('hci0', BlueToothCapability.BLE_ADAPTS_LIST)
    self.assertIn('wifi0', WiFiCapability.WIFI_STATIONS_LIST)

    # Simulate home2 allocating its adapter/station
    idx_bt = 0
    while f'hci{idx_bt}' in BlueToothCapability.BLE_ADAPTS_LIST:
      idx_bt += 1
    BlueToothCapability.BLE_ADAPTS_LIST.append(f'hci{idx_bt}')

    idx_wifi = 0
    while f'wifi{idx_wifi}' in WiFiCapability.WIFI_STATIONS_LIST:
      idx_wifi += 1
    WiFiCapability.WIFI_STATIONS_LIST.append(f'wifi{idx_wifi}')

    self.assertEqual(BlueToothCapability.BLE_ADAPTS_LIST, ['hci0', 'hci1'])
    self.assertEqual(WiFiCapability.WIFI_STATIONS_LIST, ['wifi0', 'wifi1'])

    # Destroy both homes
    home1.destroy_home()
    home2.destroy_home()

    # Creating home3 after all active homes destroyed should safely clear lists
    home3 = CirqueHome(home_id='home3')
    home3.create_home([])
    self.assertEqual(len(BlueToothCapability.BLE_ADAPTS_LIST), 0)
    self.assertEqual(len(WiFiCapability.WIFI_STATIONS_LIST), 0)
    home3.destroy_home()

  @patch('docker.from_env')
  def test_active_virtual_server_prevents_clearing(self, mock_docker):
    """Verifies active virtual server prevents create_home from clearing lists."""
    BlueToothCapability.BLE_ADAPTS_LIST.append('hci0')
    WiFiCapability.WIFI_STATIONS_LIST.append('wifi0')
    BlueToothCapability._SHARED_VIRTUAL_SERVER = MagicMock()

    home = CirqueHome(home_id='home_with_server')
    home.create_home([])

    self.assertIn('hci0', BlueToothCapability.BLE_ADAPTS_LIST)
    self.assertIn('wifi0', WiFiCapability.WIFI_STATIONS_LIST)
    home.destroy_home()


if __name__ == '__main__':
  unittest.main()
