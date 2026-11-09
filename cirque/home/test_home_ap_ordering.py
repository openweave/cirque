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
"""Tests device creation ordering in CirqueHome.create_home."""

import unittest
from unittest import mock

from cirque.home.home import CirqueHome


class TestHomeApOrdering(unittest.TestCase):
  """Verifies that create_home creates wifi_ap nodes before stations."""

  def test_wifi_ap_created_first_stable_order_preserved(self):
    mock_docker = mock.MagicMock()
    with mock.patch('docker.from_env', return_value=mock_docker):
      home = CirqueHome(home_id='test_home_order')

    added_devices = []

    def fake_add_device(device_config):
      # Record device type and name in creation order.
      added_devices.append(device_config.get('name', device_config.get('type')))
      return f'mock_id_{len(added_devices)}'

    home.add_device = fake_add_device

    # Configuration where station devices are specified before the wifi_ap.
    home_config = {
        'mobile_device': {
            'name': 'mobile_device',
            'type': 'MobileDevice',
            'wifi_auto_connect': True,
            'ssid': 'TestSSID',
            'psk': 'TestPSK',
        },
        'chip_end_device': {
            'name': 'chip_end_device',
            'type': 'CHIPEndDevice',
            'wifi_auto_connect': False,
        },
        'ap_device': {
            'name': 'ap_device',
            'type': 'wifi_ap',
            'ssid': 'TestSSID',
            'psk': 'TestPSK',
        },
        'extra_station': {
            'name': 'extra_station',
            'type': 'generic_node',
        },
    }

    home.create_home(home_config)

    # wifi_ap MUST be first, and relative order of non-AP nodes preserved.
    self.assertEqual(
        added_devices,
        ['ap_device', 'mobile_device', 'chip_end_device', 'extra_station'],
    )

  def test_homelan_ipv6_inspects_and_cleans_up_on_close(self):
    from types import SimpleNamespace
    from cirque.connectivity.homelan import HomeLan

    inspect_json = (
        b'[{"IPAM": {"Config": ['
        b'{"Subnet": "172.18.0.0/16", "Gateway": "172.18.0.1"}, '
        b'{"Subnet": "2001:470:9a1a::/48", "Gateway": "2001:470:9a1a::1"}'
        b']}}]'
    )
    commands = []

    def fake_host_run(logger, cmd):
      del logger
      commands.append(cmd)
      if isinstance(cmd, list) and cmd[:3] == ['docker', 'network', 'inspect']:
        return SimpleNamespace(returncode=0, stdout=inspect_json, stderr=b'')
      return SimpleNamespace(returncode=0, stdout=b'', stderr=b'')

    with mock.patch(
        'cirque.connectivity.homelan.host_run', side_effect=fake_host_run
    ):
      lan = HomeLan('TestHome_ipv6', internal=False, ipv6=True)
      self.assertEqual(lan.subnet, '2001:470:9a1a::/48')
      self.assertEqual(lan.gateway, '2001:470:9a1a::1')

      rm_cmd = ['docker', 'network', 'rm', 'TestHome_ipv6']
      lan.close()
      self.assertIsNone(lan.subnet)
      self.assertIn(rm_cmd, commands)
      self.assertIn('ip6tables -t nat -F', commands)

      # Second close() (e.g. from __del__) is a no-op.
      rm_count_before = commands.count(rm_cmd)
      lan.close()
      self.assertEqual(commands.count(rm_cmd), rm_count_before)


if __name__ == '__main__':
  unittest.main()
