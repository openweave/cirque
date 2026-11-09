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

"""Hermetic unit tests for HomeLan docker network gateway handling."""

import ipaddress
import json
import unittest
from unittest import mock

from cirque.common.utils import Return
from cirque.connectivity import homelan


def _inspect_payload(ipam_configs):
  return json.dumps([{'IPAM': {'Config': ipam_configs}}]).encode()


class HomeLanGatewayTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.commands = []
    self.inspect_configs = []
    host_run_patcher = mock.patch.object(
        homelan, 'host_run', side_effect=self._fake_host_run)
    self.mock_host_run = host_run_patcher.start()
    self.addCleanup(host_run_patcher.stop)
    iptable_patcher = mock.patch.object(homelan,
                                        'manipulate_iptable_src_dst_rule')
    self.mock_iptable = iptable_patcher.start()
    self.addCleanup(iptable_patcher.stop)

  def _fake_host_run(self, logger, cmd, *args, **kwargs):
    del logger, args, kwargs  # Unused.
    self.commands.append(cmd)
    if isinstance(cmd, list) and cmd[:3] == ['docker', 'network', 'inspect']:
      return Return(0, _inspect_payload(self.inspect_configs), b'')
    return Return(0, b'', b'')

  def _make_lan(self, *args, **kwargs):
    lan = homelan.HomeLan(*args, **kwargs)
    # Close while host_run is still patched so __del__ never touches the host.
    self.addCleanup(lan.close)
    return lan

  def _create_cmd(self):
    return next(c for c in self.commands
                if isinstance(c, list) and c[:3] == ['docker', 'network',
                                                     'create'])

  def test_external_lan_without_inspect_gateway_derives_gateway(self):
    # Some Docker engines (e.g. GitHub Actions runners) omit `Gateway` from
    # `docker network inspect` IPAM config when `--subnet` is passed alone.
    self.inspect_configs = [{'Subnet': '10.148.53.0/24'}]

    lan = self._make_lan('home_test_external')

    self.assertEqual(lan.subnet, '10.148.53.0/24')
    self.assertEqual(lan.gateway, '10.148.53.1')
    self.assertEqual(self.mock_iptable.call_count, 3)
    for call in self.mock_iptable.call_args_list:
      _, src, dst, _ = call.args
      self.assertIsNotNone(src)
      self.assertIsNotNone(dst)
    self.mock_iptable.assert_any_call(lan.logger, '10.148.53.1',
                                      '10.148.53.0/24', 'ACCEPT')
    self.mock_iptable.assert_any_call(lan.logger, '10.148.53.0/24',
                                      '10.148.53.1', 'ACCEPT')

  def test_create_cmd_passes_gateway_matching_subnet(self):
    self.inspect_configs = [{'Subnet': '10.148.53.0/24'}]

    self._make_lan('home_test_cmd')

    cmd = self._create_cmd()
    subnets = [a.split('=', 1)[1] for a in cmd if a.startswith('--subnet=')]
    gateways = [a.split('=', 1)[1] for a in cmd if a.startswith('--gateway=')]
    self.assertEqual(len(subnets), 1)
    self.assertEqual(len(gateways), 1)
    network = ipaddress.ip_network(subnets[0])
    self.assertEqual(ipaddress.ip_address(gateways[0]),
                     network.network_address + 1)

  def test_ipv6_create_cmd_passes_gateway_for_each_subnet(self):
    self.inspect_configs = [{'Subnet': '10.148.53.0/24'},
                            {'Subnet': homelan.IPV6_SUBNET}]

    lan = self._make_lan('home_test_ipv6', ipv6=True)

    cmd = self._create_cmd()
    subnets = [a.split('=', 1)[1] for a in cmd if a.startswith('--subnet=')]
    gateways = [a.split('=', 1)[1] for a in cmd if a.startswith('--gateway=')]
    self.assertEqual(len(subnets), 2)
    self.assertEqual(len(gateways), 2)
    for subnet in subnets:
      network = ipaddress.ip_network(subnet)
      self.assertTrue(
          any(ipaddress.ip_address(gw) in network for gw in gateways))
    self.assertEqual(lan.subnet, homelan.IPV6_SUBNET)
    self.assertEqual(lan.gateway, '2001:470:9a1a::1')

  def test_inspect_gateway_is_preserved_when_present(self):
    self.inspect_configs = [{'Subnet': '10.148.53.0/24',
                             'Gateway': '10.148.53.254'}]

    lan = self._make_lan('home_test_preserve')

    self.assertEqual(lan.gateway, '10.148.53.254')

  def test_internal_lan_without_inspect_gateway_derives_gateway(self):
    self.inspect_configs = [{'Subnet': '172.30.0.0/16'}]

    lan = self._make_lan('home_test_internal', internal=True)

    self.assertNotIn('--gateway', ' '.join(self._create_cmd()))
    self.assertEqual(lan.gateway, '172.30.0.1')
    for call in self.mock_iptable.call_args_list:
      self.assertNotIn(None, call.args)


if __name__ == '__main__':
  unittest.main()
