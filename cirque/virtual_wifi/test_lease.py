# Copyright (c) 2026 Project CHIP Authors
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
"""Tests.
"""

import unittest
from cirque.virtual_wifi.lease import (
    next_pool_address,
    parse_device_wlan0_ipv4,
    parse_device_wlan0_ipv6,
    wait_for_device_wlan0_ipv4,
    wait_for_device_wlan0_ipv6,
)

SAMPLE_IP_4_ADDR_OUTPUT = """
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    link/ether 02:00:00:00:02:0b brd ff:ff:ff:ff:ff:ff
    inet 10.0.1.10/24 brd 10.0.1.255 scope global dynamic noprefixroute wlan0
       valid_lft 86395sec preferred_lft 86395sec
"""

SAMPLE_IP_6_ADDR_OUTPUT = """
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP
    inet6 fd11:22::ff:fe00:20b/64 scope global dynamic mngtmpaddr noprefixroute
       valid_lft 86395sec preferred_lft 14395sec
    inet6 fe80::ff:fe00:20b/64 scope link
       valid_lft forever preferred_lft forever
"""


class TestWifiLeaseParser(unittest.TestCase):

  def test_parse_ipv4_leased_address(self):
    ip = parse_device_wlan0_ipv4(SAMPLE_IP_4_ADDR_OUTPUT)
    self.assertEqual(ip, '10.0.1.10')

  def test_parse_ipv4_empty_when_no_inet(self):
    empty_output = """
3: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN
    link/ether 02:00:00:00:02:0b brd ff:ff:ff:ff:ff:ff
"""
    self.assertIsNone(parse_device_wlan0_ipv4(empty_output))

  def test_parse_ipv6_addresses(self):
    addrs = parse_device_wlan0_ipv6(SAMPLE_IP_6_ADDR_OUTPUT)
    self.assertEqual(
        addrs, ['fd11:22::ff:fe00:20b', 'fe80::ff:fe00:20b']
    )

  def test_next_pool_address(self):
    self.assertEqual(next_pool_address('10.0.1.10'), '10.0.1.11')
    self.assertEqual(next_pool_address('10.0.1.11'), '10.0.1.12')
    self.assertEqual(next_pool_address('10.0.1.50'), '10.0.1.10')

  def test_wait_for_device_wlan0_ipv4_succeeds_on_nth_poll(self):
    logs = []

    class FakeLogger:

      def info(self, msg, *args):
        logs.append(msg % args)

    class FakeTest:

      def __init__(self):
        self.call_count = 0
        self.logger = FakeLogger()

      def get_device_pretty_id(self, dev_id):
        return f'pretty_{dev_id}'

      def execute_device_cmd(self, dev_id, cmd):
        self.call_count += 1
        if self.call_count < 4:
          return {'output': '3: wlan0: state DOWN\n'}
        return {'output': SAMPLE_IP_4_ADDR_OUTPUT}

    fake_test = FakeTest()
    ip = wait_for_device_wlan0_ipv4(
        fake_test, 'server0', timeout_s=1.0, interval_s=0.001
    )
    self.assertEqual(ip, '10.0.1.10')
    self.assertEqual(fake_test.call_count, 4)
    self.assertEqual(len(logs), 4)
    self.assertIn('attempt 1', logs[0])
    self.assertIn('attempt 4', logs[3])

  def test_wait_for_device_wlan0_ipv4_deadline_exceeded(self):
    logs = []

    class FakeLogger:

      def info(self, msg, *args):
        logs.append(msg % args)

    class FakeTest:

      def __init__(self):
        self.call_count = 0
        self.logger = FakeLogger()

      def execute_device_cmd(self, dev_id, cmd):
        self.call_count += 1
        return {'output': '3: wlan0: state DOWN\n'}

    fake_test = FakeTest()
    ip = wait_for_device_wlan0_ipv4(
        fake_test, 'server0', timeout_s=0.01, interval_s=0.002
    )
    self.assertIsNone(ip)
    self.assertGreater(fake_test.call_count, 0)
    self.assertEqual(len(logs), fake_test.call_count)

  def test_wait_for_device_wlan0_ipv4_rejects_non_pool_address(self):
    non_pool_output = """
3: wlan0: <BROADCAST,MULTICAST,UP> mtu 1500
    inet 192.168.1.100/24 brd 192.168.1.255 scope global dynamic wlan0
"""

    class FakeTest:

      def __init__(self):
        self.logger = None

      def execute_device_cmd(self, dev_id, cmd):
        return {'output': non_pool_output}

    fake_test = FakeTest()
    ip = wait_for_device_wlan0_ipv4(
        fake_test, 'server0', timeout_s=0.01, interval_s=0.002
    )
    self.assertIsNone(ip)

  def test_wait_for_device_wlan0_ipv4_timeout_alias(self):
    class FakeTest:

      def __init__(self):
        self.logger = None

      def execute_device_cmd(self, dev_id, cmd):
        return {'output': SAMPLE_IP_4_ADDR_OUTPUT}

    fake_test = FakeTest()
    ip = wait_for_device_wlan0_ipv4(
        fake_test, 'dev1', timeout=15.0, interval_s=0.001
    )
    self.assertEqual(ip, '10.0.1.10')

  def test_wait_for_device_wlan0_ipv6_timeout_alias(self):
    class FakeTest:

      def __init__(self):
        self.logger = None

      def execute_device_cmd(self, dev_id, cmd):
        return {'output': SAMPLE_IP_6_ADDR_OUTPUT}

    fake_test = FakeTest()
    addrs = wait_for_device_wlan0_ipv6(
        fake_test, 'dev1', timeout=15.0, interval_s=0.001
    )
    self.assertEqual(
        addrs, ['fd11:22::ff:fe00:20b', 'fe80::ff:fe00:20b']
    )


if __name__ == '__main__':
  unittest.main()
