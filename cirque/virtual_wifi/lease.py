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
"""Virtual Wi-Fi DHCP lease helpers for cirque device nodes.

Parses `ip addr show dev wlan0` output and polls a device until its wlan0
interface has a lease from the cirque virtual Wi-Fi DHCP pool.

`test_instance` is any object with execute_device_cmd(device_id, cmd) that
returns a dict with an 'output' key (for example a test harness that talks
to the cirque REST service), and optionally a `logger`.
"""

import re
import time
from typing import Any, List, Optional

__all__ = [
    'get_device_wlan0_ipv4',
    'get_device_wlan0_ipv6',
    'next_pool_address',
    'parse_device_wlan0_ipv4',
    'parse_device_wlan0_ipv6',
    'wait_for_device_wlan0_ipv4',
    'wait_for_device_wlan0_ipv6',
]

_INET_IPV4_RE = re.compile(
    r"\binet\s+([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:/[0-9]+)?\b"
)
_INET_IPV6_RE = re.compile(r"\binet6\s+([0-9a-fA-F:]+)(?:/[0-9]+)?\b")


def parse_device_wlan0_ipv4(addr_output: str) -> Optional[str]:
  """Parses the first IPv4 address from 'ip -4 addr show dev wlan0' output."""
  match = _INET_IPV4_RE.search(addr_output)
  if match:
    return match.group(1)
  return None


def parse_device_wlan0_ipv6(addr_output: str) -> List[str]:
  """Parses all IPv6 addresses from 'ip -6 addr show dev wlan0' output."""
  return _INET_IPV6_RE.findall(addr_output)


def get_device_wlan0_ipv4(test_instance: Any, device_id: str) -> Optional[str]:
  """Queries the given device via execute_device_cmd for wlan0 IPv4."""
  res = test_instance.execute_device_cmd(
      device_id, "ip -4 addr show dev wlan0"
  )
  raw_output = res.get("output", "") if isinstance(res, dict) else str(res)
  return parse_device_wlan0_ipv4(raw_output)


def get_device_wlan0_ipv6(test_instance: Any, device_id: str) -> List[str]:
  """Queries the given device via execute_device_cmd for wlan0 IPv6."""
  res = test_instance.execute_device_cmd(
      device_id, "ip -6 addr show dev wlan0"
  )
  raw_output = res.get("output", "") if isinstance(res, dict) else str(res)
  return parse_device_wlan0_ipv6(raw_output)


def wait_for_device_wlan0_ipv4(
    test_instance: Any,
    device_id: str,
    timeout_s: float = 60.0,
    interval_s: float = 1.0,
    timeout: Optional[float] = None,
) -> Optional[str]:
  """Polls get_device_wlan0_ipv4 until a 10.0.1.x address is leased or
  timeout occurs.
  """
  if timeout is not None:
    timeout_s = timeout
  deadline = time.time() + timeout_s
  attempt = 0
  pretty_id = getattr(test_instance, "get_device_pretty_id", lambda d: d)(
      device_id
  )
  while True:
    attempt += 1
    ip = get_device_wlan0_ipv4(test_instance, device_id)
    if hasattr(test_instance, "logger") and test_instance.logger:
      test_instance.logger.info(
          "Polling wlan0 IPv4 lease on %s (attempt %d): %s",
          pretty_id,
          attempt,
          ip,
      )
    if ip and ip.startswith("10.0.1."):
      return ip
    if time.time() >= deadline:
      break
    time.sleep(interval_s)
  return None


def wait_for_device_wlan0_ipv6(
    test_instance: Any,
    device_id: str,
    timeout_s: float = 60.0,
    interval_s: float = 1.0,
    timeout: Optional[float] = None,
) -> List[str]:
  """Polls get_device_wlan0_ipv6 until at least one address is found or
  timeout occurs.
  """
  if timeout is not None:
    timeout_s = timeout
  deadline = time.time() + timeout_s
  attempt = 0
  pretty_id = getattr(test_instance, "get_device_pretty_id", lambda d: d)(
      device_id
  )
  while True:
    attempt += 1
    addrs = get_device_wlan0_ipv6(test_instance, device_id)
    if hasattr(test_instance, "logger") and test_instance.logger:
      test_instance.logger.info(
          "Polling wlan0 IPv6 addresses on %s (attempt %d): %s",
          pretty_id,
          attempt,
          addrs,
      )
    if addrs:
      return addrs
    if time.time() >= deadline:
      break
    time.sleep(interval_s)
  return []


def next_pool_address(base_ip: str) -> str:
  """Derives the next pool address from base_ip for negative pre-ping checks."""
  # VirtualDhcpServer pool starts at 10.0.1.10. If base_ip is 10.0.1.X,
  # pick X+1 (or 10.0.1.10 if wrapped) so pre-ping does not ping self
  # or gateway.
  prefix, last_str = base_ip.rsplit(".", 1)
  last = int(last_str)
  next_last = last + 1 if last < 50 else 10
  return f"{prefix}.{next_last}"

