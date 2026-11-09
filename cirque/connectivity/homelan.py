# Copyright 2020 Google LLC
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

import ipaddress
import json

from cirque.common.cirquelog import CirqueLog
from cirque.common.utils import host_run, manipulate_iptable_src_dst_rule

IPV6_SUBNET = "2001:470:9a1a::/48"
IPV6_GATEWAY = "2001:470:9a1a::1"


def _first_host(subnet):
  """Returns the first host address of `subnet` (Docker's default gateway)."""
  network = ipaddress.ip_network(subnet, strict=False)
  return str(network.network_address + 1)


class HomeLan:

  def __init__(self, name, internal=False, ipv6=False):
    self.logger = CirqueLog.get_cirque_logger('lan_{}'.format(name))
    self.__name = name
    self.__internal = internal
    self.__ipv6 = ipv6
    self.subnet = None
    self.gateway = None
    if 'ipvlan' in self.__name:
      self._create_ipvlan_network()
    else:
      self._create_docker_network()
      self._inspect_network_properties()
      # bypass disable mutual access for ipv4
      # in ipv6 feature.
      if 'ipv6' not in self.__name:
        self._disable_container_mutual_access()

  def _create_docker_network(self):
    import random
    max_retries = 10
    used_subnet = IPV6_SUBNET
    for attempt in range(max_retries):
      cmd = ['docker', 'network', 'create', self.__name]

      if self.__internal:
        cmd.append('--internal')
      else:
        # Always provide a random IPv4 subnet to prevent pool exhaustion.
        v4_subnet = (
            f'10.{random.randint(100, 250)}.{random.randint(0, 250)}.0/24'
        )
        cmd.append(f'--subnet={v4_subnet}')
        # Pin the gateway too: some Docker engines omit IPAM `Gateway`
        # from `network inspect` when only `--subnet` is given.
        cmd.append(f'--gateway={_first_host(v4_subnet)}')

        if self.__ipv6:
          # Use standard IPv6 on attempt 0, random on retries
          if attempt == 0:
            used_subnet = IPV6_SUBNET
            alt_gw = IPV6_GATEWAY
          else:
            subnet_id = random.randint(1, 0xFFFF)
            used_subnet = f'fd00:c17c:{subnet_id:04x}::/64'
            alt_gw = f'fd00:c17c:{subnet_id:04x}::1'
          cmd.append(f'--subnet={used_subnet}')
          cmd.append(f'--gateway={alt_gw}')
          cmd.append('--ipv6')

      ret = host_run(self.logger, cmd)
      if ret.returncode == 0:
        break
      self.logger.warning(
          'docker network create failed on attempt %d: %s', attempt, ret.stderr
      )

    if ret.returncode != 0:
      self.logger.error(
          'Failed to create home lan %s: %s', self.__name, ret.stderr
      )

    if self.__ipv6:
      self._enable_ipv6_external_access(used_subnet)

  def _create_ipvlan_network(self):
    interface_command = "route | awk '/default / {print $8}'"
    ret = host_run(self.logger, interface_command)
    if ret.returncode != 0:
      self.logger.error(
          'Failed to get network interface for creating ipvlan %s: %s',
          self.__name, ret.stderr)
    interface = ret.stdout.rstrip().decode('utf-8')
    subnet_command = "ip addr show %s | awk '/inet / {print $2}'" % interface
    ret = host_run(self.logger, subnet_command)
    if ret.returncode != 0:
      self.logger.error(
          'Failed to get subnetwork for create ipvalen %s: %s',
          self.__name, ret.stderr)
    subnet = ret.stdout.rstrip().decode('utf-8')
    gateway_command = "ip r | awk '/default via/ {print $3}'"
    ret = host_run(self.logger, gateway_command)
    if ret.returncode != 0:
      self.logger.error(
          'Failed to retrieve gateway for create ipvalen %s: %s',
          self.__name, ret.stderr)
    gateway = ret.stdout.rstrip().decode('utf-8')
    ipvlan_command = 'docker network create -d ipvlan --subnet=%s'\
        ' --gateway=%s -o parent=%s %s' % (
            subnet, gateway, interface, self.__name)
    ret = host_run(self.logger, ipvlan_command)
    if ret.returncode != 0:
      self.logger.error(
          'Failed to create ipvlan %s: %s', self.__name, ret.stderr)
    self._inspect_network_properties()

  def _disable_container_mutual_access(self):
    if not self.subnet:
      return
    manipulate_iptable_src_dst_rule(self.logger, self.subnet, self.subnet,
                                    'DROP')
    manipulate_iptable_src_dst_rule(self.logger, self.gateway, self.subnet,
                                    'ACCEPT')
    manipulate_iptable_src_dst_rule(self.logger, self.subnet, self.gateway,
                                    'ACCEPT')

  def _disable_ipv6_external_access(self):
    flush_command = "ip6tables -t nat -F"
    ret = host_run(self.logger, flush_command)
    if ret.returncode != 0:
      self.logger.debug("Unable to flush nat rule from ipv6...")

  def _enable_ipv6_external_access(self, subnet=None):
    target_subnet = subnet or self.subnet or IPV6_SUBNET
    ip6tables_command = " ".join([
        "ip6tables -t nat -A POSTROUTING -s {}".format(target_subnet),
        "! -o docker0 -j MASQUERADE",
    ])
    ret = host_run(self.logger, ip6tables_command)
    if ret.returncode != 0:
      self.logger.debug("Fail to setup ipv6 external access in ip6tables")

  def _inspect_network_properties(self):
    ret = host_run(self.logger, ['docker', 'network', 'inspect', self.__name])
    self.logger.debug(
        'network inspect: ret=%s, out=%s, err=%s',
        ret.returncode, ret.stdout, ret.stderr,
    )
    if ret.returncode != 0:
      self.logger.error('Failed to inspect home lan %s', self.__name)
      return
    network_info = json.loads(ret.stdout.decode())
    if not network_info:
      self.logger.error('Failed to inspect home lan %s', self.__name)
      return
    network_configs = network_info[0].get('IPAM', {}).get('Config', [])
    if not network_configs:
      return
    for cfg in network_configs:
      subnet = cfg.get('Subnet', '')
      if self.__ipv6 and ':' in subnet:
        self.subnet = subnet
        self.gateway = cfg.get('Gateway')
        break
      elif not self.__ipv6 and '.' in subnet:
        self.subnet = subnet
        self.gateway = cfg.get('Gateway')
        break
    if not self.subnet:
      self.subnet = network_configs[0].get('Subnet')
      self.gateway = network_configs[0].get('Gateway')
    if self.subnet and not self.gateway:
      self.gateway = _first_host(self.subnet)

  def close(self):
    if not self.subnet:
      return
    cmd = ['docker', 'network', 'rm', self.__name]
    if host_run(self.logger, cmd).returncode != 0:
      self.logger.error('Failed to remove home lan %s', self.__name)
    if self.__ipv6:
      self._disable_ipv6_external_access()
    if all(nwk not in self.__name for nwk in ('ipv6', 'ipvlan')):
      manipulate_iptable_src_dst_rule(
          self.logger, self.subnet, self.subnet, 'DROP', add=False)
      manipulate_iptable_src_dst_rule(
          self.logger, self.gateway, self.subnet, 'ACCEPT', add=False)
      manipulate_iptable_src_dst_rule(
          self.logger, self.subnet, self.gateway, 'ACCEPT', add=False)
    self.gateway = None
    self.subnet = None

  @property
  def name(self):
    return self.__name

  @property
  def internal(self):
    return self.__internal

  def __del__(self):
    self.close()

  _HomeLan__create_docker_network = _create_docker_network
  _HomeLan__create_ipvlan_network = _create_ipvlan_network
  _HomeLan__disable_container_mutual_access = _disable_container_mutual_access
  _HomeLan__disable_ipv6_external_access = _disable_ipv6_external_access
  _HomeLan__enable_ipv6_external_access = _enable_ipv6_external_access
  _HomeLan__inspect_network_properties = _inspect_network_properties
