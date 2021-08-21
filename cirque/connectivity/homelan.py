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


class HomeLan:

  def __init__(self, name, internal=False):
    self.logger = CirqueLog.get_cirque_logger('lan_{}'.format(name))
    self.__name = name
    self.__internal = internal
    self.subnet = None
    self.gateway = None
    if 'ipvlan' in self.__name:
      self.__create_ipvlan_network()
    else:
      self.__create_docker_network()
      self.__disable_container_mutual_access()

  def __create_docker_network(self):
    # The docker-py library will add a weird route which disconnects
    # the host when creating networks. The `docker network inspect`isn't
    # supported neither so we use bash commands directly.
    cmd = ['docker', 'network', 'create', self.__name]
    if self.__internal:
      cmd.append('--internal')
    ret = host_run(self.logger, cmd)
    if ret.returncode != 0:
      self.logger.error('Failed to create home lan %s', self.__name)

  def __create_ipvlan_network(self):

    interface_command = "route | awk '/default / {print $8}'"
    ret = host_run(self.logger, interface_command)
    if ret.returncode != 0:
      self.logger.error('Failed to get network interface for creating '
                        'ipvlan %s: %s' % (self.__name, ret.stderr))
    interface = ret.stdout.rstrip().decode('utf-8')
    subnet_command = "ip addr show %s | awk '/inet / {print $2}'" % interface
    ret = host_run(self.logger, subnet_command)
    if ret.returncode != 0:
      self.logger.error('Failed to get subnetwork for create '
                        'ipvalen %s: %s' % (self.__name, ret.stderr))
    subnet = ret.stdout.rstrip().decode('utf-8')
    gateway_command = "ip r | awk '/default via/ {print $3}'"
    ret = host_run(self.logger, gateway_command)
    if ret.returncode != 0:
      self.logger.error('Failed to retrieve gateway for create '
                        'ipvalen %s: %s' % (self.__name, ret.stderr))
    gateway = ret.stdout.rstrip().decode('utf-8')
    ipvlan_command = 'docker network create -d ipvlan --subnet=%s'\
        ' --gateway=%s -o parent=%s %s' % (
            subnet, gateway, interface, self.__name)
    ret = host_run(self.logger, ipvlan_command)
    if ret.returncode != 0:
      self.logger.error('Failed to create ipvlan %s: %s' %
                        (self.__name, ret.stderr))
    self.__inspect_network_properties()

  def __disable_container_mutual_access(self):
    self.__inspect_network_properties()
    manipulate_iptable_src_dst_rule(self.logger, self.subnet, self.subnet,
                                    'DROP')
    manipulate_iptable_src_dst_rule(self.logger, self.gateway, self.subnet,
                                    'ACCEPT')
    manipulate_iptable_src_dst_rule(self.logger, self.subnet, self.gateway,
                                    'ACCEPT')

  def __inspect_network_properties(self):
    ret = host_run(self.logger, ['docker', 'network', 'inspect', self.__name])
    if ret.returncode != 0:
      self.logger.error('Failed to inspect home lan %s' % self.__name)
      return
    network_info = json.loads(ret.stdout.decode())
    if not network_info:
      self.logger.error('Failed to inspect home lan %s' % self.__name)
      return
    network_configs = network_info[0]['IPAM']['Config']
    if len(network_configs) != 1:
      self.logger.error('Unexpected network behavior on home lan %s' %
                        self.__name)
    self.subnet = network_configs[0]['Subnet']
    if 'ipvlan' not in self.__name:
      self.gateway = network_configs[0]['Gateway']

  def close(self):
    if not self.subnet:
      return
    cmd = ['docker', 'network', 'rm', self.__name]
    if host_run(self.logger, cmd).returncode != 0:
      self.logger.error('Failed to remove home lan %s', self.__name)
    if 'ipvlan' not in self.__name:
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
