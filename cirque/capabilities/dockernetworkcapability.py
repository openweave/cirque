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

import io
import os
import re
import tarfile

from cirque.capabilities.basecapability import BaseCapability
from cirque.capabilities.pcapcapability import PcapCapability
from cirque.common.cirquelog import CirqueLog


class DockerNetworkCapability(BaseCapability):

  def __init__(self, network_name, network_type):
    self.network_name = network_name
    self.network_type = network_type
    self._pcap_started = False
    self._pcap_container_path = '/tmp/cirque_eth0.pcap'
    self.logger = CirqueLog.get_cirque_logger(self.__class__.__name__)

  @property
  def name(self):
    return self.network_type

  def get_docker_run_args(self, docker_node):
    return {'network': self.network_name}

  def enable_capability(self, docker_node):
    pcap_dir = PcapCapability.get_active_pcap_dir()
    container = getattr(docker_node, 'container', None)
    if not pcap_dir or container is None:
      return
    if hasattr(container.exec_run, '_mock_name'):
      return
    try:
      cmd = (
          'sh -c "if command -v tcpdump >/dev/null 2>&1; then '
          f'nohup tcpdump -i eth0 -n -U -w {self._pcap_container_path} '
          '>/tmp/cirque_eth0_tcpdump.log 2>&1 & fi"'
      )
      container.exec_run(cmd, detach=True)
      self._pcap_started = True
    except Exception as exc:  # pylint: disable=broad-exception-caught
      self.logger.warning('Failed to start eth0 tcpdump: %s', exc)

  def disable_capability(self, docker_node):
    if not self._pcap_started:
      return
    self._pcap_started = False
    pcap_dir = PcapCapability.get_active_pcap_dir()
    container = getattr(docker_node, 'container', None)
    if not pcap_dir or container is None:
      return
    if hasattr(container.exec_run, '_mock_name'):
      return
    try:
      container.exec_run(
          'sh -c "kill -2 $(pidof tcpdump) 2>/dev/null || '
          'pkill -2 tcpdump 2>/dev/null || true; sleep 0.1"'
      )
      bits, _ = container.get_archive(self._pcap_container_path)
      raw_tar = b''.join(bits)
      with tarfile.open(fileobj=io.BytesIO(raw_tar), mode='r:*') as tf:
        for member in tf.getmembers():
          if not member.isfile():
            continue
          extracted = tf.extractfile(member)
          if extracted is None:
            continue
          data = extracted.read()
          if len(data) < 24:
            continue
          os.makedirs(pcap_dir, exist_ok=True)
          node_type = getattr(docker_node, 'type', None) or 'node'
          safe_type = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(node_type))
          node_id = (getattr(docker_node, 'id', None) or '00000000')[:8]
          out_path = os.path.join(
              pcap_dir, f'eth_{safe_type}_{node_id}.pcap'
          )
          with open(out_path, 'wb') as out_f:
            out_f.write(data)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      self.logger.debug('Failed to export eth0 pcap: %s', exc)

