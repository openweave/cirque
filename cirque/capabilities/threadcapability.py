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

import os

from cirque.capabilities.basecapability import BaseCapability
from cirque.capabilities.pcapcapability import PcapCapability
from cirque.common.cirquelog import CirqueLog
from cirque.connectivity.threadsimpipe import ThreadSimPipe
from cirque.pcap.thread_keys import (
    DEFAULT_OT_DATASET_TLVS_HEX,
    DEFAULT_OT_NETWORK_KEY,
    THREAD_KEY_FILE,
    parse_ot_ctl_output,
    write_thread_key_files,
)


class ThreadCapability(BaseCapability):

  def __init__(self, node_id, petition_id, daemons=None, rcp=False):
    if daemons is None:
      daemons = ('wpantund', 'otbr-agent')
    self.thread_endpoint = ThreadSimPipe(node_id, petition_id, rcp)
    self.thread_endpoint.open()
    self.logger = CirqueLog.get_cirque_logger(self.__class__.__name__)
    self.daemons = list(daemons)
    for daemon in self.daemons:
      if daemon not in {'wpantund', 'otbr-agent'}:
        self.logger.warning(
            'using unkown thread daemon mode: %s', daemon
        )

  @property
  def name(self):
    return 'Thread'

  def get_docker_run_args(self, dockernode):
    return {
        'devices': [
            '{}:/dev/ttyUSB0'.format(self.thread_endpoint.pipe_path_for_user)
        ],
        'volumes': [
            '{}:/dev/ttyUSB0'.format(self.thread_endpoint.pipe_path_for_user)
        ],
        'sysctls': {
            'net.ipv6.conf.all.disable_ipv6': 0,
            'net.ipv4.conf.all.forwarding': 1,
            'net.ipv6.conf.all.forwarding': 1,
        },
        'privileged': True,
        'tty': True,
    }

  def _export_thread_keys(self, docker_node):
    pcap_dir = PcapCapability.get_active_pcap_dir()
    container = getattr(docker_node, 'container', None)
    if not pcap_dir or container is None:
      return
    if hasattr(container.exec_run, '_mock_name'):
      return
    try:
      ret = container.exec_run(
          'sh -c "ot-ctl dataset active -x 2>/dev/null; '
          'ot-ctl dataset active 2>/dev/null; '
          'ot-ctl networkkey 2>/dev/null"'
      )
      output = (
          ret.output.decode('utf-8', errors='replace')
          if hasattr(ret, 'output') and isinstance(ret.output, bytes)
          else ''
      )
      parsed = parse_ot_ctl_output(output)
      if parsed.get('network_key'):
        write_thread_key_files(
            pcap_dir,
            network_key=parsed['network_key'],
            pan_id=parsed.get('pan_id'),
            ext_pan_id=parsed.get('ext_pan_id', ''),
            channel=parsed.get('channel'),
            dataset_tlvs_hex=parsed.get('dataset_tlvs_hex', ''),
        )
      elif not os.path.exists(os.path.join(pcap_dir, THREAD_KEY_FILE)):
        write_thread_key_files(
            pcap_dir,
            network_key=DEFAULT_OT_NETWORK_KEY,
            dataset_tlvs_hex=DEFAULT_OT_DATASET_TLVS_HEX,
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
      self.logger.debug('Failed to export Thread key files: %s', exc)

  def disable_capability(self, docker_node):
    self._export_thread_keys(docker_node)
    for daemon in self.daemons:
      docker_node.container.exec_run('killall {}'.format(daemon))
    self.thread_endpoint.close()
    self.thread_endpoint = None
