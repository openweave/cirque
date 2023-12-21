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
import subprocess
import shutil
from threading import Lock

from cirque.common.cirquelog import CirqueLog
from cirque.common.taskrunner import TaskRunner
from cirque.connectivity.socatpipepair import SocatPipePair


class ThreadSimPipe:
  __next_petition_id = 0
  __THREAD_GROUP_SIZE = 34
  __petition_mutex = Lock()

  @classmethod
  def get_next_petition(cls):
    with cls.__petition_mutex:
      cls.__next_petition_id += 1
      return cls.__next_petition_id

  def __init__(self, node_id, petition_id=0, rcp=False):
    self._socat_pipe = SocatPipePair()
    self.pipe_path_for_user = None
    self.pipe_path_for_ncp = None
    self.node_id = node_id
    self.radio_fd = None
    self.radio_process = None
    self.petition_id = petition_id
    self.logger = CirqueLog.get_cirque_logger(self.__class__.__name__)
    if rcp:
      self.radio_command = 'ot-rcp'
    else:
      self.radio_command = 'ot-ncp-ftd'

  def open(self):
    self._socat_pipe.open()
    self.pipe_path_for_user = self._socat_pipe.pipe0
    self.pipe_path_for_ncp = self._socat_pipe.pipe1
    self.radio_fd = os.open(self.pipe_path_for_ncp, os.O_RDWR)
    env = os.environ
    env['PORT_OFFSET'] = str(self.petition_id * self.__THREAD_GROUP_SIZE)
    command = [self.radio_command, '{}'.format(self.node_id)]
    self.logger.info("-> Start virtual OpenThread Radio: command=%s, env=%s", command, env)
    self.radio_process = TaskRunner.post_task(lambda:subprocess.Popen(
        command,
        env=env,
        stdout=self.radio_fd,
        stdin=self.radio_fd,
        stderr=subprocess.PIPE)).wait()

  def close(self):
    if self.radio_fd is not None:
      os.close(self.radio_fd)
      self.radio_fd = None
    if self.radio_process is not None:
      self.radio_process.terminate()
      self.radio_process = None
    if self._socat_pipe is not None:
      self._socat_pipe.close()
      self._socat_pipe = None
    if os.path.exists('./tmp'):
      shutil.rmtree('./tmp')

  def __del__(self):
    self.close()
