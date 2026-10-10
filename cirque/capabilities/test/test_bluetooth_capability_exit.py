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
"""The shared virtual BT service must not orphan its dbus-daemon on exit."""

import os
import shutil
import subprocess
import sys
import time
import unittest

from cirque.common.isolated_runtime_dirs import isolate_virtual_runtime_dirs

_CHILD = r"""
from cirque.capabilities.bluetoothcapability import BlueToothCapability
BlueToothCapability.get_or_start_virtual_server(host='127.0.0.1')
svc = BlueToothCapability._SHARED_BLUEZ_DBUS
proc = getattr(svc, '_dbus_proc', None)
print('DBUS_PID', proc.pid if proc is not None else -1, flush=True)
# Exit without calling stop_virtual_server(), like a unit test would.
"""


def _alive(pid: int) -> bool:
  try:
    with open(f'/proc/{pid}/stat', 'r', encoding='utf-8') as f:
      state = f.read().rsplit(')', 1)[1].split()[0]
    return state != 'Z'
  except (FileNotFoundError, IndexError):
    return False


def setUpModule():
  # The child inherits the private runtime dirs through the environment.
  unittest.addModuleCleanup(isolate_virtual_runtime_dirs())


class SharedVirtualServerExitTest(unittest.TestCase):

  @unittest.skipUnless(shutil.which('dbus-daemon'), 'dbus-daemon not installed')
  def test_dbus_daemon_is_stopped_when_interpreter_exits(self):
    root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', '..', '..')
    )
    env = dict(os.environ, PYTHONPATH=root, PYTHONDONTWRITEBYTECODE='1')
    out = subprocess.run(
        [sys.executable, '-c', _CHILD],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    ).stdout
    pids = [
        int(line.split()[1])
        for line in out.splitlines()
        if line.startswith('DBUS_PID')
    ]
    self.assertEqual(len(pids), 1, out)
    pid = pids[0]
    if pid < 0:
      self.skipTest('shared service did not start a dedicated dbus-daemon')
    deadline = time.time() + 5.0
    while _alive(pid) and time.time() < deadline:
      time.sleep(0.05)
    alive = _alive(pid)
    if alive:
      os.kill(pid, 15)
    self.assertFalse(alive, f'dbus-daemon {pid} outlived its parent')


if __name__ == '__main__':
  unittest.main()
