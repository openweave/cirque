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
"""Test helper that keeps virtual BT/Wi-Fi sockets away from live homes.

Without CIRQUE_VIRTUAL_BT_RUNTIME_DIR / CIRQUE_VIRTUAL_WIFI_RUNTIME_DIR the
shared virtual servers bind their Unix sockets under the host-global
/tmp/cirque_virtual_bt and /tmp/cirque_virtual_wifi directories. A cirque home
running on the same host uses those too, so its agents would reconnect into the
test process (and the test would replace the home's sockets).

Usage in a test module:

  def setUpModule():
    unittest.addModuleCleanup(isolate_virtual_runtime_dirs())
"""

import os
import shutil
import tempfile
from typing import Callable

from cirque.capabilities.bluetoothcapability import BlueToothCapability
from cirque.capabilities.wificapability import WiFiCapability

_ENV_SUBDIRS = (
    ('CIRQUE_VIRTUAL_BT_RUNTIME_DIR', 'bt'),
    ('CIRQUE_VIRTUAL_WIFI_RUNTIME_DIR', 'wifi'),
)


def _stop_shared_servers() -> None:
  BlueToothCapability.stop_virtual_server()
  WiFiCapability.stop_virtual_server()


def isolate_virtual_runtime_dirs() -> Callable[[], None]:
  """Points both runtime dirs at a private temp dir; returns the cleanup.

  Shared servers left running by an earlier module in the same process are
  stopped first so the next one is created under the private dir. The cleanup
  stops the shared servers, restores the environment, and removes the dir.
  """
  _stop_shared_servers()
  saved = {name: os.environ.get(name) for name, _ in _ENV_SUBDIRS}
  root = tempfile.mkdtemp(prefix='cirque_rt_')
  for name, subdir in _ENV_SUBDIRS:
    os.environ[name] = os.path.join(root, subdir)

  def cleanup() -> None:
    _stop_shared_servers()
    for name, value in saved.items():
      if value is None:
        os.environ.pop(name, None)
      else:
        os.environ[name] = value
    shutil.rmtree(root, ignore_errors=True)

  return cleanup
