#!/usr/bin/env python3
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
"""Negative control check for Virtual Bluetooth relay."""

import sys
from cirque.capabilities.bluetoothcapability import BlueToothCapability

def main() -> int:
  server = BlueToothCapability.get_or_start_virtual_server()
  server.set_relay_enabled(False)
  if getattr(server, 'relay_enabled', None) is not False:
    print("FAILED: BT relay still enabled after disable", file=sys.stderr)
    return 1
  server.set_relay_enabled(True)
  if getattr(server, 'relay_enabled', None) is not True:
    print("FAILED: BT relay not re-enabled", file=sys.stderr)
    return 1
  print("SUCCESS: BT relay enable/disable negative control verified.")
  return 0

if __name__ == '__main__':
  sys.exit(main())
