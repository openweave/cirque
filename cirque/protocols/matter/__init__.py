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
"""Matter wire-format helpers for cirque.

Everything here follows the public Matter Core Specification and does not
depend on the connectedhomeip source tree:

  ble_bridge  BLE commissioning transport: the 0xFFF6 advertisement service
              data and the BTP GATT service (C1 / C2 / C3), packaged as the
              MATTER_BLE_PROFILE for cirque.virtual_bt's adapter bridge, plus
              MatterBleAdapterBridge with Matter-named methods.
  session     Session key log parsing, BTP reassembly and AES-128-CCM
              decryption of Matter messages, used by the pcap flow visualizer.

Tests that exercise the connectedhomeip SDK itself live in connectedhomeip
(src/test_driver/linux-cirque and docs/testing).
"""
