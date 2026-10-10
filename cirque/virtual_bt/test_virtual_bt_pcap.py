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
"""Integration test for VirtualBluetoothServer PCAP capture.

Tests both HCI (DLT 201) and Link Layer (DLT 256) formats.
"""

import os
import shutil
import struct
import tempfile
import time
import unittest

from cirque.pcap.summarize_pcap import (
    read_pcap_records,
    summarize_pcap,
    verify_pcap_with_tcpdump,
    verify_pcap_with_tshark,
)
from cirque.virtual_bt.client import H4TcpClient
from cirque.virtual_bt.hci_h4 import H4Packet, H4PacketType, HciOpcode
from cirque.virtual_bt.server import VirtualBluetoothServer


class TestVirtualBluetoothPcap(unittest.TestCase):

  def setUp(self):
    self.temp_dir = tempfile.mkdtemp(prefix='cirque_bt_pcap_test_')
    self.server = VirtualBluetoothServer(
        host='127.0.0.1', pcap_dir=self.temp_dir
    )
    self.server.start()

  def tearDown(self):
    self.server.stop()
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_virtual_bt_pcap_exchange(self):
    """Verifies real in-process H4 and LinkLayer frame capture into PCAP."""
    # Controller hci0 and hci1 created
    ctrl0 = self.server.create_controller('hci0', dedicated_port=True)
    ctrl1 = self.server.create_controller('hci1', dedicated_port=True)

    hci0_pcap = os.path.join(self.temp_dir, 'bt_hci_hci0.pcap')
    hci1_pcap = os.path.join(self.temp_dir, 'bt_hci_hci1.pcap')
    medium_pcap = os.path.join(self.temp_dir, 'bt_medium.pcap')

    # Files must exist immediately as valid 24-byte headers
    self.assertTrue(os.path.exists(hci0_pcap))
    self.assertTrue(os.path.exists(hci1_pcap))
    self.assertTrue(os.path.exists(medium_pcap))
    self.assertEqual(os.path.getsize(hci0_pcap), 24)
    self.assertEqual(os.path.getsize(medium_pcap), 24)

    sum_h4 = summarize_pcap(hci0_pcap)
    self.assertEqual(sum_h4['dlt'], 201)
    self.assertEqual(sum_h4['records'], 0)

    sum_med = summarize_pcap(medium_pcap)
    self.assertEqual(sum_med['dlt'], 256)
    self.assertEqual(sum_med['records'], 0)

    # Connect client to hci0 dedicated port
    client = H4TcpClient(
        host=self.server.host,
        port=ctrl0.dedicated_hci_port,
    )
    client.reset()

    # Broadcast one advertisement from ctrl0
    # Length byte 0x09: 1 byte type (0x09 complete name) + 8 chars 'CirqueBT'
    ctrl0.state.adv_enabled = True
    ctrl0.state.adv_data = b'\x02\x01\x06\x09\x09CirqueBT'
    ctrl0.broadcast_advertising_once()

    time.sleep(0.1)
    client.close()

    # Assertions on HCI H4 PCAP
    h4_records = read_pcap_records(hci0_pcap)
    self.assertGreaterEqual(len(h4_records), 2)
    # First record: host -> controller (direction 0)
    dir_host_to_ctrl = struct.unpack('!I', h4_records[0][1][:4])[0]
    self.assertEqual(dir_host_to_ctrl, 0)
    # Second record: controller -> host (direction 1)
    dir_ctrl_to_host = struct.unpack('!I', h4_records[1][1][:4])[0]
    self.assertEqual(dir_ctrl_to_host, 1)

    # Assertions on LinkLayer PHY medium PCAP
    ll_records = read_pcap_records(medium_pcap)
    self.assertGreaterEqual(len(ll_records), 1)

    # Verify hci1 has zero frames and remains exactly 24 bytes header-only
    sum_hci1 = summarize_pcap(hci1_pcap)
    self.assertEqual(sum_hci1['records'], 0)
    self.assertEqual(sum_hci1['dlt'], 201)
    self.assertEqual(os.path.getsize(hci1_pcap), 24)

    # Verify with tcpdump
    if shutil.which('tcpdump'):
      ok, msg = verify_pcap_with_tcpdump(hci0_pcap)
      self.assertTrue(ok, f'tcpdump failed on hci0_pcap: {msg}')
      ok, msg = verify_pcap_with_tcpdump(hci1_pcap)
      self.assertTrue(ok, f'tcpdump failed on hci1_pcap: {msg}')
      ok, msg = verify_pcap_with_tcpdump(medium_pcap)
      self.assertTrue(ok, f'tcpdump failed on medium_pcap: {msg}')

    # Verify with tshark
    if shutil.which('tshark'):
      ok, msg = verify_pcap_with_tshark(hci0_pcap)
      self.assertTrue(ok, f'tshark failed on hci0_pcap: {msg}')
      ok, msg = verify_pcap_with_tshark(hci1_pcap)
      self.assertTrue(ok, f'tshark failed on hci1_pcap: {msg}')
      ok, msg = verify_pcap_with_tshark(medium_pcap)
      self.assertTrue(ok, f'tshark failed on medium_pcap: {msg}')


if __name__ == '__main__':
  unittest.main()
