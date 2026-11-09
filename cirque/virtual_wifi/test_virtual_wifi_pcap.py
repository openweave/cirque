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
"""Integration test for VirtualWiFiServer PCAP capture.

Tests DLT 1 Ethernet and EAPOL frame formats.
"""

import os
import shutil
import socket
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
from cirque.virtual_wifi.server import VirtualWiFiServer


class TestVirtualWiFiPcap(unittest.TestCase):

  def setUp(self):
    self.temp_dir = tempfile.mkdtemp(prefix='cirque_wifi_pcap_test_')
    self.server = VirtualWiFiServer(host='127.0.0.1', pcap_dir=self.temp_dir)
    self.server.start()

  def tearDown(self):
    self.server.stop()
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_virtual_wifi_pcap_exchange(self):
    """Verifies in-process L2 Ethernet and EAPOL frame capture into PCAP."""
    self.server.register_ap(ssid='TestAP', psk='12345678', ap_id='ap0')
    sta0 = self.server.register_station('sta0')
    sta1 = self.server.register_station('sta1', mac_addr='02:00:00:00:02:01')
    sta2 = self.server.register_station('sta2', mac_addr='02:00:00:00:02:02')

    medium_pcap = os.path.join(self.temp_dir, 'wifi_medium.pcap')
    ap_pcap = os.path.join(self.temp_dir, 'wifi_ap.pcap')
    sta0_pcap = os.path.join(self.temp_dir, 'wifi_sta0.pcap')
    sta1_pcap = os.path.join(self.temp_dir, 'wifi_sta1.pcap')
    sta2_pcap = os.path.join(self.temp_dir, 'wifi_sta2.pcap')

    # All files must exist with valid 24-byte header immediately upon
    # registration
    for p in (medium_pcap, ap_pcap, sta0_pcap, sta1_pcap, sta2_pcap):
      self.assertTrue(os.path.exists(p), f'Missing {p}')
      self.assertEqual(os.path.getsize(p), 24)
      sum_meta = summarize_pcap(p)
      self.assertEqual(sum_meta['dlt'], 1)
      self.assertEqual(sum_meta['records'], 0)

    # Transition sta1 and sta2 to completed so L2 switch allows data frames
    sta1.state = 'completed'
    sta2.state = 'completed'

    # Connect sta1 and sta2 data sockets to data_port
    sock1 = socket.create_connection(('127.0.0.1', self.server.data_port))
    sock1.sendall(struct.pack('!H', len('sta1')) + b'sta1')

    sock2 = socket.create_connection(('127.0.0.1', self.server.data_port))
    sock2.sendall(struct.pack('!H', len('sta2')) + b'sta2')

    time.sleep(0.05)

    # Send L2 Ethernet frame from sta1 to sta2
    dst_mac = bytes.fromhex(sta2.mac_addr.replace(':', ''))
    src_mac = bytes.fromhex(sta1.mac_addr.replace(':', ''))
    test_eth_payload = (
        dst_mac
        + src_mac
        + struct.pack('!H', 0x0800)
        + b'WiFiTestDataPacketPayload12345678'
    )
    sock1.sendall(struct.pack('!H', len(test_eth_payload)) + test_eth_payload)

    # Read frame on sock2
    hdr = sock2.recv(2)
    self.assertEqual(len(hdr), 2)
    flen = struct.unpack('!H', hdr)[0]
    rx_frame = sock2.recv(flen)
    self.assertEqual(len(rx_frame), flen)

    # Send EAPOL frame from AP to sta1
    eapol_dummy = b'\x01\x03\x00\x05hello'
    self.server._send_eapol_frame_to_station(
        'sta1', '02:00:00:00:01:00', sta1.mac_addr, eapol_dummy
    )

    time.sleep(0.05)
    sock1.close()
    sock2.close()

    # Verify medium PCAP recorded both the relayed data frame and the
    # EAPOL frame
    med_records = read_pcap_records(medium_pcap)
    self.assertEqual(len(med_records), 2)
    self.assertEqual(med_records[0][1], test_eth_payload)
    self.assertIn(eapol_dummy, med_records[1][1])

    # Verify sta1 PCAP recorded both frames (1 sent, 1 received)
    sta1_records = read_pcap_records(sta1_pcap)
    self.assertEqual(len(sta1_records), 2)

    # Verify sta2 PCAP recorded the received data frame
    sta2_records = read_pcap_records(sta2_pcap)
    self.assertEqual(len(sta2_records), 1)
    self.assertEqual(sta2_records[0][1], test_eth_payload)

    # Verify AP PCAP recorded the EAPOL frame
    ap_records = read_pcap_records(ap_pcap)
    self.assertEqual(len(ap_records), 1)

    # Verify sta0 has zero frames and remains exactly 24 bytes header-only
    self.assertEqual(os.path.getsize(sta0_pcap), 24)
    sum_sta0 = summarize_pcap(sta0_pcap)
    self.assertEqual(sum_sta0['records'], 0)

    # Verify all generated PCAP files parse with tcpdump
    if shutil.which('tcpdump'):
      for p in (medium_pcap, ap_pcap, sta0_pcap, sta1_pcap, sta2_pcap):
        ok, msg = verify_pcap_with_tcpdump(p)
        self.assertTrue(ok, f'tcpdump failed on {p}: {msg}')

    # Verify all generated PCAP files parse with tshark without malformation
    if shutil.which('tshark'):
      for p in (medium_pcap, ap_pcap, sta0_pcap, sta1_pcap, sta2_pcap):
        ok, msg = verify_pcap_with_tshark(p)
        self.assertTrue(ok, f'tshark failed on {p}: {msg}')


if __name__ == '__main__':
  unittest.main()
