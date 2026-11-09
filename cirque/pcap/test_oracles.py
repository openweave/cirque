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
"""Unit tests for cirque.pcap.oracles and cirque.protocols.matter.icd."""

import os
import socket
import struct
import tempfile
import unittest
from unittest import mock

from cirque.pcap import oracles
from cirque.protocols.matter import icd


def _write_pcap(path, linktype, records):
  """records: iterable of (ts_float, frame_bytes)."""
  with open(path, 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype))
    for ts, frame in records:
      sec = int(ts)
      usec = int(round((ts - sec) * 1e6))
      f.write(struct.pack('<IIII', sec, usec, len(frame), len(frame)))
      f.write(frame)


def _eth(ethertype, payload):
  return b'\x02' * 6 + b'\x04' * 6 + struct.pack('!H', ethertype) + payload


def _ipv4_udp(src, dst, sport, dport, payload):
  udp = struct.pack('!HHHH', sport, dport, 8 + len(payload), 0) + payload
  ip = struct.pack(
      '!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
      socket.inet_aton(src), socket.inet_aton(dst),
  )
  return ip + udp


def _dhcp(msg_type, yiaddr):
  bootp = bytearray(240)
  bootp[0] = 2  # BOOTREPLY
  bootp[16:20] = socket.inet_aton(yiaddr)
  bootp[236:240] = b'\x63\x82\x53\x63'
  return bytes(bootp) + bytes([53, 1, msg_type, 0xFF])


def _hci_le_conn_complete(handle, status=0, sub_event=0x01):
  params = bytes([sub_event, status]) + struct.pack('<H', handle) + b'\x00' * 15
  h4 = bytes([0x04, 0x3E, len(params)]) + params
  return struct.pack('!I', 1) + h4  # PHDR direction + H4 packet


def _checkin_message(counter=7, source_node_id=0x1122334455667788):
  msg_flags = 0x04  # source node id present, no destination
  hdr = struct.pack('<BHBI', msg_flags, 0, 0, counter)
  hdr += struct.pack('<Q', source_node_id)
  exch = struct.pack('<BBHH', 0x00, 0x50, 0x1234, 0x0000)  # flags, opcode, xid, proto
  return hdr + exch + bytes(range(40))  # >= 35-byte Check-In payload


class TestGenericOracles(unittest.TestCase):

  def setUp(self):
    self.tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp.cleanup)

  def _path(self, name):
    return os.path.join(self.tmp.name, name)

  def test_iter_pcap_records_with_ts(self):
    p = self._path('a.pcap')
    _write_pcap(p, oracles.DLT_EN10MB, [(1.5, b'abc'), (2.25, b'de')])
    recs = list(oracles.iter_pcap_records_with_ts(p))
    self.assertEqual([r[0] for r in recs], [oracles.DLT_EN10MB] * 2)
    self.assertAlmostEqual(recs[0][1], 1.5)
    self.assertEqual([r[2] for r in recs], [b'abc', b'de'])

  def test_not_a_pcap_raises(self):
    p = self._path('bad.pcap')
    with open(p, 'wb') as f:
      f.write(b'\x00' * 24)
    with self.assertRaises(ValueError):
      list(oracles.iter_pcap_records(p))

  def test_hci_le_connection_complete_handles(self):
    p = self._path('bt.pcap')
    _write_pcap(p, oracles.DLT_BLUETOOTH_HCI_H4_WITH_PHDR, [
        (1.0, _hci_le_conn_complete(0x0040)),
        (1.1, _hci_le_conn_complete(0x0041, status=0x3E)),  # failed
        (1.2, _hci_le_conn_complete(0x0042, sub_event=0x0A)),  # enhanced
    ])
    self.assertEqual(oracles.hci_le_connection_complete_handles(p), [0x40, 0x42])

  def test_dhcp_ack_addresses_and_eapol_count(self):
    p = self._path('wifi.pcap')
    _write_pcap(p, oracles.DLT_EN10MB, [
        (1.0, _eth(0x0800, _ipv4_udp('10.0.1.1', '10.0.1.12', 67, 68, _dhcp(2, '10.0.1.12')))),
        (1.1, _eth(0x0800, _ipv4_udp('10.0.1.1', '10.0.1.12', 67, 68, _dhcp(5, '10.0.1.12')))),
        (1.2, _eth(0x888E, b'\x02\x03\x00\x5f')),
        (1.3, _eth(0x888E, b'\x02\x03\x00\x5f')),
    ])
    self.assertEqual(oracles.dhcp_ack_addresses(p), ['10.0.1.12'])
    self.assertEqual(oracles.eapol_frame_count(p), 2)

  def test_mac_commands_acks_and_pairing(self):
    p = self._path('thread.pcap')
    data_req = struct.pack('<HB', 0xC863, 0x21) + b'\xff\xff' + b'\x04'
    ack_pending = struct.pack('<HB', 0x0012, 0x21)
    ack_other = struct.pack('<HB', 0x0002, 0x99)
    _write_pcap(p, oracles.DLT_IEEE802_15_4_NOFCS, [
        (10.000, data_req),
        (10.010, ack_other),
        (10.020, ack_pending),
    ])
    cmds = oracles.ieee802154_mac_command_frames(p)
    acks = oracles.ieee802154_ack_frames(p)
    self.assertEqual([c['seq'] for c in cmds], [0x21])
    self.assertEqual([(a['seq'], a['frame_pending']) for a in acks], [(0x99, False), (0x21, True)])
    matched = oracles.acked_mac_commands(cmds, acks)
    self.assertEqual(len(matched), 1)
    self.assertTrue(matched[0]['frame_pending'])
    self.assertEqual(oracles.acked_mac_commands(cmds, acks, max_delay_s=0.005), [])

  def test_tshark_missing_raises(self):
    with mock.patch.object(oracles.shutil, 'which', return_value=None):
      with self.assertRaises(RuntimeError):
        oracles.thread_decrypted_udp_frames('x.pcap', '00' * 16)
      with self.assertRaises(RuntimeError):
        oracles.thread_mle_frames('x.pcap', '00' * 16)


class TestMatterIcdOracles(unittest.TestCase):

  def test_parse_checkin(self):
    parsed = icd.parse_matter_icd_checkin(_checkin_message())
    self.assertIsNotNone(parsed)
    self.assertEqual(parsed['msg_counter'], 7)
    self.assertEqual(parsed['source_node_id'], 0x1122334455667788)
    self.assertEqual(parsed['exchange_id'], 0x1234)
    self.assertEqual(parsed['payload_len'], 40)

  def test_rejects_secured_or_wrong_opcode(self):
    msg = bytearray(_checkin_message())
    msg[1] = 0x01  # non-zero session id
    self.assertIsNone(icd.parse_matter_icd_checkin(bytes(msg)))
    msg = bytearray(_checkin_message())
    msg[8 + 8 + 1] = 0x51  # opcode
    self.assertIsNone(icd.parse_matter_icd_checkin(bytes(msg)))

  def test_checkin_packets_from_ipv6_capture(self):
    payload = _checkin_message()
    udp = struct.pack('!HHHH', 5540, 5540, 8 + len(payload), 0) + payload
    ip6 = struct.pack('!IHBB', 0x60000000, len(udp), 17, 64)
    ip6 += socket.inet_pton(socket.AF_INET6, 'fd00::1')
    ip6 += socket.inet_pton(socket.AF_INET6, 'fd00::2')
    with tempfile.TemporaryDirectory() as tmp:
      p = os.path.join(tmp, 'wifi.pcap')
      _write_pcap(p, oracles.DLT_EN10MB, [(3.0, _eth(0x86DD, ip6 + udp))])
      found = icd.matter_icd_checkin_packets(p)
    self.assertEqual(len(found), 1)
    self.assertEqual(found[0]['src_ip'], 'fd00::1')
    self.assertEqual(found[0]['dport'], 5540)


if __name__ == '__main__':
  unittest.main()
