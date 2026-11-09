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
"""Unit tests for PcapWriter and PcapCapability."""

import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from cirque.capabilities.pcapcapability import (
    BLE_ADV_ACCESS_ADDRESS,
    DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
    DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    DLT_EN10MB,
    H4_DIRECTION_RECV_CTRL_TO_HOST,
    H4_DIRECTION_SENT_HOST_TO_CTRL,
    LE_LL_PDU_DIRECTION_CENTRAL_TO_PERIPHERAL,
    LE_LL_PDU_DIRECTION_PERIPHERAL_TO_CENTRAL,
    LE_LL_PHDR_PDU_TYPE_SHIFT,
    LE_LLID_CONTINUATION,
    LE_LLID_CONTROL,
    LE_LLID_START,
    LE_MAX_DATA_PDU_PAYLOAD,
    LL_CTRL_TERMINATE_IND,
    OT_SIM_GROUP_ADDR,
    OT_SIM_LOCAL_ADDR,
    PCAP_MAGIC_MICROSECONDS,
    LeLinkLayerPcapEncoder,
    PcapCapability,
    PcapWriter,
    ThreadRadioSniffer,
    ble_channel_to_rf_channel,
    build_h4_phdr_frame,
    build_le_ll_phdr_frame,
    compute_ble_crc24,
    is_valid_connection_access_address,
    ot_sim_radio_port,
)
from cirque.connectivity.threadsimpipe import ThreadSimPipe
from cirque.pcap.summarize_pcap import (
    read_pcap_records,
    summarize_pcap,
    verify_pcap_with_tcpdump,
    verify_pcap_with_tshark,
)
from cirque.virtual_bt.link_layer import LinkLayerFrame


class TestPcapCapability(unittest.TestCase):

  def setUp(self):
    self.temp_dir = tempfile.mkdtemp(prefix='cirque_pcap_test_')

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def test_header_only_zero_frames(self):
    """Negative test: zero frames yields a valid header-only 24-byte file."""
    path = os.path.join(self.temp_dir, 'zero_frames.pcap')
    writer = PcapWriter(path, dlt=DLT_EN10MB)
    writer.close()

    self.assertTrue(os.path.exists(path))
    self.assertEqual(os.path.getsize(path), 24)
    self.assertEqual(writer.records, 0)

    with open(path, 'rb') as f:
      header = f.read(24)
      magic, maj, min_v, tz, sigfigs, snaplen, dlt = struct.unpack(
          '<IHHiIII', header
      )
      self.assertEqual(magic, PCAP_MAGIC_MICROSECONDS)
      self.assertEqual(maj, 2)
      self.assertEqual(min_v, 4)
      self.assertEqual(dlt, DLT_EN10MB)

    summary = summarize_pcap(path)
    self.assertEqual(summary['records'], 0)
    self.assertEqual(summary['dlt'], DLT_EN10MB)

    # tcpdump parses header-only file with zero error
    ok, msg = verify_pcap_with_tcpdump(path)
    if shutil.which('tcpdump'):
      self.assertTrue(ok, f'tcpdump failed: {msg}')

  def test_dlt_1_ethernet_frames(self):
    """Verifies DLT 1 Ethernet frames round-trip and match tcpdump."""
    path = os.path.join(self.temp_dir, 'test_eth.pcap')
    writer = PcapWriter(path, dlt=DLT_EN10MB)

    test_frame = (
        b'\xff\xff\xff\xff\xff\xff\x02\x00\x00\x00\x02\x01\x08\x00'
        b'TestPayload1234567890'
    )
    writer.write_frame(test_frame)
    writer.write_frame(test_frame)
    self.assertEqual(writer.records, 2)
    writer.close()

    records = read_pcap_records(path)
    self.assertEqual(len(records), 2)
    self.assertEqual(records[0][1], test_frame)
    self.assertEqual(records[1][1], test_frame)

    summary = summarize_pcap(path)
    self.assertEqual(summary['records'], 2)
    self.assertEqual(summary['dlt'], 1)

    ok, msg = verify_pcap_with_tcpdump(path)
    if shutil.which('tcpdump'):
      self.assertTrue(ok, f'tcpdump failed: {msg}')

  def test_dlt_201_hci_h4_with_phdr(self):
    """Verifies DLT 201 HCI H4 frames with direction headers."""
    path = os.path.join(self.temp_dir, 'test_h4.pcap')
    writer = PcapWriter(path, dlt=DLT_BLUETOOTH_HCI_H4_WITH_PHDR)

    # Host -> Controller: Reset command (0x0C03)
    cmd_h4 = b'\x01\x03\x0c\x00'
    frame_sent = build_h4_phdr_frame(cmd_h4, H4_DIRECTION_SENT_HOST_TO_CTRL)
    self.assertTrue(frame_sent.startswith(b'\x00\x00\x00\x00'))
    writer.write_frame(frame_sent)

    # Controller -> Host: Command Complete Event
    evt_h4 = b'\x04\x0e\x04\x01\x03\x0c\x00'
    frame_recv = build_h4_phdr_frame(evt_h4, H4_DIRECTION_RECV_CTRL_TO_HOST)
    self.assertTrue(frame_recv.startswith(b'\x00\x00\x00\x01'))
    writer.write_frame(frame_recv)

    self.assertEqual(writer.records, 2)
    writer.close()

    records = read_pcap_records(path)
    self.assertEqual(len(records), 2)
    self.assertEqual(records[0][1], frame_sent)
    self.assertEqual(records[1][1], frame_recv)

    summary = summarize_pcap(path)
    self.assertEqual(summary['dlt'], 201)
    self.assertEqual(summary['records'], 2)

    ok, msg = verify_pcap_with_tcpdump(path)
    if shutil.which('tcpdump'):
      self.assertTrue(ok, f'tcpdump failed: {msg}')

  def test_dlt_256_le_ll_with_phdr(self):
    """Verifies DLT 256 LE Link Layer frames with 10-byte pseudo-header."""
    path = os.path.join(self.temp_dir, 'test_ll.pcap')
    writer = PcapWriter(path, dlt=DLT_BLUETOOTH_LE_LL_WITH_PHDR)

    adv_frame = build_le_ll_phdr_frame(
        pdu_type='ADV_IND',
        src_bd_addr='AA:BB:CC:11:22:33',
        dst_bd_addr='FF:FF:FF:FF:FF:FF',
        src_addr_type=0,
        dst_addr_type=0,
        channel=37,
        rssi=-52,
        payload=b'\x02\x01\x06\x04\x08Cir',
    )

    # 10 bytes pseudo-header + 4 bytes access addr = 14 bytes preamble
    self.assertGreater(len(adv_frame), 14)
    # Check access address in little endian at offset 10..14
    acc_bytes = adv_frame[10:14]
    self.assertEqual(acc_bytes, struct.pack('<I', BLE_ADV_ACCESS_ADDRESS))

    writer.write_frame(adv_frame)
    self.assertEqual(writer.records, 1)
    writer.close()

    records = read_pcap_records(path)
    self.assertEqual(len(records), 1)
    self.assertEqual(records[0][1], adv_frame)

    summary = summarize_pcap(path)
    self.assertEqual(summary['dlt'], 256)
    self.assertEqual(summary['records'], 1)

    ok, msg = verify_pcap_with_tcpdump(path)
    if shutil.which('tcpdump'):
      self.assertTrue(ok, f'tcpdump failed: {msg}')

    ok, msg = verify_pcap_with_tshark(path)
    if shutil.which('tshark'):
      self.assertTrue(ok, f'tshark failed: {msg}')

  def test_concurrent_thread_safe_writes(self):
    """Verifies concurrent writes from multiple threads do not corrupt PCAP."""
    path = os.path.join(self.temp_dir, 'concurrent.pcap')
    writer = PcapWriter(path, dlt=DLT_EN10MB)

    num_threads = 8
    frames_per_thread = 50

    def _worker(thread_idx):
      for i in range(frames_per_thread):
        payload = f'Thread-{thread_idx}-Frame-{i}'.encode('utf-8')
        hdr = b'\x00\x11\x22\x33\x44\x55\x00\xaa\xbb\xcc\xdd\xee\x08\x00'
        writer.write_frame(hdr + payload)

    threads = [
        threading.Thread(target=_worker, args=(t,))
        for t in range(num_threads)
    ]
    for t in threads:
      t.start()
    for t in threads:
      t.join()

    self.assertEqual(writer.records, num_threads * frames_per_thread)
    writer.close()

    records = read_pcap_records(path)
    self.assertEqual(len(records), num_threads * frames_per_thread)

    ok, msg = verify_pcap_with_tcpdump(path)
    if shutil.which('tcpdump'):
      self.assertTrue(ok, f'tcpdump failed: {msg}')

  def test_pcap_capability_class(self):
    """Verifies PcapCapability lifecycle and description dictionary."""
    cap = PcapCapability(pcap_dir=self.temp_dir, bt=True, wifi=True)
    self.assertEqual(cap.name, 'Pcap')
    desc = cap.description
    self.assertEqual(desc['pcap_dir'], self.temp_dir)
    self.assertTrue(desc['bt'])
    self.assertTrue(desc['wifi'])

    class DummyNode:
      id = 'testnode1'

    node = DummyNode()
    cap.enable_capability(node)
    self.assertEqual(len(cap._node_writers), 2)
    cap.disable_capability(node)
    self.assertEqual(len(cap._node_writers), 0)

  def test_ble_crc24_known_vector(self):
    """Verifies BLE CRC-24 calculation against reference spec derivation.

    Specification: Bluetooth Core Spec Vol 6, Part B, Section 3.1.1 (CRC).
    Polynomial: x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1 (0x00065B).
    Init: 0x555555. Input processed LSB first, output transmitted LSB first.
    """
    # Independent reference bit-by-bit calculation from specification
    test_pdu = b'\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08'

    def _spec_crc24(pdu: bytes, init_val: int = 0x555555) -> bytes:
      lfsr = init_val & 0xFFFFFF
      for b in pdu:
        for bit in range(8):
          in_bit = (b >> bit) & 1
          feed = ((lfsr >> 23) & 1) ^ in_bit
          lfsr = ((lfsr << 1) & 0xFFFFFF) ^ (0x00065B if feed else 0)
      # Transmit bit 0 (position 23 down to 0) LSB first per byte
      out = bytearray(3)
      for i in range(24):
        bit_val = (lfsr >> (23 - i)) & 1
        byte_pos = i // 8
        bit_in_byte = i % 8
        out[byte_pos] |= (bit_val << bit_in_byte)
      return bytes(out)

    expected_crc = _spec_crc24(test_pdu, 0x555555)
    actual_crc = compute_ble_crc24(test_pdu, init=0x555555)
    self.assertEqual(actual_crc, expected_crc)
    self.assertEqual(len(actual_crc), 3)


CENTRAL = 'AA:BB:CC:11:22:33'
PERIPHERAL = 'DD:EE:FF:44:55:66'
# DLT 256 record layout: 10-byte pseudo-header, 4-byte access address,
# 2-byte PDU header, payload, 3-byte CRC.
_AA_OFFSET = 10
_PDU_OFFSET = 14


def _record_fields(record: bytes):
  """Splits a DLT 256 record into (rf_channel, flags, aa, pdu, crc)."""
  rf_channel = record[0]
  flags = struct.unpack_from('<H', record, 8)[0]
  aa = struct.unpack_from('<I', record, _AA_OFFSET)[0]
  return rf_channel, flags, aa, record[_PDU_OFFSET:-3], record[-3:]


def _l2cap_att(att: bytes) -> bytes:
  return struct.pack('<HH', len(att), 0x0004) + att


def _data_frame(src: str, dst: str, payload: bytes) -> LinkLayerFrame:
  return LinkLayerFrame('LL_DATA', src, dst, payload_hex=payload.hex())


class TestLeLinkLayerPcapEncoder(unittest.TestCase):
  """Tests the air-frame reconstruction used for DLT 256 captures."""

  def setUp(self):
    self.temp_dir = tempfile.mkdtemp(prefix='cirque_le_ll_test_')
    self.encoder = LeLinkLayerPcapEncoder(seed=7)

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def _connection_records(self, terminate=True):
    """Encodes CONNECT_IND, one ATT write each way and LL_TERMINATE_IND."""
    frames = [
        LinkLayerFrame('CONNECT_IND', CENTRAL, PERIPHERAL, channel=37),
        _data_frame(
            CENTRAL, PERIPHERAL, _l2cap_att(b'\x12\x12\x00\x01\x02\x03')
        ),
        _data_frame(PERIPHERAL, CENTRAL, _l2cap_att(b'\x13')),
    ]
    if terminate:
      frames.append(
          LinkLayerFrame('LL_TERMINATE_IND', CENTRAL, PERIPHERAL, reason=0x13)
      )
    return [self.encoder.encode(frame) for frame in frames]

  def test_ble_channel_to_rf_channel_mapping(self):
    """Core Spec Vol 6 Part B 1.4.1: advertising channels sit at RF 0/12/39."""
    self.assertEqual(ble_channel_to_rf_channel(37), 0)
    self.assertEqual(ble_channel_to_rf_channel(38), 12)
    self.assertEqual(ble_channel_to_rf_channel(39), 39)
    self.assertEqual(ble_channel_to_rf_channel(0), 1)
    self.assertEqual(ble_channel_to_rf_channel(10), 11)
    self.assertEqual(ble_channel_to_rf_channel(11), 13)
    self.assertEqual(ble_channel_to_rf_channel(36), 38)

  def test_adv_pdu_uses_rf_channel_not_adv_index(self):
    """Negative test: the phdr channel byte is never the raw index 37/38/39."""
    for channel, rf_channel in ((37, 0), (38, 12), (39, 39)):
      record = build_le_ll_phdr_frame(
          'ADV_IND', PERIPHERAL, channel=channel, payload=b'\x02\x01\x06'
      )
      self.assertEqual(record[0], rf_channel)

  def test_connection_access_address_rules(self):
    """Core Spec Vol 6 Part B 2.1.2 rejects these access addresses."""
    self.assertFalse(is_valid_connection_access_address(BLE_ADV_ACCESS_ADDRESS))
    # Differs from the advertising access address in a single bit.
    self.assertFalse(is_valid_connection_access_address(0x8E89BED7))
    # All four octets equal.
    self.assertFalse(is_valid_connection_access_address(0x11111111))
    self.assertFalse(is_valid_connection_access_address(0x00000000))
    # More than six consecutive zeros.
    self.assertFalse(is_valid_connection_access_address(0x12340080))
    # The encoder must only ever allocate valid addresses.
    for _ in range(200):
      aa = self.encoder._allocate_access_address()
      self.assertTrue(is_valid_connection_access_address(aa), hex(aa))

  def test_connect_ind_carries_real_lldata(self):
    connect_records, _, _ = self._connection_records(terminate=False)
    self.assertEqual(len(connect_records), 1)
    rf_channel, _, aa, pdu, crc = _record_fields(connect_records[0])
    self.assertEqual(rf_channel, 0)
    self.assertEqual(aa, BLE_ADV_ACCESS_ADDRESS)
    self.assertEqual(pdu[0] & 0x0F, 0x05)
    # InitA(6) + AdvA(6) + LLData(22) = 34 payload bytes.
    self.assertEqual(pdu[1], 34)
    self.assertEqual(crc, compute_ble_crc24(pdu, init=0x555555))
    lldata = pdu[2 + 12 :]
    conn_aa = struct.unpack_from('<I', lldata, 0)[0]
    self.assertNotEqual(conn_aa, BLE_ADV_ACCESS_ADDRESS)
    self.assertTrue(is_valid_connection_access_address(conn_aa))
    conn = self.encoder.connection_for(CENTRAL, PERIPHERAL)
    self.assertEqual(conn.access_address, conn_aa)
    crc_init = int.from_bytes(lldata[4:7], 'little')
    self.assertEqual(conn.crc_init, crc_init)
    win_size, win_offset, interval, latency, timeout = struct.unpack_from(
        '<BHHHH', lldata, 7
    )
    self.assertEqual((win_size, win_offset), (1, 0))
    self.assertEqual((interval, latency, timeout), (0x0018, 0, 0x01F4))
    self.assertEqual(lldata[16:21], b'\xff\xff\xff\xff\x1f')
    self.assertEqual(lldata[21] & 0x1F, conn.hop)
    self.assertTrue(5 <= conn.hop <= 16)

  def test_data_pdus_use_connection_access_address(self):
    _, c2p_records, p2c_records = self._connection_records(terminate=False)
    conn = self.encoder.connection_for(CENTRAL, PERIPHERAL)

    self.assertEqual(len(c2p_records), 1)
    rf_channel, flags, aa, pdu, crc = _record_fields(c2p_records[0])
    self.assertEqual(aa, conn.access_address)
    self.assertNotEqual(aa, BLE_ADV_ACCESS_ADDRESS)
    self.assertEqual(pdu[0] & 0x03, LE_LLID_START)
    # First PDU of the connection: SN=0, NESN=0.
    self.assertEqual(pdu[0] & 0x0C, 0x00)
    self.assertEqual(pdu[1], 10)
    self.assertEqual(pdu[2:], _l2cap_att(b'\x12\x12\x00\x01\x02\x03'))
    self.assertEqual(crc, compute_ble_crc24(pdu, init=conn.crc_init))
    self.assertNotEqual(crc, compute_ble_crc24(pdu, init=0x555555))
    self.assertEqual(
        (flags >> LE_LL_PHDR_PDU_TYPE_SHIFT) & 0x03,
        LE_LL_PDU_DIRECTION_CENTRAL_TO_PERIPHERAL,
    )
    self.assertTrue(1 <= rf_channel <= 38)
    self.assertNotIn(rf_channel, (0, 12, 39))

    _, flags, aa, pdu, _ = _record_fields(p2c_records[0])
    self.assertEqual(aa, conn.access_address)
    self.assertEqual(pdu[0] & 0x03, LE_LLID_START)
    # Reply acknowledges the central's PDU: SN=0, NESN=1.
    self.assertEqual(pdu[0] & 0x0C, 0x04)
    self.assertEqual(
        (flags >> LE_LL_PHDR_PDU_TYPE_SHIFT) & 0x03,
        LE_LL_PDU_DIRECTION_PERIPHERAL_TO_CENTRAL,
    )

  def test_terminate_becomes_ll_control_pdu_and_closes_connection(self):
    _, _, _, terminate_records = self._connection_records()
    self.assertEqual(len(terminate_records), 1)
    _, _, aa, pdu, _ = _record_fields(terminate_records[0])
    self.assertNotEqual(aa, BLE_ADV_ACCESS_ADDRESS)
    self.assertEqual(pdu[0] & 0x03, LE_LLID_CONTROL)
    self.assertEqual(pdu[2:], bytes([LL_CTRL_TERMINATE_IND, 0x13]))
    self.assertIsNone(self.encoder.connection_for(CENTRAL, PERIPHERAL))
    # A second terminate for an unknown connection produces nothing.
    self.assertEqual(
        self.encoder.encode(
            LinkLayerFrame('LL_TERMINATE_IND', CENTRAL, PERIPHERAL)
        ),
        [],
    )

  def test_emulation_only_frames_are_not_written(self):
    for pdu_type in ('CONNECT_RSP', 'PHY_ANNOUNCE'):
      self.assertEqual(
          self.encoder.encode(LinkLayerFrame(pdu_type, CENTRAL, PERIPHERAL)),
          [],
      )

  def test_data_without_connect_ind_synthesizes_connection(self):
    """A capture started mid-connection still shares one access address."""
    first = self.encoder.encode(
        _data_frame(CENTRAL, PERIPHERAL, _l2cap_att(b'\x13'))
    )
    second = self.encoder.encode(
        _data_frame(PERIPHERAL, CENTRAL, _l2cap_att(b'\x13'))
    )
    aa_first = _record_fields(first[0])[2]
    aa_second = _record_fields(second[0])[2]
    self.assertEqual(aa_first, aa_second)
    self.assertTrue(is_valid_connection_access_address(aa_first))

  def test_l2cap_continuation_fragments_get_llid_1(self):
    self.encoder.encode(LinkLayerFrame('CONNECT_IND', CENTRAL, PERIPHERAL))

    def llid_of(frame):
      records = self.encoder.encode(frame)
      self.assertEqual(len(records), 1)
      return _record_fields(records[0])[3][0] & 0x03

    # L2CAP length 10 but only 6 payload bytes present: 4 bytes to follow.
    start = struct.pack('<HH', 10, 0x0004) + b'\x01' * 6
    self.assertEqual(
        llid_of(_data_frame(CENTRAL, PERIPHERAL, start)), LE_LLID_START
    )
    # Continuation bytes that happen to look like a large length field.
    tail = b'\xff\xff\xff\xff'
    self.assertEqual(
        llid_of(_data_frame(CENTRAL, PERIPHERAL, tail)), LE_LLID_CONTINUATION
    )
    # The L2CAP PDU is complete, so the next PDU is a start fragment again.
    self.assertEqual(
        llid_of(_data_frame(CENTRAL, PERIPHERAL, _l2cap_att(b'\x13'))),
        LE_LLID_START,
    )
    # The other direction has independent reassembly state.
    self.assertEqual(
        llid_of(_data_frame(PERIPHERAL, CENTRAL, _l2cap_att(b'\x13'))),
        LE_LLID_START,
    )

  def test_long_data_pdu_is_fragmented_at_251_bytes(self):
    self.encoder.encode(LinkLayerFrame('CONNECT_IND', CENTRAL, PERIPHERAL))
    att = b'\x52' + bytes(i & 0xFF for i in range(295))
    payload = _l2cap_att(att)
    self.assertEqual(len(payload), 300)
    records = self.encoder.encode(_data_frame(CENTRAL, PERIPHERAL, payload))
    self.assertEqual(len(records), 2)
    conn = self.encoder.connection_for(CENTRAL, PERIPHERAL)
    _, _, aa0, pdu0, crc0 = _record_fields(records[0])
    _, _, aa1, pdu1, crc1 = _record_fields(records[1])
    self.assertEqual(aa0, conn.access_address)
    self.assertEqual(aa1, conn.access_address)
    self.assertEqual(pdu0[0] & 0x03, LE_LLID_START)
    self.assertEqual(pdu0[1], LE_MAX_DATA_PDU_PAYLOAD)
    self.assertEqual(pdu1[0] & 0x03, LE_LLID_CONTINUATION)
    self.assertEqual(pdu1[1], 300 - LE_MAX_DATA_PDU_PAYLOAD)
    # Consecutive fragments in one direction alternate the sequence number.
    self.assertEqual(pdu0[0] & 0x08, 0x00)
    self.assertEqual(pdu1[0] & 0x08, 0x08)
    self.assertEqual(pdu0[2:] + pdu1[2:], payload)
    self.assertEqual(crc0, compute_ble_crc24(pdu0, init=conn.crc_init))
    self.assertEqual(crc1, compute_ble_crc24(pdu1, init=conn.crc_init))

  def test_link_layer_hub_uses_encoder_for_pcap(self):
    """LinkLayerHub.set_pcap_writer installs the encoder on the hub."""
    from cirque.virtual_bt.link_layer import LinkLayerHub

    hub = LinkLayerHub()
    self.assertIsNone(hub.pcap_encoder)
    path = os.path.join(self.temp_dir, 'hub.pcap')
    writer = PcapWriter(path, dlt=DLT_BLUETOOTH_LE_LL_WITH_PHDR)
    hub.set_pcap_writer(writer)
    self.assertIsInstance(hub.pcap_encoder, LeLinkLayerPcapEncoder)
    hub.set_pcap_writer(None)
    self.assertIsNone(hub.pcap_encoder)
    writer.close()

  @unittest.skipUnless(shutil.which('tshark'), 'tshark not installed')
  def test_tshark_dissects_connection_without_errors(self):
    """Oracle: Wireshark decodes the data PDUs down to ATT with no errors."""
    path = os.path.join(self.temp_dir, 'le_connection.pcap')
    writer = PcapWriter(path, dlt=DLT_BLUETOOTH_LE_LL_WITH_PHDR)
    for records in self._connection_records():
      for record in records:
        writer.write_frame(record)
    writer.close()
    self.assertEqual(writer.records, 4)

    proc = subprocess.run(
        [
            shutil.which('tshark'),
            '-r',
            path,
            '-T',
            'fields',
            '-e',
            'frame.number',
            '-e',
            'frame.protocols',
            '-e',
            'btatt.opcode',
            '-e',
            '_ws.expert.message',
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    self.assertEqual(proc.returncode, 0, proc.stderr)
    rows = [
        (line.split('\t') + ['', '', '', ''])[:4]
        for line in proc.stdout.splitlines()
        if line.strip()
    ]
    self.assertEqual(len(rows), 4, proc.stdout)
    combined = proc.stdout + proc.stderr
    self.assertNotIn('Malformed', combined)
    self.assertNotIn('Incorrect CRC', combined)
    self.assertNotIn('Unknown', combined)
    protocols = [row[1] for row in rows]
    # CONNECT_IND is btle plus btcommon for the LLData block, never ATT.
    self.assertIn('btle', protocols[0])
    self.assertNotIn('btatt', protocols[0])
    self.assertIn('btatt', protocols[1])
    self.assertIn('btatt', protocols[2])
    opcodes = [row[2] for row in rows]
    self.assertEqual(opcodes[1], '0x12')
    self.assertEqual(opcodes[2], '0x13')
    # LL_TERMINATE_IND is an LL control PDU, so no L2CAP or ATT layer.
    self.assertIn('btle', protocols[3])
    self.assertNotIn('btl2cap', protocols[3])

  def test_traffic_control_capability_lifecycle_and_defaults(self):
    """Verifies Items 6, 7, 8: TrafficControlCapability lifecycle & defaults."""
    from types import SimpleNamespace
    from unittest.mock import MagicMock
    from cirque.capabilities.trafficcontrolcapability import (
        TrafficControlCapability,
    )
    from cirque.home.home import CirqueHome
    from cirque.home.virtual_home_topology import VirtualHomeTopology

    cap = TrafficControlCapability(latencyMs=50, loss=10)
    self.assertEqual(cap.description['latency'], 50)
    self.assertEqual(cap.description['latencyMs'], 50)
    self.assertEqual(cap.description['loss'], 10)

    # Verify enable_capability uses 'tc qdisc replace' and is idempotent
    mock_container = MagicMock()
    mock_container.exec_run.return_value = SimpleNamespace(
        exit_code=0, output=b''
    )
    mock_node = SimpleNamespace(container=mock_container)
    cap.enable_capability(mock_node)
    cap.enable_capability(mock_node)
    self.assertEqual(mock_container.exec_run.call_count, 2)
    cmd_arg = mock_container.exec_run.call_args[0][0]
    self.assertIn('tc qdisc replace dev eth0 root netem', cmd_arg)
    self.assertIn('delay 50ms', cmd_arg)
    self.assertIn('loss 10%', cmd_arg)

    # Verify non-zero exit_code raises RuntimeError
    mock_container.exec_run.return_value = SimpleNamespace(
        exit_code=2, output=b'RTNETLINK answers: Operation not permitted'
    )
    with self.assertRaises(RuntimeError):
      cap.enable_capability(mock_node)

    # Verify disable_capability removes root qdisc
    mock_container.exec_run.reset_mock()
    cap.disable_capability(mock_node)
    mock_container.exec_run.assert_called_once_with(
        'tc qdisc del dev eth0 root'
    )

    # Verify VirtualHomeTopology.default_android_emulator_ble_thread_config
    # populates default traffic_control dict and CirqueHome handles missing key
    thread_cfg = (
        VirtualHomeTopology.default_android_emulator_ble_thread_config()
    )
    self.assertIn('traffic_control', thread_cfg['thread_border_router'])
    self.assertIn('traffic_control', thread_cfg['matter_device'])
    home = CirqueHome.__new__(CirqueHome)
    tc_from_empty = home._CirqueHome__make_trafficcontrolcapability(
        'TrafficControl', {'capability': ['TrafficControl']}
    )
    self.assertEqual(tc_from_empty.latencyMs, 0)
    self.assertEqual(tc_from_empty.loss, 0)


class TestThreadRadioSniffer(unittest.TestCase):
  """ThreadRadioSniffer against the OpenThread simulation radio transport."""

  # A real 802.15.4 MAC Ack captured from the OT simulation radio (with FCS).
  ACK = bytes.fromhex('1210e0b242')

  def setUp(self):
    self.temp_dir = tempfile.mkdtemp(prefix='cirque_thread_sniffer_test_')
    # Keep clear of the 9000+ ports a real simulation on this host may use.
    self.port = 47000 + os.getpid() % 2000

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def _send_like_sim_node(self, node_id, datagram):
    # Mirrors InitTxSocketIp4() + utilsSendOverSocket() in simul_utils.c.
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
      sock.setsockopt(
          socket.IPPROTO_IP,
          socket.IP_MULTICAST_IF,
          socket.inet_aton(OT_SIM_LOCAL_ADDR),
      )
      sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
      sock.bind((OT_SIM_LOCAL_ADDR, self.port + node_id))
      sock.sendto(datagram, (OT_SIM_GROUP_ADDR, self.port))
    finally:
      sock.close()

  def test_ot_sim_radio_port(self):
    self.assertEqual(ot_sim_radio_port(0), 9000)
    self.assertEqual(ot_sim_radio_port(1), 9034)
    # ThreadSimPipe passes PORT_OFFSET = petition_id * 34 to ot-rcp.
    self.assertEqual(ot_sim_radio_port(2 * 34), 9000 + 2 * 34 * 34)
    self.assertEqual(ot_sim_radio_port(1, port_base=12000), 12034)

  def test_captures_multicast_frames_as_dlt_195(self):
    path = os.path.join(self.temp_dir, 'thread_0.pcap')
    sniffer = ThreadRadioSniffer(path, self.port)
    sniffer.start()
    try:
      self._send_like_sim_node(2, bytes([15]) + self.ACK)
      self._send_like_sim_node(3, bytes([26]) + self.ACK)
      self._send_like_sim_node(3, b'\x0f\x02')  # No room for a PSDU + FCS.
      deadline = time.time() + 2.0
      while sniffer.frames < 2 and time.time() < deadline:
        time.sleep(0.02)
    finally:
      sniffer.stop()
    self.assertEqual(sniffer.frames, 2)
    self.assertEqual(dict(sniffer.channels), {15: 1, 26: 1})
    self.assertEqual(dict(sniffer.nodes), {2: 1, 3: 1})
    with open(path, 'rb') as f:
      self.assertEqual(struct.unpack('<I', f.read(24)[20:24])[0], 195)
    self.assertEqual(
        [raw for _, raw in read_pcap_records(path)], [self.ACK, self.ACK]
    )

  def test_channel_filter(self):
    path = os.path.join(self.temp_dir, 'thread_1.pcap')
    sniffer = ThreadRadioSniffer(path, self.port + 100, channel=15)
    sniffer.start()
    try:
      self.assertTrue(sniffer.handle_datagram(b'\x0f' + self.ACK, 1, ts=1.0))
      self.assertFalse(sniffer.handle_datagram(b'\x0b' + self.ACK, 1, ts=2.0))
    finally:
      sniffer.stop()
    self.assertEqual(len(read_pcap_records(path)), 1)
    self.assertFalse(sniffer.handle_datagram(b'\x0f' + self.ACK, 1))

  def test_thread_sim_pipe_shares_one_sniffer_per_petition(self):
    env = {'CIRQUE_PCAP_DIR': self.temp_dir, 'PORT_BASE': str(self.port)}
    with patch.dict(os.environ, env):
      pipes = [ThreadSimPipe(node_id, petition_id=7) for node_id in (1, 2)]
      for pipe in pipes:
        pipe._acquire_sniffer(port_offset=0)
      sniffers = ThreadSimPipe._ThreadSimPipe__sniffers
      self.assertEqual(sniffers[7][1], 2)
      sniffer = sniffers[7][0]
      self.assertEqual(sniffer.port, self.port)
      pipes[0]._release_sniffer()
      self.assertIn(7, sniffers)
      pipes[1]._release_sniffer()
      self.assertNotIn(7, sniffers)
    self.assertIsNone(sniffer._sock)
    self.assertTrue(
        os.path.isfile(os.path.join(self.temp_dir, 'thread_7.pcap'))
    )


if __name__ == '__main__':
  unittest.main()

