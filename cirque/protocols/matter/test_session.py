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
"""Tests for Matter BTP reassembly and session-key decryption.

Messages are built here and encrypted with cryptography's AESCCM using a
nonce assembled independently of the module under test (security flags,
counter LE32, sender node ID LE64), so a nonce or AAD mistake in the
decoder fails the MIC instead of round-tripping.
"""

import os
import shutil
import struct
import tempfile
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESCCM

from cirque.capabilities.pcapcapability import (
    DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    DLT_EN10MB,
    PcapWriter,
)
from cirque.pcap import flow_visualizer as fv
from cirque.protocols.matter import session as ms

I2R_KEY = bytes.fromhex('5eded244e5532b3cdc23409dbad052d2')
R2I_KEY = bytes.fromhex('a9e011b1737c6d4b70e4c0a2fe660476')
DEVICE_SID = 0x3039  # responder (device) session ID
CONTROLLER_SID = 0x10E1  # initiator (commissioner) session ID
KEYLOG_LINE = (
    f'MATTER_SESSION_KEYS v=1 type=PASE role=responder local_sid={DEVICE_SID}'
    # A device logs the PASE peer as a PAKE key ID; PASE nonces still use 0.
    f' peer_sid={CONTROLLER_SID} local_node=0000000000000000'
    f' peer_node=FFFFFFFB00000000 i2r={I2R_KEY.hex()} r2i={R2I_KEY.hex()}'
)
CASE_INIT_NODE = 0x2211CF9734962C6F
CASE_RESP_NODE = 0x0000000000000001
CASE_I2R = bytes(range(16))
CASE_R2I = bytes(range(16, 32))
CASE_KEYLOG_LINE = (
    'MATTER_SESSION_KEYS v=1 type=CASE role=responder local_sid=7 peer_sid=9'
    f' local_node={CASE_RESP_NODE:016X} peer_node={CASE_INIT_NODE:016X}'
    f' i2r={CASE_I2R.hex()} r2i={CASE_R2I.hex()}'
)
DATASET = bytes.fromhex(
    '0e080000000000010000000300000f35060004001fffe0020811111111222222220708'
    'fdde ad00beef0000051000112233445566778899aabbccddeeff030f4f70656e5468'
    '726561642d39336361010212340410490e0f1c75476e687f88c4bee6c5bb4c0c0402a0'
    'f7f8'.replace(' ', '')
)


# Minimal Matter TLV encoder (Matter Core spec Appendix A).
def _tag(tag):
  return (0x00, b'') if tag is None else (0x20, bytes([tag]))


def tlv_uint(tag, value):
  ctl, t = _tag(tag)
  if value < 0x100:
    return bytes([ctl | 0x04]) + t + struct.pack('<B', value)
  if value < 0x10000:
    return bytes([ctl | 0x05]) + t + struct.pack('<H', value)
  return bytes([ctl | 0x06]) + t + struct.pack('<I', value)


def tlv_bytes(tag, value):
  ctl, t = _tag(tag)
  return bytes([ctl | 0x10]) + t + bytes([len(value)]) + value


def tlv_bool(tag, value):
  ctl, t = _tag(tag)
  return bytes([ctl | (0x09 if value else 0x08)]) + t


def tlv_container(tag, kind, *members):
  ctl, t = _tag(tag)
  etype = {'struct': 0x15, 'array': 0x16, 'list': 0x17}[kind]
  return bytes([ctl | etype]) + t + b''.join(members) + b'\x18'


def invoke_request(endpoint, cluster, command, fields):
  return tlv_container(
      None, 'struct',
      tlv_bool(0, False),
      tlv_bool(1, False),
      tlv_container(2, 'array', tlv_container(
          None, 'struct',
          tlv_container(0, 'list', tlv_uint(0, endpoint), tlv_uint(1, cluster),
                        tlv_uint(2, command)),
          tlv_container(1, 'struct', *fields),
      )),
      tlv_uint(0xFF, 12),  # InteractionModelRevision
  )


def invoke_response(endpoint, cluster, command, fields):
  return tlv_container(
      None, 'struct',
      tlv_bool(0, False),
      tlv_container(1, 'array', tlv_container(
          None, 'struct',
          tlv_container(0, 'struct',
                        tlv_container(0, 'list', tlv_uint(0, endpoint),
                                      tlv_uint(1, cluster),
                                      tlv_uint(2, command)),
                        tlv_container(1, 'struct', *fields)),
      )),
      tlv_uint(0xFF, 12),
  )


def protocol_header(opcode, exchange_id, protocol_id=1, initiator=True,
                    ack=None):
  flags = (0x01 if initiator else 0) | (0x02 if ack is not None else 0)
  out = struct.pack('<BBHH', flags, opcode, exchange_id, protocol_id)
  if ack is not None:
    out += struct.pack('<I', ack)
  return out


def message_header(session_id, counter, src_node=None):
  flags = 0x04 if src_node is not None else 0x00
  out = struct.pack('<BHBI', flags, session_id, 0x00, counter)
  if src_node is not None:
    out += struct.pack('<Q', src_node)
  return out


def encrypt(header, plaintext, key, nonce_node):
  nonce = bytes([header[3]]) + header[4:8] + struct.pack('<Q', nonce_node)
  return header + AESCCM(key, tag_length=16).encrypt(nonce, plaintext, header)


def thread_request_message(counter=1001, key=I2R_KEY):
  body = invoke_request(0, 0x31, 0x03, [tlv_bytes(0, DATASET),
                                        tlv_uint(1, 7)])
  plain = protocol_header(0x08, 0x4242) + body
  return encrypt(message_header(DEVICE_SID, counter), plain, key, 0)


def thread_response_message(counter=2001):
  body = invoke_response(0, 0x31, 0x05, [tlv_uint(0, 0)])
  plain = protocol_header(0x09, 0x4242, initiator=False, ack=1001) + body
  return encrypt(message_header(CONTROLLER_SID, counter), plain, R2I_KEY, 0)


class KnownAnswerTest(unittest.TestCase):

  def setUp(self):
    self.keyring = ms.MatterKeyring(ms.parse_session_keylog(KEYLOG_LINE))

  def test_invoke_request_is_decrypted_and_named(self):
    msg = ms.decrypt_message(thread_request_message(), self.keyring)
    self.assertIsNotNone(msg)
    self.assertEqual(msg['direction'], 'I2R')
    self.assertEqual(msg['message_counter'], 1001)
    proto = ms.parse_protocol_header(msg['plaintext'])
    self.assertEqual((proto['protocol_id'], proto['opcode']), (1, 0x08))
    desc = ms.describe_message(proto)
    self.assertEqual(
        desc['name'],
        'InvokeRequest NetworkCommissioning(0x31)'
        ' AddOrUpdateThreadNetwork(0x03)',
    )
    self.assertEqual(desc['commands'],
                     [{'endpoint': 0, 'cluster': 0x31, 'command': 0x03}])

  def test_invoke_response_uses_r2i_key(self):
    msg = ms.decrypt_message(thread_response_message(), self.keyring)
    self.assertEqual(msg['direction'], 'R2I')
    desc = ms.describe_message(ms.parse_protocol_header(msg['plaintext']))
    self.assertEqual(
        desc['name'],
        'InvokeResponse NetworkCommissioning(0x31)'
        ' NetworkConfigResponse(0x05)',
    )

  def test_case_nonce_uses_sender_operational_node_id(self):
    keyring = ms.MatterKeyring(ms.parse_session_keylog(CASE_KEYLOG_LINE))
    body = invoke_request(1, 0x0006, 0x02, [])
    plain = protocol_header(0x08, 7) + body
    # Initiator -> responder: responder's session ID, initiator node ID.
    data = encrypt(message_header(7, 55), plain, CASE_I2R, CASE_INIT_NODE)
    msg = ms.decrypt_message(data, keyring)
    self.assertEqual(msg['nonce_node_id'], CASE_INIT_NODE)
    self.assertEqual(
        ms.describe_message(ms.parse_protocol_header(msg['plaintext']))['name'],
        'InvokeRequest OnOff(0x06) Toggle(0x02)',
    )
    # A zero node ID in the nonce must not verify for CASE.
    bad = encrypt(message_header(7, 56), plain, CASE_I2R, 0)
    self.assertIsNone(ms.decrypt_message(bad, keyring))

  def test_mic_failure_is_not_decoded(self):
    data = bytearray(thread_request_message())
    data[-1] ^= 0x01  # corrupt the MIC
    self.assertIsNone(ms.decrypt_message(bytes(data), self.keyring))
    wrong_key = thread_request_message(key=bytes(16))
    self.assertIsNone(ms.decrypt_message(wrong_key, self.keyring))
    unknown_sid = bytearray(thread_request_message())
    unknown_sid[1:3] = struct.pack('<H', 0x7777)
    self.assertIsNone(ms.decrypt_message(bytes(unknown_sid), self.keyring))


class KeylogTest(unittest.TestCase):

  def test_parse_and_write_keylog(self):
    text = '\n'.join([
        'garbage line',
        KEYLOG_LINE,
        KEYLOG_LINE,  # duplicate
        'MATTER_SESSION_KEYS v=1 type=PASE role=responder local_sid=1',
        CASE_KEYLOG_LINE,
    ])
    sessions = ms.parse_session_keylog(text)
    self.assertEqual(len(sessions), 2)
    pase = sessions[0]
    self.assertEqual((pase.initiator_sid, pase.responder_sid),
                     (CONTROLLER_SID, DEVICE_SID))
    case = sessions[1]
    self.assertEqual((case.initiator_node, case.responder_node),
                     (CASE_INIT_NODE, CASE_RESP_NODE))
    out_dir = tempfile.mkdtemp(prefix='cirque_keylog_test_')
    try:
      path = ms.write_matter_session_key_file(out_dir, text)
      with open(path, encoding='utf-8') as f:
        content = f.read()
      self.assertIn('TEST-ONLY', content)
      key_lines = [l for l in content.splitlines()
                   if l.startswith('MATTER_SESSION_KEYS ')]
      self.assertEqual(len(key_lines), 2)
      self.assertEqual(len(ms.load_matter_session_key_file(out_dir).sessions),
                       2)
      with self.assertRaises(ValueError):
        ms.write_matter_session_key_file(out_dir, 'nothing here')
    finally:
      shutil.rmtree(out_dir, ignore_errors=True)


class BtpReassemblyTest(unittest.TestCase):

  def test_segments_reassemble_with_interleaved_acks(self):
    sdu = bytes(range(256)) * 2
    segments = ms.build_btp_segments(sdu, fragment_size=20, first_seq=1)
    self.assertGreater(len(segments), 20)
    r = ms.BtpReassembler()
    self.assertIsNone(r.feed('s', b'\x65\x6c\x04\x00'))  # handshake
    results = []
    for seg in segments:
      results.append(r.feed('s', seg))
      results.append(r.feed('other', b'\x08\x00\x00'))  # other stream ack
    self.assertEqual([x for x in results if x is not None], [sdu])

  def test_ack_flag_and_missing_begin(self):
    r = ms.BtpReassembler()
    # B|E with an ack number: flags, ack, seq, len16, payload.
    self.assertEqual(r.feed('s', b'\x0d\x05\x00\x03\x00abc'), b'abc')
    # Continuation without a beginning segment is dropped.
    self.assertIsNone(r.feed('t', b'\x04\x00xyz'))

  def test_sequence_gap_drops_partial_message(self):
    segments = ms.build_btp_segments(b'x' * 60, fragment_size=20)
    r = ms.BtpReassembler()
    self.assertIsNone(r.feed('s', segments[0]))
    # Skip segments[1]: the end segment must not yield a short message.
    self.assertIsNone(r.feed('s', segments[-1]))


def _ll_frame(payload, central_to_peripheral, aa=0x50655A3C):
  flags = 0x0D13 if central_to_peripheral else 0x0D93
  pdu = bytes([0x02, len(payload)]) + payload + b'\x00\x00\x00'
  return (struct.pack('<bbbBIH', 37, -40, -90, 0, aa, flags)
          + struct.pack('<I', aa) + pdu)


def _att(opcode, handle, value):
  att = bytes([opcode]) + struct.pack('<H', handle) + value
  return struct.pack('<HH', len(att), 4) + att


C1, C2 = 0x0010, 0x0012


class BtpCaptureTest(unittest.TestCase):

  def setUp(self):
    self.temp_dir = tempfile.mkdtemp(prefix='cirque_btp_test_')

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def write_capture(self, key_lines=None):
    writer = PcapWriter(os.path.join(self.temp_dir, 'bt_medium.pcap'),
                        dlt=DLT_BLUETOOTH_LE_LL_WITH_PHDR)
    ts = 100.0
    frames = [
        _ll_frame(_att(0x12, C1, b'\x65\x6c\x04\x00\x00\x00\xf4\x00\x06'),
                  True),
        _ll_frame(_att(0x1D, C2, b'\x65\x6c\x04\xf4\x00\x06'), False),
    ]
    for seg in ms.build_btp_segments(thread_request_message(), 30, 0):
      frames.append(_ll_frame(_att(0x52, C1, seg), True))
    for seg in ms.build_btp_segments(thread_response_message(), 30, 0):
      frames.append(_ll_frame(_att(0x1D, C2, seg), False))
    for frame in frames:
      writer.write_frame(frame, ts=ts)
      ts += 0.01
    writer.close()
    if key_lines:
      ms.write_matter_session_key_file(self.temp_dir, '\n'.join(key_lines))
    return fv.dissect_pcap_directory(self.temp_dir)

  def test_decrypted_wire_events(self):
    events = self.write_capture([KEYLOG_LINE])
    matter = [e for e in events if e.layer == 'MATTER']
    self.assertEqual(
        [e.title for e in matter],
        [
            'InvokeRequest NetworkCommissioning(0x31)'
            ' AddOrUpdateThreadNetwork(0x03)',
            'InvokeResponse NetworkCommissioning(0x31)'
            ' NetworkConfigResponse(0x05)',
        ],
    )
    req = matter[0]
    self.assertTrue(req.details['decrypted'])
    self.assertEqual(req.details['evidence'], 'wire')
    self.assertEqual(req.details['matter_command'], 'AddOrUpdateThreadNetwork')
    self.assertEqual(req.stage, 'THREAD_PROVISIONED')
    self.assertGreater(len(req.details['btp_segments']), 1)
    self.assertIn(DATASET.hex(), req.payload_hex)

  def test_no_key_file_leaves_capture_unchanged(self):
    events = self.write_capture()
    self.assertFalse([e for e in events if e.layer == 'MATTER'])
    self.assertFalse([e for e in events if e.details.get('decrypted')])

  def test_wrong_key_leaves_frames_undecoded(self):
    wrong = KEYLOG_LINE.replace(I2R_KEY.hex(), '00' * 16).replace(
        R2I_KEY.hex(), '11' * 16)
    events = self.write_capture([wrong])
    self.assertFalse([e for e in events if e.layer == 'MATTER'])


class UdpCaptureTest(unittest.TestCase):

  def test_case_udp_message_is_decrypted(self):
    temp_dir = tempfile.mkdtemp(prefix='cirque_udp_test_')
    try:
      plain = protocol_header(0x08, 9) + invoke_request(1, 0x0006, 0x02, [])
      matter = encrypt(message_header(7, 77), plain, CASE_I2R, CASE_INIT_NODE)
      udp = struct.pack('>HHHH', 5541, 5540, 8 + len(matter), 0) + matter
      ip6 = (struct.pack('>IHBB', 0x60000000, len(udp), 17, 64)
             + bytes.fromhex('fd110022' + '00' * 11 + '03')
             + bytes.fromhex('fddead00beef' + '00' * 9 + '01'))
      frame = b'\x02' * 6 + b'\x04' * 6 + b'\x86\xdd' + ip6 + udp
      writer = PcapWriter(os.path.join(temp_dir, 'wifi_ap.pcap'),
                          dlt=DLT_EN10MB)
      writer.write_frame(frame, ts=50.0)
      writer.close()
      before = fv.dissect_pcap_directory(temp_dir)
      self.assertEqual(before[0].sublayer, 'UDP')
      ms.write_matter_session_key_file(temp_dir, CASE_KEYLOG_LINE)
      (event,) = fv.dissect_pcap_directory(temp_dir)
      self.assertEqual(event.layer, 'MATTER')
      self.assertEqual(event.title, 'InvokeRequest OnOff(0x06) Toggle(0x02)')
      self.assertTrue(event.details['decrypted'])
      self.assertEqual(event.details['matter_session_type'], 'CASE')
    finally:
      shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == '__main__':
  unittest.main()
