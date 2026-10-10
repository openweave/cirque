# Copyright (c) 2026 Project CHIP Authors
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
"""Matter ICD Check-In message oracles (Matter Core Specification 4.18).

Parses SecureChannel ICD_CheckIn (protocol 0x0000, opcode 0x50) messages
from Ethernet/IPv6 captures (for example wifi_medium.pcap) and from
Thread captures decrypted with the network key, using the generic readers
in cirque.pcap.oracles.
"""

import socket
import struct
from typing import Any, Dict, List, Optional

from cirque.pcap.oracles import (
    DLT_EN10MB,
    iter_pcap_records_with_ts,
    thread_decrypted_udp_frames,
)

__all__ = [
    'matter_icd_checkin_packets',
    'parse_matter_icd_checkin',
    'thread_icd_checkin_frames',
]


def parse_matter_icd_checkin(data: bytes) -> Optional[Dict[str, Any]]:
  """Parses one Matter UDP payload as SecureChannel::ICD_CheckIn (0x0000:0x50).

  Returns None unless the message is an unsecured-session message carrying
  the ICD_CheckIn opcode with a >= 35-byte Check-In payload.
  """
  if len(data) < 14:
    return None
  msg_flags = data[0]
  if ((msg_flags & 0xF0) >> 4) != 0:
    return None
  session_id = struct.unpack_from('<H', data, 1)[0]
  security_flags = data[3]
  # ICD Check-In uses an unauthenticated session
  # (session_id == 0, session_type == 0).
  if session_id != 0 or (security_flags & 0x03) != 0:
    return None
  msg_counter = struct.unpack_from('<I', data, 4)[0]
  idx = 8
  source_node_id = None
  if msg_flags & 0x04:
    if idx + 8 > len(data):
      return None
    source_node_id = struct.unpack_from('<Q', data, idx)[0]
    idx += 8
  dsiz = msg_flags & 0x03
  if dsiz == 1:
    idx += 8
  elif dsiz == 2:
    idx += 2
  elif dsiz == 3:
    return None
  if security_flags & 0x20:
    if idx + 2 > len(data):
      return None
    mx_len = struct.unpack_from('<H', data, idx)[0]
    idx += 2 + mx_len
  if idx + 6 > len(data):
    return None
  ex_flags = data[idx]
  opcode = data[idx + 1]
  exchange_id = struct.unpack_from('<H', data, idx + 2)[0]
  p_idx = idx + 4
  vendor_id = 0
  if ex_flags & 0x10:
    if p_idx + 2 > len(data):
      return None
    vendor_id = struct.unpack_from('<H', data, p_idx)[0]
    p_idx += 2
  if p_idx + 2 > len(data):
    return None
  protocol_id = struct.unpack_from('<H', data, p_idx)[0]
  p_idx += 2
  if ex_flags & 0x02:
    p_idx += 4
  if ex_flags & 0x20:
    if p_idx + 2 > len(data):
      return None
    sx_len = struct.unpack_from('<H', data, p_idx)[0]
    p_idx += 2 + sx_len
  if p_idx > len(data):
    return None
  app_payload = data[p_idx:]
  # SecureChannel protocol (0x0000:0x0000), ICD_CheckIn opcode (0x50),
  # >= 35-byte Check-In payload.
  if (
      vendor_id != 0x0000
      or protocol_id != 0x0000
      or opcode != 0x50
      or len(app_payload) < 35
  ):
    return None
  return {
      'msg_counter': msg_counter,
      'source_node_id': source_node_id,
      'exchange_id': exchange_id,
      'payload_len': len(app_payload),
      'nonce_hex': app_payload[:13].hex(),
  }


def matter_icd_checkin_packets(path: str) -> List[Dict[str, Any]]:
  """Returns ICD_CheckIn (0x0000:0x50) UDP/IPv6 packets on port 5540.

  Reads an Ethernet (DLT_EN10MB) capture such as wifi_medium.pcap.
  """
  checkins: List[Dict[str, Any]] = []
  for linktype, ts, frame in iter_pcap_records_with_ts(path):
    if linktype != DLT_EN10MB or len(frame) < 14 + 40 + 8:
      continue
    if frame[12:14] != b'\x86\xdd':
      continue
    ip6 = frame[14:]
    if (ip6[0] >> 4) != 6 or ip6[6] != 17:
      continue
    udp = ip6[40:]
    if len(udp) < 8:
      continue
    sport, dport, ulen = struct.unpack('!HHH', udp[:6])
    if 5540 not in (sport, dport):
      continue
    parsed = parse_matter_icd_checkin(udp[8:ulen] if ulen >= 8 else udp[8:])
    if parsed is None:
      continue
    parsed.update({
        'ts': ts,
        'src_ip': socket.inet_ntop(socket.AF_INET6, ip6[8:24]),
        'dst_ip': socket.inet_ntop(socket.AF_INET6, ip6[24:40]),
        'sport': sport,
        'dport': dport,
    })
    checkins.append(parsed)
  return checkins


def thread_icd_checkin_frames(
    path: str, network_key_hex: str
) -> List[Dict[str, Any]]:
  """Returns ICD_CheckIn (0x0000:0x50) messages carried over 802.15.4.

  Each entry has the radio fields (ts, src16, dst16, sec_level, sport,
  dport) plus the parsed Matter fields (msg_counter, source_node_id,
  exchange_id, payload_len, nonce_hex).
  """
  checkins: List[Dict[str, Any]] = []
  for frame in thread_decrypted_udp_frames(path, network_key_hex):
    if 5540 not in (frame['sport'], frame['dport']):
      continue
    parsed = parse_matter_icd_checkin(frame['payload'])
    if parsed is None:
      continue
    parsed.update({k: v for k, v in frame.items() if k != 'payload'})
    checkins.append(parsed)
  return checkins
