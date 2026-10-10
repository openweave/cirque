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
"""Matter session key log, BTP reassembly and secure message decryption.

A Matter device built with the TEST-ONLY chip_enable_session_keylog GN arg
appends one line per activated PASE/CASE session to $CHIP_SESSION_KEYLOG_FILE
(format: connectedhomeip src/transport/SessionKeylog.h):

  MATTER_SESSION_KEYS v=1 type=PASE role=responder local_sid=12345
      peer_sid=4321 local_node=0000000000000000 peer_node=0000000000000000
      i2r=<32 hex> r2i=<32 hex>

A test copies that log next to its captures as matter_session_keys.txt (see
write_matter_session_key_file()). This module then
  - reassembles BTP SDUs from the ATT writes / indications of the Matter
    C1 / C2 characteristics (BtpReassembler),
  - decodes the Matter message header and decrypts the payload with
    AES-128-CCM (16-byte MIC). A message carries the receiver's session ID:
    a message for the responder's session ID was sent by the initiator and
    uses the I2R key, and vice versa. Nonce = security flags || counter
    LE32 || source node ID LE64, where the source node ID is 0 for PASE and
    the sender's operational node ID for CASE,
  - names the decrypted Interaction Model / Secure Channel message.
Nothing is named unless the MIC verifies; frames that fail stay undecoded.
"""

import dataclasses
import os
import re
import struct
from typing import Any, Dict, List, Optional, Tuple

try:  # AES-CCM comes from 'cryptography'; without it nothing is decrypted.
  from cryptography.exceptions import InvalidTag
  from cryptography.hazmat.primitives.ciphers.aead import AESCCM
except ImportError:  # pragma: no cover
  AESCCM = None
  InvalidTag = ValueError

MATTER_SESSION_KEY_FILE = 'matter_session_keys.txt'
MATTER_MIC_LENGTH = 16
_KEYLOG_PREFIX = 'MATTER_SESSION_KEYS'

_HEADER = """\
# Matter secure session keys of a Cirque SIMULATED test run, written by the
# device's TEST-ONLY session key log (chip_enable_session_keylog GN arg,
# CHIP_SESSION_KEYLOG_FILE). The sessions exist only inside one virtual test
# run; the keys protect nothing outside it.
#
# Line format: MATTER_SESSION_KEYS v=1 type=<PASE|CASE>
#   role=<initiator|responder> local_sid=<u16> peer_sid=<u16>
#   local_node=<16 hex> peer_node=<16 hex> i2r=<32 hex> r2i=<32 hex>
"""

# BTP header flags (connectedhomeip src/ble/BtpEngine.h; Matter Core spec
# BTP packet format). Handshake frames (H) carry a management opcode (M).
BTP_FLAG_BEGIN = 0x01
BTP_FLAG_CONTINUE = 0x02
BTP_FLAG_END = 0x04
BTP_FLAG_ACK = 0x08
BTP_FLAG_MANAGEMENT = 0x20
BTP_FLAG_HANDSHAKE = 0x40

PROTOCOL_SECURE_CHANNEL = 0x0000
PROTOCOL_INTERACTION_MODEL = 0x0001

SECURE_CHANNEL_OPCODES = {
    0x00: 'MsgCounterSyncReq',
    0x01: 'MsgCounterSyncRsp',
    0x10: 'StandaloneAck',
    0x20: 'PBKDFParamRequest',
    0x21: 'PBKDFParamResponse',
    0x22: 'PASE_Pake1',
    0x23: 'PASE_Pake2',
    0x24: 'PASE_Pake3',
    0x30: 'CASE_Sigma1',
    0x31: 'CASE_Sigma2',
    0x32: 'CASE_Sigma3',
    0x33: 'CASE_Sigma2Resume',
    0x40: 'StatusReport',
    0x50: 'ICD_CheckIn',
}
IM_OPCODES = {
    0x01: 'StatusResponse',
    0x02: 'ReadRequest',
    0x03: 'SubscribeRequest',
    0x04: 'SubscribeResponse',
    0x05: 'ReportData',
    0x06: 'WriteRequest',
    0x07: 'WriteResponse',
    0x08: 'InvokeRequest',
    0x09: 'InvokeResponse',
    0x0A: 'TimedRequest',
}
CLUSTER_NAMES = {
    0x0003: 'Identify',
    0x0004: 'Groups',
    0x0006: 'OnOff',
    0x0008: 'LevelControl',
    0x001D: 'Descriptor',
    0x001F: 'AccessControl',
    0x0028: 'BasicInformation',
    0x0029: 'OtaSoftwareUpdateProvider',
    0x002A: 'OtaSoftwareUpdateRequestor',
    0x0030: 'GeneralCommissioning',
    0x0031: 'NetworkCommissioning',
    0x0033: 'GeneralDiagnostics',
    0x0035: 'ThreadNetworkDiagnostics',
    0x0036: 'WiFiNetworkDiagnostics',
    0x0038: 'TimeSynchronization',
    0x003C: 'AdministratorCommissioning',
    0x003E: 'OperationalCredentials',
    0x003F: 'GroupKeyManagement',
    0x0046: 'IcdManagement',
}
# (cluster, command) -> name, requests and responses alike.
COMMAND_NAMES = {
    (0x0003, 0x00): 'Identify',
    (0x0003, 0x40): 'TriggerEffect',
    (0x0006, 0x00): 'Off',
    (0x0006, 0x01): 'On',
    (0x0006, 0x02): 'Toggle',
    (0x0030, 0x00): 'ArmFailSafe',
    (0x0030, 0x01): 'ArmFailSafeResponse',
    (0x0030, 0x02): 'SetRegulatoryConfig',
    (0x0030, 0x03): 'SetRegulatoryConfigResponse',
    (0x0030, 0x04): 'CommissioningComplete',
    (0x0030, 0x05): 'CommissioningCompleteResponse',
    (0x0031, 0x00): 'ScanNetworks',
    (0x0031, 0x01): 'ScanNetworksResponse',
    (0x0031, 0x02): 'AddOrUpdateWiFiNetwork',
    (0x0031, 0x03): 'AddOrUpdateThreadNetwork',
    (0x0031, 0x04): 'RemoveNetwork',
    (0x0031, 0x05): 'NetworkConfigResponse',
    (0x0031, 0x06): 'ConnectNetwork',
    (0x0031, 0x07): 'ConnectNetworkResponse',
    (0x0031, 0x08): 'ReorderNetwork',
    (0x003C, 0x00): 'OpenCommissioningWindow',
    (0x003C, 0x02): 'RevokeCommissioning',
    (0x003E, 0x00): 'AttestationRequest',
    (0x003E, 0x01): 'AttestationResponse',
    (0x003E, 0x02): 'CertificateChainRequest',
    (0x003E, 0x03): 'CertificateChainResponse',
    (0x003E, 0x04): 'CSRRequest',
    (0x003E, 0x05): 'CSRResponse',
    (0x003E, 0x06): 'AddNOC',
    (0x003E, 0x07): 'UpdateNOC',
    (0x003E, 0x08): 'NOCResponse',
    (0x003E, 0x09): 'UpdateFabricLabel',
    (0x003E, 0x0A): 'RemoveFabric',
    (0x003E, 0x0B): 'AddTrustedRootCertificate',
}


# -----------------------------------------------------------------------------
# Session key log
# -----------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class SessionKeys:
  """Keys of one secure session, as logged by one of its two peers."""

  session_type: str  # 'PASE' or 'CASE'
  role: str  # role of the logging node: 'initiator' or 'responder'
  local_sid: int
  peer_sid: int
  local_node: int
  peer_node: int
  i2r: bytes
  r2i: bytes

  @property
  def initiator_sid(self) -> int:
    return self.local_sid if self.role == 'initiator' else self.peer_sid

  @property
  def responder_sid(self) -> int:
    return self.peer_sid if self.role == 'initiator' else self.local_sid

  @property
  def initiator_node(self) -> int:
    return self.local_node if self.role == 'initiator' else self.peer_node

  @property
  def responder_node(self) -> int:
    return self.peer_node if self.role == 'initiator' else self.local_node

  def nonce_node(self, direction: str) -> int:
    """Source node ID in the nonce of messages sent in `direction`.

    PASE messages use the unspecified node ID (0) in both directions; the
    PASE peer node ID a device logs is a PAKE key ID (e.g.
    FFFFFFFB00000000), not a nonce input. CASE messages use the sender's
    operational node ID.
    """
    if self.session_type == 'PASE':
      return 0
    return self.initiator_node if direction == 'I2R' else self.responder_node


_KEYLOG_FIELD_RE = re.compile(r'(\w+)=(\S+)')


def parse_session_keylog(text: str) -> List[SessionKeys]:
  """Parses MATTER_SESSION_KEYS lines; other and malformed lines are skipped."""
  sessions: List[SessionKeys] = []
  for raw in (text or '').splitlines():
    line = raw.strip()
    if not line.startswith(_KEYLOG_PREFIX + ' '):
      continue
    fields = dict(_KEYLOG_FIELD_RE.findall(line))
    try:
      entry = SessionKeys(
          session_type=fields['type'],
          role=fields['role'],
          local_sid=int(fields['local_sid']),
          peer_sid=int(fields['peer_sid']),
          local_node=int(fields['local_node'], 16),
          peer_node=int(fields['peer_node'], 16),
          i2r=bytes.fromhex(fields['i2r']),
          r2i=bytes.fromhex(fields['r2i']),
      )
    except (KeyError, ValueError):
      continue
    if (
        fields.get('v') != '1'
        or entry.role not in ('initiator', 'responder')
        or len(entry.i2r) != 16
        or len(entry.r2i) != 16
    ):
      continue
    if entry not in sessions:
      sessions.append(entry)
  return sessions


def write_matter_session_key_file(out_dir: str, keylog_text: str) -> str:
  """Writes the valid key lines of a device keylog to matter_session_keys.txt.

  Returns the file path. Raises ValueError if the log holds no valid line.
  """
  lines = [
      raw.strip()
      for raw in (keylog_text or '').splitlines()
      if parse_session_keylog(raw)
  ]
  if not lines:
    raise ValueError('no MATTER_SESSION_KEYS lines in the session keylog')
  path = os.path.join(out_dir, MATTER_SESSION_KEY_FILE)
  with open(path, 'w', encoding='utf-8') as f:
    f.write(_HEADER)
    f.write('\n'.join(dict.fromkeys(lines)) + '\n')
  return path


class MatterKeyring:
  """Session keys indexed by the session ID that messages carry."""

  def __init__(self, sessions: List[SessionKeys]):
    self.sessions = list(sessions)
    # session id -> [(key, nonce node id, direction, session)]
    self._by_sid: Dict[int, List[Tuple[bytes, int, str, SessionKeys]]] = {}
    for s in self.sessions:
      self._by_sid.setdefault(s.responder_sid, []).append(
          (s.i2r, s.nonce_node('I2R'), 'I2R', s)
      )
      self._by_sid.setdefault(s.initiator_sid, []).append(
          (s.r2i, s.nonce_node('R2I'), 'R2I', s)
      )

  def __bool__(self) -> bool:
    return bool(self.sessions)

  def candidates(
      self, session_id: int
  ) -> List[Tuple[bytes, int, str, SessionKeys]]:
    return list(self._by_sid.get(session_id, ()))


def load_matter_session_key_file(pcap_dir: str) -> Optional[MatterKeyring]:
  """Loads matter_session_keys.txt from `pcap_dir`; None if absent or empty."""
  path = os.path.join(pcap_dir, MATTER_SESSION_KEY_FILE)
  try:
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
      sessions = parse_session_keylog(f.read())
  except OSError:
    return None
  return MatterKeyring(sessions) if sessions else None


# -----------------------------------------------------------------------------
# BTP reassembly
# -----------------------------------------------------------------------------


class BtpReassembler:
  """Reassembles BTP SDUs per stream (one stream per connection direction).

  feed() returns the SDU when an ending segment completes a message whose
  beginning segment was seen, else None. Handshake frames reset the stream.
  A segment whose sequence number does not follow the previous one drops the
  partial message.
  """

  def __init__(self):
    self._partial: Dict[Any, Dict[str, Any]] = {}
    self._last_seq: Dict[Any, int] = {}

  def feed(self, stream: Any, segment: bytes) -> Optional[bytes]:
    if not segment:
      return None
    flags = segment[0]
    if flags & BTP_FLAG_HANDSHAKE:
      self._partial.pop(stream, None)
      self._last_seq.pop(stream, None)
      return None
    pos = 1
    if flags & BTP_FLAG_MANAGEMENT:
      pos += 1
    if flags & BTP_FLAG_ACK:
      pos += 1
    if len(segment) < pos + 1:
      return None
    seq = segment[pos]
    pos += 1
    last = self._last_seq.get(stream)
    self._last_seq[stream] = seq
    if last is not None and seq != (last + 1) & 0xFF:
      self._partial.pop(stream, None)
    if not flags & (BTP_FLAG_BEGIN | BTP_FLAG_CONTINUE | BTP_FLAG_END):
      return None  # Stand-alone acknowledgement.
    if flags & BTP_FLAG_BEGIN:
      if len(segment) < pos + 2:
        self._partial.pop(stream, None)
        return None
      length = struct.unpack_from('<H', segment, pos)[0]
      pos += 2
      self._partial[stream] = {'length': length, 'data': bytearray()}
    partial = self._partial.get(stream)
    if partial is None:
      return None  # Missed the beginning segment.
    partial['data'] += segment[pos:]
    if not flags & BTP_FLAG_END:
      return None
    del self._partial[stream]
    if len(partial['data']) < partial['length']:
      return None
    return bytes(partial['data'][: partial['length']])


def build_btp_segments(sdu: bytes, fragment_size: int, first_seq: int = 0):
  """Splits `sdu` into BTP data segments (no acks); used by tests."""
  segments = []
  seq = first_seq
  pos = 0
  first = True
  while first or pos < len(sdu):
    if first:
      head = bytes([0, seq & 0xFF]) + struct.pack('<H', len(sdu))
    else:
      head = bytes([0, seq & 0xFF])
    room = max(1, fragment_size - len(head))
    chunk = sdu[pos : pos + room]
    pos += len(chunk)
    flags = (BTP_FLAG_BEGIN if first else BTP_FLAG_CONTINUE) | (
        BTP_FLAG_END if pos >= len(sdu) else 0
    )
    if not first and flags & BTP_FLAG_END:
      flags &= ~BTP_FLAG_CONTINUE
    segments.append(bytes([flags]) + head[1:] + chunk)
    seq += 1
    first = False
  return segments


# -----------------------------------------------------------------------------
# Matter message header and decryption
# -----------------------------------------------------------------------------


def parse_message_header(data: bytes) -> Optional[Dict[str, Any]]:
  """Decodes a version-0 Matter message header (Matter Core spec 4.4).

  Returns None for other versions, reserved DSIZ values, privacy-obfuscated
  headers and truncated input.
  """
  if len(data) < 8:
    return None
  flags, session_id, sec_flags, counter = struct.unpack_from('<BHBI', data)
  if flags >> 4 or flags & 0x03 == 0x03 or sec_flags & 0x80:
    return None
  info: Dict[str, Any] = {
      'message_flags': flags,
      'session_id': session_id,
      'security_flags': sec_flags,
      'message_counter': counter,
      'session_type': sec_flags & 0x03,
  }
  pos = 8
  try:
    if flags & 0x04:
      info['src_node_id'] = struct.unpack_from('<Q', data, pos)[0]
      pos += 8
    if flags & 0x03 == 1:
      info['dst_node_id'] = struct.unpack_from('<Q', data, pos)[0]
      pos += 8
    elif flags & 0x03 == 2:
      info['dst_group_id'] = struct.unpack_from('<H', data, pos)[0]
      pos += 2
    if sec_flags & 0x20:  # Message extensions
      pos += 2 + struct.unpack_from('<H', data, pos)[0]
  except struct.error:
    return None
  if pos > len(data):
    return None
  info['header_length'] = pos
  return info


def parse_protocol_header(payload: bytes) -> Optional[Dict[str, Any]]:
  """Decodes the (decrypted) exchange / protocol header."""
  try:
    ex_flags, opcode, exchange_id = struct.unpack_from('<BBH', payload)
    pos = 4
    vendor_id = 0
    if ex_flags & 0x10:
      vendor_id = struct.unpack_from('<H', payload, pos)[0]
      pos += 2
    protocol_id = struct.unpack_from('<H', payload, pos)[0]
    pos += 2
    info: Dict[str, Any] = {
        'exchange_flags': ex_flags,
        'opcode': opcode,
        'exchange_id': exchange_id,
        'protocol_id': protocol_id,
        'vendor_id': vendor_id,
        'initiator': bool(ex_flags & 0x01),
    }
    if ex_flags & 0x02:
      info['ack_counter'] = struct.unpack_from('<I', payload, pos)[0]
      pos += 4
    if ex_flags & 0x08:  # Secured extensions
      pos += 2 + struct.unpack_from('<H', payload, pos)[0]
  except struct.error:
    return None
  if pos > len(payload):
    return None
  info['app_payload'] = payload[pos:]
  return info


def ccm_nonce(security_flags: int, counter: int, node_id: int) -> bytes:
  return struct.pack('<BIQ', security_flags, counter, node_id)


def decrypt_message(
    data: bytes, keyring: Optional[MatterKeyring]
) -> Optional[Dict[str, Any]]:
  """Decrypts a unicast Matter message with the matching session key.

  Returns the header fields plus 'plaintext', 'direction' ('I2R' / 'R2I'),
  'session' (SessionKeys) and 'nonce_node_id', or None if no key verifies
  the MIC (or the message is not a secured unicast message).
  """
  if AESCCM is None or not keyring:
    return None
  header = parse_message_header(data)
  if header is None or header['session_id'] == 0 or header['session_type']:
    return None
  hlen = header['header_length']
  if len(data) < hlen + MATTER_MIC_LENGTH:
    return None
  aad, ciphertext = data[:hlen], data[hlen:]
  for key, sender_node, direction, session in keyring.candidates(
      header['session_id']
  ):
    nodes = [sender_node]
    if header.get('src_node_id') not in (None, sender_node):
      nodes.append(header['src_node_id'])
    for node in nodes:
      nonce = ccm_nonce(
          header['security_flags'], header['message_counter'], node
      )
      try:
        plaintext = AESCCM(key, tag_length=MATTER_MIC_LENGTH).decrypt(
            nonce, ciphertext, aad
        )
      except InvalidTag:
        continue
      result = dict(header)
      result.update(
          plaintext=plaintext,
          direction=direction,
          session=session,
          nonce_node_id=node,
      )
      return result
  return None


# -----------------------------------------------------------------------------
# Matter TLV and Interaction Model naming
# -----------------------------------------------------------------------------

_TLV_INT_SIZES = {0: 1, 1: 2, 2: 4, 3: 8}
_TLV_TAG_SIZES = {0: 0, 1: 1, 2: 2, 3: 4, 4: 2, 5: 4, 6: 6, 7: 8}
_END_OF_CONTAINER = object()


class TlvError(ValueError):
  pass


def _read_tlv(data: bytes, pos: int) -> Tuple[Any, Any, int]:
  """Reads one element at `pos`; returns (tag, value, next position)."""
  if pos >= len(data):
    raise TlvError('truncated TLV')
  control = data[pos]
  pos += 1
  tag_size = _TLV_TAG_SIZES[control >> 5]
  if pos + tag_size > len(data):
    raise TlvError('truncated TLV tag')
  tag: Any = None
  if control >> 5 == 1:
    tag = data[pos]
  elif tag_size:
    tag = ('profile', data[pos : pos + tag_size].hex())
  pos += tag_size
  etype = control & 0x1F
  if etype == 0x18:
    return tag, _END_OF_CONTAINER, pos
  if etype <= 0x07:
    size = _TLV_INT_SIZES[etype & 0x03]
    if pos + size > len(data):
      raise TlvError('truncated TLV integer')
    value = int.from_bytes(
        data[pos : pos + size], 'little', signed=etype <= 0x03
    )
    return tag, value, pos + size
  if etype in (0x08, 0x09):
    return tag, etype == 0x09, pos
  if etype == 0x0A:
    return tag, struct.unpack_from('<f', data, pos)[0], pos + 4
  if etype == 0x0B:
    return tag, struct.unpack_from('<d', data, pos)[0], pos + 8
  if 0x0C <= etype <= 0x13:
    size = _TLV_INT_SIZES[etype & 0x03]
    if pos + size > len(data):
      raise TlvError('truncated TLV length')
    length = int.from_bytes(data[pos : pos + size], 'little')
    pos += size
    if pos + length > len(data):
      raise TlvError('truncated TLV string')
    raw = data[pos : pos + length]
    value = raw.decode('utf-8', 'replace') if etype <= 0x0F else bytes(raw)
    return tag, value, pos + length
  if etype == 0x14:
    return tag, None, pos
  if etype in (0x15, 0x16, 0x17):
    items: List[Tuple[Any, Any]] = []
    while True:
      sub_tag, sub_value, pos = _read_tlv(data, pos)
      if sub_value is _END_OF_CONTAINER:
        return tag, items, pos
      items.append((sub_tag, sub_value))
  raise TlvError(f'unknown TLV element type 0x{etype:02x}')


def decode_tlv(data: bytes) -> Any:
  """Decodes one TLV element; containers become [(tag, value), ...]."""
  _, value, _ = _read_tlv(data, 0)
  return value


def _field(container: Any, tag: int, default: Any = None) -> Any:
  if isinstance(container, list):
    for item_tag, value in container:
      if item_tag == tag:
        return value
  return default


def cluster_label(cluster_id: Optional[int]) -> str:
  if cluster_id is None:
    return '*'
  name = CLUSTER_NAMES.get(cluster_id, 'Cluster')
  return f'{name}(0x{cluster_id:02x})'


def command_label(cluster_id: Optional[int], command_id: Optional[int]) -> str:
  if command_id is None:
    return '*'
  name = COMMAND_NAMES.get((cluster_id, command_id), 'Command')
  return f'{name}(0x{command_id:02x})'


def _command_paths(items: Any, data_tag: int) -> List[Dict[str, Any]]:
  """Extracts command paths of InvokeRequests / InvokeResponses items."""
  paths = []
  for item in _items(items):
    data_ib = _field(item, data_tag) if data_tag is not None else item
    status_ib = None
    if data_tag is not None and data_ib is None:  # CommandStatusIB
      status_ib = _field(item, 1)
      data_ib = status_ib
    path = _field(data_ib, 0)
    if not isinstance(path, list):
      continue
    entry = {
        'endpoint': _field(path, 0),
        'cluster': _field(path, 1),
        'command': _field(path, 2),
    }
    if status_ib is not None:
      entry['status'] = _field(_field(status_ib, 1), 0)
    paths.append(entry)
  return paths


def _attribute_path(path: Any) -> Optional[Dict[str, Any]]:
  """AttributePathIB list -> endpoint / cluster / attribute."""
  if not isinstance(path, list):
    return None
  return {
      'endpoint': _field(path, 2),
      'cluster': _field(path, 3),
      'attribute': _field(path, 4),
  }


def _paths(found: List[Any]) -> List[Dict[str, Any]]:
  return [p for p in (_attribute_path(f) for f in found) if p is not None]


def _items(container: Any) -> List[Any]:
  return [v for _, v in container] if isinstance(container, list) else []


def _attribute_paths(items: Any) -> List[Dict[str, Any]]:
  """AttributeRequests of a Read/SubscribeRequest."""
  return _paths(_items(items))


def _report_paths(items: Any) -> List[Dict[str, Any]]:
  """AttributeReportIBs: AttributeData (1: Path) or AttributeStatus (0)."""
  found = []
  for report in _items(items):
    data_ib = _field(report, 1)
    if data_ib is not None:
      found.append(_field(data_ib, 1))
    else:
      found.append(_field(_field(report, 0), 0))
  return _paths(found)


def _write_paths(items: Any) -> List[Dict[str, Any]]:
  """AttributeDataIBs of a WriteRequest (1: Path)."""
  return _paths([_field(ib, 1) for ib in _items(items)])


def _attr_summary(paths: List[Dict[str, Any]]) -> str:
  if not paths:
    return ''
  first = paths[0]
  attr = first.get('attribute')
  text = (
      f' {cluster_label(first.get("cluster"))}'
      f' attr {"*" if attr is None else f"0x{attr:04x}"}'
  )
  if len(paths) > 1:
    text += f' +{len(paths) - 1}'
  return text


def describe_message(proto: Dict[str, Any]) -> Dict[str, Any]:
  """Names a decrypted message from its protocol header and payload.

  Returns 'name' (e.g. 'InvokeRequest NetworkCommissioning(0x31)
  AddOrUpdateThreadNetwork(0x03)'), 'protocol', 'opcode_name' and, for
  invokes, 'commands' (endpoint / cluster / command dicts).
  """
  protocol_id, opcode = proto['protocol_id'], proto['opcode']
  out: Dict[str, Any] = {}
  if protocol_id == PROTOCOL_SECURE_CHANNEL and proto['vendor_id'] == 0:
    op_name = SECURE_CHANNEL_OPCODES.get(opcode, f'0x{opcode:02x}')
    out.update(protocol='SecureChannel', opcode_name=op_name)
    out['name'] = f'SecureChannel:{op_name}'
    return out
  if protocol_id != PROTOCOL_INTERACTION_MODEL or proto['vendor_id'] != 0:
    out.update(protocol=f'0x{protocol_id:04x}', opcode_name=f'0x{opcode:02x}')
    out['name'] = f'Protocol 0x{protocol_id:04x}:0x{opcode:02x}'
    return out
  op_name = IM_OPCODES.get(opcode, f'0x{opcode:02x}')
  out.update(protocol='IM', opcode_name=op_name, name=op_name)
  try:
    body = decode_tlv(proto['app_payload'])
  except (TlvError, struct.error, KeyError):
    out['tlv_error'] = True
    return out
  if opcode in (0x08, 0x09):  # InvokeRequest / InvokeResponse
    if opcode == 0x08:
      commands = _command_paths(_field(body, 2), None)
    else:
      commands = _command_paths(_field(body, 1), 0)
    out['commands'] = commands
    if commands:
      first = commands[0]
      out['name'] = (
          f'{op_name} {cluster_label(first["cluster"])}'
          f' {command_label(first["cluster"], first["command"])}'
      )
      if 'status' in first:
        out['name'] += f' status=0x{first["status"] or 0:02x}'
      if len(commands) > 1:
        out['name'] += f' +{len(commands) - 1}'
  elif opcode in (0x02, 0x03):  # ReadRequest / SubscribeRequest
    out['attributes'] = _attribute_paths(_field(body, 0))
    out['name'] = op_name + _attr_summary(out['attributes'])
  elif opcode == 0x05:  # ReportData
    out['attributes'] = _report_paths(_field(body, 1))
    out['name'] = op_name + _attr_summary(out['attributes'])
  elif opcode == 0x06:  # WriteRequest
    out['attributes'] = _write_paths(_field(body, 2))
    out['name'] = op_name + _attr_summary(out['attributes'])
  elif opcode == 0x01:  # StatusResponse
    status = _field(body, 0)
    if isinstance(status, int):
      out['name'] = f'{op_name} status=0x{status:02x}'
  return out
