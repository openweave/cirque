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
"""Thread network key files for decrypting simulated 802.15.4 captures.

A test writes the active operational dataset of its simulated Thread network
next to the thread_<petition>.pcap captures:
  - thread_network_key.txt: key=value lines (network key, PAN ID, extended
    PAN ID, channel, mesh-local prefix, active dataset TLVs) plus the tshark
    command that decrypts the captures;
  - ieee802154_keys: a Wireshark UAT file for the IEEE 802.15.4 decryption
    keys table, ready to drop into a Wireshark profile directory.
The flow visualizer reads thread_network_key.txt to decrypt the captures.
"""

import hashlib
import hmac
import ipaddress
import os
import re
from typing import Any, Dict, Optional, Tuple

THREAD_KEY_FILE = 'thread_network_key.txt'
WIRESHARK_KEYS_FILE = 'ieee802154_keys'
DEFAULT_OT_NETWORK_KEY = '00112233445566778899aabbccddeeff'
DEFAULT_OT_DATASET_TLVS_HEX = (
    '0e080000000000010000000300000d35060004001fffe00208dead00beef00cafe'
    '0708fd01234567890abc051000112233445566778899aabbccddeeff030a4f7065'
    '6e546872656164010212340410ad463152f9622c7297ec6c6c543a63e70c0302a0ff'
)

# MeshCoP TLV types used in an Active Operational Dataset.
_TLV_CHANNEL = 0
_TLV_PAN_ID = 1
_TLV_EXT_PAN_ID = 2
_TLV_NETWORK_NAME = 3
_TLV_NETWORK_KEY = 5
_TLV_MESH_LOCAL_PREFIX = 7

_HEADER = """\
# Thread network key material of a Cirque SIMULATED Thread network.
# TEST-ONLY credentials: this network exists only inside one virtual test
# run; the key protects nothing outside it.
"""


def parse_ot_ctl_output(raw_output: str) -> Dict[str, Any]:
  """Extracts dataset_tlvs_hex or network_key fields from ot-ctl output."""
  result: Dict[str, Any] = {}
  if not raw_output:
    return result
  for raw_line in raw_output.splitlines():
    line = raw_line.strip()
    if not line or line == 'Done' or line.startswith('Error'):
      continue
    if re.fullmatch(r'[0-9a-fA-F]{32}', line):
      result.setdefault('network_key', line.lower())
    elif len(line) >= 34 and len(line) % 2 == 0 and re.fullmatch(
        r'[0-9a-fA-F]+', line
    ):
      fields = parse_dataset_tlvs(line)
      if fields.get('network_key'):
        result['dataset_tlvs_hex'] = line.lower()
        result.update(fields)
    elif ':' in line:
      k, v = line.split(':', 1)
      k_low = k.strip().lower()
      v_clean = v.strip()
      if k_low in ('network key', 'master key') and re.fullmatch(
          r'[0-9a-fA-F]{32}', v_clean
      ):
        result['network_key'] = v_clean.lower()
      elif k_low == 'pan id' and v_clean.startswith('0x'):
        try:
          result['pan_id'] = int(v_clean, 16)
        except ValueError:
          pass
      elif k_low == 'ext pan id' and re.fullmatch(r'[0-9a-fA-F]{16}', v_clean):
        result['ext_pan_id'] = v_clean.lower()
      elif k_low == 'channel':
        try:
          result['channel'] = int(v_clean)
        except ValueError:
          pass
  return result


def parse_dataset_tlvs(tlvs_hex: str) -> Dict[str, Any]:
  """Decodes the fields of an Active Operational Dataset TLV hex string."""
  try:
    data = bytes.fromhex(tlvs_hex or '')
  except ValueError:
    return {}
  fields: Dict[str, Any] = {}
  pos = 0
  while pos + 2 <= len(data):
    tlv_type, tlv_len = data[pos], data[pos + 1]
    value = data[pos + 2 : pos + 2 + tlv_len]
    pos += 2 + tlv_len
    if len(value) != tlv_len:
      break
    if tlv_type == _TLV_CHANNEL and tlv_len == 3:
      fields['channel'] = int.from_bytes(value[1:3], 'big')
    elif tlv_type == _TLV_PAN_ID and tlv_len == 2:
      fields['pan_id'] = int.from_bytes(value, 'big')
    elif tlv_type == _TLV_EXT_PAN_ID and tlv_len == 8:
      fields['ext_pan_id'] = value.hex()
    elif tlv_type == _TLV_NETWORK_NAME:
      fields['network_name'] = value.decode('utf-8', 'replace')
    elif tlv_type == _TLV_NETWORK_KEY and tlv_len == 16:
      fields['network_key'] = value.hex()
    elif tlv_type == _TLV_MESH_LOCAL_PREFIX and tlv_len == 8:
      fields['mesh_local_prefix'] = value.hex()
  return fields


def write_thread_key_files(
    out_dir: str,
    network_key: str = '',
    pan_id: Optional[int] = None,
    ext_pan_id: str = '',
    channel: Optional[int] = None,
    dataset_tlvs_hex: str = '',
) -> Tuple[str, str]:
  """Writes thread_network_key.txt and ieee802154_keys into `out_dir`.

  Fields decoded from `dataset_tlvs_hex` take precedence over the separate
  arguments, because the TLVs are what the border router actually runs.
  Returns the paths of both files.
  """
  fields = parse_dataset_tlvs(dataset_tlvs_hex)
  key = str(fields.get('network_key') or network_key).lower()
  if len(key) != 32 or any(c not in '0123456789abcdef' for c in key):
    raise ValueError(f'Invalid Thread network key: {key!r}')
  pan = fields.get('pan_id', pan_id)
  lines = [f'network_key={key}']
  if pan is not None:
    lines.append(f'pan_id=0x{int(pan):04x}')
  xpan = fields.get('ext_pan_id') or ext_pan_id
  if xpan:
    lines.append(f'ext_pan_id={xpan}')
  chan = fields.get('channel', channel)
  if chan is not None:
    lines.append(f'channel={int(chan)}')
  if 'network_name' in fields:
    lines.append(f'network_name={fields["network_name"]}')
  if 'mesh_local_prefix' in fields:
    prefix = format_mesh_local_prefix(
        bytes.fromhex(fields['mesh_local_prefix'])
    )
    lines.append(f'mesh_local_prefix={prefix}')
  if dataset_tlvs_hex:
    lines.append(f'active_dataset_tlvs={dataset_tlvs_hex.lower()}')
  uat_entry = f'"{key}","0","Thread hash"'
  usage = (
      '#\n'
      '# Decrypt the 802.15.4 captures (MAC, MLE, 6LoWPAN, UDP) with tshark:\n'
      f"#   tshark -r thread_<petition>.pcap -o 'uat:ieee802154_keys:"
      f"{uat_entry}'\n"
      f'# or copy {WIRESHARK_KEYS_FILE} into a Wireshark profile directory.\n'
  )
  os.makedirs(out_dir, exist_ok=True)
  key_path = os.path.join(out_dir, THREAD_KEY_FILE)
  with open(key_path, 'w', encoding='utf-8') as f:
    f.write(_HEADER + '\n'.join(lines) + '\n' + usage)
  uat_path = os.path.join(out_dir, WIRESHARK_KEYS_FILE)
  with open(uat_path, 'w', encoding='utf-8') as f:
    f.write(_HEADER + uat_entry + '\n')
  return key_path, uat_path


def load_thread_key_file(pcap_dir: str) -> Optional[Dict[str, Any]]:
  """Reads thread_network_key.txt from `pcap_dir`.

  Returns {'network_key': bytes, 'mesh_local_prefix': bytes or None}, or
  None when the file is missing or has no valid network key.
  """
  path = os.path.join(pcap_dir, THREAD_KEY_FILE)
  values: Dict[str, str] = {}
  try:
    with open(path, 'r', encoding='utf-8') as f:
      for line in f:
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
          name, value = line.split('=', 1)
          values[name.strip()] = value.strip()
  except OSError:
    return None
  try:
    key = bytes.fromhex(values.get('network_key', ''))
  except ValueError:
    return None
  if len(key) != 16:
    return None
  try:
    net = ipaddress.IPv6Network(values.get('mesh_local_prefix', ''))
    prefix = net.network_address.packed[:8]
  except ValueError:  # Missing or malformed: fall back to the dataset TLVs.
    prefix = None
  if prefix is None and values.get('active_dataset_tlvs'):
    tlv_prefix = parse_dataset_tlvs(values['active_dataset_tlvs']).get(
        'mesh_local_prefix'
    )
    prefix = bytes.fromhex(tlv_prefix) if tlv_prefix else None
  return {'network_key': key, 'mesh_local_prefix': prefix}


def derive_thread_keys(
    network_key: bytes, key_sequence: int
) -> Tuple[bytes, bytes]:
  """Returns (MLE key, MAC key) for `key_sequence` (Thread key derivation)."""
  digest = hmac.new(
      network_key,
      (key_sequence & 0xFFFFFFFF).to_bytes(4, 'big') + b'Thread',
      hashlib.sha256,
  ).digest()
  return digest[:16], digest[16:]


def format_mesh_local_prefix(prefix: Optional[bytes]) -> str:
  """Formats an 8-byte mesh-local prefix as an IPv6 /64."""
  if not prefix or len(prefix) != 8:
    return ''
  return f'{ipaddress.IPv6Address(prefix + bytes(8))}/64'
