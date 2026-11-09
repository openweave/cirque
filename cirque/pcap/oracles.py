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
"""Raw-capture oracles over cirque pcap files.

Device log lines can be printed by the code under test whether or not the
underlying radio exchange happened. These helpers read the pcap files that
the cirque virtual Bluetooth / Wi-Fi / 802.15.4 servers write (and flush per
frame) into CIRQUE_PCAP_DIR, so a test can assert on frames that actually
crossed the virtual medium: HCI LE connections, DHCP leases, EAPOL, IEEE
802.15.4 MAC commands and acks, and Thread frames and MLE messages
decrypted with tshark and the Thread network key.

Application-protocol oracles built on these live under cirque/protocols
(for example cirque.protocols.matter.icd).
"""

import os
import shutil
import socket
import struct
import subprocess
import tempfile
from typing import Any, Dict, Iterator, List, Optional, Tuple

__all__ = [
    'DLT_BLUETOOTH_HCI_H4_WITH_PHDR',
    'DLT_EN10MB',
    'DLT_IEEE802_15_4',
    'DLT_IEEE802_15_4_NOFCS',
    'MLE_CMD_ADVERTISEMENT',
    'MLE_CMD_CHILD_ID_REQUEST',
    'MLE_CMD_CHILD_ID_RESPONSE',
    'MLE_CMD_CHILD_UPDATE_REQUEST',
    'MLE_CMD_CHILD_UPDATE_RESPONSE',
    'MLE_CMD_PARENT_REQUEST',
    'MLE_CMD_PARENT_RESPONSE',
    'acked_mac_commands',
    'dhcp_ack_addresses',
    'eapol_frame_count',
    'hci_le_connection_complete_handles',
    'ieee802154_ack_frames',
    'ieee802154_mac_command_frames',
    'iter_pcap_records',
    'iter_pcap_records_with_ts',
    'thread_decrypted_udp_frames',
    'thread_mle_frames',
]

DLT_EN10MB = 1
DLT_IEEE802_15_4 = 195
DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201
DLT_IEEE802_15_4_NOFCS = 230

_PCAP_MAGIC_LE = b'\xd4\xc3\xb2\xa1'
_PCAP_MAGIC_BE = b'\xa1\xb2\xc3\xd4'


def iter_pcap_records_with_ts(path: str) -> Iterator[Tuple[int, float, bytes]]:
  """Yields (linktype, ts_sec, frame_bytes) for each record of a pcap file."""
  with open(path, 'rb') as f:
    hdr = f.read(24)
    if len(hdr) < 24:
      return
    if hdr[:4] == _PCAP_MAGIC_LE:
      endian = '<'
    elif hdr[:4] == _PCAP_MAGIC_BE:
      endian = '>'
    else:
      raise ValueError(f'{path}: not a classic pcap file')
    linktype = struct.unpack(endian + 'I', hdr[20:24])[0]
    while True:
      rec = f.read(16)
      if len(rec) < 16:
        return
      ts_sec, ts_usec, incl_len, _ = struct.unpack(endian + 'IIII', rec)
      data = f.read(incl_len)
      if len(data) < incl_len:
        return
      yield linktype, float(ts_sec) + float(ts_usec) * 1e-6, data


def iter_pcap_records(path: str) -> Iterator[Tuple[int, bytes]]:
  """Yields (linktype, frame_bytes) for every record in a classic pcap file."""
  for linktype, _, data in iter_pcap_records_with_ts(path):
    yield linktype, data


def hci_le_connection_complete_handles(path: str) -> List[int]:
  """Returns handles of successful HCI LE (Enhanced) Connection Complete events.

  Expects DLT_BLUETOOTH_HCI_H4_WITH_PHDR records: 4-byte direction header,
  then the H4 packet (0x04 = HCI event).
  """
  handles = []
  for linktype, frame in iter_pcap_records(path):
    if linktype != DLT_BLUETOOTH_HCI_H4_WITH_PHDR or len(frame) < 9:
      continue
    h4 = frame[4:]
    if h4[0] != 0x04 or h4[1] != 0x3E:
      continue
    sub_event = h4[3]
    if sub_event not in (0x01, 0x0A):
      continue
    status = h4[4]
    if status != 0x00 or len(h4) < 7:
      continue
    handles.append((h4[5] | (h4[6] << 8)) & 0x0FFF)
  return handles


def _iter_udp_ipv4(frame: bytes) -> Iterator[Tuple[int, int, bytes]]:
  if len(frame) < 14 or frame[12:14] != b'\x08\x00':
    return
  ip = frame[14:]
  if len(ip) < 20 or (ip[0] >> 4) != 4 or ip[9] != 17:
    return
  ihl = (ip[0] & 0x0F) * 4
  udp = ip[ihl:]
  if len(udp) < 8:
    return
  sport, dport = struct.unpack('!HH', udp[:4])
  yield sport, dport, udp[8:]


def dhcp_ack_addresses(path: str) -> List[str]:
  """Returns yiaddr of every DHCPACK (option 53 == 5) sent server->client."""
  acks = []
  for linktype, frame in iter_pcap_records(path):
    if linktype != DLT_EN10MB:
      continue
    for sport, dport, payload in _iter_udp_ipv4(frame):
      if sport != 67 or dport != 68 or len(payload) < 240:
        continue
      if payload[236:240] != b'\x63\x82\x53\x63':
        continue
      opts = payload[240:]
      i = 0
      msg_type = None
      while i < len(opts) and opts[i] != 0xFF:
        if opts[i] == 0x00:
          i += 1
          continue
        if i + 1 >= len(opts):
          break
        code, length = opts[i], opts[i + 1]
        if code == 53 and length == 1 and i + 2 < len(opts):
          msg_type = opts[i + 2]
        i += 2 + length
      if msg_type == 5:
        acks.append(socket.inet_ntoa(payload[16:20]))
  return acks


def eapol_frame_count(path: str) -> int:
  """Counts Ethernet frames with EtherType 0x888E (EAPOL)."""
  return sum(
      1
      for linktype, frame in iter_pcap_records(path)
      if linktype == DLT_EN10MB
      and len(frame) >= 14
      and frame[12:14] == b'\x88\x8e'
  )


_TSHARK_FIELDS = (
    'frame.time_epoch',
    'wpan.src16',
    'wpan.dst16',
    'wpan.aux_sec.sec_level',
    'wpan.aux_sec.key_id_mode',
    'udp.srcport',
    'udp.dstport',
    'udp.payload',
)

# Thread MAC frames secured with a key derived from the network key use Key
# ID Mode 1. Mode 2 frames (for example MLE Discovery) use a fixed well-known
# key and decrypt without the network key, so they prove nothing about it.
_THREAD_NETWORK_KEY_ID_MODE = 1


def _first_field_int(value: str) -> Optional[int]:
  value = value.split(',')[0].strip()
  if not value:
    return None
  return int(value, 0)


def thread_decrypted_udp_frames(
    path: str, network_key_hex: str
) -> List[Dict[str, Any]]:
  """Returns MAC-secured 802.15.4 frames that tshark decrypts to UDP.

  Decrypts thread_<n>.pcap with the Thread network key ("Thread hash" key
  derivation) and decompresses 6LoWPAN. tshark runs with an empty
  configuration directory so that keys saved in the user's Wireshark profile
  cannot decrypt frames: a frame decrypts only if network_key_hex is the key
  the network used. Only frames secured with a network-key-derived MAC key
  (Key ID Mode 1) are returned; unsecured frames and Key ID Mode 2 frames
  (for example MLE Discovery) are skipped.

  Raises RuntimeError if tshark is missing or produces no output and fails.
  """
  tshark = shutil.which('tshark')
  if not tshark:
    raise RuntimeError(
        'tshark not found in PATH; it is required to decrypt 802.15.4 frames'
    )
  cmd = [
      tshark,
      '-n',
      '-r',
      path,
      '-o',
      f'uat:ieee802154_keys:"{network_key_hex}","0","Thread hash"',
      '-Y',
      'udp && wpan.aux_sec.sec_level',
      '-T',
      'fields',
      '-E',
      'separator=\t',
  ]
  for field in _TSHARK_FIELDS:
    cmd += ['-e', field]
  with tempfile.TemporaryDirectory(prefix='cirque_tshark_cfg_') as cfg:
    env = dict(os.environ, HOME=cfg, XDG_CONFIG_HOME=cfg)
    proc = subprocess.run(
        cmd, capture_output=True, text=True, env=env, check=False
    )
  # A capture still being flushed can end mid-record; tshark then exits
  # non-zero but still prints every complete frame.
  if proc.returncode != 0 and not proc.stdout.strip():
    raise RuntimeError(
        f'tshark failed on {path} (exit {proc.returncode}): {proc.stderr}'
    )
  frames: List[Dict[str, Any]] = []
  for line in proc.stdout.splitlines():
    cols = line.split('\t')
    if len(cols) != len(_TSHARK_FIELDS):
      continue
    ts, src16, dst16, sec_level, key_id_mode, sport, dport, payload = cols
    sec = _first_field_int(sec_level)
    if not sec:
      continue
    if _first_field_int(key_id_mode) != _THREAD_NETWORK_KEY_ID_MODE:
      continue
    frames.append({
        'ts': float(ts),
        'src16': _first_field_int(src16),
        'dst16': _first_field_int(dst16),
        'sec_level': sec,
        'sport': _first_field_int(sport),
        'dport': _first_field_int(dport),
        'payload': bytes.fromhex(
            payload.split(',')[0].replace(':', '').strip()
        ),
    })
  return frames


def ieee802154_mac_command_frames(path: str) -> List[Dict[str, Any]]:
  """Returns IEEE 802.15.4 MAC Command frames (fcf & 0x07 == 0x03, e.g.

  SED Data Requests).
  """
  frames: List[Dict[str, Any]] = []
  for linktype, ts, data in iter_pcap_records_with_ts(path):
    if (
        linktype not in (DLT_IEEE802_15_4, DLT_IEEE802_15_4_NOFCS)
        or len(data) < 3
    ):
      continue
    fcf = struct.unpack_from('<H', data, 0)[0]
    if (fcf & 0x07) != 0x03:
      continue
    frames.append({
        'ts': ts,
        'fcf': fcf,
        'seq': data[2],
        'frame_len': len(data),
    })
  return frames


# MLE command codes (Thread spec, MLE Command TLV values) used by the
# parent-restart tests.
MLE_CMD_ADVERTISEMENT = 4
MLE_CMD_PARENT_REQUEST = 9
MLE_CMD_PARENT_RESPONSE = 10
MLE_CMD_CHILD_ID_REQUEST = 11
MLE_CMD_CHILD_ID_RESPONSE = 12
MLE_CMD_CHILD_UPDATE_REQUEST = 13
MLE_CMD_CHILD_UPDATE_RESPONSE = 14

_MLE_TSHARK_FIELDS = (
    'frame.time_epoch',
    'wpan.src16',
    'wpan.src64',
    'wpan.dst16',
    'wpan.dst64',
    'ipv6.dst',
    'mle.cmd',
)


def thread_mle_frames(
    path: str, network_key_hex: str
) -> List[Dict[str, Any]]:
  """Returns MLE messages in an 802.15.4 capture with their decoded command.

  MLE messages are MAC-unsecured and secured at the MLE layer; tshark
  decrypts them with the same "Thread hash" key derivation as the MAC
  frames. Messages whose command cannot be decoded (wrong key) are skipped,
  so an empty result with a wrong key is expected.

  Raises RuntimeError if tshark is missing or fails without output.
  """
  tshark = shutil.which('tshark')
  if not tshark:
    raise RuntimeError(
        'tshark not found in PATH; it is required to decrypt MLE messages'
    )
  cmd = [
      tshark,
      '-n',
      '-r',
      path,
      '-o',
      f'uat:ieee802154_keys:"{network_key_hex}","0","Thread hash"',
      '-Y',
      'mle.cmd',
      '-T',
      'fields',
      '-E',
      'separator=\t',
  ]
  for field in _MLE_TSHARK_FIELDS:
    cmd += ['-e', field]
  with tempfile.TemporaryDirectory(prefix='cirque_tshark_cfg_') as cfg:
    env = dict(os.environ, HOME=cfg, XDG_CONFIG_HOME=cfg)
    proc = subprocess.run(
        cmd, capture_output=True, text=True, env=env, check=False
    )
  if proc.returncode != 0 and not proc.stdout.strip():
    raise RuntimeError(
        f'tshark failed on {path} (exit {proc.returncode}): {proc.stderr}'
    )
  frames: List[Dict[str, Any]] = []
  for line in proc.stdout.splitlines():
    cols = line.split('\t')
    if len(cols) != len(_MLE_TSHARK_FIELDS):
      continue
    ts, src16, src64, dst16, dst64, ip6_dst, mle_cmd = cols
    cmd_val = _first_field_int(mle_cmd)
    if cmd_val is None:
      continue
    frames.append({
        'ts': float(ts),
        'src16': _first_field_int(src16),
        'src64': src64.strip().lower(),
        'dst16': _first_field_int(dst16),
        'dst64': dst64.strip().lower(),
        'ip6_dst': ip6_dst.split(',')[0].strip().lower(),
        'cmd': cmd_val,
    })
  return frames


def ieee802154_ack_frames(path: str) -> List[Dict[str, Any]]:
  """Returns IEEE 802.15.4 Imm-Ack frames (fcf & 0x07 == 0x02).

  Each entry has the acknowledged sequence number and the Frame Pending bit
  (fcf & 0x10), which a parent sets when it claims to hold data for the
  polling child.
  """
  frames: List[Dict[str, Any]] = []
  for linktype, ts, data in iter_pcap_records_with_ts(path):
    if (
        linktype not in (DLT_IEEE802_15_4, DLT_IEEE802_15_4_NOFCS)
        or len(data) < 3
    ):
      continue
    fcf = struct.unpack_from('<H', data, 0)[0]
    if (fcf & 0x07) != 0x02:
      continue
    frames.append({
        'ts': ts,
        'seq': data[2],
        'frame_pending': bool(fcf & 0x10),
    })
  return frames


def acked_mac_commands(
    commands: List[Dict[str, Any]],
    acks: List[Dict[str, Any]],
    max_delay_s: float = 0.05,
) -> List[Dict[str, Any]]:
  """Pairs MAC Command frames with the Imm-Ack that follows them.

  An Ack matches a command when it carries the same sequence number and is
  captured no more than max_delay_s after it. Returns the matched commands,
  each with `ack_ts` and `frame_pending` from its Ack.
  """
  matched: List[Dict[str, Any]] = []
  ack_idx = 0
  ordered_acks = sorted(acks, key=lambda a: a['ts'])
  for cmd in sorted(commands, key=lambda c: c['ts']):
    while (
        ack_idx < len(ordered_acks)
        and ordered_acks[ack_idx]['ts'] < cmd['ts']
    ):
      ack_idx += 1
    j = ack_idx
    while (
        j < len(ordered_acks)
        and ordered_acks[j]['ts'] - cmd['ts'] <= max_delay_s
    ):
      if ordered_acks[j]['seq'] == cmd['seq']:
        matched.append(dict(
            cmd,
            ack_ts=ordered_acks[j]['ts'],
            frame_pending=ordered_acks[j]['frame_pending'],
        ))
        break
      j += 1
  return matched
