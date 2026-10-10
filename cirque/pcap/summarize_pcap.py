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
"""CLI helper and programmatic reader for verifying PCAP files.

Counts records, extracts LinkType / DLT headers, verifies timestamps and
payload lengths, and optionally runs `tcpdump` to validate file integrity.
"""

import argparse
import json
import os
import shutil
import struct
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

DLT_NAMES: Dict[int, str] = {
    1: 'EN10MB (Ethernet)',
    187: 'BLUETOOTH_HCI_H4',
    201: 'BLUETOOTH_HCI_H4_WITH_PHDR',
    251: 'BLUETOOTH_LE_LL',
    256: 'BLUETOOTH_LE_LL_WITH_PHDR',
}


def read_pcap_records(filepath: str) -> List[Tuple[float, bytes]]:
  """Reads all (timestamp, frame_bytes) records from a PCAP file."""
  records: List[Tuple[float, bytes]] = []
  if not os.path.exists(filepath):
    raise FileNotFoundError(f'PCAP file not found: {filepath}')

  with open(filepath, 'rb') as f:
    hdr_bytes = f.read(24)
    if len(hdr_bytes) < 24:
      raise ValueError(
          f'Truncated PCAP header in {filepath}: {len(hdr_bytes)}B'
      )

    magic = struct.unpack('<I', hdr_bytes[:4])[0]
    if magic == 0xA1B2C3D4:
      endian = '<'
      is_nano = False
    elif magic == 0xD4C3B2A1:
      endian = '>'
      is_nano = False
    elif magic == 0xA1B23C4D:
      endian = '<'
      is_nano = True
    elif magic == 0x4D3CB2A1:
      endian = '>'
      is_nano = True
    else:
      raise ValueError(f'Invalid PCAP magic: 0x{magic:08x}')

    _, _, _, _, _, _ = struct.unpack(f'{endian}HHiIII', hdr_bytes[4:])

    while True:
      rec_hdr = f.read(16)
      if not rec_hdr:
        break
      if len(rec_hdr) < 16:
        raise ValueError('Truncated PCAP record header')
      sec, subsec, incl_len, _ = struct.unpack(f'{endian}IIII', rec_hdr)
      data = f.read(incl_len)
      if len(data) < incl_len:
        raise ValueError(
            f'Truncated packet data: expected {incl_len} bytes, got {len(data)}'
        )
      ts = float(sec) + (float(subsec) / (1e9 if is_nano else 1e6))
      records.append((ts, data))
  return records


def summarize_pcap(filepath: str) -> Dict[str, Any]:
  """Parses a PCAP file and returns a structured metadata dictionary."""
  if not os.path.exists(filepath):
    raise FileNotFoundError(f'PCAP file not found: {filepath}')

  file_size = os.path.getsize(filepath)
  with open(filepath, 'rb') as f:
    hdr_bytes = f.read(24)
    if len(hdr_bytes) < 24:
      raise ValueError(
          f'Truncated PCAP header in {filepath}: {len(hdr_bytes)}B'
      )

    magic = struct.unpack('<I', hdr_bytes[:4])[0]
    if magic == 0xA1B2C3D4:
      endian = '<'
      is_nano = False
    elif magic == 0xD4C3B2A1:
      endian = '>'
      is_nano = False
    elif magic == 0xA1B23C4D:
      endian = '<'
      is_nano = True
    elif magic == 0x4D3CB2A1:
      endian = '>'
      is_nano = True
    else:
      raise ValueError(f'Invalid PCAP magic: 0x{magic:08x}')

    v_maj, v_min, tz, sigfigs, snaplen, dlt = struct.unpack(
        f'{endian}HHiIII', hdr_bytes[4:]
    )

    records = 0
    total_payload_bytes = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    while True:
      rec_hdr = f.read(16)
      if not rec_hdr:
        break
      if len(rec_hdr) < 16:
        raise ValueError('Truncated PCAP record header')
      sec, subsec, incl_len, orig_len = struct.unpack(f'{endian}IIII', rec_hdr)
      data = f.read(incl_len)
      if len(data) < incl_len:
        raise ValueError('Truncated packet data')
      ts = float(sec) + (float(subsec) / (1e9 if is_nano else 1e6))
      if first_ts is None:
        first_ts = ts
      last_ts = ts
      records += 1
      total_payload_bytes += len(data)

  return {
      'path': filepath,
      'file_size': file_size,
      'magic': f'0x{magic:08x}',
      'version': f'{v_maj}.{v_min}',
      'snaplen': snaplen,
      'dlt': dlt,
      'dlt_name': DLT_NAMES.get(dlt, f'DLT_{dlt}'),
      'records': records,
      'total_payload_bytes': total_payload_bytes,
      'start_ts': first_ts,
      'end_ts': last_ts,
  }


def verify_pcap_with_tcpdump(filepath: str) -> Tuple[bool, str]:
  """Runs `tcpdump -r <filepath>` to verify external tool parsing validity."""
  tcpdump_bin = shutil.which('tcpdump')
  if not tcpdump_bin:
    return False, 'tcpdump executable not found on host'

  cmd = [tcpdump_bin, '-r', filepath, '-q']
  try:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode == 0:
      return True, proc.stderr.strip()
    return False, (
        f'tcpdump exited with code {proc.returncode}: {proc.stderr.strip()}'
    )
  except Exception as exc:  # pylint: disable=broad-exception-caught
    return False, str(exc)


def verify_pcap_with_tshark(filepath: str) -> Tuple[bool, str]:
  """Runs `tshark -r <filepath>` to verify packet dissection and errors."""
  tshark_bin = shutil.which('tshark')
  if not tshark_bin:
    return False, 'tshark executable not found on host'

  cmd = [tshark_bin, '-r', filepath]
  try:
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    combined = (proc.stdout + '\n' + proc.stderr).strip()
    if proc.returncode != 0:
      return False, f'tshark exited with code {proc.returncode}: {combined}'
    for line in combined.splitlines():
      if 'Malformed' in line:
        return False, f'Malformed packet detected by tshark: {line.strip()}'
    return True, combined
  except Exception as exc:  # pylint: disable=broad-exception-caught
    return False, str(exc)


def main() -> int:
  parser = argparse.ArgumentParser(
      description='Summarize and verify PCAP files.'
  )
  parser.add_argument('pcap_file', nargs='?', default=None, help='Path to PCAP file or directory')
  parser.add_argument(
      '--dir', default=None, help='Path to directory containing PCAP files'
  )
  parser.add_argument(
      '--json', action='store_true', help='Output in JSON format'
  )
  parser.add_argument(
      '--verify',
      action='store_true',
      help='Verify with tcpdump if available on host',
  )
  parser.add_argument(
      '--tshark',
      action='store_true',
      help='Verify with tshark if available on host',
  )
  args = parser.parse_args()

  target_dir = args.dir or (
      args.pcap_file if args.pcap_file and os.path.isdir(args.pcap_file) else None
  )
  if target_dir:
    pcap_files = sorted(
        os.path.join(target_dir, f)
        for f in os.listdir(target_dir)
        if f.endswith('.pcap')
    )
  elif args.pcap_file:
    pcap_files = [args.pcap_file]
  else:
    parser.print_help()
    return 1

  summaries = []
  exit_code = 0
  for pcap_path in pcap_files:
    try:
      summary = summarize_pcap(pcap_path)
      if args.verify:
        ok, msg = verify_pcap_with_tcpdump(pcap_path)
        summary['tcpdump_verified'] = ok
        summary['tcpdump_message'] = msg
      if args.tshark:
        ok, msg = verify_pcap_with_tshark(pcap_path)
        summary['tshark_verified'] = ok
        summary['tshark_message'] = msg
      summaries.append(summary)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      print(f'Error reading PCAP {pcap_path}: {exc}', file=sys.stderr)
      exit_code = 1

  if args.json:
    print(json.dumps(summaries if len(pcap_files) > 1 else (summaries[0] if summaries else {}), indent=2))
  else:
    for summary in summaries:
      print(f"File: {summary['path']} ({summary['file_size']} bytes)")
      print(f"Version: {summary['version']} (Magic: {summary['magic']})")
      print(f"DLT: {summary['dlt']} - {summary['dlt_name']}")
      print(f"Records: {summary['records']}")
      print(f"Payload Bytes: {summary['total_payload_bytes']}")
      if summary['start_ts'] is not None:
        print(f"Timestamp Range: {summary['start_ts']} -> {summary['end_ts']}")
      if args.verify:
        status = 'PASSED' if summary.get('tcpdump_verified') else 'FAILED'
        print(
            f"tcpdump Verification: {status} ({summary.get('tcpdump_message')})"
        )
      if args.tshark:
        status = 'PASSED' if summary.get('tshark_verified') else 'FAILED'
        print(
            f"tshark Verification: {status} ({summary.get('tshark_message')})"
        )
      print('')

  return exit_code


if __name__ == '__main__':
  sys.exit(main())
