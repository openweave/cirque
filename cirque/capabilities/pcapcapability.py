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
"""Cirque PCAP packet capture capability and high-precision PCAP writer.

Provides thread-safe capture of virtual Bluetooth (HCI H4 and LE Link Layer)
and virtual Wi-Fi (L2 Ethernet and EAPOL) traffic into standard,
Wireshark-compatible PCAP files:
  - DLT 1   (LINKTYPE_ETHERNET / EN10MB): Wi-Fi relayed L2 and EAPOL frames.
  - DLT 201 (LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR): BT HCI UART stream with a
    4-byte big-endian direction header (0 = host->ctrl, 1 = ctrl->host).
  - DLT 256 (LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR): Bluetooth LE air interface
    with a 10-byte pseudo-header for channel, signal/noise power, and flags.
    DLT 256 was chosen over raw DLT 251 (LINKTYPE_BLUETOOTH_LE_LL) because
    the 10-byte pseudo-header preserves RF channel number, RSSI / signal power,
    and de-whitened flags, allowing Wireshark to accurately dissect channels
    (e.g., 37, 38, 39 for advertising) and signal metrics.
    `LeLinkLayerPcapEncoder` reconstructs air PDUs from the simulated
    LinkLayerFrames: CONNECT_IND carries a real LLData block, data PDUs use
    the connection access address, LLID header and CRCInit, so Wireshark
    dissects the capture down to L2CAP and ATT.
  - DLT 195 (LINKTYPE_IEEE802_15_4_WITHFCS): Thread 802.15.4 frames copied
    off the OpenThread simulation radio by `ThreadRadioSniffer`.
"""

import collections
import logging
import os
import random
import select
import socket
import struct
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger('PcapCapability')

from cirque.capabilities.basecapability import BaseCapability

# Standard PCAP Global Header constants
PCAP_MAGIC_MICROSECONDS = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_GLOBAL_HEADER_LEN = 24
PCAP_RECORD_HEADER_LEN = 16

# Data Link Types (DLT / LinkType)
DLT_EN10MB = 1
DLT_BLUETOOTH_HCI_H4 = 187
DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201
DLT_BLUETOOTH_LE_LL = 251
DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256
DLT_IEEE802_15_4_WITHFCS = 195

# OpenThread simulation radio transport (openthread examples/platforms/
# simulation/radio.c and simul_utils.c). Each node sends every frame as one
# UDP datagram, [channel (1 byte)] + PSDU (the MAC frame including its valid
# 2-byte FCS), from 127.0.0.1:<base + node_id> to the multicast group
# 224.0.0.116:<base>, where base = PORT_BASE + PORT_OFFSET *
# (MAX_NETWORK_SIZE + 1). Every socket that joins the group on the loopback
# interface gets a copy, so a sniffer sees each frame exactly once.
OT_SIM_GROUP_ADDR = '224.0.0.116'
OT_SIM_LOCAL_ADDR = '127.0.0.1'
OT_SIM_DEFAULT_PORT_BASE = 9000
OT_SIM_MAX_NETWORK_SIZE = 33

# Direction headers for DLT 201 (4-byte big-endian)
H4_DIRECTION_SENT_HOST_TO_CTRL = 0x00000000
H4_DIRECTION_RECV_CTRL_TO_HOST = 0x00000001

# BLE Advertising Channel Access Address (Little Endian on wire)
BLE_ADV_ACCESS_ADDRESS = 0x8E89BED6


def compute_ble_crc24(data: bytes, init: int = 0x555555) -> bytes:
  """Computes BLE Link Layer 24-bit CRC over PDU bytes (Header + Payload).

  Generator polynomial: x^24 + x^10 + x^9 + x^6 + x^4 + x^3 + x + 1 (0x00065B).
  Shift register is initialized with `init` (0x555555 for advertising channels).
  Bits are processed least-significant bit (LSB) first.
  Returns 3 bytes formatted LSB-first on the wire.
  """
  state = init & 0xFFFFFF
  for byte in data:
    for bit_idx in range(8):
      bit = (byte >> bit_idx) & 0x01
      top_bit = (state >> 23) & 0x01
      state = ((state << 1) & 0xFFFFFF)
      if top_bit ^ bit:
        state ^= 0x00065B

  # Bit-reverse each byte of the final 24-bit CRC state so position 0 is LSB
  def _reverse_byte(val: int) -> int:
    res = 0
    for i in range(8):
      if (val >> i) & 1:
        res |= (1 << (7 - i))
    return res

  b0 = _reverse_byte((state >> 16) & 0xFF)
  b1 = _reverse_byte((state >> 8) & 0xFF)
  b2 = _reverse_byte(state & 0xFF)
  return bytes([b0, b1, b2])


def build_h4_phdr_frame(h4_bytes: bytes, direction: int) -> bytes:
  """Prefixes raw H4 bytes with a 4-byte big-endian DLT 201 direction header."""
  return struct.pack('!I', direction) + h4_bytes


# Core Spec Vol 6 Part B, 1.4.1: RF channel index of each advertising channel.
ADV_CHANNEL_TO_RF_CHANNEL = {37: 0, 38: 12, 39: 39}

# Core Spec Vol 6 Part B, 2.4: largest Data Physical Channel PDU payload
# (LE Data Length Extension). Longer L2CAP PDUs are fragmented on air.
LE_MAX_DATA_PDU_PAYLOAD = 251

# LE Data PDU header bits (Vol 6 Part B, 2.4).
LE_LLID_CONTINUATION = 0x01
LE_LLID_START = 0x02
LE_LLID_CONTROL = 0x03
LE_DATA_HEADER_NESN = 0x04
LE_DATA_HEADER_SN = 0x08

# LL Control PDU opcodes (Vol 6 Part B, 2.4.2).
LL_CTRL_TERMINATE_IND = 0x02

# DLT 256 pseudo-header flags (Wireshark packet-btle.c / LINKTYPE 256).
LE_LL_PHDR_FLAG_DEWHITENED = 0x0001
LE_LL_PHDR_FLAG_SIGNAL_VALID = 0x0002
LE_LL_PHDR_FLAG_REF_AA_VALID = 0x0010
LE_LL_PHDR_FLAG_CRC_CHECKED = 0x0400
LE_LL_PHDR_FLAG_CRC_VALID = 0x0800
LE_LL_PHDR_PDU_TYPE_SHIFT = 7
LE_LL_PDU_DIRECTION_UNSPECIFIED = 0
LE_LL_PDU_DIRECTION_CENTRAL_TO_PERIPHERAL = 2
LE_LL_PDU_DIRECTION_PERIPHERAL_TO_CENTRAL = 3

_LE_ADV_PDU_TYPES = {
    'ADV_IND': 0x00,
    'ADV_DIRECT_IND': 0x01,
    'ADV_NONCONN_IND': 0x02,
    'SCAN_REQ': 0x03,
    'SCAN_RSP': 0x04,
    'CONNECT_IND': 0x05,
    'ADV_SCAN_IND': 0x06,
}


def ble_channel_to_rf_channel(channel: int) -> int:
  """Maps a BLE channel index to the RF channel index used by DLT 256.

  Advertising channels 37/38/39 live on RF channels 0/12/39; data channel k
  is RF channel k + 1 below RF channel 12 and k + 2 above it.
  """
  channel = int(channel)
  if channel in ADV_CHANNEL_TO_RF_CHANNEL:
    return ADV_CHANNEL_TO_RF_CHANNEL[channel]
  channel = max(0, min(36, channel))
  return channel + 1 if channel < 11 else channel + 2


def is_valid_connection_access_address(aa: int) -> bool:
  """Checks the Access Address rules of Core Spec Vol 6 Part B, 2.1.2."""
  aa &= 0xFFFFFFFF
  if aa == BLE_ADV_ACCESS_ADDRESS:
    return False
  if bin(aa ^ BLE_ADV_ACCESS_ADDRESS).count('1') <= 1:
    return False
  octets = [(aa >> shift) & 0xFF for shift in (0, 8, 16, 24)]
  if len(set(octets)) == 1:
    return False
  bits = [(aa >> i) & 1 for i in range(32)]
  transitions = sum(1 for i in range(1, 32) if bits[i] != bits[i - 1])
  if transitions > 24:
    return False
  if sum(1 for i in range(27, 32) if bits[i] != bits[i - 1]) < 2:
    return False
  run = 1
  for i in range(1, 32):
    run = run + 1 if bits[i] == bits[i - 1] else 1
    if run > 6:
      return False
  return True


def build_le_ll_air_frame(
    access_address: int,
    pdu_header: int,
    pdu_payload: bytes,
    crc_init: int = 0x555555,
    rf_channel: int = 0,
    rssi: int = -45,
    direction: int = LE_LL_PDU_DIRECTION_UNSPECIFIED,
) -> bytes:
  """Builds one DLT 256 record: pseudo-header + access address + PDU + CRC.

  The 10-byte pseudo-header is rf_channel(1), signal(1), noise(1),
  access_address_offenses(1), ref_access_address(4 LE), flags(2 LE). The
  flags mark the PDU as de-whitened with a valid signal power, a valid
  reference access address, and a CRC that was checked and found valid,
  which is accurate because the CRC is computed here from `crc_init`.
  """
  pdu = bytes([pdu_header & 0xFF, len(pdu_payload) & 0xFF]) + pdu_payload
  crc = compute_ble_crc24(pdu, init=crc_init)
  flags = (
      LE_LL_PHDR_FLAG_DEWHITENED
      | LE_LL_PHDR_FLAG_SIGNAL_VALID
      | LE_LL_PHDR_FLAG_REF_AA_VALID
      | LE_LL_PHDR_FLAG_CRC_CHECKED
      | LE_LL_PHDR_FLAG_CRC_VALID
      | ((direction & 0x03) << LE_LL_PHDR_PDU_TYPE_SHIFT)
  )
  phdr = struct.pack(
      '<bbbBIH',
      max(0, min(39, int(rf_channel))),
      max(-128, min(127, int(rssi))),
      -128,
      0,
      access_address & 0xFFFFFFFF,
      flags,
  )
  return phdr + struct.pack('<I', access_address & 0xFFFFFFFF) + pdu + crc


def _bd_addr_to_le_bytes(addr_str: str) -> bytes:
  clean = addr_str.replace(':', '').replace('-', '')
  try:
    return bytes.fromhex(clean)[::-1]
  except (ValueError, TypeError):
    return b'\x00' * 6


def build_le_ll_phdr_frame(
    pdu_type: str,
    src_bd_addr: str,
    dst_bd_addr: str = 'FF:FF:FF:FF:FF:FF',
    src_addr_type: int = 0,
    dst_addr_type: int = 0,
    channel: int = 37,
    rssi: int = -45,
    payload: bytes = b'',
    access_address: int = BLE_ADV_ACCESS_ADDRESS,
) -> bytes:
  """Encodes an advertising-channel LinkLayer PDU as a DLT 256 record.

  `payload` is the AdvData for advertising PDUs and the 22-byte LLData
  block for CONNECT_IND (zero padded if shorter). `channel` is the BLE
  advertising channel index (37, 38 or 39).
  """
  pdu_code = _LE_ADV_PDU_TYPES.get(pdu_type, 0x00)
  src_bytes = _bd_addr_to_le_bytes(src_bd_addr)
  dst_bytes = _bd_addr_to_le_bytes(dst_bd_addr)

  if pdu_type in ('ADV_IND', 'ADV_NONCONN_IND', 'SCAN_RSP', 'ADV_SCAN_IND'):
    pdu_payload = src_bytes + payload
  elif pdu_type in ('SCAN_REQ', 'ADV_DIRECT_IND'):
    pdu_payload = src_bytes + dst_bytes
  elif pdu_type == 'CONNECT_IND':
    conn_params = (payload + b'\x00' * 22)[:22]
    pdu_payload = src_bytes + dst_bytes + conn_params
  else:
    pdu_payload = payload

  pdu_header = (
      (pdu_code & 0x0F)
      | ((src_addr_type & 0x01) << 6)
      | ((dst_addr_type & 0x01) << 7)
  )
  return build_le_ll_air_frame(
      access_address=access_address,
      pdu_header=pdu_header,
      pdu_payload=pdu_payload,
      crc_init=0x555555,
      rf_channel=ble_channel_to_rf_channel(channel),
      rssi=rssi,
  )


class _LeConnectionCapture:
  """Per-connection state needed to encode data PDUs like an air sniffer."""

  def __init__(
      self,
      access_address: int,
      crc_init: int,
      central_bd_addr: str,
      peripheral_bd_addr: str,
      hop: int,
  ):
    self.access_address = access_address
    self.crc_init = crc_init
    self.central_bd_addr = central_bd_addr.upper()
    self.peripheral_bd_addr = peripheral_bd_addr.upper()
    self.hop = hop
    self.data_channel = 0
    # Sequence numbers are tracked per direction so a protocol analyzer does
    # not classify consecutive PDUs as retransmissions.
    self.sequence_numbers = {
        LE_LL_PDU_DIRECTION_CENTRAL_TO_PERIPHERAL: 0,
        LE_LL_PDU_DIRECTION_PERIPHERAL_TO_CENTRAL: 0,
    }
    # Bytes of the current L2CAP PDU still expected per direction. A real
    # controller learns this from the HCI ACL packet boundary flag; here it
    # is derived from the L2CAP length field of each start fragment.
    self.l2cap_remaining = {
        LE_LL_PDU_DIRECTION_CENTRAL_TO_PERIPHERAL: 0,
        LE_LL_PDU_DIRECTION_PERIPHERAL_TO_CENTRAL: 0,
    }

  def direction_for(self, src_bd_addr: str) -> int:
    if src_bd_addr.upper() == self.central_bd_addr:
      return LE_LL_PDU_DIRECTION_CENTRAL_TO_PERIPHERAL
    return LE_LL_PDU_DIRECTION_PERIPHERAL_TO_CENTRAL

  def next_llid(self, payload: bytes, direction: int) -> int:
    """Returns the LLID of the first air fragment carrying `payload`."""
    remaining = self.l2cap_remaining[direction]
    if remaining > 0:
      self.l2cap_remaining[direction] = max(0, remaining - len(payload))
      return LE_LLID_CONTINUATION
    if len(payload) >= 4:
      l2cap_len = struct.unpack_from('<H', payload, 0)[0]
      self.l2cap_remaining[direction] = max(0, l2cap_len + 4 - len(payload))
    return LE_LLID_START

  def next_data_channel(self) -> int:
    # Channel Selection Algorithm #1 (Vol 6 Part B, 4.5.8.2) with all 37
    # data channels in the channel map.
    self.data_channel = (self.data_channel + self.hop) % 37
    return self.data_channel

  def next_header(self, llid: int, direction: int) -> int:
    sn = self.sequence_numbers[direction]
    other = (
        LE_LL_PDU_DIRECTION_PERIPHERAL_TO_CENTRAL
        if direction == LE_LL_PDU_DIRECTION_CENTRAL_TO_PERIPHERAL
        else LE_LL_PDU_DIRECTION_CENTRAL_TO_PERIPHERAL
    )
    nesn = self.sequence_numbers[other]
    self.sequence_numbers[direction] = sn ^ 1
    header = llid & 0x03
    if sn:
      header |= LE_DATA_HEADER_SN
    if nesn:
      header |= LE_DATA_HEADER_NESN
    return header


class LeLinkLayerPcapEncoder:
  """Stateful encoder turning simulated LinkLayerFrames into DLT 256 records.

  The virtual link layer exchanges JSON-described frames, not air PDUs. To
  make the capture dissectable by Wireshark the encoder reconstructs what a
  sniffer would have seen:
    - CONNECT_IND carries a real 22-byte LLData block with a freshly chosen
      connection Access Address and CRCInit;
    - LL_DATA frames are emitted on that Access Address with an LLID data
      header (start/complete or continuation, derived from the L2CAP
      length field), fragmented at 251 bytes, with per-direction sequence
      numbers and a CRC computed with the connection CRCInit;
    - LL_TERMINATE_IND becomes an LL Control PDU and closes the entry;
    - CONNECT_RSP and PHY_ANNOUNCE are emulation-only control frames that
      never exist on air, so they are not written.
  """

  def __init__(self, seed: Optional[int] = None):
    self._lock = threading.Lock()
    self._connections: Dict[frozenset, _LeConnectionCapture] = {}
    self._rng = random.Random(seed)

  @staticmethod
  def _key(src_bd_addr: str, dst_bd_addr: str) -> frozenset:
    return frozenset((src_bd_addr.upper(), dst_bd_addr.upper()))

  def _allocate_access_address(self) -> int:
    used = {c.access_address for c in self._connections.values()}
    while True:
      aa = self._rng.getrandbits(32)
      if is_valid_connection_access_address(aa) and aa not in used:
        return aa

  def _open_connection(
      self, central_bd_addr: str, peripheral_bd_addr: str
  ) -> _LeConnectionCapture:
    conn = _LeConnectionCapture(
        access_address=self._allocate_access_address(),
        crc_init=self._rng.getrandbits(24),
        central_bd_addr=central_bd_addr,
        peripheral_bd_addr=peripheral_bd_addr,
        hop=self._rng.randint(5, 16),
    )
    self._connections[self._key(central_bd_addr, peripheral_bd_addr)] = conn
    return conn

  def connection_for(
      self, src_bd_addr: str, dst_bd_addr: str
  ) -> Optional[_LeConnectionCapture]:
    with self._lock:
      return self._connections.get(self._key(src_bd_addr, dst_bd_addr))

  def encode(self, frame) -> List[bytes]:
    """Returns zero or more DLT 256 records for a LinkLayerFrame."""
    pdu_type = str(frame.pdu_type)
    if pdu_type in _LE_ADV_PDU_TYPES and pdu_type != 'CONNECT_IND':
      return [
          build_le_ll_phdr_frame(
              pdu_type=pdu_type,
              src_bd_addr=frame.src_bd_addr,
              dst_bd_addr=frame.dst_bd_addr,
              src_addr_type=frame.src_addr_type,
              dst_addr_type=frame.dst_addr_type,
              channel=frame.channel,
              rssi=frame.rssi,
              payload=frame.payload,
          )
      ]
    if pdu_type == 'CONNECT_IND':
      return [self._encode_connect_ind(frame)]
    if pdu_type == 'LL_DATA':
      return self._encode_data(frame)
    if pdu_type == 'LL_TERMINATE_IND':
      return self._encode_terminate(frame)
    return []

  def _encode_connect_ind(self, frame) -> bytes:
    with self._lock:
      conn = self._open_connection(frame.src_bd_addr, frame.dst_bd_addr)
      # LLData (Vol 6 Part B, 2.3.3.1): AA, CRCInit, WinSize, WinOffset,
      # Interval, Latency, Timeout, ChM, Hop | SCA.
      lldata = (
          struct.pack('<I', conn.access_address)
          + struct.pack('<I', conn.crc_init)[:3]
          + struct.pack(
              '<BHHHH',
              0x01,
              0x0000,
              int(frame.conn_interval) & 0xFFFF,
              int(frame.conn_latency) & 0xFFFF,
              int(frame.supervision_timeout) & 0xFFFF,
          )
          + b'\xff\xff\xff\xff\x1f'
          + bytes([conn.hop & 0x1F])
      )
    return build_le_ll_phdr_frame(
        pdu_type='CONNECT_IND',
        src_bd_addr=frame.src_bd_addr,
        dst_bd_addr=frame.dst_bd_addr,
        src_addr_type=frame.src_addr_type,
        dst_addr_type=frame.dst_addr_type,
        channel=frame.channel,
        rssi=frame.rssi,
        payload=lldata,
    )

  def _encode_data(self, frame) -> List[bytes]:
    payload = frame.payload
    with self._lock:
      conn = self._connections.get(
          self._key(frame.src_bd_addr, frame.dst_bd_addr)
      )
      if conn is None:
        # Capture started after the connection was made: synthesize the
        # connection state so the data PDUs still share one access address.
        conn = self._open_connection(frame.src_bd_addr, frame.dst_bd_addr)
      direction = conn.direction_for(frame.src_bd_addr)
      # The payload is the HCI ACL payload, i.e. an L2CAP PDU or a
      # continuation fragment of one; the connection state tracks which.
      llid = conn.next_llid(payload, direction)
      records = []
      fragments = [
          payload[i : i + LE_MAX_DATA_PDU_PAYLOAD]
          for i in range(0, len(payload), LE_MAX_DATA_PDU_PAYLOAD)
      ] or [b'']
      for idx, fragment in enumerate(fragments):
        header = conn.next_header(
            llid if idx == 0 else LE_LLID_CONTINUATION, direction
        )
        records.append(
            build_le_ll_air_frame(
                access_address=conn.access_address,
                pdu_header=header,
                pdu_payload=fragment,
                crc_init=conn.crc_init,
                rf_channel=ble_channel_to_rf_channel(
                    conn.next_data_channel()
                ),
                rssi=frame.rssi,
                direction=direction,
            )
        )
    return records

  def _encode_terminate(self, frame) -> List[bytes]:
    with self._lock:
      key = self._key(frame.src_bd_addr, frame.dst_bd_addr)
      conn = self._connections.pop(key, None)
      if conn is None:
        return []
      direction = conn.direction_for(frame.src_bd_addr)
      header = conn.next_header(LE_LLID_CONTROL, direction)
      record = build_le_ll_air_frame(
          access_address=conn.access_address,
          pdu_header=header,
          pdu_payload=bytes([LL_CTRL_TERMINATE_IND, int(frame.reason) & 0xFF]),
          crc_init=conn.crc_init,
          rf_channel=ble_channel_to_rf_channel(conn.next_data_channel()),
          rssi=frame.rssi,
          direction=direction,
      )
    return [record]


class PcapWriter:
  """Thread-safe PCAP file writer that flushes frame records to disk.

  Creates a valid 24-byte PCAP file upon initialization. Every call to
  `write_frame()` appends a 16-byte record header followed by frame bytes and
  immediately flushes to disk.
  """

  def __init__(
      self,
      filepath: str,
      dlt: int = DLT_EN10MB,
      snaplen: int = 65535,
  ):
    self.filepath = os.path.abspath(filepath)
    self.dlt = dlt
    self.snaplen = snaplen
    self.records = 0
    self._lock = threading.Lock()

    parent_dir = os.path.dirname(self.filepath)
    if parent_dir:
      os.makedirs(parent_dir, exist_ok=True)

    self._file = open(self.filepath, 'wb')
    # Write 24-byte global PCAP header
    global_hdr = struct.pack(
        '<IHHiIII',
        PCAP_MAGIC_MICROSECONDS,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        0,
        0,
        self.snaplen,
        self.dlt,
    )
    self._file.write(global_hdr)
    self._file.flush()

  def write_frame(
      self,
      frame_bytes: bytes,
      ts: Optional[float] = None,
  ) -> None:
    """Appends an individual packet frame to the PCAP file and flushes."""
    if ts is None:
      ts = time.time()
    sec = int(ts)
    usec = int((ts - sec) * 1000000)
    orig_len = len(frame_bytes)
    incl_len = min(orig_len, self.snaplen)

    pkt_hdr = struct.pack('<IIII', sec, usec, incl_len, orig_len)
    with self._lock:
      if self._file and not self._file.closed:
        self._file.write(pkt_hdr + frame_bytes[:incl_len])
        self._file.flush()
        self.records += 1

  def close(self) -> None:
    """Flushes and closes the PCAP file safely."""
    with self._lock:
      if self._file and not self._file.closed:
        try:
          self._file.flush()
          self._file.close()
        except OSError as exc:
          logger.debug('Error closing PCAP file %s: %s', self.filepath, exc)

  def __enter__(self) -> 'PcapWriter':
    return self

  def __exit__(self, exc_type, exc_val, exc_tb) -> None:
    self.close()


def ot_sim_radio_port(
    port_offset: int,
    port_base: int = OT_SIM_DEFAULT_PORT_BASE,
    max_network_size: int = OT_SIM_MAX_NETWORK_SIZE,
) -> int:
  """Returns the multicast port of an OpenThread simulation radio group.

  `port_offset` is the PORT_OFFSET environment value given to ot-rcp; the
  simulation platform scales it by (max_network_size + 1) itself.
  """
  return port_base + port_offset * (max_network_size + 1)


class ThreadRadioSniffer:
  """Copies every frame of one OpenThread simulation radio group to a pcap.

  The pcap uses DLT 195 (IEEE 802.15.4 with FCS) because the simulation
  radio computes a real FCS for every frame it sends. The leading channel
  byte of each datagram is not part of the PSDU and is stripped; frames on
  other channels than `channel` are dropped when `channel` is set. The
  sending node is `sender_port - port`, as in simul_utils.c.
  """

  def __init__(
      self,
      pcap_path: str,
      port: int,
      channel: Optional[int] = None,
      local_addr: str = OT_SIM_LOCAL_ADDR,
  ):
    self.pcap_path = pcap_path
    self.port = port
    self.channel = channel
    self.local_addr = local_addr
    self.frames = 0
    self.channels: Dict[int, int] = collections.Counter()
    self.nodes: Dict[int, int] = collections.Counter()
    self._writer: Optional[PcapWriter] = None
    self._sock: Optional[socket.socket] = None
    self._stop = threading.Event()
    self._thread: Optional[threading.Thread] = None

  def start(self) -> None:
    """Joins the radio group and starts the capture thread."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
      mreq = socket.inet_aton(OT_SIM_GROUP_ADDR) + socket.inet_aton(
          self.local_addr
      )
      sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
      sock.bind((OT_SIM_GROUP_ADDR, self.port))
    except OSError:
      sock.close()
      raise
    self._sock = sock
    self._writer = PcapWriter(self.pcap_path, dlt=DLT_IEEE802_15_4_WITHFCS)
    self._stop.clear()
    self._thread = threading.Thread(
        target=self._run, name=f'thread-sniffer-{self.port}', daemon=True
    )
    self._thread.start()
    logger.info(
        'Thread radio sniffer on %s:%d -> %s',
        OT_SIM_GROUP_ADDR,
        self.port,
        self.pcap_path,
    )

  def handle_datagram(
      self, data: bytes, sender_port: int, ts: Optional[float] = None
  ) -> bool:
    """Writes one simulation radio datagram; returns True if it was kept."""
    # A PSDU always carries at least a 2-byte FCS after the channel byte.
    if len(data) < 4 or self._writer is None:
      return False
    channel = data[0]
    if self.channel is not None and channel != self.channel:
      return False
    self._writer.write_frame(data[1:], ts=ts)
    self.frames += 1
    self.channels[channel] += 1
    self.nodes[sender_port - self.port] += 1
    return True

  def _run(self) -> None:
    while not self._stop.is_set():
      sock = self._sock
      if sock is None:
        return
      try:
        readable, _, _ = select.select([sock], [], [], 0.2)
        if not readable:
          continue
        data, (_, sender_port) = sock.recvfrom(256)
      except (OSError, ValueError):
        return
      self.handle_datagram(data, sender_port, ts=time.time())

  def stop(self) -> None:
    """Stops the capture thread and closes the socket and the pcap."""
    self._stop.set()
    if self._thread is not None:
      self._thread.join(timeout=2.0)
      self._thread = None
    if self._sock is not None:
      self._sock.close()
      self._sock = None
    if self._writer is not None:
      self._writer.close()
      self._writer = None
    logger.info(
        'Thread radio sniffer stopped: %d frames, channels %s, nodes %s',
        self.frames,
        dict(self.channels),
        dict(self.nodes),
    )


_PCAP_WRITERS_LOCK = threading.Lock()
_GLOBAL_PCAP_WRITERS: Dict[str, PcapWriter] = {}


class PcapCapability(BaseCapability):
  """Cirque packet capture capability managing per-node and shared PCAP files.

  Configurable via home device_config dictionary:
    'pcap': {
        'dir': '/tmp/cirque_pcap',
        'bt': True,
        'wifi': True,
    }
  Or globally via the `CIRQUE_PCAP_DIR` environment variable.
  """

  def __init__(
      self,
      pcap_dir: Optional[str] = None,
      bt: bool = True,
      wifi: bool = True,
  ):
    env_dir = (
        os.environ.get('CIRQUE_PCAP_DIR')
        or os.environ.get('DEVICE_LOG_DIR')
    )
    self.pcap_dir = pcap_dir or env_dir or '/tmp/cirque_pcap'
    self.bt = bt
    self.wifi = wifi
    self._node_writers: List[PcapWriter] = []
    if self.pcap_dir:
      os.makedirs(self.pcap_dir, exist_ok=True)

  @property
  def name(self) -> str:
    return 'Pcap'

  @property
  def description(self) -> Dict[str, Any]:
    return {
        'pcap_dir': self.pcap_dir,
        'bt': self.bt,
        'wifi': self.wifi,
    }

  @classmethod
  def get_active_pcap_dir(cls) -> Optional[str]:
    """Returns the globally configured PCAP directory from env if set."""
    return (
        os.environ.get('CIRQUE_PCAP_DIR')
        or os.environ.get('DEVICE_LOG_DIR')
    )

  @classmethod
  def get_or_create_writer(
      cls,
      pcap_dir: str,
      filename: str,
      dlt: int = DLT_EN10MB,
  ) -> PcapWriter:
    """Thread-safe registry returning a singleton PcapWriter per target file."""
    path = os.path.join(pcap_dir, filename)
    with _PCAP_WRITERS_LOCK:
      cached = _GLOBAL_PCAP_WRITERS.get(path)
      if cached is None or cached._file.closed:
        cached = PcapWriter(path, dlt=dlt)
        _GLOBAL_PCAP_WRITERS[path] = cached
      return cached

  @classmethod
  def close_all_writers(cls) -> None:
    """Closes all globally registered PcapWriter instances."""
    with _PCAP_WRITERS_LOCK:
      for writer in list(_GLOBAL_PCAP_WRITERS.values()):
        writer.close()
      _GLOBAL_PCAP_WRITERS.clear()

  def enable_capability(self, docker_node) -> None:
    """Enables packet capture hooks for a Cirque Docker node."""
    node_id = getattr(docker_node, 'id', 'node')
    if self.wifi:
      sta_writer = self.get_or_create_writer(
          self.pcap_dir, f'wifi_{node_id}.pcap', dlt=DLT_EN10MB
      )
      self._node_writers.append(sta_writer)
    if self.bt:
      bt_writer = self.get_or_create_writer(
          self.pcap_dir,
          f'bt_hci_{node_id}.pcap',
          dlt=DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
      )
      self._node_writers.append(bt_writer)

  def disable_capability(self, docker_node) -> None:
    """Disables packet capture and flushes node writers."""
    for writer in self._node_writers:
      writer.close()
    self._node_writers.clear()
