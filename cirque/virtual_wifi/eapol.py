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
"""EAPOL and EAPOL-Key Frame Encoders and Decoders (IEEE 802.1X / 802.11i).

Supports IEEE 802.1X encapsulation and WPA2 EAPOL-Key frames (descriptor
type 2 = IEEE 802.11i).

EAPOL Header:
  - Protocol Version (1 byte): 1 or 2 (typically 1 or 2 in WPA2)
  - Packet Type (1 byte): 3 = EAPOL-Key
  - Packet Body Length (2 bytes, big-endian)

EAPOL-Key Frame Layout (95 bytes fixed header + key_data):
  - Descriptor Type (1 byte): 2 (IEEE 802.11)
  - Key Information (2 bytes, big-endian bitfield):
      * Key Descriptor Version (bits 0..2): 2 = HMAC-SHA1-128 / AES-128-KW
      * Key Type (bit 3): 1 = Pairwise, 0 = Group
      * Key Index (bits 4..5): 0 for pairwise, or group key index
      * Install (bit 6): 1 in Msg3 (install PTK)
      * Key Ack (bit 7): 1 in Msg1, Msg3 (AP expects reply)
      * Key MIC (bit 8): 1 if MIC is included (Msg2, Msg3, Msg4)
      * Secure (bit 9): 1 in Msg3, Msg4 (secure handshake)
      * Error (bit 10): 0
      * Request (bit 11): 0
      * Encrypted Key Data (bit 12): 1 if key data is encrypted (Msg3 with GTK)
      * Reserved (bits 13..15): 0
  - Key Length (2 bytes, big-endian): 16 bytes for TKIP/CCMP TK
  - Key Replay Counter (8 bytes, big-endian uint64)
  - Key Nonce (32 bytes): ANonce (AP) or SNonce (STA)
  - Key IV (16 bytes): 16 zero bytes
  - Key RSC (8 bytes): Receive Sequence Counter (0 in handshake)
  - Reserved (8 bytes): 8 zero bytes
  - Key MIC (16 bytes): 128-bit HMAC-SHA1
  - Key Data Length (2 bytes, big-endian)
  - Key Data (variable length, e.g. RSN IE, GTK KDE)
"""

from dataclasses import dataclass
import struct
from typing import Optional, Tuple

EAPOL_VERSION_1 = 1
EAPOL_VERSION_2 = 2
EAPOL_TYPE_KEY = 3

DESC_TYPE_RSN_WPA2 = 2

# Key Information Bit Masks (IEEE 802.11-2016 / 802.11i)
KEY_INFO_KEY_DESC_VERSION_MASK = 0x0007
KEY_DESC_VERSION_HMAC_SHA1_AES = 2  # WPA2-PSK (AES / CCMP)

KEY_INFO_KEY_TYPE_PAIRWISE = 1 << 3     # 0x0008 (Pairwise vs Group)
KEY_INFO_INSTALL = 1 << 6               # 0x0040 (Install bit)
KEY_INFO_KEY_ACK = 1 << 7               # 0x0080 (Key Ack)
KEY_INFO_KEY_MIC = 1 << 8               # 0x0100 (Key MIC present)
KEY_INFO_SECURE = 1 << 9                # 0x0200 (Secure bit)
KEY_INFO_ERROR = 1 << 10                # 0x0400 (Error bit)
KEY_INFO_REQUEST = 1 << 11              # 0x0800 (Request bit)
KEY_INFO_ENCRYPTED_KEY_DATA = 1 << 12   # 0x1000 (Encrypted Key Data)

# Standard Ethernet Type for 802.1X EAPOL frames
ETHERTYPE_EAPOL = 0x888E


@dataclass
class EapolKeyFrame:
  """Representation of an IEEE 802.11i / WPA2 EAPOL-Key frame."""

  version: int = EAPOL_VERSION_1
  descriptor_type: int = DESC_TYPE_RSN_WPA2
  key_info: int = 0
  key_length: int = 16
  replay_counter: int = 0
  nonce: bytes = b'\x00' * 32
  iv: bytes = b'\x00' * 16
  rsc: int = 0
  mic: bytes = b'\x00' * 16
  key_data: bytes = b''

  @property
  def is_pairwise(self) -> bool:
    return bool(self.key_info & KEY_INFO_KEY_TYPE_PAIRWISE)

  @property
  def has_mic(self) -> bool:
    return bool(self.key_info & KEY_INFO_KEY_MIC)

  @property
  def key_ack(self) -> bool:
    return bool(self.key_info & KEY_INFO_KEY_ACK)

  @property
  def install(self) -> bool:
    return bool(self.key_info & KEY_INFO_INSTALL)

  @property
  def secure(self) -> bool:
    return bool(self.key_info & KEY_INFO_SECURE)

  @property
  def encrypted_key_data(self) -> bool:
    return bool(self.key_info & KEY_INFO_ENCRYPTED_KEY_DATA)

  def encode(self) -> bytes:
    """Encodes the EAPOL-Key frame including the 4-byte 802.1X header."""
    key_data_len = len(self.key_data)
    # EAPOL-Key body is 95 bytes fixed + key_data
    body_len = 95 + key_data_len
    eapol_hdr = struct.pack('!BBH', self.version, EAPOL_TYPE_KEY, body_len)

    body = (
        struct.pack('!B', self.descriptor_type)
        + struct.pack('!H', self.key_info)
        + struct.pack('!H', self.key_length)
        + struct.pack('!Q', self.replay_counter)
        + self.nonce
        + self.iv
        + struct.pack('!Q', self.rsc)
        + b'\x00' * 8
        + self.mic
        + struct.pack('!H', key_data_len)
        + self.key_data
    )
    return eapol_hdr + body

  def encode_with_zeroed_mic(self) -> bytes:
    """Encodes the full EAPOL frame with Key MIC field zeroed for hashing."""
    orig_mic = self.mic
    self.mic = b'\x00' * 16
    try:
      return self.encode()
    finally:
      self.mic = orig_mic


def decode_eapol_key_frame(data: bytes) -> EapolKeyFrame:
  """Decodes an EAPOL-Key frame from raw bytes.

  Data must include the 4-byte 802.1X header.
  """
  if len(data) < 4 + 95:
    raise ValueError(f'EAPOL frame too short: {len(data)} bytes < 99')

  version, pkt_type, body_len = struct.unpack('!BBH', data[:4])
  if pkt_type != EAPOL_TYPE_KEY:
    raise ValueError(f'Not an EAPOL-Key frame: packet_type={pkt_type}')
  if len(data) < 4 + body_len:
    raise ValueError(f'Truncated EAPOL body: {len(data) - 4} < {body_len}')

  body = data[4 : 4 + body_len]
  if len(body) < 95:
    raise ValueError(f'EAPOL-Key body too short: {len(body)} < 95')

  desc_type = body[0]
  key_info = struct.unpack('!H', body[1:3])[0]
  key_length = struct.unpack('!H', body[3:5])[0]
  replay_counter = struct.unpack('!Q', body[5:13])[0]
  nonce = body[13:45]
  iv = body[45:61]
  rsc = struct.unpack('!Q', body[61:69])[0]
  mic = body[77:93]
  key_data_len = struct.unpack('!H', body[93:95])[0]
  key_data = body[95 : 95 + key_data_len]

  return EapolKeyFrame(
      version=version,
      descriptor_type=desc_type,
      key_info=key_info,
      key_length=key_length,
      replay_counter=replay_counter,
      nonce=nonce,
      iv=iv,
      rsc=rsc,
      mic=mic,
      key_data=key_data,
  )


def build_gtk_kde(gtk: bytes, key_id: int = 1) -> bytes:
  """Builds an IEEE 802.11i Group Transient Key (GTK) Key Data Encapsulation (KDE).

  KDE Format:
    - Type: 0xDD (Vendor Specific)
    - Length: 1 byte (length of OUI + DataType + Data)
    - OUI: 00-0F-AC (IEEE 802.11)
    - Data Type: 1 (GTK)
    - Key ID / flags: bits 0..1 key_id, bit 2 Tx, bits 3..7 reserved
    - Reserved: 0x00
    - GTK data: 16 bytes (CCMP)
  Total length: 2 + 6 + 16 = 24 bytes (multiple of 8, perfect for AES KW).
  """
  kde_type = 0xDD
  oui_and_data_type = bytes([0x00, 0x0F, 0xAC, 0x01])  # 802.11 GTK KDE
  key_id_byte = key_id & 0x03
  payload = oui_and_data_type + bytes([key_id_byte, 0x00]) + gtk
  return bytes([kde_type, len(payload)]) + payload


def parse_gtk_from_kde(key_data: bytes) -> bytes:
  """Extracts the 16-byte GTK from decrypted Key Data containing a GTK KDE."""
  idx = 0
  while idx < len(key_data):
    if key_data[idx] != 0xDD:
      # Non-vendor specific or padding (0x00)
      if key_data[idx] == 0x00:
        idx += 1
        continue
      # Skip element: type (1B), len (1B), payload
      if idx + 1 >= len(key_data):
        break
      elem_len = key_data[idx + 1]
      idx += 2 + elem_len
      continue
    # Vendor-specific (KDE)
    if idx + 2 > len(key_data):
      break
    length = key_data[idx + 1]
    elem_end = idx + 2 + length
    if elem_end > len(key_data):
      break
    kde_content = key_data[idx + 2 : elem_end]
    # Check OUI 00-0F-AC and data type 01 (GTK)
    if len(kde_content) >= 6 and kde_content[:4] == bytes([0x00, 0x0F, 0xAC, 0x01]):
      # GTK is at offset 6 (after OUI:4B, key_id:1B, reserved:1B)
      return kde_content[6:]
    idx = elem_end

  raise ValueError('No valid GTK KDE found in key data')
