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
"""WPA2-PSK Cryptographic Primitives (IEEE 802.11i / RFC 3394).

Implements:
  1. PBKDF2-SHA1 PMK derivation: 4096 iterations, 32-byte PMK.
  2. PRF-512 PTK derivation: PRF-512(PMK, "Pairwise key expansion",
     min(AA,SPA) || max(AA,SPA) || min(ANonce,SNonce) || max(ANonce,SNonce)).
     Splits into:
       - KCK (Key Confirmation Key): bytes 0..16 (128 bits)
       - KEK (Key Encryption Key): bytes 16..32 (128 bits)
       - TK  (Temporal Key): bytes 32..48 (128 bits)
  3. HMAC-SHA1-128 MIC: calculates 128-bit HMAC-SHA1 over EAPOL frame with
     the Key MIC field zeroed, keyed by KCK.
  4. AES Key Wrap / Unwrap (RFC 3394 / NIST Key Wrap): wraps GTK KDE with KEK.
"""

from dataclasses import dataclass
import hashlib
import hmac
import struct
from typing import Tuple

try:
  from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
  _HAS_CRYPTOGRAPHY = True
except ImportError:
  _HAS_CRYPTOGRAPHY = False


@dataclass(frozen=True)
class Wpa2Ptk:
  """Pairwise Transient Key (PTK) split into KCK, KEK, and TK."""

  kck: bytes  # 16 bytes (Key Confirmation Key)
  kek: bytes  # 16 bytes (Key Encryption Key)
  tk: bytes   # 16 bytes (Temporal Key)
  raw: bytes  # 48 or 64 bytes total


def pbkdf2_sha1_pmk(passphrase: str, ssid: str) -> bytes:
  """Derives the 32-byte Pairwise Master Key (PMK) per IEEE 802.11i.

  Uses PBKDF2-HMAC-SHA1 with 4096 iterations and 32 bytes output length.
  Passphrase is UTF-8 encoded, and SSID is used as the salt.
  """
  return hashlib.pbkdf2_hmac(
      'sha1',
      passphrase.encode('utf-8'),
      ssid.encode('utf-8') if isinstance(ssid, str) else ssid,
      4096,
      dklen=32,
  )


def prf_512(key: bytes, prefix: bytes, data: bytes) -> bytes:
  """Computes IEEE 802.11i PRF-512 pseudo-random function.

  PRF-512(K, A, B) = HMAC-SHA1(K, A || 0x00 || B || 0) ||
                     HMAC-SHA1(K, A || 0x00 || B || 1) ||
                     HMAC-SHA1(K, A || 0x00 || B || 2) ||
                     HMAC-SHA1(K, A || 0x00 || B || 3)[0:4] -> 64 bytes total.
  """
  out = bytearray()
  counter = 0
  while len(out) < 64:
    msg = prefix + b'\x00' + data + bytes([counter])
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    out.extend(digest)
    counter += 1
  return bytes(out[:64])


def derive_ptk(
    pmk: bytes,
    aa_mac: bytes,
    spa_mac: bytes,
    anonce: bytes,
    snonce: bytes,
) -> Wpa2Ptk:
  """Derives the WPA2-PSK PTK using PRF-512 per IEEE 802.11i.

  Data order:
    min(AA, SPA) || max(AA, SPA) || min(ANonce, SNonce) || max(ANonce, SNonce)
  """
  mac_data = min(aa_mac, spa_mac) + max(aa_mac, spa_mac)
  nonce_data = min(anonce, snonce) + max(anonce, snonce)
  ptk_raw = prf_512(pmk, b'Pairwise key expansion', mac_data + nonce_data)
  kck = ptk_raw[0:16]
  kek = ptk_raw[16:32]
  tk = ptk_raw[32:48]
  return Wpa2Ptk(kck=kck, kek=kek, tk=tk, raw=ptk_raw)


def compute_mic(kck: bytes, eapol_frame_bytes: bytes) -> bytes:
  """Computes HMAC-SHA1-128 MIC over an EAPOL frame (Key MIC zeroed)."""
  return hmac.new(kck, eapol_frame_bytes, hashlib.sha1).digest()[:16]


def verify_mic(
    kck: bytes, eapol_frame_bytes: bytes, expected_mic: bytes
) -> bool:
  """Verifies the HMAC-SHA1-128 MIC in constant time."""
  actual_mic = compute_mic(kck, eapol_frame_bytes)
  return hmac.compare_digest(actual_mic, expected_mic)


# RFC 3394 AES Key Wrap / Unwrap default IV: 0xA6A6A6A6A6A6A6A6
RFC3394_DEFAULT_IV = b'\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6'


def _aes_ecb_encrypt_block(key: bytes, block16: bytes) -> bytes:
  """Encrypts a single 16-byte block with AES-128 ECB."""
  if _HAS_CRYPTOGRAPHY:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(block16) + encryptor.finalize()
  raise RuntimeError('AES key wrap requires cryptography package')


def _aes_ecb_decrypt_block(key: bytes, block16: bytes) -> bytes:
  """Decrypts a single 16-byte block with AES-128 ECB."""
  if _HAS_CRYPTOGRAPHY:
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    return decryptor.update(block16) + decryptor.finalize()
  raise RuntimeError('AES key unwrap requires cryptography package')


def aes_key_wrap(
    kek: bytes, plaintext: bytes, iv: bytes = RFC3394_DEFAULT_IV
) -> bytes:
  """Wraps key data using RFC 3394 AES Key Wrap Algorithm.

  Plaintext length must be a non-zero multiple of 8 bytes.
  """
  n = len(plaintext) // 8
  if n == 0 or len(plaintext) % 8 != 0:
    raise ValueError('Plaintext length must be a positive multiple of 8 bytes')

  a = iv
  r = [plaintext[i * 8 : (i + 1) * 8] for i in range(n)]

  for j in range(6):
    for i in range(1, n + 1):
      b = _aes_ecb_encrypt_block(kek, a + r[i - 1])
      t = (n * j) + i
      # A = MSB(64, B) ^ t
      a_high = struct.unpack('!Q', b[:8])[0] ^ t
      a = struct.pack('!Q', a_high)
      r[i - 1] = b[8:]

  return a + b''.join(r)


def aes_key_unwrap(
    kek: bytes, ciphertext: bytes, iv: bytes = RFC3394_DEFAULT_IV
) -> bytes:
  """Unwraps key data using RFC 3394 AES Key Unwrap Algorithm.

  Ciphertext length must be at least 16 bytes and a multiple of 8 bytes.
  Raises ValueError if integrity check fails.
  """
  if len(ciphertext) < 16 or len(ciphertext) % 8 != 0:
    raise ValueError('Ciphertext length must be >= 16 and a multiple of 8 bytes')

  n = (len(ciphertext) // 8) - 1
  a = ciphertext[:8]
  r = [ciphertext[(i + 1) * 8 : (i + 2) * 8] for i in range(n)]

  for j in range(5, -1, -1):
    for i in range(n, 0, -1):
      t = (n * j) + i
      a_high = struct.unpack('!Q', a)[0] ^ t
      b = _aes_ecb_decrypt_block(kek, struct.pack('!Q', a_high) + r[i - 1])
      a = b[:8]
      r[i - 1] = b[8:]

  if not hmac.compare_digest(a, iv):
    raise ValueError('RFC 3394 AES Key Unwrap integrity check failed')

  return b''.join(r)
