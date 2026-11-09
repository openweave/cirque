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
"""Event-driven Station-Side WPA2 Supplicant State Machine.

Runs an independent 802.11 / WPA2 station state machine:
  - Computes its OWN PMK from its OWN passphrase.
  - Generates its OWN SNonce.
  - Processes EAPOL Msg1 (computes PTK, constructs & sends Msg2 with MIC).
  - Processes EAPOL Msg3 (verifies MIC, verifies replay counter, decrypts GTK,
    constructs & sends Msg4 with MIC).
  - Transitions through canonical wpa_supplicant D-Bus State strings:
      'disconnected', 'scanning', 'authenticating', 'associating',
      'associated', '4way_handshake', 'group_handshake', 'completed'.
  - Pluggable frame transport via `on_send_frame(frame_bytes)` callback.
  - Pluggable state change notification via `on_state_change(new_state)` callback.
"""

import logging
import os
from typing import Callable, Optional

from cirque.virtual_wifi.eapol import (
    EAPOL_VERSION_1,
    EAPOL_VERSION_2,
    EapolKeyFrame,
    KEY_DESC_VERSION_HMAC_SHA1_AES,
    KEY_INFO_ENCRYPTED_KEY_DATA,
    KEY_INFO_INSTALL,
    KEY_INFO_KEY_ACK,
    KEY_INFO_KEY_MIC,
    KEY_INFO_KEY_TYPE_PAIRWISE,
    KEY_INFO_SECURE,
    build_gtk_kde,
    decode_eapol_key_frame,
    parse_gtk_from_kde,
)
from cirque.virtual_wifi.wpa2_crypto import (
    Wpa2Ptk,
    aes_key_unwrap,
    compute_mic,
    derive_ptk,
    pbkdf2_sha1_pmk,
    verify_mic,
)

logger = logging.getLogger('Wpa2SupplicantSM')


class Wpa2SupplicantStateMachine:
  """Event-driven Station-side WPA2-PSK Supplicant State Machine."""

  def __init__(
      self,
      station_mac: str,
      on_send_frame: Optional[Callable[[bytes], None]] = None,
      on_state_change: Optional[Callable[[str], None]] = None,
  ):
    self.station_mac = station_mac
    self.on_send_frame = on_send_frame or (lambda frame: None)
    self.on_state_change = on_state_change or (lambda state: None)

    self._state = 'disconnected'
    self.ssid = ''
    self.passphrase = ''
    self.ap_bssid = ''
    self.pmk: Optional[bytes] = None
    self.ptk: Optional[Wpa2Ptk] = None
    self.gtk: Optional[bytes] = None
    self.anonce: Optional[bytes] = None
    self.snonce: Optional[bytes] = None
    self.last_replay_counter: int = 0

  @property
  def state(self) -> str:
    return self._state

  def _set_state(self, new_state: str) -> None:
    if self._state != new_state:
      logger.debug(
          'Supplicant %s: state transition %s -> %s',
          self.station_mac,
          self._state,
          new_state,
      )
      self._state = new_state
      self.on_state_change(new_state)

  def start_association(
      self, ssid: str, passphrase: str, ap_bssid: str
  ) -> None:
    """Initiates association to target AP, computing station-side PMK."""
    self.ssid = ssid
    self.passphrase = passphrase
    self.ap_bssid = ap_bssid
    self.pmk = pbkdf2_sha1_pmk(passphrase, ssid)
    self.ptk = None
    self.gtk = None
    self.anonce = None
    self.snonce = None
    self.last_replay_counter = 0

    self._set_state('authenticating')
    self._set_state('associating')
    self._set_state('associated')

  def handle_eapol_frame(self, frame_bytes: bytes) -> bool:
    """Processes an incoming EAPOL frame from the AP (Msg1 or Msg3).

    Returns True if the frame was successfully processed, False otherwise.
    """
    try:
      msg = decode_eapol_key_frame(frame_bytes)
    except Exception as e:
      logger.warning('Failed to decode EAPOL frame: %s', e)
      return False

    if not msg.is_pairwise:
      logger.warning('Ignoring non-pairwise EAPOL frame')
      return False

    # Msg1: Key Ack = 1, Key MIC = 0
    if msg.key_ack and not msg.has_mic:
      return self._handle_msg1(msg)

    # Msg3: Key Ack = 1, Key MIC = 1, Install = 1
    if msg.key_ack and msg.has_mic and msg.install:
      return self._handle_msg3(msg)

    logger.warning(
        'Unexpected EAPOL message format: ack=%s mic=%s install=%s',
        msg.key_ack,
        msg.has_mic,
        msg.install,
    )
    return False

  def _handle_msg1(self, msg1: EapolKeyFrame) -> bool:
    """Processes EAPOL Msg1 from AP, generates SNonce, PTK, and sends Msg2."""
    if self.pmk is None:
      logger.error('Cannot process Msg1: PMK not initialized')
      return False

    self._set_state('4way_handshake')
    self.anonce = msg1.nonce
    self.last_replay_counter = msg1.replay_counter
    self.snonce = os.urandom(32)

    # Convert MAC addresses to bytes
    ap_mac_bytes = bytes.fromhex(self.ap_bssid.replace(':', ''))
    sta_mac_bytes = bytes.fromhex(self.station_mac.replace(':', ''))

    # Derive PTK
    self.ptk = derive_ptk(
        self.pmk,
        aa_mac=ap_mac_bytes,
        spa_mac=sta_mac_bytes,
        anonce=self.anonce,
        snonce=self.snonce,
    )

    # Build Msg2
    # Key Info: Pairwise (bit 3), MIC (bit 8), Version 2 (bits 0..2)
    key_info = (
        KEY_INFO_KEY_TYPE_PAIRWISE
        | KEY_INFO_KEY_MIC
        | KEY_DESC_VERSION_HMAC_SHA1_AES
    )
    msg2 = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=msg1.descriptor_type,
        key_info=key_info,
        key_length=16,
        replay_counter=msg1.replay_counter,
        nonce=self.snonce,
        iv=b'\x00' * 16,
        rsc=0,
        mic=b'\x00' * 16,
        key_data=b'',  # Can include RSN IE
    )

    # Compute MIC with KCK over msg2 with zeroed MIC
    msg2_bytes_zeroed = msg2.encode_with_zeroed_mic()
    msg2.mic = compute_mic(self.ptk.kck, msg2_bytes_zeroed)

    out_frame = msg2.encode()
    self.on_send_frame(out_frame)
    return True

  def _handle_msg3(self, msg3: EapolKeyFrame) -> bool:
    """Processes EAPOL Msg3 from AP, verifies MIC & replay counter, sends Msg4."""
    if self.ptk is None:
      logger.error('Cannot process Msg3: PTK not established')
      return False

    # Check replay counter strictly greater than msg1
    if msg3.replay_counter <= self.last_replay_counter:
      logger.warning(
          'Msg3 replay counter %d not greater than %d',
          msg3.replay_counter,
          self.last_replay_counter,
      )
      return False

    # Verify Msg3 MIC
    msg3_zeroed = msg3.encode_with_zeroed_mic()
    if not verify_mic(self.ptk.kck, msg3_zeroed, msg3.mic):
      logger.warning('Msg3 MIC verification failed')
      return False

    self.last_replay_counter = msg3.replay_counter

    # Unwrap GTK from Key Data if encrypted key data bit is set
    if msg3.encrypted_key_data and msg3.key_data:
      try:
        decrypted_key_data = aes_key_unwrap(self.ptk.kek, msg3.key_data)
        self.gtk = parse_gtk_from_kde(decrypted_key_data)
      except Exception as e:
        logger.warning('Failed to decrypt/parse GTK from Msg3: %s', e)
        return False

    # Build Msg4
    # Key Info: Pairwise (bit 3), MIC (bit 8), Secure (bit 9), Version 2
    key_info = (
        KEY_INFO_KEY_TYPE_PAIRWISE
        | KEY_INFO_KEY_MIC
        | KEY_INFO_SECURE
        | KEY_DESC_VERSION_HMAC_SHA1_AES
    )
    msg4 = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=msg3.descriptor_type,
        key_info=key_info,
        key_length=16,
        replay_counter=msg3.replay_counter,
        nonce=b'\x00' * 32,
        iv=b'\x00' * 16,
        rsc=0,
        mic=b'\x00' * 16,
        key_data=b'',
    )

    msg4_zeroed = msg4.encode_with_zeroed_mic()
    msg4.mic = compute_mic(self.ptk.kck, msg4_zeroed)

    out_frame = msg4.encode()
    self.on_send_frame(out_frame)

    # State transitions to completed only AFTER msg4 is transmitted
    self._set_state('completed')
    return True
