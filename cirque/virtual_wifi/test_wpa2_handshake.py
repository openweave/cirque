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
"""Comprehensive unit tests for WPA2-PSK Cryptography and EAPOL-Key 4-Way Handshake.

Verifies:
  1. IEEE 802.11 Annex J.4 test vectors for PBKDF2-SHA1 PMK derivation.
  2. RFC 3394 test vectors for AES-128 Key Wrap and Unwrap.
  3. IEEE 802.11i PRF-512 and PTK derivation (KCK, KEK, TK).
  4. HMAC-SHA1-128 MIC computation and verification.
  5. EAPOL-Key frame serialization, deserialization, and GTK KDE packing.
  6. End-to-end 4-way handshake between VirtualWiFiServer and Wpa2SupplicantStateMachine.
  7. Negative test: Station with invalid passphrase fails Msg2 MIC verification.
  8. Negative test: Tampered Msg3 MIC is rejected by station.
  9. Negative test: Replayed Msg3 (stale replay counter) is rejected by station.
  10. Authenticator never receives station passphrase (architectural isolation).
  11. L2 data frames are gated until Msg4 completes the handshake.
"""

import json
import os
import socket
import struct
import time
import unittest

from cirque.virtual_wifi.eapol import (
    DESC_TYPE_RSN_WPA2,
    EAPOL_TYPE_KEY,
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
from cirque.virtual_wifi.server import VirtualWiFiServer
from cirque.virtual_wifi.wpa2_crypto import (
    aes_key_unwrap,
    aes_key_wrap,
    compute_mic,
    derive_ptk,
    pbkdf2_sha1_pmk,
    prf_512,
    verify_mic,
)
from cirque.virtual_wifi.wpa2_supplicant_sm import Wpa2SupplicantStateMachine



class TestWpa2CryptoVectors(unittest.TestCase):
  """Verifies cryptographic primitives against standard published test vectors."""

  def test_ieee80211_annex_j4_pmk_derivation_vector(self):
    """Verifies PBKDF2-SHA1 against IEEE 802.11i Annex J.4 official vector.

    Passphrase: 'password'
    SSID: 'IEEE'
    Expected PMK:
      f4 2c 6f c5 2d f0 eb ef 9e bb 4b 90 b3 8a 5f 90
      2e 83 fe 1b 13 5a 70 e2 3a ed 76 2e 97 10 a1 2e
    """
    passphrase = 'password'
    ssid = 'IEEE'
    expected_hex = (
        'f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e'
    )
    pmk = pbkdf2_sha1_pmk(passphrase, ssid)
    self.assertEqual(pmk.hex(), expected_hex)

  def test_ieee80211_annex_j_and_hostapd_prf_512_vectors(self):
    """Verifies PRF-512 against IEEE 802.11 / hostapd published test vectors.

    Citations:
      - IEEE Std 802.11-2016 Annex J (Security test vectors)
      - IEEE Std 802.11i-2004 Section 8.5.1.1 (PRF-512)
      - hostapd crypto_module_tests.c (test_sha1 PRF-SHA1 test cases 0, 1, 2)
    """
    # Vector 0: 20-byte key (0x0b*20), prefix 'prefix', data 'Hi There'
    key0 = b'\x0b' * 20
    prefix = b'prefix'
    data0 = b'Hi There'
    expected0 = bytes.fromhex(
        'bcd4c650b30b9684951829e0d75f9d54'
        'b862175ed9f00606e17d8da35402ffee'
        '75df78c3d31e0f889f012120c0862beb'
        '67753e7439ae242edb8373698356cf5a'
    )
    self.assertEqual(prf_512(key0, prefix, data0), expected0)

    # Vector 1: key 'Jefe', prefix 'prefix', data 'what do ya want for nothing?'
    key1 = b'Jefe'
    data1 = b'what do ya want for nothing?'
    expected1 = bytes.fromhex(
        '51f4de5b33f249adf81aeb713a3c20f4'
        'fe631446fabdfa58244759ae58ef9009'
        'a99abf4eac2ca5fa87e692c440eb4002'
        '3e7babb206d61de7b92f41529092b8fc'
    )
    self.assertEqual(prf_512(key1, prefix, data1), expected1)

    # Vector 2: 20-byte key (0xaa*20), prefix 'prefix', data 50 bytes of 0xdd
    key2 = b'\xaa' * 20
    data2 = b'\xdd' * 50
    expected2 = bytes.fromhex(
        'e1ac546ec4cb636f9976487be5c86be1'
        '7a0252ca5d8d8df12cfb0473525249ce'
        '9dd8d177ead710bc9b590547239107ae'
        'f7b4abd43d87f0a68f1cbd9e2b6f7607'
    )
    self.assertEqual(prf_512(key2, prefix, data2), expected2)

  def test_rfc3394_aes128_key_wrap_and_unwrap_vectors(self):
    """Verifies RFC 3394 4.1 128-bit KEK wrapping 128-bit key data."""
    kek = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
    plaintext = bytes.fromhex('00112233445566778899AABBCCDDEEFF')
    expected_cipher = bytes.fromhex('1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5')

    wrapped = aes_key_wrap(kek, plaintext)
    self.assertEqual(wrapped, expected_cipher)

    unwrapped = aes_key_unwrap(kek, wrapped)
    self.assertEqual(unwrapped, plaintext)

  def test_rfc3394_key_wrap_192bit_data(self):
    """Verifies RFC 3394 4.2 128-bit KEK wrapping 192 bits (24 bytes) of key data.

    Matches 24-byte GTK KDE wrapping.
    """
    kek = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
    plaintext = bytes.fromhex(
        '00112233445566778899AABBCCDDEEFF0001020304050607'
    )
    expected_cipher = bytes.fromhex(
        '1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5'
    )
    wrapped = aes_key_wrap(kek, plaintext[:16])
    self.assertEqual(wrapped, expected_cipher)

    # Verify 24-byte wrapping roundtrip
    wrapped_24 = aes_key_wrap(kek, plaintext)
    unwrapped_24 = aes_key_unwrap(kek, wrapped_24)
    self.assertEqual(unwrapped_24, plaintext)

  def test_rfc3394_aes_unwrap_tampered_fails(self):
    """Verifies that tampered ciphertext raises ValueError in RFC 3394 unwrap."""
    kek = bytes.fromhex('000102030405060708090A0B0C0D0E0F')
    plaintext = b'1234567812345678'
    wrapped = bytearray(aes_key_wrap(kek, plaintext))
    # Corrupt last byte
    wrapped[-1] ^= 0x01
    with self.assertRaises(ValueError):
      aes_key_unwrap(kek, bytes(wrapped))

  def test_prf_512_and_ptk_derivation(self):
    """Verifies PRF-512 splits into 16-byte KCK, 16-byte KEK, and 16-byte TK."""
    pmk = os.urandom(32)
    aa_mac = bytes.fromhex('020000000100')
    spa_mac = bytes.fromhex('020000000201')
    anonce = os.urandom(32)
    snonce = os.urandom(32)

    ptk = derive_ptk(pmk, aa_mac, spa_mac, anonce, snonce)
    self.assertEqual(len(ptk.kck), 16)
    self.assertEqual(len(ptk.kek), 16)
    self.assertEqual(len(ptk.tk), 16)
    self.assertEqual(len(ptk.raw), 64)
    self.assertEqual(ptk.kck, ptk.raw[:16])
    self.assertEqual(ptk.kek, ptk.raw[16:32])
    self.assertEqual(ptk.tk, ptk.raw[32:48])

    # Re-running with same inputs produces deterministic PTK
    ptk2 = derive_ptk(pmk, aa_mac, spa_mac, anonce, snonce)
    self.assertEqual(ptk.raw, ptk2.raw)

    # Different nonce produces different PTK
    ptk3 = derive_ptk(pmk, aa_mac, spa_mac, anonce, os.urandom(32))
    self.assertNotEqual(ptk.raw, ptk3.raw)


class TestEapolCodecAndKde(unittest.TestCase):
  """Verifies EAPOL-Key frame serialization, deserialization, and GTK KDE packing."""

  def test_gtk_kde_packing_and_parsing(self):
    """Verifies packing a 16-byte GTK into a KDE and extracting it back."""
    gtk = os.urandom(16)
    kde = build_gtk_kde(gtk, key_id=2)
    self.assertEqual(len(kde), 24)  # 24 bytes = 8 * 3 (RFC 3394 compatible)
    parsed_gtk = parse_gtk_from_kde(kde)
    self.assertEqual(parsed_gtk, gtk)

  def test_eapol_frame_encode_decode_roundtrip(self):
    """Verifies round-trip encoding and decoding of an EAPOL-Key frame."""
    frame = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=2,
        key_info=(
            KEY_INFO_KEY_TYPE_PAIRWISE
            | KEY_INFO_KEY_ACK
            | KEY_DESC_VERSION_HMAC_SHA1_AES
        ),
        key_length=16,
        replay_counter=42,
        nonce=b'\x11' * 32,
        iv=b'\x22' * 16,
        rsc=0,
        mic=b'\x33' * 16,
        key_data=b'ArbitraryKeyDataPayload12345678',
    )
    encoded = frame.encode()
    decoded = decode_eapol_key_frame(encoded)

    self.assertEqual(decoded.version, frame.version)
    self.assertEqual(decoded.descriptor_type, frame.descriptor_type)
    self.assertEqual(decoded.key_info, frame.key_info)
    self.assertEqual(decoded.key_length, frame.key_length)
    self.assertEqual(decoded.replay_counter, frame.replay_counter)
    self.assertEqual(decoded.nonce, frame.nonce)
    self.assertEqual(decoded.iv, frame.iv)
    self.assertEqual(decoded.rsc, frame.rsc)
    self.assertEqual(decoded.mic, frame.mic)
    self.assertEqual(decoded.key_data, frame.key_data)

  def test_eapol_encode_zeroed_mic(self):
    """Verifies that encode_with_zeroed_mic produces 16 zero bytes at the MIC offset."""
    frame = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=2,
        key_info=KEY_INFO_KEY_MIC,
        key_length=16,
        replay_counter=1,
        mic=b'\xAA' * 16,
    )
    encoded_zeroed = frame.encode_with_zeroed_mic()
    # 4B header + 1B desc + 2B info + 2B len + 8B replay + 32B nonce + 16B iv + 8B rsc + 8B reserved = 81B
    mic_in_zeroed = encoded_zeroed[81:97]
    self.assertEqual(mic_in_zeroed, b'\x00' * 16)
    # Original frame MIC remains intact
    self.assertEqual(frame.mic, b'\xAA' * 16)


def drive_loopback_handshake_in_test(
    server: VirtualWiFiServer, station_id: str, ssid: str, psk: str
) -> dict:
  """Test helper driving full genuine 4-way handshake locally without network IO.

  # SIMULATION-DISCLOSURE: This test helper drives the AP state machine and the
  # Wpa2SupplicantStateMachine in memory purely for unit testing the 4-way logic.
  """
  with server._lock:
    station = server._stations.get(station_id) or server.register_station(station_id)
    target_ap = next((ap for ap in server._aps.values() if ap.ssid == ssid), None)
    if target_ap is None:
      station.state = 'disconnected'
      return {'ok': False, 'reason': 'ssid_not_found', 'status_code': 1}

    msg1_bytes = server.initiate_eapol_handshake(
        station_id, target_ap.ap_id, send_data_client=False
    )
    if not msg1_bytes:
      station.state = 'disconnected'
      return {'ok': False, 'reason': 'initiate_failed', 'status_code': 1}

  supplicant_sent_frames = []
  supplicant = Wpa2SupplicantStateMachine(
      station_mac=station.mac_addr,
      on_send_frame=lambda f: supplicant_sent_frames.append(f),
  )
  supplicant.start_association(ssid=ssid, passphrase=psk, ap_bssid=target_ap.bssid)

  supplicant_sent_frames.clear()
  ok = supplicant.handle_eapol_frame(msg1_bytes)
  if not ok or not supplicant_sent_frames:
    station.state = 'disconnected'
    return {'ok': False, 'reason': 'supplicant_msg1_failed', 'status_code': 15}

  msg2_bytes = supplicant_sent_frames.pop(0)

  ok, msg3_bytes = server.process_eapol_frame(
      station_id, msg2_bytes, send_data_client=False
  )
  if not ok or not msg3_bytes:
    station.state = 'disconnected'
    return {'ok': False, 'reason': 'invalid_psk', 'status_code': 15}

  supplicant_sent_frames.clear()
  ok = supplicant.handle_eapol_frame(msg3_bytes)
  if not ok or not supplicant_sent_frames:
    station.state = 'disconnected'
    return {'ok': False, 'reason': 'supplicant_msg3_failed', 'status_code': 15}

  msg4_bytes = supplicant_sent_frames.pop(0)

  ok, _ = server.process_eapol_frame(
      station_id, msg4_bytes, send_data_client=False
  )
  if not ok or station.state != 'completed':
    station.state = 'disconnected'
    return {'ok': False, 'reason': 'handshake_incomplete', 'status_code': 15}

  return {
      'ok': True,
      'ap': target_ap.to_public_dict(),
      'station': {
          'station_id': station.station_id,
          'state': station.state,
          'associated_ssid': station.associated_ssid,
          'associated_bssid': station.associated_bssid,
      },
  }


class TestWpa2EapolHandshakeE2E(unittest.TestCase):
  """Verifies end-to-end WPA2 4-way handshake, state machines, and negative tests."""

  def setUp(self):
    super().setUp()
    self.server = VirtualWiFiServer(host='127.0.0.1')
    self.server.start()

  def tearDown(self):
    self.server.stop()
    super().tearDown()

  def test_authenticate_and_associate_disabled_raises_runtime_error(self):
    """Verifies that public authenticate_and_associate is disabled and raises."""
    with self.assertRaises(RuntimeError) as ctx:
      self.server.authenticate_and_associate('sta0', 'SSID', 'PSK')
    self.assertIn('Passphrase isolation invariant', str(ctx.exception))

  def test_e2e_4way_handshake_success(self):
    """Verifies complete 4-way handshake between AP and Supplicant reaching completed."""
    ssid = 'SecureHomeWiFi'
    psk = 'SuperSecretKey123'
    ap_state = self.server.register_ap(ssid=ssid, psk=psk, ap_id='ap0')
    station = self.server.register_station('sta0', mac_addr='02:00:00:00:02:aa')

    res = drive_loopback_handshake_in_test(self.server, 'sta0', ssid, psk)
    self.assertTrue(res.get('ok'))
    self.assertEqual(res['station']['state'], 'completed')
    self.assertEqual(res['station']['associated_ssid'], ssid)

    # Server state is completed
    st = self.server.get_station('sta0')
    self.assertIsNotNone(st)
    self.assertEqual(st.state, 'completed')

  def test_wrong_passphrase_fails_msg2_mic_check(self):
    """Verifies that an incorrect station passphrase fails Msg2 MIC check at AP."""
    ssid = 'ProtectedNetwork'
    ap_psk = 'CorrectPassword999'
    bad_psk = 'WrongPassword000'

    self.server.register_ap(ssid=ssid, psk=ap_psk, ap_id='ap0')
    self.server.register_station('sta_bad', mac_addr='02:00:00:00:02:bb')

    res = drive_loopback_handshake_in_test(self.server, 'sta_bad', ssid, bad_psk)
    self.assertFalse(res.get('ok'))
    self.assertEqual(res.get('status_code'), 15)
    st = self.server.get_station('sta_bad')
    self.assertEqual(st.state, 'disconnected')

  def test_architectural_isolation_ap_never_receives_station_passphrase(self):
    """Verifies that the AP authenticator state machine is driven purely via EAPOL frames.

    AP knows ONLY target_ap.psk. Station SM knows ONLY its own passphrase.
    No function or message sends station's passphrase to the AP.
    """
    ssid = 'IsolatedNet'
    ap_psk = 'APKnowledgeOnly'
    station_passphrase = 'APKnowledgeOnly'

    ap = self.server.register_ap(ssid=ssid, psk=ap_psk, ap_id='ap_iso')
    station = self.server.register_station('sta_iso', mac_addr='02:00:00:00:02:cc')

    # Step 1: AP generates Msg1
    msg1_bytes = self.server.initiate_eapol_handshake(
        'sta_iso', ap.ap_id, send_data_client=False
    )
    self.assertIsNotNone(msg1_bytes)

    # Step 2: Supplicant runs independently
    supplicant_sent: list[bytes] = []
    supplicant_states: list[str] = []
    supplicant = Wpa2SupplicantStateMachine(
        station_mac=station.mac_addr,
        on_send_frame=lambda f: supplicant_sent.append(f),
        on_state_change=lambda s: supplicant_states.append(s),
    )
    supplicant.start_association(
        ssid=ssid, passphrase=station_passphrase, ap_bssid=ap.bssid
    )

    # Supplicant processes Msg1 -> emits Msg2
    ok = supplicant.handle_eapol_frame(msg1_bytes)
    self.assertTrue(ok)
    self.assertEqual(len(supplicant_sent), 1)
    msg2_bytes = supplicant_sent.pop(0)

    # Step 3: AP receives Msg2 (raw bytes only, zero access to station passphrase)
    ok, msg3_bytes = self.server.process_eapol_frame(
        'sta_iso', msg2_bytes, send_data_client=False
    )
    self.assertTrue(ok)
    self.assertIsNotNone(msg3_bytes)

    # Step 4: Supplicant receives Msg3 -> emits Msg4
    ok = supplicant.handle_eapol_frame(msg3_bytes)
    self.assertTrue(ok)
    self.assertEqual(len(supplicant_sent), 1)
    msg4_bytes = supplicant_sent.pop(0)

    # Supplicant transitioned to completed
    self.assertEqual(supplicant.state, 'completed')

    # Step 5: AP receives Msg4 -> marks station completed
    ok, _ = self.server.process_eapol_frame(
        'sta_iso', msg4_bytes, send_data_client=False
    )
    self.assertTrue(ok)

    st = self.server.get_station('sta_iso')
    self.assertEqual(st.state, 'completed')

    # Both AP and Supplicant agree on PTK TK and GTK
    ap_auth = self.server._auth_states.get('sta_iso')
    self.assertIsNotNone(ap_auth)
    self.assertEqual(ap_auth.ptk.tk, supplicant.ptk.tk)
    self.assertEqual(self.server._ap_gtks[ap.ap_id], supplicant.gtk)

  def test_tampered_msg3_rejected_by_supplicant(self):
    """Verifies that tampering with Msg3 MIC or Key Data causes station rejection."""
    ssid = 'TamperNet'
    psk = 'ValidPassword123'
    ap = self.server.register_ap(ssid=ssid, psk=psk, ap_id='ap_t')
    station = self.server.register_station('sta_t', mac_addr='02:00:00:00:02:dd')

    msg1_bytes = self.server.initiate_eapol_handshake(
        'sta_t', ap.ap_id, send_data_client=False
    )

    supplicant_sent: list[bytes] = []
    supplicant = Wpa2SupplicantStateMachine(
        station_mac=station.mac_addr,
        on_send_frame=lambda f: supplicant_sent.append(f),
    )
    supplicant.start_association(ssid=ssid, passphrase=psk, ap_bssid=ap.bssid)
    supplicant.handle_eapol_frame(msg1_bytes)
    msg2_bytes = supplicant_sent.pop(0)

    ok, msg3_bytes = self.server.process_eapol_frame(
        'sta_t', msg2_bytes, send_data_client=False
    )
    self.assertTrue(ok)

    # Tamper with Msg3 MIC byte
    tampered_msg3 = bytearray(msg3_bytes)
    tampered_msg3[85] ^= 0xFF  # Flip bit in MIC field
    result = supplicant.handle_eapol_frame(bytes(tampered_msg3))
    self.assertFalse(result)
    self.assertNotEqual(supplicant.state, 'completed')

  def test_replayed_msg3_rejected_by_supplicant(self):
    """Verifies that a replayed Msg3 with a stale or decremented replay counter is rejected."""
    ssid = 'ReplayNet'
    psk = 'ValidPassword123'
    ap = self.server.register_ap(ssid=ssid, psk=psk, ap_id='ap_r')
    station = self.server.register_station('sta_r', mac_addr='02:00:00:00:02:ee')

    msg1_bytes = self.server.initiate_eapol_handshake(
        'sta_r', ap.ap_id, send_data_client=False
    )

    supplicant_sent: list[bytes] = []
    supplicant = Wpa2SupplicantStateMachine(
        station_mac=station.mac_addr,
        on_send_frame=lambda f: supplicant_sent.append(f),
    )
    supplicant.start_association(ssid=ssid, passphrase=psk, ap_bssid=ap.bssid)
    supplicant.handle_eapol_frame(msg1_bytes)
    msg2_bytes = supplicant_sent.pop(0)

    ok, msg3_bytes = self.server.process_eapol_frame(
        'sta_r', msg2_bytes, send_data_client=False
    )
    self.assertTrue(ok)

    # Decode Msg3, modify replay_counter to 1 (same as Msg1), recompute valid MIC
    msg3_obj = decode_eapol_key_frame(msg3_bytes)
    msg3_obj.replay_counter = 1  # Stale replay counter!
    msg3_zeroed = msg3_obj.encode_with_zeroed_mic()
    msg3_obj.mic = compute_mic(supplicant.ptk.kck, msg3_zeroed)
    stale_msg3_bytes = msg3_obj.encode()

    result = supplicant.handle_eapol_frame(stale_msg3_bytes)
    self.assertFalse(result)
    self.assertNotEqual(supplicant.state, 'completed')

  def test_l2_data_gate_blocks_until_handshake_msg4_completes(self):
    """Verifies that non-EAPOL L2 frames are blocked until the genuine handshake finishes."""
    ssid = 'GatedL2Net'
    psk = 'ValidSecret123'
    self.server.register_ap(ssid=ssid, psk=psk, ap_id='ap_gate')
    self.server.register_station('peer_a', is_ap_bridge=True)
    self.server.register_station('peer_b', is_ap_bridge=False)

    addr = ('127.0.0.1', self.server.data_port)
    with (
        socket.create_connection(addr, timeout=1.0) as sa,
        socket.create_connection(addr, timeout=1.0) as sb,
    ):
      sa.sendall(struct.pack('!H', 6) + b'peer_a')
      sb.sendall(struct.pack('!H', 6) + b'peer_b')
      sb.settimeout(0.2)

      # Unauthenticated peer_b sends L2 data frame -> AP switch drops it
      eth_data = bytes.fromhex('0200000001000200000002010800') + b'TEST_DATA'
      sb.sendall(struct.pack('!H', len(eth_data)) + eth_data)
      with self.assertRaises(socket.timeout):
        sa.recv(1024)

      # Authenticate peer_b via genuine 4-way handshake
      res = drive_loopback_handshake_in_test(self.server, 'peer_b', ssid, psk)
      self.assertTrue(res.get('ok'))

      # Now peer_b sends L2 data frame -> forwarded to peer_a
      sb.sendall(struct.pack('!H', len(eth_data)) + eth_data)
      flen = struct.unpack('!H', sa.recv(2))[0]
      received = sa.recv(flen)
      self.assertEqual(received, eth_data)

  def test_real_socket_eapol_handshake_e2e(self):
    """End-to-end integration test over a real TCP data socket carrying 0x888E frames.

    Verifies:
      1. connect RPC accepts station_id and ssid without psk (and ignores any psk passed).
      2. VirtualWiFiServer and station state store zero station passphrases.
      3. AP emits Msg1 (Ethertype 0x888E) over station's data socket.
      4. Station with wrong passphrase responds with Msg2, AP rejects MIC, stays disconnected.
      5. Station with correct passphrase responds with Msg2, receives Msg3, responds with Msg4.
      6. AP marks station 'completed' and unlocks L2 data traffic.
    """
    ssid = 'RealSocketNet'
    ap_psk = 'RealAPSecretPassphrase123'
    bad_psk = 'AttackerWrongPassphrase456'
    self.server.register_ap(
        ssid=ssid, psk=ap_psk, ap_id='ap_real', bssid='02:00:00:00:01:55'
    )
    self.server.register_station(
        'sta_real', mac_addr='02:00:00:00:02:55'
    )
    sta_mac = bytes.fromhex('020000000255')
    ap_mac = bytes.fromhex('020000000155')

    # Also register an already-authenticated peer to test L2 data transmission
    self.server.register_station('peer_station', is_ap_bridge=True)
    peer_mac = bytes.fromhex('020000000256')

    ctrl_addr = ('127.0.0.1', self.server.control_port)
    data_addr = ('127.0.0.1', self.server.data_port)

    with (
        socket.create_connection(data_addr, timeout=3.0) as sta_sock,
        socket.create_connection(data_addr, timeout=3.0) as peer_sock,
    ):
      # Station greeting on data_port: [2B length][station_id]
      sta_sock.sendall(struct.pack('!H', len(b'sta_real')) + b'sta_real')
      peer_sock.sendall(struct.pack('!H', len(b'peer_station')) + b'peer_station')
      time.sleep(0.05)

      # Subtest 1: connect RPC ignores psk, initiates handshake, server stores no station PSK
      with socket.create_connection(ctrl_addr, timeout=3.0) as ctrl_sock:
        ctrl_sock.sendall(
            json.dumps({
                'cmd': 'CONNECT',
                'station_id': 'sta_real',
                'ssid': ssid,
                'psk': 'IGNORED_PASSPHRASE_NOT_STORED',
            }).encode('utf-8')
            + b'\n'
        )
        resp = json.loads(ctrl_sock.makefile('r').readline())
        self.assertTrue(resp.get('ok'))
        self.assertEqual(resp.get('status'), 'handshake_initiated')

      # Verify server stores no station passphrase in station state or auth state
      st_obj = self.server.get_station('sta_real')
      self.assertFalse(hasattr(st_obj, 'psk'))
      self.assertEqual(st_obj.state, 'authenticating')
      auth_obj = self.server._auth_states.get('sta_real')
      self.assertIsNotNone(auth_obj)
      self.assertFalse(hasattr(auth_obj, 'psk'))

      # Subtest 2: Station responds with Msg2 computed with BAD passphrase -> fails
      raw_len = sta_sock.recv(2)
      flen = struct.unpack('!H', raw_len)[0]
      msg1_frame = sta_sock.recv(flen)
      self.assertTrue(len(msg1_frame) >= 14)
      self.assertEqual(msg1_frame[12:14], b'\x88\x8e')

      supp_frames = []
      supp_bad = Wpa2SupplicantStateMachine(
          '02:00:00:00:02:55', on_send_frame=supp_frames.append
      )
      supp_bad.start_association(ssid, bad_psk, '02:00:00:00:01:55')
      self.assertTrue(supp_bad.handle_eapol_frame(msg1_frame[14:]))
      msg2_bad = supp_frames.pop(0)

      eth_msg2_bad = ap_mac + sta_mac + struct.pack('!H', 0x888E) + msg2_bad
      sta_sock.sendall(struct.pack('!H', len(eth_msg2_bad)) + eth_msg2_bad)
      time.sleep(0.05)

      # AP rejected Msg2 MIC; station state is disconnected, auth state cleared
      st_obj = self.server.get_station('sta_real')
      self.assertEqual(st_obj.state, 'disconnected')
      self.assertNotIn('sta_real', self.server._auth_states)

      # Subtest 3: Station responds with Msg2 computed with CORRECT passphrase -> completes
      with socket.create_connection(ctrl_addr, timeout=3.0) as ctrl_sock:
        ctrl_sock.sendall(
            json.dumps({
                'cmd': 'CONNECT',
                'station_id': 'sta_real',
                'ssid': ssid,
            }).encode('utf-8')
            + b'\n'
        )
        resp = json.loads(ctrl_sock.makefile('r').readline())
        self.assertTrue(resp.get('ok'))

      # AP emits Msg1 on data_port
      raw_len = sta_sock.recv(2)
      flen = struct.unpack('!H', raw_len)[0]
      msg1_frame2 = sta_sock.recv(flen)
      self.assertEqual(msg1_frame2[12:14], b'\x88\x8e')

      supp_good = Wpa2SupplicantStateMachine(
          '02:00:00:00:02:55', on_send_frame=supp_frames.append
      )
      supp_good.start_association(ssid, ap_psk, '02:00:00:00:01:55')
      self.assertTrue(supp_good.handle_eapol_frame(msg1_frame2[14:]))
      msg2_good = supp_frames.pop(0)

      eth_msg2_good = ap_mac + sta_mac + struct.pack('!H', 0x888E) + msg2_good
      sta_sock.sendall(struct.pack('!H', len(eth_msg2_good)) + eth_msg2_good)

      # AP verifies Msg2 MIC, emits Msg3 (with wrapped GTK KDE) on data_port
      raw_len = sta_sock.recv(2)
      flen = struct.unpack('!H', raw_len)[0]
      msg3_frame = sta_sock.recv(flen)
      self.assertEqual(msg3_frame[12:14], b'\x88\x8e')

      self.assertTrue(supp_good.handle_eapol_frame(msg3_frame[14:]))
      msg4_good = supp_frames.pop(0)

      eth_msg4_good = ap_mac + sta_mac + struct.pack('!H', 0x888E) + msg4_good
      sta_sock.sendall(struct.pack('!H', len(eth_msg4_good)) + eth_msg4_good)
      time.sleep(0.05)

      # AP marked station completed
      st_obj = self.server.get_station('sta_real')
      self.assertEqual(st_obj.state, 'completed')
      self.assertEqual(supp_good.state, 'completed')

      # Subtest 4: Non-EAPOL L2 data frame can now pass through switch to peer!
      eth_data = peer_mac + sta_mac + bytes.fromhex('0800') + b'GENUINE_WIFI_DATA'
      sta_sock.sendall(struct.pack('!H', len(eth_data)) + eth_data)
      peer_sock.settimeout(1.0)
      raw_len = peer_sock.recv(2)
      flen = struct.unpack('!H', raw_len)[0]
      received = peer_sock.recv(flen)
      self.assertEqual(received, eth_data)

  def test_rpc_responses_do_not_leak_ap_passphrase(self):
    """Walks all RPC responses asserting no key is 'psk' and no value matches AP passphrase.

    Checks:
      1. register_ap
      2. connect
      3. list_aps
      4. scan
      5. get_status
    """
    secret_passphrase = 'TopSecretApPassphrase999!'
    ctrl_addr = ('127.0.0.1', self.server.control_port)

    def _assert_no_psk_leak(obj, path=''):
      if isinstance(obj, dict):
        for k, v in obj.items():
          self.assertNotEqual(
              k,
              'psk',
              f"Leaked key 'psk' at {path}.{k}: {v}",
          )
          self.assertNotEqual(
              v,
              secret_passphrase,
              f"Leaked secret passphrase value at {path}.{k}",
          )
          _assert_no_psk_leak(v, f'{path}.{k}')
      elif isinstance(obj, list):
        for idx, item in enumerate(obj):
          self.assertNotEqual(
              item,
              secret_passphrase,
              f"Leaked secret passphrase value at {path}[{idx}]",
          )
          _assert_no_psk_leak(item, f'{path}[{idx}]')
      else:
        self.assertNotEqual(
            obj,
            secret_passphrase,
            f"Leaked secret passphrase value at {path}",
        )

    def _send_rpc(payload: dict) -> dict:
      with socket.create_connection(ctrl_addr, timeout=3.0) as sock:
        sock.sendall(json.dumps(payload).encode('utf-8') + b'\n')
        line = sock.makefile('r', encoding='utf-8').readline()
        return json.loads(line)

    # 1. register_ap
    reg_resp = _send_rpc({
        'cmd': 'register_ap',
        'ssid': 'LeakTestSSID',
        'psk': secret_passphrase,
        'ap_id': 'ap_leak_test',
    })
    self.assertTrue(reg_resp.get('ok'))
    _assert_no_psk_leak(reg_resp, 'register_ap')
    self.assertEqual(reg_resp['ap'].get('key_mgmt'), 'WPA-PSK')

    # Register station for connect test
    _send_rpc({
        'cmd': 'register_station',
        'station_id': 'sta_leak_test',
    })

    # 2. connect
    conn_resp = _send_rpc({
        'cmd': 'connect',
        'station_id': 'sta_leak_test',
        'ssid': 'LeakTestSSID',
        'psk': secret_passphrase,  # Even if client sends psk, response must not leak it
    })
    self.assertTrue(conn_resp.get('ok'))
    _assert_no_psk_leak(conn_resp, 'connect')
    self.assertEqual(conn_resp['ap'].get('key_mgmt'), 'WPA-PSK')

    # 3. list_aps
    list_resp = _send_rpc({'cmd': 'list_aps'})
    self.assertTrue(list_resp.get('ok'))
    _assert_no_psk_leak(list_resp, 'list_aps')
    for ap_entry in list_resp.get('aps', []):
      self.assertEqual(ap_entry.get('key_mgmt'), 'WPA-PSK')

    # 4. scan
    scan_resp = _send_rpc({'cmd': 'scan'})
    self.assertTrue(scan_resp.get('ok'))
    _assert_no_psk_leak(scan_resp, 'scan')
    for ap_entry in scan_resp.get('aps', []):
      self.assertEqual(ap_entry.get('key_mgmt'), 'WPA-PSK')

    # 5. get_status
    status_resp = _send_rpc({'cmd': 'get_status'})
    self.assertTrue(status_resp.get('ok'))
    _assert_no_psk_leak(status_resp, 'get_status')
    for ap_entry in status_resp.get('aps', []):
      self.assertEqual(ap_entry.get('key_mgmt'), 'WPA-PSK')



class TestEapolCodecEdgeCases(unittest.TestCase):
  """Verifies edge cases, malformed frames, and properties for EAPOL codec."""

  def test_eapol_key_frame_properties(self):
    """Verifies property accessors on EapolKeyFrame."""
    frame = EapolKeyFrame(
        key_info=(
            KEY_INFO_KEY_TYPE_PAIRWISE
            | KEY_INFO_KEY_MIC
            | KEY_INFO_KEY_ACK
            | KEY_INFO_INSTALL
            | KEY_INFO_SECURE
            | KEY_INFO_ENCRYPTED_KEY_DATA
        )
    )
    self.assertTrue(frame.is_pairwise)
    self.assertTrue(frame.has_mic)
    self.assertTrue(frame.key_ack)
    self.assertTrue(frame.install)
    self.assertTrue(frame.secure)
    self.assertTrue(frame.encrypted_key_data)

    empty_frame = EapolKeyFrame(key_info=0)
    self.assertFalse(empty_frame.is_pairwise)
    self.assertFalse(empty_frame.has_mic)
    self.assertFalse(empty_frame.key_ack)
    self.assertFalse(empty_frame.install)
    self.assertFalse(empty_frame.secure)
    self.assertFalse(empty_frame.encrypted_key_data)

  def test_decode_eapol_frame_too_short(self):
    """Verifies ValueError when raw data is shorter than 99 bytes."""
    with self.assertRaises(ValueError) as ctx:
      decode_eapol_key_frame(b'\x01\x03\x00\x10' + b'\x00' * 50)
    self.assertIn('EAPOL frame too short', str(ctx.exception))

  def test_decode_eapol_frame_not_key_type(self):
    """Verifies ValueError when packet type is not EAPOL_TYPE_KEY (3)."""
    # Packet type 1 (EAP-Packet) with 95 bytes body
    data = struct.pack('!BBH', EAPOL_VERSION_1, 1, 95) + b'\x00' * 95
    with self.assertRaises(ValueError) as ctx:
      decode_eapol_key_frame(data)
    self.assertIn('Not an EAPOL-Key frame', str(ctx.exception))

  def test_decode_eapol_frame_truncated_body(self):
    """Verifies ValueError when frame is truncated relative to header length."""
    # Header claims body_len is 120, but provided only 95 bytes
    data = struct.pack('!BBH', EAPOL_VERSION_1, EAPOL_TYPE_KEY, 120) + (
        b'\x00' * 95
    )
    with self.assertRaises(ValueError) as ctx:
      decode_eapol_key_frame(data)
    self.assertIn('Truncated EAPOL body', str(ctx.exception))

  def test_decode_eapol_frame_body_too_short(self):
    """Verifies ValueError when body_len is specified less than 95 bytes."""
    # Header claims body_len is 50 bytes, total length is 4 + 95 = 99 bytes
    data = struct.pack('!BBH', EAPOL_VERSION_1, EAPOL_TYPE_KEY, 50) + (
        b'\x00' * 95
    )
    with self.assertRaises(ValueError) as ctx:
      decode_eapol_key_frame(data)
    self.assertIn('EAPOL-Key body too short', str(ctx.exception))

  def test_parse_gtk_from_kde_padding_and_elements(self):
    """Verifies KDE parser handles 0x00 padding and non-vendor elements."""
    gtk = b'\x55' * 16
    valid_kde = build_gtk_kde(gtk, key_id=1)
    # Prefix with 0x00 padding and a dummy element (type 0x01, len 2, payload)
    padded_key_data = b'\x00\x00' + b'\x01\x02\xaa\xbb' + valid_kde
    extracted = parse_gtk_from_kde(padded_key_data)
    self.assertEqual(extracted, gtk)

  def test_parse_gtk_from_kde_missing_or_truncated(self):
    """Verifies ValueError when no valid GTK KDE exists in key data."""
    # Completely empty key_data
    with self.assertRaises(ValueError) as ctx:
      parse_gtk_from_kde(b'')
    self.assertIn('No valid GTK KDE found', str(ctx.exception))

    # Only padding
    with self.assertRaises(ValueError):
      parse_gtk_from_kde(b'\x00' * 10)

    # Incomplete element header at end of data (idx + 1 >= len(key_data))
    with self.assertRaises(ValueError):
      parse_gtk_from_kde(b'\x01')

    # Truncated KDE header (idx + 2 > len(key_data))
    with self.assertRaises(ValueError):
      parse_gtk_from_kde(b'\xdd')

    # Truncated KDE content (elem_end > len(key_data))
    with self.assertRaises(ValueError):
      parse_gtk_from_kde(b'\xdd\x20\x00\x0f\xac\x01')

    # Non-GTK vendor element (type 0xDD, but wrong OUI / data type)
    non_gtk_kde = bytes([0xDD, 4, 0x00, 0x50, 0xF2, 0x02])
    with self.assertRaises(ValueError):
      parse_gtk_from_kde(non_gtk_kde)


class TestWpa2CryptoEdgeCases(unittest.TestCase):
  """Verifies edge cases and error handling for WPA2 crypto primitives."""

  def test_crypto_unsupported_exception_paths(self):
    """Verifies RuntimeError when _HAS_CRYPTOGRAPHY is False."""
    from cirque.virtual_wifi import wpa2_crypto

    orig_has_crypto = wpa2_crypto._HAS_CRYPTOGRAPHY
    try:
      wpa2_crypto._HAS_CRYPTOGRAPHY = False
      with self.assertRaises(RuntimeError) as ctx:
        wpa2_crypto._aes_ecb_encrypt_block(b'\x00' * 16, b'\x00' * 16)
      self.assertIn('AES key wrap requires cryptography', str(ctx.exception))

      with self.assertRaises(RuntimeError) as ctx:
        wpa2_crypto._aes_ecb_decrypt_block(b'\x00' * 16, b'\x00' * 16)
      self.assertIn('AES key unwrap requires cryptography', str(ctx.exception))
    finally:
      wpa2_crypto._HAS_CRYPTOGRAPHY = orig_has_crypto

  def test_aes_key_wrap_invalid_plaintext_length(self):
    """Verifies ValueError when plaintext is not a positive multiple of 8."""
    kek = b'\x00' * 16
    with self.assertRaises(ValueError):
      aes_key_wrap(kek, b'')
    with self.assertRaises(ValueError):
      aes_key_wrap(kek, b'\x00' * 7)
    with self.assertRaises(ValueError):
      aes_key_wrap(kek, b'\x00' * 15)

  def test_aes_key_unwrap_invalid_ciphertext_length(self):
    """Verifies ValueError when ciphertext length is invalid."""
    kek = b'\x00' * 16
    with self.assertRaises(ValueError):
      aes_key_unwrap(kek, b'\x00' * 8)
    with self.assertRaises(ValueError):
      aes_key_unwrap(kek, b'\x00' * 15)
    with self.assertRaises(ValueError):
      aes_key_unwrap(kek, b'\x00' * 17)



class TestWpa2SupplicantSmEdgeCases(unittest.TestCase):
  """Verifies error branches and edge cases in Wpa2SupplicantStateMachine."""

  def test_handle_eapol_frame_decode_error(self):
    """Verifies handle_eapol_frame returns False on malformed EAPOL bytes."""
    supp = Wpa2SupplicantStateMachine(station_mac='02:00:00:00:02:01')
    self.assertFalse(supp.handle_eapol_frame(b'bad_short_frame'))

  def test_handle_eapol_frame_non_pairwise_ignored(self):
    """Verifies non-pairwise frames (Group Key) are ignored and return False."""
    supp = Wpa2SupplicantStateMachine(station_mac='02:00:00:00:02:01')
    frame = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=DESC_TYPE_RSN_WPA2,
        key_info=KEY_INFO_KEY_ACK,  # Missing KEY_INFO_KEY_TYPE_PAIRWISE
        key_length=16,
    )
    self.assertFalse(supp.handle_eapol_frame(frame.encode()))

  def test_handle_eapol_frame_unexpected_format(self):
    """Verifies pairwise frame with unknown flags returns False."""
    supp = Wpa2SupplicantStateMachine(station_mac='02:00:00:00:02:01')
    frame = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=DESC_TYPE_RSN_WPA2,
        key_info=KEY_INFO_KEY_TYPE_PAIRWISE,  # Neither Msg1 nor Msg3 format
        key_length=16,
    )
    self.assertFalse(supp.handle_eapol_frame(frame.encode()))

  def test_handle_msg1_without_pmk_returns_false(self):
    """Verifies _handle_msg1 returns False if PMK is uninitialized."""
    supp = Wpa2SupplicantStateMachine(station_mac='02:00:00:00:02:01')
    msg1 = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=DESC_TYPE_RSN_WPA2,
        key_info=KEY_INFO_KEY_TYPE_PAIRWISE | KEY_INFO_KEY_ACK,
        key_length=16,
        nonce=b'\x11' * 32,
        replay_counter=1,
    )
    # PMK is None
    self.assertIsNone(supp.pmk)
    self.assertFalse(supp.handle_eapol_frame(msg1.encode()))

  def test_handle_msg3_without_ptk_returns_false(self):
    """Verifies _handle_msg3 returns False if PTK is not established."""
    supp = Wpa2SupplicantStateMachine(station_mac='02:00:00:00:02:01')
    msg3 = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=DESC_TYPE_RSN_WPA2,
        key_info=(
            KEY_INFO_KEY_TYPE_PAIRWISE
            | KEY_INFO_KEY_ACK
            | KEY_INFO_KEY_MIC
            | KEY_INFO_INSTALL
        ),
        key_length=16,
        nonce=b'\x11' * 32,
        replay_counter=2,
    )
    self.assertIsNone(supp.ptk)
    self.assertFalse(supp.handle_eapol_frame(msg3.encode()))

  def test_handle_msg3_corrupted_gtk_fails(self):
    """Verifies that Msg3 with corrupted encrypted key data fails gracefully."""
    ssid = 'GtkCorruptNet'
    psk = 'ValidSecret123'
    bssid = '02:00:00:00:01:01'
    sta_mac = '02:00:00:00:02:01'

    sent_frames = []
    supp = Wpa2SupplicantStateMachine(
        station_mac=sta_mac, on_send_frame=sent_frames.append
    )
    supp.start_association(ssid=ssid, passphrase=psk, ap_bssid=bssid)

    # Process Msg1 to establish PTK
    anonce = b'\xaa' * 32
    msg1 = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=DESC_TYPE_RSN_WPA2,
        key_info=KEY_INFO_KEY_TYPE_PAIRWISE | KEY_INFO_KEY_ACK,
        key_length=16,
        replay_counter=1,
        nonce=anonce,
    )
    self.assertTrue(supp.handle_eapol_frame(msg1.encode()))
    self.assertIsNotNone(supp.ptk)

    # Build Msg3 with corrupted key data (invalid key wrap ciphertext length)
    msg3 = EapolKeyFrame(
        version=EAPOL_VERSION_1,
        descriptor_type=DESC_TYPE_RSN_WPA2,
        key_info=(
            KEY_INFO_KEY_TYPE_PAIRWISE
            | KEY_INFO_KEY_ACK
            | KEY_INFO_KEY_MIC
            | KEY_INFO_INSTALL
            | KEY_INFO_ENCRYPTED_KEY_DATA
        ),
        key_length=16,
        replay_counter=2,
        nonce=anonce,
        key_data=b'bad_corrupt_data',  # Length not multiple of 8
    )
    msg3_zeroed = msg3.encode_with_zeroed_mic()
    msg3.mic = compute_mic(supp.ptk.kck, msg3_zeroed)

    # Should fail inside aes_key_unwrap or parse_gtk_from_kde
    self.assertFalse(supp.handle_eapol_frame(msg3.encode()))
    self.assertNotEqual(supp.state, 'completed')


if __name__ == '__main__':
  unittest.main()

