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

"""Unit tests for the multi-radio RF channel simulator."""

import json
import os
import tempfile
import unittest

from cirque.connectivity.rf_channel_simulator import (
    RfChannelSimulator,
    ble_channel_freq_mhz,
    compute_802154_lqi,
    compute_openthread_link_quality,
    per_from_sinr,
    spectral_overlap_factor,
    thread_channel_freq_mhz,
    wifi_channel_freq_mhz,
)


class RfChannelSimulatorTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.temp_dir = tempfile.TemporaryDirectory()
    self.conf_path = os.path.join(self.temp_dir.name, 'cirque_rf_thread.conf')
    self.sim = RfChannelSimulator(seed=42, thread_conf_path=self.conf_path)

  def tearDown(self):
    self.temp_dir.cleanup()
    super().tearDown()

  def test_channel_frequencies_and_spectral_overlap(self):
    # Wi-Fi Ch 3 is 2422 MHz (20 MHz BW -> [2412, 2432] MHz)
    # Thread Ch 15 is 2425 MHz (2 MHz BW -> [2424, 2426] MHz)
    # PSD fraction of 20 MHz Wi-Fi captured by 2 MHz Thread RX is 2/20 = 0.1,
    # whereas 100% (2/2 = 1.0) of 2 MHz Thread TX falls inside 20 MHz Wi-Fi RX.
    self.assertAlmostEqual(wifi_channel_freq_mhz(3), 2422.0)
    self.assertAlmostEqual(thread_channel_freq_mhz(15), 2425.0)
    self.assertAlmostEqual(
        spectral_overlap_factor(2422.0, 20.0, 2425.0, 2.0), 0.1
    )
    self.assertAlmostEqual(
        spectral_overlap_factor(2425.0, 2.0, 2422.0, 20.0), 1.0
    )

    # Wi-Fi Ch 11 is 2462 MHz ([2452, 2472] MHz) -> disjoint from Thread Ch 15
    self.assertAlmostEqual(wifi_channel_freq_mhz(11), 2462.0)
    self.assertAlmostEqual(
        spectral_overlap_factor(2462.0, 20.0, 2425.0, 2.0), 0.0
    )

    # BLE adv Ch 38 is 2426 MHz ([2425, 2427] MHz) -> 50% overlap w/ Thread 15
    self.assertAlmostEqual(ble_channel_freq_mhz(38), 2426.0)
    self.assertAlmostEqual(
        spectral_overlap_factor(2426.0, 2.0, 2425.0, 2.0), 0.5
    )

  def test_path_loss_and_wall_attenuation_monotonicity(self):
    self.sim.update_config({
        'enabled': True,
        'path_loss_exp': 2.5,
        'wall_loss_db': 6.0,
    })
    self.sim.set_node_position('tx', 0.0, 0.0, 1.0, walls=0)
    self.sim.set_node_position('rx_near', 1.5, 0.0, 1.0, walls=0)
    self.sim.set_node_position('rx_far', 15.0, 0.0, 1.0, walls=0)
    self.sim.set_node_position('rx_far_walled', 15.0, 0.0, 1.0, walls=2)

    s_near = self.sim.evaluate_packet(
        'thread', 'tx', 'rx_near', frame_bytes=64, record_telemetry=False
    )
    s_far = self.sim.evaluate_packet(
        'thread', 'tx', 'rx_far', frame_bytes=64, record_telemetry=False
    )
    s_walled = self.sim.evaluate_packet(
        'thread', 'tx', 'rx_far_walled', frame_bytes=64, record_telemetry=False
    )

    self.assertGreater(s_near.rssi_dbm, s_far.rssi_dbm)
    self.assertGreater(s_far.rssi_dbm, s_walled.rssi_dbm)
    self.assertAlmostEqual(
        s_walled.path_loss_db - s_far.path_loss_db, 12.0, places=2
    )

  def test_logistic_per_and_lqi_mappings(self):
    for proto in ('thread', 'ble', 'wifi'):
      p_low = per_from_sinr(proto, -5.0)
      p_mid = per_from_sinr(proto, 8.0)
      p_high = per_from_sinr(proto, 25.0)
      self.assertGreater(p_low, p_mid)
      self.assertGreater(p_mid, p_high)
      self.assertGreaterEqual(p_high, 0.0)
      self.assertLessEqual(p_low, 1.0)
    self.assertAlmostEqual(per_from_sinr('thread', 3.0), 0.5)
    self.assertEqual(per_from_sinr('ble', 500.0), 0.0)
    self.assertEqual(per_from_sinr('ble', -500.0), 1.0)

    self.assertEqual(compute_802154_lqi(-10.0), 0)
    self.assertEqual(compute_802154_lqi(15.0), 128)
    self.assertEqual(compute_802154_lqi(60.0), 255)

  def test_interferer_duty_cycle_is_seeded_and_deterministic(self):
    def run(seed):
      sim = RfChannelSimulator(seed=seed, thread_conf_path=self.conf_path)
      sim.apply_regime_preset('regime_c_cochannel_interference')
      return [
          (s.sinr_db, s.dropped)
          for s in (
              sim.evaluate_packet('thread', 'a', 'b', record_telemetry=False)
              for _ in range(400)
          )
      ]

    first = run(7)
    self.assertEqual(first, run(7))
    self.assertNotEqual(first, run(8))
    # RSSI is fixed, so SINR is bimodal: interferer on (deep) or off (clean).
    self.assertEqual(len({sinr for sinr, _ in first}), 2)
    on_fraction = sum(
        1 for sinr, _ in first if sinr < 0.0
    ) / float(len(first))
    self.assertGreater(on_fraction, 0.8)
    self.assertLess(on_fraction, 0.97)

  def test_regime_c_degrades_sinr_per_and_lqi_vs_ideal(self):
    # Enabled ideal baseline, exactly as the connectedhomeip RF test applies.
    self.sim.update_config({'preset': 'ideal', 'enabled': True,
                            'max_per_cap': 0.0})
    for _ in range(150):
      self.sim.evaluate_packet('ble', 'android', 'lock', frame_bytes=48)
      self.sim.evaluate_packet('wifi', 'android', 'tbr', frame_bytes=256)
      self.sim.evaluate_packet('thread', 'tbr', 'lock', frame_bytes=80)
    status_ideal = self.sim.get_status()['telemetry']

    self.sim.apply_regime_preset('regime_c_cochannel_interference')
    for _ in range(150):
      self.sim.evaluate_packet('ble', 'android', 'lock', frame_bytes=48)
      self.sim.evaluate_packet(
          'ble', 'android', 'lock', channel=37, frame_bytes=48
      )
      self.sim.evaluate_packet('wifi', 'android', 'tbr', frame_bytes=256)
      self.sim.evaluate_packet('thread', 'tbr', 'lock', frame_bytes=80)
    status_c = self.sim.get_status()['telemetry']

    for proto in ('ble', 'wifi', 'thread'):
      self.assertEqual(status_ideal[proto]['dropped_packets'], 0)
      self.assertGreater(
          status_ideal[proto]['mean_rssi_dbm'],
          status_c[proto]['mean_rssi_dbm'],
      )
      self.assertGreater(
          status_ideal[proto]['mean_sinr_db'],
          status_c[proto]['mean_sinr_db'] + 15.0,
          f'{proto}: ideal mean SINR must exceed Regime C by > 15 dB',
      )
      self.assertGreater(status_c[proto]['mean_per'], 0.05)
      self.assertLessEqual(status_c[proto]['mean_per'], 0.45)
      self.assertGreater(status_c[proto]['dropped_packets'], 0)

    self.assertGreater(
        status_ideal['thread']['mean_lqi'], status_c['thread']['mean_lqi']
    )
    self.assertEqual(
        compute_openthread_link_quality(
            int(status_ideal['thread']['mean_lqi']),
            status_ideal['thread']['mean_sinr_db'],
        ),
        3,
    )

  def test_thread_config_file_sync_and_c_telemetry_harvest(self):
    self.sim.apply_regime_preset('regime_c_cochannel_interference')
    self.assertTrue(os.path.isfile(self.conf_path))
    with open(self.conf_path, 'r', encoding='utf-8') as f:
      conf_text = f.read()
    self.assertIn('enabled=1', conf_text)
    self.assertIn('regime_name=regime_c_cochannel_interference', conf_text)

    lqi_val = compute_802154_lqi(25.0)
    self.assertGreaterEqual(lqi_val, 200)

  def test_ble_link_layer_and_virtual_wifi_integration(self):
    from cirque.virtual_bt.link_layer import LinkLayerHub
    from cirque.virtual_wifi.server import VirtualWiFiServer

    rf_shared = RfChannelSimulator.get_shared()
    try:
      rf_shared.apply_regime_preset('ideal')
      hub = LinkLayerHub()
      rssi_ideal = [
          hub.get_rssi('AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02')
          for _ in range(30)
      ]
      rf_shared.apply_regime_preset('regime_c_cochannel_interference')
      rssi_c = [
          hub.get_rssi('AA:BB:CC:DD:EE:01', 'AA:BB:CC:DD:EE:02')
          for _ in range(30)
      ]
      self.assertGreater(
          sum(rssi_ideal) / len(rssi_ideal), sum(rssi_c) / len(rssi_c)
      )

      wifi_srv = VirtualWiFiServer()
      counters = wifi_srv.get_frame_counters()
      self.assertIn('dropped_rf_frames', counters)
    finally:
      rf_shared.apply_regime_preset('ideal')

  def test_spinel_hdlc_rf_proxy_pure_cirque_interception(self):
    from cirque.connectivity.threadsimpipe import (
        SpinelHdlcRfProxy,
        hdlc_decode_frame,
        hdlc_encode_frame,
    )

    # 1. HDLC encode/decode round-trip including all 5 escaped control bytes
    raw_body = bytes([0x81, 0x06, 0x71, 0x11, 0x13, 0x7D, 0x7E, 0xF8, 0x42])
    encoded = hdlc_encode_frame(raw_body)
    self.assertEqual(encoded[0], 0x7E)
    self.assertEqual(encoded[-1], 0x7E)
    decoded = hdlc_decode_frame(encoded[1:-1])
    self.assertEqual(decoded, raw_body)

    proxy = SpinelHdlcRfProxy(node_id=1, simulator=self.sim)

    # 2. Construct RCP -> Host SPINEL_PROP_STREAM_RAW (cmd=6, prop=0x71) frame
    # PackRadioFrame layout at offset 3:
    #   [psdu_len_lo, psdu_len_hi] + psdu + [rssi(-20), noise(-128), flags_lo,
    #   flags_hi, phy_len_lo(10), phy_len_hi(0), channel(15), lqi(0), ts(8B)]
    psdu = bytes([0x61, 0x88, 0x01, 0xCD, 0xAB, 0xFF, 0xFF, 0x01, 0x00, 0xAA])
    psdu_len = len(psdu)
    rx_body = (
        bytes([0x80, 0x06, 0x71, psdu_len & 0xFF, (psdu_len >> 8) & 0xFF])
        + psdu
        + bytes([
            (-20) & 0xFF,
            (-128) & 0xFF,
            0x00,
            0x00,
            0x0A,
            0x00,
            15,
            0,
        ])
        + bytes(8)
    )

    # Enabled ideal baseline so the proxy rewrites RSSI/LQI.
    self.sim.update_config(
        {'preset': 'ideal', 'enabled': True, 'max_per_cap': 0.0}
    )
    wire_a = proxy.feed_rcp_to_host(hdlc_encode_frame(rx_body))
    body_a = hdlc_decode_frame(wire_a[1:-1])
    rssi_a = body_a[5 + psdu_len] - (256 if body_a[5 + psdu_len] >= 128 else 0)
    lqi_a = body_a[12 + psdu_len]

    self.sim.apply_regime_preset('regime_c_cochannel_interference')
    wire_c = proxy.feed_rcp_to_host(hdlc_encode_frame(rx_body))
    body_c = hdlc_decode_frame(wire_c[1:-1])
    rssi_c = body_c[5 + psdu_len] - (256 if body_c[5 + psdu_len] >= 128 else 0)
    lqi_c = body_c[12 + psdu_len]

    self.assertGreater(rssi_a, rssi_c + 10)
    self.assertGreater(lqi_a, lqi_c + 30)

    # 3. RCP -> Host SPINEL_PROP_LAST_STATUS (0x00) w/ ACK PackRadioFrame @ 6
    ack_psdu = bytes([0x02, 0x00, 0x42, 0x12, 0x34])
    ack_body = (
        bytes([0x83, 0x06, 0x00, 0x00, 0x00, 0x00, len(ack_psdu), 0x00])
        + ack_psdu
        + bytes([(-20) & 0xFF, (-128) & 0xFF, 0x00, 0x00, 0x0A, 0x00, 15, 0])
        + bytes(8)
    )
    ack_wire = proxy.feed_rcp_to_host(hdlc_encode_frame(ack_body))
    ack_out = hdlc_decode_frame(ack_wire[1:-1])
    ack_lqi = ack_out[15 + len(ack_psdu)]
    self.assertGreater(ack_lqi, 0)

    # 4. RCP -> Host SPINEL_PROP_PHY_RSSI (0x26) ambient CCA RSSI query
    cca_req = bytes([0x84, 0x06, 0x26, (-98) & 0xFF])
    cca_wire = proxy.feed_rcp_to_host(hdlc_encode_frame(cca_req))
    cca_out = hdlc_decode_frame(cca_wire[1:-1])
    cca_rssi_c = cca_out[3] - (256 if cca_out[3] >= 128 else 0)
    self.assertGreater(cca_rssi_c, -90)

    # 5. Host -> RCP outbound data TX drop -> SPINEL_STATUS_NO_ACK (0x11)
    #    preserving RCP headerUpdated=1 and 5-byte (keyIndex, frameCounter)
    tx_psdu = bytes([0x69, 0x88]) + bytes(78)  # 80-byte secured data frame
    tx_meta = bytes([15, 4, 3, 1, 1, 0, 1]) + bytes(10)  # channel=15, is_retx=0
    tx_body = (
        bytes([0x85, 0x03, 0x71, len(tx_psdu) & 0xFF, 0x00]) + tx_psdu + tx_meta
    )
    sec_trailer = bytes([0x01, 0x12, 0x34, 0x56, 0x78])
    rcp_tx_done_reply = (
        bytes([0x85, 0x06, 0x00, 0x00, 0x00, 0x01, len(ack_psdu), 0x00])
        + ack_psdu
        + bytes([(-20) & 0xFF, (-128) & 0xFF, 0x00, 0x00, 0x0A, 0x00, 15, 0])
        + bytes(8)
        + sec_trailer
    )
    converted_to_no_ack = False
    for _ in range(50):
      proxy.feed_host_to_rcp(hdlc_encode_frame(tx_body))
      host_reply_wire = proxy.feed_rcp_to_host(
          hdlc_encode_frame(rcp_tx_done_reply)
      )
      host_reply_body = hdlc_decode_frame(host_reply_wire[1:-1])
      if host_reply_body[:4] == bytes([0x85, 0x06, 0x00, 0x11]):
        converted_to_no_ack = True
        self.assertEqual(
            host_reply_body,
            bytes([0x85, 0x06, 0x00, 0x11, 0x00, 0x01]) + sec_trailer,
        )
        break
    self.assertTrue(
        converted_to_no_ack,
        'Expected at least one outbound data frame in Regime C to be rewritten'
        ' to SPINEL_STATUS_NO_ACK (0x11) with preserved security trailer',
    )

  def test_only_ideal_and_regime_c_presets_remain(self):
    status = self.sim.get_status()
    self.assertEqual(
        status['available_presets'],
        ['ideal', 'regime_c_cochannel_interference'],
    )
    for alias in ('regime_c', 'cochannel_interference', 'interference'):
      self.sim.apply_regime_preset(alias)
      self.assertEqual(
          self.sim.config.regime_name, 'regime_c_cochannel_interference'
      )
    for removed in ('regime_a_near_los', 'regime_b_far_nlos_fading'):
      with self.assertRaises(ValueError):
        self.sim.apply_regime_preset(removed)

  def test_regime_packet_drops(self):
    """Verifies that regimes cause expected packet drops without Matter specifics."""
    def run_trial(preset_name: str, seed: int, n_trials: int = 150):
      self.sim.set_seed(seed)
      self.sim.apply_regime_preset(preset_name)
      if preset_name != 'ideal':
        self.sim.set_node_position(
            'tbr', x_m=0.0, y_m=0.0, z_m=1.0, tx_power_thread_dbm=4.0, walls=1
        )
        self.sim.set_node_position(
            'sed', x_m=15.0, y_m=0.0, z_m=1.0, tx_power_thread_dbm=0.0, walls=1
        )
      drops = 0
      trials = (
          (('tbr', 'sed'), 64),
          (('sed', 'tbr'), 120),
          (('tbr', 'sed'), 48),
      )
      for _ in range(n_trials):
        for direction, flen in trials:
          sample = self.sim.evaluate_packet(
              'thread', direction[0], direction[1], frame_len_bytes=flen
          )
          drops += int(sample.dropped)
      return drops

    ideal_drops = run_trial('ideal', seed=2026)
    regime_c_drops = run_trial('regime_c_cochannel_interference', seed=2026)

    self.assertEqual(ideal_drops, 0)
    self.assertGreater(regime_c_drops, 0)


if __name__ == '__main__':
  unittest.main()
