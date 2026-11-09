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
"""Tests for Matter commissioning and Thread decoding in the flow visualizer.

Log lines are verbatim excerpts of the AndroidBleThreadMobileDeviceTest CI
run (CHIPEndDevice and Android logcat). The 802.15.4 frames were captured by
ThreadRadioSniffer from two OpenThread simulation nodes (network key
00112233445566778899aabbccddeeff, a test-only key).
"""

import calendar
import os
import shutil
import struct
import tempfile
import unittest

from cirque.capabilities.pcapcapability import (
    DLT_IEEE802_15_4_WITHFCS,
    PcapWriter,
)
from cirque.pcap import flow_visualizer as fv
from cirque.pcap import thread_keys

DEVICE_LOG = 'CHIPEndDevice-1791928996-12fa6692.log'
LOGCAT_LOG = 'android_emulator-1791928996-e3795874-logcat.log'

EM_SIGMA1_RX = (
    '[1791928975.270] [164:164] [EM] >>> [E:5440r S:0 M:241328646] (U) Msg'
    ' RX from 0:2211CF9734962C6F [0000] to 0000000000000000 --- Type'
    ' 0000:30 (SecureChannel:CASE_Sigma1) (B:203)'
)
EM_SIGMA2_TX = (
    '[1791928975.282] [164:164] [EM] <<< [E:5440r S:0 M:180170359 '
    '(Ack:241328646)] (U) Msg TX from 0000000000000000 to '
    '0:2211CF9734962C6F [0000] [UDP:[fd11:33::1]:5542] --- Type 0000:31 '
    '(SecureChannel:CASE_Sigma2) (B:524)'
)
EM_SIGMA3_RX = (
    '[1791928975.339] [164:164] [EM] >>> [E:5440r S:0 M:241328648 '
    '(Ack:180170359)] (U) Msg RX from 0:2211CF9734962C6F [0000] to '
    '0000000000000000 --- Type 0000:32 (SecureChannel:CASE_Sigma3) (B:364)'
)
DMG_ARMFAILSAFE = (
    '[1791928973.761] [164:164] [DMG] Received command for Endpoint=0 '
    'Cluster=0x0000_0030 Command=0x0000_0000'
)
LOGCAT_SIGMA1_TX = (
    '10-13 22:02:55.071  4732  4732 I EM      : <<< [E:5440i S:0 '
    'M:241328646] (U) Msg TX from 2211CF9734962C6F to 0:0000000000000000 '
    '[0000] [UDP:10.0.1.20:5540] --- Type 0000:30 '
    '(SecureChannel:CASE_Sigma1) (B:203)'
)
LOGCAT_CTL_SEND_NOC = (
    "10-13 22:02:53.706  4732  4895 I CTL     : Performing next"
    " commissioning step 'SendNOC'"
)
LOGCAT_CTL_CLEANUP = (
    "10-13 22:02:55.178  4732  4837 I CTL     : Performing next"
    " commissioning step 'Cleanup'"
)

DATASET_TLVS = (
    '35060004001fffe0030f4f70656e5468726561642d393363610410490e0f1c75476e68'
    '7f88c4bee6c5bb4c0c0402a0f7f80e080000000000010000000300000f010212340208'
    '1111111122222222051000112233445566778899aabbccddeeff0708fddead00beef00'
    '00'
)
# MLE Advertisement (MAC unsecured, extended source address).
FRAME_MLE_ADVERTISEMENT = bytes.fromhex(
    '41d8de3412ffff703d7f13cf1772ba7f3b01f04d4c4d4ca93300150300000000000000'
    '010c11a1a9bab9a44bfb24d04c943a848d8a041e2134fe9d8bee8acba515beb8f6e9'
)
# MLE Child ID Request from the joining node (extended addresses).
FRAME_MLE_CHILD_ID_REQUEST = bytes.fromhex(
    '61dcc43412703d7f13cf1772ba30c104be1e9b90f27f33f04d4c4d4c89330015010000'
    '000000000001f5b4973278aa0639557b9e7df7b46ff05ebbae291bb30e74aea78ae9cf'
    'fa06d6c9dff6eb0a3a809260c01ae2cc8dd792d6c535b37103ca92a6'
)
# MAC-secured data frame 0xb001 -> 0xb000 carrying UDP 5540 with a Sigma1
# message header (counter 241328646, exchange 5440).
FRAME_UDP_5540 = bytes.fromhex(
    '6998c6341200b001b00d0100000001047198ecc98fbb39a5a10538f604be8d729ff3a7'
    '0d73c596dd3188a476b99a2eefa17836d021f93f60b6283c6de6c188b7736187c0832c'
    '2ce54594e50f8db99da0fe2ac1e82dfd1e818cb731ecd860d4dcab58f813e7507c7ef8'
    'db'
)
# MAC-secured ICMPv6 echo request.
FRAME_PING = bytes.fromhex(
    '6998c8341200b001b00d0300000001ce4eef88ce7ae96bf053e5bb3fdf616790c3ef63'
    '98a713cb68efe4aaf32de202fa104f74d8718afb8e'
)
THREAD_FRAMES = (
    FRAME_MLE_ADVERTISEMENT,
    FRAME_MLE_CHILD_ID_REQUEST,
    FRAME_UDP_5540,
    FRAME_PING,
)


def _event(event_id, ts, layer='WIFI', stage='NETWORK_CONFIG', **details):
  return fv.FlowEvent(
      event_id=event_id,
      timestamp=ts,
      layer=layer,
      sublayer='UDP',
      stage=stage,
      src='a',
      dst='b',
      title=event_id,
      summary='',
      details=details,
  )


class FlowVisualizerTestBase(unittest.TestCase):

  def setUp(self):
    self.temp_dir = tempfile.mkdtemp(prefix='cirque_flow_test_')

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  def log_events(self, lines, name=DEVICE_LOG):
    path = os.path.join(self.temp_dir, name)
    with open(path, 'w', encoding='utf-8') as f:
      f.write('\n'.join(lines) + '\n')
    return fv.dissect_log_file(path)


class ChipLogParsingTest(FlowVisualizerTestBase):

  def test_em_lines_with_ack_and_udp_address_are_parsed(self):
    events = self.log_events([EM_SIGMA1_RX, EM_SIGMA2_TX, EM_SIGMA3_RX])
    self.assertEqual(
        [ev.title for ev in events],
        [
            'SecureChannel:CASE_Sigma1 (RX)',
            'SecureChannel:CASE_Sigma2 (TX)',
            'SecureChannel:CASE_Sigma3 (RX)',
        ],
    )
    sigma1, sigma2, sigma3 = events
    self.assertEqual(sigma2.details['ack_counter'], '241328646')
    self.assertEqual(sigma2.details['peer_addr'], 'fd11:33::1')
    self.assertEqual(sigma2.details['peer_port'], 5542)
    self.assertEqual(sigma2.dst, 'fd11:33::1')
    # RX lines print no address; the exchange's TX line supplies it.
    self.assertEqual((sigma1.src, sigma1.dst), ('fd11:33::1', 'CHIPEndDevice'))
    self.assertTrue(sigma3.details['peer_addr_from_exchange'])
    self.assertEqual(
        sigma1.details['matter_msg_key'],
        fv.matter_message_key(241328646, 5440, 0x0000, 0x30),
    )

  def test_android_logcat_lines_are_parsed_with_utc_year(self):
    events = self.log_events(
        [LOGCAT_SIGMA1_TX, LOGCAT_CTL_SEND_NOC], name=LOGCAT_LOG
    )
    self.assertEqual(len(events), 2)
    sigma1, add_noc = events
    self.assertEqual(sigma1.title, 'SecureChannel:CASE_Sigma1 (TX)')
    self.assertEqual(
        sigma1.timestamp,
        calendar.timegm((2026, 10, 13, 22, 2, 55, 0, 0, 0)) + 0.071,
    )
    self.assertEqual(
        (sigma1.src, sigma1.dst), ('android_emulator (logcat)', '10.0.1.20')
    )
    self.assertEqual(add_noc.title, 'OperationalCredentials:AddNOC (TX)')
    self.assertEqual(add_noc.details['commissioning_step'], 'SendNOC')

  def test_logcat_year_rolls_back_across_new_year(self):
    ts = fv._logcat_timestamp(
        ('12', '31', '23', '59', '59', '500'),
        calendar.timegm((2027, 1, 1, 0, 0, 5, 0, 0, 0)),
    )
    self.assertEqual(ts, calendar.timegm((2026, 12, 31, 23, 59, 59)) + 0.5)

  def test_evidence_tags_for_device_and_intent(self):
    logs = [
        # CTL Intent
        "10-13 22:02:53.706  4732  4895 I CTL     : Performing next commissioning step 'SendNOC'",
        # DMG Device log
        "[1791928975.339] [164:164] [DMG] Received command for Endpoint=0 Cluster=0x0000_003E Command=0x0000_0006"
    ]
    events = self.log_events(logs)
    self.assertEqual(len(events), 2)
    intent, device = events
    self.assertEqual(intent.details['evidence'], 'controller_intent')
    self.assertEqual(device.details['evidence'], 'device_log')

    # The wire, host_hci and relay tags are added by the Matter flow plugin;
    # their legend and arrow styles are covered by SequenceDiagramTest.

  def test_commissioning_commands_are_named(self):
    events = self.log_events([DMG_ARMFAILSAFE])
    self.assertEqual(
        [ev.title for ev in events], ['GeneralCommissioning:ArmFailSafe (RX)']
    )
    self.assertEqual((events[0].src, events[0].dst), ('Controller',
                                                      'CHIPEndDevice'))
    self.assertEqual(events[0].details['cluster_id'], '0x0030')
    # Steps that send no command produce no event.
    self.assertEqual(self.log_events([LOGCAT_CTL_CLEANUP], LOGCAT_LOG), [])

  def test_received_keyword_lines_point_at_the_node(self):
    events = self.log_events(
        ['[1791928975.271] [164:164] [SC] Received Sigma1 msg']
    )
    self.assertEqual((events[0].src, events[0].dst), ('Controller',
                                                      'CHIPEndDevice'))

  def test_full_logcat_is_skipped_when_excerpt_exists(self):
    for name in (LOGCAT_LOG, LOGCAT_LOG.replace('-logcat', '-logcat-full')):
      with open(os.path.join(self.temp_dir, name), 'w') as f:
        f.write(LOGCAT_SIGMA1_TX + '\n')
    self.assertEqual(
        [os.path.basename(p) for p in fv.list_log_files(self.temp_dir)],
        [LOGCAT_LOG],
    )
    self.assertEqual(len(fv.dissect_log_directory(self.temp_dir)), 1)


class MergeTest(unittest.TestCase):

  def test_capture_copies_are_deduplicated_and_messages_joined(self):
    key = fv.matter_message_key(241328646, 5440, 0, 0x30)
    events = fv.merge_and_sort_flow_events(
        [
            _event('medium', 1.000, pcap_file='wifi_medium.pcap',
                   packet_index=3, dedup_key='MATTER:' + key,
                   matter_msg_key=key),
            _event('station', 1.002, pcap_file='wifi_wifi2.pcap',
                   packet_index=9, dedup_key='MATTER:' + key,
                   matter_msg_key=key),
            _event('retransmit', 1.400, pcap_file='wifi_medium.pcap',
                   packet_index=40, dedup_key='MATTER:' + key,
                   matter_msg_key=key),
            _event('device_log', 1.010, log_file=DEVICE_LOG,
                   matter_msg_key=key),
        ],
        [],
    )
    self.assertEqual(
        [ev.event_id for ev in events], ['medium', 'device_log', 'retransmit']
    )
    self.assertEqual(events[0].details['duplicates'], ['wifi_wifi2.pcap#9'])
    self.assertEqual(
        events[1].details['joined_events'], ['medium', 'retransmit']
    )


class SequenceDiagramTest(FlowVisualizerTestBase):

  def test_default_view_opens_on_first_pase_or_case_event(self):
    events = [_event(f'wifi{i}', i) for i in range(100)]
    events.append(_event('pase', 100, layer='MATTER', stage='PASE_HANDSHAKE'))
    self.assertEqual(fv.default_sequence_focus_index(events), 100)
    as_dicts = [ev.to_dict() for ev in events]
    self.assertEqual(fv.default_sequence_focus_index(as_dicts), 100)
    # Emulates renderSequenceDiagram(): 60 frames around INITIAL_INDEX.
    focus = fv.default_sequence_focus_index(as_dicts)
    start = max(0, min(focus - 25, len(as_dicts) - 60))
    window = as_dicts[start : start + 60]
    self.assertIn('MATTER', {ev['layer'] for ev in window})
    self.assertEqual(fv.default_sequence_focus_index(events[:5]), 0)

  def test_lane_aliases_for_border_router_relay(self):
    logs = self.log_events([EM_SIGMA1_RX, EM_SIGMA2_TX])
    logs += self.log_events([LOGCAT_SIGMA1_TX], name=LOGCAT_LOG)
    capture = _event(
        'sigma1_pcap',
        1791928975.26,
        pcap_file='wifi_medium.pcap',
        src_ip='10.0.1.21',
        dst_ip='10.0.1.20',
        matter_msg_key=fv.matter_message_key(241328646, 5440, 0, 0x30),
    )
    aliases = fv.infer_lane_aliases(logs + [capture])
    self.assertEqual(aliases['10.0.1.21'], fv.LANE_CONTROLLER)
    self.assertEqual(aliases['2211cf9734962c6f'], fv.LANE_CONTROLLER)
    self.assertEqual(aliases['10.0.1.20'], fv.LANE_BORDER_ROUTER)
    self.assertEqual(aliases['fd11:33::1'], fv.LANE_BORDER_ROUTER)

    out = os.path.join(self.temp_dir, 'studio.html')
    fv.generate_flow_html(
        fv.merge_and_sort_flow_events(logs + [capture], []), out
    )
    with open(out, encoding='utf-8') as f:
      page = f.read()
    self.assertIn('"fd11:33::1": 2', page)
    self.assertIn('"10.0.1.20": 2', page)
    self.assertIn('const INITIAL_INDEX = 0;', page)
    self.assertIn('id="stage-jump-select"', page)

  def test_wifi_macs_map_to_station_lanes_and_ap_lane(self):
    logs = self.log_events([EM_SIGMA1_RX, EM_SIGMA2_TX])
    logs += self.log_events([LOGCAT_SIGMA1_TX], name=LOGCAT_LOG)
    capture = _event(
        'sigma1_pcap',
        1791928975.26,
        pcap_file='wifi_medium.pcap',
        src_ip='10.0.1.21',
        dst_ip='10.0.1.20',
        src_mac='02:00:00:00:02:0C',
        dst_mac='02:00:00:00:02:0B',
        matter_msg_key=fv.matter_message_key(241328646, 5440, 0, 0x30),
    )
    eapol = _event(
        'eapol_1',
        1791928970.0,
        pcap_file='wifi_medium.pcap',
        src_mac='02:00:00:00:01:01',
        dst_mac='02:00:00:00:02:0C',
    )
    eapol.sublayer = 'EAPOL'
    # A second station that only associates (no IP traffic) and its EAPOL
    # reply; the AP is the MAC that runs EAPOL with both stations.
    eapol_2 = _event(
        'eapol_2',
        1791928971.0,
        pcap_file='wifi_medium.pcap',
        src_mac='02:00:00:00:02:0D',
        dst_mac='02:00:00:00:01:01',
    )
    eapol_2.sublayer = 'EAPOL'
    aliases = fv.infer_lane_aliases(logs + [capture, eapol, eapol_2])
    # The station MAC follows the IP it carried; only the AP gets the AP lane.
    self.assertEqual(aliases['02:00:00:00:02:0c'], fv.LANE_CONTROLLER)
    self.assertEqual(aliases['02:00:00:00:01:01'], fv.LANE_WIFI_AP)
    self.assertEqual(aliases['02:00:00:00:02:0d'], fv.LANE_ACCESSORY)
    self.assertEqual(
        aliases[fv._lane_alias_key(fv.DHCP_SERVER_ENDPOINT)], fv.LANE_WIFI_AP
    )

  def test_connect_network_stage_follows_the_added_network(self):
    def cmd(event_id, ts, command):
      ev = _event(event_id, ts, layer='MATTER', stage='CLUSTER_CONTROL',
                  matter_command=command)
      return ev

    wifi = [
        cmd('add_wifi', 10.0, 'AddOrUpdateWiFiNetwork'),
        cmd('connect_wifi', 11.0, 'ConnectNetwork'),
    ]
    thread = [
        cmd('add_thread', 20.0, 'AddOrUpdateThreadNetwork'),
        cmd('connect_thread', 21.0, 'ConnectNetwork'),
    ]
    merged = fv.merge_and_sort_flow_events(list(reversed(wifi + thread)), [])
    stages = {ev.event_id: ev.stage for ev in merged}
    self.assertEqual(stages['connect_wifi'], 'WIFI_PROVISIONED')
    self.assertEqual(stages['connect_thread'], 'THREAD_PROVISIONED')

  def test_evidence_tiers_have_legend_and_arrow_styles(self):
    out = os.path.join(self.temp_dir, 'studio.html')
    fv.generate_flow_html([_event('hci', 1.0, pcap_file='bt_hci_hci0.pcap')],
                          out)
    with open(out, encoding='utf-8') as f:
      page = f.read()
    for label in ('Over-the-Air (Wire)', 'Host HCI (Host-Controller)',
                  'Device Log', 'Relay/Proxy', 'Controller Intent'):
      self.assertIn(f'font-medium">{label}</span>', page)
    self.assertIn("ev.details.evidence === 'host_hci'", page)
    self.assertIn('else if (isHostHci) dash = \' stroke-dasharray="6 3"\';',
                  page)
    # The dash pattern is emitted on both self-loop paths and lane arrows.
    self.assertEqual(page.count('${dash}'), 2)

  def test_decrypted_wire_filter_pill_and_badge_rendered(self):
    out = os.path.join(self.temp_dir, 'studio_decr.html')
    ev = _event(
        'm_decr',
        1.5,
        layer='MATTER',
        decrypted=True,
        evidence='wire',
    )
    fv.generate_flow_html([ev], out)
    with open(out, encoding='utf-8') as f:
      page = f.read()
    self.assertIn('id="filter-btn-DECRYPTED_WIRE"', page)
    self.assertIn('Decrypted Wire (1)', page)
    self.assertIn('DECRYPTED', page)
    self.assertIn("activeFilter === 'DECRYPTED_WIRE'", page)

  def test_event_strings_are_escaped_before_inner_html(self):
    out = os.path.join(self.temp_dir, 'studio_xss.html')
    payload = '<img src=x onerror=alert(1)>'
    fv.generate_flow_html([_event(payload, 1.0)], out)
    with open(out, encoding='utf-8') as f:
      page = f.read()
    # The embedded event data never contains a live tag.
    self.assertNotIn(payload, page)
    # Frame list and inspector panes escape every event-derived field.
    for raw in ('>${ev.layer}<', '>${ev.title}<', '>${ev.src} ',
                ' ${ev.dst}<', '>${ev.sublayer}<'):
      self.assertNotIn(raw, page)
    for field in ('ev.layer', 'ev.title', 'ev.src', 'ev.dst', 'ev.sublayer'):
      self.assertIn('escapeXml(String(' + field + '))', page)
    self.assertIn('${escapeXml(String(layer))}', page)
    self.assertIn('${escapeXml(String(k))}', page)
    self.assertIn('${escapeXml(String(v))}', page)

  def test_btp_events_deduplicated_across_medium_and_hci(self):
    msg = {
        'session_id': 1234,
        'message_counter': 5678,
        'direction': 'i2r',
        'nonce_node_id': 0,
        'session': type('Session', (), {'session_type': 'PASE'})(),
    }
    proto = {
        'protocol_id': 0x0000,
        'protocol_name': 'SecureChannel',
        'exchange_id': 1,
        'opcode': 0x20,
    }
    desc = {'name': 'TestCommand', 'protocol': 'IM'}
    decoded = {
        'msg': msg,
        'proto': proto,
        'desc': desc,
        'decrypted': True,
        'plaintext': b'xyz',
    }
    ev_wire = fv._matter_btp_event(
        'bt_medium.pcap', [1, 2], 1.0, True, b'raw', decoded, 'wire'
    )
    ev_hci = fv._matter_btp_event(
        'bt_hci_hci0.pcap', [10], 1.001, True, b'raw', decoded, 'host_hci'
    )
    self.assertEqual(
        ev_wire.details.get('dedup_key'), ev_hci.details.get('dedup_key')
    )
    seen_keys = set()
    deduped = []
    for ev in [ev_wire, ev_hci]:
      k = ev.details.get('dedup_key')
      if k and k in seen_keys:
        continue
      if k:
        seen_keys.add(k)
      deduped.append(ev)
    self.assertEqual(len(deduped), 1)
    self.assertEqual(deduped[0].details['evidence'], 'wire')

  def test_sequence_diagram_windowing_adaptive_logic(self):
    out = os.path.join(self.temp_dir, 'studio_window.html')
    fv.generate_flow_html([_event('e1', 1.0)], out)
    with open(out, encoding='utf-8') as f:
      page = f.read()
    self.assertIn('!isAll || filtered.length <= 500', page)
    self.assertIn('const windowSize = 150;', page)


class ThreadCaptureTest(FlowVisualizerTestBase):

  def write_capture(self, with_key):
    writer = PcapWriter(
        os.path.join(self.temp_dir, 'thread_0.pcap'),
        dlt=DLT_IEEE802_15_4_WITHFCS,
    )
    for idx, frame in enumerate(THREAD_FRAMES):
      writer.write_frame(frame, ts=100.0 + idx)
    writer.close()
    if with_key:
      thread_keys.write_thread_key_files(
          self.temp_dir, dataset_tlvs_hex=DATASET_TLVS
      )
    return fv.dissect_pcap_directory(self.temp_dir)

  def test_frames_without_key_stay_encrypted(self):
    events = self.write_capture(with_key=False)
    self.assertTrue(all(ev.details['wpan_fcs_ok'] for ev in events))
    self.assertEqual(
        [ev.title for ev in events],
        [
            'Thread MLE Secured',
            'Thread MLE Secured',
            '802.15.4 Data seq 198 (encrypted)',
            '802.15.4 Data seq 200 (encrypted)',
        ],
    )

  @unittest.skipIf(fv.AESCCM is None, 'cryptography is not installed')
  def test_key_file_decrypts_mle_and_mac_frames(self):
    events = self.write_capture(with_key=True)
    self.assertEqual(
        [(ev.layer, ev.sublayer, ev.title) for ev in events[:2]],
        [
            ('THREAD', 'MLE', 'Thread MLE Advertisement'),
            ('THREAD', 'MLE', 'Thread MLE Child ID Request'),
        ],
    )
    udp, ping = events[2:]
    self.assertTrue(udp.details['wpan_decrypted'])
    self.assertEqual(udp.details['dst_port'], 5540)
    self.assertEqual(udp.dst, 'fdde:ad00:beef:0:e83c:772e:52af:98b6')
    # Matter header: flags 0x04, session 0, counter 241328646, exchange 5440.
    self.assertTrue(
        udp.details['udp_payload_hex'].startswith('040000000662620e')
    )
    self.assertEqual(
        ping.title,
        'Thread ICMPv6 fdde:ad00:beef:0:fbdc:b96f:8046:483f ->'
        ' fdde:ad00:beef:0:e83c:772e:52af:98b6',
    )


  @unittest.skipIf(fv.AESCCM is None, 'cryptography is not installed')
  def test_fallback_simulation_key_decrypts_pre_commissioning_frames(self):
    self.write_capture(with_key=False)
    thread_keys.write_thread_key_files(
        self.temp_dir,
        network_key='ffeeddccbbaa99887766554433221100',
        dataset_tlvs_hex=(
            '000300000f020811111111222222220510ffeeddccbbaa99887766554433221100'
            '0708fddead00beef000001021234'
        ),
    )
    events = fv.dissect_pcap_directory(self.temp_dir)
    self.assertEqual(
        [(ev.layer, ev.sublayer, ev.title) for ev in events[:2]],
        [
            ('THREAD', 'MLE', 'Thread MLE Advertisement'),
            ('THREAD', 'MLE', 'Thread MLE Child ID Request'),
        ],
    )
    self.assertTrue(events[2].details['wpan_decrypted'])

  def test_eth_pcap_ipv6_udp_dissected(self):
    eth_hdr = bytes.fromhex('3333000000fb0242fd00000186dd')
    ipv6_hdr = (
        struct.pack('>IHBB', 0x60000000, 12, 17, 64)
        + bytes.fromhex('fd000000fab100060000000000000002')
        + bytes.fromhex('fd000000fab100060000000000000003')
    )
    udp_hdr = struct.pack('>HHHH', 5540, 5540, 12, 0) + b'CHIP'
    eth_pcap = os.path.join(self.temp_dir, 'eth_CHIPEndDevice_12345678.pcap')
    with open(eth_pcap, 'wb') as f:
      f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
      pkt = eth_hdr + ipv6_hdr + udp_hdr
      f.write(struct.pack('<IIII', 1700000000, 0, len(pkt), len(pkt)) + pkt)
    events = fv.dissect_pcap_directory(self.temp_dir)
    self.assertEqual(len(events), 1)
    self.assertEqual(events[0].layer, 'WIFI')
    self.assertEqual(events[0].sublayer, 'UDP')
    self.assertEqual(events[0].title, 'IPv6 UDP :5540->:5540')

  def test_eth_pcap_ipv4_dhcp_dissected(self):
    # BOOTREPLY (op=2), xid=0x12345678, yiaddr=192.168.1.2, option 53=Offer.
    bootp = (
        struct.pack('>BBBBI', 2, 1, 6, 0, 0x12345678)
        + bytes(8)
        + bytes([192, 168, 1, 2])
        + bytes(8 + 16 + 64 + 128)
        + struct.pack('>I', 0x63825363)
        + bytes([53, 1, 2, 255])
    )
    udp = struct.pack('>HHHH', 67, 68, 8 + len(bootp), 0) + bootp
    ipv4 = (
        struct.pack('>BBHHHBBH', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0)
        + bytes([192, 168, 1, 1])
        + bytes([192, 168, 1, 2])
    )
    pkt = bytes.fromhex('ffffffffffff0200000001010800') + ipv4 + udp
    eth_pcap = os.path.join(self.temp_dir, 'eth_DHCP_1234.pcap')
    with open(eth_pcap, 'wb') as f:
      f.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
      f.write(struct.pack('<IIII', 1700000000, 0, len(pkt), len(pkt)) + pkt)
    events = fv.dissect_pcap_directory(self.temp_dir)
    self.assertEqual(len(events), 1)
    self.assertEqual(events[0].layer, 'WIFI')
    self.assertEqual(events[0].sublayer, 'DHCP')
    self.assertEqual(events[0].title, 'DHCP Offer')
    self.assertEqual(
        (events[0].src, events[0].dst),
        ('02:00:00:00:01:01', 'FF:FF:FF:FF:FF:FF'),
    )
    self.assertTrue(events[0].details.get('decrypted'))
    self.assertEqual(events[0].details.get('evidence'), 'wire')


class ThreadKeysTest(FlowVisualizerTestBase):

  def test_dataset_fields_and_key_files(self):
    fields = thread_keys.parse_dataset_tlvs(DATASET_TLVS)
    self.assertEqual(fields['channel'], 15)
    self.assertEqual(fields['pan_id'], 0x1234)
    self.assertEqual(fields['ext_pan_id'], '1111111122222222')
    self.assertEqual(fields['network_key'], '00112233445566778899aabbccddeeff')
    key_path, uat_path = thread_keys.write_thread_key_files(
        self.temp_dir, network_key='ff' * 16, dataset_tlvs_hex=DATASET_TLVS
    )
    with open(key_path, encoding='utf-8') as f:
      text = f.read()
    self.assertIn('TEST-ONLY', text)
    for line in (
        'network_key=00112233445566778899aabbccddeeff',
        'pan_id=0x1234',
        'ext_pan_id=1111111122222222',
        'channel=15',
        'mesh_local_prefix=fdde:ad00:beef::/64',
        f'active_dataset_tlvs={DATASET_TLVS}',
    ):
      self.assertIn(line + '\n', text)
    self.assertIn(
        "-o 'uat:ieee802154_keys:\"00112233445566778899aabbccddeeff\",\"0\","
        "\"Thread hash\"'",
        text,
    )
    with open(uat_path, encoding='utf-8') as f:
      self.assertTrue(
          f.read().endswith(
              '"00112233445566778899aabbccddeeff","0","Thread hash"\n'
          )
      )
    loaded = thread_keys.load_thread_key_file(self.temp_dir)
    self.assertEqual(loaded['network_key'].hex(), fields['network_key'])
    self.assertEqual(loaded['mesh_local_prefix'].hex(), 'fddead00beef0000')

  def test_parse_ot_ctl_output(self):
    raw = (
        f'{DATASET_TLVS}\r\nDone\r\n'
        'Network Key: 00112233445566778899aabbccddeeff\r\nDone\r\n'
    )
    parsed = thread_keys.parse_ot_ctl_output(raw)
    self.assertEqual(parsed['network_key'], '00112233445566778899aabbccddeeff')
    self.assertEqual(parsed['dataset_tlvs_hex'], DATASET_TLVS)

  def test_invalid_key_is_rejected(self):
    with self.assertRaises(ValueError):
      thread_keys.write_thread_key_files(self.temp_dir, network_key='abc')
    self.assertIsNone(thread_keys.load_thread_key_file(self.temp_dir))


if __name__ == '__main__':
  unittest.main()
