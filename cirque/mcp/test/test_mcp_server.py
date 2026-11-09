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
"""Comprehensive unit tests for Cirque MCP Server across Iterations 1-5."""

import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CIRQUE_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, '..', '..', '..'))
if CIRQUE_ROOT not in sys.path:
  sys.path.insert(0, CIRQUE_ROOT)

from cirque.capabilities.bluetoothcapability import BlueToothCapability
from cirque.capabilities.pcapcapability import DLT_EN10MB, PcapWriter
from cirque.capabilities.wificapability import WiFiCapability
from cirque.common.isolated_runtime_dirs import isolate_virtual_runtime_dirs
from cirque.home.home import CirqueHome
from cirque.mcp.server import CirqueMcpServer, main
from cirque.restservice import service


def setUpModule():
  unittest.addModuleCleanup(isolate_virtual_runtime_dirs())


class TestCirqueMcpServer(unittest.TestCase):
  """Unit test suite for CirqueMcpServer covering all 5 capability iterations."""

  def setUp(self):
    self.temp_dir = tempfile.mkdtemp(prefix='cirque_mcp_test_')
    self.mock_home = MagicMock(spec=CirqueHome)
    self.mock_home.home_id = 'home_test_123'
    self.mock_home.devices = {}
    self.homes = {'home_test_123': self.mock_home}
    self.server = CirqueMcpServer(
        homes_provider=lambda: self.homes, pcap_dir=self.temp_dir
    )

  def tearDown(self):
    shutil.rmtree(self.temp_dir, ignore_errors=True)

  # ---------------------------------------------------------------------------
  # Protocol, Initialization, Ping, and JSON-RPC 2.0 Error Handling
  # ---------------------------------------------------------------------------

  def test_initialize_and_ping(self):
    # initialize
    init_req = {
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'initialize',
        'params': {'protocolVersion': '2024-11-05'},
    }
    resp = self.server.handle_message(init_req)
    self.assertEqual(resp['id'], 1)
    self.assertEqual(resp['result']['protocolVersion'], '2024-11-05')
    self.assertIn('tools', resp['result']['capabilities'])
    self.assertIn('resources', resp['result']['capabilities'])
    self.assertIn('prompts', resp['result']['capabilities'])
    self.assertTrue(self.server._initialized)

    # notifications/initialized
    notify = {'jsonrpc': '2.0', 'method': 'notifications/initialized'}
    self.assertIsNone(self.server.handle_message(notify))

    # ping
    ping_req = {'jsonrpc': '2.0', 'id': 2, 'method': 'ping'}
    ping_resp = self.server.handle_message(ping_req)
    self.assertEqual(ping_resp['id'], 2)
    self.assertEqual(ping_resp['result'], {})

  def test_jsonrpc_errors_and_batch(self):
    # Invalid request
    inv_req = {'bad': 'request'}
    resp = self.server.handle_message(inv_req)
    self.assertEqual(resp['error']['code'], -32600)

    # Method not found
    nf_req = {'jsonrpc': '2.0', 'id': 9, 'method': 'non_existent_method'}
    resp = self.server.handle_message(nf_req)
    self.assertEqual(resp['error']['code'], -32601)

    # Batch request
    batch = [
        {'jsonrpc': '2.0', 'id': 10, 'method': 'ping'},
        {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
        {'jsonrpc': '2.0', 'id': 11, 'method': 'ping'},
    ]
    batch_resp = self.server.handle_message(batch)
    self.assertIsInstance(batch_resp, list)
    self.assertEqual(len(batch_resp), 2)
    self.assertEqual(batch_resp[0]['id'], 10)
    self.assertEqual(batch_resp[1]['id'], 11)

  def test_notifications_never_get_a_reply(self):
    """Regression: JSON-RPC 2.0 forbids replying to notifications."""
    for method in ('notifications/cancelled', 'non_existent_method', 'ping'):
      with self.subTest(method=method):
        self.assertIsNone(
            self.server.handle_message({'jsonrpc': '2.0', 'method': method})
        )
    # Notifications inside a batch are dropped from the reply array, and a
    # batch of only notifications gets no reply at all.
    batch_resp = self.server.handle_message([
        {'jsonrpc': '2.0', 'method': 'notifications/cancelled'},
        {'jsonrpc': '2.0', 'id': 12, 'method': 'ping'},
    ])
    self.assertEqual([r['id'] for r in batch_resp], [12])
    self.assertIsNone(
        self.server.handle_message(
            [{'jsonrpc': '2.0', 'method': 'notifications/progress'}]
        )
    )
    # id: null is a request (not a notification), so it still gets a reply.
    resp = self.server.handle_message(
        {'jsonrpc': '2.0', 'id': None, 'method': 'non_existent_method'}
    )
    self.assertEqual(resp['error']['code'], -32601)

  # ---------------------------------------------------------------------------
  # Iteration 1 Tools (Topology & Virtual Home Lifecycle)
  # ---------------------------------------------------------------------------

  def test_tools_list_contains_all_core_12_tools(self):
    req = {'jsonrpc': '2.0', 'id': 100, 'method': 'tools/list'}
    resp = self.server.handle_message(req)
    tools = resp['result']['tools']
    tool_names = [t['name'] for t in tools]
    expected_tools = [
        'cirque_list_homes',
        'cirque_create_virtual_home',
        'cirque_get_home_topology',
        'cirque_destroy_home',
        'cirque_execute_device_cmd',
        'cirque_get_radio_state',
        'cirque_summarize_pcaps',
        'cirque_inspect_thread_mesh',
        'cirque_inject_rf_fault',
        'cirque_android_ui_and_video',
        'cirque_diagnose_home_health',
        'cirque_register_mcp_extension',
        'cirque_list_mcp_extensions',
    ]
    for exp in expected_tools:
      self.assertIn(exp, tool_names)

  def test_iteration1_tools_lifecycle(self):
    # 1. cirque_list_homes
    dev_mock = SimpleNamespace(
        name='mock_dev', type='IoTEndDevice', base_image='base:img'
    )
    self.mock_home.devices['dev1'] = dev_mock
    res = self.server._tool_list_homes({})
    self.assertEqual(res['total_count'], 1)
    self.assertEqual(res['homes'][0]['home_id'], 'home_test_123')

    # 2. cirque_create_virtual_home
    with patch('cirque.mcp.server.CirqueHome') as mock_home_cls:
      inst = MagicMock()
      inst.create_home.return_value = 'new_home_456'
      inst.devices = {'n1': MagicMock()}
      mock_home_cls.return_value = inst

      create_res1 = self.server._tool_create_virtual_home(
          {'preset': 'two_node_ble_wifi'}
      )
      self.assertEqual(create_res1['home_id'], 'new_home_456')

      create_res2 = self.server._tool_create_virtual_home(
          {'preset': 'android_ble_wifi'}
      )
      self.assertEqual(create_res2['home_id'], 'new_home_456')

      create_res3 = self.server._tool_create_virtual_home(
          {'preset': 'android_ble_thread'}
      )
      self.assertEqual(create_res3['home_id'], 'new_home_456')

      create_res4 = self.server._tool_create_virtual_home(
          {'config': {'node1': {'type': 'wifi_ap'}}}
      )
      self.assertEqual(create_res4['home_id'], 'new_home_456')

      with self.assertRaises(ValueError):
        self.server._tool_create_virtual_home({})

    # 3. cirque_get_home_topology
    self.mock_home.get_wifiap_ssid_psk.return_value = ('TestSSID', 'TestPSK')
    cap_mock = SimpleNamespace(name='Bluetooth', description={'dlt': 201})
    dev_with_cap = SimpleNamespace(
        name='dev_wifi',
        type='wifi_ap',
        base_image='img',
        capabilities=[cap_mock],
        get_docker_ip=MagicMock(return_value='10.0.1.1'),
        description={'info': 'test'},
    )
    self.mock_home.devices['dev_wifi'] = dev_with_cap
    top_res = self.server._tool_get_home_topology({'home_id': 'home_test_123'})
    self.assertEqual(top_res['home_id'], 'home_test_123')
    self.assertEqual(top_res['wifi_ssid_psk'], ('TestSSID', 'TestPSK'))
    self.assertIn('dev_wifi', top_res['devices'])

    # Failure mode for non-existent home
    with self.assertRaises(ValueError):
      self.server._tool_get_home_topology({'home_id': 'unknown_home'})

    # 4. cirque_execute_device_cmd
    self.mock_home.execute_device_cmd.return_value = SimpleNamespace(
        exit_code=0, output=b'echo hello\n'
    )
    cmd_res = self.server._tool_execute_device_cmd({
        'home_id': 'home_test_123',
        'device_id': 'dev_wifi',
        'cmd': 'echo hello',
    })
    self.assertEqual(cmd_res['return_code'], 0)
    self.assertEqual(cmd_res['output'].strip(), 'echo hello')

    with self.assertRaises(ValueError):
      self.server._tool_execute_device_cmd({
          'home_id': 'unknown',
          'device_id': 'x',
          'cmd': 'y',
      })
    with self.assertRaises(ValueError):
      self.server._tool_execute_device_cmd({
          'home_id': 'home_test_123',
          'device_id': 'unknown_dev',
          'cmd': 'y',
      })

    # 5. cirque_destroy_home
    self.mock_home.destroy_home.return_value = 'home_test_123'
    des_res = self.server._tool_destroy_home({'home_id': 'home_test_123'})
    self.assertEqual(des_res['status'], 'destroyed')

    # Destroy all
    self.homes['h_a'] = MagicMock()
    self.homes['h_b'] = MagicMock()
    des_all = self.server._tool_destroy_home({'home_id': 'all'})
    self.assertEqual(des_all['status'], 'destroyed_all')
    self.assertIn('h_a', des_all['destroyed_homes'])
    self.assertIn('h_b', des_all['destroyed_homes'])

  # ---------------------------------------------------------------------------
  # Iteration 2 Tools (Radio State, PCAPs, Thread Mesh)
  # ---------------------------------------------------------------------------

  def test_iteration2_radio_state_and_thread_mesh(self):
    # cirque_get_radio_state
    mock_android = MagicMock()
    mock_android.describe_radio_path.return_value = {'emulator_bt': True}
    self.mock_home.devices['android_node'] = mock_android

    rad_res = self.server._tool_get_radio_state({
        'home_id': 'home_test_123',
        'android_device_id': 'android_node',
    })
    self.assertIn('bluetooth', rad_res)
    self.assertIn('wifi', rad_res)
    self.assertIn('android_radio_path', rad_res)

    # cirque_summarize_pcaps
    # Write a dummy PCAP file into temp_dir
    pcap_path = os.path.join(self.temp_dir, 'wifi_medium.pcap')
    writer = PcapWriter(pcap_path, dlt=DLT_EN10MB)
    writer.write_frame(b'\x00' * 60)
    writer.close()

    pcap_res = self.server._tool_summarize_pcaps({'pcap_dir': self.temp_dir})
    self.assertEqual(pcap_res['pcap_count'], 1)
    self.assertEqual(pcap_res['files'][0]['dlt'], DLT_EN10MB)

    # Missing directory check
    missing_res = self.server._tool_summarize_pcaps({
        'pcap_dir': '/tmp/non_existent_cirque_dir_xyz'
    })
    self.assertEqual(missing_res['pcap_count'], 0)

    # cirque_inspect_thread_mesh
    tbr_mock = MagicMock()
    tbr_mock.type = 'ThreadBorderRouter'
    tbr_mock.capabilities = [SimpleNamespace(name='Thread')]
    self.mock_home.devices['tbr1'] = tbr_mock

    def fake_cmd(cmd, dev_id):
      if 'ot-ctl state' in cmd:
        return SimpleNamespace(exit_code=0, output=b'leader\n')
      if 'ot-ctl panid' in cmd:
        return SimpleNamespace(exit_code=0, output=b'0x1234\n')
      return SimpleNamespace(exit_code=0, output=b'mock\n')

    self.mock_home.execute_device_cmd = fake_cmd
    mesh_res = self.server._tool_inspect_thread_mesh({'home_id': 'home_test_123'})
    self.assertEqual(mesh_res['thread_node_count'], 1)
    self.assertEqual(mesh_res['nodes']['tbr1']['state'], 'leader')
    self.assertEqual(mesh_res['nodes']['tbr1']['panid'], '0x1234')

  # ---------------------------------------------------------------------------
  # Iteration 3 Tool (RF Fault Injection & Chaos Recipes)
  # ---------------------------------------------------------------------------

  def test_iteration3_rf_fault_injection(self):
    wifi_srv = WiFiCapability.get_or_start_virtual_server()
    wifi_srv.register_ap('MockSSID', 'MockPass123', ap_id='ap0')
    wifi_srv.register_station('wifi_mock_sta', mac_addr='02:00:00:00:02:99')
    # Recipes
    r1 = self.server._tool_inject_rf_fault({'recipe': 'ble_brownout'})
    self.assertIn('status', r1)
    r2 = self.server._tool_inject_rf_fault({'recipe': 'ble_restore'})
    self.assertIn('status', r2)
    r3 = self.server._tool_inject_rf_fault({'recipe': 'wifi_deauth_roam'})
    self.assertIn('status', r3)
    r4 = self.server._tool_inject_rf_fault({'recipe': 'clear_all_faults'})
    self.assertIn('status', r4)

    # Fine grained fault parameters
    fine_res = self.server._tool_inject_rf_fault({
        'bt_relay_enabled': True,
        'bt_packet_loss_rate': 0.1,
        'bt_latency_ms': 5.0,
        'bt_rssi_dbm': -60,
        'bt_src_bd_addr': '02:00:00:00:00:01',
        'bt_dst_bd_addr': '02:00:00:00:00:02',
        'wifi_drop_station': 'wifi_mock_sta',
        'wifi_deauth_station': 'wifi_mock_sta',
        'wifi_reassociate_station': 'wifi_mock_sta',
    })
    self.assertEqual(fine_res['status'], 'applied')
    self.assertTrue(len(fine_res['actions']) >= 7)
    self.server._tool_inject_rf_fault({'recipe': 'clear_all_faults'})

  def test_every_advertised_rf_fault_recipe_is_accepted(self):
    """Regression: the schema enum and the validation set must agree."""
    from cirque.connectivity.rf_channel_simulator import RfChannelSimulator

    resp = self.server.handle_message(
        {'jsonrpc': '2.0', 'id': 7, 'method': 'tools/list', 'params': {}}
    )
    tool = next(
        t
        for t in resp['result']['tools']
        if t['name'] == 'cirque_inject_rf_fault'
    )
    advertised = tool['inputSchema']['properties']['recipe']['enum']
    self.assertEqual(len(advertised), 5)

    rf_sim = RfChannelSimulator.get_shared()
    expected_regime = {
        'rf_cochannel_interference': 'regime_c_cochannel_interference',
    }
    def _verify_recipe(recipe):
      res = self.server._tool_inject_rf_fault({'recipe': recipe})
      self.assertIn('status', res)
      if recipe in expected_regime:
        self.assertEqual(rf_sim.config.regime_name, expected_regime[recipe])

    try:
      for recipe in advertised:
        with self.subTest(recipe=recipe):
          _verify_recipe(recipe)
      self.assertEqual(
          set(expected_regime), {r for r in advertised if r.startswith('rf_')}
      )
    finally:
      self.server._tool_inject_rf_fault({'recipe': 'clear_all_faults'})
      rf_sim.apply_regime_preset('ideal')

  # ---------------------------------------------------------------------------
  # Iteration 4 Tools (Android Commissioning, OnOff, UI & Video)
  # ---------------------------------------------------------------------------

  def test_iteration4_android_tools(self):
    android_mock = MagicMock()
    android_mock.type = 'android_emulator'
    android_mock.start_screen_recording.return_value = {
        'started': True,
        'name': 'test.mp4',
    }
    android_mock.stop_screen_recording.return_value = {
        'stopped': True,
        'name': 'test.mp4',
    }
    android_mock.commission_via_chiptool_ui.return_value = {
        'status': 'success',
        'network': 'wifi',
    }
    android_mock.commission_thread_via_chiptool_ui.return_value = {
        'status': 'success',
        'network': 'thread',
    }
    android_mock.toggle_onoff_via_chiptool_ui.return_value = {
        'status': 'success',
        'state': 'toggled',
    }
    android_mock.read_onoff_via_chiptool_ui.return_value = {
        'status': 'success',
        'value': 'ON',
    }
    android_mock.dump_ui_hierarchy.return_value = '<hierarchy></hierarchy>'
    android_mock.find_ui_element.return_value = (100, 200)
    android_mock.tap_ui_element.return_value = (100, 200)
    android_mock.input_text_ui_element.return_value = (100, 200)
    android_mock.list_screen_recordings.return_value = [
        {'name': 'test.mp4', 'size': 1234}
    ]

    self.mock_home.devices['android_emu'] = android_mock

    # cirque_android_ui_and_video actions
    dump_ui = self.server._tool_android_ui_and_video({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'action': 'dump_ui',
    })
    self.assertIn('xml', dump_ui)

    find_el = self.server._tool_android_ui_and_video({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'action': 'find_element',
        'text': 'Submit',
    })
    self.assertEqual(find_el['center'], (100, 200))

    tap_el = self.server._tool_android_ui_and_video({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'action': 'tap',
        'text': 'Submit',
    })
    self.assertEqual(tap_el['tapped_coords'], (100, 200))

    inp_el = self.server._tool_android_ui_and_video({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'action': 'input_text',
        'text_to_input': 'hello',
    })
    self.assertEqual(inp_el['injected_text'], 'hello')

    dism = self.server._tool_android_ui_and_video({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'action': 'dismiss_dialogs',
    })
    self.assertEqual(dism['status'], 'dismissed')

    s_rec = self.server._tool_android_ui_and_video({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'action': 'start_recording',
    })
    self.assertTrue(s_rec['recording']['started'])

    e_rec = self.server._tool_android_ui_and_video({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'action': 'stop_recording',
    })
    self.assertTrue(e_rec['recording']['stopped'])

    l_rec = self.server._tool_android_ui_and_video({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'action': 'list_recordings',
    })
    self.assertEqual(len(l_rec['recordings']), 1)

  # ---------------------------------------------------------------------------
  # Iteration 5 Tool, Resources & Prompts (Diagnose Health)
  # ---------------------------------------------------------------------------

  def test_iteration5_diagnose_health(self):
    diag = self.server._tool_diagnose_commissioning_health({
        'home_id': 'home_test_123'
    })
    self.assertIn('healthy', diag)
    self.assertIn('oracles', diag)
    self.assertIn('root_causes', diag)
    self.assertIn('remediation_steps', diag)

  def test_mcp_resources_list_and_read(self):
    self.homes['home_test_123'] = self.mock_home
    self.mock_home.get_wifiap_ssid_psk.return_value = ('TestSSID', 'TestPSK')
    # list resources
    list_req = {'jsonrpc': '2.0', 'id': 200, 'method': 'resources/list'}
    resp = self.server.handle_message(list_req)
    uris = [r['uri'] for r in resp['result']['resources']]
    self.assertIn('cirque://homes', uris)
    self.assertIn('cirque://homes/home_test_123/topology', uris)
    self.assertIn('cirque://homes/home_test_123/radio', uris)
    self.assertIn('cirque://homes/home_test_123/pcaps', uris)
    self.assertIn('cirque://homes/home_test_123/health', uris)

    # templates list
    tmpl_req = {
        'jsonrpc': '2.0',
        'id': 201,
        'method': 'resources/templates/list',
    }
    tmpl_resp = self.server.handle_message(tmpl_req)
    self.assertTrue(len(tmpl_resp['result']['resourceTemplates']) >= 6)

    # read cirque://homes
    r_homes = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 202,
        'method': 'resources/read',
        'params': {'uri': 'cirque://homes'},
    })
    self.assertEqual(
        r_homes['result']['contents'][0]['mimeType'], 'application/json'
    )

    # read cirque://homes/home_test_123/topology
    r_top = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 203,
        'method': 'resources/read',
        'params': {'uri': 'cirque://homes/home_test_123/topology'},
    })
    self.assertEqual(
        r_top['result']['contents'][0]['mimeType'], 'application/json'
    )

    # read cirque://homes/home_test_123/radio
    r_rad = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 204,
        'method': 'resources/read',
        'params': {'uri': 'cirque://homes/home_test_123/radio'},
    })
    self.assertEqual(
        r_rad['result']['contents'][0]['mimeType'], 'application/json'
    )

    # read cirque://homes/home_test_123/pcaps
    r_pcap = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 205,
        'method': 'resources/read',
        'params': {'uri': 'cirque://homes/home_test_123/pcaps'},
    })
    self.assertEqual(
        r_pcap['result']['contents'][0]['mimeType'], 'application/json'
    )

    # read cirque://homes/home_test_123/health
    r_hlt = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 206,
        'method': 'resources/read',
        'params': {'uri': 'cirque://homes/home_test_123/health'},
    })
    self.assertEqual(
        r_hlt['result']['contents'][0]['mimeType'], 'application/json'
    )

    # read cirque://homes/home_test_123/devices/dev1/logs
    self.mock_home.devices['dev1'] = SimpleNamespace(name='dev1', type='IoTEndDevice')
    self.mock_home.get_device_log.return_value = 'sample device logs'
    r_log = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 207,
        'method': 'resources/read',
        'params': {'uri': 'cirque://homes/home_test_123/devices/dev1/logs'},
    })
    self.assertEqual(r_log['result']['contents'][0]['text'], 'sample device logs')

    # read cirque://homes/home_test_123/devices/dev1/videos
    dev_with_vids = SimpleNamespace(
        list_screen_recordings=MagicMock(return_value=[{'name': 'vid1.mp4'}])
    )
    self.mock_home.devices['dev_vid'] = dev_with_vids
    r_vid = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 208,
        'method': 'resources/read',
        'params': {'uri': 'cirque://homes/home_test_123/devices/dev_vid/videos'},
    })
    self.assertIn('vid1.mp4', r_vid['result']['contents'][0]['text'])

    # read invalid scheme or not found
    r_inv = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 209,
        'method': 'resources/read',
        'params': {'uri': 'http://invalid'},
    })
    self.assertEqual(r_inv['error']['code'], -32602)

  def test_mcp_prompts_list_and_get(self):
    # list prompts
    p_list = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 300,
        'method': 'prompts/list',
    })
    prompts = p_list['result']['prompts']
    p_names = [p['name'] for p in prompts]
    self.assertIn('debug_commissioning_failure', p_names)
    self.assertIn('rf_chaos_resilience_drill', p_names)
    self.assertIn('thread_border_router_triage', p_names)
    self.assertIn('android_matter_certification', p_names)

    # get prompts
    for p_name in p_names:
      p_get = self.server.handle_message({
          'jsonrpc': '2.0',
          'id': 301,
          'method': 'prompts/get',
          'params': {'name': p_name, 'arguments': {'home_id': 'h1'}},
      })
      self.assertIn('messages', p_get['result'])

    # prompt not found
    p_nf = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 302,
        'method': 'prompts/get',
        'params': {'name': 'unknown_prompt'},
    })
    self.assertEqual(p_nf['error']['code'], -32602)

  # ---------------------------------------------------------------------------
  # Stdio Stream Processing & CLI main()
  # ---------------------------------------------------------------------------

  def test_handle_stream_stdio(self):
    input_lines = (
        json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'ping'})
        + '\n'
        + 'not a json\n'
        + json.dumps({
            'jsonrpc': '2.0',
            'id': 2,
            'method': 'tools/call',
            'params': {'name': 'cirque_list_homes', 'arguments': {}},
        })
        + '\n'
    )
    in_buf = io.StringIO(input_lines)
    out_buf = io.StringIO()

    self.server.handle_stream(in_stream=in_buf, out_stream=out_buf)
    output = out_buf.getvalue().strip().splitlines()
    self.assertEqual(len(output), 3)

    resp1 = json.loads(output[0])
    self.assertEqual(resp1['id'], 1)

    resp2 = json.loads(output[1])
    self.assertEqual(resp2['error']['code'], -32700)

    resp3 = json.loads(output[2])
    self.assertEqual(resp3['id'], 2)
    self.assertIn('content', resp3['result'])

  def test_cli_main_entrypoint(self):
    with patch.object(sys, 'argv', ['cirque-mcp-server']), patch(
        'cirque.mcp.server.CirqueMcpServer.handle_stream'
    ) as mock_stream:
      main()
      mock_stream.assert_called_once()

  # ---------------------------------------------------------------------------
  # Flask REST Service Integration (/mcp & /mcp/tools)
  # ---------------------------------------------------------------------------

  def test_flask_rest_mcp_endpoints(self):
    test_client = service.app.test_client()
    service.homes['h_flask'] = self.mock_home

    try:
      # POST /mcp valid ping
      res = test_client.post(
          '/mcp',
          json={'jsonrpc': '2.0', 'id': 500, 'method': 'ping'},
      )
      self.assertEqual(res.status_code, 200)
      self.assertEqual(res.get_json()['id'], 500)

      # POST /mcp notification
      res_notif = test_client.post(
          '/mcp',
          json={'jsonrpc': '2.0', 'method': 'notifications/initialized'},
      )
      self.assertEqual(res_notif.status_code, 204)

      # POST /mcp parse error
      res_err = test_client.post(
          '/mcp',
          data='invalid json content',
          content_type='application/json',
      )
      self.assertEqual(res_err.status_code, 400)
      self.assertEqual(res_err.get_json()['error']['code'], -32700)

      # GET /mcp/tools discovery endpoint
      res_tools = test_client.get('/mcp/tools')
      self.assertEqual(res_tools.status_code, 200)
      data = res_tools.get_json()
      self.assertIn('tools', data)
      self.assertIn('resources', data)
      self.assertIn('prompts', data)
      self.assertTrue(len(data['tools']) >= 12)
      self.assertTrue(len(data['resources']) >= 1)
      self.assertTrue(len(data['prompts']) >= 4)

      # GET /mcp/extensions
      res_ext = test_client.get('/mcp/extensions')
      self.assertEqual(res_ext.status_code, 200)
      ext_data = res_ext.get_json()
      self.assertIn('loaded_extensions', ext_data)
      self.assertIn('tools', ext_data)

      # POST /mcp/extensions/register missing parameter
      res_reg_err = test_client.post('/mcp/extensions/register', json={})
      self.assertEqual(res_reg_err.status_code, 400)

      # Create temporary dummy extension file
      dummy_ext_path = os.path.join(self.temp_dir, 'dummy_rest_ext.py')
      with open(dummy_ext_path, 'w', encoding='utf-8') as f:
        f.write(
            'def register_cirque_extension(server):\n'
            '  server.register_tool({\n'
            '      "name": "dummy_rest_tool",\n'
            '      "description": "Dummy tool",\n'
            '      "inputSchema": {"type": "object", "properties": {}}\n'
            '  }, lambda args: {"status": "ok"}, extension_name="dummy_rest")\n'
        )

      res_reg_ok = test_client.post(
          '/mcp/extensions/register',
          json={'module_or_path': dummy_ext_path},
      )
      self.assertEqual(res_reg_ok.status_code, 200)
      reg_json = res_reg_ok.get_json()
      self.assertEqual(reg_json['status'], 'registered')
      self.assertIn('dummy_rest_tool', reg_json['extensions']['tools'])
    finally:
      service.homes.pop('h_flask', None)
      service.TaskRunner.stop()

  # ---------------------------------------------------------------------------
  # Dynamic Extension Registration Unit Tests
  # ---------------------------------------------------------------------------

  def test_dynamic_extension_registration_api(self):
    server = CirqueMcpServer()

    # 1. register_tool
    server.register_tool(
        {
            'name': 'ext_tool_foo',
            'description': 'Custom extension tool',
            'inputSchema': {'type': 'object', 'properties': {'x': {'type': 'integer'}}},
        },
        lambda args: {'result': args.get('x', 0) * 2},
        extension_name='ext_foo',
    )
    tools_list = server.handle_message({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'})
    tool_names = [t['name'] for t in tools_list['result']['tools']]
    self.assertIn('ext_tool_foo', tool_names)

    call_res = server.handle_message({
        'jsonrpc': '2.0',
        'id': 2,
        'method': 'tools/call',
        'params': {'name': 'ext_tool_foo', 'arguments': {'x': 21}},
    })
    self.assertEqual(json.loads(call_res['result']['content'][0]['text'])['result'], 42)

    # 2. register_resource & read
    server.register_resource(
        {
            'uri': 'cirque://ext/static',
            'name': 'Static Ext Resource',
            'mimeType': 'application/json',
        },
        reader_fn=lambda uri: {'static': True},
        extension_name='ext_foo',
    )
    res_list = server.handle_message({'jsonrpc': '2.0', 'id': 3, 'method': 'resources/list'})
    res_uris = [r['uri'] for r in res_list['result']['resources']]
    self.assertIn('cirque://ext/static', res_uris)

    read_res = server.handle_message({
        'jsonrpc': '2.0',
        'id': 4,
        'method': 'resources/read',
        'params': {'uri': 'cirque://ext/static'},
    })
    self.assertEqual(json.loads(read_res['result']['contents'][0]['text'])['static'], True)

    # 3. register_resource_template & read
    server.register_resource_template(
        {
            'uriTemplate': 'cirque://ext/items/{item_id}',
            'name': 'Item Resource',
            'mimeType': 'application/json',
        },
        pattern=r'^cirque://ext/items/([^/]+)$',
        reader_fn=lambda uri, m: {'item_id': m.group(1)},
        extension_name='ext_foo',
    )
    tmpl_list = server.handle_message({'jsonrpc': '2.0', 'id': 5, 'method': 'resources/templates/list'})
    tmpl_uris = [t['uriTemplate'] for t in tmpl_list['result']['resourceTemplates']]
    self.assertIn('cirque://ext/items/{item_id}', tmpl_uris)

    read_tmpl = server.handle_message({
        'jsonrpc': '2.0',
        'id': 6,
        'method': 'resources/read',
        'params': {'uri': 'cirque://ext/items/abc123'},
    })
    self.assertEqual(json.loads(read_tmpl['result']['contents'][0]['text'])['item_id'], 'abc123')

    # 4. register_prompt & get
    server.register_prompt(
        {
            'name': 'ext_prompt_test',
            'description': 'Custom prompt',
            'arguments': [{'name': 'target', 'required': True}],
        },
        renderer_fn=lambda args: f'Hello {args.get("target")}',
        extension_name='ext_foo',
    )
    p_list = server.handle_message({'jsonrpc': '2.0', 'id': 7, 'method': 'prompts/list'})
    p_names = [p['name'] for p in p_list['result']['prompts']]
    self.assertIn('ext_prompt_test', p_names)

    p_get = server.handle_message({
        'jsonrpc': '2.0',
        'id': 8,
        'method': 'prompts/get',
        'params': {'name': 'ext_prompt_test', 'arguments': {'target': 'World'}},
    })
    self.assertEqual(p_get['result']['messages'][0]['content']['text'], 'Hello World')

    # 5. register_health_oracle hook into cirque_diagnose_home_health
    def custom_oracle(home, android_id):
      return {
          'healthy': False,
          'oracles': {'custom_check': False},
          'root_causes': ['Custom failure detected'],
          'remediation_steps': ['Fix custom issue'],
      }
    server.register_health_oracle('custom_oracle', custom_oracle, extension_name='ext_foo')

    home_mock = MagicMock()
    home_mock.devices = {}
    with self.assertRaises(ValueError):
      server._tool_diagnose_home_health({'home_id': 'missing_home'})

    server._local_homes['h1'] = home_mock
    diag_res = server._tool_diagnose_home_health({'home_id': 'h1'})
    self.assertFalse(diag_res['healthy'])
    self.assertIn('Custom failure detected', diag_res['root_causes'])
    self.assertIn('custom_check', diag_res['oracles'])
    self.assertIn('custom_oracle', diag_res['extension_findings'])

    # 6. cirque_register_mcp_extension & cirque_list_mcp_extensions tools
    ext_list_tool = server._tool_list_mcp_extensions({})
    self.assertIn('ext_tool_foo', ext_list_tool['tools'])

    dummy_ext_path2 = os.path.join(self.temp_dir, 'dummy_tool_ext.py')
    with open(dummy_ext_path2, 'w', encoding='utf-8') as f:
      f.write(
          'def register_cirque_extension(server):\n'
          '  server.register_tool({\n'
          '      "name": "dyn_tool",\n'
          '      "description": "Dynamic tool",\n'
          '      "inputSchema": {"type": "object", "properties": {}}\n'
          '  }, lambda args: {"dyn": True}, extension_name="dyn_mod")\n'
      )

    reg_tool_res = server._tool_register_mcp_extension({'module_or_path': dummy_ext_path2})
    self.assertEqual(reg_tool_res['status'], 'registered')
    self.assertIn('dyn_tool', reg_tool_res['extensions']['tools'])

  # ---------------------------------------------------------------------------
  # Edge Cases & Branch Coverage Hardening (>=95% coverage)
  # ---------------------------------------------------------------------------

  def test_edge_cases_and_error_branches(self):
    # tools/call unknown tool error
    resp_unk = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 991,
        'method': 'tools/call',
        'params': {'name': 'non_existent_tool', 'arguments': {}},
    })
    self.assertEqual(resp_unk['error']['code'], -32601)

    # tools/call execution exception (isError: True)
    resp_exc = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 992,
        'method': 'tools/call',
        'params': {'name': 'cirque_get_home_topology', 'arguments': {'home_id': 'invalid'}},
    })
    self.assertTrue(resp_exc['result']['isError'])

    # cirque_android_ui_and_video error paths
    with self.assertRaises(ValueError):
      self.server._tool_android_ui_and_video({'home_id': 'missing', 'device_id': 'd', 'action': 'dump_ui'})
    with self.assertRaises(ValueError):
      self.server._tool_android_ui_and_video({'home_id': 'home_test_123', 'device_id': 'missing', 'action': 'dump_ui'})
    with self.assertRaises(ValueError):
      self.server._tool_android_ui_and_video({'home_id': 'home_test_123', 'device_id': 'good_node', 'action': 'unknown_ui_action'})

    # cirque_diagnose_commissioning_health error paths & Thread mesh oracles
    with self.assertRaises(ValueError):
      self.server._tool_diagnose_commissioning_health({'home_id': 'missing'})

    # Test diagnose with Thread node and Android node
    android_dev = MagicMock()
    android_dev.type = 'android_emulator'
    android_dev._chiptool_logcat_contains = MagicMock(return_value=True)
    tbr_dev = MagicMock()
    tbr_dev.type = 'ThreadBorderRouter'
    tbr_dev.capabilities = [SimpleNamespace(name='Thread')]
    self.mock_home.devices['android_node'] = android_dev
    self.mock_home.devices['tbr_node'] = tbr_dev

    self.mock_home.execute_device_cmd = MagicMock(
        return_value=SimpleNamespace(exit_code=0, output=b'leader\n')
    )
    diag_full = self.server._tool_diagnose_commissioning_health({
        'home_id': 'home_test_123',
        'android_device_id': 'android_node',
    })
    self.assertIn('thread_leader_elected', diag_full['oracles'])
    self.assertTrue(diag_full['oracles']['pase_established'])
    self.assertTrue(diag_full['oracles']['case_established'])

    # Test default local_homes when no external homes_provider given
    default_server = CirqueMcpServer()
    self.assertIsInstance(default_server.homes, dict)

    # Test stream execution exception in device_cmd
    dev_stream_mock = SimpleNamespace(
        name='stream_dev',
        type='IoTEndDevice',
        base_image='base',
        capabilities=[],
        get_docker_ip=MagicMock(side_effect=Exception('no ip')),
    )
    self.mock_home.devices['stream_dev'] = dev_stream_mock
    self.mock_home.execute_device_cmd = MagicMock(
        return_value=SimpleNamespace(exit_code=0, output=b'stream_data')
    )
    cmd_stream_res = self.server._tool_execute_device_cmd({
        'home_id': 'home_test_123',
        'device_id': 'stream_dev',
        'cmd': 'ls',
        'stream': True,
    })
    self.assertEqual(cmd_stream_res['output'], 'stream_data')

    # Test top-level topology with IP exception covered
    top_res2 = self.server._tool_get_home_topology({'home_id': 'home_test_123'})
    self.assertIsNone(top_res2['devices']['stream_dev']['ipv4'])

    # Test inspect thread mesh device command failure
    tbr_fail = MagicMock()
    tbr_fail.type = 'ThreadBorderRouter'
    tbr_fail.capabilities = [SimpleNamespace(name='Thread')]
    self.mock_home.devices['tbr_fail'] = tbr_fail
    self.mock_home.execute_device_cmd = MagicMock(side_effect=Exception('cmd failed'))
    mesh_fail = self.server._tool_inspect_thread_mesh({'home_id': 'home_test_123'})
    self.assertIn('Error: cmd failed', mesh_fail['nodes']['tbr_fail']['state'])

    # Test summarize_pcaps with corrupt pcap file
    corrupt_pcap = os.path.join(self.temp_dir, 'corrupt.pcap')
    with open(corrupt_pcap, 'wb') as f:
      f.write(b'short')
    pcap_corrupt_res = self.server._tool_summarize_pcaps({'pcap_dir': self.temp_dir})
    self.assertTrue(any('error' in f for f in pcap_corrupt_res['files']))

    # Test diagnose_commissioning_health with disabled BT relay and no leader
    bt_server = BlueToothCapability.get_or_start_virtual_server()
    bt_server.set_relay_enabled(False)
    self.mock_home.execute_device_cmd = MagicMock(
        return_value=SimpleNamespace(exit_code=0, output=b'detached\n')
    )
    diag_unhealthy = self.server._tool_diagnose_commissioning_health({
        'home_id': 'home_test_123',
        'android_device_id': 'stream_dev',
    })
    self.assertFalse(diag_unhealthy['healthy'])
    self.assertTrue(len(diag_unhealthy['root_causes']) >= 2)
    bt_server.set_relay_enabled(True)

    # Test resources/read with missing devices
    r_bad_log = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 993,
        'method': 'resources/read',
        'params': {'uri': 'cirque://homes/home_test_123/devices/non_existent_dev/logs'},
    })
    self.assertEqual(r_bad_log['error']['code'], -32603)

    r_bad_vid = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 994,
        'method': 'resources/read',
        'params': {'uri': 'cirque://homes/home_test_123/devices/non_existent_dev/videos'},
    })
    self.assertEqual(r_bad_vid['error']['code'], -32603)

    r_not_found_res = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 995,
        'method': 'resources/read',
        'params': {'uri': 'cirque://homes/home_test_123/unsupported_resource'},
    })
    self.assertEqual(r_not_found_res['error']['code'], -32602)

  # ---------------------------------------------------------------------------
  # Cross-Layer Flow Visualizer, MCP Tool, and REST Endpoint Tests
  # ---------------------------------------------------------------------------

  def test_flow_visualizer_and_mcp_tools(self):
    from cirque.pcap.flow_visualizer import FlowEvent, generate_flow_html

    # 1. Test event recording and retrieval
    ev1 = self.server.record_flow_event({
        'layer': 'APP',
        'sublayer': 'HANDSHAKE',
        'stage': 'APP_HANDSHAKE',
        'src': 'Controller',
        'dst': 'Accessory',
        'title': 'AppHelloRequest',
        'summary': 'Application hello request',
        'encapsulation': ['BLE', 'ATT', 'APP'],
        'payload_hex': '0102030405',
    })
    self.assertIn('event_id', ev1)
    events = self.server.get_flow_events()
    self.assertEqual(len(events), 1)

    # 2. Test dissector and layer metadata registration
    def dummy_dissector(ev: FlowEvent) -> FlowEvent:
      if ev.layer == 'APP':
        ev.details['dissected_by'] = 'test_dissector'
      return ev

    self.server.register_flow_dissector('test_dissector', dummy_dissector)
    self.server.register_flow_layer(
        'APP', {'label': 'Application', 'color': 'amber', 'order': 10}
    )

    # 3. Test cirque_generate_flow_visualization tool
    out_html = os.path.join(self.temp_dir, 'custom_studio.html')
    out_json = os.path.join(self.temp_dir, 'custom_trace.json')

    vis_res = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 701,
        'method': 'tools/call',
        'params': {
            'name': 'cirque_generate_flow_visualization',
            'arguments': {
                'pcap_dir': self.temp_dir,
                'output_html': out_html,
                'output_json': out_json,
                'title': 'Test Studio Run',
            },
        },
    })
    self.assertEqual(vis_res['id'], 701)
    payload_str = vis_res['result']['content'][0]['text']
    data = json.loads(payload_str)
    self.assertEqual(data['status'], 'success')
    self.assertTrue(os.path.isfile(out_html))
    self.assertTrue(os.path.isfile(out_json))
    self.assertGreaterEqual(data['total_events'], 1)
    self.assertIn('APP', data['layer_counts'])
    with open(out_json, 'r', encoding='utf-8') as f:
      trace = json.load(f)
    self.assertEqual(trace[0]['details']['dissected_by'], 'test_dissector')

    # Verify HTML contains Tailwind, semantic variables and the plugin layer
    with open(out_html, 'r', encoding='utf-8') as f:
      html_content = f.read()
    self.assertIn('cdn.tailwindcss.com', html_content)
    self.assertIn('var(--card)', html_content)
    self.assertIn('var(--background)', html_content)
    self.assertNotIn('fill="var(--card)"', html_content)
    self.assertNotIn('fill="var(--secondary)"', html_content)
    self.assertIn('id="filter-btn-APP"', html_content)
    self.assertIn('Application (1)', html_content)
    self.assertIn('"APP": "amber"', html_content)
    self.assertIn('id="sequence-diagram-svg"', html_content)
    self.assertIn('<marker id="arrowhead"', html_content)
    self.assertIn('participant-lifeline', html_content)
    self.assertIn('stage-divider', html_content)
    self.assertIn('message-arrow-group', html_content)
    self.assertIn('renderSequenceDiagram', html_content)
    self.assertIn('toggleLayerOverlay', html_content)
    self.assertIn('setLayerPreset', html_content)
    self.assertIn('btn-preset-ble-matter', html_content)
    self.assertIn('btn-preset-thread-matter', html_content)
    self.assertIn('seq-participant-box', html_content)
    self.assertIn('seq-stage-box', html_content)
    self.assertIn('seq-pill-bg', html_content)

    # 4. Test cirque://flow/visualization resource read
    r_flow = self.server.handle_message({
        'jsonrpc': '2.0',
        'id': 702,
        'method': 'resources/read',
        'params': {'uri': 'cirque://flow/visualization'},
    })
    self.assertEqual(r_flow['id'], 702)
    flow_content = json.loads(r_flow['result']['contents'][0]['text'])
    self.assertEqual(flow_content['status'], 'success')
    self.assertEqual(flow_content['html_path'], out_html)

    # 5. Test REST endpoint /mcp/visualize
    app_client = service.app.test_client()
    service.app._cirque_mcp_server = self.server

    rest_resp = app_client.get(f'/mcp/visualize?pcap_dir={self.temp_dir}')
    self.assertEqual(rest_resp.status_code, 200)
    rest_data = json.loads(rest_resp.data.decode('utf-8'))
    self.assertEqual(rest_data.get('status'), 'success')

    # Test clear_flow_events
    cleared = self.server.clear_flow_events()
    self.assertEqual(cleared, 1)
    self.assertEqual(len(self.server.get_flow_events()), 0)

  def _write_flow_fixture_pcaps(self, pcap_dir):
    """Writes BT HCI, BT LE LL and Wi-Fi pcaps with app-agnostic payloads."""
    from cirque.capabilities.pcapcapability import (
        DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
        DLT_BLUETOOTH_LE_LL_WITH_PHDR,
        build_le_ll_phdr_frame,
    )

    l2cap = struct.pack('<HH', 7, 0x0004) + bytes.fromhex('120b00aabbcc01')
    acl = b'\x02' + struct.pack('<HH', 0x40, len(l2cap)) + l2cap
    writer = PcapWriter(
        os.path.join(pcap_dir, 'bt_hci_test.pcap'),
        dlt=DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
    )
    writer.write_frame(struct.pack('>I', 0) + acl, 1000.0)
    writer.close()

    adv_data = bytes.fromhex('020106') + bytes.fromhex('0516341201ff')
    writer = PcapWriter(
        os.path.join(pcap_dir, 'bt_medium_test.pcap'),
        dlt=DLT_BLUETOOTH_LE_LL_WITH_PHDR,
    )
    writer.write_frame(
        build_le_ll_phdr_frame(
            'ADV_IND', '11:22:33:44:55:66', payload=adv_data
        ),
        1000.1,
    )
    writer.close()

    udp = struct.pack('>HHHH', 40000, 7777, 12, 0) + b'ping'
    ip = (
        bytes([0x45, 0])
        + struct.pack('>H', 20 + len(udp))
        + bytes(4)
        + bytes([64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2])
    )
    writer = PcapWriter(
        os.path.join(pcap_dir, 'wifi_test.pcap'), dlt=DLT_EN10MB
    )
    writer.write_frame(
        bytes.fromhex('020000000002020000000001') + b'\x08\x00' + ip + udp,
        1000.2,
    )
    writer.close()

  def test_flow_core_is_protocol_agnostic(self):
    from cirque.pcap.flow_visualizer import (
        dissect_pcap_directory,
        merge_and_sort_flow_events,
    )

    self._write_flow_fixture_pcaps(self.temp_dir)
    events = merge_and_sort_flow_events(
        dissect_pcap_directory(self.temp_dir), [{'title': 'untyped'}]
    )
    by_file = {ev.details.get('pcap_file'): ev for ev in events}

    # Without plugins only link/transport layers (and the neutral default for
    # untyped recorded events) are emitted.
    self.assertEqual({ev.layer for ev in events}, {'BT', 'WIFI', 'GENERAL'})
    att = by_file['bt_hci_test.pcap']
    self.assertEqual(att.sublayer, 'ATT')
    self.assertEqual(att.details['att_handle'], '0x000b')
    self.assertEqual(att.details['att_value_hex'], 'aabbcc01')
    self.assertIsNone(att.replay_mcp_call)
    adv = by_file['bt_medium_test.pcap']
    self.assertEqual(adv.details['ad_service_uuids'], ['0x1234'])
    udp = by_file['wifi_test.pcap']
    self.assertEqual(udp.sublayer, 'UDP')
    self.assertEqual(
        (udp.details['src_port'], udp.details['dst_port']), (40000, 7777)
    )

  def test_le_ll_advertiser_address_offset(self):
    from cirque.capabilities.pcapcapability import build_le_ll_phdr_frame
    from cirque.pcap.flow_visualizer import dissect_le_ll_packet

    adv_aa = 0x8E89BED6
    phdr = struct.pack('<bbbBIH', 0, -45, -90, 0, adv_aa, 0)
    # LL PDU: header (ADV_IND, TxAdd=1), length, AdvA (LE), AdvData, CRC.
    pdu = (
        bytes([0x40, 9])
        + bytes.fromhex('665544332211')
        + bytes.fromhex('020106')
        + bytes(3)
    )
    adv = dissect_le_ll_packet(
        1.0, phdr + struct.pack('<I', adv_aa) + pdu, 'bt_medium.pcap', 0
    )
    self.assertEqual(adv.details['pdu_type'], 'ADV_IND')
    self.assertEqual(adv.details['adv_addr'], '11:22:33:44:55:66')
    self.assertEqual(adv.src, '11:22:33:44:55:66')

    connect = dissect_le_ll_packet(
        2.0,
        build_le_ll_phdr_frame(
            'CONNECT_IND', '0A:0B:0C:0D:0E:0F', '11:22:33:44:55:66'
        ),
        'bt_medium.pcap',
        1,
    )
    self.assertEqual(
        (connect.src, connect.dst), ('0A:0B:0C:0D:0E:0F', '11:22:33:44:55:66')
    )

  def test_flow_visualizer_cli_plugin(self):
    from cirque.pcap import flow_visualizer

    self._write_flow_fixture_pcaps(self.temp_dir)
    plugin_path = os.path.join(self.temp_dir, 'app_flow_plugin.py')
    # The plugin returns a new FlowEvent built from the canonical module, which
    # must be accepted when the CLI runs as `python -m`.
    with open(plugin_path, 'w', encoding='utf-8') as f:
      f.write(
          'from cirque.pcap.flow_visualizer import FlowEvent\n'
          'def classify(event):\n'
          "  if event.details.get('dst_port') == 7777:\n"
          "    return FlowEvent(**dict(event.to_dict(), layer='APP',"
          " title='App Ping'))\n"
          '  return None\n'
          "FLOW_DISSECTORS = {'app': classify}\n"
          "FLOW_LAYERS = {'APP': {'label': 'Application', 'color': 'amber',"
          " 'order': 10}}\n"
      )
    out_html = os.path.join(self.temp_dir, 'cli.html')
    out_json = os.path.join(self.temp_dir, 'cli.json')

    def run_cli(*extra):
      subprocess.run(
          [
              sys.executable,
              '-m',
              'cirque.pcap.flow_visualizer',
              '--pcap-dir',
              self.temp_dir,
              '--output',
              out_html,
              '--json-output',
              out_json,
              *extra,
          ],
          check=True,
          cwd=self.temp_dir,
          env=dict(os.environ, PYTHONPATH=CIRQUE_ROOT),
          capture_output=True,
      )
      with open(out_json, 'r', encoding='utf-8') as f:
        trace = json.load(f)
      with open(out_html, 'r', encoding='utf-8') as f:
        return trace, f.read()

    trace, html_content = run_cli()
    self.assertNotIn('APP', {ev['layer'] for ev in trace})
    self.assertNotIn('filter-btn-APP', html_content)

    trace, html_content = run_cli('--plugin', plugin_path)
    app_events = [ev for ev in trace if ev['layer'] == 'APP']
    self.assertEqual([ev['title'] for ev in app_events], ['App Ping'])
    self.assertIn('id="filter-btn-APP"', html_content)
    self.assertIn('Application (1)', html_content)
    self.assertEqual(len(trace), 3)

    with self.assertRaises(FileNotFoundError):
      flow_visualizer.load_flow_plugin(plugin_path + '.missing')

  def test_flow_dissectors_are_isolated(self):
    from cirque.pcap.flow_visualizer import (
        FlowEvent,
        generate_flow_html,
        merge_and_sort_flow_events,
    )

    recorded = [
        {'event_id': 'a', 'timestamp': 1.0, 'title': 'first'},
        {
            'event_id': 'b',
            'timestamp': 2.0,
            'title': 'boom',
            'encapsulation': ['L2'],
        },
        {'event_id': 'c', 'timestamp': 3.0, 'title': 'third', 'layer': None},
        FlowEvent(
            event_id='d',
            timestamp=4.0,
            layer='APP',
            sublayer='X',
            stage='S',
            src='s',
            dst='d',
            title='fourth',
            summary='',
        ),
    ]

    def tag(ev):
      ev.encapsulation.append('TAG')
      ev.details['seen'] = True
      return ev

    def explode(ev):
      if ev.title == 'boom':
        raise RuntimeError('boom')
      ev.stage = 'EXPLODE_OK'
      return ev

    def bad_return(ev):
      return {'not': 'an event'}

    dissectors = {'tag': tag, 'explode': explode, 'bad': bad_return}
    for _ in range(2):
      merged = merge_and_sort_flow_events([], recorded, dissectors=dissectors)
    # Stored recorded events are never mutated by dissectors.
    self.assertEqual(recorded[1]['encapsulation'], ['L2'])
    self.assertNotIn('details', recorded[0])
    self.assertEqual(recorded[3].encapsulation, [])
    self.assertEqual([ev.event_id for ev in merged], ['a', 'b', 'c', 'd'])
    self.assertEqual(merged[1].encapsulation, ['L2', 'TAG'])
    # A raising dissector only skips its failing event.
    self.assertEqual(
        [ev.stage for ev in merged],
        ['EXPLODE_OK', 'GENERAL', 'EXPLODE_OK', 'EXPLODE_OK'],
    )
    self.assertEqual(merged[2].layer, 'GENERAL')

    # Embedded JSON cannot close the <script>; bad colors fall back to slate.
    merged[0].title = '</script><b>x</b>'
    out_html = os.path.join(self.temp_dir, 'escaped.html')
    generate_flow_html(
        merged, out_html, layers={'APP': {'color': 'red;x', 'label': 'App'}}
    )
    with open(out_html, 'r', encoding='utf-8') as f:
      html_content = f.read()
    self.assertNotIn('</script><b>', html_content)
    self.assertIn('\\u003c/script>', html_content)
    self.assertIn('"APP": "slate"', html_content)

  def test_rf_fault_clear_all_faults_and_relay_decoupling(self):
    """Verifies Items 1 & 11: clear_all_faults & relay decoupling."""
    from cirque.virtual_bt.link_layer import LinkLayerFrame

    bt_srv = BlueToothCapability.get_or_start_virtual_server()
    wifi_srv = WiFiCapability.get_or_start_virtual_server()
    hub = bt_srv.phy_hub
    hub.reset_medium()

    received = []
    addr_a = 'AA:BB:CC:DD:EE:01'
    addr_b = 'AA:BB:CC:DD:EE:02'
    hub.register_local_endpoint(addr_a, lambda f: None)
    hub.register_local_endpoint(addr_b, received.append)

    # Item 11: set 40% loss, toggle relay False -> True, verify 40% preserved
    self.server._tool_inject_rf_fault({'bt_packet_loss_rate': 0.4})
    self.server._tool_inject_rf_fault({'bt_relay_enabled': False})
    self.assertEqual(
        self.server._tool_get_radio_state({})['bluetooth'][
            'effective_packet_loss_rate'
        ],
        1.0,
    )
    for i in range(20):
      hub.transmit(
          LinkLayerFrame(
              pdu_type='DATA',
              src_bd_addr=addr_a,
              dst_bd_addr=addr_b,
              payload_hex=f'{i:04x}',
          )
      )
    self.assertEqual(len(received), 0)

    self.server._tool_inject_rf_fault({'bt_relay_enabled': True})
    self.assertAlmostEqual(hub._packet_loss_rate, 0.4)
    for i in range(200):
      hub.transmit(
          LinkLayerFrame(
              pdu_type='DATA',
              src_bd_addr=addr_a,
              dst_bd_addr=addr_b,
              payload_hex=f'{i + 100:04x}',
          )
      )
    self.assertGreater(len(received), 60)
    self.assertLess(len(received), 180)

    # Item 11 health check when bt_relay_enabled=True and loss=1.0
    self.server._tool_inject_rf_fault({'bt_packet_loss_rate': 1.0})
    diag = self.server._tool_diagnose_commissioning_health(
        {'home_id': 'home_test_123'}
    )
    self.assertFalse(diag['healthy'])
    self.assertFalse(diag['oracles']['bt_packet_loss_healthy'])
    self.assertEqual(diag['oracles']['bt_effective_packet_loss_rate'], 1.0)

    # Item 1: set pairwise RSSI, isolated addr, and disconnected Wi-Fi station
    wifi_srv.register_ap('TestSSID', 'TestPSK123', ap_id='ap0')
    sta = wifi_srv.register_station(
        'sta_clear_test', mac_addr='02:00:00:00:02:55'
    )
    wifi_srv.disconnect_station('sta_clear_test', reason='dropped')
    self.server._tool_inject_rf_fault({
        'bt_rssi_dbm': -92,
        'bt_src_bd_addr': addr_a,
        'bt_dst_bd_addr': addr_b,
    })
    hub.set_isolated(addr_b, True)

    clear_res = self.server._tool_inject_rf_fault(
        {'recipe': 'clear_all_faults'}
    )
    self.assertEqual(clear_res['cleared']['rssi_matrix_cleared'], 1)
    self.assertEqual(clear_res['cleared']['isolated_addresses_cleared'], 1)
    self.assertIn(
        'sta_clear_test', clear_res['cleared']['wifi_stations_restored']
    )
    self.assertEqual(sta.state, 'completed')

    received.clear()
    for i in range(100):
      hub.transmit(
          LinkLayerFrame(
              pdu_type='DATA',
              src_bd_addr=addr_a,
              dst_bd_addr=addr_b,
              payload_hex=f'{i + 500:04x}',
          )
      )
    self.assertEqual(len(received), 100)
    self.assertTrue(all(f.rssi == -45 for f in received))
    hub.unregister_local_endpoint(addr_a)
    hub.unregister_local_endpoint(addr_b)

  def test_wifi_station_drop_deauth_reassociate_and_validation(self):
    """Verifies Items 2, 9, 10: Wi-Fi station recovery & input validation."""
    wifi_srv = WiFiCapability.get_or_start_virtual_server()
    wifi_srv.register_ap('HomeSSID', 'HomePass123', ap_id='ap0')
    ap_sta = wifi_srv.register_station(
        'ap_bridge', mac_addr='02:00:00:00:01:01', is_ap_bridge=True
    )
    sta = wifi_srv.register_station('matter_sta', mac_addr='02:00:00:00:02:77')
    wifi_srv.reassociate_station('matter_sta')
    self.assertEqual(sta.state, 'completed')
    self.assertTrue(sta.connected)
    self.assertEqual(sta.wpa_state, 'COMPLETED')

    eth_frame = (
        bytes.fromhex(ap_sta.mac_addr.replace(':', ''))
        + bytes.fromhex(sta.mac_addr.replace(':', ''))
        + b'\x08\x00'
        + b'x' * 32
    )
    wifi_srv.reset_frame_counters()
    for _ in range(20):
      wifi_srv._relay_l2_frame('matter_sta', eth_frame)
    self.assertEqual(
        wifi_srv.get_frame_counters()['relayed_data_frames'], 20
    )

    # Drop station: preserves MAC, drops 20/20 frames
    self.server._tool_inject_rf_fault({'wifi_drop_station': 'matter_sta'})
    self.assertEqual(sta.state, 'disconnected')
    self.assertEqual(sta.disconnect_reason, 'dropped')
    self.assertEqual(sta.mac_addr, '02:00:00:00:02:77')
    wifi_srv.reset_frame_counters()
    for _ in range(20):
      wifi_srv._relay_l2_frame('matter_sta', eth_frame)
    self.assertEqual(
        wifi_srv.get_frame_counters()['relayed_data_frames'], 0
    )

    # Reassociate station: preserves MAC, forwards 20/20 frames
    self.server._tool_inject_rf_fault(
        {'wifi_reassociate_station': 'matter_sta'}
    )
    self.assertEqual(sta.state, 'completed')
    self.assertEqual(sta.mac_addr, '02:00:00:00:02:77')
    wifi_srv.reset_frame_counters()
    for _ in range(20):
      wifi_srv._relay_l2_frame('matter_sta', eth_frame)
    self.assertEqual(
        wifi_srv.get_frame_counters()['relayed_data_frames'], 20
    )

    # Item 10: Reassociating an already-completed station raises ValueError
    with self.assertRaises(ValueError):
      self.server._tool_inject_rf_fault(
          {'wifi_reassociate_station': 'matter_sta'}
      )

    # Item 10: Unknown station raises ValueError
    for key in (
        'wifi_drop_station',
        'wifi_deauth_station',
        'wifi_reassociate_station',
    ):
      with self.assertRaises(ValueError):
        self.server._tool_inject_rf_fault({key: 'nonexistent_station_xyz'})

    # Item 9: Unknown recipe raises ValueError; out-of-range values clamp
    with self.assertRaises(ValueError):
      self.server._tool_inject_rf_fault({'recipe': 'ble_typo_nonexistent'})

    clamped = self.server._tool_inject_rf_fault({
        'bt_packet_loss_rate': 5.0,
        'bt_latency_ms': -25.0,
        'bt_rssi_dbm': -500,
    })
    self.assertEqual(clamped['bt_packet_loss_rate'], 1.0)
    self.assertEqual(clamped['bt_latency_ms'], 0.0)
    self.assertEqual(clamped['bt_rssi_dbm'], -127)
    self.server._tool_inject_rf_fault({'recipe': 'clear_all_faults'})

  def test_device_log_dir_pcap_fallback_and_log_dissection(self):
    """Verifies DEVICE_LOG_DIR fallback, container .log dissection, and --require-non-empty."""
    from cirque.pcap import flow_visualizer

    log_dir = os.path.join(self.temp_dir, 'device_logs_test')
    os.makedirs(log_dir, exist_ok=True)

    # 1. Verify DEVICE_LOG_DIR fallback when CIRQUE_PCAP_DIR is absent
    with patch.dict(
        os.environ, {'DEVICE_LOG_DIR': log_dir}, clear=False
    ):
      os.environ.pop('CIRQUE_PCAP_DIR', None)
      srv = CirqueMcpServer()
      self.assertEqual(srv._pcap_dir, log_dir)

    # 2. Verify container .log dissection when 0 .pcap files exist
    matter_log = os.path.join(
        log_dir, 'MatterNode0-00e553b407d4-b799b18f.log'
    )
    with open(matter_log, 'w', encoding='utf-8') as f:
      f.write(
          '2026-04-19 20:51:15,595 [helper] [INFO] Will run command:'
          ' /usr/sbin/otbr-agent -I wpan0 -d7 -v\n'
          '00:00:00.095 [I] Mle-----------: Role disabled -> detached\n'
          '00:00:08.532 [I] Mle-----------: Role detached -> leader\n'
          '00:00:09.100 [I] MeshForwarder-: Sent IPv6 UDP msg, len:96,'
          ' chksum:8e8c, ecn:no, to:0xffff, sec:no, prio:net\n'
          '[1776631886.996390][49:52] CHIP:BLE: BLE advertisement started.\n'
          '[1776631896.817887][49:49] CHIP:EM: <<< [E:20892r S:0 M:226165355]'
          ' (U) Msg RX from 0:B22D9B353E5F8AB1 [0000] to 0:0000000000000000'
          ' [BLE] --- Type 0000:20 (SecureChannel:PBKDFParamRequest)'
          ' (B:94)\n'
          '[1776631899.640147][49:49] CHIP:SVR: Commissioning completed'
          ' session establishment step\n'
          '[1776631902.120000][49:49] CHIP:DIS: mDNS service published:'
          ' _matter._tcp\n'
      )

    events = flow_visualizer.dissect_pcap_directory(log_dir)
    self.assertGreaterEqual(len(events), 6)
    layers = {ev.layer for ev in events}
    self.assertIn('THREAD', layers)
    self.assertIn('BT', layers)
    self.assertIn('WIFI', layers)

    # 3. Verify plugin parse_log_directory hook overrides built-in log parser
    plugin_mod = SimpleNamespace(
        parse_log_directory=lambda d: [
            flow_visualizer.FlowEvent(
                event_id='plug_1',
                timestamp=1234.5,
                layer='MATTER',
                sublayer='PASE',
                stage='MATTER_PASE',
                src='Controller',
                dst='MatterNode0',
                title='Plugin PASE Event',
                summary='Parsed via plugin',
            )
        ]
    )
    plug_events = flow_visualizer.dissect_pcap_directory(
        log_dir, plugins=[plugin_mod]
    )
    self.assertTrue(any(ev.event_id == 'plug_1' for ev in plug_events))

    # 4. Verify --require-non-empty exits with code 1 on empty directory
    empty_dir = os.path.join(self.temp_dir, 'empty_pcaps')
    os.makedirs(empty_dir, exist_ok=True)
    empty_html = os.path.join(empty_dir, 'empty.html')
    with self.assertRaises(SystemExit) as ctx:
      flow_visualizer.main([
          '--pcap-dir',
          empty_dir,
          '--output',
          empty_html,
          '--require-non-empty',
      ])
    self.assertEqual(ctx.exception.code, 1)


  def test_android_commission_and_onoff(self):
    """Tests _tool_android_commission and _tool_android_onoff_action."""
    android_mock = MagicMock()
    android_mock.type = 'android_emulator'
    android_mock.start_screen_recording.return_value = {'started': True}
    android_mock.stop_screen_recording.return_value = {'stopped': True}
    android_mock.commission_via_chiptool_ui.return_value = {'status': 'success'}
    android_mock.commission_thread_via_chiptool_ui.return_value = {'status': 'success'}
    android_mock.toggle_onoff_via_chiptool_ui.return_value = {'status': 'success'}
    android_mock.read_onoff_via_chiptool_ui.return_value = {'status': 'success'}

    self.mock_home.devices['android_emu'] = android_mock

    # Test commission wifi
    res = self.server._tool_android_commission({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'network_type': 'wifi',
        'record_video': True,
    })
    self.assertEqual(res['status'], 'success')
    android_mock.commission_via_chiptool_ui.assert_called()

    # Test commission thread
    res = self.server._tool_android_commission({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'network_type': 'thread',
        'record_video': True,
    })
    self.assertEqual(res['status'], 'success')
    android_mock.commission_thread_via_chiptool_ui.assert_called()

    # Test onoff toggle
    res = self.server._tool_android_onoff_action({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'action': 'toggle',
        'record_video': True,
    })
    self.assertEqual(res['result']['status'], 'success')
    android_mock.toggle_onoff_via_chiptool_ui.assert_called()

    # Test onoff read
    res = self.server._tool_android_onoff_action({
        'home_id': 'home_test_123',
        'device_id': 'android_emu',
        'action': 'read',
        'record_video': True,
    })
    self.assertEqual(res['result']['status'], 'success')
    android_mock.read_onoff_via_chiptool_ui.assert_called()

if __name__ == '__main__':
  unittest.main()


