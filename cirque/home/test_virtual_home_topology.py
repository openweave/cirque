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
"""Tests for the Thread dataset-completion helper in VirtualHomeTopology.

The helper is executed for real as a subprocess against a scripted ``ot-ctl``
placed on ``PATH``. No part of the helper is mocked; only the OpenThread CLI
it talks to is replaced by a recorder that replays the output format of a
partial active dataset as committed by Android CHIPTool.
"""

import os
import re
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

from cirque.capabilities.bluetoothcapability import BlueToothCapability
from cirque.capabilities.wificapability import WiFiCapability
from cirque.home.virtual_home_topology import OTBR_DATASET_COMPLETION_HELPER
from cirque.home.virtual_home_topology import VirtualHomeApSpec
from cirque.home.virtual_home_topology import VirtualHomeNodeSpec
from cirque.home.virtual_home_topology import VirtualHomeTopology

_FAKE_OT_CTL = textwrap.dedent('''\
    #!/bin/sh
    # Scripted ot-ctl recorder used by the dataset-completion helper tests.
    echo "$*" >> "$FAKE_OT_DIR/calls.log"
    case "$*" in
      "state")
        n=$(cat "$FAKE_OT_DIR/state_calls" 2>/dev/null || echo 0)
        n=$((n + 1)); echo "$n" > "$FAKE_OT_DIR/state_calls"
        if [ -f "$FAKE_OT_DIR/leader" ]; then
          echo "leader"
        elif [ "$FAKE_OT_MODE" = "existing_parent" ] && [ "$n" -gt 1 ]; then
          echo "child"
        else
          echo "detached"
        fi
        echo "Done" ;;
      "state leader")
        touch "$FAKE_OT_DIR/leader"; echo "Done" ;;
      "dataset active")
        cat "$FAKE_OT_DIR/dataset_active.txt"; echo "Done" ;;
      *)
        echo "Done" ;;
    esac
    ''')

# Output of `ot-ctl dataset active` after CHIPTool commits its 37-byte
# partial dataset: channel, extended PAN ID, network key and PAN ID only.
_PARTIAL_DATASET_ACTIVE = (
    'Channel: 15\n'
    'Ext PAN ID: 1111111122222222\n'
    'Network Key: 00112233445566778899aabbccddeeff\n'
    'PAN ID: 0x1234\n'
)


class OtbrDatasetCompletionHelperTest(unittest.TestCase):
  """Runs the real helper script against a scripted ot-ctl."""

  def setUp(self):
    super().setUp()
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)
    self.fake_dir = self._tmp.name
    ot_ctl = os.path.join(self.fake_dir, 'ot-ctl')
    with open(ot_ctl, 'w', encoding='utf-8') as f:
      f.write(_FAKE_OT_CTL)
    os.chmod(ot_ctl, os.stat(ot_ctl).st_mode | stat.S_IXUSR)
    self.helper_path = os.path.join(self.fake_dir, 'dataset_helper.py')
    with open(self.helper_path, 'w', encoding='utf-8') as f:
      f.write(OTBR_DATASET_COMPLETION_HELPER)

  def _run_helper(self, dataset_active: str, mode: str = 'empty_mesh') -> str:
    with open(
        os.path.join(self.fake_dir, 'dataset_active.txt'),
        'w',
        encoding='utf-8',
    ) as f:
      f.write(dataset_active)
    env = dict(os.environ)
    env['PATH'] = self.fake_dir + os.pathsep + env.get('PATH', '')
    env['FAKE_OT_DIR'] = self.fake_dir
    env['FAKE_OT_MODE'] = mode
    proc = subprocess.run(
        [sys.executable, self.helper_path],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    self.assertEqual(proc.returncode, 0, proc.stderr)
    return proc.stdout

  def _calls(self):
    with open(
        os.path.join(self.fake_dir, 'calls.log'), encoding='utf-8'
    ) as f:
      return [line.rstrip('\n') for line in f]

  def test_helper_script_compiles(self):
    compile(OTBR_DATASET_COMPLETION_HELPER, 'dataset_helper.py', 'exec')

  def test_partial_dataset_is_completed_and_leader_requested(self):
    stdout = self._run_helper(_PARTIAL_DATASET_ACTIVE)
    calls = self._calls()

    self.assertIn('Became leader: leader', stdout)
    # Commissioned parameters are preserved verbatim.
    self.assertIn('dataset channel 15', calls)
    self.assertIn('dataset panid 0x1234', calls)
    self.assertIn('dataset extpanid 1111111122222222', calls)
    self.assertIn(
        'dataset networkkey 00112233445566778899aabbccddeeff', calls
    )
    # Missing mandatory fields are supplied before the commit.
    self.assertIn('dataset activetimestamp 1', calls)
    self.assertIn('dataset meshlocalprefix fdde:ad00:beef:0::', calls)
    self.assertIn('dataset networkname CirqueThread', calls)
    self.assertLess(
        calls.index('dataset init new'), calls.index('dataset commit active')
    )
    self.assertLess(
        calls.index('dataset commit active'), calls.index('state leader')
    )
    self.assertLess(calls.index('thread start'), calls.index('state leader'))
    self.assertIn('route add fd11:22::/64 s med', calls)
    self.assertIn('netdata register', calls)
    # Exactly one completion cycle.
    self.assertEqual(calls.count('dataset commit active'), 1)

  def test_dataset_without_key_or_extpanid_is_left_untouched(self):
    # Negative control: a dataset lacking the commissioned key material must
    # never be rewritten; when the node attaches to an existing parent the
    # helper exits without touching the dataset.
    stdout = self._run_helper('Channel: 15\n', mode='existing_parent')
    calls = self._calls()

    self.assertIn('Target state reached: child', stdout)
    self.assertNotIn('dataset init new', calls)
    self.assertNotIn('dataset commit active', calls)
    self.assertNotIn('state leader', calls)

  def test_attached_node_is_never_reconfigured(self):
    # Negative control: once leader, the helper exits on its first poll and
    # issues no dataset command at all.
    open(os.path.join(self.fake_dir, 'leader'), 'w', encoding='utf-8').close()
    stdout = self._run_helper(_PARTIAL_DATASET_ACTIVE)
    calls = self._calls()

    self.assertIn('Target state reached: leader', stdout)
    self.assertEqual(calls, ['state'])


class FakeCommandResult:
  """Test double for docker / node command execution results."""

  def __init__(self, exit_code: int = 0, output: str = ''):
    self.exit_code = exit_code
    self.output = output


class FakeContainerResult:
  """Test double for container.exec_run output."""

  def __init__(self, exit_code: int = 0, output: bytes = b''):
    self.exit_code = exit_code
    self.output = output


class FakeContainer:
  """Test double for docker container object."""

  def __init__(self, output: bytes = b'inet 10.0.1.5'):
    self.output = output

  def exec_run(self, cmd: str) -> FakeContainerResult:
    return FakeContainerResult(0, self.output)


class FakeCapability:
  """Test double for node capability."""

  def __init__(self, name: str, station_id: str = 'wifi0'):
    self.name = name
    self.station_id = station_id


class FakeAndroidNode:
  """Test double for AndroidDockerNode."""

  def __init__(self):
    self.calls = []
    self.container = FakeContainer()
    self.capabilities = [FakeCapability('WiFi', 'wifi_station_0')]

  def describe_radio_path(self):
    return {'transport': 'pty_bridge', 'bound_device': 'hci0'}

  def start_pty_bridge(self, bt_port, host_ip, bind_id):
    self.calls.append(('start_pty_bridge', bt_port, host_ip, bind_id))

  def get_guest_wlan_mac(self, iface):
    del iface
    return '02:15:b2:11:22:33'

  def setup_guest_wifi(self, iface):
    self.calls.append(('setup_guest_wifi', iface))

  def commission_via_chiptool_ui(self, **kwargs):
    self.calls.append(('commission_via_chiptool_ui', kwargs))
    return {'status': 'success'}

  def commission_thread_via_chiptool_ui(self, **kwargs):
    self.calls.append(('commission_thread_via_chiptool_ui', kwargs))
    return {'status': 'success'}

  def toggle_onoff_via_chiptool_ui(self, node_id, endpoint):
    self.calls.append(('toggle_onoff_via_chiptool_ui', node_id, endpoint))
    return {'status': 'success'}

  def read_onoff_via_chiptool_ui(self, node_id, endpoint):
    self.calls.append(('read_onoff_via_chiptool_ui', node_id, endpoint))
    return {'status': 'success'}


class FakeController:
  """Test double for BlueToothController."""

  def __init__(
      self, tx_packets: int = 10, rx_packets: int = 20, is_dict: bool = True
  ):
    self.tx = tx_packets
    self.rx = rx_packets
    self.is_dict = is_dict

  def to_dict(self):
    if not self.is_dict:
      return 'invalid_controller_dict'
    return {'tx_packets': self.tx, 'rx_packets': self.rx}


class FakeBluetoothServer:
  """Test double for VirtualBluetoothServer."""

  def __init__(self, ctrl=None):
    self.controllers = {
        'android_hci0': (
            ctrl if ctrl is not None else FakeController(10, 20)
        )
    }
    self.hci_port = 23458

  def get_controller(self, bind_id):
    return self.controllers.get(bind_id)


class FakeWiFiServer:
  """Test double for VirtualWiFiServer."""

  def __init__(self, counters=None):
    self.counters = counters or {'relayed_udp5540_frames': 5}

  def get_frame_counters(self):
    return dict(self.counters)


class FakeDockerManager:
  """Test double for WiFiDockerManager."""

  def __init__(self):
    self.calls = []

  def setup_container_interface(self, **kwargs):
    self.calls.append(kwargs)


class FakeCirqueHome:
  """Test double for CirqueHome."""

  def __init__(self, handler=None):
    self.calls = []
    self.handler = handler
    self.home = {'devices': {}}

  def execute_device_cmd(
      self, cmd: str, node_id: str, stream: bool = False
  ) -> FakeCommandResult:
    del stream
    self.calls.append((node_id, cmd))
    if self.handler:
      res = self.handler(node_id, cmd)
      if res is not None:
        if isinstance(res, tuple):
          return FakeCommandResult(res[0], res[1])
        return FakeCommandResult(0, res)
    return FakeCommandResult(0, '')


class VirtualHomeConfigTest(unittest.TestCase):
  """Tests VirtualHomeNodeSpec, VirtualHomeApSpec, and topology configs."""

  def setUp(self):
    super().setUp()
    self._tmp = tempfile.TemporaryDirectory()
    self.addCleanup(self._tmp.cleanup)
    self.temp_dir = self._tmp.name

  def test_node_spec_capabilities_and_to_device_config(self):
    spec = VirtualHomeNodeSpec(
        name='node_a',
        device_type='TestDevice',
        enable_bluetooth=True,
        enable_wifi=False,
        enable_thread=True,
        mount_pairs=(('/host/a', '/cntr/a'),),
        rcp_mode=True,
        bd_addr='AA:BB:CC:DD:EE:11',
    )
    caps = spec.capabilities_list()
    self.assertEqual(caps, ['Bluetooth', 'Thread', 'Mount'])

    dev_cfg = spec.to_device_config()
    self.assertEqual(dev_cfg['type'], 'TestDevice')
    self.assertEqual(dev_cfg['capability'], caps)
    self.assertTrue(dev_cfg['use_virtual_bt_tcp'])
    self.assertTrue(dev_cfg['use_virtual_wifi_tcp'])
    self.assertFalse(dev_cfg['wifi_auto_connect'])
    self.assertEqual(dev_cfg['bd_addr'], 'AA:BB:CC:DD:EE:11')
    self.assertEqual(dev_cfg['mount_pairs'], [['/host/a', '/cntr/a']])
    self.assertTrue(dev_cfg['rcp_mode'])

  def test_ap_spec_and_build_home_config(self):
    ap_spec = VirtualHomeApSpec(
        name='test_ap', ssid='TEST_SSID', wifi_psk='secret_psk'
    )
    self.assertTrue(ap_spec.is_wpa2_enabled())
    ap_cfg = ap_spec.to_device_config()
    self.assertEqual(ap_cfg['type'], 'wifi_ap')
    self.assertEqual(ap_cfg['ssid'], 'TEST_SSID')
    self.assertEqual(ap_cfg['psk'], 'secret_psk')
    self.assertTrue(ap_cfg['use_virtual_wifi_tcp'])

    open_ap = VirtualHomeApSpec(wifi_psk='')
    self.assertFalse(open_ap.is_wpa2_enabled())
    self.assertFalse(open_ap.to_device_config()['use_virtual_wifi_tcp'])

    node_spec = VirtualHomeNodeSpec(name='node_1', device_type='Node')
    topology = VirtualHomeTopology.build_home_config([node_spec], ap_spec)
    self.assertIn('test_ap', topology)
    self.assertIn('node_1', topology)

    topo_no_ap = VirtualHomeTopology.build_home_config([node_spec], None)
    self.assertNotIn('test_ap', topo_no_ap)
    self.assertIn('node_1', topo_no_ap)

  def test_default_chip_binary_paths_and_instance_init(self):
    vht = VirtualHomeTopology(cirque_home='fake_home')
    self.assertEqual(vht.cirque_home, 'fake_home')

    with mock.patch.dict(os.environ, {}, clear=True):
      self.assertEqual(
          VirtualHomeTopology.get_default_controller_bin(),
          '/cirque-build/out/controller-cli',
      )
      self.assertEqual(
          VirtualHomeTopology.get_default_device_app_bin(),
          '/cirque-build/out/device-app',
      )
      self.assertEqual(
          VirtualHomeTopology.get_default_chip_tool_bin(),
          '/cirque-build/out/controller-cli',
      )
      self.assertEqual(
          VirtualHomeTopology.get_default_chip_app_bin(),
          '/cirque-build/out/device-app',
      )

    with mock.patch.dict(
        os.environ,
        {'CIRQUE_CONTROLLER_BIN': '/custom/controller', 'CIRQUE_DEVICE_APP_BIN': '/custom/app'},
    ):
      self.assertEqual(
          VirtualHomeTopology.get_default_controller_bin(), '/custom/controller'
      )
      self.assertEqual(
          VirtualHomeTopology.get_default_device_app_bin(), '/custom/app'
      )
      self.assertEqual(
          VirtualHomeTopology.get_default_chip_tool_bin(), '/custom/controller'
      )
      self.assertEqual(
          VirtualHomeTopology.get_default_chip_app_bin(), '/custom/app'
      )

  def test_resolve_chip_build_mount_variations(self):
    # Case 1: CHIP_BUILD_ROOT unset, relative ../../../../out exists.
    rel_out_dir = os.path.join(self.temp_dir, 'mock_out')
    os.makedirs(os.path.join(rel_out_dir, 'controller-cli'), exist_ok=True)
    with mock.patch.dict(os.environ, {}, clear=True):
      with mock.patch(
          'os.path.abspath', return_value=rel_out_dir
      ):
        mount = VirtualHomeTopology.resolve_chip_build_mount()
        self.assertEqual(mount, (rel_out_dir, '/cirque-build/out'))
        mount_host = VirtualHomeTopology.resolve_host_build_mount()
        self.assertEqual(mount_host, (rel_out_dir, '/cirque-build/out'))

    # Case 2: Neither set and relative dir missing -> None.
    with mock.patch.dict(os.environ, {}, clear=True):
      with mock.patch(
          'os.path.abspath', return_value='/nonexistent/rel_out'
      ):
        self.assertIsNone(VirtualHomeTopology.resolve_chip_build_mount())
        self.assertIsNone(VirtualHomeTopology.resolve_host_build_mount())

    # Case 3: CHIP_VBT_PATH set without CHIP_BUILD_ROOT -> /chip-vbt.
    vbt_dir = os.path.join(self.temp_dir, 'vbt_root')
    os.makedirs(vbt_dir, exist_ok=True)
    with mock.patch.dict(
        os.environ, {'CHIP_VBT_PATH': vbt_dir}, clear=True
    ):
      mount = VirtualHomeTopology.resolve_chip_build_mount()
      self.assertEqual(mount, (vbt_dir, '/chip-vbt'))

    # Case 4: CHIP_BUILD_ROOT with binary -> /cirque-build/out.
    chip_root_tool = os.path.join(self.temp_dir, 'chip_tool_dir')
    os.makedirs(chip_root_tool, exist_ok=True)
    open(
        os.path.join(chip_root_tool, 'controller-cli'),
        'w',
        encoding='utf-8',
    ).close()
    with mock.patch.dict(
        os.environ, {'CIRQUE_HOST_BUILD_DIR': chip_root_tool}, clear=True
    ):
      mount = VirtualHomeTopology.resolve_host_build_mount(binary_name='controller-cli')
      self.assertEqual(mount, (chip_root_tool, '/cirque-build/out'))

    # Case 5: CHIP_BUILD_ROOT containing 'out' subdirectory -> /cirque-build.
    chip_root_repo = os.path.join(self.temp_dir, 'chip_repo')
    os.makedirs(os.path.join(chip_root_repo, 'out'), exist_ok=True)
    with mock.patch.dict(
        os.environ, {'CIRQUE_HOST_BUILD_DIR': chip_root_repo}, clear=True
    ):
      mount = VirtualHomeTopology.resolve_host_build_mount()
      self.assertEqual(mount, (chip_root_repo, '/cirque-build'))

    # Case 6: Empty directory fallback -> /cirque-build/out.
    chip_root_plain = os.path.join(self.temp_dir, 'chip_plain')
    os.makedirs(chip_root_plain, exist_ok=True)
    with mock.patch.dict(
        os.environ, {'CIRQUE_HOST_BUILD_DIR': chip_root_plain}, clear=True
    ):
      mount = VirtualHomeTopology.resolve_host_build_mount()
      self.assertEqual(mount, (chip_root_plain, '/cirque-build/out'))

  def test_default_two_node_ble_wifi_config_mount_variants(self):
    ev_dir = os.path.join(self.temp_dir, 'evidence_dump')
    with mock.patch.dict(os.environ, {'CIRQUE_EVIDENCE_DIR': ev_dir}):
      with mock.patch.object(
          VirtualHomeTopology,
          'resolve_chip_build_mount',
          return_value=('/host/out', '/connectedhomeip/out'),
      ):
        cfg = VirtualHomeTopology.default_two_node_ble_wifi_config()
        self.assertIn('mobile_controller', cfg)
        self.assertIn('iot_end_device', cfg)
        mounts = cfg['mobile_controller']['mount_pairs']
        self.assertIn(['/host/out', '/connectedhomeip/out'], mounts)
        self.assertIn(['/host/out', '/chip-vbt/out'], mounts)
        self.assertIn([ev_dir, '/evidence'], mounts)

      with mock.patch.object(
          VirtualHomeTopology,
          'resolve_chip_build_mount',
          return_value=('/host/repo', '/connectedhomeip'),
      ):
        cfg = VirtualHomeTopology.default_two_node_ble_wifi_config()
        mounts = cfg['mobile_controller']['mount_pairs']
        self.assertIn(['/host/repo', '/connectedhomeip'], mounts)
        self.assertIn(['/host/repo', '/chip-vbt'], mounts)

  def test_default_android_two_node_ble_wifi_config_variants(self):
    with mock.patch.object(
        VirtualHomeTopology,
        'resolve_chip_build_mount',
        return_value=('/host/out', '/connectedhomeip/out'),
    ):
      cfg = VirtualHomeTopology.default_android_two_node_ble_wifi_config(
          wifi_psk='explicit_psk'
      )
      self.assertIn('android_controller', cfg)
      self.assertIn('matter_device', cfg)
      self.assertEqual(cfg['wifi_ap']['psk'], 'explicit_psk')
      mounts = cfg['android_controller']['mount_pairs']
      self.assertIn(['/host/out', '/chip-vbt/out'], mounts)

    with mock.patch.object(
        VirtualHomeTopology,
        'resolve_chip_build_mount',
        return_value=('/host/repo', '/connectedhomeip'),
    ):
      cfg = VirtualHomeTopology.default_android_two_node_ble_wifi_config(
          psk='fallback_psk', wifi_psk=None
      )
      self.assertEqual(cfg['wifi_ap']['psk'], 'fallback_psk')
      mounts = cfg['android_controller']['mount_pairs']
      self.assertIn(['/host/repo', '/chip-vbt'], mounts)

  def test_default_android_emulator_ble_wifi_config_variants(self):
    pcap_target = os.path.join(self.temp_dir, 'pcap_logs')
    with mock.patch.object(
        VirtualHomeTopology,
        'resolve_chip_build_mount',
        return_value=('/host/out', '/connectedhomeip/out'),
    ):
      cfg = VirtualHomeTopology.default_android_emulator_ble_wifi_config(
          pcap_dir=pcap_target
      )
      self.assertEqual(os.environ.get('CIRQUE_PCAP_DIR'), pcap_target)
      self.assertEqual(cfg['android_emulator']['labels']['owner'], 't9')
      self.assertEqual(
          cfg['android_emulator']['preferred_mode'], 'kvm_emulator'
      )
      self.assertTrue(cfg['android_emulator']['is_tap_station'])
      mounts = cfg['android_emulator']['mount_pairs']
      self.assertIn(['/host/out', '/chip-vbt/out'], mounts)

    with mock.patch.object(
        VirtualHomeTopology,
        'resolve_chip_build_mount',
        return_value=('/host/repo', '/connectedhomeip'),
    ):
      cfg = VirtualHomeTopology.default_android_emulator_ble_wifi_config(
          pcap_dir=None
      )
      mounts = cfg['android_emulator']['mount_pairs']
      self.assertIn(['/host/repo', '/chip-vbt'], mounts)

  def test_default_android_emulator_ble_thread_config_variants(self):
    pcap_thread = os.path.join(self.temp_dir, 'pcap_thread')
    with mock.patch.object(
        VirtualHomeTopology,
        'resolve_chip_build_mount',
        return_value=('/host/out', '/connectedhomeip/out'),
    ):
      cfg = VirtualHomeTopology.default_android_emulator_ble_thread_config(
          pcap_dir=pcap_thread, wifi_auto_connect=True
      )
      self.assertEqual(os.environ.get('CIRQUE_PCAP_DIR'), pcap_thread)
      self.assertEqual(cfg['android_emulator']['labels']['owner'], 't10')
      self.assertEqual(
          cfg['android_emulator']['preferred_mode'], 'kvm_emulator'
      )
      self.assertIn('thread_border_router', cfg)
      tbr_cfg = cfg['thread_border_router']
      self.assertEqual(tbr_cfg['type'], 'ThreadBorderRouter')
      self.assertTrue(tbr_cfg['rcp_mode'])
      self.assertTrue(tbr_cfg['wifi_auto_connect'])
      self.assertIn('WiFi', tbr_cfg['capability'])
      self.assertIn('Thread', tbr_cfg['capability'])
      dev_cfg = cfg['matter_device']
      self.assertTrue(dev_cfg['rcp_mode'])
      self.assertFalse(dev_cfg.get('wifi_auto_connect', False))
      self.assertIn('Thread', dev_cfg['capability'])
      self.assertNotIn('WiFi', dev_cfg['capability'])
      mounts = cfg['android_emulator']['mount_pairs']
      self.assertIn(['/host/out', '/chip-vbt/out'], mounts)

    with mock.patch.object(
        VirtualHomeTopology,
        'resolve_chip_build_mount',
        return_value=('/host/repo', '/connectedhomeip'),
    ):
      cfg = VirtualHomeTopology.default_android_emulator_ble_thread_config(
          pcap_dir=None
      )
      mounts = cfg['android_emulator']['mount_pairs']
      self.assertIn(['/host/repo', '/chip-vbt'], mounts)


class VirtualHomeShellHelpersTest(unittest.TestCase):
  """Tests shell execution, D-Bus queries, and interface parsers."""

  def setUp(self):
    super().setUp()
    patcher = mock.patch(
        'cirque.home.virtual_home_topology.time.sleep', return_value=None
    )
    patcher.start()
    self.addCleanup(patcher.stop)

  def test_exec_in_node_wrapping_and_types(self):
    home = FakeCirqueHome()

    # Automatic wrapping of unwrapped shell commands
    ec, out = VirtualHomeTopology._exec_in_node_with_exit_code(
        home, 'n1', "echo 'hello world'"
    )
    self.assertEqual(ec, 0)
    self.assertEqual(out, '')
    recorded_cmd = home.calls[-1][1]
    self.assertTrue(
        recorded_cmd.startswith("sh -c '") or recorded_cmd.startswith('sh -c "')
    )

    # Already wrapped commands should not be double wrapped
    home.calls.clear()
    VirtualHomeTopology._exec_in_node_with_exit_code(
        home, 'n1', "sh -c 'echo 123'"
    )
    self.assertEqual(home.calls[-1][1], "sh -c 'echo 123'")

    # Byte output decoding
    home_bytes = FakeCirqueHome(
        handler=lambda nid, cmd: (0, b'binary_data_decoded')
    )
    ec, out = VirtualHomeTopology._exec_in_node_with_exit_code(
        home_bytes, 'n1', 'cmd'
    )
    self.assertEqual(out, 'binary_data_decoded')

    # Non-bytes output stringification
    home_obj = FakeCirqueHome(handler=lambda nid, cmd: (42, 12345))
    ec, out = VirtualHomeTopology._exec_in_node_with_exit_code(
        home_obj, 'n1', 'cmd'
    )
    self.assertEqual(ec, 42)
    self.assertEqual(out, '12345')

    # _exec_in_node convenience helper
    text = VirtualHomeTopology._exec_in_node(home_obj, 'n1', 'cmd')
    self.assertEqual(text, '12345')

  def test_read_wpa_state(self):
    home = FakeCirqueHome(
        handler=lambda nid, cmd: '  ("completed",)  '
    )
    state = VirtualHomeTopology._read_wpa_state(home, 'n1')
    self.assertEqual(state, '("completed",)')

  def test_verify_virtual_bt_between_nodes(self):
    def bt_handler(nid, cmd):
      if 'GetManagedObjects' in cmd:
        return f'managed_objects_for_{nid}'
      return 'done'

    home = FakeCirqueHome(handler=bt_handler)
    res = VirtualHomeTopology.verify_virtual_bt_between_nodes(
        home, 'ctrl_node', 'dev_node'
    )
    self.assertEqual(
        res,
        {
            'controller_bt': 'managed_objects_for_ctrl_node',
            'device_bt': 'managed_objects_for_dev_node',
        },
    )

  def test_associate_wpa_and_dhcp_and_poll_retry(self):
    ip_poll_count = [0]

    dbus_supplicant = '/fi/w1/wpa_' + 'supplicant1'

    def assoc_handler(nid, cmd):
      if 'AddNetwork' in cmd:
        return f'object path "{dbus_supplicant}/Interfaces/0/Networks/1"'
      if 'State' in cmd:
        return '("completed",)'
      if 'ip -4 addr show dev wlan0' in cmd:
        ip_poll_count[0] += 1
        if ip_poll_count[0] == 1:
          return (
              '3: wlan0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 '
              'qdisc noop state DOWN'
          )
        return 'inet 10.0.1.44/24 brd 10.0.1.255 scope global wlan0'
      return 'OK'

    home = FakeCirqueHome(handler=assoc_handler)
    state = VirtualHomeTopology._associate_wpa_and_dhcp(
        home, 'dev1', 'TEST_AP', 'TEST_PSK'
    )
    self.assertEqual(state, '("completed",)')
    self.assertGreaterEqual(ip_poll_count[0], 2)

    # Test fallback network path regex branch
    def fallback_handler(nid, cmd):
      if 'AddNetwork' in cmd:
        return 'no_object_path_match'
      if 'SelectNetwork' in cmd:
        self.assertIn(f'{dbus_supplicant}/Interfaces/0/Networks/0', cmd)
      if 'State' in cmd:
        return '("completed",)'
      if 'ip -4 addr' in cmd:
        return 'inet 10.0.1.45/24'
      return ''

    home_fallback = FakeCirqueHome(handler=fallback_handler)
    VirtualHomeTopology._associate_wpa_and_dhcp(
        home_fallback, 'dev2', 'AP', 'PSK'
    )

  def test_read_wlan0_ipv4(self):
    home_match = FakeCirqueHome(
        handler=lambda nid, cmd: 'inet 10.0.1.75/24 scope global wlan0'
    )
    ip = VirtualHomeTopology._read_wlan0_ipv4(home_match, 'node')
    self.assertEqual(ip, '10.0.1.75')

    home_nomatch = FakeCirqueHome(handler=lambda nid, cmd: 'Device not found')
    ip_empty = VirtualHomeTopology._read_wlan0_ipv4(home_nomatch, 'node')
    self.assertEqual(ip_empty, '')

  def test_read_wlan0_ipv6_variants(self):
    home_slaac = FakeCirqueHome(
        handler=lambda nid, cmd: 'inet6 fd11:22:33:44::1/64 scope global'
    )
    ip_slaac = VirtualHomeTopology._read_wlan0_ipv6(home_slaac, 'node')
    self.assertEqual(ip_slaac, 'fd11:22:33:44::1')

    home_generic = FakeCirqueHome(
        handler=lambda nid, cmd: 'inet6 2001:db8::abcd/64 scope global'
    )
    ip_generic = VirtualHomeTopology._read_wlan0_ipv6(home_generic, 'node')
    self.assertEqual(ip_generic, '2001:db8::abcd')

    home_empty = FakeCirqueHome(handler=lambda nid, cmd: 'no inet6')
    self.assertEqual(
        VirtualHomeTopology._read_wlan0_ipv6(home_empty, 'node'), ''
    )

  def test_android_hci_frame_count_variants(self):
    self.assertEqual(
        VirtualHomeTopology._android_hci_frame_count(None, 'hci0'), 0
    )

    bt_none_ctrl = FakeBluetoothServer()
    bt_none_ctrl.controllers.clear()
    self.assertEqual(
        VirtualHomeTopology._android_hci_frame_count(bt_none_ctrl, 'hci0'), 0
    )

    bt_bad_dict = FakeBluetoothServer(ctrl=FakeController(is_dict=False))
    self.assertEqual(
        VirtualHomeTopology._android_hci_frame_count(
            bt_bad_dict, 'android_hci0'
        ),
        0,
    )

    bt_valid = FakeBluetoothServer(ctrl=FakeController(15, 25))
    self.assertEqual(
        VirtualHomeTopology._android_hci_frame_count(bt_valid, 'android_hci0'),
        40,
    )

  def test_android_radio_path(self):
    android_node = FakeAndroidNode()
    bt_server = FakeBluetoothServer(ctrl=FakeController(12, 18))
    path = VirtualHomeTopology._android_radio_path(
        android_node, bt_server, hci_frames_before=10, bind_id='android_hci0'
    )
    self.assertEqual(path['transport'], 'pty_bridge')
    self.assertTrue(path['bt_controller_bound'])
    self.assertEqual(path['android_hci_frames'], 20)  # (12 + 18) - 10

    # Test with None node and missing controller
    path_empty = VirtualHomeTopology._android_radio_path(
        None, None, hci_frames_before=0
    )
    self.assertFalse(path_empty['bt_controller_bound'])
    self.assertEqual(path_empty['android_hci_frames'], 0)

  def test_verify_virtual_wifi_commissioning_and_data_plane(self):
    def wifi_plane_handler(nid, cmd):
      if 'State' in cmd:
        return '("completed",)'
      if 'ip -4 addr' in cmd:
        return (
            'inet 10.0.1.10/24'
            if nid == 'ctrl'
            else 'inet 10.0.1.20/24'
        )
      if 'ping' in cmd:
        return '2 packets transmitted, 2 received, 0% packet loss, time 1001ms'
      return 'OK'

    home = FakeCirqueHome(handler=wifi_plane_handler)
    res = VirtualHomeTopology.verify_virtual_wifi_commissioning_and_data_plane(
        home, 'ctrl', 'dev'
    )
    self.assertEqual(res['controller_ip'], '10.0.1.10')
    self.assertEqual(res['device_ip'], '10.0.1.20')
    packet_loss_ok = res['packet_loss_zero']
    self.assertTrue(packet_loss_ok)

  def test_enforce_eth0_mdns_isolation_success_and_failure(self):
    valid_rules = (
        '-A OUTPUT -o eth0 -p udp -m udp --dport 5353 -j DROP\n'
        '-A INPUT -i eth0 -p udp -m udp --dport 5353 -j DROP\n'
    )
    home_ok = FakeCirqueHome(handler=lambda nid, cmd: valid_rules)
    VirtualHomeTopology._enforce_eth0_mdns_isolation(home_ok, 'dev')

    home_fail = FakeCirqueHome(handler=lambda nid, cmd: 'no rules')
    with self.assertRaises(RuntimeError) as ctx:
      VirtualHomeTopology._enforce_eth0_mdns_isolation(home_fail, 'dev')
    self.assertIn('failed to isolate eth0 mDNS', str(ctx.exception))


class VirtualHomeCleanDeviceStateTest(unittest.TestCase):
  """Tests device reset, GATT readiness polling, and process lifecycle."""

  def setUp(self):
    super().setUp()
    patcher = mock.patch(
        'cirque.home.virtual_home_topology.time.sleep', return_value=None
    )
    patcher.start()
    self.addCleanup(patcher.stop)

  def test_clean_chip_device_state_and_restart_success(self):
    pidof_calls = [0]
    port_calls = [0]

    def reset_handler(nid, cmd):
      if 'pidof ' in cmd:
        pidof_calls[0] += 1
        if pidof_calls[0] == 1:
          return (0, '12345')
        return (1, '')
      if 'ss -lntu | grep :5540' in cmd:
        port_calls[0] += 1
        if port_calls[0] == 1:
          return (0, '0.0.0.0:5540')
        return (0, '')
      if 'iptables' in cmd:
        return (
            '-A OUTPUT -o eth0 -p udp --dport 5353 -j DROP\n'
            '-A INPUT -i eth0 -p udp --dport 5353 -j DROP\n'
        )
      if 'cat /sys/class/net/wlan0/ifindex' in cmd:
        return '4'
      if 'grep -E "GATT application registered' in cmd:
        return (0, 'CHIP:DL: BLE adv start')
      return (0, 'OK')

    home = FakeCirqueHome(handler=reset_handler)

    mock_dbus = mock.MagicMock()
    mock_bt_server = mock.MagicMock()
    with mock.patch.object(
        BlueToothCapability, '_SHARED_BLUEZ_DBUS', mock_dbus
    ):
      with mock.patch.object(
          BlueToothCapability, '_SHARED_VIRTUAL_SERVER', mock_bt_server
      ):
        VirtualHomeTopology.clean_chip_device_state_and_restart(
            cirque_home=home,
            device_id='dev_node',
            controller_id='ctrl_node',
            discriminator=3840,
            passcode=20202021,
        )

    mock_dbus.reset_connections.assert_called_once()
    mock_bt_server.reset_all_controllers.assert_called_once()
    self.assertGreaterEqual(pidof_calls[0], 2)
    self.assertGreaterEqual(port_calls[0], 2)
    app_launch_cmds = [
        cmd for nid, cmd in home.calls if 'device-app' in cmd or 'chip-all-clusters-app' in cmd
    ]
    self.assertTrue(any('--discriminator 3840' in c for c in app_launch_cmds))

  def test_clean_chip_device_state_bluetooth_exception_handled(self):
    def reset_handler(nid, cmd):
      if 'iptables' in cmd:
        return (
            '-A OUTPUT -o eth0 -p udp --dport 5353 -j DROP\n'
            '-A INPUT -i eth0 -p udp --dport 5353 -j DROP\n'
        )
      if 'grep -E "GATT application registered' in cmd:
        return (0, 'BLE adv start')
      return (0, '')

    home = FakeCirqueHome(handler=reset_handler)
    mock_dbus = mock.MagicMock()
    mock_dbus.reset_connections.side_effect = RuntimeError('DBus error')
    with mock.patch.object(
        BlueToothCapability, '_SHARED_BLUEZ_DBUS', mock_dbus
    ):
      VirtualHomeTopology.clean_chip_device_state_and_restart(
          cirque_home=home, device_id='dev'
      )

  def test_clean_chip_device_state_gatt_failure_raises(self):
    def gatt_fail_handler(nid, cmd):
      if 'iptables' in cmd:
        return (
            '-A OUTPUT -o eth0 -p udp --dport 5353 -j DROP\n'
            '-A INPUT -i eth0 -p udp --dport 5353 -j DROP\n'
        )
      if 'grep -E "GATT application registered' in cmd:
        return (1, '')
      if 'cat /tmp/chip-all-clusters.log' in cmd:
        return (0, 'FATAL: Bluetooth adapter not found')
      return (0, '')

    home = FakeCirqueHome(handler=gatt_fail_handler)
    with self.assertRaises(RuntimeError) as ctx:
      VirtualHomeTopology.clean_chip_device_state_and_restart(
          cirque_home=home, device_id='dev', timeout_sec=0.01
      )
    self.assertIn('failed to initialize or register GATT', str(ctx.exception))
    self.assertIn('Bluetooth adapter not found', str(ctx.exception))

  def test_clean_chip_thread_device_state_and_restart_success(self):
    ot_state_calls = [0]
    pidof_calls = [0]
    port_calls = [0]

    def thread_reset_handler(nid, cmd):
      if 'pidof ' in cmd:
        pidof_calls[0] += 1
        if pidof_calls[0] == 1:
          return (0, '54321')
        return (1, '')
      if 'ss -lntu | grep :5540' in cmd:
        port_calls[0] += 1
        if port_calls[0] == 1:
          return (0, '0.0.0.0:5540')
        return (0, '')
      if 'iptables' in cmd:
        return (
            '-A OUTPUT -o eth0 -p udp --dport 5353 -j DROP\n'
            '-A INPUT -i eth0 -p udp --dport 5353 -j DROP\n'
        )
      if 'pidof otbr-agent' in cmd:
        return (1, '')  # Triggers otbr-agent start branch
      if 'ot-ctl state' in cmd:
        ot_state_calls[0] += 1
        if ot_state_calls[0] == 1:
          return (0, 'detached')
        return (0, 'disabled')
      if 'grep -E "GATT application registered' in cmd:
        return (0, 'BLE advertisement started')
      return (0, 'OK')

    home = FakeCirqueHome(handler=thread_reset_handler)
    mock_dbus = mock.MagicMock()
    mock_bt_server = mock.MagicMock()
    with mock.patch.object(
        BlueToothCapability, '_SHARED_BLUEZ_DBUS', mock_dbus
    ):
      with mock.patch.object(
          BlueToothCapability, '_SHARED_VIRTUAL_SERVER', mock_bt_server
      ):
        VirtualHomeTopology.clean_chip_thread_device_state_and_restart(
            cirque_home=home,
            device_id='dev_node',
            controller_id='ctrl_node',
            discriminator=3840,
            passcode=20202021,
        )

    mock_dbus.reset_connections.assert_called_once()
    mock_bt_server.reset_all_controllers.assert_called_once()
    self.assertGreaterEqual(pidof_calls[0], 2)
    self.assertGreaterEqual(port_calls[0], 2)
    self.assertGreaterEqual(ot_state_calls[0], 2)
    deployed_helpers = [
        cmd for nid, cmd in home.calls if 'dataset_helper.py' in cmd
    ]
    self.assertTrue(len(deployed_helpers) > 0)

  def test_clean_chip_thread_device_state_bluetooth_exception_handled(self):
    def reset_handler(nid, cmd):
      if 'iptables' in cmd:
        return (
            '-A OUTPUT -o eth0 -p udp --dport 5353 -j DROP\n'
            '-A INPUT -i eth0 -p udp --dport 5353 -j DROP\n'
        )
      if 'ot-ctl state' in cmd:
        return (0, 'disabled')
      if 'grep -E "GATT application registered' in cmd:
        return (0, 'BLE advertisement started')
      return (0, '')

    home = FakeCirqueHome(handler=reset_handler)
    mock_dbus = mock.MagicMock()
    mock_dbus.reset_connections.side_effect = RuntimeError('Thread DBus error')
    with mock.patch.object(
        BlueToothCapability, '_SHARED_BLUEZ_DBUS', mock_dbus
    ):
      VirtualHomeTopology.clean_chip_thread_device_state_and_restart(
          cirque_home=home, device_id='dev'
      )

  def test_clean_chip_thread_device_state_gatt_failure_raises(self):
    def thread_gatt_fail(nid, cmd):
      if 'iptables' in cmd:
        return (
            '-A OUTPUT -o eth0 -p udp --dport 5353 -j DROP\n'
            '-A INPUT -i eth0 -p udp --dport 5353 -j DROP\n'
        )
      if 'ot-ctl state' in cmd:
        return (0, 'disabled')
      if 'grep -E "GATT application registered' in cmd:
        return (1, '')
      if 'tail -n 50 /tmp/' in cmd:
        return (0, 'CRASH: Thread radio init failure')
      return (0, '')

    home = FakeCirqueHome(handler=thread_gatt_fail)
    with self.assertRaises(RuntimeError) as ctx:
      VirtualHomeTopology.clean_chip_thread_device_state_and_restart(
          cirque_home=home, device_id='dev', timeout_sec=0.01
      )
    self.assertIn('failed GATT registration', str(ctx.exception))
    self.assertIn('Thread radio init failure', str(ctx.exception))


class VirtualHomeCommissioningVerificationTest(unittest.TestCase):
  """Tests Wi-Fi, Thread, and Android emulator commissioning flows."""

  def setUp(self):
    super().setUp()
    patcher = mock.patch(
        'cirque.home.virtual_home_topology.time.sleep', return_value=None
    )
    patcher.start()
    self.addCleanup(patcher.stop)

  def test_verify_real_chip_ble_wifi_commissioning_success(self):
    dev_ip_polls = [0]

    def comm_handler(nid, cmd):
      if 'State' in cmd:
        return '("completed",)'
      if 'ip -4 addr' in cmd:
        if nid == 'ctrl':
          return 'inet 10.0.1.10/24'
        dev_ip_polls[0] += 1
        if dev_ip_polls[0] == 1:
          return ''
        return 'inet 10.0.1.55/24'
      if 'pairing ble-wifi' in cmd:
        return (0, 'Device commissioning completed successfully')
      if 'onoff toggle' in cmd:
        return (0, 'Endpoint 1 OnOff toggle OK')
      if 'onoff read on-off' in cmd:
        return (0, 'Endpoint 1 OnOff = true')
      if 'ping' in cmd:
        return '2 packets transmitted, 2 received, 0% packet loss'
      if 'cat /tmp/chip-all-clusters.log' in cmd:
        return 'all-clusters-app running clean'
      return 'OK'

    home = FakeCirqueHome(handler=comm_handler)
    wifi_server = FakeWiFiServer({'relayed_udp5540_frames': 10})
    with mock.patch.object(
        VirtualHomeTopology, 'clean_chip_device_state_and_restart'
    ):
      with mock.patch.object(
          WiFiCapability, '_SHARED_VIRTUAL_SERVER', wifi_server
      ):
        res = VirtualHomeTopology.verify_real_chip_ble_wifi_commissioning(
            cirque_home=home,
            controller_id='ctrl',
            device_id='dev',
            node_id=1001,
            restart_app=True,
        )

    status_outcome = res['status']
    self.assertEqual(status_outcome, 'success')
    self.assertEqual(res['phase'], 'operational_interaction')
    self.assertEqual(res['controller_ip'], '10.0.1.10')
    self.assertEqual(res['device_ip'], '10.0.1.55')
    self.assertEqual(res['toggle_exit_code'], 0)
    self.assertEqual(res['read_exit_code'], 0)
    packet_loss_ok = res['packet_loss_zero']
    self.assertTrue(packet_loss_ok)
    self.assertEqual(res['ops_wifi_before'], {'relayed_udp5540_frames': 10})
    self.assertEqual(res['ops_wifi_after'], {'relayed_udp5540_frames': 10})

  def test_verify_real_chip_ble_wifi_commissioning_wifi_counter_exception(
      self,
  ):
    def comm_handler(nid, cmd):
      if 'State' in cmd:
        return '("completed",)'
      if 'ip -4 addr' in cmd:
        return 'inet 10.0.1.55/24'
      if 'pairing ble-wifi' in cmd:
        return (0, 'Device commissioning completed')
      if 'onoff' in cmd or 'ping' in cmd:
        return (0, '0% packet loss')
      return 'OK'

    home = FakeCirqueHome(handler=comm_handler)
    mock_wifi = mock.MagicMock()
    mock_wifi.get_frame_counters.side_effect = RuntimeError('Wifi counter err')
    with mock.patch.object(
        VirtualHomeTopology, 'clean_chip_device_state_and_restart'
    ):
      with mock.patch.object(
          WiFiCapability, '_SHARED_VIRTUAL_SERVER', mock_wifi
      ):
        res = VirtualHomeTopology.verify_real_chip_ble_wifi_commissioning(
            cirque_home=home,
            controller_id='ctrl',
            device_id='dev',
            restart_app=False,
        )
    status_outcome = res['status']
    self.assertEqual(status_outcome, 'success')
    self.assertIsNone(res['ops_wifi_before'])
    self.assertIsNone(res['ops_wifi_after'])

  def test_verify_real_chip_ble_wifi_commissioning_dhcp_failure(self):
    def dhcp_fail_handler(nid, cmd):
      if 'State' in cmd:
        return '("completed",)'
      if 'ip -4 addr' in cmd:
        return 'inet 10.0.1.10/24' if nid == 'ctrl' else ''
      if 'pairing ble-wifi' in cmd:
        return (0, 'Device commissioning completed')
      return ''

    home = FakeCirqueHome(handler=dhcp_fail_handler)
    with mock.patch.object(
        VirtualHomeTopology, 'clean_chip_device_state_and_restart'
    ):
      res = VirtualHomeTopology.verify_real_chip_ble_wifi_commissioning(
          cirque_home=home,
          controller_id='ctrl',
          device_id='dev',
          restart_app=False,
      )
    self.assertEqual(res['status'], 'failed')
    self.assertEqual(res['phase'], 'wifi_dhcp')
    self.assertIn('did not acquire wlan0 IP', res['error'])

  def test_verify_real_chip_ble_wifi_commissioning_phase_failures(self):
    with mock.patch.object(
        VirtualHomeTopology, 'clean_chip_device_state_and_restart'
    ):
      # Phase: wifi_provisioning
      home_wprov = FakeCirqueHome(
          handler=lambda nid, cmd: (
              1,
              'PASE establishment successful\n'
              'ConnectNetwork response, networkingStatus=2\n',
          )
      )
      res_wprov = (
          VirtualHomeTopology.verify_real_chip_ble_wifi_commissioning(
              home_wprov, 'ctrl', 'dev', restart_app=False
          )
      )
      self.assertEqual(res_wprov['phase'], 'wifi_provisioning')
      self.assertEqual(res_wprov['connect_network_status'], 2)

      # Phase: pase_authentication
      home_pase = FakeCirqueHome(
          handler=lambda nid, cmd: (
              1,
              "Failed to verify peer's MAC address in handshake",
          )
      )
      res_pase = VirtualHomeTopology.verify_real_chip_ble_wifi_commissioning(
          home_pase, 'ctrl', 'dev', restart_app=False
      )
      self.assertEqual(res_pase['phase'], 'pase_authentication')

      # Phase: ble_discovery_timeout
      home_ble = FakeCirqueHome(
          handler=lambda nid, cmd: (1, 'CHIP Error: BLE scan timeout')
      )
      res_ble = VirtualHomeTopology.verify_real_chip_ble_wifi_commissioning(
          home_ble, 'ctrl', 'dev', restart_app=False
      )
      self.assertEqual(res_ble['phase'], 'ble_discovery_timeout')

      # Phase: commissioning_failed generic fallback
      home_gen = FakeCirqueHome(
          handler=lambda nid, cmd: (1, 'PBKDFParamResponse received but failed')
      )
      res_gen = VirtualHomeTopology.verify_real_chip_ble_wifi_commissioning(
          home_gen, 'ctrl', 'dev', restart_app=False
      )
      self.assertEqual(res_gen['phase'], 'commissioning_failed')

  def test_verify_android_emulator_ble_wifi_commissioning_success(self):
    dev_ip_polls = [0]

    def emu_wifi_handler(nid, cmd):
      if 'ip -4 addr' in cmd:
        dev_ip_polls[0] += 1
        if dev_ip_polls[0] == 1:
          return ''
        return 'inet 10.0.1.88/24'
      if 'cat /tmp/chip-all-clusters.log' in cmd:
        return 'chip app operational logs'
      return 'OK'

    home = FakeCirqueHome(handler=emu_wifi_handler)
    android_node = FakeAndroidNode()
    android_node.container = FakeContainer(output=b'inet 10.0.1.77/24')
    home.home['devices']['android_ctrl'] = android_node

    bt_server = FakeBluetoothServer(ctrl=FakeController(20, 30))
    wifi_server = FakeWiFiServer({'relayed_udp5540_frames': 15})
    docker_mgr = FakeDockerManager()

    with mock.patch.object(
        VirtualHomeTopology, 'clean_chip_device_state_and_restart'
    ):
      with mock.patch.object(
          BlueToothCapability,
          'get_or_start_virtual_server',
          return_value=bt_server,
      ):
        with mock.patch.object(
            WiFiCapability,
            'get_or_start_virtual_server',
            return_value=wifi_server,
        ):
          with mock.patch.object(
              WiFiCapability, '_SHARED_DOCKER_MANAGER', docker_mgr
          ):
            vht_verify = (
                VirtualHomeTopology
                .verify_android_emulator_ble_wifi_commissioning
            )
            res = vht_verify(
                cirque_home=home,
                controller_id='android_ctrl',
                device_id='dev_node',
                restart_app=True,
            )

    status_outcome = res['status']
    self.assertEqual(status_outcome, 'success')
    self.assertEqual(res['phase'], 'operational_interaction')
    self.assertEqual(res['controller_ip'], '10.0.1.77')
    self.assertEqual(res['device_ip'], '10.0.1.88')
    self.assertEqual(len(docker_mgr.calls), 1)
    self.assertIn(('setup_guest_wifi', 'wlan0'), android_node.calls)

  def test_verify_android_emulator_ble_wifi_commissioning_failure_and_fallback(
      self,
  ):
    # Tests controller_id not present in devices -> fallback IP 10.0.1.5
    home = FakeCirqueHome(handler=lambda nid, cmd: '')
    bt_server = FakeBluetoothServer()
    wifi_server = FakeWiFiServer()

    with mock.patch.object(
        VirtualHomeTopology, 'clean_chip_device_state_and_restart'
    ):
      with mock.patch.object(
          BlueToothCapability,
          'get_or_start_virtual_server',
          return_value=bt_server,
      ):
        with mock.patch.object(
            WiFiCapability,
            'get_or_start_virtual_server',
            return_value=wifi_server,
        ):
          vht_verify = (
              VirtualHomeTopology
              .verify_android_emulator_ble_wifi_commissioning
          )
          res = vht_verify(
              cirque_home=home,
              controller_id='missing_node',
              device_id='dev_node',
              restart_app=False,
          )

    self.assertEqual(res['status'], 'failed')
    self.assertEqual(res['phase'], 'commissioning')
    self.assertEqual(res['controller_ip'], '10.0.1.5')
    self.assertEqual(res['device_ip'], '')

  def test_verify_android_emulator_ble_thread_commissioning_success(self):
    ot_state_polls = [0]

    def emu_thread_handler(nid, cmd):
      if 'State' in cmd:
        return '("completed",)'
      if 'iptables' in cmd:
        return (
            '-A OUTPUT -o eth0 -p udp --dport 5353 -j DROP\n'
            '-A INPUT -i eth0 -p udp --dport 5353 -j DROP\n'
        )
      if 'ot-ctl state' in cmd:
        ot_state_polls[0] += 1
        if ot_state_polls[0] == 1:
          return 'detached'
        return 'leader'
      if 'ot-ctl extpanid' in cmd:
        return '1111222233334444'
      if 'ot-ctl panid' in cmd:
        return '0x1234'
      if 'ot-ctl channel' in cmd:
        return '15'
      if 'ip -4 addr' in cmd:
        return 'inet 10.0.1.92/24'
      if 'cat /tmp/chip-all-clusters.log' in cmd:
        return 'thread chip app running'
      return 'OK'

    home = FakeCirqueHome(handler=emu_thread_handler)
    android_node = FakeAndroidNode()
    android_node.container = FakeContainer(output=b'inet 10.0.1.77/24')
    home.home['devices']['android_ctrl'] = android_node

    bt_server = FakeBluetoothServer(ctrl=FakeController(10, 20))
    wifi_server = FakeWiFiServer({'relayed_udp5540_frames': 8})
    docker_mgr = FakeDockerManager()

    with mock.patch.object(
        VirtualHomeTopology, 'clean_chip_thread_device_state_and_restart'
    ):
      with mock.patch.object(
          BlueToothCapability,
          'get_or_start_virtual_server',
          return_value=bt_server,
      ):
        with mock.patch.object(
            WiFiCapability,
            'get_or_start_virtual_server',
            return_value=wifi_server,
        ):
          with mock.patch.object(
              WiFiCapability, '_SHARED_DOCKER_MANAGER', docker_mgr
          ):
            vht_verify = (
                VirtualHomeTopology
                .verify_android_emulator_ble_thread_commissioning
            )
            res = vht_verify(
                cirque_home=home,
                controller_id='android_ctrl',
                device_id='dev_node',
                restart_app=True,
            )

    status_outcome = res['status']
    self.assertEqual(status_outcome, 'success')
    self.assertEqual(res['phase'], 'operational_interaction')
    self.assertEqual(res['thread_state'], 'leader')
    self.assertEqual(res['thread_extpanid'], '1111222233334444')
    self.assertEqual(res['thread_panid'], '0x1234')
    self.assertEqual(res['thread_channel'], '15')
    self.assertEqual(res['controller_ip'], '10.0.1.77')
    self.assertEqual(res['device_ip'], '10.0.1.92')

  def test_verify_android_emulator_ble_thread_commissioning_failure(self):
    def emu_thread_fail(nid, cmd):
      if 'State' in cmd:
        return '("completed",)'
      if 'iptables' in cmd:
        return (
            '-A OUTPUT -o eth0 -p udp --dport 5353 -j DROP\n'
            '-A INPUT -i eth0 -p udp --dport 5353 -j DROP\n'
        )
      if 'ot-ctl state' in cmd:
        return 'detached'
      return ''

    home = FakeCirqueHome(handler=emu_thread_fail)
    bt_server = FakeBluetoothServer()
    wifi_server = FakeWiFiServer()

    with mock.patch.object(
        VirtualHomeTopology, 'clean_chip_thread_device_state_and_restart'
    ):
      with mock.patch.object(
          BlueToothCapability,
          'get_or_start_virtual_server',
          return_value=bt_server,
      ):
        with mock.patch.object(
            WiFiCapability,
            'get_or_start_virtual_server',
            return_value=wifi_server,
        ):
          vht_verify = (
              VirtualHomeTopology
              .verify_android_emulator_ble_thread_commissioning
          )
          res = vht_verify(
              cirque_home=home,
              controller_id='missing_node',
              device_id='dev_node',
              restart_app=False,
          )

    self.assertEqual(res['status'], 'failed')
    self.assertEqual(res['phase'], 'commissioning')
    self.assertEqual(res['controller_ip'], '10.0.1.5')
    self.assertEqual(res['thread_state'], 'detached')

  def test_associate_wpa_and_dhcp_link_up_and_create_interface_fallback(self):
    cmds_executed = []

    def iface_fallback_handler(nid, cmd):
      """Simulates _exec_in_node handling inside container."""
      cmds_executed.append(cmd)
      if 'GetInterface' in cmd:
        return 'Error org.freedesktop.DBus.Error.Failed: Interface not found'
      if 'CreateInterface' in cmd:
        return '("/fi/w1/wpa_supplicant1/Interfaces/0",)'
      if 'AddNetwork' in cmd:
        return '("/fi/w1/wpa_supplicant1/Interfaces/0/Networks/1",)'
      if 'State' in cmd:
        return '("completed",)'
      if 'ip -4 addr show' in cmd:
        return 'inet 10.0.1.66/24 dev wlan0'
      return ''

    home = FakeCirqueHome(handler=iface_fallback_handler)
    state = VirtualHomeTopology._associate_wpa_and_dhcp(
        home, 'test_dev', 'TestSSID', 'TestPSK'
    )
    self.assertIn('completed', state)

    link_up = next(c for c in cmds_executed if 'ip link set dev wlan0 up' in c)
    self.assertIsNotNone(link_up)

    create_iface = next(c for c in cmds_executed if 'CreateInterface' in c)
    self.assertIn('Ifname', create_iface)
    self.assertIn('wlan0', create_iface)

    dhcpcd_cmd = next(c for c in cmds_executed if 'dhcpcd' in c)
    self.assertIn('dhcpcd -n -4 wlan0', dhcpcd_cmd)
    self.assertIn('dhcpcd -b -4 --noipv4ll wlan0', dhcpcd_cmd)


class VirtualHomeThreadBorderRouterTest(unittest.TestCase):
  """Tests ThreadBorderRouter topology helpers, dataset parsers, and proxies."""

  def setUp(self):
    super().setUp()
    patcher = mock.patch(
        'cirque.home.virtual_home_topology.time.sleep', return_value=None
    )
    patcher.start()
    self.addCleanup(patcher.stop)

  def test_thread_border_router_constants(self):
    from cirque.home import virtual_home_topology as vht

    self.assertEqual(vht.DEFAULT_HOME_SUBNET, '10.0.1.0/24')
    self.assertEqual(vht.DEFAULT_HOME_SSID, 'CirqueHomeAP')
    self.assertEqual(vht.DEFAULT_HOME_PSK, 'cirquewifipassword')
    self.assertEqual(vht.DEFAULT_THREAD_PREFIX, 'fd11:33::/64')
    self.assertEqual(vht.DEFAULT_WIFI_IPV6_PREFIX, 'fd11:22::/64')
    self.assertEqual(vht.DEFAULT_THREAD_MESH_LOCAL_PREFIX, 'fdde:ad00:beef:0::/64')
    self.assertEqual(vht.DEFAULT_UDP_SERVICE_PORT, 5540)
    self.assertEqual(vht.DEFAULT_TBR_CONTROL_PORT, 5541)

    self.assertEqual(vht.DEFAULT_MATTER_THREAD_PREFIX, vht.DEFAULT_THREAD_PREFIX)
    self.assertEqual(vht.DEFAULT_MATTER_PORT, vht.DEFAULT_UDP_SERVICE_PORT)
    self.assertEqual(
        vht.DEFAULT_MATTER_MESH_LOCAL_PREFIX, vht.DEFAULT_THREAD_MESH_LOCAL_PREFIX
    )

    self.assertIn('ot-ctl', vht.THREAD_JOINER_ATTACH_HELPER)
    self.assertIn('publish_avahi_service', vht.THREAD_BORDER_ROUTER_PROXY_HELPER)

  def test_form_thread_border_router_network(self):
    def tbr_handler(nid, cmd):
      if 'ot-ctl dataset active -x' in cmd:
        return '0e080000000000010000\nDone\n'
      if 'ot-ctl dataset active' in cmd:
        return (
            'Active Timestamp: 1\n'
            'Channel: 15\n'
            'Channel Mask: 0x07fff800\n'
            'Ext PAN ID: 1111111122222222\n'
            'Mesh Local Prefix: fdde:ad00:beef:0::/64\n'
            'Network Key: 00112233445566778899aabbccddeeff\n'
            'Network Name: CirqueTBR\n'
            'PAN ID: 0x1234\n'
            'Done\n'
        )
      if 'ot-ctl state' in cmd:
        return 'leader'
      return 'OK'

    home = FakeCirqueHome(handler=tbr_handler)
    res = VirtualHomeTopology.form_thread_border_router_network(
        cirque_home=home,
        tbr_id='tbr_node',
        channel=15,
        pan_id='0x1234',
        ext_pan_id='1111111122222222',
    )
    self.assertEqual(res['channel'], 15)
    self.assertEqual(res['pan_id'], '0x1234')
    self.assertEqual(res['ext_pan_id'], '1111111122222222')
    self.assertEqual(res['state'], 'leader')
    self.assertTrue(any('ot-ctl dataset commit active' in c for n, c in home.calls))
    self.assertTrue(any('ot-ctl state leader' in c for n, c in home.calls))

  def test_start_thread_border_router_proxy(self):
    home = FakeCirqueHome()
    VirtualHomeTopology.start_thread_border_router_proxy(
        cirque_home=home,
        tbr_id='tbr_node',
        default_target_ip='fd11:33::2',
        service_port=5540,
        control_port=5541,
    )
    proxy_calls = [c for n, c in home.calls if 'tbr_proxy_helper.py' in c]
    self.assertTrue(len(proxy_calls) > 0)
    self.assertIn('CIRQUE_TBR_CONTROL_PORT=5541', proxy_calls[0])

  def test_prepare_thread_end_device_joiner(self):
    home = FakeCirqueHome()
    VirtualHomeTopology.prepare_thread_end_device_joiner(
        cirque_home=home,
        device_id='dev_node',
        end_device_wpan_ip='fd11:33::2/64',
        tbr_wpan_ip='fd11:33::1',
    )
    joiner_calls = [c for n, c in home.calls if 'dataset_helper.py' in c]
    self.assertTrue(len(joiner_calls) > 0)
    self.assertIn('CIRQUE_TBR_CONTROL_ADDR=fd11:33::1', joiner_calls[0])

  def test_module_level_tbr_exports(self):
    from cirque.home import virtual_home_topology as vht

    self.assertEqual(
        vht.form_thread_border_router_network,
        VirtualHomeTopology.form_thread_border_router_network,
    )
    self.assertEqual(
        vht.get_thread_active_dataset,
        VirtualHomeTopology.get_thread_active_dataset,
    )
    self.assertEqual(
        vht.start_thread_border_router_proxy,
        VirtualHomeTopology.start_thread_border_router_proxy,
    )
    self.assertEqual(
        vht.prepare_thread_end_device_joiner,
        VirtualHomeTopology.prepare_thread_end_device_joiner,
    )
    self.assertEqual(
        vht.clean_thread_device_state_and_restart,
        VirtualHomeTopology.clean_thread_device_state_and_restart,
    )
    self.assertEqual(
        vht.clean_chip_thread_device_state_and_restart,
        VirtualHomeTopology.clean_chip_thread_device_state_and_restart,
    )

  def test_thread_joiner_attach_helper_compiles_and_pan_id_regex(self):
    from cirque.home import virtual_home_topology as vht

    compile(vht.THREAD_JOINER_ATTACH_HELPER, 'joiner_helper.py', 'exec')
    compile(vht.THREAD_BORDER_ROUTER_PROXY_HELPER, 'tbr_proxy.py', 'exec')
    m = re.search(
        r'(?<!Ext )PAN ID:\s*(0x[0-9a-fA-F]+)', _PARTIAL_DATASET_ACTIVE
    )
    self.assertIsNotNone(m)
    self.assertEqual(m.group(1), '0x1234')


if __name__ == '__main__':
  unittest.main()

