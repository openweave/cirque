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
"""Unit tests for AndroidDockerNode and Android emulator data plane."""

import logging
import os
import shlex
import shutil
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from cirque.capabilities.pcapcapability import DLT_EN10MB, PcapWriter
from cirque.common.isolated_runtime_dirs import isolate_virtual_runtime_dirs
from cirque.home.virtual_home_topology import (
    VirtualHomeApSpec,
    VirtualHomeNodeSpec,
    VirtualHomeTopology,
)
from cirque.nodes.androiddockernode import AndroidDockerNode
from cirque.pcap.summarize_pcap import summarize_pcap

_REPO_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..', '..', '..')
)
_VALIDATE_SCRIPT = os.path.join(
    _REPO_ROOT, 'examples', 'validate_virtual_android_home.sh'
)


def setUpModule():
  unittest.addModuleCleanup(isolate_virtual_runtime_dirs())


class TestAndroidDockerNode(unittest.TestCase):
  """Unit tests for AndroidDockerNode."""

  def set_up(self):
    self.mock_client = MagicMock()
    self.mock_container = MagicMock()
    self.mock_container.exec_run.return_value = SimpleNamespace(
        exit_code=0, output=b'ok\n'
    )
    self.mock_client.containers.run.return_value = self.mock_container

  setUp = set_up

  def test_init_defaults_and_runtime_mode(self):
    with patch('os.path.exists', return_value=True):
      node = AndroidDockerNode(self.mock_client)
      self.assertEqual(node.runtime_mode, 'kvm_emulator')
      self.assertEqual(node.image_name, 'cirque-device-base:latest')
      self.assertEqual(node.tap_interface, 'cirque_tap0')
      self.assertTrue(node.is_tap_station)
      self.assertEqual(
          node.radio_feature_flags,
          '-feature -BluetoothEmulation -feature -WiFiPacketStream',
      )
      self.assertEqual(
          node.get_bluetooth_hci_socket_path(),
          '/dev/virtual_bt/hci_bridge.sock',
      )
      self.assertIn('/dev/kvm:/dev/kvm:rwm', node.devices)
      self.assertIn('/dev/net/tun:/dev/net/tun:rwm', node.devices)

  def test_run_with_emulator_volume_mounts(self):
    with (
        patch('os.path.exists', return_value=True),
        patch('os.path.isdir', return_value=True),
    ):
      node = AndroidDockerNode(
          self.mock_client,
          sdk_path='/fake/sdk',
          avd_path='/fake/avd',
          preferred_mode='kvm_emulator',
      )
      node.run()
      self.mock_client.containers.run.assert_called_once()
      call_kwargs = self.mock_client.containers.run.call_args[1]
      self.assertTrue(call_kwargs.get('privileged'))
      volumes = call_kwargs.get('volumes', [])
      self.assertIn('/fake/sdk:/opt/android/sdk:ro', volumes)
      self.assertIn('/fake/avd:/root/.android/avd:rw', volumes)

  def test_setup_tap_device(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    node.setup_tap_device('cirque_tap0')
    self.mock_container.exec_run.assert_called()
    called_cmd = self.mock_container.exec_run.call_args[0][0]
    self.assertIn('ip tuntap add dev cirque_tap0 mode tap', called_cmd)
    self.assertIn('accept_ra=0', called_cmd)
    self.assertIn('autoconf=0', called_cmd)
    self.assertIn('router_solicitations=0', called_cmd)
    self.assertNotIn('disable_ipv6=1', called_cmd)
    self.assertNotIn('addr flush', called_cmd)

  def test_start_emulator_command_flags(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    executed_cmds = []

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      executed_cmds.append(cmd_str)
      if 'sys.boot_completed' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'1\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    started = node.start_emulator(timeout_sec=1.0)
    self.assertTrue(started)

    emu_launch_cmd = next(c for c in executed_cmds if 'emulator -avd' in c)
    self.assertIn('-feature -BluetoothEmulation', emu_launch_cmd)
    self.assertIn('-feature -WiFiPacketStream', emu_launch_cmd)
    self.assertNotIn('-packet-streamer-endpoint', emu_launch_cmd)
    self.assertIn('-wifi-tap cirque_tap0', emu_launch_cmd)
    self.assertIn('-read-only', emu_launch_cmd)

  # Process line as printed by `ps -ef` inside a live emulator container.
  _EMULATOR_PS_LINE = (
      'root          74       1 99 06:32 ?        00:01:50 '
      '/opt/android/sdk/emulator/qemu/linux-x86_64/qemu-system-x86_64-headless'
      ' -avd Pixel_6_API_34 -no-window -no-audio -no-boot-anim'
      ' -gpu swiftshader_indirect -read-only -no-snapshot'
      ' -feature -BluetoothEmulation -feature -WiFiPacketStream'
      ' -wifi-tap cirque_tap0\n'
  )

  def _node_with_ps_output(self, ps_output: str) -> AndroidDockerNode:
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    def fake_exec(cmd, **kwargs):
      if 'ps -ef' in str(cmd):
        return SimpleNamespace(exit_code=0, output=ps_output.encode())
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    return node

  def test_describe_radio_path_from_running_emulator(self):
    ps_output = (
        'UID          PID    PPID  C STIME TTY          TIME CMD\n'
        'root           1       0  0 06:31 ?        00:00:00 /sbin/init\n'
        + self._EMULATOR_PS_LINE
    )
    node = self._node_with_ps_output(ps_output)
    path = node.describe_radio_path()
    self.assertTrue(path['emulator_running'])
    self.assertTrue(path['bt_builtin_emulation_disabled'])
    self.assertTrue(path['wifi_packet_stream_disabled'])
    self.assertTrue(path['wifi_tap_attached'])
    self.assertEqual(
        path['radio_feature_flags'],
        '-feature -BluetoothEmulation -feature -WiFiPacketStream',
    )
    self.assertEqual(path['wifi_tap'], 'cirque_tap0')

  def test_describe_radio_path_without_emulator(self):
    node = self._node_with_ps_output(
        'UID          PID    PPID  C STIME TTY          TIME CMD\n'
        'root           1       0  0 06:31 ?        00:00:00 /sbin/init\n'
    )
    path = node.describe_radio_path()
    self.assertFalse(path['emulator_running'])
    self.assertFalse(path['bt_builtin_emulation_disabled'])
    self.assertFalse(path['wifi_packet_stream_disabled'])
    self.assertFalse(path['wifi_tap_attached'])

  def test_describe_radio_path_rejects_unpinned_bluetooth_hal(self):
    unpinned = self._EMULATOR_PS_LINE.replace(
        ' -feature -BluetoothEmulation', ''
    )
    node = self._node_with_ps_output(unpinned)
    path = node.describe_radio_path()
    self.assertTrue(path['emulator_running'])
    self.assertFalse(path['bt_builtin_emulation_disabled'])
    self.assertTrue(path['wifi_tap_attached'])

  def test_describe_radio_path_without_container(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = None
    self.assertEqual(node.get_emulator_cmdline(), '')
    self.assertFalse(node.describe_radio_path()['emulator_running'])

  def test_topology_android_radio_path_reports_hci_delta(self):
    class _Controller:

      def __init__(self, tx: int, rx: int):
        self._tx = tx
        self._rx = rx

      def to_dict(self):
        return {'tx_packets': self._tx, 'rx_packets': self._rx}

    class _BtServer:

      def __init__(self, ctrl):
        self._ctrl = ctrl

      def get_controller(self, bind_id):
        return self._ctrl if bind_id == 'android_hci0' else None

    node = self._node_with_ps_output(self._EMULATOR_PS_LINE)
    server = _BtServer(_Controller(tx=10, rx=5))
    before = VirtualHomeTopology._android_hci_frame_count(
        server, 'android_hci0'
    )
    self.assertEqual(before, 15)
    server._ctrl = _Controller(tx=300, rx=250)
    path = VirtualHomeTopology._android_radio_path(node, server, before)
    self.assertTrue(path['bt_controller_bound'])
    self.assertEqual(path['android_hci_frames'], 535)
    self.assertTrue(path['bt_builtin_emulation_disabled'])
    self.assertTrue(path['wifi_tap_attached'])

    unbound = VirtualHomeTopology._android_radio_path(node, _BtServer(None), 0)
    self.assertFalse(unbound['bt_controller_bound'])
    self.assertEqual(unbound['android_hci_frames'], 0)

  def test_install_chiptool(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    with patch('os.path.exists', return_value=True):
      self.mock_container.exec_run.return_value = SimpleNamespace(
          exit_code=0, output=b'Success\n'
      )
      self.assertTrue(node.install_chiptool('/fake/CHIPTool.apk'))

  def test_start_pty_bridge_and_bluetooth_hal_restart(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    executed_cmds = []

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      executed_cmds.append(cmd_str)
      if 'readlink' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'/dev/pts/0\n')
      if 'ps -ef' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'root 123 1 pty_bridge\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    bt_patch_target = (
        'cirque.capabilities.bluetoothcapability.'
        'BlueToothCapability.get_or_start_virtual_server'
    )
    with patch(bt_patch_target) as mock_get_server:
      mock_server = mock_get_server.return_value
      mock_server.get_controller.return_value = MagicMock()
      self.assertTrue(node.start_pty_bridge(bt_port=23458, host_ip='10.0.2.2'))

    bridge_run = next(c for c in executed_cmds if '/dev/bluetooth0' in c)
    self.assertIn('/dev/bluetooth0 10.0.2.2 23458 android_hci0', bridge_run)

    restart_run = next(
        c for c in executed_cmds if 'android.hardware.bluetooth-service' in c
    )
    self.assertIn('killall bt_vhci_forwarder', restart_run)
    self.assertIn('cmd bluetooth_manager disable', restart_run)
    self.assertIn('cmd bluetooth_manager enable', restart_run)
    self.assertIn('svc bluetooth enable', restart_run)

    chmod_chcon = next(
        c for c in executed_cmds if 'chcon u:object_r:hci_attach_dev:s0' in c
    )
    self.assertIn('/dev/bluetooth0 /dev/pts/*', chmod_chcon)

  def test_start_pty_bridge_relaunches_when_first_launch_is_lost(self):
    """First launch is swallowed by the adbd restart; second one works."""
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    launches = []
    readlink_calls = []

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if '/dev/bluetooth0 ' in cmd_str and 'pty_bridge.log 2>&1 &' in cmd_str:
        launches.append(cmd_str)
        return SimpleNamespace(exit_code=0, output=b'')
      if 'readlink' in cmd_str:
        readlink_calls.append(len(launches))
        if len(launches) >= 2:
          return SimpleNamespace(exit_code=0, output=b'/dev/pts/3\n')
        return SimpleNamespace(exit_code=0, output=b'/dev/vport7p2\n')
      if 'pidof pty_bridge' in cmd_str:
        return SimpleNamespace(exit_code=1, output=b'')
      if 'pty_bridge.log' in cmd_str and 'cat ' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'')
      if 'adb shell id' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'uid=0(root)\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    bt_patch_target = (
        'cirque.capabilities.bluetoothcapability.'
        'BlueToothCapability.get_or_start_virtual_server'
    )
    with (
        patch(bt_patch_target) as mock_get_server,
        patch('cirque.nodes.androiddockernode.time.sleep'),
    ):
      mock_get_server.return_value.get_controller.return_value = MagicMock()
      self.assertTrue(node.start_pty_bridge(bt_port=23458))

    self.assertEqual(len(launches), 2)
    # Attempt 1 polled the full window (20 readlinks) with no PTY; attempt
    # 2 saw the PTY on its first poll.
    self.assertEqual(readlink_calls.count(1), 20)
    self.assertEqual(readlink_calls.count(2), 1)

  def test_start_pty_bridge_waits_for_root_before_launch(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    id_calls = []
    order = []

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'adb shell id' in cmd_str:
        id_calls.append(cmd_str)
        order.append('id')
        uid = b'uid=2000(shell)\n' if len(id_calls) < 3 else b'uid=0(root)\n'
        return SimpleNamespace(exit_code=0, output=uid)
      if '/dev/bluetooth0 ' in cmd_str and 'pty_bridge.log 2>&1 &' in cmd_str:
        order.append('launch')
        return SimpleNamespace(exit_code=0, output=b'')
      if 'readlink' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'/dev/pts/0\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    bt_patch_target = (
        'cirque.capabilities.bluetoothcapability.'
        'BlueToothCapability.get_or_start_virtual_server'
    )
    with (
        patch(bt_patch_target) as mock_get_server,
        patch('cirque.nodes.androiddockernode.time.sleep'),
    ):
      mock_get_server.return_value.get_controller.return_value = MagicMock()
      self.assertTrue(node.start_pty_bridge(bt_port=23458))

    self.assertEqual(len(id_calls), 3)
    self.assertEqual(order[:4], ['id', 'id', 'id', 'launch'])

  def test_start_pty_bridge_fails_after_three_lost_launches(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    launches = []

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if '/dev/bluetooth0 ' in cmd_str and 'pty_bridge.log 2>&1 &' in cmd_str:
        launches.append(cmd_str)
        return SimpleNamespace(exit_code=0, output=b'')
      if 'readlink' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'/dev/vport7p2\n')
      if 'pidof pty_bridge' in cmd_str:
        return SimpleNamespace(exit_code=1, output=b'')
      if 'pty_bridge.log' in cmd_str and 'cat ' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=b'connect: Connection refused\n'
        )
      if 'adb shell id' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'uid=0(root)\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    with (
        patch('cirque.nodes.androiddockernode.time.sleep'),
        self.assertLogs(level='WARNING') as logs,
    ):
      self.assertFalse(node.start_pty_bridge(bt_port=23458))

    self.assertEqual(len(launches), 3)
    joined = '\n'.join(logs.output)
    self.assertIn('Connection refused', joined)
    self.assertIn('does not point to a PTY', joined)

  def _pty_bridge_bind_fixture(self, bound_after_launch: int):
    """Wires a node whose server binds android_hci0 only after N launches.

    Returns `(node, launches, hal_restarts, server)`. The fake server's
    get_controller() answers None until pty_bridge has been launched
    `bound_after_launch` times, which models a BIND line that was lost on
    the earlier connections.
    """
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    launches = []
    hal_restarts = []

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if '/dev/bluetooth0 ' in cmd_str and 'pty_bridge.log 2>&1 &' in cmd_str:
        launches.append(cmd_str)
        return SimpleNamespace(exit_code=0, output=b'')
      if 'killall bt_vhci_forwarder' in cmd_str:
        hal_restarts.append(cmd_str)
        return SimpleNamespace(exit_code=0, output=b'')
      if 'readlink' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'/dev/pts/1\n')
      if 'pidof pty_bridge' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'4127\n')
      if 'pty_bridge.log' in cmd_str and 'cat ' in cmd_str:
        return SimpleNamespace(
            exit_code=0,
            output=(
                b'[pty_bridge] Connected to Cirque! '
                b'Sent: BIND android_hci0\n'
            ),
        )
      if cmd_str == 'ps -ef':
        return SimpleNamespace(
            exit_code=0,
            output=(
                b'root 1 0 0 22:04 ? 00:00:00 /sbin/init\n'
                b'root 806 0 0 22:04 ? 00:00:00 python3 '
                b'/dev/virtual_bt/bin/bt_tcp_to_unix_relay.py 23458 '
                b'/dev/virtual_bt/shared_hci.sock\n'
            ),
        )
      if cmd_str == 'ss -ltnp':
        return SimpleNamespace(
            exit_code=0,
            output=(
                b'LISTEN 0 16 0.0.0.0:23458 0.0.0.0:* '
                b'users:(("python3",pid=806,fd=3))\n'
            ),
        )
      if 'adb shell id' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'uid=0(root)\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec

    class FakeServer:

      def get_controller(self, bind_id):
        if bind_id == 'android_hci0' and len(launches) >= bound_after_launch:
          return object()
        return None

      def list_controllers(self):
        ids = ['hci0', 'hci1', 'hci2']
        if len(launches) >= bound_after_launch:
          ids.append('android_hci0')
        return [{'controller_id': cid} for cid in ids]

    return node, launches, hal_restarts, FakeServer()

  def test_start_pty_bridge_relaunches_bridge_when_bind_is_missed(self):
    """A lost BIND line costs one bridge relaunch, not the whole test."""
    node, launches, hal_restarts, server = self._pty_bridge_bind_fixture(
        bound_after_launch=2
    )
    bt_patch_target = (
        'cirque.capabilities.bluetoothcapability.'
        'BlueToothCapability.get_or_start_virtual_server'
    )
    with (
        patch(bt_patch_target, return_value=server),
        patch('cirque.nodes.androiddockernode.time.sleep') as mock_sleep,
        self.assertLogs(level='WARNING') as logs,
    ):
      self.assertTrue(node.start_pty_bridge(bt_port=23458))

    self.assertEqual(len(launches), 2)
    self.assertEqual(len(hal_restarts), 2)
    joined = '\n'.join(logs.output)
    self.assertIn(
        'does not have controller android_hci0 bound (pty_bridge round 1 of '
        '2, relaunching the bridge)',
        joined,
    )
    # The diagnostics name both ends of the HCI path.
    self.assertIn("bound controllers: ['hci0', 'hci1', 'hci2']", joined)
    self.assertIn('pty_bridge target: 10.0.2.2:23458', joined)
    self.assertIn('Sent: BIND android_hci0', joined)
    self.assertIn('bt_tcp_to_unix_relay.py 23458', joined)
    self.assertIn('0.0.0.0:23458', joined)
    self.assertNotIn('ERROR', joined)
    # Round 1 polled the full bind window before giving up on it.
    bind_polls = [
        c for c in mock_sleep.call_args_list if c.args == (0.5,)
    ]
    self.assertGreaterEqual(len(bind_polls), 19)

  def test_start_pty_bridge_fails_when_controller_never_binds(self):
    node, launches, hal_restarts, server = self._pty_bridge_bind_fixture(
        bound_after_launch=99
    )
    bt_patch_target = (
        'cirque.capabilities.bluetoothcapability.'
        'BlueToothCapability.get_or_start_virtual_server'
    )
    with (
        patch(bt_patch_target, return_value=server),
        patch('cirque.nodes.androiddockernode.time.sleep'),
        self.assertLogs(level='WARNING') as logs,
    ):
      self.assertFalse(node.start_pty_bridge(bt_port=23458))

    self.assertEqual(len(launches), 2)
    self.assertEqual(len(hal_restarts), 2)
    errors = [line for line in logs.output if line.startswith('ERROR')]
    self.assertEqual(len(errors), 1)
    self.assertIn(
        'does not have controller android_hci0 bound (pty_bridge round 2 of '
        '2)',
        errors[0],
    )
    self.assertIn('guest pidof pty_bridge: 4127', errors[0])
    self.assertIn('guest /dev/bluetooth0 -> /dev/pts/1', errors[0])

  def test_ui_automator_helper_xml_fixture(self):
    from cirque.nodes.androiddockernode import UiAutomatorHelper

    xml_fixture = (
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
        '<hierarchy rotation="0">\n'
        '  <node index="0" text="" resource-id="" '
        'class="android.widget.FrameLayout" '
        'package="com.google.chip.chiptool" bounds="[0,0][1080,2400]">\n'
        '    <node index="0" text="PROVISION CHIP DEVICE WITH WI-FI" '
        'resource-id="com.google.chip.chiptool:id/provisionWiFiCredentialsBtn" '
        'class="android.widget.Button" bounds="[21,443][694,569]" />\n'
        '    <node index="1" text="MANUAL CODE" '
        'resource-id="com.google.chip.chiptool:id/manualCodeBtn" '
        'class="android.widget.RadioButton" bounds="[849,2211][1080,2337]" />\n'
        '    <node index="2" text="" '
        'resource-id="com.google.chip.chiptool:id/manualCodeEditText" '
        'class="android.widget.EditText" bounds="[42,2211][849,2337]" />\n'
        '    <node index="3" text="" '
        'resource-id="com.google.chip.chiptool:id/ssidEd" '
        'class="android.widget.EditText" bounds="[42,596][1038,722]" />\n'
        '    <node index="4" text="" '
        'resource-id="com.google.chip.chiptool:id/pwdEd" '
        'class="android.widget.EditText" bounds="[42,806][1038,932]" />\n'
        '    <node index="5" text="SAVE NETWORK" '
        'resource-id="com.google.chip.chiptool:id/saveNetworkBtn" '
        'class="android.widget.Button" bounds="[679,2160][1038,2295]" />\n'
        '    <node index="6" text="LIGHT ON/OFF &amp; LEVEL CLUSTER" '
        'resource-id="com.google.chip.chiptool:id/onOffClusterBtn" '
        'class="android.widget.Button" bounds="[21,884][639,1010]" />\n'
        '    <node index="7" text="TOGGLE" '
        'resource-id="com.google.chip.chiptool:id/toggleBtn" '
        'class="android.widget.Button" bounds="[432,631][643,772]" />\n'
        '    <node index="8" text="READ" '
        'resource-id="com.google.chip.chiptool:id/readBtn" '
        'class="android.widget.Button" bounds="[21,631][232,772]" />\n'
        '  </node>\n'
        '</hierarchy>\n'
    )
    parsed = UiAutomatorHelper.parse_bounds('[21,443][694,569]')
    self.assertEqual(parsed, (21, 443, 694, 569))

    center = UiAutomatorHelper.get_element_center(
        xml_fixture, resource_id='provisionWiFiCredentialsBtn'
    )
    self.assertEqual(center, ((21 + 694) // 2, (443 + 569) // 2))

    center_text = UiAutomatorHelper.get_element_center(
        xml_fixture, text='SAVE NETWORK'
    )
    self.assertEqual(center_text, ((679 + 1038) // 2, (2160 + 2295) // 2))

    center_toggle = UiAutomatorHelper.get_element_center(
        xml_fixture, resource_id='toggleBtn'
    )
    self.assertEqual(center_toggle, ((432 + 643) // 2, (631 + 772) // 2))

    self.assertIsNone(
        UiAutomatorHelper.get_element_center(
            xml_fixture, resource_id='nonexistent'
        )
    )

  def test_setup_guest_wifi(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'adb shell id' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'uid=0(root)\n')
      if 'ip addr show' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=b'inet 10.0.1.5/24 brd 10.0.1.255 dev wlan0\n'
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    self.assertEqual(
        node.setup_guest_wifi('wlan0', timeout_sec=1.0), '10.0.1.5'
    )

  def test_setup_guest_wifi_retries_dhcpclient_and_link_up(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    exec_cmds = []
    poll_count = [0]

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      exec_cmds.append(cmd_str)
      if 'ip addr show' in cmd_str:
        poll_count[0] += 1
        if poll_count[0] >= 3:
          return SimpleNamespace(
              exit_code=0, output=b'inet 10.0.1.42/24 dev wlan0\n'
          )
        return SimpleNamespace(exit_code=0, output=b'')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    with (
        patch('cirque.nodes.androiddockernode.time.time') as mock_time,
        patch('cirque.nodes.androiddockernode.time.sleep'),
    ):
      mock_time.side_effect = [
          100.0,  # start, last_retry
          100.0,  # loop 1 time.time() - start
          101.0,  # loop 1 time.time() - last_retry
          107.0,  # loop 2 time.time() - start
          107.0,  # loop 2 time.time() - last_retry >= 6.0 trigger
          107.0,  # loop 2 last_retry = time.time()
          108.0,  # loop 3 time.time() - start (acquired!)
      ]
      res = node.setup_guest_wifi('wlan0', timeout_sec=20.0)
      self.assertEqual(res, '10.0.1.42')

    link_up_cmds = [c for c in exec_cmds if 'ip link set dev wlan0 up' in c]
    self.assertGreaterEqual(len(link_up_cmds), 2)
    dhcp_cmds = [c for c in exec_cmds if 'dhcpclient -i wlan0' in c]
    self.assertGreaterEqual(len(dhcp_cmds), 2)

  def test_get_emulator_cmdline_fallback_to_ps_ef(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if cmd_str == 'ps -efww':
        return SimpleNamespace(exit_code=1, output=b'')
      if cmd_str == 'ps -ef':
        return SimpleNamespace(
            exit_code=0,
            output=self._EMULATOR_PS_LINE.encode('utf-8'),
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    cmdline = node.get_emulator_cmdline()
    self.assertIn('-avd Pixel_6_API_34', cmdline)
    self.assertIn('-wifi-tap cirque_tap0', cmdline)

  # uiautomator dump of CHIPTool's Wi-Fi provisioning screens.
  _WIFI_PROVISION_XML = (
      "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
      '<hierarchy rotation="0">\n'
      '  <node bounds="[0,0][1080,2400]">\n'
      '    <node '
      'resource-id="com.google.chip.chiptool:id/provisionWiFiCredentialsBtn" '
      'bounds="[21,443][694,569]"\n'
      '      text="PROVISION CHIP DEVICE WITH WI-FI" />\n'
      '    <node resource-id="com.google.chip.chiptool:id/manualCodeBtn" '
      'bounds="[849,2211][1080,2337]" text="MANUAL CODE" />\n'
      '    <node '
      'resource-id="com.google.chip.chiptool:id/manualCodeEditText" '
      'bounds="[42,2211][849,2337]" text="" />\n'
      '    <node resource-id="com.google.chip.chiptool:id/ssidEd" '
      'bounds="[42,596][1038,722]" text="" />\n'
      '    <node resource-id="com.google.chip.chiptool:id/pwdEd" '
      'bounds="[42,806][1038,932]" text="" />\n'
      '    <node resource-id="com.google.chip.chiptool:id/saveNetworkBtn" '
      'bounds="[679,2160][1038,2295]" text="SAVE NETWORK" />\n'
      '  </node>\n'
      '</hierarchy>\n'
  )
  _INTENT_ACTION = 'com.google.chip.chiptool.action.COMMISSION_BLE_WIFI'
  _BLE_SCAN_LINE = (
      b'I DeviceProvisioningFragment: showMessage:'
      b'Scanning for BLE device 3840\n'
  )
  _COMMISSIONED_LINE = b'D CHIP: onCommissioningComplete for nodeId 1: 0\n'

  def test_commission_via_chiptool_ui(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'cat /data/local/tmp/ui.xml' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=self._WIFI_PROVISION_XML.encode('utf-8')
        )
      if 'logcat' in cmd_str:
        return SimpleNamespace(exit_code=0, output=self._COMMISSIONED_LINE)
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    res = node.commission_via_chiptool_ui(
        ssid='CIRQUE_HOME_AP',
        psk='cirque_home_psk',
        timeout_sec=1.0,
        trigger='ui',
    )
    self.assertEqual(res.get('status'), 'success')
    self.assertEqual(res.get('commissioned_node_id'), 1)
    self.assertEqual(res.get('trigger'), 'ui')
    self.assertIn('video_recording', res)
    self.assertEqual(
        res['video_recording']['name'], '1_ble_wifi_commissioning.mp4'
    )

  def _intent_node(self, apk_handles_intent: bool):
    """Builds a node whose fake adb behaves like CHIPTool.

    When `apk_handles_intent` is False the fake models an APK that predates
    the commissioning intent: the BLE scan only starts once the UI flow has
    launched the activity without an action.
    """
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    executed_cmds = []
    state = {'ui_flow_started': False}

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      executed_cmds.append(cmd_str)
      if 'am start' in cmd_str and ' -a ' not in cmd_str:
        state['ui_flow_started'] = True
      if 'cat /data/local/tmp/ui.xml' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=self._WIFI_PROVISION_XML.encode('utf-8')
        )
      if 'Scanning for BLE device' in cmd_str:
        if apk_handles_intent or state['ui_flow_started']:
          return SimpleNamespace(exit_code=0, output=self._BLE_SCAN_LINE)
        return SimpleNamespace(exit_code=1, output=b'')
      if 'Submit Code:' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'Submit Code: ok\n')
      if 'grep -E' in cmd_str:
        return SimpleNamespace(exit_code=0, output=self._COMMISSIONED_LINE)
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    return node, executed_cmds

  @staticmethod
  def _guest_extras(start_cmd: str) -> dict:
    """Recovers the `am start` string extras as the guest shell sees them.

    docker-py splits the command with shlex, adb joins that argv with
    spaces, and the guest shell splits it again.
    """
    host_argv = shlex.split(start_cmd)
    guest_line = ' '.join(host_argv[host_argv.index('shell') + 1 :])
    guest_argv = shlex.split(guest_line)
    return {
        guest_argv[i + 1]: guest_argv[i + 2]
        for i, tok in enumerate(guest_argv)
        if tok == '--es'
    }

  def test_commission_via_chiptool_intent(self):
    node, executed_cmds = self._intent_node(apk_handles_intent=True)
    res = node.commission_via_chiptool_ui(timeout_sec=1.0)
    self.assertEqual(res.get('status'), 'success')
    self.assertEqual(res.get('commissioned_node_id'), 1)
    self.assertEqual(res.get('trigger'), 'intent')

    start_cmd = next(c for c in executed_cmds if 'am start' in c)
    self.assertIn('-n com.google.chip.chiptool/.CHIPToolActivity', start_cmd)
    self.assertIn(f'-a {self._INTENT_ACTION}', start_cmd)
    self.assertIn('--ei discriminator 3840', start_cmd)
    self.assertIn('--el setupPinCode 20202021', start_cmd)
    self.assertEqual(
        self._guest_extras(start_cmd),
        {'wifiSsid': 'CIRQUE_HOME_AP', 'wifiPassword': 'cirque_home_psk'},
    )
    self.assertFalse(
        [c for c in executed_cmds if 'uiautomator dump' in c],
        'intent path must not drive the UI',
    )

  def test_commission_intent_quotes_credentials(self):
    node, executed_cmds = self._intent_node(apk_handles_intent=True)
    res = node.commission_via_chiptool_intent(
        ssid='Home AP', psk="p@ss word's $1", timeout_sec=1.0
    )
    self.assertEqual(res.get('status'), 'success')
    start_cmd = next(c for c in executed_cmds if 'am start' in c)
    self.assertEqual(
        self._guest_extras(start_cmd),
        {'wifiSsid': 'Home AP', 'wifiPassword': "p@ss word's $1"},
    )

  def test_commission_auto_falls_back_to_ui_when_intent_ignored(self):
    node, executed_cmds = self._intent_node(apk_handles_intent=False)
    res = node.commission_via_chiptool_ui(
        timeout_sec=1.0, intent_ack_timeout_sec=0.2
    )
    self.assertEqual(res.get('status'), 'success')
    self.assertEqual(res.get('trigger'), 'ui')
    starts = [c for c in executed_cmds if 'am start' in c]
    self.assertEqual(len(starts), 2)
    self.assertIn(f'-a {self._INTENT_ACTION}', starts[0])
    self.assertNotIn(' -a ', starts[1])
    self.assertTrue([c for c in executed_cmds if 'uiautomator dump' in c])

  def test_commission_trigger_intent_reports_unacknowledged(self):
    node, executed_cmds = self._intent_node(apk_handles_intent=False)
    res = node.commission_via_chiptool_ui(
        timeout_sec=1.0, trigger='intent', intent_ack_timeout_sec=0.2
    )
    self.assertEqual(res.get('status'), 'failed')
    self.assertEqual(res.get('error'), 'intent_not_acknowledged')
    self.assertEqual(res.get('trigger'), 'intent')
    self.assertIsNone(res.get('commissioned_node_id'))
    self.assertEqual(len([c for c in executed_cmds if 'am start' in c]), 1)
    self.assertFalse([c for c in executed_cmds if 'uiautomator dump' in c])

  def test_commission_rejects_unknown_trigger(self):
    node, _ = self._intent_node(apk_handles_intent=True)
    with self.assertRaises(ValueError):
      node.commission_via_chiptool_ui(trigger='tap')

  def test_toggle_and_read_onoff_via_chiptool_ui(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    xml_cluster = (
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
        '<hierarchy rotation="0">\n'
        '  <node bounds="[0,0][1080,2400]">\n'
        '    <node resource-id="com.google.chip.chiptool:id/onOffClusterBtn"\n'
        '      bounds="[21,884][639,1010]" '
        'text="LIGHT ON/OFF &amp; LEVEL CLUSTER" />\n'
        '    <node resource-id="com.google.chip.chiptool:id/toggleBtn" '
        'bounds="[432,631][643,772]" text="TOGGLE" />\n'
        '    <node resource-id="com.google.chip.chiptool:id/readBtn" '
        'bounds="[21,631][232,772]" text="READ" />\n'
        '  </node>\n'
        '</hierarchy>\n'
    )

    # `logcat -d` dumps the whole buffer, so both the toggle response and
    # the later attribute read appear in one answer. Lines are verbatim
    # CHIPTool OnOffClientFragment output.
    logcat_dump = (
        b'10-15 17:16:31.875  5017  5105 E OnOffClientFragment: onResponse :'
        b' Endpoint 1, cluster 6, command 2, Code : 0\n'
        b'10-15 17:16:34.708  5017  5105 V OnOffClientFragment: On/Off'
        b' attribute value: true\n'
    )

    executed_cmds = []
    first_ui_dump = True

    def fake_exec(cmd, **kwargs):
      nonlocal first_ui_dump
      cmd_str = str(cmd)
      executed_cmds.append(cmd_str)
      if 'cat /data/local/tmp/ui.xml' in cmd_str:
        if first_ui_dump:
          first_ui_dump = False
          return SimpleNamespace(exit_code=0, output=b'<hierarchy></hierarchy>')
        return SimpleNamespace(exit_code=0, output=xml_cluster.encode('utf-8'))
      if 'logcat -d -s OnOffClientFragment' in cmd_str:
        return SimpleNamespace(exit_code=0, output=logcat_dump)
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    toggle_res = node.toggle_onoff_via_chiptool_ui(node_id=1, timeout_sec=1.0)
    self.assertEqual(toggle_res.get('status'), 'success')
    self.assertIn('video_recording', toggle_res)
    self.assertEqual(
        toggle_res['video_recording']['name'], '3_onoff_cluster_toggle.mp4'
    )
    start_cmd = next(c for c in executed_cmds if 'am start' in c)
    self.assertIn('--activity-clear-top', start_cmd)
    self.assertIn('--activity-single-top', start_cmd)

    read_res = node.read_onoff_via_chiptool_ui(node_id=1, timeout_sec=1.0)
    self.assertEqual(read_res.get('status'), 'success')
    self.assertEqual(read_res.get('value'), 'true')
    self.assertIn('video_recording', read_res)
    self.assertEqual(
        read_res['video_recording']['name'], '3_onoff_cluster_read.mp4'
    )

    # Negative check: 'READ' must not match 'Thread' on SelectActionFragment
    from cirque.nodes.androiddockernode import UiAutomatorHelper

    select_action_xml = (
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
        '<hierarchy rotation="0">\n'
        '  <node bounds="[0,0][1080,2400]">\n'
        '    <node resource-id="com.google.chip.chiptool:id/'
        'provisionThreadCredentialsBtn" '
        'bounds="[21,590][749,716]" '
        'text="Provision CHIP device with Thread" />\n'
        '  </node>\n'
        '</hierarchy>\n'
    )
    self.assertIsNone(
        UiAutomatorHelper.get_element_center(
            select_action_xml, resource_id='readBtn', text='READ'
        )
    )
    self.assertIsNone(
        UiAutomatorHelper.get_element_center(select_action_xml, text='READ')
    )

  def test_toggle_rejects_bare_command_or_status_markers(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    xml_cluster = (
        '<hierarchy rotation="0"><node bounds="[0,0][1080,2400]">'
        '<node resource-id="com.google.chip.chiptool:id/onOffClusterBtn" '
        'bounds="[21,884][639,1010]" '
        'text="LIGHT ON/OFF &amp; LEVEL CLUSTER" />'
        '<node resource-id="com.google.chip.chiptool:id/toggleBtn" '
        'bounds="[432,631][643,772]" text="TOGGLE" />'
        '</node></hierarchy>'
    )
    # A failed Toggle and a successful On (command 1) carry the bare
    # 'command 2' / 'Code : 0' substrings the old check accepted.
    logcat_dump = (
        b'E OnOffClientFragment: onResponse : Endpoint 1, cluster 6,'
        b' command 2, Code : 1\n'
        b'E OnOffClientFragment: onResponse : Endpoint 1, cluster 6,'
        b' command 1, Code : 0\n'
    )

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'cat /data/local/tmp/ui.xml' in cmd_str:
        return SimpleNamespace(exit_code=0, output=xml_cluster.encode('utf-8'))
      if 'logcat -d -s OnOffClientFragment' in cmd_str:
        return SimpleNamespace(exit_code=0, output=logcat_dump)
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    toggle_res = node.toggle_onoff_via_chiptool_ui(
        node_id=1, timeout_sec=1.0, record_video=False
    )
    self.assertEqual(toggle_res.get('status'), 'failed')

  def test_dismiss_system_dialogs_closes_app_error_window(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    executed_cmds = []

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      executed_cmds.append(cmd_str)
      if 'dumpsys window windows' in cmd_str:
        return SimpleNamespace(
            exit_code=0,
            output=(
                b'Window{1839a67 u0 Application Error: '
                b'com.google.android.bluetooth}\n'
            ),
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    node.dismiss_system_dialogs()
    self.assertTrue(any('hide_error_dialogs 1' in c for c in executed_cmds))
    self.assertTrue(any('input tap 537 730' in c for c in executed_cmds))

  def test_stop_emulator(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    node.stop_emulator()
    all_cmds = [
        str(call[0][0]) for call in self.mock_container.exec_run.call_args_list
    ]
    self.assertTrue(any('adb emu kill' in c for c in all_cmds))
    self.assertTrue(any('rm -rf /root/.android/avd/' in c for c in all_cmds))
    node.stop()
    self.mock_container.stop.assert_called_once()

  def test_description(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    self.mock_container.id = 'dummy_id'
    self.mock_client.api.inspect_container.return_value = {
        'Config': {},
        'NetworkSettings': {'Networks': {}},
    }
    desc = node.description
    self.assertIn('tap_interface', desc)
    self.assertIn('is_tap_station', desc)
    self.assertIn('radio_feature_flags', desc)

  def test_commission_thread_via_chiptool_ui(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    xml_thread = (
        "<?xml version='1.0' encoding='UTF-8' standalone='yes' ?>\n"
        '<hierarchy rotation="0">\n'
        '  <node bounds="[0,0][1080,2400]">\n'
        '    <node '
        'resource-id="com.google.chip.chiptool:id/'
        'provisionThreadCredentialsBtn" '
        'bounds="[21,443][694,569]"\n'
        '      text="PROVISION CHIP DEVICE WITH THREAD" />\n'
        '    <node resource-id="com.google.chip.chiptool:id/manualCodeBtn" '
        'bounds="[849,2211][1080,2337]" text="MANUAL CODE" />\n'
        '    <node '
        'resource-id="com.google.chip.chiptool:id/manualCodeEditText" '
        'bounds="[42,2211][849,2337]" text="" />\n'
        '    <node resource-id="com.google.chip.chiptool:id/channelEd" '
        'bounds="[42,596][1038,722]" text="15" />\n'
        '    <node resource-id="com.google.chip.chiptool:id/panIdEd" '
        'bounds="[42,750][1038,870]" text="1234" />\n'
        '    <node resource-id="com.google.chip.chiptool:id/xpanIdEd" '
        'bounds="[42,900][1038,1020]" text="11:11:11:11:22:22:22:22" />\n'
        '    <node resource-id="com.google.chip.chiptool:id/masterKeyEd" '
        'bounds="[42,1050][1038,1170]" '
        'text="00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF" />\n'
        '    <node resource-id="com.google.chip.chiptool:id/saveNetworkBtn" '
        'bounds="[679,2160][1038,2295]" text="SAVE NETWORK" />\n'
        '  </node>\n'
        '</hierarchy>\n'
    )

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'cat /data/local/tmp/ui.xml' in cmd_str:
        return SimpleNamespace(exit_code=0, output=xml_thread.encode('utf-8'))
      if 'logcat' in cmd_str:
        if 'Submit Code:' in cmd_str:
          return SimpleNamespace(
              exit_code=0, output=b'Submit Code: 34970112332\n'
          )
        if 'Scanning for BLE device' in cmd_str:
          return SimpleNamespace(
              exit_code=0, output=b'Scanning for BLE device\n'
          )
        if 'onCommissioningComplete' in cmd_str:
          return SimpleNamespace(
              exit_code=0,
              output=b'D CHIP: onCommissioningComplete for nodeId 1: 0\n',
          )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    res = node.commission_thread_via_chiptool_ui(
        channel=15, pan_id='1234', timeout_sec=1.0, trigger='ui'
    )
    self.assertEqual(res.get('status'), 'success')
    self.assertEqual(res.get('commissioned_node_id'), 1)
    self.assertIn('video_recording', res)
    self.assertEqual(
        res['video_recording']['name'], '2_ble_thread_commissioning.mp4'
    )

  def test_commission_thread_via_chiptool_intent_ack(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'logcat' in cmd_str:
        if 'Scanning for BLE device' in cmd_str:
          return SimpleNamespace(
              exit_code=0, output=b'Scanning for BLE device\n'
          )
        if 'onCommissioningComplete' in cmd_str:
          return SimpleNamespace(
              exit_code=0,
              output=b'D CHIP: onCommissioningComplete for nodeId 1: 0\n',
          )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    res = node.commission_thread_via_chiptool_intent(
        channel=15, pan_id='1234', timeout_sec=1.0, ack_timeout_sec=1.0
    )
    self.assertEqual(res.get('status'), 'success')
    self.assertEqual(res.get('trigger'), 'intent')
    self.assertEqual(res.get('commissioned_node_id'), 1)

  def test_commission_thread_via_chiptool_intent_unack(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    def fake_exec(cmd, **kwargs):
      return SimpleNamespace(exit_code=0, output=b'no matching logs\n')

    self.mock_container.exec_run = fake_exec
    res = node.commission_thread_via_chiptool_intent(
        channel=15, pan_id='1234', timeout_sec=0.1, ack_timeout_sec=0.1
    )
    self.assertEqual(res.get('status'), 'failed')
    self.assertEqual(res.get('error'), 'intent_not_acknowledged')
    self.assertEqual(res.get('trigger'), 'intent')

  def test_commission_thread_via_chiptool_ui_auto_trigger(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    node.start_screen_recording = MagicMock(return_value={'started': False})
    node.stop_screen_recording = MagicMock(return_value=None)
    node.dismiss_system_dialogs = MagicMock()
    node.tap_ui_element = MagicMock()
    node.input_text_ui_element = MagicMock()
    node.dump_ui_hierarchy = MagicMock(return_value='manualCodeBtn')

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'logcat' in cmd_str:
        if 'Submit Code:' in cmd_str:
          return SimpleNamespace(
              exit_code=0, output=b'Submit Code: 34970112332\n'
          )
        if 'Scanning for BLE device' in cmd_str:
          return SimpleNamespace(
              exit_code=0, output=b'Scanning for BLE device\n'
          )
        if 'onCommissioningComplete' in cmd_str:
          return SimpleNamespace(
              exit_code=0,
              output=b'D CHIP: onCommissioningComplete for nodeId 1: 0\n',
          )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    with patch.object(
        node,
        'commission_thread_via_chiptool_intent',
        return_value={'status': 'failed', 'error': 'intent_not_acknowledged'},
    ):
      res = node.commission_thread_via_chiptool_ui(
          channel=15, pan_id='1234', timeout_sec=1.0, trigger='auto', record_video=False
      )
      self.assertEqual(res.get('status'), 'success')
      self.assertEqual(res.get('trigger'), 'ui')
      self.assertEqual(res.get('commissioned_node_id'), 1)
      # The 'auto' fallback leaves CHIPTool's defaults alone.
      node.input_text_ui_element.assert_not_called()

  def test_commission_thread_explicit_ui_types_every_dataset_field(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    node.start_screen_recording = MagicMock(return_value={'started': False})
    node.stop_screen_recording = MagicMock(return_value=None)
    node.dismiss_system_dialogs = MagicMock()
    node.tap_ui_element = MagicMock()
    node.input_text_ui_element = MagicMock()
    node.dump_ui_hierarchy = MagicMock(return_value='manualCodeBtn')
    node.commission_thread_via_chiptool_intent = MagicMock()

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      for marker, out in (
          ('Submit Code:', b'Submit Code: 34970112332\n'),
          ('Scanning for BLE device', b'Scanning for BLE device\n'),
          ('onCommissioningComplete',
           b'D CHIP: onCommissioningComplete for nodeId 1: 0\n'),
      ):
        if 'logcat' in cmd_str and marker in cmd_str:
          return SimpleNamespace(exit_code=0, output=out)
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    res = node.commission_thread_via_chiptool_ui(
        channel=15,
        pan_id='1234',
        xpan_id='1111111122222222',
        master_key='00112233445566778899aabbccddeeff',
        timeout_sec=1.0,
        trigger='ui',
        record_video=False,
    )
    self.assertEqual(res.get('trigger'), 'ui')
    node.commission_thread_via_chiptool_intent.assert_not_called()
    typed = {
        c.kwargs['resource_id']: (c.args[0], c.kwargs.get('clear_all'))
        for c in node.input_text_ui_element.call_args_list
    }
    self.assertEqual(
        typed,
        {
            'channelEd': ('15', True),
            'panIdEd': ('1234', True),
            'xpanIdEd': ('11:11:11:11:22:22:22:22', True),
            'masterKeyEd': (
                '00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF',
                True,
            ),
        },
    )

  def test_input_text_clear_all_deletes_prefilled_value(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    node.tap_ui_element = MagicMock(return_value=(1, 2))
    issued = []
    self.mock_container.exec_run = lambda cmd, **kw: issued.append(cmd)
    with patch('time.sleep'):
      node.input_text_ui_element('15', resource_id='channelEd', clear_all=True)
    self.assertEqual(
        issued[0],
        'adb shell input keyevent 93 123 ' + ' '.join(['67'] * 64),
    )
    self.assertEqual(issued[1], 'adb shell input text 15')

  def test_input_text_quotes_shell_metacharacters(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    node.tap_ui_element = MagicMock(return_value=(1, 2))
    issued = []
    self.mock_container.exec_run = lambda cmd, **kw: issued.append(cmd)
    with patch('time.sleep'):
      node.input_text_ui_element("my pa$s;reboot'", resource_id='pwdEd')
    typed_cmds = [c for c in issued if c.startswith('adb shell input text ')]
    self.assertEqual(len(typed_cmds), 1)
    # docker exec splits once on the host; adb hands the rest to the guest sh.
    host_argv = shlex.split(typed_cmds[0])
    self.assertEqual(host_argv[:4], ['adb', 'shell', 'input', 'text'])
    self.assertEqual(len(host_argv), 5)
    self.assertEqual(shlex.split(host_argv[4]), ["my%spa$s;reboot'"])

  def test_input_text_xml_snapshot_reuses_bounds_and_sizes_deletes(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    node.dump_ui_hierarchy = MagicMock()
    xml_snap = (
        '<hierarchy rotation="0"><node bounds="[0,0][1080,2400]">'
        '<node resource-id="com.google.chip.chiptool:id/channelEd" '
        'bounds="[42,596][1038,722]" text="15" />'
        '</node></hierarchy>'
    )
    issued = []
    self.mock_container.exec_run = lambda cmd, **kw: issued.append(cmd)
    with patch('time.sleep'):
      coords = node.input_text_ui_element(
          '15',
          resource_id='channelEd',
          clear_all=True,
          xml_snapshot=xml_snap,
          hide_keyboard=False,
      )
    self.assertEqual(coords, (540, 659))
    node.dump_ui_hierarchy.assert_not_called()
    self.assertEqual(
        issued,
        [
            'adb shell input tap 540 659',
            'adb shell input keyevent 93 123 67 67 67 67',
            'adb shell input text 15',
        ],
    )

  def test_rest_service_commission_thread_chiptool(self):
    from cirque.restservice import service
    test_client = service.app.test_client()

    mock_home = MagicMock()
    mock_node = MagicMock()
    mock_node.commission_thread_via_chiptool_ui.return_value = {
        'status': 'success', 'commissioned_node_id': 1, 'trigger': 'ui'
    }
    mock_node.commission_via_chiptool_ui.return_value = {
        'status': 'success', 'commissioned_node_id': 1, 'trigger': 'ui'
    }
    mock_thread_dev = MagicMock()
    mock_thread_dev.type = 'GenericNode'
    mock_thread_dev.capabilities = [SimpleNamespace(name='Thread')]
    mock_thread_dev.container = MagicMock()

    mock_home.devices = {
        'android_emu': mock_node,
        'matter_dev': mock_thread_dev,
    }
    service.homes['test_home_123'] = mock_home
    try:
      resp = test_client.get(
          '/commission_thread_chiptool/test_home_123/android_emu'
          '?network_type=thread&channel=15&pan_id=1234'
      )
      self.assertEqual(resp.status_code, 200)
      data = resp.get_json()
      self.assertEqual(data.get('status'), 'success')
      self.assertEqual(data.get('commissioned_node_id'), 1)
      self.assertEqual(
          mock_node.commission_thread_via_chiptool_ui.call_args.kwargs.get(
              'trigger'
          ),
          'ui',
      )

      resp_wifi = test_client.get(
          '/commission_thread_chiptool/test_home_123/android_emu?network_type=wifi&ssid=TestSSID&psk=TestPSK'
      )
      self.assertEqual(resp_wifi.status_code, 200)
      self.assertEqual(resp_wifi.get_json().get('status'), 'success')

      mock_home.devices['plain_dev'] = MagicMock(spec=[])
      resp_err = test_client.get(
          '/commission_thread_chiptool/test_home_123/plain_dev?network_type=thread'
      )
      self.assertEqual(resp_err.status_code, 400)
      self.assertEqual(resp_err.get_json().get('status'), 'failed')
    finally:
      service.homes.pop('test_home_123', None)

  def test_default_android_emulator_ble_thread_config(self):
    config = VirtualHomeTopology.default_android_emulator_ble_thread_config()
    self.assertIn('wifi_ap', config)
    self.assertIn('android_emulator', config)
    self.assertIn('matter_device', config)
    self.assertIn('thread_border_router', config)
    tbr_cfg = config['thread_border_router']
    self.assertEqual(tbr_cfg.get('type'), 'ThreadBorderRouter')
    self.assertTrue(tbr_cfg.get('rcp_mode'))
    self.assertTrue(tbr_cfg.get('wifi_auto_connect'))
    self.assertIn('WiFi', tbr_cfg.get('capability', []))
    self.assertIn('Thread', tbr_cfg.get('capability', []))
    matter_cfg = config['matter_device']
    self.assertTrue(matter_cfg.get('rcp_mode'))
    self.assertFalse(matter_cfg.get('wifi_auto_connect', False))
    self.assertIn('Thread', matter_cfg.get('capability', []))
    self.assertNotIn('WiFi', matter_cfg.get('capability', []))
    self.assertIn('Bluetooth', matter_cfg.get('capability', []))
    self.assertEqual(matter_cfg.get('labels', {}).get('owner'), 't10')

  def test_clean_chip_thread_device_state_and_restart(self):
    mock_home = MagicMock()

    def fake_cmd(cmd, device_id, **kwargs):
      cmd_str = str(cmd)
      if 'iptables' in cmd_str:
        return SimpleNamespace(
            exit_code=0,
            output=(
                b'-A OUTPUT -o eth0 -p udp -m udp --dport 5353 -j DROP\n'
                b'-A INPUT -i eth0 -p udp -m udp --dport 5353 -j DROP\n'
            ),
        )
      if 'pidof chip-all-clusters-app' in cmd_str:
        return SimpleNamespace(exit_code=1, output=b'')
      if 'ot-ctl state' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'disabled\n')
      if 'grep -E' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'CHIP:DL: BLE adv start\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    mock_home.execute_device_cmd = fake_cmd
    VirtualHomeTopology.clean_chip_thread_device_state_and_restart(
        cirque_home=mock_home,
        device_id='matter_device',
        timeout_sec=1.0,
    )

  def test_verify_android_emulator_ble_thread_commissioning(self):
    mock_home = MagicMock()
    mock_android = MagicMock()
    mock_android.get_guest_wlan_mac.return_value = '02:15:b2:00:00:00'
    mock_android.get_wifi_station_id.return_value = 'android_emulator'
    mock_android.capabilities = []
    mock_android.commission_thread_via_chiptool_ui.return_value = {
        'status': 'success',
        'commissioned_node_id': 1,
    }
    mock_android.toggle_onoff_via_chiptool_ui.return_value = {
        'status': 'success'
    }
    mock_android.read_onoff_via_chiptool_ui.return_value = {
        'status': 'success',
        'value': 'true',
    }
    mock_home.home = {'devices': {'android_emulator': mock_android}}

    def fake_cmd(cmd, device_id, **kwargs):
      cmd_str = str(cmd)
      if 'iptables' in cmd_str:
        return SimpleNamespace(
            exit_code=0,
            output=(
                b'-A OUTPUT -o eth0 -p udp -m udp --dport 5353 -j DROP\n'
                b'-A INPUT -i eth0 -p udp -m udp --dport 5353 -j DROP\n'
            ),
        )
      if 'pidof chip-all-clusters-app' in cmd_str:
        return SimpleNamespace(exit_code=1, output=b'')
      if 'ot-ctl state' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'leader\n')
      if 'ot-ctl extpanid' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'1111111122222222\n')
      if 'ot-ctl panid' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'0x1234\n')
      if 'ot-ctl channel' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'15\n')
      if 'grep -E' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'CHIP:DL: BLE adv start\n')
      if 'ip -4 addr show dev wlan0' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=b'inet 10.0.1.10/24 brd 10.0.1.255 dev wlan0\n'
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    mock_home.execute_device_cmd = fake_cmd
    res = VirtualHomeTopology.verify_android_emulator_ble_thread_commissioning(
        cirque_home=mock_home,
        controller_id='android_emulator',
        device_id='matter_device',
        timeout_sec=1.0,
        restart_app=True,
    )
    self.assertEqual(res.get('status'), 'success')
    self.assertEqual(res.get('thread_state'), 'leader')
    self.assertEqual(res.get('thread_extpanid'), '1111111122222222')
    self.assertEqual(res.get('thread_panid'), '0x1234')
    self.assertEqual(res.get('thread_channel'), '15')
    self.assertIn('android_hci_frames', res.get('radio_path', {}))
    self.assertIn('bt_controller_bound', res.get('radio_path', {}))

  def test_run_android_emulator(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    node.start_emulator = MagicMock(return_value=True)
    node.install_chiptool = MagicMock(return_value=True)
    node.start_pty_bridge = MagicMock(return_value=True)
    node.setup_guest_wifi = MagicMock(return_value='10.0.1.5')

    res = node.run_android_emulator(timeout_sec=10.0, bt_port=23458)
    self.assertEqual(res.get('status'), 'success')
    self.assertTrue(res.get('booted'))
    self.assertTrue(res.get('bridge_ok'))
    self.assertEqual(res.get('guest_ip'), '10.0.1.5')
    node.start_emulator.assert_called_once_with(timeout_sec=10.0)
    node.install_chiptool.assert_called_once()
    node.start_pty_bridge.assert_called_once_with(
        bt_port=23458, host_ip='10.0.2.2', bind_id='android_hci0'
    )
    node.setup_guest_wifi.assert_called_once_with('wlan0', timeout_sec=20.0)

  def test_run_android_emulator_boot_fail(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    node.start_emulator = MagicMock(return_value=False)

    res = node.run_android_emulator(timeout_sec=5.0)
    self.assertEqual(res.get('status'), 'failed')
    self.assertIn('timeout', res.get('error', ''))

  def test_clean_avd_locks_preserves_vwifi_l2_agent_and_fallback_wifi(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    executed_cmds = []

    def fake_exec(cmd, **kwargs):
      executed_cmds.append(str(cmd))
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    node._clean_avd_locks_and_runtime()
    self.assertTrue(len(executed_cmds) == 1)
    self.assertNotIn('vwifi_l2_agent.py', executed_cmds[0])

    executed_cmds.clear()
    node.start_emulator = MagicMock(return_value=True)
    node.install_chiptool = MagicMock(return_value=True)
    node.start_pty_bridge = MagicMock(return_value=True)
    node.setup_guest_wifi = MagicMock(return_value=None)
    res = node.run_android_emulator(timeout_sec=5.0, bt_port=23458)
    self.assertEqual(res.get('status'), 'success')
    self.assertEqual(res.get('guest_ip'), '10.0.1.5')
    joined = '\n'.join(executed_cmds)
    self.assertIn('cmd wifi connect-network AndroidWifi open', joined)
    self.assertIn('ip -4 addr replace 10.0.1.5/24', joined)
    self.assertIn('table eth0', joined)

  def test_android_ble_wifi_and_thread_topology_configs(self):
    wifi_cfg = VirtualHomeTopology.default_android_emulator_ble_wifi_config(
        ssid='TEST_AP', wifi_psk='test_psk'
    )
    self.assertIn('wifi_ap', wifi_cfg)
    self.assertIn('android_emulator', wifi_cfg)
    self.assertIn('matter_device', wifi_cfg)
    emu_cfg = wifi_cfg['android_emulator']
    self.assertEqual(emu_cfg['type'], 'android_emulator')
    self.assertTrue(emu_cfg['is_tap_station'])
    self.assertEqual(emu_cfg['tap_interface'], 'cirque_tap0')
    self.assertEqual(emu_cfg['preferred_mode'], 'kvm_emulator')
    self.assertIn('Bluetooth', emu_cfg['capability'])
    self.assertIn('WiFi', emu_cfg['capability'])

    thread_cfg = VirtualHomeTopology.default_android_emulator_ble_thread_config(
        ssid='TEST_AP', wifi_psk='test_psk'
    )
    self.assertIn('thread_border_router', thread_cfg)
    tbr_cfg = thread_cfg['thread_border_router']
    self.assertEqual(tbr_cfg.get('type'), 'ThreadBorderRouter')
    self.assertTrue(tbr_cfg.get('rcp_mode'))
    self.assertTrue(tbr_cfg.get('wifi_auto_connect'))
    self.assertIn('WiFi', tbr_cfg.get('capability', []))
    self.assertIn('Thread', tbr_cfg.get('capability', []))
    dev_cfg = thread_cfg['matter_device']
    self.assertTrue(dev_cfg.get('rcp_mode'))
    self.assertFalse(dev_cfg.get('wifi_auto_connect', False))
    self.assertIn('Thread', dev_cfg['capability'])
    self.assertNotIn('WiFi', dev_cfg['capability'])

  def test_validate_virtual_android_home_cli(self):
    help_proc = subprocess.run(
        [_VALIDATE_SCRIPT, '--help'],
        capture_output=True,
        text=True,
        check=False,
    )
    self.assertEqual(help_proc.returncode, 0)
    self.assertIn('Usage:', help_proc.stdout)
    self.assertIn('--negative-psk', help_proc.stdout)
    self.assertIn('--negative-bt', help_proc.stdout)

    bt_proc = subprocess.run(
        [_VALIDATE_SCRIPT, '--negative-bt'],
        capture_output=True,
        text=True,
        check=False,
        env=dict(os.environ, PYTHONPATH=_REPO_ROOT),
    )
    self.assertEqual(bt_proc.returncode, 0)
    self.assertIn(
        'SUCCESS: BT relay enable/disable negative control verified',
        bt_proc.stdout,
    )

    psk_proc = subprocess.run(
        [_VALIDATE_SCRIPT, '--negative-psk'],
        capture_output=True,
        text=True,
        check=False,
        env=dict(os.environ, CIRQUE_DISABLE_CONTAINER_AUTODISCOVERY='1'),
    )
    self.assertNotEqual(psk_proc.returncode, 0)
    self.assertIn(
        'ERROR: IoTEndDevice container required for negative PSK test',
        psk_proc.stderr,
    )

  def test_pcap_generation_and_summarize(self):
    tmp_dir = tempfile.mkdtemp(prefix='cirque_android_unit_')
    try:
      pcap_path = os.path.join(tmp_dir, 'wifi_medium.pcap')
      writer = PcapWriter(pcap_path, dlt=DLT_EN10MB)
      eapol_frame = (
          b'\x02\x00\x00\x00\x01\x01\x02\x15\xb2\x00\x00\x00\x88\x8e'
          b'\x01\x03\x00\x00'
      )
      writer.write_frame(eapol_frame)
      udp5540_frame = (
          b'\x02\x00\x00\x00\x01\x02\x02\x15\xb2\x00\x00\x00\x08\x00'
          b'\x45\x00\x00\x20\x00\x01\x00\x00\x40\x11\x00\x00'
          b'\x0a\x00\x01\x05\x0a\x00\x01\x0a'
          b'\x15\xa4\x15\xa4\x00\x0c\x00\x00'
          b'\x00\x01\x02\x03'
      )
      writer.write_frame(udp5540_frame)
      writer.close()

      summary = summarize_pcap(pcap_path)
      self.assertEqual(summary['records'], 2)
      self.assertEqual(summary['dlt'], 1)
      self.assertIn('EN10MB', summary['dlt_name'])

      proc = subprocess.run(
          [
              'python3',
              '-m',
              'cirque.pcap.summarize_pcap',
              '--dir',
              tmp_dir,
              '--json',
          ],
          capture_output=True,
          text=True,
          check=False,
          env=dict(os.environ, PYTHONPATH=_REPO_ROOT),
      )
      self.assertEqual(proc.returncode, 0)
      self.assertIn('wifi_medium.pcap', proc.stdout)
    finally:
      shutil.rmtree(tmp_dir, ignore_errors=True)

  def test_wait_for_boot_does_not_kill_alive_emulator_on_thread_hang_log(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    exec_calls = []
    boot_checks = 0

    def fake_exec(cmd, **kwargs):
      nonlocal boot_checks
      cmd_str = str(cmd)
      exec_calls.append(cmd_str)
      if 'tail -n 60 /tmp/emulator.log' in cmd_str:
        return SimpleNamespace(
            exit_code=0,
            output=(
                b'WARNING | Unable to connect to packet streamer\n'
                b"ERROR | detected a hanging thread 'QEMU2 CPU0 thread'. "
                b"No response for 19811 ms\n"
                b"ERROR | detected a hanging thread 'QEMU2 CPU1 thread'. "
                b"No response for 19812 ms\n"
            ),
        )
      if 'pgrep -f' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'104\n')
      if 'sys.boot_completed' in cmd_str:
        boot_checks += 1
        if boot_checks >= 2:
          return SimpleNamespace(exit_code=0, output=b'1\n')
        return SimpleNamespace(exit_code=0, output=b'0\n')
      if 'pm path android' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=b'package:/system/framework/framework-res.apk\n'
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    with patch('cirque.nodes.androiddockernode.time.sleep'):
      with self.assertLogs(level='WARNING') as cm:
        booted = node.wait_for_boot(timeout_sec=10.0, max_restarts=2)
    self.assertTrue(booted)
    self.assertFalse(any('emulator -avd' in c for c in exec_calls))
    self.assertTrue(any('pm path android' in c for c in exec_calls))
    hang_warnings = [
        msg
        for msg in cm.output
        if (
            'Emulator hang-detector warning (advisory, emulator still alive)'
            in msg
        )
    ]
    self.assertEqual(len(hang_warnings), 2)

  def test_wait_for_boot_auto_restarts_on_crash(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    exec_calls = []
    launch_count = 0

    def fake_exec(cmd, **kwargs):
      nonlocal launch_count
      cmd_str = str(cmd)
      exec_calls.append(cmd_str)
      if 'emulator -avd' in cmd_str:
        launch_count += 1
        return SimpleNamespace(exit_code=0, output=b'')
      if 'tail -n 60 /tmp/emulator.log' in cmd_str:
        if launch_count < 1:
          return SimpleNamespace(
              exit_code=0,
              output=b"ERROR | detected a hanging thread 'QEMU2 CPU0 thread'\n",
          )
        return SimpleNamespace(exit_code=0, output=b'INFO | Running normally\n')
      if 'pgrep -f' in cmd_str:
        if launch_count < 1:
          return SimpleNamespace(exit_code=1, output=b'')
        return SimpleNamespace(exit_code=0, output=b'200\n')
      if 'sys.boot_completed' in cmd_str:
        if launch_count >= 1:
          return SimpleNamespace(exit_code=0, output=b'1\n')
        return SimpleNamespace(exit_code=0, output=b'0\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    with patch('cirque.nodes.androiddockernode.time.sleep'):
      booted = node.wait_for_boot(timeout_sec=10.0, max_restarts=2)
    self.assertTrue(booted)
    self.assertEqual(launch_count, 1)
    self.assertTrue(any('rm -rf /root/.android/avd/' in c for c in exec_calls))

  def test_wait_for_boot_fails_when_max_restarts_exceeded(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    launch_count = 0

    def fake_exec(cmd, **kwargs):
      nonlocal launch_count
      cmd_str = str(cmd)
      if 'emulator -avd' in cmd_str:
        launch_count += 1
        return SimpleNamespace(exit_code=0, output=b'')
      if 'tail -n 60 /tmp/emulator.log' in cmd_str:
        return SimpleNamespace(
            exit_code=0,
            output=b'ERROR | Segmentation fault (core dumped)\n',
        )
      if 'sys.boot_completed' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'0\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    with patch('cirque.nodes.androiddockernode.time.sleep'):
      booted = node.wait_for_boot(timeout_sec=10.0, max_restarts=2)
    self.assertFalse(booted)
    self.assertEqual(launch_count, 2)

  def test_dockernode_ephemeral_udp_reuseport_guard(self):
    from cirque.nodes.dockernode import DockerNode

    b64_src = DockerNode._build_ephemeral_udp_guard_b64()
    self.assertTrue(len(b64_src) > 100)
    node = DockerNode(self.mock_client, 'test_image')
    node.container = self.mock_container
    self.assertTrue(node._install_ephemeral_udp_reuseport_guard(force=True))
    called_cmd = self.mock_container.exec_run.call_args[0][0]
    self.assertIn('libno_ephemeral_reuseport.so', called_cmd)
    self.assertIn('/etc/ld.so.preload', called_cmd)

  def test_setup_guest_wifi_routes_without_su_root(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    executed_cmds = []

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      executed_cmds.append(cmd_str)
      if 'adb shell id' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'uid=0(root)\n')
      if 'ip addr show' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=b'inet 10.0.1.5/24 brd 10.0.1.255 dev wlan0\n'
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    self.assertEqual(
        node.setup_guest_wifi('wlan0', timeout_sec=1.0), '10.0.1.5'
    )
    self.assertFalse(any('su root' in c for c in executed_cmds))
    self.assertTrue(any('fd11:22::/64' in c for c in executed_cmds))
    self.assertTrue(any('fe80::/64' in c for c in executed_cmds))

  def test_check_emulator_crashed_on_qemu_main_loop_hang(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    pgrep_exit_code = 0

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'tail -n 60 /tmp/emulator.log' in cmd_str:
        return SimpleNamespace(
            exit_code=0,
            output=b"ERROR | detected a hanging thread 'QEMU2 main loop'\n",
        )
      if 'pgrep -f' in cmd_str:
        return SimpleNamespace(exit_code=pgrep_exit_code, output=b'104\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    crashed_alive, _ = node._check_emulator_crashed()
    self.assertFalse(crashed_alive)
    pgrep_exit_code = 1
    crashed_exited, reason = node._check_emulator_crashed()
    self.assertTrue(crashed_exited)
    self.assertIn('QEMU thread hang detected', reason)

  def test_check_emulator_crashed_on_multi_hanging_threads_pgrep_zero(
      self,
  ):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'tail -n 60 /tmp/emulator.log' in cmd_str:
        log_content = (
            b"ERROR | detected a hanging thread 'QEMU2 CPU0 thread'. "
            b"No response for 19811 ms\n"
            b"ERROR | detected a hanging thread 'QEMU2 CPU1 thread'. "
            b"No response for 19812 ms\n"
        )
        return SimpleNamespace(exit_code=0, output=log_content)
      if 'pgrep -f' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'104\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    crashed, reason = node._check_emulator_crashed()
    self.assertFalse(crashed)
    self.assertEqual(reason, '')

  def test_check_emulator_crashed_on_same_thread_hang_pgrep_nonzero(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'tail -n 60 /tmp/emulator.log' in cmd_str:
        log_content = (
            b"ERROR | detected a hanging thread 'QEMU2 CPU0 thread'. "
            b"No response for 19811 ms\n"
            b"ERROR | detected a hanging thread 'QEMU2 CPU0 thread'. "
            b"No response for 15000 ms\n"
        )
        return SimpleNamespace(exit_code=0, output=log_content)
      if 'pgrep -f' in cmd_str:
        return SimpleNamespace(exit_code=1, output=b'')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    crashed, reason = node._check_emulator_crashed()
    self.assertTrue(crashed)
    self.assertEqual(reason, 'QEMU thread hang detected')

  def test_check_emulator_crashed_on_hang_then_crashpad(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'tail -n 60 /tmp/emulator.log' in cmd_str:
        log_content = (
            b"ERROR | detected a hanging thread 'QEMU2 CPU0 thread'. "
            b"No response for 19811 ms\n"
            b"ERROR | detected a hanging thread 'QEMU2 CPU1 thread'. "
            b"No response for 19812 ms\n"
            b'[125:125:20261007,043311.398715:ERROR file_io_posix.cc:145] '
            b'open /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq: '
            b'No such file or directory (2)\n'
        )
        return SimpleNamespace(exit_code=0, output=log_content)
      if 'pgrep -f' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'104\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    crashed, reason = node._check_emulator_crashed()
    self.assertTrue(crashed)
    self.assertEqual(reason, 'Crashpad crash report generated')

  def test_check_emulator_crashed_on_crashpad_file_io_posix(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'tail -n 60 /tmp/emulator.log' in cmd_str:
        log_content = (
            b'[125:125:20261007,043311.398715:ERROR file_io_posix.cc:145] '
            b'open /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq: '
            b'No such file or directory (2)\n'
        )
        return SimpleNamespace(exit_code=0, output=log_content)
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    crashed, reason = node._check_emulator_crashed()
    self.assertTrue(crashed)
    self.assertEqual(reason, 'Crashpad crash report generated')

  def test_check_emulator_crashed_on_chardev_failure_logged_once(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    chardev_log = (
        b'qemu-system-x86_64-headless: Unable to connect character device'
        b' modem: address resolution failed for ::1:44119: Name or service'
        b' not known\n'
    )

    def fake_exec(cmd, **kwargs):
      cmd_str = str(cmd)
      if 'tail -n 60 /tmp/emulator.log' in cmd_str:
        return SimpleNamespace(exit_code=0, output=chardev_log)
      if 'pgrep -f' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'104\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec

    with self.assertLogs(level='ERROR') as cm:
      crashed1, reason1 = node._check_emulator_crashed()
      self.assertFalse(crashed1)
      self.assertEqual(reason1, '')
      self.assertTrue(
          any(
              'emulator chardev connect failed; guest radio/10.0.2.2 path'
              ' will be down:' in msg
              for msg in cm.output
          )
      )
      self.assertEqual(len(node._reported_chardev_lines), 1)

    # Calling a second time should not log the same line again
    with self.assertLogs(level='INFO') as cm2:
      logging.info('sentinel marker')
      crashed2, reason2 = node._check_emulator_crashed()
      self.assertFalse(crashed2)
      self.assertEqual(reason2, '')
      error_logs = [m for m in cm2.output if 'emulator chardev connect' in m]
      self.assertEqual(len(error_logs), 0)

  def test_stop_emulator_uses_sh_c_and_bracket_regex(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    executed_cmds = []

    def fake_exec(cmd, **kwargs):
      executed_cmds.append(str(cmd))
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    node.stop_emulator()
    self.assertTrue(len(executed_cmds) >= 2)
    self.assertTrue(
        any('sh -c' in c and '[q]emu-system' in c for c in executed_cmds)
    )

  def test_stop_emulator_and_clean_avd_locks_when_container_none(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = None
    node.stop_emulator()
    node._clean_avd_locks_and_runtime()

  def test_start_and_stop_screen_recording(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    executed_cmds = []

    def fake_exec(cmd, **kwargs):
      executed_cmds.append(cmd)
      if isinstance(cmd, (list, tuple)) and 'stat -c %s' in str(cmd):
        return SimpleNamespace(exit_code=0, output=b'123456\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    start_res = node.start_screen_recording(
        '1_ble_wifi_commissioning.mp4', bit_rate=4000000, time_limit_sec=120
    )
    self.assertTrue(start_res['started'])
    self.assertEqual(start_res['name'], '1_ble_wifi_commissioning.mp4')
    self.assertEqual(
        start_res['guest_path'], '/sdcard/1_ble_wifi_commissioning.mp4'
    )
    self.assertEqual(
        start_res['container_path'],
        '/tmp/cirque_videos/1_ble_wifi_commissioning.mp4',
    )

    # Stop recording
    stop_res = node.stop_screen_recording()
    self.assertTrue(stop_res['stopped'])
    self.assertEqual(stop_res['name'], '1_ble_wifi_commissioning.mp4')
    self.assertIsNone(node._active_screen_recording)
    self.assertEqual(len(node._recorded_videos), 1)

    # Calling stop again when no recording is active returns no_active_recording
    stop_again = node.stop_screen_recording()
    self.assertFalse(stop_again['stopped'])
    self.assertEqual(stop_again['reason'], 'no_active_recording')

  def test_nested_screen_recording_guard(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    # Outer caller starts continuous recording
    outer_res = node.start_screen_recording('3_onoff_cluster_toggle_read.mp4')
    self.assertTrue(outer_res['started'])
    self.assertEqual(outer_res['name'], '3_onoff_cluster_toggle_read.mp4')

    # Inner caller tries to start recording (e.g. from
    # toggle_onoff_via_chiptool_ui)
    inner_res = node.start_screen_recording('3_onoff_cluster_toggle.mp4')
    self.assertFalse(inner_res['started'])
    self.assertTrue(inner_res['nested'])
    self.assertEqual(inner_res['active'], '3_onoff_cluster_toggle_read.mp4')

    # Active recording remains the outer one
    self.assertEqual(
        node._active_screen_recording['name'], '3_onoff_cluster_toggle_read.mp4'
    )

    # Stop outer recording
    stop_res = node.stop_screen_recording()
    self.assertTrue(stop_res['stopped'])
    self.assertEqual(stop_res['name'], '3_onoff_cluster_toggle_read.mp4')

  def test_list_screen_recordings(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    node._recorded_videos = [{
        'name': 'test1.mp4',
        'container_path': '/tmp/cirque_videos/test1.mp4',
        'guest_path': '/sdcard/test1.mp4',
        'size_bytes': 1000,
        'stopped': True,
    }]

    def fake_exec(cmd, **kwargs):
      if (
          isinstance(cmd, (list, tuple))
          and 'find /tmp/cirque_videos' in str(cmd)
      ):
        return SimpleNamespace(
            exit_code=0, output=b'test1.mp4 1000\ntest2.mp4 2000\n'
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    recs = node.list_screen_recordings()
    rec_names = [r['name'] for r in recs]
    self.assertIn('test1.mp4', rec_names)
    self.assertIn('test2.mp4', rec_names)

  def test_get_screen_recording_bytes(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    # When get_archive raises or is unmocked, base64 fallback is used
    self.mock_container.get_archive.side_effect = Exception('no archive')
    self.mock_container.exec_run.return_value = SimpleNamespace(
        exit_code=0, output=b'AAAA\n'
    )
    data = node.get_screen_recording_bytes('sample.mp4')
    self.assertEqual(data, b'\x00\x00\x00')

  def test_get_screen_recording_bytes_via_tar_archive(self):
    import io
    import tarfile
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode='w') as tar:
      data_content = b'mock_mp4_bytes'
      tarinfo = tarfile.TarInfo(name='sample.mp4')
      tarinfo.size = len(data_content)
      tar.addfile(tarinfo, io.BytesIO(data_content))

    tar_buf.seek(0)
    self.mock_container.get_archive.side_effect = None
    self.mock_container.get_archive.return_value = ([tar_buf.getvalue()], None)
    data = node.get_screen_recording_bytes('sample.mp4')
    self.assertEqual(data, b'mock_mp4_bytes')

  def test_rest_service_screen_recording_endpoints(self):
    from cirque.restservice import service
    test_app = service.app.test_client()

    fake_home = SimpleNamespace(
        home_id='home1',
        devices={
            'dev1': SimpleNamespace(
                start_screen_recording=MagicMock(
                    return_value={
                        'started': True,
                        'name': 'test.mp4',
                        'container_path': '/tmp/cirque_videos/test.mp4',
                    }
                ),
                stop_screen_recording=MagicMock(
                    return_value={
                        'stopped': True,
                        'name': 'test.mp4',
                        'size_bytes': 100,
                    }
                ),
                list_screen_recordings=MagicMock(
                    return_value=[{'name': 'test.mp4', 'size_bytes': 100}]
                ),
                get_screen_recording_bytes=MagicMock(
                    return_value=b'fake_mp4_bytes'
                ),
            )
        },
    )
    service.homes['home1'] = fake_home
    try:
      # start_screen_recording
      res = test_app.get(
          '/start_screen_recording/home1/dev1?name=test.mp4&bit_rate=2000000'
      )
      self.assertEqual(res.status_code, 200)
      self.assertTrue(res.get_json().get('started'))

      # stop_screen_recording
      res = test_app.get('/stop_screen_recording/home1/dev1')
      self.assertEqual(res.status_code, 200)
      self.assertTrue(res.get_json().get('stopped'))

      # list_screen_recordings
      res = test_app.get('/list_screen_recordings/home1/dev1')
      self.assertEqual(res.status_code, 200)
      self.assertEqual(len(res.get_json().get('recordings', [])), 1)

      # get_screen_recording
      res = test_app.get('/get_screen_recording/home1/dev1/test.mp4')
      self.assertEqual(res.status_code, 200)
      self.assertEqual(res.mimetype, 'video/mp4')
      self.assertEqual(res.data, b'fake_mp4_bytes')

      # 404 for unknown home
      res = test_app.get('/list_screen_recordings/unknown_home/dev1')
      self.assertEqual(res.status_code, 404)
    finally:
      service.homes.pop('home1', None)
      service.TaskRunner.stop()

  def test_generic_app_controller_methods(self):
    node = AndroidDockerNode(docker_client=MagicMock())
    mock_container = MagicMock()
    mock_container.exec_run.return_value = SimpleNamespace(exit_code=0, output=b'Success\n')
    node.container = mock_container

    with patch.object(node, 'install_chiptool', return_value=True) as mock_inst:
      with patch.object(node, 'grant_app_runtime_permissions', return_value=True) as mock_grant:
        res = node.install_app_apk('/path/to/app.apk', package_name='com.example.app')
        self.assertTrue(res)
        mock_inst.assert_called_once_with(apk_path='/path/to/app.apk')
        mock_grant.assert_called_once_with('com.example.app')

    # grant_app_runtime_permissions
    self.assertTrue(node.grant_app_runtime_permissions('com.example.app'))
    self.assertTrue(any('pm grant com.example.app' in str(c) for c in mock_container.exec_run.call_args_list))

    # start_app_activity
    self.assertTrue(
        node.start_app_activity(
            activity='com.example.app/.MainActivity',
            extras={'debug': True, 'count': 42, 'msg': 'hello'},
        )
    )
    start_calls = [
        str(c) for c in mock_container.exec_run.call_args_list if 'am start -n com.example.app/.MainActivity' in str(c)
    ]
    self.assertTrue(len(start_calls) > 0)
    self.assertIn('--ez debug true', start_calls[0])
    self.assertIn('--ei count 42', start_calls[0])
    self.assertIn('--es msg "hello"', start_calls[0])

    # commission_device_via_ui
    with patch.object(
        node, 'commission_via_chiptool_ui', return_value={'delegated': 'wifi_ok'}
    ) as mock_comm_wifi:
      res = node.commission_device_via_ui(network_type='wifi', ssid='AP')
      self.assertEqual(res.get('delegated'), 'wifi_ok')
      mock_comm_wifi.assert_called_once_with(ssid='AP')

    with patch.object(
        node,
        'commission_thread_via_chiptool_ui',
        return_value={'delegated': 'thread_ok'},
    ) as mock_comm_thread:
      res = node.commission_device_via_ui(network_type='thread', channel=15)
      self.assertEqual(res.get('delegated'), 'thread_ok')
      mock_comm_thread.assert_called_once_with(channel=15)

    # toggle_cluster_via_ui
    with patch.object(
        node,
        'toggle_onoff_via_chiptool_ui',
        return_value={'delegated': 'toggle_ok'},
    ) as mock_toggle:
      res = node.toggle_cluster_via_ui(node_id=1, endpoint=1)
      self.assertEqual(res.get('delegated'), 'toggle_ok')
      mock_toggle.assert_called_once_with(
          node_id=1, endpoint=1, timeout_sec=30.0
      )

    # read_cluster_via_ui
    with patch.object(
        node,
        'read_onoff_via_chiptool_ui',
        return_value={'delegated': 'read_ok', 'value': '1'},
    ) as mock_read:
      res = node.read_cluster_via_ui(node_id=1, endpoint=1)
      self.assertEqual(res.get('delegated'), 'read_ok')
      mock_read.assert_called_once_with(
          node_id=1, endpoint=1, timeout_sec=30.0
      )

  def test_rest_service_generic_app_endpoints(self):
    from cirque.restservice import service

    mock_node = MagicMock()
    mock_node.commission_via_chiptool_ui.return_value = {
        'delegated': 'comm_ok',
        'phase': 'commissioned',
    }
    mock_node.toggle_onoff_via_chiptool_ui.return_value = {
        'delegated': 'toggle_ok',
    }
    mock_node.read_onoff_via_chiptool_ui.return_value = {
        'delegated': 'read_ok',
        'value': 'true',
    }

    mock_home = MagicMock()
    mock_home.devices = {'dev1': mock_node}
    service.homes['home1'] = mock_home

    test_app = service.app.test_client()
    try:
      # /commission_app/<home_id>/<device_id>
      res = test_app.get('/commission_app/home1/dev1')
      self.assertEqual(res.status_code, 200)
      self.assertEqual(res.get_json().get('delegated'), 'comm_ok')

      # /toggle_app/<home_id>/<device_id>
      res = test_app.get('/toggle_app/home1/dev1')
      self.assertEqual(res.status_code, 200)
      self.assertEqual(res.get_json().get('delegated'), 'toggle_ok')

      # /read_app/<home_id>/<device_id>
      res = test_app.get('/read_app/home1/dev1')
      self.assertEqual(res.status_code, 200)
      self.assertEqual(res.get_json().get('delegated'), 'read_ok')

      # Single-home variants
      res = test_app.get('/commission_app/dev1')
      self.assertEqual(res.status_code, 200)
      self.assertEqual(res.get_json().get('delegated'), 'comm_ok')

      res = test_app.get('/toggle_app/dev1')
      self.assertEqual(res.status_code, 200)
      self.assertEqual(res.get_json().get('delegated'), 'toggle_ok')

      res = test_app.get('/read_app/dev1')
      self.assertEqual(res.status_code, 200)
      self.assertEqual(res.get_json().get('delegated'), 'read_ok')
    finally:
      service.homes.pop('home1', None)
      service.TaskRunner.stop()

  def test_screen_recording_uses_non_edge_swipe(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    executed_cmds = []

    def fake_exec(cmd, **kwargs):
      executed_cmds.append(str(cmd))
      return SimpleNamespace(exit_code=0, output=b'1024\n')

    self.mock_container.exec_run = fake_exec
    node.start_screen_recording('test.mp4')
    node.stop_screen_recording()
    joined = '\n'.join(executed_cmds)
    self.assertIn('input swipe 540 100 541 101 50', joined)
    self.assertNotIn('input swipe 1 1 2 2 50', joined)


  def test_topology_and_android_node_device_base_image_defaults(self):
    """Verifies default base_image is cirque-device-base:latest across topology.
    """
    spec = VirtualHomeNodeSpec(name='node1', device_type='IoTEndDevice')
    self.assertEqual(spec.base_image, 'cirque-device-base:latest')
    cfg = spec.to_device_config()
    self.assertEqual(cfg.get('base_image'), 'cirque-device-base:latest')

    ap_spec = VirtualHomeApSpec()
    self.assertEqual(ap_spec.base_image, 'cirque-device-base:latest')

    home_cfg = VirtualHomeTopology.default_two_node_ble_wifi_config()
    self.assertEqual(
        home_cfg['mobile_controller']['base_image'], 'cirque-device-base:latest'
    )
    self.assertEqual(
        home_cfg['iot_end_device']['base_image'], 'cirque-device-base:latest'
    )

    em_cfg = VirtualHomeTopology.default_android_emulator_ble_wifi_config()
    self.assertEqual(
        em_cfg['matter_device']['base_image'], 'cirque-device-base:latest'
    )

    th_cfg = VirtualHomeTopology.default_android_emulator_ble_thread_config()
    self.assertEqual(
        th_cfg['matter_device']['base_image'], 'cirque-device-base:latest'
    )

  def test_android_node_emulator_switches_device_base_to_android_runner(self):
    """Verifies run() switches base_image to cirque-android-runner:latest."""
    with (
        patch('os.path.exists', return_value=True),
        patch('os.path.isdir', return_value=True),
    ):
      # Case 1: Default base_image 'cirque-device-base:latest'
      node1 = AndroidDockerNode(
          self.mock_client,
          preferred_mode='kvm_emulator',
      )
      self.assertEqual(node1.image_name, 'cirque-device-base:latest')
      node1.run()
      called_image1 = self.mock_client.containers.run.call_args[0][0]
      self.assertEqual(called_image1, 'cirque-android-runner:latest')

      # Case 2: Custom *-device-base image name
      self.mock_client.containers.run.reset_mock()
      node2 = AndroidDockerNode(
          self.mock_client,
          base_image='custom-device-base:v1',
          preferred_mode='kvm_emulator',
      )
      node2.run()
      called_image2 = self.mock_client.containers.run.call_args[0][0]
      self.assertEqual(called_image2, 'cirque-android-runner:latest')

      # Case 3: Explicit runner image remains untouched
      self.mock_client.containers.run.reset_mock()
      node3 = AndroidDockerNode(
          self.mock_client,
          base_image='my-custom-runner:latest',
          preferred_mode='kvm_emulator',
      )
      node3.run()
      called_image3 = self.mock_client.containers.run.call_args[0][0]
      self.assertEqual(called_image3, 'my-custom-runner:latest')

  def test_setup_guest_wifi_disables_captive_portal_mode(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    setup_cmds = []
    ensure_cmds = []
    active_list = setup_cmds

    def fake_exec(cmd, **kwargs):
      del kwargs
      cmd_str = str(cmd)
      active_list.append(cmd_str)
      if 'ip addr show' in cmd_str:
        return SimpleNamespace(
            exit_code=0,
            output=(
                b'3: wlan0: <BROADCAST,MULTICAST> state DOWN\n'
                b'    inet 10.0.1.20/24 dev wlan0\n'
            ),
        )
      if 'cmd wifi status' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=b'Wifi is connected to "AndroidWifi"\n'
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    leased = node.setup_guest_wifi('wlan0', timeout_sec=1.0)
    self.assertEqual(leased, '10.0.1.20')
    joined_setup = '\n'.join(setup_cmds)
    self.assertIn('captive_portal_mode 0', joined_setup)
    self.assertIn('captive_portal_detection_enabled 0', joined_setup)

    active_list = ensure_cmds
    node._ensure_guest_wifi_ready('wlan0')
    joined_ensure = '\n'.join(ensure_cmds)
    self.assertIn('captive_portal_mode 0', joined_ensure)
    self.assertIn('captive_portal_detection_enabled 0', joined_ensure)

  def test_setup_guest_wifi_retries_when_cmd_wifi_disconnected(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    exec_cmds = []
    wifi_polls = [0]

    def fake_exec(cmd, **kwargs):
      del kwargs
      cmd_str = str(cmd)
      exec_cmds.append(cmd_str)
      if 'ip addr show' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=b'inet 10.0.1.20/24 brd 10.0.1.255 dev wlan0\n'
        )
      if 'cmd wifi status' in cmd_str:
        wifi_polls[0] += 1
        if wifi_polls[0] == 1:
          return SimpleNamespace(exit_code=0, output=b'Wifi is disconnected\n')
        return SimpleNamespace(
            exit_code=0, output=b'Wifi is connected to "AndroidWifi"\n'
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    with patch('cirque.nodes.androiddockernode.time.sleep'):
      leased = node.setup_guest_wifi('wlan0', timeout_sec=5.0)
    self.assertEqual(leased, '10.0.1.20')
    self.assertEqual(wifi_polls[0], 2)
    connect_cmds = [
        c for c in exec_cmds if 'cmd wifi connect-network AndroidWifi open' in c
    ]
    self.assertGreaterEqual(len(connect_cmds), 2)

    # Timeout fallback path when cmd wifi status remains disabled.
    fallback_cmds = []

    def fake_exec_disabled(cmd, **kwargs):
      del kwargs
      cmd_str = str(cmd)
      fallback_cmds.append(cmd_str)
      if 'ip addr show' in cmd_str:
        return SimpleNamespace(
            exit_code=0, output=b'inet 10.0.1.21/24 brd 10.0.1.255 dev wlan0\n'
        )
      if 'cmd wifi status' in cmd_str:
        return SimpleNamespace(exit_code=0, output=b'Wifi is disabled\n')
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec_disabled
    with (
        patch('cirque.nodes.androiddockernode.time.time') as mock_time,
        patch('cirque.nodes.androiddockernode.time.sleep'),
    ):
      mock_time.side_effect = [100.0, 100.0, 106.0]
      fallback_ip = node.setup_guest_wifi('wlan0', timeout_sec=5.0)
    self.assertEqual(fallback_ip, '10.0.1.21')
    self.assertTrue(
        any('224.0.0.0/4' in c for c in fallback_cmds),
        'Expected multicast/guest Wi-Fi routes applied for fallback_leased_ip',
    )

  def test_ensure_wifi_network_registered(self):
    node = AndroidDockerNode(self.mock_client)
    node.container = self.mock_container
    exec_cmds = []
    attempt = [0]

    def fake_exec(cmd, **kwargs):
      del kwargs
      cmd_str = str(cmd)
      exec_cmds.append(cmd_str)
      if 'cmd wifi status' in cmd_str:
        attempt[0] += 1
        if attempt[0] == 1:
          return SimpleNamespace(exit_code=0, output=b'Wifi is disconnected\n')
        return SimpleNamespace(
            exit_code=0, output=b'Wifi is connected to "AndroidWifi"\n'
        )
      if 'dumpsys connectivity' in cmd_str:
        if attempt[0] == 1:
          return SimpleNamespace(
              exit_code=0,
              output=(
                  b'Current Networks:\n'
                  b'  NetworkAgentInfo{network{101} ni{MOBILE CONNECTED}}\n'
                  b'Network Connectivity Log:\n'
                  b'  [102 WIFI] going from CONNECTING to CONNECTED\n'
              ),
          )
        return SimpleNamespace(
            exit_code=0,
            output=(
                b'Current Networks:\n'
                b'  NetworkAgentInfo{network{102} ni{WIFI CONNECTED}}\n'
            ),
        )
      if 'ip -4 addr show' in cmd_str or 'ip addr show' in cmd_str:
        if attempt[0] == 1:
          return SimpleNamespace(exit_code=0, output=b'3: wlan0: mtu 1500\n')
        return SimpleNamespace(
            exit_code=0, output=b'inet 10.0.1.20/24 brd 10.0.1.255 dev wlan0\n'
        )
      return SimpleNamespace(exit_code=0, output=b'ok\n')

    self.mock_container.exec_run = fake_exec
    with patch('cirque.nodes.androiddockernode.time.sleep'):
      ok = node.ensure_wifi_network_registered(
          'wlan0', expected_ip='10.0.1.20', timeout_sec=5.0
      )
    self.assertTrue(ok)
    self.assertEqual(attempt[0], 2)
    joined = '\n'.join(exec_cmds)
    self.assertIn('captive_portal_mode 0', joined)
    self.assertIn('cmd wifi connect-network AndroidWifi open', joined)
    self.assertIn('224.0.0.0/4', joined)

    # Verify run_android_emulator invokes ensure_wifi_network_registered.
    node.start_emulator = MagicMock(return_value=True)
    node.install_chiptool = MagicMock(return_value=True)
    node.start_pty_bridge = MagicMock(return_value=True)
    node.setup_guest_wifi = MagicMock(return_value='10.0.1.20')
    node.ensure_wifi_network_registered = MagicMock(return_value=True)
    res = node.run_android_emulator(timeout_sec=5.0, bt_port=23458)
    self.assertEqual(res.get('status'), 'success')
    node.ensure_wifi_network_registered.assert_called_once()


if __name__ == '__main__':
  unittest.main()
