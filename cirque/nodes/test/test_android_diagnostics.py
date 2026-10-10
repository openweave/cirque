# Copyright (c) 2026 Project CHIP Authors
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
"""Tests.
"""

import base64
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from cirque.nodes.android_diagnostics import _save_android_screen_recordings
from cirque.nodes.android_diagnostics import save_android_emulator_diagnostics


class FakeHttpResponse:
  """Fake requests response supporting status_code, content, and json()."""

  def __init__(self, status_code=200, content=b'', json_data=None):
    self.status_code = status_code
    self.content = content
    self._json_data = json_data if json_data is not None else {}

  def json(self):
    return self._json_data


class FakeStreamResponse:
  """Fake requests Response object supporting .content bytes."""

  def __init__(self, content: bytes):
    self.content = content


class FakeTestInstance:
  """Fake CHIPTestBase instance providing scripted responses."""

  def __init__(self, non_ap_devices=None, home_id='fake_home_id'):
    self.non_ap_devices = non_ap_devices or []
    self.home_id = home_id
    self.executed_cmds = []
    self.scripted_stream = {}
    self.scripted_json = {}
    self.fail_stream_cmds = set()
    self.fail_all_cmds = set()
    self.logger = None

  def _build_request_url(self, end_point, args=None):
    args = args or []
    arg_part = '/'.join(str(a) for a in args)
    if arg_part:
      return f'http://cirque/{end_point}/{arg_part}'
    return f'http://cirque/{end_point}'

  def execute_device_cmd(self, device_id, cmd, stream=False):
    self.executed_cmds.append((device_id, cmd, stream))
    if cmd in self.fail_all_cmds:
      raise RuntimeError(f'Simulated command failure for {cmd}')
    if stream:
      if cmd in self.fail_stream_cmds:
        raise RuntimeError(f'Simulated stream failure for {cmd}')
      if cmd in self.scripted_stream:
        return FakeStreamResponse(self.scripted_stream[cmd])
      return FakeStreamResponse(b'')
    if cmd in self.scripted_json:
      return {'return_code': 0, 'output': self.scripted_json[cmd]}
    return {'return_code': 0, 'output': ''}


class TestAndroidEmulatorLogs(unittest.TestCase):

  def setUp(self):
    self.test_dir = tempfile.mkdtemp()
    self.original_env = os.environ.get('DEVICE_LOG_DIR')

  def tearDown(self):
    if self.original_env is not None:
      os.environ['DEVICE_LOG_DIR'] = self.original_env
    else:
      os.environ.pop('DEVICE_LOG_DIR', None)
    if os.path.exists(self.test_dir):
      shutil.rmtree(self.test_dir)

  def test_save_android_emulator_diagnostics_success(self):
    os.environ['DEVICE_LOG_DIR'] = self.test_dir
    fake_inst = FakeTestInstance(
        non_ap_devices=[
            {
                'id': '3dc12c79fe62149dc7cd60cbd30f8fdf54e55326',
                'type': 'android_emulator',
            },
            {
                'id': '156343a66d5e02f3e9c3172e185326ce8438f272',
                'type': 'CHIPEndDevice',
            },
        ]
    )
    fake_inst.scripted_stream['cat /tmp/emulator.log'] = (
        b'emu log line 1\nemu log line 2\n'
    )
    fake_inst.scripted_stream['adb logcat -d -v threadtime -t 20000'] = (
        b'01-01 00:00:01.000 1 1 D Test: logcat entry\n'
    )
    fake_inst.scripted_json['adb devices -l'] = (
        'emulator-5554 device product:sdk_gphone64_x86_64\n'
    )
    fake_inst.scripted_json[
        "sh -c 'cat /proc/loadavg; free -m; nproc; ls -l /dev/kvm'"
    ] = '0.50 0.40 0.30 1/100 1234\n'
    fake_inst.scripted_json['adb shell getprop sys.boot_completed'] = '1\n'
    fake_inst.scripted_json['adb shell getprop init.svc.bootanim'] = (
        'stopped\n'
    )
    fake_inst.scripted_json['adb shell getprop ro.build.version.release'] = (
        '14\n'
    )

    timestamp = 1791388126
    save_android_emulator_diagnostics(fake_inst, timestamp)

    short_id = '3dc12c79'
    emu_file = f'android_emulator-{timestamp}-{short_id}-emulator.log'
    logcat_file = f'android_emulator-{timestamp}-{short_id}-logcat.log'
    state_file = f'android_emulator-{timestamp}-{short_id}-emulator-state.log'

    emu_path = os.path.join(self.test_dir, emu_file)
    logcat_path = os.path.join(self.test_dir, logcat_file)
    state_path = os.path.join(self.test_dir, state_file)

    self.assertTrue(os.path.exists(emu_path), f'Missing {emu_path}')
    self.assertTrue(os.path.exists(logcat_path), f'Missing {logcat_path}')
    self.assertTrue(os.path.exists(state_path), f'Missing {state_path}')

    with open(emu_path, 'rb') as fp:
      self.assertEqual(fp.read(), b'emu log line 1\nemu log line 2\n')

    with open(logcat_path, 'rb') as fp:
      self.assertEqual(
          fp.read(), b'01-01 00:00:01.000 1 1 D Test: logcat entry\n'
      )

    with open(state_path, 'rb') as fp:
      state_content = fp.read().decode('utf-8')
      self.assertIn('emulator-5554 device', state_content)
      self.assertIn('sys.boot_completed', state_content)
      self.assertIn('init.svc.bootanim', state_content)
      self.assertIn('ro.build.version.release', state_content)

  def test_streaming_fallback_to_json(self):
    os.environ['DEVICE_LOG_DIR'] = self.test_dir
    fake_inst = FakeTestInstance(
        non_ap_devices=[
            {
                'id': 'abcdef1234567890',
                'type': 'android_emulator',
            }
        ]
    )
    fake_inst.fail_stream_cmds.add('cat /tmp/emulator.log')
    fake_inst.scripted_json['cat /tmp/emulator.log'] = (
        'fallback emu log content'
    )

    timestamp = 1000
    save_android_emulator_diagnostics(fake_inst, timestamp)

    emu_path = os.path.join(
        self.test_dir, 'android_emulator-1000-abcdef12-emulator.log'
    )
    self.assertTrue(os.path.exists(emu_path))
    with open(emu_path, 'rb') as fp:
      self.assertEqual(fp.read(), b'fallback emu log content')

  def test_raising_command_does_not_propagate(self):
    os.environ['DEVICE_LOG_DIR'] = self.test_dir
    fake_inst = FakeTestInstance(
        non_ap_devices=[
            {
                'id': 'deadbeef00000000',
                'type': 'android_emulator',
            }
        ]
    )
    fake_inst.fail_all_cmds.add('cat /tmp/emulator.log')
    fake_inst.fail_all_cmds.add('adb logcat -d -v threadtime -t 20000')

    # Must not raise an exception
    timestamp = 2000
    save_android_emulator_diagnostics(fake_inst, timestamp)

  def test_device_log_dir_unset_path_only_warns(self):
    os.environ.pop('DEVICE_LOG_DIR', None)
    fake_inst = FakeTestInstance(
        non_ap_devices=[
            {
                'id': 'cafebabe11111111',
                'type': 'android_emulator',
            }
        ]
    )
    # Must not raise and must not execute commands
    save_android_emulator_diagnostics(fake_inst, 3000)
    self.assertEqual(fake_inst.executed_cmds, [])

  @patch('requests.get')
  def test_save_android_screen_recordings_http_endpoint(
      self, mock_requests_get
  ):
    fake_inst = FakeTestInstance(
        non_ap_devices=[
            {'id': '1122334455667788', 'type': 'android_emulator'}
        ],
        home_id='test_home_123',
    )
    dev_id = '1122334455667788'
    prefix = 'android_emulator-5000-11223344'
    mp4_bytes = b'\x00\x00\x00\x1cftypisom\x00\x00\x02\x00isomiso2mp41'

    def fake_get(url, **kwargs):
      del kwargs
      if 'stop_screen_recording' in url:
        return FakeHttpResponse(
            200, b'{"status": "stopped"}', {'status': 'stopped'}
        )
      if 'list_screen_recordings' in url:
        return FakeHttpResponse(
            200,
            (
                b'["1_ble_wifi_commissioning.mp4",'
                b' "3_onoff_cluster_toggle_read.mp4"]'
            ),
            [
                '1_ble_wifi_commissioning.mp4',
                '3_onoff_cluster_toggle_read.mp4',
            ],
        )
      if 'get_screen_recording' in url:
        return FakeHttpResponse(200, mp4_bytes)
      return FakeHttpResponse(404, b'')

    mock_requests_get.side_effect = fake_get

    _save_android_screen_recordings(fake_inst, dev_id, prefix, self.test_dir)

    for name in (
        '1_ble_wifi_commissioning.mp4',
        '3_onoff_cluster_toggle_read.mp4',
    ):
      prefixed = os.path.join(self.test_dir, f'{prefix}-{name}')
      canonical = os.path.join(self.test_dir, name)
      self.assertFalse(
          os.path.exists(prefixed), f'Unexpected duplicate {prefixed}'
      )
      self.assertTrue(os.path.exists(canonical), f'Missing {canonical}')
      with open(canonical, 'rb') as fp:
        self.assertEqual(fp.read(), mp4_bytes)

  def test_save_android_screen_recordings_base64_fallback(self):
    fake_inst = FakeTestInstance(
        non_ap_devices=[
            {'id': 'aabbccdd11223344', 'type': 'android_emulator'}
        ]
    )
    dev_id = 'aabbccdd11223344'
    prefix = 'android_emulator-6000-aabbccdd'
    mp4_bytes = b'FAKE_THREAD_COMMISSIONING_VIDEO_BYTES_DATA'
    b64_str = base64.b64encode(mp4_bytes).decode('utf-8')

    fake_inst.scripted_json[
        "sh -c 'ls -1 /tmp/cirque_videos/*.mp4 2>/dev/null || true'"
    ] = '/tmp/cirque_videos/2_ble_thread_commissioning.mp4\n'
    b64_cmd = (
        "sh -c 'base64 -w 0 /tmp/cirque_videos/2_ble_thread_commissioning.mp4"
        " 2>/dev/null || base64"
        " /tmp/cirque_videos/2_ble_thread_commissioning.mp4 2>/dev/null'"
    )
    fake_inst.scripted_json[b64_cmd] = b64_str

    _save_android_screen_recordings(fake_inst, dev_id, prefix, self.test_dir)

    prefixed = os.path.join(
        self.test_dir, f'{prefix}-2_ble_thread_commissioning.mp4'
    )
    canonical = os.path.join(
        self.test_dir, '2_ble_thread_commissioning.mp4'
    )
    self.assertFalse(
        os.path.exists(prefixed), f'Unexpected duplicate {prefixed}'
    )
    self.assertTrue(os.path.exists(canonical), f'Missing {canonical}')
    with open(canonical, 'rb') as fp:
      self.assertEqual(fp.read(), mp4_bytes)

  def test_save_android_emulator_diagnostics_includes_screen_recordings(self):
    os.environ['DEVICE_LOG_DIR'] = self.test_dir
    fake_inst = FakeTestInstance(
        non_ap_devices=[
            {'id': '5566778899aabbcc', 'type': 'android_emulator'}
        ]
    )
    fake_inst.scripted_stream['cat /tmp/emulator.log'] = b'emu log'
    fake_inst.scripted_stream[
        'adb logcat -d -v threadtime -t 20000'
    ] = b'logcat'
    fake_inst.scripted_json[
        "sh -c 'cat /proc/loadavg; free -m; nproc; ls -l /dev/kvm'"
    ] = 'loadavg'
    fake_inst.scripted_json['adb devices -l'] = 'device'
    fake_inst.scripted_json['adb shell getprop sys.boot_completed'] = '1'
    fake_inst.scripted_json['adb shell getprop init.svc.bootanim'] = 'stopped'
    fake_inst.scripted_json['adb shell getprop ro.build.version.release'] = '14'

    mp4_bytes = b'MP4_PAYLOAD_3_TOGGLE_READ'
    fake_inst.scripted_json[
        "sh -c 'ls -1 /tmp/cirque_videos/*.mp4 2>/dev/null || true'"
    ] = '/tmp/cirque_videos/3_onoff_cluster_toggle_read.mp4\n'
    b64_cmd = (
        "sh -c 'base64 -w 0 /tmp/cirque_videos/3_onoff_cluster_toggle_read.mp4"
        " 2>/dev/null || base64"
        " /tmp/cirque_videos/3_onoff_cluster_toggle_read.mp4 2>/dev/null'"
    )
    fake_inst.scripted_json[b64_cmd] = base64.b64encode(mp4_bytes).decode(
        'utf-8'
    )

    timestamp = 7000
    save_android_emulator_diagnostics(fake_inst, timestamp)

    short_id = '55667788'
    prefix = f'android_emulator-{timestamp}-{short_id}'

    self.assertTrue(
        os.path.exists(os.path.join(self.test_dir, f'{prefix}-emulator.log'))
    )
    self.assertTrue(
        os.path.exists(os.path.join(self.test_dir, f'{prefix}-logcat.log'))
    )
    self.assertTrue(
        os.path.exists(
            os.path.join(self.test_dir, f'{prefix}-emulator-state.log')
        )
    )
    prefixed_mp4 = os.path.join(
        self.test_dir, f'{prefix}-3_onoff_cluster_toggle_read.mp4'
    )
    canonical_mp4 = os.path.join(
        self.test_dir, '3_onoff_cluster_toggle_read.mp4'
    )
    self.assertFalse(
        os.path.exists(prefixed_mp4), f'Unexpected duplicate {prefixed_mp4}'
    )
    self.assertTrue(os.path.exists(canonical_mp4), f'Missing {canonical_mp4}')
    with open(canonical_mp4, 'rb') as fp:
      self.assertEqual(fp.read(), mp4_bytes)

  def test_save_android_emulator_diagnostics_pulls_profraw_files(self):
    os.environ['DEVICE_LOG_DIR'] = self.test_dir
    fake_inst = FakeTestInstance(
        non_ap_devices=[{
            'id': '3dc12c79fe62149dc7cd60cbd30f8fdf54e55326',
            'type': 'android_emulator',
        }]
    )
    fake_inst.scripted_stream['cat /tmp/emulator.log'] = b'emu log'
    fake_inst.scripted_stream[
        'adb logcat -d -v threadtime -t 20000'
    ] = b'logcat'
    pull_ls_cmd = (
        "sh -c 'rm -rf /tmp/profraw_tmp && mkdir -p /tmp/profraw_tmp && "
        'adb pull /data/user/0/com.google.chip.chiptool/files/ '
        '/tmp/profraw_tmp/ >/dev/null 2>&1; '
        'find /tmp/profraw_tmp -type f -name "*.profraw" 2>/dev/null || true\''
    )
    remote_profraw = '/tmp/profraw_tmp/files/coverage_4521.profraw'
    fake_inst.scripted_json[pull_ls_cmd] = f'{remote_profraw}\n'
    profraw_bytes = b'\xfflprofr\x81MOCK_CONTINUOUS_PROFRAW_PAYLOAD'
    b64_cmd = (
        f"sh -c 'base64 -w 0 {remote_profraw} 2>/dev/null || "
        f"base64 {remote_profraw} 2>/dev/null'"
    )
    fake_inst.scripted_json[b64_cmd] = base64.b64encode(profraw_bytes).decode(
        'utf-8'
    )

    save_android_emulator_diagnostics(fake_inst, 8000)

    expected_profraw = os.path.join(
        self.test_dir, 'profraw', '3dc12c79-coverage_4521.profraw'
    )
    self.assertTrue(
        os.path.exists(expected_profraw), f'Missing {expected_profraw}'
    )
    with open(expected_profraw, 'rb') as fp:
      self.assertEqual(fp.read(), profraw_bytes)


if __name__ == '__main__':
  unittest.main()
