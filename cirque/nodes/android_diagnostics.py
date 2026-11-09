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
"""Diagnostics collection for cirque Android emulator nodes.

Saves bounded logcat, emulator host state and screen recordings of an
Android emulator node (AndroidDockerNode) into DEVICE_LOG_DIR.

`test_instance` is any object with execute_device_cmd(device_id, cmd,
stream=...) and optionally `logger`, `home_id` and
_build_request_url(endpoint, args) for the cirque REST screen-recording
endpoints (stop_screen_recording, list_screen_recordings,
get_screen_recording). Without those, recordings are copied with base64
over execute_device_cmd. The `requests` package is only needed for the
REST path.
"""

import base64
import time
import gzip
import os
from typing import Any, List, Set
try:
  import requests
except ImportError:  # requests is optional
  requests = None

__all__ = [
    'CMD_HOST_STATE',
    'CMD_LOGCAT_BOUNDED',
    'save_android_emulator_diagnostics',
]

# Command to capture bounded logcat output in threadtime format.
CMD_LOGCAT_BOUNDED = 'adb logcat -d -v threadtime -t 20000'

# Command to capture system diagnostic counters and kernel load state.
CMD_HOST_STATE = (
    "sh -c 'cat /proc/loadavg; free -m; nproc; ls -l /dev/kvm'"
)


def _fetch_file_content(
    test_instance: Any, device_id: str, cmd: str
) -> bytes:
  """Executes cmd via stream=True if supported, falling back to JSON output."""
  try:
    resp = test_instance.execute_device_cmd(device_id, cmd, stream=True)
    if hasattr(resp, 'content'):
      return resp.content
    if isinstance(resp, dict):
      output = resp.get('output', '')
      if isinstance(output, str):
        return output.encode('utf-8')
      return bytes(output)
    return str(resp).encode('utf-8')
  except Exception as e:  # pylint: disable=broad-except
    if hasattr(test_instance, 'logger') and test_instance.logger:
      test_instance.logger.warning(
          'Streaming command failed (%s): %s; falling back to non-stream path',
          cmd,
          e,
      )
    try:
      resp = test_instance.execute_device_cmd(device_id, cmd, stream=False)
      if isinstance(resp, dict):
        output = resp.get('output', '')
        if isinstance(output, str):
          return output.encode('utf-8')
        return bytes(output)
      return str(resp).encode('utf-8')
    except Exception as fallback_err:  # pylint: disable=broad-except
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.warning(
            'Non-streaming fallback failed for (%s): %s', cmd, fallback_err
        )
      return b''


def _extract_recording_names(data: Any) -> Set[str]:
  """Extracts basename of .mp4 recording names from list or dict response."""
  names: Set[str] = set()
  items: List[Any] = []
  if isinstance(data, list):
    items = data
  elif isinstance(data, dict):
    recs = (
        data.get('recordings', [])
        or data.get('files', [])
        or data.get('output', [])
    )
    if isinstance(recs, list):
      items = recs
  for item in items:
    if isinstance(item, str) and item.endswith('.mp4'):
      names.add(os.path.basename(item))
    elif isinstance(item, dict) and 'name' in item:
      names.add(os.path.basename(str(item['name'])))
  return names


def _save_android_screen_recordings(
    test_instance: Any, dev_id: str, prefix: str, log_dir: str
) -> None:
  """Discovers and persists recorded MP4 videos from the emulator node."""
  del prefix
  # Stop any active recording so the video container finishes writing moov atom
  if requests is not None and hasattr(
      test_instance, '_build_request_url') and hasattr(
      test_instance, 'home_id'
  ):
    try:
      stop_url = test_instance._build_request_url(
          'stop_screen_recording', [test_instance.home_id, dev_id]
      )
      requests.get(stop_url, timeout=15)
    except Exception as stop_err:  # pylint: disable=broad-except
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.debug(
            'stop_screen_recording endpoint ignored: %s', stop_err
        )

  try:
    test_instance.execute_device_cmd(
        dev_id, "sh -c 'kill -2 $(pidof screenrecord) 2>/dev/null || true'"
    )
  except Exception as kill_err:  # pylint: disable=broad-except
    if hasattr(test_instance, 'logger') and test_instance.logger:
      test_instance.logger.debug(
          'kill -2 screenrecord fallback ignored: %s', kill_err
      )

  discovered_names = set()

  # 1. Query list_screen_recordings REST endpoint
  if requests is not None and hasattr(
      test_instance, '_build_request_url') and hasattr(
      test_instance, 'home_id'
  ):
    try:
      list_url = test_instance._build_request_url(
          'list_screen_recordings', [test_instance.home_id, dev_id]
      )
      resp = requests.get(list_url, timeout=10)
      if resp.status_code == 200:
        discovered_names.update(_extract_recording_names(resp.json()))
    except Exception as list_err:  # pylint: disable=broad-except
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.debug(
            'list_screen_recordings endpoint failed: %s', list_err
        )

  # 2. Check /tmp/cirque_videos/*.mp4 in container
  try:
    ls_res = test_instance.execute_device_cmd(
        dev_id, "sh -c 'ls -1 /tmp/cirque_videos/*.mp4 2>/dev/null || true'"
    )
    if isinstance(ls_res, dict):
      ls_out = ls_res.get('output', '') or ls_res.get('return_value', '')
    else:
      ls_out = str(ls_res)
    if isinstance(ls_out, bytes):
      ls_out = ls_out.decode('utf-8', errors='replace')
    for line in str(ls_out).splitlines():
      candidate = line.strip()
      if candidate.endswith('.mp4'):
        discovered_names.add(os.path.basename(candidate))
  except Exception as ls_err:  # pylint: disable=broad-except
    if hasattr(test_instance, 'logger') and test_instance.logger:
      test_instance.logger.debug(
          'ls -1 /tmp/cirque_videos/*.mp4 command failed: %s', ls_err
      )

  # 3. Pull and persist each discovered recording
  for rec_name in sorted(discovered_names):
    content = b''
    # REST endpoint binary fetch
    if requests is not None and hasattr(
      test_instance, '_build_request_url') and hasattr(
        test_instance, 'home_id'
    ):
      try:
        get_url = test_instance._build_request_url(
            'get_screen_recording', [test_instance.home_id, dev_id, rec_name]
        )
        resp = requests.get(get_url, timeout=30)
        if resp.status_code == 200 and resp.content:
          content = resp.content
      except Exception as get_err:  # pylint: disable=broad-except
        if hasattr(test_instance, 'logger') and test_instance.logger:
          test_instance.logger.debug(
              'get_screen_recording REST fetch failed for %s: %s',
              rec_name,
              get_err,
          )

    # Fallback: base64 shell extraction
    if not content:
      try:
        b64_cmd = (
            "sh -c 'base64 -w 0 /tmp/cirque_videos/"
            f'{rec_name} 2>/dev/null || base64 /tmp/cirque_videos/{rec_name}'
            " 2>/dev/null'"
        )
        b64_res = test_instance.execute_device_cmd(dev_id, b64_cmd)
        if isinstance(b64_res, dict):
          b64_str = (
              b64_res.get('output', '') or b64_res.get('return_value', '')
          )
        else:
          b64_str = str(b64_res)
        if isinstance(b64_str, bytes):
          b64_str = b64_str.decode('utf-8', errors='replace')
        cleaned_b64 = str(b64_str).strip()
        if cleaned_b64:
          content = base64.b64decode(cleaned_b64)
      except Exception as b64_err:  # pylint: disable=broad-except
        if hasattr(test_instance, 'logger') and test_instance.logger:
          test_instance.logger.warning(
              'base64 fallback failed for %s: %s', rec_name, b64_err
          )

    if content:
      canonical_path = os.path.join(log_dir, rec_name)
      try:
        with open(canonical_path, 'wb') as fp:
          fp.write(content)
        if hasattr(test_instance, 'logger') and test_instance.logger:
          test_instance.logger.info(
              'Saved screen recording (%d bytes) to %s',
              len(content),
              canonical_path,
          )
      except Exception as write_err:  # pylint: disable=broad-except
        if hasattr(test_instance, 'logger') and test_instance.logger:
          test_instance.logger.warning(
              'Failed to write screen recording %s: %s', rec_name, write_err
          )


import gzip
import time

def _save_android_coverage_files(
    test_instance: Any, dev_id: str, short_id: str, log_dir: str
) -> None:
  """Discovers and persists LLVM .profraw coverage files from CHIPTool."""
  
  try:
    dump_cmd = (
        "sh -c 'adb shell am broadcast --receiver-foreground -a com.google.chip.chiptool.DUMP_COVERAGE -n com.google.chip.chiptool/com.google.chip.chiptool.CoverageReceiver >/dev/null 2>&1 || true; "
        "adb shell am broadcast --receiver-foreground -a com.matter.casting.DUMP_COVERAGE -n com.chip.casting/com.matter.casting.CoverageReceiver >/dev/null 2>&1 || true; "
        "adb shell am broadcast --receiver-foreground -a com.matter.tv.server.DUMP_COVERAGE -n com.matter.tv.server/com.matter.tv.server.CoverageReceiver >/dev/null 2>&1 || true; "
        "adb shell am broadcast --receiver-foreground -a com.example.contentapp.DUMP_COVERAGE -n com.example.contentapp/com.example.contentapp.CoverageReceiver >/dev/null 2>&1 || true'"
    )
    test_instance.execute_device_cmd(dev_id, dump_cmd)
  except Exception as e:
    if hasattr(test_instance, 'logger') and test_instance.logger:
      test_instance.logger.warning('Failed to send broadcast: %s', e)

  discovered_paths = []
  for _ in range(15):
    try:
      ls_cmd = (
          "sh -c 'rm -rf /tmp/profraw_tmp && mkdir -p /tmp/profraw_tmp && "
          "if adb shell \"run-as com.google.chip.chiptool test -s files/coverage.ec\" >/dev/null 2>&1; then adb exec-out \"run-as com.google.chip.chiptool cat files/coverage.ec 2>/dev/null\" > /tmp/profraw_tmp/chiptool.ec; fi; "
          "if adb shell \"run-as com.google.chip.chiptool test -s files/coverage.profraw\" >/dev/null 2>&1; then adb exec-out \"run-as com.google.chip.chiptool cat files/coverage.profraw 2>/dev/null\" > /tmp/profraw_tmp/chiptool.profraw; fi; "
          "if adb shell \"run-as com.chip.casting test -s files/coverage.ec\" >/dev/null 2>&1; then adb exec-out \"run-as com.chip.casting cat files/coverage.ec 2>/dev/null\" > /tmp/profraw_tmp/casting.ec; fi; "
          "if adb shell \"run-as com.chip.casting test -s files/coverage.profraw\" >/dev/null 2>&1; then adb exec-out \"run-as com.chip.casting cat files/coverage.profraw 2>/dev/null\" > /tmp/profraw_tmp/casting.profraw; fi; "
          "if adb shell \"run-as com.matter.tv.server test -s files/coverage.ec\" >/dev/null 2>&1; then adb exec-out \"run-as com.matter.tv.server cat files/coverage.ec 2>/dev/null\" > /tmp/profraw_tmp/tvserver.ec; fi; "
          "if adb shell \"run-as com.matter.tv.server test -s files/coverage.profraw\" >/dev/null 2>&1; then adb exec-out \"run-as com.matter.tv.server cat files/coverage.profraw 2>/dev/null\" > /tmp/profraw_tmp/tvserver.profraw; fi; "
          "if adb shell \"run-as com.example.contentapp test -s files/coverage.ec\" >/dev/null 2>&1; then adb exec-out \"run-as com.example.contentapp cat files/coverage.ec 2>/dev/null\" > /tmp/profraw_tmp/contentapp.ec; fi; "
          "if adb shell \"run-as com.example.contentapp test -s files/coverage.profraw\" >/dev/null 2>&1; then adb exec-out \"run-as com.example.contentapp cat files/coverage.profraw 2>/dev/null\" > /tmp/profraw_tmp/contentapp.profraw; fi; "
          "find /tmp/profraw_tmp -size 0 -delete 2>/dev/null || true; "
          "find /tmp/profraw_tmp -type f \\( -name \"*.profraw\" -o -name \"*.ec\" \\) 2>/dev/null || true'"
      )
      ls_res = test_instance.execute_device_cmd(dev_id, ls_cmd)
      if isinstance(ls_res, dict):
        ls_out = ls_res.get('output', '') or ls_res.get('return_value', '')
      else:
        ls_out = str(ls_res)
      if isinstance(ls_out, bytes):
        ls_out = ls_out.decode('utf-8', errors='replace')
      current_paths = [
          line.strip()
          for line in str(ls_out).splitlines()
          if line.strip().endswith('.profraw') or line.strip().endswith('.ec')
      ]
      if not current_paths:
        pull_ls_cmd = (
            "sh -c 'rm -rf /tmp/profraw_tmp && mkdir -p /tmp/profraw_tmp && "
            'adb pull /data/user/0/com.google.chip.chiptool/files/ '
            '/tmp/profraw_tmp/ >/dev/null 2>&1; '
            'find /tmp/profraw_tmp -type f -name "*.profraw" '
            "2>/dev/null || true'"
        )
        fb_res = test_instance.execute_device_cmd(dev_id, pull_ls_cmd)
        fb_out = (
            fb_res.get('output', '') or fb_res.get('return_value', '')
            if isinstance(fb_res, dict)
            else str(fb_res)
        )
        if isinstance(fb_out, bytes):
          fb_out = fb_out.decode('utf-8', errors='replace')
        current_paths = [
            line.strip()
            for line in str(fb_out).splitlines()
            if line.strip().endswith('.profraw') or line.strip().endswith('.ec')
        ]
      discovered_paths = current_paths
      if any(p.endswith('.profraw') for p in current_paths):
        break
    except Exception as ls_err:  # pylint: disable=broad-except
      pass
    time.sleep(1)

  if not discovered_paths:
    return

  coverage_path = os.path.join(log_dir, 'profraw')
  os.makedirs(coverage_path, exist_ok=True)
  for remote_path in sorted(discovered_paths):
    try:
      b64_cmd = f"sh -c 'gzip -c {remote_path} 2>/dev/null | base64 -w 0 2>/dev/null'"
      b64_res = test_instance.execute_device_cmd(dev_id, b64_cmd)
      if isinstance(b64_res, dict):
        b64_str = b64_res.get('output', '') or b64_res.get('return_value', '')
      else:
        b64_str = str(b64_res)
      if isinstance(b64_str, bytes):
        b64_str = b64_str.decode('utf-8', errors='replace')
      cleaned_b64 = ''.join(str(b64_str).split())
      if not cleaned_b64:
        fb_b64_cmd = (
            f"sh -c 'base64 -w 0 {remote_path} 2>/dev/null || "
            f"base64 {remote_path} 2>/dev/null'"
        )
        fb_b64_res = test_instance.execute_device_cmd(dev_id, fb_b64_cmd)
        fb_b64_str = (
            fb_b64_res.get('output', '') or fb_b64_res.get('return_value', '')
            if isinstance(fb_b64_res, dict)
            else str(fb_b64_res)
        )
        if isinstance(fb_b64_str, bytes):
          fb_b64_str = fb_b64_str.decode('utf-8', errors='replace')
        cleaned_b64 = ''.join(str(fb_b64_str).split())
      if not cleaned_b64:
        continue
      raw_payload = base64.b64decode(cleaned_b64)
      try:
        content = gzip.decompress(raw_payload)
      except Exception:
        content = raw_payload
      if content:
        prof_name = f"{short_id}-{os.path.basename(remote_path)}"
        dest_path = os.path.join(coverage_path, prof_name)
        with open(dest_path, 'wb') as fp:
          fp.write(content)
        if hasattr(test_instance, 'logger') and test_instance.logger:
          test_instance.logger.info(
              'Saved Android coverage file (%d bytes) to %s',
              len(content),
              dest_path,
          )
    except Exception as err:  # pylint: disable=broad-except
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.warning(
            'Failed to pull coverage file %s: %s', remote_path, err
        )

def save_android_emulator_diagnostics(
    test_instance: Any, timestamp: int
) -> None:
  """Persists emulator diagnostics into DEVICE_LOG_DIR for emulator nodes.

  Saves diagnostic artifacts per android_emulator node:
    - {type}-{timestamp}-{id[:8]}-emulator.log
    - {type}-{timestamp}-{id[:8]}-logcat.log
    - {type}-{timestamp}-{id[:8]}-emulator-state.log
    - {type}-{timestamp}-{id[:8]}-<rec>.mp4 and <rec>.mp4
  """
  log_dir = os.environ.get('DEVICE_LOG_DIR')
  if not log_dir:
    if hasattr(test_instance, 'logger') and test_instance.logger:
      test_instance.logger.warning(
          'DEVICE_LOG_DIR is not set; skipping Android emulator diagnostics'
      )
    return

  if not os.path.exists(log_dir):
    try:
      os.makedirs(log_dir, exist_ok=True)
    except Exception as e:  # pylint: disable=broad-except
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.warning(
            'Failed to create DEVICE_LOG_DIR %s: %s', log_dir, e
        )
      return

  devices = getattr(test_instance, 'non_ap_devices', [])
  for device in devices:
    if device.get('type') != 'android_emulator':
      continue
    dev_id = device.get('id', '')
    dev_type = device.get('type', 'android_emulator')
    short_id = dev_id[:8]
    prefix = f'{dev_type}-{timestamp}-{short_id}'

    # 1. emulator.log: full container emulator log
    emu_file = f'{dev_type}-{timestamp}-{short_id}-emulator.log'
    emu_path = os.path.join(log_dir, emu_file)
    try:
      content = _fetch_file_content(
          test_instance, dev_id, 'cat /tmp/emulator.log'
      )
      with open(emu_path, 'wb') as fp:
        fp.write(content)
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.info(
            'Saved Android emulator log (%d bytes) to %s',
            len(content),
            emu_path,
        )
    except Exception as e:  # pylint: disable=broad-except
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.warning(
            'Failed to save emulator log for %s: %s', short_id, e
        )

    # 5. LLVM coverage files: .profraw
    try:
      _save_android_coverage_files(test_instance, dev_id, short_id, log_dir)
    except Exception as e:  # pylint: disable=broad-except
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.warning(
            'Failed to save coverage files for %s: %s', short_id, e
        )
    # 2. logcat.log: bounded logcat output
    logcat_file = f'{dev_type}-{timestamp}-{short_id}-logcat.log'
    logcat_path = os.path.join(log_dir, logcat_file)
    try:
      content = _fetch_file_content(
          test_instance, dev_id, CMD_LOGCAT_BOUNDED
      )
      with open(logcat_path, 'wb') as fp:
        fp.write(content)
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.info(
            'Saved Android logcat (%d bytes) to %s',
            len(content),
            logcat_path,
        )
    except Exception as e:  # pylint: disable=broad-except
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.warning(
            'Failed to save logcat for %s: %s', short_id, e
        )

    # 3. emulator-state.log: adb devices, system stats, getprop facts
    state_file = f'{dev_type}-{timestamp}-{short_id}-emulator-state.log'
    state_path = os.path.join(log_dir, state_file)
    try:
      state_cmds = [
          'adb devices -l',
          CMD_HOST_STATE,
          'adb shell getprop sys.boot_completed',
          'adb shell getprop init.svc.bootanim',
          'adb shell getprop ro.build.version.release',
      ]
      state_outputs = []
      for cmd in state_cmds:
        try:
          res = test_instance.execute_device_cmd(
              dev_id, cmd, stream=False
          )
          out = (
              res.get('output', '') if isinstance(res, dict) else str(res)
          )
        except Exception as cmd_err:  # pylint: disable=broad-except
          out = f'<command failed: {cmd_err}>\n'
        state_outputs.append(f'=== {cmd} ===\n{out}\n')
      with open(state_path, 'wb') as fp:
        fp.write(''.join(state_outputs).encode('utf-8'))
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.info(
            'Saved Android emulator state to %s', state_path
        )
    except Exception as e:  # pylint: disable=broad-except
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.warning(
            'Failed to save emulator state for %s: %s', short_id, e
        )

    # 4. screen recordings: .mp4 videos
    try:
      _save_android_screen_recordings(test_instance, dev_id, prefix, log_dir)
    except Exception as e:  # pylint: disable=broad-except
      if hasattr(test_instance, 'logger') and test_instance.logger:
        test_instance.logger.warning(
            'Failed to save screen recordings for %s: %s', short_id, e
        )

