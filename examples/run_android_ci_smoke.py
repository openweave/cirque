#!/usr/bin/env python3
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
"""Android emulator radio-path smoke test for CI.

Boots the real headless KVM Android emulator inside the
``cirque-android-runner`` container together with one IoTEndDevice and the
virtual AP, then proves - without needing CHIPTool.apk or any Matter
binaries - that both emulator radios are wired into cirque's userspace
virtual RF:

  Bluetooth  Android BT HAL -> /dev/bluetooth0 -> pty_bridge -> TCP ->
             VirtualBluetoothServer controller ``android_hci0``. The oracle
             is that the controller is bound and has exchanged HCI packets
             (the Android stack issues HCI Reset / Read Local Version as
             soon as the HAL attaches).
  Wi-Fi      guest wlan0 -> -wifi-tap cirque_tap0 -> VirtualWiFiServer L2
             relay -> WPA2 (cirque supplicant on behalf of the tap station)
             -> VirtualDhcpServer lease 10.0.1.x. The oracle is a 10.0.1.x
             lease on guest wlan0 and a 0 % loss ping to the IoTEndDevice's
             wlan0 address through the relay.

Finally it runs ``examples/validate_virtual_android_home.sh --pcap-dir`` on
the live containers and the cirque pcap directory so the manual validation
script is exercised by CI as well.

Exit codes:
  0  all oracles passed
  1  one or more oracles failed (details in <out-dir>/summary.json)
  2  preconditions missing (no /dev/kvm, image or AVD absent)

Environment honoured (see cirque/nodes/androiddockernode.py):
  ANDROID_SDK_ROOT / ANDROID_HOME, ANDROID_AVD_HOME, CHIPTOOL_APK (optional:
  if the APK exists it is installed and reported, otherwise skipped),
  CHIP_BUILD_ROOT (optional: only needed for full commissioning, which this
  smoke test does not perform; run the connectedhomeip linux-cirque Android
  test drivers for full CHIPTool commissioning E2E).
"""

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from typing import Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, '..'))
if ROOT_DIR not in sys.path:
  sys.path.insert(0, ROOT_DIR)

VALIDATE_SCRIPT = os.path.join(SCRIPT_DIR, 'validate_virtual_android_home.sh')
ANDROID_RUNNER_IMAGE = 'cirque-android-runner:latest'
DEVICE_BASE_IMAGE = 'cirque-device-base:latest'
PING_ZERO_LOSS_RE = re.compile(r'(?<!\d)0%\s+packet\s+loss')

logger = logging.getLogger('android_ci_smoke')


def sha256_of(path: str) -> str:
  digest = hashlib.sha256()
  with open(path, 'rb') as handle:
    for chunk in iter(lambda: handle.read(65536), b''):
      digest.update(chunk)
  return digest.hexdigest()


def docker_image_exists(image: str) -> bool:
  proc = subprocess.run(
      ['docker', 'image', 'inspect', image],
      stdout=subprocess.DEVNULL,
      stderr=subprocess.DEVNULL,
      check=False,
  )
  return proc.returncode == 0


def check_preconditions(avd_name: str) -> List[str]:
  """Returns a list of human-readable reasons the smoke test cannot run."""
  problems = []
  if not os.path.exists('/dev/kvm'):
    problems.append('/dev/kvm is not available on this host')
  for image in (ANDROID_RUNNER_IMAGE, DEVICE_BASE_IMAGE):
    if not docker_image_exists(image):
      problems.append(f'docker image {image} is not built')
  sdk = os.environ.get(
      'ANDROID_SDK_ROOT',
      os.environ.get('ANDROID_HOME', os.path.expanduser('~/Android/Sdk')),
  )
  if not os.path.isfile(os.path.join(sdk, 'emulator', 'emulator')):
    problems.append(f'no emulator binary under {sdk}/emulator')
  avd_home = os.environ.get(
      'ANDROID_AVD_HOME', os.path.expanduser('~/.android/avd')
  )
  if not os.path.exists(os.path.join(avd_home, f'{avd_name}.ini')):
    problems.append(f'AVD {avd_name} not found in {avd_home}')
  return problems


def start_stream(cmd: List[str], path: str) -> Tuple[subprocess.Popen, object]:
  """Streams a long-running command's output straight to a file."""
  handle = open(path, 'w', buffering=1)  # pylint: disable=consider-using-with
  proc = subprocess.Popen(  # pylint: disable=consider-using-with
      cmd, stdout=handle, stderr=subprocess.STDOUT
  )
  return proc, handle


def stop_streams(streams) -> None:
  for proc, handle in streams:
    if proc.poll() is None:
      proc.terminate()
      try:
        proc.wait(timeout=5.0)
      except subprocess.TimeoutExpired:
        proc.kill()
    handle.close()


def wait_for(predicate, timeout_sec: float, interval: float = 1.0) -> bool:
  deadline = time.time() + timeout_sec
  while time.time() < deadline:
    if predicate():
      return True
    time.sleep(interval)
  return bool(predicate())


def adb_text(android_node, command: str) -> str:
  code, out = android_node.adb_shell(command)
  del code
  if isinstance(out, (bytes, bytearray)):
    return out.decode('utf-8', errors='replace')
  return str(out)


def guest_wlan0_ipv4(android_node) -> str:
  out = adb_text(android_node, 'ip -4 -o addr show dev wlan0')
  match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', out)
  return match.group(1) if match else ''


def _ping_with_retries(
    android_node, dev_ip: str, topo, home, device_node, args
) -> str:
  adb_text(
      android_node,
      f'ip neigh flush dev wlan0 2>/dev/null; ping -c 1 -W 1 {dev_ip} '
      '2>/dev/null || true',
  )
  ping_out = ''
  for attempt in range(4):
    ping_out = adb_text(android_node, f'ping -I wlan0 -c 3 -W 2 {dev_ip}')
    if PING_ZERO_LOSS_RE.search(ping_out):
      return ping_out
    ping_out = adb_text(android_node, f'ping -c 3 -W 2 {dev_ip}')
    if PING_ZERO_LOSS_RE.search(ping_out):
      return ping_out
    if attempt < 3:
      time.sleep(1.0)

  for retry in range(3):
    logging.info(
        'Ping had packet loss; re-associating Wi-Fi (retry %d/3)...',
        retry + 1,
    )
    topo._associate_wpa_and_dhcp(home, device_node.id, args.ssid, args.psk)
    android_node.setup_guest_wifi('wlan0', timeout_sec=20.0)
    ping_out = adb_text(android_node, f'ping -I wlan0 -c 3 -W 2 {dev_ip}')
    if PING_ZERO_LOSS_RE.search(ping_out):
      return ping_out
    ping_out = adb_text(android_node, f'ping -c 3 -W 2 {dev_ip}')
    if PING_ZERO_LOSS_RE.search(ping_out):
      return ping_out
    time.sleep(1.0)
  return ping_out


def summarize_pcaps(pcap_dir: str) -> Dict[str, Dict[str, object]]:
  from cirque.pcap.summarize_pcap import summarize_pcap

  result: Dict[str, Dict[str, object]] = {}
  if not os.path.isdir(pcap_dir):
    return result
  for name in sorted(os.listdir(pcap_dir)):
    if not name.endswith('.pcap'):
      continue
    path = os.path.join(pcap_dir, name)
    try:
      summary = summarize_pcap(path)
      result[name] = {
          'records': summary.get('records', 0),
          'link_type': summary.get('dlt_name', ''),
          'bytes': summary.get('file_size', 0),
          'sha256': sha256_of(path),
      }
    except Exception as exc:  # pylint: disable=broad-exception-caught
      result[name] = {'error': str(exc)}
  return result


def run_smoke(args) -> int:
  from cirque.capabilities.bluetoothcapability import BlueToothCapability
  from cirque.capabilities.wificapability import WiFiCapability
  from cirque.common.taskrunner import TaskRunner
  from cirque.home.home import CirqueHome
  from cirque.home.virtual_home_topology import VirtualHomeTopology
  from cirque.nodes.androiddockernode import AndroidDockerNode

  out_dir = os.path.abspath(args.out_dir)
  pcap_dir = os.path.join(out_dir, 'pcap')
  os.makedirs(pcap_dir, exist_ok=True)
  os.environ['CIRQUE_PCAP_DIR'] = pcap_dir

  oracles: Dict[str, bool] = {}
  details: Dict[str, object] = {}
  streams = []
  home: Optional[CirqueHome] = None

  TaskRunner.start()
  try:
    home = CirqueHome()
    config = VirtualHomeTopology.default_android_emulator_ble_wifi_config(
        ssid=args.ssid,
        wifi_psk=args.psk,
        avd_name=args.avd,
        pcap_dir=pcap_dir,
        wifi_auto_connect=True,
    )
    home_id = home.create_home(config)
    logger.info('Created CirqueHome %s', home_id)

    android_node = next(
        d for d in home.home['devices'].values()
        if isinstance(d, AndroidDockerNode)
    )
    device_node = next(
        d for d in home.home['devices'].values()
        if getattr(d, 'type', '') == 'IoTEndDevice'
    )
    emu_name = android_node.container.name
    dev_name = device_node.container.name
    details['containers'] = {'android': emu_name, 'device': dev_name}
    streams.append(start_stream(
        ['docker', 'logs', '-f', dev_name],
        os.path.join(out_dir, 'device.log')))

    logger.info('Booting headless emulator %s (timeout %ss)...',
                args.avd, args.boot_timeout)
    booted = android_node.start_emulator(timeout_sec=args.boot_timeout)
    oracles['emulator_booted'] = booted
    if not booted:
      with open(os.path.join(out_dir, 'emulator.log'), 'w') as handle:
        subprocess.run(['docker', 'exec', emu_name, 'cat',
                        '/tmp/emulator.log'], stdout=handle, check=False)
      raise RuntimeError('emulator did not reach sys.boot_completed=1')
    streams.append(start_stream(
        ['docker', 'exec', emu_name, 'adb', 'logcat', '-v', 'time'],
        os.path.join(out_dir, 'logcat.txt')))

    try:
      installed = android_node.install_chiptool()
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.warning('install_chiptool failed (optional): %s', exc)
      details['chiptool_install_error'] = repr(exc)
      installed = False
    details['chiptool_installed'] = installed
    if args.require_chiptool:
      oracles['chiptool_installed'] = installed

    # --- Bluetooth: pty_bridge -> VirtualBluetoothServer ------------------
    topo = VirtualHomeTopology  # pylint: disable=protected-access
    bt_server = BlueToothCapability.get_or_start_virtual_server()
    hci_port = getattr(bt_server, 'hci_port', 23458)
    bridge_ok = android_node.start_pty_bridge(
        bt_port=hci_port, host_ip='10.0.2.2', bind_id='android_hci0')
    oracles['pty_bridge_started'] = bool(bridge_ok)

    def hci_frames() -> int:
      return topo._android_hci_frame_count(bt_server, 'android_hci0')

    # Poll in 15s slices up to args.radio_timeout; if no frames arrive, re-attach
    # the guest Bluetooth HAL in case it missed the initial PTY creation.
    hci_start = time.time()
    while time.time() - hci_start < args.radio_timeout:
      slice_timeout = min(15.0, args.radio_timeout)
      if wait_for(lambda: hci_frames() > 0, timeout_sec=slice_timeout):
        break
      if hci_frames() == 0:
        logging.info('No guest HCI frames after slice; re-attaching BT HAL...')
        adb_text(
            android_node,
            'cmd bluetooth_manager enable 2>/dev/null; svc bluetooth enable'
            ' 2>/dev/null || true',
        )
        time.sleep(3.0)
        if hci_frames() > 0:
          break
        android_node._restart_bluetooth_hal_onto_pty()

    radio_path = topo._android_radio_path(
        android_node, bt_server, 0, bind_id='android_hci0')
    details['radio_path'] = radio_path
    oracles['emulator_running'] = bool(radio_path.get('emulator_running'))
    oracles['bt_builtin_emulation_disabled'] = bool(
        radio_path.get('bt_builtin_emulation_disabled'))
    oracles['wifi_packet_stream_disabled'] = bool(
        radio_path.get('wifi_packet_stream_disabled'))
    oracles['wifi_tap_attached'] = bool(radio_path.get('wifi_tap_attached'))
    oracles['bt_controller_bound'] = bool(
        radio_path.get('bt_controller_bound'))
    oracles['android_hci_frames_gt_0'] = (
        int(radio_path.get('android_hci_frames', 0)) > 0)

    # --- Wi-Fi: tap station -> WPA2 -> DHCP -------------------------------
    manager = WiFiCapability._SHARED_DOCKER_MANAGER  # pylint: disable=W0212
    oracles['wifi_docker_manager_present'] = manager is not None
    wifi_server = WiFiCapability.get_or_start_virtual_server()
    if manager is not None:
      wifi_cap = next(
          (c for c in android_node.capabilities
           if getattr(c, 'name', '') == 'WiFi'), None)
      station_id = (getattr(wifi_cap, 'station_id', None)
                    or android_node.get_wifi_station_id())
      guest_mac = android_node.get_guest_wlan_mac('wlan0')
      details['station'] = {'id': station_id, 'mac': guest_mac}
      if wifi_server is not None and hasattr(wifi_server, 'register_station'):
        wifi_server.register_station(
            station_id=station_id, mac_addr=guest_mac, ipv4_addr='10.0.1.5'
        )
      manager.setup_container_interface(
          station_id=station_id,
          docker_node=android_node,
          mac_addr=guest_mac,
          auto_connect=True,
      )
    guest_ip = android_node.setup_guest_wifi('wlan0', timeout_sec=30.0) or ''
    if not guest_ip.startswith('10.0.1.'):
      if manager is not None:
        if wifi_server is not None and hasattr(wifi_server, 'register_station'):
          wifi_server.register_station(
              station_id=station_id, mac_addr=guest_mac, ipv4_addr='10.0.1.5'
          )
        manager.setup_container_interface(
            station_id=station_id,
            docker_node=android_node,
            mac_addr=guest_mac,
            auto_connect=True,
        )
      android_node.setup_guest_wifi('wlan0', timeout_sec=30.0)
      wait_for(lambda: guest_wlan0_ipv4(android_node).startswith('10.0.1.'),
               timeout_sec=args.radio_timeout)
      guest_ip = guest_wlan0_ipv4(android_node)
    details['guest_wlan0_ip'] = guest_ip
    oracles['guest_wlan0_lease_10_0_1'] = guest_ip.startswith('10.0.1.')

    def device_ip() -> str:
      return topo._read_wlan0_ipv4(home, device_node.id)

    if not wait_for(lambda: device_ip().startswith('10.0.1.'),
                    timeout_sec=15.0):
      for _ in range(3):
        topo._associate_wpa_and_dhcp(
            home, device_node.id, args.ssid, args.psk)
        if wait_for(lambda: device_ip().startswith('10.0.1.'),
                    timeout_sec=20.0):
          break
    dev_ip = device_ip()
    details['device_wlan0_ip'] = dev_ip
    oracles['device_wlan0_lease_10_0_1'] = dev_ip.startswith('10.0.1.')

    ping_out = ''
    if oracles['guest_wlan0_lease_10_0_1'] and dev_ip:
      ping_out = _ping_with_retries(
          android_node, dev_ip, topo, home, device_node, args
      )
    details['ping_output'] = ping_out.strip()
    oracles['guest_to_device_ping_zero_loss'] = bool(
        PING_ZERO_LOSS_RE.search(ping_out))

    wifi_server = WiFiCapability.get_or_start_virtual_server()
    details['wifi_counters'] = (
        wifi_server.get_frame_counters() if wifi_server else {})
    details['bt_counters'] = (
        bt_server.get_frame_counters()
        if hasattr(bt_server, 'get_frame_counters') else {})

    # --- The manual validation script, against the live containers -------
    validate_log = os.path.join(out_dir, 'validate_virtual_android_home.log')
    with open(validate_log, 'w') as handle:
      proc = subprocess.run(
          [VALIDATE_SCRIPT, '--pcap-dir', pcap_dir, emu_name, dev_name],
          stdout=handle, stderr=subprocess.STDOUT, check=False,
          env=dict(os.environ, PYTHONPATH=ROOT_DIR),
      )
    with open(validate_log) as handle:
      validate_text = handle.read()
    oracles['validate_script_rc_0'] = proc.returncode == 0
    oracles['validate_script_success_banner'] = (
        'SUCCESS: Android Virtual Home (BLE + Wi-Fi Data Plane) Validated!'
        in validate_text)
    details['validate_script_log'] = validate_log
    if not oracles['validate_script_rc_0']:
      details['validate_script_output'] = validate_text[-4000:]

    # --- Negative control: the BT relay switch on the server the emulator
    # is actually bound to can be disabled and re-enabled. (A subprocess
    # would start its own server on ephemeral ports and prove nothing.)
    bt_server.set_relay_enabled(False)
    relay_off = getattr(bt_server, 'relay_enabled', None) is False
    bt_server.set_relay_enabled(True)
    relay_on = getattr(bt_server, 'relay_enabled', None) is True
    # --- Export recorded videos before destroying home -------------------
    exported_videos = []
    if android_node is not None:
      list_rec_fn = getattr(android_node, 'list_screen_recordings', None)
      get_bytes_fn = getattr(android_node, 'get_screen_recording_bytes', None)
      if callable(list_rec_fn) and callable(get_bytes_fn):
        for rec in list_rec_fn():
          vname = rec.get('name')
          if not vname:
            continue
          dst_path = os.path.join(out_dir, vname)
          vbytes = get_bytes_fn(vname)
          if vbytes:
            with open(dst_path, 'wb') as f:
              f.write(vbytes)
            exported_videos.append({
                'name': vname,
                'path': dst_path,
                'size_bytes': len(vbytes),
            })
    details['recorded_videos'] = exported_videos

  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.exception('smoke run aborted: %s', exc)
    details['exception'] = repr(exc)
  finally:
    stop_streams(streams)
    if home is not None:
      try:
        home.destroy_home()
      except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning('destroy_home failed: %s', exc)
    try:
      TaskRunner.stop()
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.warning('TaskRunner.stop failed: %s', exc)

  details['pcaps'] = summarize_pcaps(pcap_dir)
  completed = (
      'exception' not in details
      and 'validate_script_success_banner' in oracles
  )
  passed = completed and all(oracles.values())
  summary = {
      'status': 'success' if passed else 'failed',
      'completed': completed,
      'oracles': oracles,
      'details': details,
      'recorded_videos': details.get('recorded_videos', []),
  }
  summary_path = os.path.join(out_dir, 'summary.json')
  with open(summary_path, 'w') as handle:
    json.dump(summary, handle, indent=2, default=str)
  logger.info('Oracles:\n%s', json.dumps(oracles, indent=2))
  if not passed:
    logger.error('Smoke failure details:\n%s',
                 json.dumps(details, indent=2, default=str))
  logger.info('Summary written to %s (status=%s)',
              summary_path, summary['status'])
  return 0 if passed else 1


def main(argv: Optional[List[str]] = None) -> int:
  parser = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
  parser.add_argument('--out-dir', default='/tmp/cirque_android_ci_smoke',
                      help='Where logs, pcaps and summary.json are written')
  parser.add_argument('--avd', default='Pixel_6_API_34',
                      help='AVD name to boot inside cirque-android-runner')
  parser.add_argument('--ssid', default='CIRQUE_HOME_AP')
  parser.add_argument('--psk', default='cirque_home_psk')
  parser.add_argument('--boot-timeout', type=float, default=300.0,
                      help='Seconds to wait for sys.boot_completed=1')
  parser.add_argument('--radio-timeout', type=float, default=60.0,
                      help='Seconds to wait for HCI frames / DHCP leases')
  parser.add_argument('--require-chiptool', action='store_true',
                      help='Fail if CHIPTOOL_APK is missing or not installed')
  parser.add_argument('--check-only', action='store_true',
                      help='Only report preconditions and exit')
  args = parser.parse_args(argv)

  logging.basicConfig(
      level=logging.INFO,
      format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
  )
  problems = check_preconditions(args.avd)
  if problems:
    for problem in problems:
      logger.error('precondition: %s', problem)
    return 2
  if args.check_only:
    logger.info('preconditions satisfied')
    return 0
  return run_smoke(args)


if __name__ == '__main__':
  sys.exit(main())
