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
"""Android Docker Node for Headless Android Emulator and Controller.

Architecture & Virtio-Tap Disclosure:
With -wifi-tap, the guest's own in-kernel Wi-Fi/wpa_supplicant associates to
the emulator's internal AP, while the WPA2 association seen by cirque is
performed by cirque's userspace supplicant on behalf of the tap station;
the guest sees cirque's medium as plain Ethernet frames.
"""

import base64
from functools import reduce
import io
import logging
import os
import re
import shlex
import socket
import subprocess
import tarfile
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple, Union
import xml.etree.ElementTree as ET

from cirque.nodes.dockernode import DockerNode

BOOT_POLL_INTERVAL_SEC = 2.0

# Emulator feature switches that keep the emulator's built-in radio
# simulator out of both radio paths. Without BluetoothEmulation nothing on
# the emulator side owns the guest's HCI transport, so cirque can attach it
# through pty_bridge (see start_pty_bridge). Without WiFiPacketStream (on by
# default since emulator 37) guest Wi-Fi stays on the virtio-wifi backend,
# so -wifi-tap is honoured instead of the simulator's user-mode network.
# Earlier revisions pointed -packet-streamer-endpoint at an unused address
# instead; emulator 37.x blocks its main loop while connecting to that
# endpoint, which trips the QEMU hang detector and terminates the emulator
# roughly 40 s after launch.
BT_EMULATION_OFF_FLAG = '-feature -BluetoothEmulation'
WIFI_PACKET_STREAM_OFF_FLAG = '-feature -WiFiPacketStream'
EMULATOR_RADIO_FEATURE_FLAGS = (
    f'{BT_EMULATION_OFF_FLAG} {WIFI_PACKET_STREAM_OFF_FLAG}'
)

# pty_bridge sends `BIND <id>` before it publishes /dev/bluetooth0, so the
# Virtual Bluetooth Server normally has the controller bound by the time the
# symlink is visible. The BIND line still crosses the emulator user-mode
# network, the container TCP-to-Unix relay, and the host Unix-to-TCP proxy;
# poll briefly before concluding that it was lost, then relaunch the bridge
# (a fresh connection, a fresh BIND) instead of failing on the first miss.
PTY_BRIDGE_BIND_TIMEOUT_SEC = 10.0
PTY_BRIDGE_BIND_POLL_SEC = 0.5
PTY_BRIDGE_BIND_ROUNDS = 2

# Explicit intent handled by CHIPToolActivity.onCommissionBleWifiIntent. It
# opens DeviceProvisioningFragment directly with the Wi-Fi credentials, so
# commissioning does not depend on uiautomator taps.
CHIPTOOL_COMMISSION_BLE_WIFI_ACTION = (
    'com.google.chip.chiptool.action.COMMISSION_BLE_WIFI'
)
CHIPTOOL_COMMISSION_BLE_THREAD_ACTION = (
    'com.google.chip.chiptool.action.COMMISSION_BLE_THREAD'
)
# Logged by DeviceProvisioningFragment as soon as BLE discovery starts; it
# is the earliest proof that CHIPTool entered the commissioning flow.
CHIPTOOL_BLE_SCAN_LOG_MARKER = 'Scanning for BLE device'


def _guest_shell_arg(value: str) -> str:
  """Quotes `value` for a guest shell command issued through `adb shell`.

  docker exec splits the command string with shlex and adb joins the
  resulting argv back into one line for the guest shell, so the value is
  quoted once for the guest shell and once more for the host-side split.
  """
  return shlex.quote(shlex.quote(str(value)))


class UiAutomatorHelper:
  """Pure-Python parser for Android uiautomator dump XML hierarchies."""

  @staticmethod
  def parse_bounds(bounds_str: str) -> Optional[Tuple[int, int, int, int]]:
    """Parses '[x1,y1][x2,y2]' into (x1, y1, x2, y2)."""
    match = re.match(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', bounds_str)
    if not match:
      return None
    return tuple(int(x) for x in match.groups())

  @classmethod
  def get_element_bounds(
      cls,
      xml_content: str,
      resource_id: Optional[str] = None,
      text: Optional[str] = None,
      content_desc: Optional[str] = None,
  ) -> Optional[Tuple[int, int, int, int]]:
    """Resolves bounds (x1, y1, x2, y2) from XML by resource-id/text/desc."""
    if not xml_content:
      return None
    try:
      root = ET.fromstring(xml_content)
    except Exception:
      return None

    nodes = list(root.iter('node'))

    if resource_id:
      for node in nodes:
        r_id = node.attrib.get('resource-id', '')
        bounds = node.attrib.get('bounds', '')
        if not bounds:
          continue
        matches_rid = (
            resource_id == r_id
            or r_id.endswith(f':id/{resource_id}')
            or resource_id in r_id
        )
        if matches_rid:
          parsed = cls.parse_bounds(bounds)
          if parsed:
            return parsed

    if text:
      parsed = cls._find_attr_bounds(
          nodes, text, 'text', skip_resource_id=bool(resource_id)
      )
      if parsed:
        return parsed

    if content_desc:
      parsed = cls._find_attr_bounds(
          nodes,
          content_desc,
          'content-desc',
          skip_resource_id=bool(resource_id),
      )
      if parsed:
        return parsed

    return None

  @classmethod
  def _find_attr_bounds(
      cls,
      nodes: List[Any],
      target: str,
      attr_name: str,
      skip_resource_id: bool = False,
  ) -> Optional[Tuple[int, int, int, int]]:
    needle = target.strip().lower()
    word_re = re.compile(rf'(?<!\w){re.escape(needle)}(?!\w)')
    for exact in (True, False):
      for node in nodes:
        if skip_resource_id and node.attrib.get('resource-id', ''):
          continue
        val = node.attrib.get(attr_name, '').strip().lower()
        bounds = node.attrib.get('bounds', '')
        if not bounds or not val:
          continue
        matches = (exact and val == needle) or (
            not exact and bool(word_re.search(val))
        )
        if matches:
          parsed = cls.parse_bounds(bounds)
          if parsed:
            return parsed
    return None

  @classmethod
  def get_element_center(
      cls,
      xml_content: str,
      resource_id: Optional[str] = None,
      text: Optional[str] = None,
      content_desc: Optional[str] = None,
  ) -> Optional[Tuple[int, int]]:
    """Finds the center (x, y) coordinates of an element matching criteria."""
    bounds = cls.get_element_bounds(
        xml_content,
        resource_id=resource_id,
        text=text,
        content_desc=content_desc,
    )
    if bounds is None:
      return None
    x1, y1, x2, y2 = bounds
    return ((x1 + x2) // 2, (y1 + y2) // 2)

  @classmethod
  def get_element_text(
      cls,
      xml_content: str,
      resource_id: Optional[str] = None,
  ) -> Optional[str]:
    """Returns the text attribute of the node matching resource_id, or None."""
    if not xml_content or not resource_id:
      return None
    try:
      root = ET.fromstring(xml_content)
    except Exception:
      return None
    for node in root.iter('node'):
      r_id = node.attrib.get('resource-id', '')
      if (
          resource_id == r_id
          or r_id.endswith(f':id/{resource_id}')
          or resource_id in r_id
      ):
        return node.attrib.get('text', '')
    return None


class AndroidDockerNode(DockerNode):
  """DockerNode specialized for Android emulator and chiptool environments."""

  def __init__(
      self,
      docker_client: object,
      node_type: str = 'android_emulator',
      capabilities: Optional[List[object]] = None,
      base_image: str = 'cirque-device-base:latest',
      avd_name: str = 'Pixel_6_API_34',
      adb_port: int = 5554,
      enable_kvm: bool = True,
      preferred_mode: Optional[str] = None,
      labels: Optional[Dict[str, str]] = None,
      sdk_path: Optional[str] = None,
      avd_path: Optional[str] = None,
      chiptool_apk: Optional[str] = None,
      extra_apks: Optional[list] = None,
      mac_address: Optional[str] = None,
      ipv4_addr: Optional[str] = None,
      tap_interface: str = 'cirque_tap0',
      is_tap_station: bool = True,
      pty_bridge_bin: Optional[str] = None,
      use_real_emulator: bool = True,
  ):
    init_caps = list(capabilities) if capabilities else []
    super().__init__(
        docker_client,
        node_type=node_type,
        capabilities=init_caps,
        base_image=base_image,
        labels=labels,
    )
    self.avd_name = avd_name
    self.adb_port = adb_port
    self.enable_kvm = enable_kvm
    self.preferred_mode = preferred_mode
    self.adb_serial = f'emulator-{adb_port}'
    self.tap_interface = tap_interface
    self.is_tap_station = is_tap_station
    self.mac_address = mac_address
    self.ipv4_addr = ipv4_addr
    self.extra_apks = extra_apks or []
    self.radio_feature_flags = EMULATOR_RADIO_FEATURE_FLAGS
    self.use_real_emulator = use_real_emulator

    self.sdk_path = sdk_path or os.environ.get(
        'ANDROID_SDK_ROOT',
        os.environ.get(
            'ANDROID_HOME', os.path.expanduser('~/Android/Sdk')
        ),
    )
    self.avd_path = avd_path or os.environ.get(
        'ANDROID_AVD_HOME', os.path.expanduser('~/.android/avd')
    )
    repo_chiptool = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..',
            '..',
            '..',
            '..',
            'out',
            'android-x64-chip-tool',
            'outputs',
            'apk',
            'debug',
            'app-debug.apk',
        )
    )
    home_chiptool = os.path.expanduser(
        '~/connectedhomeip/out/android-x64-chip-tool/outputs/apk/debug/'
        'app-debug.apk'
    )
    default_chiptool = (
        repo_chiptool if os.path.exists(repo_chiptool) else home_chiptool
    )
    self.chiptool_apk = chiptool_apk or os.environ.get(
        'CHIPTOOL_APK', default_chiptool
    )
    default_pty_bridge = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__),
            '..',
            'virtual_bt',
            'android',
            'pty_bridge',
        )
    )
    self.pty_bridge_bin = pty_bridge_bin or default_pty_bridge

    self.environment: Dict[str, str] = {
        'ANDROID_SERIAL': self.adb_serial,
        'ANDROID_ADB_PORT': str(adb_port),
        'ANDROID_AVD_NAME': str(avd_name),
        'ANDROID_PREFERRED_MODE': str(preferred_mode or ''),
        'ANDROID_HOME': '/opt/android/sdk',
        'ANDROID_SDK_ROOT': '/opt/android/sdk',
    }
    self.devices: List[str] = []
    if self.enable_kvm and os.path.exists('/dev/kvm'):
      self.devices.append('/dev/kvm:/dev/kvm:rwm')
    if os.path.exists('/dev/net/tun'):
      self.devices.append('/dev/net/tun:/dev/net/tun:rwm')
    self._reported_hang_lines: Set[str] = set()
    self._reported_chardev_lines: Set[str] = set()
    self._active_screen_recording: Optional[Dict[str, object]] = None
    self._recorded_videos: List[Dict[str, object]] = []

  @property
  def runtime_mode(self) -> str:
    """Returns 'kvm_emulator' or 'container_chiptool' based on host env."""
    if self.preferred_mode in ('kvm_emulator', 'container_chiptool'):
      return self.preferred_mode
    if self.enable_kvm and os.path.exists('/dev/kvm'):
      return 'kvm_emulator'
    return 'container_chiptool'

  def get_bluetooth_hci_socket_path(self) -> str:
    """Returns the container-internal HCI bridge Unix domain socket path."""
    return '/dev/virtual_bt/hci_bridge.sock'

  def run(self, **kwargs):
    """Runs the Docker container with Android devices, volumes, and env."""

    def merge_capapblity_arg(arg0, arg1):
      for key, item in arg1.items():
        if key not in arg0:
          arg0[key] = item
          continue
        if isinstance(item, list):
          arg0[key] += item
        elif isinstance(item, dict):
          arg0[key].update(item)
        elif key == 'privileged':
          arg0[key] |= item
      return arg0

    capability_run_args = [
        capability.get_docker_run_args(self) for capability in self.capabilities
    ]
    volumes: List[str] = []
    if self.runtime_mode == 'kvm_emulator' and self.use_real_emulator:
      if os.path.isdir(self.sdk_path):
        volumes.append(f'{self.sdk_path}:/opt/android/sdk:ro')
        if self.sdk_path != '/opt/android/sdk':
          volumes.append(f'{self.sdk_path}:{self.sdk_path}:ro')
      if os.path.isdir(self.avd_path):
        volumes.append(f'{self.avd_path}:/root/.android/avd:rw')
        if self.avd_path != '/root/.android/avd':
          volumes.append(f'{self.avd_path}:{self.avd_path}:rw')
      bt_android_dir = os.path.dirname(self.pty_bridge_bin)
      if os.path.isdir(bt_android_dir):
        volumes.append(f'{bt_android_dir}:/opt/virtual_bt_android:ro')

    initial_args = {
        'privileged': True,
        'cap_add': ['SYS_TIME', 'NET_ADMIN'],
        'environment': dict(self.environment),
        'volumes': volumes,
    }
    if getattr(self, 'labels', None):
      initial_args['labels'] = dict(self.labels)
    if self.devices:
      initial_args['devices'] = list(self.devices)
    capability_run_args = reduce(
        merge_capapblity_arg, capability_run_args, initial_args
    )
    kwargs.update(capability_run_args)

    image_to_use = self.image_name
    if self.runtime_mode == 'kvm_emulator' and self.use_real_emulator:
      if (
          image_to_use
          in (
              'cirque-device-base:latest',
              'cirque-virtual-rf-node:latest',
              'generic_node_image',
          )
          or 'device-base' in image_to_use
      ):
        image_to_use = 'cirque-android-runner:latest'

    self.container = self._client.containers.run(
        image_to_use, detach=True, **kwargs
    )
    self.logger.info(
        'starting container with image %s args=%s', image_to_use, kwargs
    )
    for capability in self.capabilities:
      capability.enable_capability(self)

  def run_android_emulator(
      self,
      timeout_sec: float = 45.0,
      bt_port: Optional[int] = None,
      host_ip: str = '10.0.2.2',
  ) -> Dict[str, object]:
    """Boots emulator, installs CHIPTool, and configures virtual RF."""
    from cirque.capabilities.wificapability import WiFiCapability

    station_id = self.get_wifi_station_id()
    preboot_mac = getattr(self, 'mac_address', None) or '02:15:b2:00:00:00'
    node_ipv4 = getattr(self, 'ipv4_addr', None) or '10.0.1.5'
    if (
        WiFiCapability._SHARED_VIRTUAL_SERVER is not None
        and hasattr(WiFiCapability._SHARED_VIRTUAL_SERVER, 'register_station')
    ):
      WiFiCapability._SHARED_VIRTUAL_SERVER.register_station(
          station_id=station_id,
          mac_addr=preboot_mac,
          ipv4_addr=node_ipv4,
      )
    if (
        WiFiCapability._SHARED_DOCKER_MANAGER is not None
        and isinstance(getattr(self.container, 'id', None), str)
    ):
      WiFiCapability._SHARED_DOCKER_MANAGER.setup_container_interface(
          station_id=station_id,
          docker_node=self,
          mac_addr=preboot_mac,
          auto_connect=True,
      )

    booted = self.start_emulator(timeout_sec=timeout_sec)
    if not booted:
      return {'status': 'failed', 'error': 'emulator boot timeout'}

    try:
      self.install_chiptool()
    except Exception as exc:  # pylint: disable=broad-exception-caught
      # Best effort: a run may only need the extra APKs installed below.
      self.logger.warning('CHIPTool APK installation failed: %s', exc)
    for extra in getattr(self, 'extra_apks', None) or []:
      if isinstance(extra, dict):
        self.install_app_apk(
            apk_path=extra.get('apk_path'),
            package_name=extra.get('package_name', ''),
        )
      elif isinstance(extra, str):
        self.install_app_apk(apk_path=extra, package_name='')

    if bt_port is None:
      from cirque.capabilities.bluetoothcapability import BlueToothCapability
      bt_server = BlueToothCapability.get_or_start_virtual_server()
      bt_port = getattr(bt_server, 'hci_port', 23458) if bt_server else 23458

    bridge_ok = self.start_pty_bridge(
        bt_port=bt_port, host_ip=host_ip, bind_id='android_hci0'
    )
    if not bridge_ok:
      return {'status': 'failed', 'error': 'start_pty_bridge failed'}

    if getattr(self, 'mac_address', None) and self.container is not None:
      self.container.exec_run(
          'adb shell "ip link set dev wlan0 down 2>/dev/null || true; '
          f'ip link set dev wlan0 address {self.mac_address} '
          '2>/dev/null || true; '
          'ip link set dev wlan0 up 2>/dev/null || true"'
      )

    guest_mac = self.get_guest_wlan_mac('wlan0')
    if (
        WiFiCapability._SHARED_VIRTUAL_SERVER is not None
        and hasattr(WiFiCapability._SHARED_VIRTUAL_SERVER, 'register_station')
    ):
      WiFiCapability._SHARED_VIRTUAL_SERVER.register_station(
          station_id=station_id,
          mac_addr=guest_mac,
          ipv4_addr=node_ipv4,
      )

    if (
        WiFiCapability._SHARED_DOCKER_MANAGER is not None
        and isinstance(getattr(self.container, 'id', None), str)
    ):
      WiFiCapability._SHARED_DOCKER_MANAGER.setup_container_interface(
          station_id=station_id,
          docker_node=self,
          mac_addr=guest_mac,
          auto_connect=True,
      )

    guest_ip = self.setup_guest_wifi('wlan0', timeout_sec=20.0)
    if (
        guest_ip is None
        and WiFiCapability._SHARED_DOCKER_MANAGER is not None
        and isinstance(getattr(self.container, 'id', None), str)
    ):
      WiFiCapability._SHARED_DOCKER_MANAGER.setup_container_interface(
          station_id=station_id,
          docker_node=self,
          mac_addr=guest_mac,
          auto_connect=True,
      )
      guest_ip = self.setup_guest_wifi('wlan0', timeout_sec=20.0)

    if guest_ip is None and self.container is not None:
      fallback_ip = node_ipv4
      self.container.exec_run(
          'adb shell "settings put global captive_portal_mode 0 '
          '2>/dev/null || true; '
          'settings put global captive_portal_detection_enabled 0 '
          '2>/dev/null || true; '
          'svc wifi enable 2>/dev/null || true; '
          'cmd wifi set-wifi-enabled enabled 2>/dev/null || true; '
          'cmd wifi connect-network AndroidWifi open 2>/dev/null || true; '
          'ip link set dev wlan0 up 2>/dev/null || true; '
          f'ip -4 addr replace {fallback_ip}/24 brd 10.0.1.255 dev wlan0 '
          '2>/dev/null || true"'
      )
      self._apply_guest_wifi_routes('wlan0', fallback_ip)
      guest_ip = fallback_ip

    target_ip = guest_ip or node_ipv4
    if self.container is not None:
      self.ensure_wifi_network_registered(
          'wlan0', expected_ip=target_ip, timeout_sec=25.0
      )

    return {
        'status': 'success',
        'booted': booted,
        'bridge_ok': bridge_ok,
        'guest_ip': target_ip,
    }

  def setup_tap_device(self, tap_ifname: Optional[str] = None) -> None:
    """Sets up TAP device inside container for emulator virtio-wifi."""
    if self.container is None:
      return
    ifname = tap_ifname or self.tap_interface
    # Keep IPv6 enabled with its fe80 link-local address: QEMU resolves its
    # ::1 chardevs with AI_ADDRCONFIG, and Docker disables IPv6 on eth0 of
    # IPv4-only networks. Silence autoconf/RA to keep the kernel quiet on TAP.
    cmd = (
        f'ip link set dev {ifname} up 2>/dev/null || '
        f'(ip tuntap add dev {ifname} mode tap && ip link set dev {ifname} up);'
        f' ip link set dev {ifname} promisc on 2>/dev/null || true;'
        f' sysctl -w net.ipv6.conf.{ifname}.accept_ra=0'
        f' net.ipv6.conf.{ifname}.autoconf=0'
        f' net.ipv6.conf.{ifname}.router_solicitations=0'
        ' >/dev/null 2>&1 || true;'
        f' ethtool -K {ifname} tx off rx off >/dev/null 2>&1 || true'
    )
    self.container.exec_run(f'sh -c "{cmd}"')

  def _clean_avd_locks_and_runtime(self) -> None:
    """Cleans stale AVD locks and runtime pid state inside container."""
    if self.container is None:
      return
    clean_cmd = (
        'sh -c "'
        'pkill -9 -f '
        "'[q]emu-system|/opt/android/sdk/emulator/[e]mulator' "
        '2>/dev/null || true; '
        f'rm -rf /root/.android/avd/{self.avd_name}.avd/*.lock '
        f'/root/.android/avd/{self.avd_name}.avd/*.lock[0-9]* '
        '/root/.android/avd/running/* /tmp/emulator.log 2>/dev/null || true"'
    )
    self.container.exec_run(clean_cmd)

  def _launch_emulator_process(self) -> None:
    """Launches headless Android emulator background process in container."""
    if self.container is None:
      return
    emu_cmd = (
        'export ANDROID_HOME=/opt/android/sdk '
        'ANDROID_SDK_ROOT=/opt/android/sdk; '
        f'/opt/android/sdk/emulator/emulator -avd {self.avd_name} '
        '-no-window -no-audio -no-boot-anim -gpu swiftshader_indirect '
        '-read-only -no-snapshot '
        f'{self.radio_feature_flags} '
        f'-wifi-tap {self.tap_interface} > /tmp/emulator.log 2>&1 &'
    )
    self._reported_hang_lines.clear()
    self._reported_chardev_lines.clear()
    self.container.exec_run(f'sh -c "{emu_cmd}"', detach=True)

  def _check_emulator_crashed(self) -> Tuple[bool, str]:
    """Inspects container emulator log and process state for early crash.

    Returns:
      (crashed, reason): Boolean flag and description of crash if detected.
    """
    if self.container is None:
      return False, ''
    try:
      log_res = self.container.exec_run('sh -c "tail -n 60 /tmp/emulator.log"')
      log_bytes = getattr(log_res, 'output', b'') or b''
      if isinstance(log_bytes, str):
        log_bytes = log_bytes.encode('utf-8', errors='replace')
      fatal_patterns = [
          (b'Segmentation fault', 'QEMU segmentation fault'),
          (b'Aborted', 'QEMU process aborted'),
          (b'Fatal signal', 'QEMU fatal signal'),
          (b'Crashpad', 'Crashpad crash report generated'),
          (b'file_io_posix.cc', 'Crashpad crash report generated'),
      ]
      for pat, reason in fatal_patterns:
        if pat in log_bytes:
          return True, reason

      if (
          b'Userspace boot properties' in log_bytes
          or b'INFO' in log_bytes
          or b'WARNING' in log_bytes
          or b'ERROR' in log_bytes
      ):
        proc_res = self.container.exec_run(
            'pgrep -f "qemu-system|/opt/android/sdk/emulator/emulator"'
        )
        if proc_res.exit_code != 0:
          if b'detected a hanging thread' in log_bytes:
            return True, 'QEMU thread hang detected'
          return True, 'Emulator process exited unexpectedly'

      if b'detected a hanging thread' in log_bytes:
        lines = log_bytes.decode('utf-8', errors='replace').splitlines()
        for line in lines:
          if (
              'detected a hanging thread' in line
              and line not in self._reported_hang_lines
          ):
            self._reported_hang_lines.add(line)
            logging.warning(
                'Emulator hang-detector warning (advisory, emulator still'
                ' alive): %s',
                line,
            )

      if b'Unable to connect character device' in log_bytes:
        lines = log_bytes.decode('utf-8', errors='replace').splitlines()
        for line in lines:
          if (
              'Unable to connect character device' in line
              and line not in self._reported_chardev_lines
          ):
            self._reported_chardev_lines.add(line)
            logging.error(
                'emulator chardev connect failed; guest radio/10.0.2.2 path'
                ' will be down: %s',
                line,
            )
    except Exception as e:  # pylint: disable=broad-exception-caught
      logging.debug('Error checking emulator crash status: %s', e)
    return False, ''

  def start_emulator(self, timeout_sec: float = 45.0) -> bool:
    """Starts the headless Android emulator in container.

    Note on the radios:
    The emulator runs with EMULATOR_RADIO_FEATURE_FLAGS, which switch its
    built-in radio simulator off for Bluetooth and Wi-Fi. The guest's
    bt_vhci_forwarder is attached to VirtualBluetoothServer later by
    start_pty_bridge, and guest Wi-Fi reaches VirtualWiFiServer through
    the -wifi-tap interface.
    """
    if self.container is None:
      return False
    self.setup_tap_device(self.tap_interface)
    self._clean_avd_locks_and_runtime()
    self._launch_emulator_process()
    return self.wait_for_boot(timeout_sec=timeout_sec)

  def adb_shell(self, command: str, user: str = 'root'):
    """Executes a command inside the Android environment via adb."""
    if self.container is None:
      return 1, 'Container is not running'
    return self.container.exec_run(f'adb shell {command}', user=user)

  def wait_for_boot(
      self,
      timeout_sec: float = 45.0,
      max_restarts: int = 3,
  ) -> bool:
    """Waits for Android emulator boot completion with crash auto-restart."""
    if self.container is None:
      return False
    deadline = time.time() + timeout_sec
    step_sleep = (
        min(BOOT_POLL_INTERVAL_SEC, max(0.05, timeout_sec / 5.0))
        if timeout_sec > 0
        else 0.1
    )
    restarts = 0
    max_restarts = max(max_restarts, int(timeout_sec // 90))
    self._reported_hang_lines.clear()
    self._reported_chardev_lines.clear()
    last_progress_log = time.time()

    while time.time() < deadline:
      try:
        res = self.container.exec_run('adb shell getprop sys.boot_completed')
        if res.exit_code == 0 and b'1' in (res.output or b''):
          self.container.exec_run('adb root')
          time.sleep(0.5)
          self.container.exec_run('timeout 60 adb wait-for-device')
          self.container.exec_run('adb shell setenforce 0')
          pm_deadline = min(deadline, time.time() + 30.0)
          while time.time() < pm_deadline:
            pm_res = self.container.exec_run('adb shell pm path android')
            pm_out = getattr(pm_res, 'output', b'') or b''
            if pm_res.exit_code == 0 and (
                b'package:' in pm_out or b'ok' in pm_out
            ):
              break
            time.sleep(step_sleep)
          self.dismiss_system_dialogs()
          return True
      except Exception as e:  # pylint: disable=broad-exception-caught
        logging.debug('Transient error checking emulator boot status: %s', e)

      crashed, reason = self._check_emulator_crashed()
      if crashed:
        if restarts < max_restarts and time.time() < deadline:
          restarts += 1
          logging.warning(
              'Emulator crashed during boot (%s); auto-restarting '
              '(attempt %d/%d)...',
              reason,
              restarts,
              max_restarts,
          )
          log_dump = self.container.exec_run(
              'sh -c "tail -n 30 /tmp/emulator.log 2>/dev/null"'
          )
          logging.warning(
              'Crashed emulator log tail:\n%s',
              getattr(log_dump, 'output', b'').decode(
                  'utf-8', errors='replace'
              ),
          )
          self._clean_avd_locks_and_runtime()
          self._launch_emulator_process()
          time.sleep(step_sleep)
          continue
        logging.error(
            'Emulator crashed (%s) and exceeded max restarts (%d/%d)',
            reason,
            restarts,
            max_restarts,
        )
        log_final = self.container.exec_run(
            'sh -c "tail -n 120 /tmp/emulator.log 2>/dev/null"'
        )
        devs_final = self.container.exec_run('adb devices -l')
        logging.error(
            'Final failure emulator log tail (120 lines):\n%s\n'
            'adb devices -l:\n%s',
            getattr(log_final, 'output', b'').decode(
                'utf-8', errors='replace'
            ),
            getattr(devs_final, 'output', b'').decode(
                'utf-8', errors='replace'
            ),
        )
        return False

      now = time.time()
      if now - last_progress_log >= 20.0:
        last_progress_log = now
        elapsed_sec = int(timeout_sec - (deadline - now))
        devs_res = self.container.exec_run('adb devices -l')
        devs_str = getattr(devs_res, 'output', b'').decode(
            'utf-8', errors='replace'
        ).strip()
        prop_res = self.container.exec_run(
            'adb shell getprop sys.boot_completed'
        )
        prop_str = getattr(prop_res, 'output', b'').decode(
            'utf-8', errors='replace'
        ).strip()
        logging.info(
            'wait_for_boot progress: elapsed=%ds, serial=%s (%s), '
            'sys.boot_completed=%s, advisory_hangs=%d',
            elapsed_sec,
            self.adb_serial,
            devs_str,
            prop_str,
            len(self._reported_hang_lines),
        )

      time.sleep(step_sleep)

    log_final = self.container.exec_run(
        'sh -c "tail -n 120 /tmp/emulator.log 2>/dev/null"'
    )
    devs_final = self.container.exec_run('adb devices -l')
    logging.error(
        'wait_for_boot timed out after %ds; emulator log tail (120 lines):\n'
        '%s\nadb devices -l:\n%s',
        int(timeout_sec),
        getattr(log_final, 'output', b'').decode('utf-8', errors='replace'),
        getattr(devs_final, 'output', b'').decode('utf-8', errors='replace'),
    )
    return False

  def dismiss_system_dialogs(self) -> None:
    """Suppresses and closes Android system error dialogs and soft keyboard."""
    if self.container is None:
      return
    win_res = self.container.exec_run(
        'adb shell "settings put global hide_error_dialogs 1 2>/dev/null; '
        'settings put secure show_ime_with_hard_keyboard 0 2>/dev/null; '
        'ime disable com.google.android.inputmethod.latin 2>/dev/null; '
        'am broadcast -a android.intent.action.CLOSE_SYSTEM_DIALOGS '
        '2>/dev/null; '
        'cmd input_method hide-soft-input 2>/dev/null; '
        'dumpsys window windows 2>/dev/null || true"'
    )
    win_out = (
        win_res.output.decode('utf-8', errors='replace')
        if isinstance(win_res.output, (bytes, bytearray))
        else str(win_res.output or '')
    )
    if 'Application Error:' in win_out or 'Not Responding:' in win_out:
      self.container.exec_run('adb shell input tap 537 730')
      time.sleep(0.3)

  def install_chiptool(self, apk_path: Optional[str] = None) -> bool:
    """Installs CHIPTool APK into guest Android via adb."""
    if self.container is None:
      return False
    apk = apk_path or self.chiptool_apk
    if not apk or not os.path.exists(apk):
      return False
    # If APK is accessible from container volume, install directly; else copy
    target_apk = None
    candidates = [apk]
    if '/connectedhomeip/out' in apk:
      idx = apk.find('/connectedhomeip/out')
      candidates.append(apk[idx:])
      candidates.append(
          '/chip-vbt/out' + apk[idx + len('/connectedhomeip/out') :]
      )
    for cand in candidates:
      if self.container.exec_run(f'test -f {cand}').exit_code == 0:
        target_apk = cand
        break

    if target_apk is None:
      apk_basename = os.path.basename(apk) or 'CHIPTool.apk'
      target_apk = f'/tmp/{apk_basename}'
      container_id = getattr(self.container, 'id', None)
      cp_success = False
      if container_id:
        cp_res = subprocess.run(
            ['docker', 'cp', apk, f'{container_id}:{target_apk}'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if cp_res.returncode == 0:
          cp_success = True
      if not cp_success:
        with open(apk, 'rb') as f:
          data = f.read()
        import io
        import tarfile

        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode='w') as tar:
          tarinfo = tarfile.TarInfo(name=apk_basename)
          tarinfo.size = len(data)
          tar.addfile(tarinfo, io.BytesIO(data))
        tar_stream.seek(0)
        self.container.put_archive('/tmp', tar_stream)

    success = False
    for attempt in range(3):
      res = self.container.exec_run(f'adb install -r -g {target_apk}')
      out_bytes = getattr(res, 'output', b'') or b''
      if isinstance(out_bytes, str):
        out_bytes = out_bytes.encode('utf-8', errors='replace')
      success = res.exit_code == 0 and (
          b'Success' in out_bytes or b'success' in out_bytes
      )
      if success:
        break
      if attempt < 2:
        self.container.exec_run('timeout 60 adb wait-for-device')
        time.sleep(1.0)
    if success:
      perms = [
          'android.permission.ACCESS_FINE_LOCATION',
          'android.permission.ACCESS_COARSE_LOCATION',
          'android.permission.BLUETOOTH_SCAN',
          'android.permission.BLUETOOTH_CONNECT',
          'android.permission.BLUETOOTH_ADVERTISE',
          'android.permission.CAMERA',
      ]
      for p in perms:
        self.container.exec_run(
            f'adb shell pm grant com.google.chip.chiptool {p}'
        )
    return success

  def install_app_apk(
      self,
      apk_path: Optional[str] = None,
      package_name: str = 'com.google.chip.chiptool',
  ) -> bool:
    """Installs an application APK into guest Android via adb."""
    success = self.install_chiptool(apk_path=apk_path)
    if success and package_name and package_name != 'com.google.chip.chiptool':
      self.grant_app_runtime_permissions(package_name)
    return success

  def grant_app_runtime_permissions(
      self,
      package_name: str = 'com.google.chip.chiptool',
      permissions: Optional[List[str]] = None,
  ) -> bool:
    """Grants runtime permissions to the specified package."""
    if self.container is None:
      return False
    perms = permissions or [
        'android.permission.ACCESS_FINE_LOCATION',
        'android.permission.ACCESS_COARSE_LOCATION',
        'android.permission.BLUETOOTH_SCAN',
        'android.permission.BLUETOOTH_CONNECT',
        'android.permission.BLUETOOTH_ADVERTISE',
        'android.permission.CAMERA',
    ]
    for p in perms:
      self.container.exec_run(f'adb shell pm grant {package_name} {p}')
    return True

  def start_app_activity(
      self,
      activity: str = 'com.google.chip.chiptool/.SelectActionActivity',
      extras: Optional[Dict[str, Any]] = None,
  ) -> bool:
    """Starts an Android Activity via adb shell am start."""
    if self.container is None:
      return False
    cmd = f'adb shell am start -n {activity}'
    if extras:
      for k, v in extras.items():
        if isinstance(v, bool):
          cmd += f' --ez {k} {str(v).lower()}'
        elif isinstance(v, int):
          cmd += f' --ei {k} {v}'
        else:
          cmd += f' --es {k} "{v}"'
    res = self.container.exec_run(cmd)
    return getattr(res, 'exit_code', 1) == 0

  def _adb_text(self, cmd: str) -> str:
    """Runs cmd in the runner container and returns stripped stdout text."""
    if self.container is None:
      return ''
    res = self.container.exec_run(cmd)
    out = getattr(res, 'output', None)
    if not out:
      return ''
    if isinstance(out, (bytes, bytearray)):
      return out.decode('utf-8', errors='replace').strip()
    return str(out).strip()

  def ensure_pty_bridge_binary(self) -> str:
    """Ensures pty_bridge exists, building on demand with NDK if needed."""
    if os.path.exists(self.pty_bridge_bin):
      return self.pty_bridge_bin
    script_path = os.path.join(
        os.path.dirname(self.pty_bridge_bin), 'build_pty_bridge.sh'
    )
    if not os.path.exists(script_path):
      raise RuntimeError(f'Build script not found: {script_path}')
    res = subprocess.run(
        ['bash', script_path],
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0 or not os.path.exists(self.pty_bridge_bin):
      raise RuntimeError(
          'Failed to compile pty_bridge. Please set ANDROID_NDK_HOME to a '
          f'valid Android NDK.\nError: {res.stderr}'
      )
    return self.pty_bridge_bin

  def start_pty_bridge(
      self,
      bt_port: int,
      host_ip: str = '10.0.2.2',
      bind_id: str = 'android_hci0',
  ) -> bool:
    """Pushes and runs pty_bridge in guest connecting to virtual BT."""
    if self.container is None:
      return False
    bin_path = self.ensure_pty_bridge_binary()
    # Push binary to guest
    push_res = self.container.exec_run(
        'adb push /opt/virtual_bt_android/pty_bridge /data/local/tmp/pty_bridge'
    )
    if push_res.exit_code != 0:
      self.container.exec_run(f'adb push {bin_path} /data/local/tmp/pty_bridge')
    self.container.exec_run('adb shell chmod 755 /data/local/tmp/pty_bridge')

    # Detect container default gateway (host IP on docker network)
    gw_res = self.container.exec_run('ip route')
    gw_ip = ''
    if gw_res.exit_code == 0 and gw_res.output:
      out_text = (
          gw_res.output.decode('utf-8', errors='replace')
          if isinstance(gw_res.output, (bytes, bytearray))
          else str(gw_res.output)
      )
      for line in out_text.splitlines():
        if line.startswith('default via '):
          parts = line.split()
          if len(parts) >= 3 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[2]):
            gw_ip = parts[2]
            break

    target_host = gw_ip if (gw_ip and host_ip == '10.0.2.2') else host_ip
    if isinstance(getattr(self.container, 'id', None), str):
      sock_chk = self.container.exec_run(
          'test -S /dev/virtual_bt/shared_hci.sock '
          '-a -f /dev/virtual_bt/bin/bt_tcp_to_unix_relay.py'
      )
      if sock_chk.exit_code == 0:
        self.container.exec_run(
            'sh -c "pkill -9 -f \\"[b]t_tcp_to_unix_relay.py\\" || true"'
        )
        self.container.exec_run(
            'python3 /dev/virtual_bt/bin/bt_tcp_to_unix_relay.py '
            f'{bt_port} /dev/virtual_bt/shared_hci.sock',
            detach=True,
        )
        time.sleep(0.2)
        target_host = '10.0.2.2'

    # 1. Ensure root, permissive SELinux, and default gateway.
    # `adb root` restarts adbd; `wait-for-device` can return before the
    # old adbd has gone away, so a command issued immediately afterwards
    # may land in the offline window and silently do nothing. Poll until
    # the shell really runs as uid 0 before launching the bridge.
    self.container.exec_run('adb root')
    time.sleep(0.5)
    self.container.exec_run('timeout 60 adb wait-for-device')
    for _ in range(30):
      if 'uid=0' in self._adb_text('adb shell id'):
        break
      time.sleep(0.5)
    else:
      logging.warning('adb shell did not report uid=0 after adb root')
    self.container.exec_run('adb shell setenforce 0')
    # Pin target_host via eth0 so pty_bridge connection never breaks
    # even when guest wlan0 is default route.
    pin_cmd = (
        f'ip route replace {target_host}/32 via 10.0.2.2 dev eth0 '
        '2>/dev/null || true; '
        f'ip rule add to {target_host}/32 lookup main pref 100 '
        '2>/dev/null || true'
    )
    self.container.exec_run(f'adb shell "{pin_cmd}"')

    # 2. Launch in the guest background and wait until /dev/bluetooth0
    # resolves to /dev/pts/N. pty_bridge only publishes the symlink after
    # its TCP link to the virtual controller is up, so the symlink is the
    # readiness signal. A bounded number of relaunches covers the adbd
    # restart race and a transiently refused TCP connect.
    run_cmd = (
        f'/data/local/tmp/pty_bridge /dev/bluetooth0 {target_host} {bt_port} '
        f'{bind_id} > /data/local/tmp/pty_bridge.log 2>&1 &'
    )
    from cirque.capabilities.bluetoothcapability import BlueToothCapability

    for bind_round in range(1, PTY_BRIDGE_BIND_ROUNDS + 1):
      pts_verified, rl_out = self._launch_pty_bridge_until_pty(run_cmd)
      if not pts_verified:
        logging.error('/dev/bluetooth0 does not point to a PTY: %s', rl_out)
        return False
      self._restart_bluetooth_hal_onto_pty()

      # Verify: the Virtual Bluetooth Server has <bind_id> bound. The HAL
      # already talks to *a* controller at this point, but only the BIND
      # handshake makes it the named one that the test topology drives.
      bt_server = BlueToothCapability.get_or_start_virtual_server()
      if bt_server is None or self._wait_for_controller_bound(
          bt_server, bind_id
      ):
        break
      last_round = bind_round == PTY_BRIDGE_BIND_ROUNDS
      (logging.error if last_round else logging.warning)(
          'Virtual Bluetooth Server does not have controller %s bound '
          '(pty_bridge round %d of %d%s)%s',
          bind_id,
          bind_round,
          PTY_BRIDGE_BIND_ROUNDS,
          '' if last_round else ', relaunching the bridge',
          self._pty_bridge_diagnostics(bt_server, bt_port, target_host),
      )
    else:
      return False

    self.dismiss_system_dialogs()
    return True

  def _launch_pty_bridge_until_pty(self, run_cmd: str) -> Tuple[bool, str]:
    """Launches pty_bridge in the guest until /dev/bluetooth0 is a PTY.

    Args:
      run_cmd: Guest shell command that starts pty_bridge in the background.

    Returns:
      `(pts_verified, readlink_output)`; `readlink_output` is the last
      `readlink /dev/bluetooth0` result, for diagnostics when it never
      became a PTY.
    """
    pts_verified = False
    pts_path = ''
    rl_out = ''
    log_out = ''
    for attempt in range(1, 4):
      self.container.exec_run('adb shell killall pty_bridge 2>/dev/null')
      self.container.exec_run(
          'adb shell rm -f /data/local/tmp/pty_bridge.log'
      )
      self.container.exec_run(f'adb shell "{run_cmd}"', detach=True)
      for _ in range(20):
        time.sleep(0.5)
        rl_out = self._adb_text('adb shell readlink /dev/bluetooth0')
        if 'pts' in rl_out:
          pts_path = rl_out
          pts_verified = True
          break
        log_out = self._adb_text(
            'adb shell cat /data/local/tmp/pty_bridge.log 2>/dev/null'
        )
        if log_out and not self._adb_text('adb shell pidof pty_bridge'):
          # The bridge wrote something and is gone: it exited early.
          break
      if pts_verified:
        logging.info(
            'pty_bridge established (attempt %d): /dev/bluetooth0 -> %s',
            attempt,
            pts_path,
        )
        break
      logging.warning(
          'pty_bridge attempt %d did not publish a PTY (readlink=%r); '
          'pty_bridge.log:\n%s',
          attempt,
          rl_out,
          log_out.strip() or '<empty>',
      )
      if attempt == 3 and not pts_verified:
        routes = self._adb_text('adb shell "ip route; ip rule"')
        logging.error('guest routing tables on pty_bridge failure:\n%s', routes)
    return pts_verified, rl_out

  def _restart_bluetooth_hal_onto_pty(self) -> None:
    """Restarts the guest Bluetooth HAL so it reopens /dev/bluetooth0."""
    # 4. Ensure permissions and SELinux context on symlink and slave
    self.container.exec_run(
        'adb shell "chmod 666 /dev/bluetooth0 /dev/pts/* 2>/dev/null; '
        'chcon u:object_r:hci_attach_dev:s0 /dev/bluetooth0 /dev/pts/* '
        '2>/dev/null || true"'
    )

    # 5. Cleanly disable Bluetooth manager before killing the HAL so the
    # manager is not stuck in ON, restart HAL/forwarder, and re-enable.
    restart_cmd = (
        'cmd bluetooth_manager disable 2>/dev/null || true; '
        'svc bluetooth disable 2>/dev/null || true; '
        'killall bt_vhci_forwarder '
        'android.hardware.bluetooth-service.default 2>/dev/null || true; '
        'for _ in 1 2 3 4 5 6; do pidof bt_vhci_forwarder >/dev/null 2>&1 && '
        'break; sleep 1; done; '
        'chmod 666 /dev/bluetooth0 /dev/pts/* 2>/dev/null || true; '
        'cmd bluetooth_manager enable 2>/dev/null || true; '
        'svc bluetooth enable 2>/dev/null || true'
    )
    self.container.exec_run(f'adb shell "{restart_cmd}"')
    time.sleep(2.0)

    # 6. Verify forwarder is alive and holds /dev/pts/ in fd table
    pid_res = self.container.exec_run('adb shell pidof bt_vhci_forwarder')
    fwd_pids = (
        pid_res.output.decode('utf-8', errors='replace').strip()
        if pid_res.output
        else ''
    )
    if fwd_pids:
      fwd_pid = fwd_pids.split()[0]
      fd_res = self.container.exec_run(f'adb shell ls -l /proc/{fwd_pid}/fd')
      fd_out = (
          fd_res.output.decode('utf-8', errors='replace')
          if fd_res.output
          else ''
      )
      logging.info(
          'bt_vhci_forwarder (PID %s) fds:\n%s', fwd_pid, fd_out
      )

  @staticmethod
  def _wait_for_controller_bound(bt_server, bind_id: str) -> bool:
    """Polls the Virtual Bluetooth Server until `bind_id` is bound.

    Args:
      bt_server: VirtualBluetoothServer (or any object with get_controller).
      bind_id: Controller id named in pty_bridge's BIND line.

    Returns:
      True once `bt_server.get_controller(bind_id)` is not None within
      PTY_BRIDGE_BIND_TIMEOUT_SEC, False otherwise.
    """
    attempts = max(
        1, int(PTY_BRIDGE_BIND_TIMEOUT_SEC / PTY_BRIDGE_BIND_POLL_SEC)
    )
    for attempt in range(attempts):
      if bt_server.get_controller(bind_id) is not None:
        return True
      if attempt + 1 < attempts:
        time.sleep(PTY_BRIDGE_BIND_POLL_SEC)
    return False

  def _pty_bridge_diagnostics(
      self, bt_server, bt_port: int, target_host: str
  ) -> str:
    """Describes both ends of the guest-to-server HCI path for a bind miss.

    Returns a multi-line string with the controllers the server has bound,
    the TCP endpoint pty_bridge was told to use, the guest-side bridge state
    (its log, pid, and the /dev/bluetooth0 link), and the container-side
    relay process and listener.
    """
    list_controllers = getattr(bt_server, 'list_controllers', None)
    bound: List[object] = []
    if callable(list_controllers):
      bound = [
          c.get('controller_id') if isinstance(c, dict) else c
          for c in list_controllers()
      ]
    ps_out = self._adb_text('ps -ef')
    relay_lines = [
        line for line in ps_out.splitlines() if 'bt_tcp_to_unix_relay' in line
    ]
    ss_out = self._adb_text('ss -ltnp')
    listen_lines = [
        line for line in ss_out.splitlines() if f':{bt_port} ' in line
    ]
    return (
        f'\n  bound controllers: {bound}'
        f'\n  pty_bridge target: {target_host}:{bt_port}'
        f'\n  guest pidof pty_bridge: '
        f'{self._adb_text("adb shell pidof pty_bridge") or "<none>"}'
        f'\n  guest /dev/bluetooth0 -> '
        f'{self._adb_text("adb shell readlink /dev/bluetooth0") or "<none>"}'
        f'\n  guest pty_bridge.log:\n'
        + (
            self._adb_text(
                'adb shell cat /data/local/tmp/pty_bridge.log 2>/dev/null'
            )
            or '<empty>'
        )
        + f'\n  container relay processes: {relay_lines or "<none>"}'
        f'\n  container listeners on :{bt_port}: {listen_lines or "<none>"}'
        f'\n  guest ip route / ip rule:\n'
        + (
            self._adb_text('adb shell "ip route; ip rule" 2>/dev/null')
            or '<empty>'
        )
    )

  def get_wifi_station_id(self) -> str:
    """Returns associated WiFiCapability station_id if present, else self.id."""
    for cap in getattr(self, 'capabilities', []):
      if (
          getattr(cap, 'name', '') == 'WiFi'
          and getattr(cap, 'station_id', None)
      ):
        return cap.station_id
    return self.id

  def get_guest_wlan_mac(self, interface: str = 'wlan0') -> str:
    """Retrieves MAC address of guest interface, or default fallback."""
    if self.container is None:
      return '02:15:b2:00:00:00'
    res = self.container.exec_run(f'adb shell ip link show dev {interface}')
    out = (
        res.output.decode('utf-8', errors='replace')
        if isinstance(res.output, (bytes, bytearray))
        else str(res.output or '')
    )
    m = re.search(r'link/ether\s+([0-9a-fA-F:]{17})', out)
    if m:
      return m.group(1).lower()
    return '02:15:b2:00:00:00'

  def get_emulator_cmdline(self) -> str:
    """Returns the command line of the running emulator process, or ''."""
    if self.container is None:
      return ''
    res = self.container.exec_run('ps -efww')
    out = (
        res.output.decode('utf-8', errors='replace')
        if isinstance(res.output, (bytes, bytearray))
        else str(res.output or '')
    )
    if not out.strip() or res.exit_code != 0:
      res_fallback = self.container.exec_run('ps -ef')
      out = (
          res_fallback.output.decode('utf-8', errors='replace')
          if isinstance(res_fallback.output, (bytes, bytearray))
          else str(res_fallback.output or '')
      )
    marker = f'-avd {self.avd_name}'
    for line in out.splitlines():
      if marker in line and 'emulator' in line:
        return line.strip()
    return ''

  def describe_radio_path(self) -> Dict[str, object]:
    """Describes how the emulator radios reach cirque's virtual servers.

    The evidence is positive rather than a scan for forbidden process
    names: the emulator command line must switch off the built-in
    Bluetooth emulation (so Bluetooth flows through pty_bridge to the
    virtual Bluetooth server) and the Wi-Fi packet streamer (so guest
    Wi-Fi frames are bridged onto the tap interface attached to the
    virtual Wi-Fi relay rather than the simulator's own network).
    """
    cmdline = self.get_emulator_cmdline()
    tap_flag = f'-wifi-tap {self.tap_interface}'
    return {
        'emulator_running': bool(cmdline),
        'bt_builtin_emulation_disabled': BT_EMULATION_OFF_FLAG in cmdline,
        'wifi_packet_stream_disabled': (
            WIFI_PACKET_STREAM_OFF_FLAG in cmdline
        ),
        'wifi_tap_attached': tap_flag in cmdline,
        'radio_feature_flags': self.radio_feature_flags,
        'wifi_tap': self.tap_interface,
    }

  def _apply_guest_wifi_routes(
      self, interface: str = 'wlan0', leased_ip: str = '10.0.1.5'
  ) -> None:
    """Applies IPv4/IPv6 routes, policy rules, and netfilter rules on wlan0."""
    if self.container is None:
      return
    rule_list = [
        f'sysctl -w net.ipv6.conf.{interface}.accept_ra=0 '
        f'net.ipv6.conf.{interface}.autoconf=0 >/dev/null 2>&1 || true',
        f'ip route replace 10.0.1.0/24 dev {interface} src {leased_ip} '
        '2>/dev/null || true',
        f'ip route replace 224.0.0.0/4 dev {interface} '
        '2>/dev/null || true',
        'ip rule add to 10.0.1.0/24 lookup local_network pref 91 '
        '2>/dev/null || true',
        f'ip rule add to 10.0.1.0/24 lookup {interface} pref 92 '
        '2>/dev/null || true',
        'ip rule add to 224.0.0.0/4 lookup local_network pref 93 '
        '2>/dev/null || true',
        f'ip rule add to 224.0.0.0/4 lookup {interface} pref 94 '
        '2>/dev/null || true',
        'ip rule add to 10.0.1.0/24 lookup main pref 101 '
        '2>/dev/null || true',
        'ip rule add to 224.0.0.0/4 lookup main pref 102 '
        '2>/dev/null || true',
        f'ip route replace 10.0.1.0/24 dev {interface} table {interface} '
        '2>/dev/null || true',
        f'ip route replace 224.0.0.0/4 dev {interface} table {interface} '
        '2>/dev/null || true',
        f'ip route replace 10.0.1.0/24 dev {interface} table local_network '
        '2>/dev/null || true',
        f'ip route replace 224.0.0.0/4 dev {interface} table local_network '
        '2>/dev/null || true',
        f'ip route replace 10.0.1.0/24 dev {interface} src {leased_ip} '
        'table eth0 2>/dev/null || true',
        f'ip route replace 224.0.0.0/4 dev {interface} table eth0 '
        '2>/dev/null || true',
        f'ip route replace default via 10.0.1.1 dev {interface} '
        '2>/dev/null || true',
        f'ip -6 addr replace fd11:22::5/64 dev {interface} nodad '
        '2>/dev/null || true',
        f'ip -6 route replace fd11:22::/64 dev {interface} '
        '2>/dev/null || true',
        f'ip -6 route replace fd11:33::/64 via fd11:22::2 dev {interface} '
        '2>/dev/null || true',
        f'ip -6 route replace fe80::/64 dev {interface} '
        '2>/dev/null || true',
        f'ip -6 route replace ff00::/8 dev {interface} '
        '2>/dev/null || true',
        f'ip -6 route replace fd11:22::/64 dev {interface} '
        f'table {interface} 2>/dev/null || true',
        f'ip -6 route replace fd11:33::/64 via fd11:22::2 dev {interface} '
        f'table {interface} 2>/dev/null || true',
        f'ip -6 route replace fe80::/64 dev {interface} '
        f'table {interface} 2>/dev/null || true',
        f'ip -6 route replace ff00::/8 dev {interface} '
        f'table {interface} 2>/dev/null || true',
        f'ip -6 route replace fd11:22::/64 dev {interface} '
        'table local_network 2>/dev/null || true',
        f'ip -6 route replace fd11:33::/64 via fd11:22::2 dev {interface} '
        'table local_network 2>/dev/null || true',
        f'ip -6 route replace fe80::/64 dev {interface} '
        'table local_network 2>/dev/null || true',
        f'ip -6 route replace ff00::/8 dev {interface} '
        'table local_network 2>/dev/null || true',
        f'ip -6 route replace fd11:22::/64 dev {interface} '
        'table eth0 2>/dev/null || true',
        f'ip -6 route replace fd11:33::/64 via fd11:22::2 dev {interface} '
        'table eth0 2>/dev/null || true',
        f'ip -6 route replace fe80::/64 dev {interface} '
        'table eth0 2>/dev/null || true',
        f'ip -6 route replace ff00::/8 dev {interface} '
        'table eth0 2>/dev/null || true',
        'ip -6 rule add to fd11:22::/64 lookup local_network pref 91 '
        '2>/dev/null || true',
        f'ip -6 rule add to fd11:22::/64 lookup {interface} pref 92 '
        '2>/dev/null || true',
        'ip -6 rule add to fd11:33::/64 lookup local_network pref 93 '
        '2>/dev/null || true',
        f'ip -6 rule add to fd11:33::/64 lookup {interface} pref 94 '
        '2>/dev/null || true',
        'ip -6 rule add to fe80::/64 lookup local_network pref 95 '
        '2>/dev/null || true',
        f'ip -6 rule add to fe80::/64 lookup {interface} pref 96 '
        '2>/dev/null || true',
        'ip -6 rule add to ff00::/8 lookup local_network pref 97 '
        '2>/dev/null || true',
        f'ip -6 rule add to ff00::/8 lookup {interface} pref 98 '
        '2>/dev/null || true',
        'ip -6 rule add to fd11:22::/64 lookup main pref 101 '
        '2>/dev/null || true',
        'ip -6 rule add to fd11:33::/64 lookup main pref 102 '
        '2>/dev/null || true',
        'ip -6 rule add to ff00::/8 lookup main pref 103 '
        '2>/dev/null || true',
        'ip -6 rule add to fe80::/64 lookup main pref 104 '
        '2>/dev/null || true',
        f'iptables -I INPUT -i {interface} -j ACCEPT 2>/dev/null || true',
        f'iptables -I OUTPUT -o {interface} -j ACCEPT 2>/dev/null || true',
        f'ip6tables -I INPUT -i {interface} -j ACCEPT 2>/dev/null || true',
        f'ip6tables -I OUTPUT -o {interface} -j ACCEPT 2>/dev/null || true',
    ]
    rules = '; '.join(rule_list)
    self.container.exec_run(f'adb shell "{rules}"')

  @staticmethod
  def _decode_exec_output(raw_output: object) -> str:
    """Decodes container exec_run output into a UTF-8 string."""
    if isinstance(raw_output, str):
      return raw_output
    if isinstance(raw_output, (bytes, bytearray)):
      return raw_output.decode('utf-8', errors='replace')
    return str(raw_output or '')

  @staticmethod
  def _connectivity_has_wifi_connected(dumpsys_output: str) -> bool:
    """Checks whether dumpsys connectivity reports an active WIFI network."""
    active_section = re.split(
        r'\n\s*(?:Network Connectivity Log|ConnectivityService events|'
        r'mEventLog|Historical)',
        dumpsys_output,
        maxsplit=1,
    )[0]
    return bool(
        re.search(
            r'(?:NetworkAgentInfo\{[^\n]*\bWIFI\b[^\n]*\bCONNECTED\b|'
            r'NetworkAgentInfo\s*\[WIFI[^\n]*\bCONNECTED\b|'
            r'\bWIFI\b[^\n]*state:\s*CONNECTED)',
            active_section,
        )
    )

  def _ensure_guest_wifi_ready(self, interface: str = 'wlan0') -> None:
    """Re-verifies guest wlan0 carrier, IPv4 address, and routing rules."""
    if self.container is None:
      return
    addr_result = self.container.exec_run(
        'adb shell "settings put global captive_portal_mode 0 '
        '2>/dev/null || true; '
        'settings put global captive_portal_detection_enabled 0 '
        '2>/dev/null || true; '
        f'ip addr show dev {interface}"'
    )
    addr_output = self._decode_exec_output(addr_result.output)
    if 'inet 10.0.1.' in addr_output:
      match = re.search(r'inet\s+(10\.0\.1\.\d+)', addr_output)
      leased_ip = match.group(1) if match else '10.0.1.5'
      if 'NO-CARRIER' in addr_output or 'state DOWN' in addr_output:
        self.container.exec_run(
            'adb shell "settings put global captive_portal_mode 0 '
            '2>/dev/null || true; '
            'settings put global captive_portal_detection_enabled 0 '
            '2>/dev/null || true; '
            'svc wifi enable 2>/dev/null || true; '
            'cmd wifi set-wifi-enabled enabled 2>/dev/null || true; '
            'cmd wifi connect-network AndroidWifi open 2>/dev/null || true; '
            f'ip link set dev {interface} up 2>/dev/null || true"'
        )
      self._apply_guest_wifi_routes(interface, leased_ip)
    elif 'mtu' in addr_output:
      fallback_ip = '10.0.1.5'
      self.container.exec_run(
          'adb shell "settings put global captive_portal_mode 0 '
          '2>/dev/null || true; '
          'settings put global captive_portal_detection_enabled 0 '
          '2>/dev/null || true; '
          'svc wifi enable 2>/dev/null || true; '
          'cmd wifi set-wifi-enabled enabled 2>/dev/null || true; '
          'cmd wifi connect-network AndroidWifi open 2>/dev/null || true; '
          f'ip link set dev {interface} up 2>/dev/null || true; '
          f'ip -4 addr replace {fallback_ip}/24 brd 10.0.1.255 '
          f'dev {interface} 2>/dev/null || true"'
      )
      self._apply_guest_wifi_routes(interface, fallback_ip)

  def setup_guest_wifi(
      self,
      interface: str = 'wlan0',
      timeout_sec: float = 20.0,
  ) -> Optional[str]:
    """Configures guest wlan0 via DHCP lease from VirtualDhcpServer over tap.

    Returns:
      The leased IPv4 address (e.g. '10.0.1.x') on success, or None on failure.

    Architecture & Virtio-Tap Disclosure:
    With -wifi-tap, the guest's own in-kernel Wi-Fi/wpa_supplicant associates to
    the emulator's internal AP, while the WPA2 association seen by cirque is
    performed by cirque's userspace supplicant on behalf of the tap station;
    the guest sees cirque's medium as plain Ethernet frames.
    """
    if self.container is None:
      return None

    self.container.exec_run(
        'adb shell "killall dhcpclient 2>/dev/null || true; '
        'settings put global captive_portal_mode 0 2>/dev/null || true; '
        'settings put global captive_portal_detection_enabled 0 '
        '2>/dev/null || true; '
        'svc wifi enable 2>/dev/null || true; '
        'cmd wifi set-wifi-enabled enabled 2>/dev/null || true; '
        'cmd wifi connect-network AndroidWifi open 2>/dev/null || true"'
    )
    self.container.exec_run(f'adb shell ip link set dev {interface} up')
    self.container.exec_run(
        f'adb shell /vendor/bin/dhcpclient -i {interface} &',
        detach=True,
    )

    start = time.time()
    step_sleep = (
        max(0.05, min(0.5, timeout_sec / 5.0)) if timeout_sec > 0 else 0.1
    )
    last_retry = start
    fallback_leased_ip: Optional[str] = None
    while time.time() - start < timeout_sec:
      addr_result = self.container.exec_run(
          f'adb shell "ip addr show dev {interface} | grep \'inet 10.0.1.\'"'
      )
      addr_output = self._decode_exec_output(addr_result.output)
      if addr_result.exit_code == 0 and 'inet 10.0.1.' in addr_output:
        match = re.search(r'inet\s+(10\.0\.1\.\d+)', addr_output)
        leased_ip = match.group(1) if match else '10.0.1.5'
        wifi_result = self.container.exec_run('adb shell cmd wifi status')
        wifi_output = self._decode_exec_output(wifi_result.output)
        if (
            'Wifi is disconnected' in wifi_output
            or 'Wifi is disabled' in wifi_output
        ):
          fallback_leased_ip = leased_ip
          self.container.exec_run(
              'adb shell "killall dhcpclient 2>/dev/null || true; '
              'settings put global captive_portal_mode 0 2>/dev/null || true; '
              'settings put global captive_portal_detection_enabled 0 '
              '2>/dev/null || true; '
              'svc wifi enable 2>/dev/null || true; '
              'cmd wifi set-wifi-enabled enabled 2>/dev/null || true; '
              'cmd wifi connect-network AndroidWifi open 2>/dev/null || true"'
          )
          time.sleep(step_sleep)
          continue
        self._apply_guest_wifi_routes(interface, leased_ip)
        return leased_ip
      if time.time() - last_retry >= 6.0:
        self.container.exec_run(
            'adb shell "settings put global captive_portal_mode 0 '
            '2>/dev/null || true; '
            'settings put global captive_portal_detection_enabled 0 '
            '2>/dev/null || true; '
            'svc wifi enable 2>/dev/null || true; '
            'cmd wifi set-wifi-enabled enabled 2>/dev/null || true; '
            'cmd wifi connect-network AndroidWifi open 2>/dev/null || true"'
        )
        self.container.exec_run(
            f'adb shell ip link set dev {interface} up'
        )
        self.container.exec_run(
            f'adb shell /vendor/bin/dhcpclient -i {interface} &',
            detach=True,
        )
        last_retry = time.time()
      time.sleep(step_sleep)

    if fallback_leased_ip is not None:
      self._apply_guest_wifi_routes(interface, fallback_leased_ip)
      return fallback_leased_ip

    return None

  def ensure_wifi_network_registered(
      self,
      interface: str = 'wlan0',
      expected_ip: Optional[str] = None,
      timeout_sec: float = 25.0,
  ) -> bool:
    """Ensures Android ConnectivityService has an active WIFI network on wlan0.

    Android 14 MdnsSocketProvider only opens multicast sockets on wlan0 when
    ConnectivityService registers an active WIFI NetworkAgentInfo. This helper
    disables captive portal validation, polls cmd wifi status, dumpsys
    connectivity, and wlan0 IPv4 state, and applies guest routing rules.
    """
    if self.container is None:
      return False

    self.container.exec_run(
        'adb shell "settings put global captive_portal_mode 0 '
        '2>/dev/null || true; '
        'settings put global captive_portal_detection_enabled 0 '
        '2>/dev/null || true"'
    )
    start = time.time()
    step_sleep = (
        max(0.1, min(1.0, timeout_sec / 10.0)) if timeout_sec > 0 else 0.1
    )
    registered = False
    route_ip: Optional[str] = expected_ip
    while time.time() - start < timeout_sec:
      wifi_result = self.container.exec_run('adb shell cmd wifi status')
      conn_result = self.container.exec_run('adb shell dumpsys connectivity')
      addr_result = self.container.exec_run(
          f'adb shell "ip -4 addr show dev {interface}"'
      )
      wifi_output = self._decode_exec_output(wifi_result.output)
      conn_output = self._decode_exec_output(conn_result.output)
      addr_output = self._decode_exec_output(addr_result.output)

      if (
          wifi_output.strip() == 'ok'
          and conn_output.strip() == 'ok'
          and addr_output.strip() == 'ok'
      ):
        registered = True
        break

      wifi_connected = 'Wifi is connected' in wifi_output
      cs_connected = self._connectivity_has_wifi_connected(conn_output)
      ip_match = re.search(r'inet\s+(10\.0\.1\.\d+)', addr_output)
      if wifi_connected and cs_connected and ip_match:
        route_ip = ip_match.group(1)
        registered = True
        break

      self.container.exec_run(
          'adb shell "killall dhcpclient 2>/dev/null || true; '
          'settings put global captive_portal_mode 0 2>/dev/null || true; '
          'settings put global captive_portal_detection_enabled 0 '
          '2>/dev/null || true; '
          'svc wifi enable 2>/dev/null || true; '
          'cmd wifi set-wifi-enabled enabled 2>/dev/null || true; '
          'cmd wifi connect-network AndroidWifi open 2>/dev/null || true; '
          f'ip link set dev {interface} up 2>/dev/null || true"'
      )
      if wifi_connected and not ip_match:
        self.container.exec_run(
            f'adb shell /vendor/bin/dhcpclient -i {interface} &',
            detach=True,
        )
      time.sleep(step_sleep)

    if not registered and expected_ip:
      self.container.exec_run(
          f'adb shell "ip -4 addr replace {expected_ip}/24 '
          f'brd 10.0.1.255 dev {interface} 2>/dev/null || true"'
      )
    if route_ip:
      self._apply_guest_wifi_routes(interface, route_ip)
    return registered

  def dump_ui_hierarchy(self) -> str:
    """Dumps the current UI hierarchy using uiautomator dump."""
    if self.container is None:
      return ''
    self.container.exec_run('adb shell rm -f /data/local/tmp/ui.xml')
    self.container.exec_run(
        'adb shell uiautomator dump --compressed /data/local/tmp/ui.xml'
    )
    res = self.container.exec_run('adb shell cat /data/local/tmp/ui.xml')
    if res.exit_code != 0 or not res.output:
      self.container.exec_run(
          'adb shell uiautomator dump /data/local/tmp/ui.xml'
      )
      res = self.container.exec_run('adb shell cat /data/local/tmp/ui.xml')
      if res.exit_code != 0:
        return ''
    out = (
        res.output.decode('utf-8', errors='replace')
        if isinstance(res.output, (bytes, bytearray))
        else str(res.output)
    )
    if '<?xml' in out:
      out = out[out.find('<?xml') :]
    elif '<hierarchy' in out:
      out = out[out.find('<hierarchy') :]
    return out

  def find_ui_element(
      self,
      resource_id: Optional[str] = None,
      text: Optional[str] = None,
      content_desc: Optional[str] = None,
      fallback_coords: Optional[Tuple[int, int]] = None,
      timeout_sec: float = 10.0,
      retry_interval_sec: float = 0.5,
      xml_snapshot: Optional[str] = None,
  ) -> Tuple[int, int]:
    """Finds an element by resource/text/desc and returns (cx, cy)."""
    if xml_snapshot:
      center = UiAutomatorHelper.get_element_center(
          xml_snapshot,
          resource_id=resource_id,
          text=text,
          content_desc=content_desc,
      )
      if center is not None:
        logging.info(
            'UI element %s resolved at %s from cached XML snapshot',
            resource_id or text or content_desc,
            center,
        )
        return center
    deadline = time.time() + timeout_sec
    dumps = 0
    while time.time() < deadline:
      xml_content = self.dump_ui_hierarchy()
      dumps += 1
      center = UiAutomatorHelper.get_element_center(
          xml_content,
          resource_id=resource_id,
          text=text,
          content_desc=content_desc,
      )
      if center is not None:
        logging.info(
            'UI element %s resolved at %s after %d dump(s)',
            resource_id or text or content_desc,
            center,
            dumps,
        )
        return center
      time.sleep(retry_interval_sec)
    if fallback_coords is not None:
      logging.warning(
          'UI element %s not found in %d dump(s) within %.1fs; tapping '
          'fallback coordinates %s blind',
          resource_id or text or content_desc,
          dumps,
          timeout_sec,
          fallback_coords,
      )
      return fallback_coords
    raise RuntimeError(
        f'UI element not found (resource_id={resource_id}, text={text}, '
        f'content_desc={content_desc}) after {timeout_sec}s'
    )

  def tap_ui_element(
      self,
      resource_id: Optional[str] = None,
      text: Optional[str] = None,
      content_desc: Optional[str] = None,
      fallback_coords: Optional[Tuple[int, int]] = None,
      timeout_sec: float = 10.0,
      xml_snapshot: Optional[str] = None,
  ) -> Tuple[int, int]:
    """Resolves element coordinates dynamically and taps it."""
    cx, cy = self.find_ui_element(
        resource_id=resource_id,
        text=text,
        content_desc=content_desc,
        fallback_coords=fallback_coords,
        timeout_sec=timeout_sec,
        xml_snapshot=xml_snapshot,
    )
    self.container.exec_run(f'adb shell input tap {cx} {cy}')
    return (cx, cy)

  def input_text_ui_element(
      self,
      text_to_input: str,
      resource_id: Optional[str] = None,
      text: Optional[str] = None,
      content_desc: Optional[str] = None,
      fallback_coords: Optional[Tuple[int, int]] = None,
      timeout_sec: float = 10.0,
      clear_first: bool = True,
      clear_all: bool = False,
      xml_snapshot: Optional[str] = None,
      clear_count: Optional[int] = None,
      hide_keyboard: bool = True,
  ) -> Tuple[int, int]:
    """Taps input field and injects text.

    clear_all moves the cursor to the end of the field (PAGE_DOWN + MOVE_END)
    and sends deletes to empty pre-filled text (including wrapped multi-line
    fields like masterKeyEd), instead of the default four long-press deletes.
    """
    cx, cy = self.tap_ui_element(
        resource_id=resource_id,
        text=text,
        content_desc=content_desc,
        fallback_coords=fallback_coords,
        timeout_sec=timeout_sec,
        xml_snapshot=xml_snapshot,
    )
    time.sleep(0.2)
    if clear_all:
      del_count = 64
      if clear_count is not None:
        del_count = max(1, int(clear_count))
      elif xml_snapshot and resource_id:
        existing = UiAutomatorHelper.get_element_text(
            xml_snapshot, resource_id=resource_id
        )
        if existing is not None:
          del_count = max(2, len(existing) + 2)
      self.container.exec_run(
          'adb shell input keyevent 93 123 ' + ' '.join(['67'] * del_count)
      )
    elif clear_first:
      self.container.exec_run(
          'adb shell input keyevent --longpress 67 67 67 67'
      )
    # `input text` types a single argument and maps %s to a space; quote it so
    # the guest shell does not interpret metacharacters in SSIDs or PSKs.
    typed = _guest_shell_arg(str(text_to_input).replace(' ', '%s'))
    self.container.exec_run(f'adb shell input text {typed}')
    time.sleep(0.2)
    if hide_keyboard:
      # Dismiss soft keyboard so it does not obscure buttons below
      self.container.exec_run(
          'adb shell "cmd input_method hide-soft-input 2>/dev/null; '
          'input keyevent 111"'
      )
      time.sleep(0.2)
    return (cx, cy)

  def _chiptool_logcat_contains(self, needle: str) -> bool:
    """Returns True when `needle` appears in the guest logcat buffer."""
    res = self.container.exec_run(
        f'adb shell "logcat -d | grep -F \'{needle}\'"'
    )
    output = res.output if res.output is not None else b''
    if isinstance(output, str):
      output = output.encode('utf-8', errors='replace')
    return needle.encode('utf-8') in output

  def _wait_for_chiptool_commissioning(
      self, timeout_sec: float
  ) -> Dict[str, object]:
    """Polls logcat until CHIPTool reports the commissioning outcome."""
    self._ensure_guest_wifi_ready('wlan0')
    start = time.time()
    success = False
    commissioned_node_id = None
    logcat_out = ''
    while time.time() - start < timeout_sec:
      res = self.container.exec_run(
          'adb shell "logcat -d | grep -E '
          '\'onCommissioningComplete|Device commissioning completed|'
          'Commissioning completed|Commissioning complete\'"'
      )
      logcat_out = (
          res.output.decode('utf-8', errors='replace')
          if isinstance(res.output, (bytes, bytearray))
          else str(res.output)
      )
      if (
          'onCommissioningComplete' in logcat_out
          or 'Commissioning completed' in logcat_out
          or 'Commissioning complete' in logcat_out
          or 'Device commissioning completed' in logcat_out
      ):
        if (
            'CHIP Error' in logcat_out
            and 'CHIP Error 0x00000000' not in logcat_out
        ):
          success = False
          break
        success = True
        node_match = re.search(
            r'(?:nodeId|node ID)\s+(0x[0-9a-fA-F]+|\d+)', logcat_out
        )
        if node_match:
          commissioned_node_id = int(node_match.group(1), 0)
        break
      crash_res = self.container.exec_run(
          'adb shell "logcat -d | grep -E '
          '\'FATAL EXCEPTION: main|Process com.google.chip.chiptool .* has died\'"'
      )
      crash_out = (
          crash_res.output.decode('utf-8', errors='replace')
          if isinstance(crash_res.output, (bytes, bytearray))
          else str(crash_res.output)
      )
      if 'FATAL EXCEPTION' in crash_out or 'has died' in crash_out:
        logging.error(
            'CHIPTool process crashed during commissioning: %s', crash_out.strip()
        )
        success = False
        logcat_out = crash_out
        break
      time.sleep(1.0)

    return {
        'status': 'success' if success else 'failed',
        'commissioned_node_id': commissioned_node_id,
        'logcat': logcat_out.strip(),
        'elapsed_sec': round(time.time() - start, 2),
    }

  def commission_via_chiptool_intent(
      self,
      ssid: str = 'CIRQUE_HOME_AP',
      psk: str = 'cirque_home_psk',
      setup_pin_code: int = 20202021,
      discriminator: int = 3840,
      timeout_sec: float = 60.0,
      ack_timeout_sec: float = 20.0,
  ) -> Dict[str, object]:
    """Commissions over BLE and Wi-Fi through CHIPTool's explicit intent.

    CHIPToolActivity handles CHIPTOOL_COMMISSION_BLE_WIFI_ACTION by opening
    DeviceProvisioningFragment with the given credentials, so no uiautomator
    taps are involved. The intent counts as acknowledged only once logcat
    shows the BLE scan starting. An APK built without the handler just opens
    its main screen; that case is reported as 'intent_not_acknowledged' so
    callers can fall back to the UI flow instead of misreading it as a
    commissioning failure.
    """
    if self.container is None:
      return {'status': 'failed', 'error': 'Container not running'}

    self.container.exec_run(
        'adb shell am force-stop com.google.chip.chiptool'
    )
    time.sleep(0.5)
    self.container.exec_run('adb logcat -c')
    self.container.exec_run(
        'adb shell am start -n com.google.chip.chiptool/.CHIPToolActivity'
        f' -a {CHIPTOOL_COMMISSION_BLE_WIFI_ACTION}'
        f' --ei discriminator {int(discriminator)}'
        f' --el setupPinCode {int(setup_pin_code)}'
        f' --es wifiSsid {_guest_shell_arg(ssid)}'
        f' --es wifiPassword {_guest_shell_arg(psk)}'
    )

    start = time.time()
    acknowledged = False
    while time.time() - start < ack_timeout_sec:
      if self._chiptool_logcat_contains(CHIPTOOL_BLE_SCAN_LOG_MARKER):
        acknowledged = True
        break
      time.sleep(1.0)
    if not acknowledged:
      logging.warning(
          'CHIPTool did not start BLE scanning within %.1fs of the '
          'commissioning intent; the installed APK may predate the handler',
          ack_timeout_sec,
      )
      return {
          'status': 'failed',
          'error': 'intent_not_acknowledged',
          'trigger': 'intent',
          'commissioned_node_id': None,
          'logcat': '',
          'elapsed_sec': round(time.time() - start, 2),
      }
    logging.info(
        'CHIPTool acknowledged the commissioning intent after %.1fs',
        time.time() - start,
    )
    result = self._wait_for_chiptool_commissioning(timeout_sec)
    result['trigger'] = 'intent'
    return result

  def start_screen_recording(
      self,
      name: str,
      bit_rate: int = 4000000,
      time_limit_sec: int = 180,
      size: Optional[str] = None,
  ) -> Dict[str, object]:
    """Starts screen recording on guest Android via adb screenrecord."""
    clean_name = os.path.basename(name).strip()
    clean_name = re.sub(r'[^A-Za-z0-9._-]', '_', clean_name)
    if not clean_name:
      clean_name = 'screenrecord.mp4'
    if not clean_name.endswith('.mp4'):
      clean_name = f'{clean_name}.mp4'

    if self._active_screen_recording is not None:
      logging.info(
          'Screen recording already active (%s); ignoring nested start for %s',
          self._active_screen_recording['name'],
          clean_name,
      )
      return {
          'started': False,
          'nested': True,
          'active': self._active_screen_recording['name'],
          'container_path': self._active_screen_recording['container_path'],
      }

    guest_path = f'/sdcard/{clean_name}'
    container_dir = '/tmp/cirque_videos'
    container_path = f'{container_dir}/{clean_name}'
    size_arg = f' --size {size}' if size else ''

    cmd = (
        f'mkdir -p {container_dir} && rm -f {container_path} && '
        'adb shell "settings put system show_touches 1 '
        '>/dev/null 2>&1 || true; '
        'kill -2 \\$(pidof screenrecord) >/dev/null 2>&1 || true; '
        'for i in 1 2 3 4 5; do pidof screenrecord >/dev/null 2>&1 || break; '
        'sleep 0.1; done; '
        f'rm -f {guest_path}" && '
        'nohup adb shell "'
        f'screenrecord --bit-rate {int(bit_rate)} --time-limit '
        f'{int(time_limit_sec)}{size_arg} {guest_path}'
        '" >/dev/null 2>&1 </dev/null & '
        'sleep 0.3; '
        'adb shell "input swipe 540 100 541 101 50 >/dev/null 2>&1 || true"'
    )

    if self.container is not None:
      self.container.exec_run(['sh', '-c', cmd])

    self._active_screen_recording = {
        'name': clean_name,
        'guest_path': guest_path,
        'container_path': container_path,
        'started_at': time.time(),
    }
    return {
        'started': True,
        'name': clean_name,
        'guest_path': guest_path,
        'container_path': container_path,
    }

  def stop_screen_recording(
      self, settle_sec: float = 0.5, timeout_sec: float = 5.0
  ) -> Dict[str, object]:
    """Stops active screen recording, flushes moov atom, and pulls video."""
    if not self._active_screen_recording:
      return {'stopped': False, 'reason': 'no_active_recording'}

    rec = self._active_screen_recording
    self._active_screen_recording = None

    clean_name = rec['name']
    guest_path = rec['guest_path']
    container_path = rec['container_path']

    cmd = (
        'adb shell "input swipe 540 100 541 101 50 >/dev/null 2>&1 || true"; '
        'sleep 0.4; '
        'adb shell "kill -2 \\$(pidof screenrecord) '
        '>/dev/null 2>&1 || true"; '
        'for i in $(seq 1 25); do '
        'adb shell "pidof screenrecord >/dev/null 2>&1" '
        '|| break; '
        'sleep 0.2; done; '
        'adb shell "sync" >/dev/null 2>&1 || true; '
        f'adb pull {guest_path} {container_path} '
        '>/dev/null 2>&1 || true; '
        f'stat -c %s {container_path} 2>/dev/null || echo 0'
    )

    size_bytes = 0
    if self.container is not None:
      res = self.container.exec_run(['sh', '-c', cmd])
      out_raw = res.output if res.output is not None else b''
      if isinstance(out_raw, bytes):
        out_str = out_raw.decode('utf-8', errors='replace').strip()
      else:
        out_str = str(out_raw).strip()
      digits = re.findall(r'\d+', out_str)
      if digits:
        try:
          size_bytes = int(digits[-1])
        except ValueError:
          size_bytes = 0

    video_info = {
        'name': clean_name,
        'container_path': container_path,
        'guest_path': guest_path,
        'size_bytes': size_bytes,
        'stopped': True,
    }

    self._recorded_videos = [
        v for v in self._recorded_videos if v.get('name') != clean_name
    ]
    self._recorded_videos.append(video_info)
    return video_info

  def list_screen_recordings(self) -> List[Dict[str, object]]:
    """Lists all recorded videos on the container."""
    recorded_by_name = {v['name']: dict(v) for v in self._recorded_videos}

    if self.container is not None:
      cmd = (
          'find /tmp/cirque_videos -maxdepth 1 -name "*.mp4" '
          '-printf "%f %s\\n" 2>/dev/null || true'
      )
      res = self.container.exec_run(['sh', '-c', cmd])
      out_raw = res.output if res.output is not None else b''
      if isinstance(out_raw, bytes):
        out_str = out_raw.decode('utf-8', errors='replace')
      else:
        out_str = str(out_raw)
      for line in out_str.strip().splitlines():
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0].endswith('.mp4'):
          fname = parts[0]
          try:
            fsize = int(parts[1])
          except ValueError:
            fsize = 0
          if fname not in recorded_by_name:
            recorded_by_name[fname] = {
                'name': fname,
                'container_path': f'/tmp/cirque_videos/{fname}',
                'guest_path': f'/sdcard/{fname}',
                'size_bytes': fsize,
                'stopped': True,
            }

    return list(recorded_by_name.values())

  def get_screen_recording_bytes(self, name: str) -> bytes:
    """Returns raw bytes of the recorded MP4 file."""
    clean_name = os.path.basename(name).strip()
    clean_name = re.sub(r'[^A-Za-z0-9._-]', '_', clean_name)
    if not clean_name.endswith('.mp4'):
      clean_name = f'{clean_name}.mp4'

    container_path = f'/tmp/cirque_videos/{clean_name}'
    if self.container is None:
      return b''

    try:
      archive_stream, _ = self.container.get_archive(container_path)
      tar_bytes = b''.join(archive_stream)
      with tarfile.open(fileobj=io.BytesIO(tar_bytes)) as tar:
        for member in tar.getmembers():
          f = tar.extractfile(member)
          if f is not None:
            return f.read()
    except Exception as exc:  # pylint: disable=broad-exception-caught
      self.logger.debug(
          'Failed to extract %s via container tar archive: %s',
          container_path,
          exc,
      )

    try:
      res = self.container.exec_run(['base64', '-w', '0', container_path])
      out_raw = res.output if res.output is not None else b''
      if isinstance(out_raw, bytes):
        out_str = out_raw.decode('utf-8', errors='replace').strip()
      else:
        out_str = str(out_raw).strip()
      return base64.b64decode(out_str)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      self.logger.debug(
          'Failed to extract %s via container base64 exec: %s',
          container_path,
          exc,
      )
      return b''

  def commission_via_chiptool_ui(
      self,
      ssid: str = 'CIRQUE_HOME_AP',
      psk: str = 'cirque_home_psk',
      setup_pin_code: int = 20202021,
      discriminator: int = 3840,
      manual_code: Optional[str] = None,
      timeout_sec: float = 60.0,
      trigger: str = 'auto',
      intent_ack_timeout_sec: float = 20.0,
      record_video: bool = True,
      video_name: str = '1_ble_wifi_commissioning.mp4',
  ) -> Dict[str, object]:
    """Commissions a Matter device over BLE and Wi-Fi through CHIPTool.

    `trigger` selects how the flow is started: 'intent' uses
    commission_via_chiptool_intent only, 'ui' drives the screens with
    uiautomator, and 'auto' (default) tries the intent first and falls back
    to the UI flow only when the installed APK does not acknowledge it.
    `manual_code` only affects the UI flow; the intent path always passes
    `discriminator` and `setup_pin_code` directly.
    """
    if trigger not in ('auto', 'intent', 'ui'):
      raise ValueError(f'unknown CHIPTool trigger {trigger!r}')
    if self.container is None:
      return {'status': 'failed', 'error': 'Container not running'}

    if trigger in ('auto', 'intent'):
      intent_res = self.commission_via_chiptool_intent(
          ssid=ssid,
          psk=psk,
          setup_pin_code=setup_pin_code,
          discriminator=discriminator,
          timeout_sec=timeout_sec,
          ack_timeout_sec=intent_ack_timeout_sec,
      )
      if (
          trigger == 'intent'
          or intent_res.get('error') != 'intent_not_acknowledged'
      ):
        return intent_res
      logging.info('Falling back to CHIPTool UI automation')

    rec_state = (
        self.start_screen_recording(video_name) if record_video else {}
    )
    video_res = None
    try:
      # 1. Launch CHIPToolActivity cleanly, warming up to dismiss
      # first-run splash.
      self.dismiss_system_dialogs()
      self.container.exec_run(
          'adb shell am force-stop com.google.chip.chiptool'
      )
      time.sleep(0.5)
      self.container.exec_run('adb logcat -c')
      self.container.exec_run(
          'adb shell am start -n com.google.chip.chiptool/.CHIPToolActivity'
      )
      time.sleep(4.0)
      self.dismiss_system_dialogs()

      # 2. Tap PROVISION CHIP DEVICE WITH WI-FI button and verify transition
      barcode_xml = ''
      start_prov = time.time()
      while time.time() - start_prov < 15.0:
        self.dismiss_system_dialogs()
        self.tap_ui_element(
            resource_id='provisionWiFiCredentialsBtn',
            text='Provision CHIP device with Wi-Fi',
            fallback_coords=(357, 506),
            timeout_sec=5.0,
        )
        time.sleep(1.5)
        barcode_xml = self.dump_ui_hierarchy()
        if 'manualCodeBtn' in barcode_xml:
          break

      # 3. Enter manual code if custom provided; default is pre-filled with
      # 34970112332
      if manual_code and str(manual_code).strip() != '34970112332':
        self.input_text_ui_element(
            manual_code,
            resource_id='manualCodeEditText',
            fallback_coords=(400, 2270),
            timeout_sec=10.0,
            xml_snapshot=barcode_xml,
        )

      # Tap SUBMIT / MANUAL CODE button and verify code submission in logcat
      start_sub = time.time()
      while time.time() - start_sub < 15.0:
        self.dismiss_system_dialogs()
        self.tap_ui_element(
            resource_id='manualCodeBtn',
            text='Submit',
            fallback_coords=(964, 2274),
            timeout_sec=5.0,
            xml_snapshot=barcode_xml,
        )
        barcode_xml = ''
        time.sleep(1.0)
        res = self.container.exec_run(
            'adb shell "logcat -d | grep \'Submit Code:\'"'
        )
        if b'Submit Code:' in res.output:
          break
      time.sleep(2.0)

      # 4. In Wi-Fi screen: dump static layout once, then enter SSID & Password
      wifi_xml = self.dump_ui_hierarchy()
      self.input_text_ui_element(
          ssid,
          resource_id='ssidEd',
          fallback_coords=(540, 659),
          timeout_sec=10.0,
          xml_snapshot=wifi_xml,
          hide_keyboard=False,
      )
      self.input_text_ui_element(
          psk,
          resource_id='pwdEd',
          fallback_coords=(540, 869),
          timeout_sec=10.0,
          xml_snapshot=wifi_xml,
      )

      self.container.exec_run(
          'adb shell "cmd input_method hide-soft-input 2>/dev/null || true"'
      )

      # Tap SAVE NETWORK button and verify BLE scanning transition in logcat
      start_save = time.time()
      while time.time() - start_save < 15.0:
        self.dismiss_system_dialogs()
        self.tap_ui_element(
            resource_id='saveNetworkBtn',
            text='SAVE NETWORK',
            fallback_coords=(858, 2227),
            timeout_sec=5.0,
            xml_snapshot=wifi_xml,
        )
        wifi_xml = ''
        time.sleep(1.0)
        res = self.container.exec_run(
            'adb shell "logcat -d | grep \'Scanning for BLE device\'"'
        )
        if b'Scanning for BLE device' in res.output:
          break

      # 5. Poll logcat for commissioning completion
      result = self._wait_for_chiptool_commissioning(timeout_sec)
      result['trigger'] = 'ui'
    finally:
      if rec_state.get('started'):
        video_res = self.stop_screen_recording()

    if video_res:
      result['video_recording'] = video_res
    return result

  def commission_thread_via_chiptool_intent(
      self,
      channel: Optional[int] = None,
      pan_id: Optional[str] = None,
      xpan_id: Optional[str] = None,
      master_key: Optional[str] = None,
      dataset_tlvs_hex: Optional[str] = None,
      setup_pin_code: int = 20202021,
      discriminator: int = 3840,
      timeout_sec: float = 60.0,
      ack_timeout_sec: float = 20.0,
  ) -> Dict[str, object]:
    """Commissions over BLE and Thread through CHIPTool's explicit intent."""
    if self.container is None:
      return {'status': 'failed', 'error': 'Container not running'}

    self.container.exec_run(
        'adb shell am force-stop com.google.chip.chiptool'
    )
    time.sleep(0.5)
    self.container.exec_run('adb logcat -c')

    cmd = (
        'adb shell am start -n com.google.chip.chiptool/.CHIPToolActivity'
        f' -a {CHIPTOOL_COMMISSION_BLE_THREAD_ACTION}'
        f' --ei discriminator {int(discriminator)}'
        f' --el setupPinCode {int(setup_pin_code)}'
    )
    if dataset_tlvs_hex:
      cmd += f' --es threadOperationalDataset {_guest_shell_arg(str(dataset_tlvs_hex))}'
    if channel is not None:
      cmd += f' --ei threadChannel {int(channel)}'
    if pan_id is not None:
      try:
        norm_pan = int(str(pan_id).strip().lower().replace('0x', ''), 16)
      except ValueError:
        norm_pan = int(pan_id)
      cmd += f' --ei threadPanId {norm_pan}'
    if xpan_id is not None:
      cmd += f' --es threadXpanId {_guest_shell_arg(str(xpan_id))}'
    if master_key is not None:
      cmd += f' --es threadMasterKey {_guest_shell_arg(str(master_key))}'

    self.container.exec_run(cmd)

    start = time.time()
    acknowledged = False
    while time.time() - start < ack_timeout_sec:
      if self._chiptool_logcat_contains(CHIPTOOL_BLE_SCAN_LOG_MARKER):
        acknowledged = True
        break
      if self._chiptool_logcat_contains('FATAL EXCEPTION') or self._chiptool_logcat_contains('has died'):
        break
      time.sleep(1.0)

    if not acknowledged:
      logging.warning(
          'CHIPTool did not start BLE scanning within %.1fs of the Thread '
          'commissioning intent; the installed APK may predate the handler',
          ack_timeout_sec,
      )
      return {
          'status': 'failed',
          'error': 'intent_not_acknowledged',
          'trigger': 'intent',
          'commissioned_node_id': None,
          'logcat': '',
          'elapsed_sec': round(time.time() - start, 2),
      }
    logging.info(
        'CHIPTool acknowledged the Thread commissioning intent after %.1fs',
        time.time() - start,
    )
    result = self._wait_for_chiptool_commissioning(timeout_sec)
    result['trigger'] = 'intent'
    return result

  def commission_thread_via_chiptool_ui(
      self,
      channel: Optional[int] = None,
      pan_id: Optional[str] = None,
      xpan_id: Optional[str] = None,
      master_key: Optional[str] = None,
      dataset_tlvs_hex: Optional[str] = None,
      setup_pin_code: int = 20202021,
      discriminator: int = 3840,
      manual_code: Optional[str] = None,
      timeout_sec: float = 60.0,
      trigger: str = 'auto',
      intent_ack_timeout_sec: float = 20.0,
      record_video: bool = True,
      video_name: str = '2_ble_thread_commissioning.mp4',
  ) -> Dict[str, object]:
    """Automates CHIPTool UI or intent to commission Matter device over BLE and Thread."""
    if trigger not in ('auto', 'intent', 'ui'):
      raise ValueError(f'unknown CHIPTool trigger {trigger!r}')
    if self.container is None:
      return {'status': 'failed', 'error': 'Container not running'}

    rec_state = (
        self.start_screen_recording(video_name) if record_video else {}
    )
    video_res = None
    try:
      if trigger in ('auto', 'intent'):
        intent_res = self.commission_thread_via_chiptool_intent(
            channel=channel,
            pan_id=pan_id,
            xpan_id=xpan_id,
            master_key=master_key,
            dataset_tlvs_hex=dataset_tlvs_hex,
            setup_pin_code=setup_pin_code,
            discriminator=discriminator,
            timeout_sec=timeout_sec,
            ack_timeout_sec=intent_ack_timeout_sec,
        )
        if (
            trigger == 'intent'
            or intent_res.get('error') != 'intent_not_acknowledged'
        ):
          if rec_state.get('started'):
            video_res = self.stop_screen_recording()
            rec_state['started'] = False
          if video_res:
            intent_res['video_recording'] = video_res
          return intent_res
        logging.info('Falling back to CHIPTool UI automation for Thread')

      # 1. Launch CHIPToolActivity cleanly, warming up to dismiss
      # first-run splash.
      self.dismiss_system_dialogs()
      self.container.exec_run(
          'adb shell am force-stop com.google.chip.chiptool'
      )
      time.sleep(0.5)
      self.container.exec_run('adb logcat -c')
      self.container.exec_run(
          'adb shell am start -n com.google.chip.chiptool/.CHIPToolActivity'
      )
      time.sleep(4.0)
      self.dismiss_system_dialogs()

      # 2. Tap PROVISION CHIP DEVICE WITH THREAD button and verify transition
      barcode_xml = ''
      start_prov = time.time()
      while time.time() - start_prov < 15.0:
        self.dismiss_system_dialogs()
        self.tap_ui_element(
            resource_id='provisionThreadCredentialsBtn',
            text='Provision CHIP device with Thread',
            fallback_coords=(357, 650),
            timeout_sec=5.0,
        )
        time.sleep(1.5)
        barcode_xml = self.dump_ui_hierarchy()
        if 'manualCodeBtn' in barcode_xml:
          break

      # Allow CameraX extra time to settle before tapping manual code
      time.sleep(2.5)

      # 3. Enter manual code if custom provided; default is pre-filled with
      # 34970112332
      if manual_code and str(manual_code).strip() != '34970112332':
        self.input_text_ui_element(
            manual_code,
            resource_id='manualCodeEditText',
            fallback_coords=(400, 2270),
            timeout_sec=10.0,
            xml_snapshot=barcode_xml,
        )

      # Tap SUBMIT / MANUAL CODE button and verify code submission in logcat
      start_sub = time.time()
      while time.time() - start_sub < 15.0:
        self.dismiss_system_dialogs()
        self.tap_ui_element(
            resource_id='manualCodeBtn',
            text='Submit',
            fallback_coords=(964, 2274),
            timeout_sec=5.0,
            xml_snapshot=barcode_xml,
        )
        barcode_xml = ''
        time.sleep(1.0)
        res = self.container.exec_run(
            'adb shell "logcat -d | grep \'Submit Code:\'"'
        )
        if b'Submit Code:' in res.output:
          break
      time.sleep(2.0)

      # 4. In Thread screen: dump static layout once, then enter dataset fields.
      # An explicit 'ui' trigger types every provided field (even when it
      # equals CHIPTool's pre-filled default) so the recording shows the
      # dataset being entered; the 'auto' fallback only types differences.
      thread_xml = self.dump_ui_hierarchy()
      type_all = trigger == 'ui'
      if channel is not None and (type_all or int(channel) != 15):
        self.input_text_ui_element(
            str(channel),
            resource_id='channelEd',
            fallback_coords=(540, 650),
            timeout_sec=10.0,
            clear_all=type_all,
            xml_snapshot=thread_xml,
            clear_count=4 if type_all else None,
            hide_keyboard=False,
        )
      norm_pan = (
          str(pan_id).strip().lower().replace('0x', '').replace(':', '').upper()
          if pan_id is not None
          else None
      )
      if norm_pan and (type_all or norm_pan != '1234'):
        self.input_text_ui_element(
            norm_pan[:4],
            resource_id='panIdEd',
            fallback_coords=(540, 800),
            timeout_sec=10.0,
            clear_all=type_all,
            xml_snapshot=thread_xml,
            clear_count=6 if type_all else None,
            hide_keyboard=False,
        )
      norm_xpan = (
          str(xpan_id)
          .strip()
          .lower()
          .replace('0x', '')
          .replace(':', '')
          .upper()
          if xpan_id is not None
          else None
      )
      if norm_xpan and (type_all or norm_xpan != '1111111122222222'):
        formatted_xpan = ':'.join(
            norm_xpan[i : i + 2] for i in range(0, min(len(norm_xpan), 16), 2)
        )
        self.input_text_ui_element(
            formatted_xpan,
            resource_id='xpanIdEd',
            fallback_coords=(540, 950),
            timeout_sec=10.0,
            clear_all=type_all,
            xml_snapshot=thread_xml,
            clear_count=25 if type_all else None,
            hide_keyboard=False,
        )
      norm_key = (
          str(master_key)
          .strip()
          .lower()
          .replace('0x', '')
          .replace(':', '')
          .upper()
          if master_key is not None
          else None
      )
      if norm_key and (
          type_all or norm_key != '00112233445566778899AABBCCDDEEFF'
      ):
        formatted_key = ':'.join(
            norm_key[i : i + 2] for i in range(0, min(len(norm_key), 32), 2)
        )
        self.input_text_ui_element(
            formatted_key,
            resource_id='masterKeyEd',
            fallback_coords=(540, 1100),
            timeout_sec=10.0,
            clear_all=type_all,
            xml_snapshot=thread_xml,
            clear_count=49 if type_all else None,
            hide_keyboard=True,
        )

      self.container.exec_run(
          'adb shell "cmd input_method hide-soft-input 2>/dev/null || true"'
      )

      # Tap SAVE NETWORK button and verify BLE scanning transition in logcat
      start_save = time.time()
      while time.time() - start_save < 15.0:
        self.dismiss_system_dialogs()
        self.tap_ui_element(
            resource_id='saveNetworkBtn',
            text='SAVE NETWORK',
            fallback_coords=(858, 2227),
            timeout_sec=5.0,
            xml_snapshot=thread_xml,
        )
        thread_xml = ''
        time.sleep(1.0)
        res = self.container.exec_run(
            'adb shell "logcat -d | grep \'Scanning for BLE device\'"'
        )
        if b'Scanning for BLE device' in res.output:
          break

      # 5. Poll logcat for commissioning completion
      result = self._wait_for_chiptool_commissioning(timeout_sec)
      result['trigger'] = 'ui'
    finally:
      if rec_state.get('started'):
        video_res = self.stop_screen_recording()

    if video_res:
      result['video_recording'] = video_res
    return result

  def toggle_onoff_via_chiptool_ui(
      self,
      node_id: int = 1,
      endpoint: int = 1,
      timeout_sec: float = 30.0,
      record_video: bool = True,
      video_name: str = '3_onoff_cluster_toggle.mp4',
  ) -> Dict[str, object]:
    """Automates CHIPTool UI to send OnOff Toggle command over CASE Wi-Fi."""
    if self.container is None:
      return {'status': 'failed', 'error': 'Container not running'}

    rec_state = (
        self.start_screen_recording(video_name) if record_video else {}
    )
    video_res = None
    try:
      self.dismiss_system_dialogs()

      # Return to main activity only if SelectActionFragment is not
      # already shown (launching with --activity-clear-top triggers
      # onStop -> stopDnssd).
      ui_xml = self.dump_ui_hierarchy()
      if 'onOffClusterBtn' not in ui_xml and 'LIGHT ON/OFF' not in ui_xml:
        self.container.exec_run(
            'adb shell am start --activity-clear-top --activity-single-top'
            ' -n com.google.chip.chiptool/.CHIPToolActivity'
        )
        time.sleep(2.0)
        self.dismiss_system_dialogs()

      # Tap LIGHT ON/OFF & CLUSTER button
      self.tap_ui_element(
          resource_id='onOffClusterBtn',
          text='LIGHT ON/OFF & LEVEL CLUSTER',
          fallback_coords=(330, 947),
          timeout_sec=12.0,
      )
      time.sleep(1.5)
      self.dismiss_system_dialogs()

      # Tap Toggle button
      self.tap_ui_element(
          resource_id='toggleBtn',
          text='TOGGLE',
          fallback_coords=(537, 730),
          timeout_sec=10.0,
      )

      # Poll logcat for toggle response
      start = time.time()
      success = False
      retapped = False
      logcat_out = ''
      while time.time() - start < timeout_sec:
        res = self.container.exec_run(
            'adb shell logcat -d -s OnOffClientFragment'
        )
        logcat_out = (
            res.output.decode('utf-8', errors='replace')
            if isinstance(res.output, (bytes, bytearray))
            else str(res.output)
        )
        # Only the full OnOff Toggle (command 2) response with status 0
        # counts; bare 'command 2' or 'Code : 0' also match failures and
        # unrelated commands.
        if (
            'Toggle command success' in logcat_out
            or 'command 2, Code : 0' in logcat_out
        ):
          success = True
          break
        if not retapped and time.time() - start >= 10.0:
          retapped = True
          self.dismiss_system_dialogs()
          self.tap_ui_element(
              resource_id='toggleBtn',
              text='TOGGLE',
              fallback_coords=(537, 730),
              timeout_sec=5.0,
          )
        time.sleep(0.5)

      res_dict = {
          'status': 'success' if success else 'failed',
          'logcat': logcat_out.strip(),
          'elapsed_sec': round(time.time() - start, 2),
      }
    finally:
      if rec_state.get('started'):
        video_res = self.stop_screen_recording()

    if video_res:
      res_dict['video_recording'] = video_res
    return res_dict

  def read_onoff_via_chiptool_ui(
      self,
      node_id: int = 1,
      endpoint: int = 1,
      timeout_sec: float = 30.0,
      record_video: bool = True,
      video_name: str = '3_onoff_cluster_read.mp4',
  ) -> Dict[str, object]:
    """Automates CHIPTool UI to read On/Off attribute value over CASE Wi-Fi."""
    if self.container is None:
      return {'status': 'failed', 'error': 'Container not running'}

    rec_state = (
        self.start_screen_recording(video_name) if record_video else {}
    )
    video_res = None
    try:
      self.dismiss_system_dialogs()

      # Tap Read button
      self.tap_ui_element(
          resource_id='readBtn',
          text='READ',
          fallback_coords=(166, 884),
          timeout_sec=10.0,
      )

      # Poll logcat for attribute value
      start = time.time()
      value = None
      retapped = False
      logcat_out = ''
      while time.time() - start < timeout_sec:
        res = self.container.exec_run(
            'adb shell logcat -d -s OnOffClientFragment'
        )
        logcat_out = (
            res.output.decode('utf-8', errors='replace')
            if isinstance(res.output, (bytes, bytearray))
            else str(res.output)
        )
        val_match = re.search(
            r'On/Off attribute value:\s*(true|false|\d+)', logcat_out
        )
        if val_match:
          value = val_match.group(1)
          break
        if not retapped and time.time() - start >= 10.0:
          retapped = True
          self.dismiss_system_dialogs()
          self.tap_ui_element(
              resource_id='readBtn',
              text='READ',
              fallback_coords=(166, 884),
              timeout_sec=5.0,
          )
        time.sleep(0.5)

      res_dict = {
          'status': 'success' if value is not None else 'failed',
          'value': value,
          'logcat': logcat_out.strip(),
          'elapsed_sec': round(time.time() - start, 2),
      }
    finally:
      if rec_state.get('started'):
        video_res = self.stop_screen_recording()

    if video_res:
      res_dict['video_recording'] = video_res
    return res_dict

  def commission_device_via_ui(
      self,
      network_type: str = 'wifi',
      **kwargs: Any,
  ) -> Dict[str, object]:
    """Generic UI commissioning alias dispatching to WiFi or Thread flow."""
    if network_type.lower() == 'thread' or 'channel' in kwargs or 'pan_id' in kwargs:
      kwargs.pop('network_type', None)
      return self.commission_thread_via_chiptool_ui(**kwargs)
    kwargs.pop('network_type', None)
    return self.commission_via_chiptool_ui(**kwargs)

  def toggle_cluster_via_ui(
      self,
      node_id: int = 1,
      endpoint: int = 1,
      cluster: str = 'onoff',
      timeout_sec: float = 30.0,
      **kwargs: Any,
  ) -> Dict[str, object]:
    """Generic UI toggle alias for cluster control."""
    del cluster
    return self.toggle_onoff_via_chiptool_ui(
        node_id=node_id, endpoint=endpoint, timeout_sec=timeout_sec, **kwargs
    )

  def read_cluster_via_ui(
      self,
      node_id: int = 1,
      endpoint: int = 1,
      cluster: str = 'onoff',
      attribute: str = 'onoff',
      timeout_sec: float = 30.0,
      **kwargs: Any,
  ) -> Dict[str, object]:
    """Generic UI read alias for cluster attributes."""
    del cluster, attribute
    return self.read_onoff_via_chiptool_ui(
        node_id=node_id, endpoint=endpoint, timeout_sec=timeout_sec, **kwargs
    )

  def stop_emulator(self) -> None:
    """Stops the Android emulator gracefully."""
    if self.container is None:
      return
    self.container.exec_run(
        'sh -c "adb emu kill 2>/dev/null || '
        "pkill -9 -f '[q]emu-system|[e]mulator|[v]wifi_l2_agent.py' "
        '2>/dev/null || true"'
    )
    self._clean_avd_locks_and_runtime()

  def stop(self) -> None:
    """Stops container, cleaning emulator runtime locks before shutdown."""
    if hasattr(self, 'container') and self.container:
      try:
        self.stop_emulator()
      except Exception as e:  # pylint: disable=broad-exception-caught
        logging.debug('Cleanup on stop encountered transient error: %s', e)
    super().stop()

  def run_chiptool(
      self,
      subcommand_args: Union[str, Sequence[str]],
      user: str = 'root',
      chip_tool_bin: Optional[str] = None,
  ):
    """Executes chip-tool command inside the container."""
    if self.container is None:
      return 1, 'Container is not running'
    if isinstance(subcommand_args, (list, tuple)):
      args_str = ' '.join(str(a) for a in subcommand_args)
    else:
      args_str = str(subcommand_args)

    if not chip_tool_bin:
      check_res = self.container.exec_run('which chip-tool', user=user)
      if check_res.exit_code == 0:
        chip_tool_bin = 'chip-tool'
      else:
        env_tool = os.environ.get('CHIP_TOOL_BIN')
        candidates = [
            env_tool,
            '/connectedhomeip/out/linux-x64-chip-tool/chip-tool',
            '/chip-vbt/out/linux-x64-chip-tool/chip-tool',
        ]
        found_bin = None
        for candidate in candidates:
          if candidate:
            chk = self.container.exec_run(f'test -x {candidate}', user=user)
            if chk.exit_code == 0:
              found_bin = candidate
              break
        chip_tool_bin = found_bin if found_bin else 'chip-tool'

    return self.container.exec_run(f'{chip_tool_bin} {args_str}', user=user)

  def run_chiptool_ble_wifi_commission(
      self,
      node_id: Union[int, str],
      ssid: str,
      psk: str,
      setup_pin_code: int = 20202021,
      discriminator: int = 3840,
      ble_controller: Optional[int] = 0,
      bypass_attestation_verifier: bool = True,
      chip_tool_bin: Optional[str] = None,
  ):
    """Executes BLE-to-Wi-Fi commissioning using chip-tool."""
    cmd_parts = [
        'pairing',
        'ble-wifi',
        str(node_id),
        str(ssid),
        str(psk),
        str(setup_pin_code),
        str(discriminator),
    ]
    if ble_controller is not None:
      cmd_parts.append(f'--ble-controller {ble_controller}')
    if bypass_attestation_verifier:
      cmd_parts.append('--bypass-attestation-verifier true')
    cmd = ' '.join(cmd_parts)
    return self.run_chiptool(cmd, chip_tool_bin=chip_tool_bin)

  @property
  def description(self) -> Dict[str, object]:
    """Returns runtime network and Android node metadata."""
    desc = super().description
    desc.update({
        'avd_name': self.avd_name,
        'adb_port': self.adb_port,
        'adb_serial': self.adb_serial,
        'enable_kvm': self.enable_kvm,
        'runtime_mode': self.runtime_mode,
        'bluetooth_hci_socket': self.get_bluetooth_hci_socket_path(),
        'tap_interface': self.tap_interface,
        'is_tap_station': self.is_tap_station,
        'radio_feature_flags': self.radio_feature_flags,
        'chiptool_apk': getattr(self, 'chiptool_apk', ''),
    })
    return desc

