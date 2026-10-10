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
"""Declarative Virtual Home Topology Builder & E2E Multi-Docker RF Verifier.

Provides reusable topology specifications and end-to-end verification routines
so external GitHub repositories and developers can spin up multi-container
Cirque Virtual Homes with kernel-module-free Virtual Bluetooth (`virtbt` over
TCP) and Virtual Wi-Fi (`virtual_wifi` over TCP + `fi.w1.wpa_supplicant1` D-Bus)
inside standard unprivileged CI runners (such as GitHub Actions
`ubuntu-latest`).
"""

from dataclasses import dataclass
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

logger = logging.getLogger(__name__)

# Primary constants for Virtual Home topologies
DEFAULT_HOME_SUBNET = '10.0.1.0/24'
DEFAULT_HOME_SSID = 'CirqueHomeAP'
DEFAULT_HOME_PSK = 'cirquewifipassword'
DEFAULT_THREAD_PREFIX = 'fd11:33::/64'
DEFAULT_WIFI_IPV6_PREFIX = 'fd11:22::/64'
DEFAULT_THREAD_MESH_LOCAL_PREFIX = 'fdde:ad00:beef:0::/64'
DEFAULT_UDP_SERVICE_PORT = 5540
DEFAULT_TBR_CONTROL_PORT = 5541

# Backward-compatible aliases
DEFAULT_MATTER_SUBNET = DEFAULT_HOME_SUBNET
DEFAULT_MATTER_SSID = DEFAULT_HOME_SSID
DEFAULT_MATTER_PSK = DEFAULT_HOME_PSK
DEFAULT_MATTER_THREAD_PREFIX = DEFAULT_THREAD_PREFIX
DEFAULT_MATTER_WIFI_IPV6_PREFIX = DEFAULT_WIFI_IPV6_PREFIX
DEFAULT_MATTER_MESH_LOCAL_PREFIX = DEFAULT_THREAD_MESH_LOCAL_PREFIX
DEFAULT_MATTER_PORT = DEFAULT_UDP_SERVICE_PORT

# Helper executed inside the device container next to otbr-agent.
#
# Android controller's AddOrUpdateThreadNetwork carries a 37-byte partial
# operational dataset (channel, PAN ID, extended PAN ID and network key only).
# OpenThread never forms a new partition from a partially complete active
# dataset; it keeps sending Parent Requests and Announces looking for an
# existing leader, so the D-Bus Attach issued by ConnectNetwork would time out
# on an otherwise empty simulated mesh. The helper waits for otbr-agent to
# enter the detached role, re-commits the commissioned parameters together
# with the missing mandatory fields, and asks the stack to become leader.
# The commissioned channel, PAN ID, extended PAN ID and network key are
# preserved verbatim.
OTBR_DATASET_COMPLETION_HELPER = r'''
import re, subprocess, time
def sh(cmd):
  try:
    out = subprocess.check_output(
        cmd, shell=True, stderr=subprocess.STDOUT
    ).decode("utf-8", "replace").strip()
    print(f"+ {cmd} -> {out}", flush=True)
    return out
  except Exception as e:
    print(f"+ {cmd} -> ERR: {e}", flush=True)
    return ""
print("Helper started", flush=True)
for _ in range(300):
  time.sleep(0.4)
  state = sh("ot-ctl state")
  if "leader" in state or "router" in state or "child" in state:
    print(f"Target state reached: {state}", flush=True)
    break
  if "detached" in state:
    act = sh("ot-ctl dataset active")
    chan_m = re.search(r"Channel:\s*(\d+)", act)
    pan_m = re.search(r"(?<!Ext )PAN ID:\s*(0x[0-9a-fA-F]+)", act)
    xpan_m = re.search(r"Ext PAN ID:\s*([0-9a-fA-F]+)", act)
    key_m = re.search(r"Network Key:\s*([0-9a-fA-F]+)", act)
    if xpan_m and key_m:
      chan = chan_m.group(1) if chan_m else "15"
      pan = pan_m.group(1) if pan_m else "0x1234"
      xpan = xpan_m.group(1)
      key = key_m.group(1)
      sh("ot-ctl thread stop")
      sh("ot-ctl dataset init new")
      sh("ot-ctl dataset activetimestamp 1")
      sh("ot-ctl dataset networkname CirqueThread")
      sh("ot-ctl dataset meshlocalprefix fdde:ad00:beef:0::")
      sh(f"ot-ctl dataset channel {chan}")
      sh(f"ot-ctl dataset panid {pan}")
      sh(f"ot-ctl dataset extpanid {xpan}")
      sh(f"ot-ctl dataset networkkey {key}")
      sh("ot-ctl dataset commit active")
      sh("ot-ctl ifconfig up")
      sh("ot-ctl thread start")
      time.sleep(0.2)
      sh("ot-ctl state leader")
      sh("ot-ctl route add fd11:22::/64 s med")
      sh("ot-ctl netdata register")
      print("Committed dataset and requested leader", flush=True)
      time.sleep(1.0)
      st = sh("ot-ctl state")
      if "leader" in st:
        print(f"Became leader: {st}", flush=True)
        break
'''

# Generic Thread End Device joiner helper script.
THREAD_JOINER_ATTACH_HELPER = r'''
import glob, os, re, socket, struct, subprocess, sys, time

def sh(cmd):
  try:
    out = subprocess.check_output(
        cmd, shell=True, stderr=subprocess.STDOUT
    ).decode("utf-8", "replace").strip()
    print(f"+ {cmd} -> {out}", flush=True)
    return out
  except Exception as e:
    print(f"+ {cmd} -> ERR: {e}", flush=True)
    return ""

def query_local_matter_instance():
  q = (
      b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
      b"\x07_matter\x04_tcp\x05local\x00\x00\x0c\x00\x01"
  )
  pat = re.compile(r"([0-9A-Fa-f]{16}-[0-9A-Fa-f]{16})")
  targets = (
      (socket.AF_INET6, ("::1", 5353)),
      (socket.AF_INET, ("127.0.0.1", 5353)),
  )
  for fam, addr in targets:
    try:
      s = socket.socket(fam, socket.SOCK_DGRAM)
      s.settimeout(0.3)
      s.sendto(q, addr)
      resp, _ = s.recvfrom(2048)
      s.close()
      text = resp.decode("latin-1", "ignore")
      m = pat.search(text)
      if m:
        return m.group(1).upper()
    except OSError as e:
      sys.stderr.write(f"Note: DNS probe {addr} skipped: {e}\n")
  return None

print("Thread joiner attach helper started", flush=True)
attached = False
for _ in range(300):
  time.sleep(0.4)
  state = sh("ot-ctl state")
  if any(s in state for s in ("child", "router")):
    print(f"Attached to parent as {state}", flush=True)
    attached = True
    break
  if "leader" in state:
    print(f"Already leader: {state}", flush=True)
    attached = True
    break
  if "detached" in state or "Dataset:present" in state or "disabled" in state:
    act = sh("ot-ctl dataset active")
    chan_m = re.search(r"Channel:\s*(\d+)", act)
    pan_m = re.search(r"(?<!Ext )PAN ID:\s*(0x[0-9a-fA-F]+)", act)
    xpan_m = re.search(r"Ext PAN ID:\s*([0-9a-fA-F]+)", act)
    key_m = re.search(r"Network Key:\s*([0-9a-fA-F]+)", act)
    if xpan_m and key_m:
      chan = chan_m.group(1) if chan_m else "15"
      pan = pan_m.group(1) if pan_m else "0x1234"
      xpan = xpan_m.group(1)
      key = key_m.group(1)
      sh("ot-ctl thread stop")
      sh("ot-ctl dataset init new")
      sh("ot-ctl dataset activetimestamp 1")
      sh("ot-ctl dataset networkname CirqueThread")
      sh("ot-ctl dataset meshlocalprefix fdde:ad00:beef:0::")
      sh(f"ot-ctl dataset channel {chan}")
      sh(f"ot-ctl dataset panid {pan}")
      sh(f"ot-ctl dataset extpanid {xpan}")
      sh(f"ot-ctl dataset networkkey {key}")
      sh("ot-ctl dataset commit active")
      sh("ot-ctl ifconfig up")
      sh("ot-ctl thread start")
      print("Committed active dataset, waiting up to 10s for parent attach...", flush=True)
      for _ in range(25):
        time.sleep(0.4)
        st = sh("ot-ctl state")
        if any(s in st for s in ("child", "router")):
          attached = True
          break
      if not attached and os.environ.get("CIRQUE_THREAD_ALLOW_STANDALONE_LEADER", "0") == "1":
        print("No parent attached within 10s, falling back to standalone leader", flush=True)
        sh("ot-ctl state leader")
        time.sleep(0.5)
        st = sh("ot-ctl state")
        if "leader" in st:
          attached = True
      break

st = sh("ot-ctl state")
if any(s in st for s in ("child", "router", "leader")):
  sh("ip -6 addr replace fd11:33::2/64 dev wpan0 nodad")
  sh("ip -6 route replace fd11:22::/64 via fd11:33::1 dev wpan0")
  sh("ip -6 route replace fdde:ad00:beef:0::/64 dev wpan0")
  print("Configured wpan0 IPv6 and routes", flush=True)

  instance_name = query_local_matter_instance()
  pattern = re.compile(r"\b([0-9A-F]{16}-[0-9A-F]{16})\b", re.IGNORECASE)
  log_files = ["/var/log/syslog"] + glob.glob("/tmp/*.log")
  if not instance_name:
    for log_file in log_files:
      if not os.path.exists(log_file):
        continue
      try:
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
          content = f.read()
          m = pattern.search(content)
          if m:
            instance_name = m.group(1).upper()
            break
      except (IOError, OSError) as e:
        sys.stderr.write(f"Warning: could not read {log_file}: {e}\n")

  if not instance_name:
    sys.stderr.write("Could not find instance name in logs.\n")
    sys.exit(1)

  # Find the IPv6 address on wpan0
  ip6 = None
  try:
    import subprocess
    ip_out = subprocess.check_output("ip -6 addr show dev wpan0 scope global", shell=True).decode("utf-8")
    m = re.search(r"inet6 ([a-f0-9:]+)/", ip_out)
    if m:
      ip6 = m.group(1)
  except Exception as e:
    sys.stderr.write(f"Failed to get wpan0 IP: {e}\n")
    
  if not ip6:
    ip_out = sh("ot-ctl ipaddr")
    for line in ip_out.splitlines():
      if line.startswith("fd") and "ff:fe00" not in line:
        ip6 = line.strip()
        break
        
  if not ip6:
    ip6 = "fd11:33::2"
    
  print(f"[SRP-Shim] Registering SRP for {instance_name} with IP {ip6}", flush=True)
  sh(f"ot-ctl srp client host name {instance_name}")
  sh(f"ot-ctl srp client host address {ip6}")
  # Use hardcoded TTLs and service string like in original shim
  sh(f"ot-ctl srp client service add {instance_name} _matter._tcp 5540 0 0 075349493D353030075341493D33303003543D31")
  sh("ot-ctl srp client autostart enable")
  print("[SRP-Shim] SRP registration requested", flush=True)
  
  while True:
    time.sleep(3600)
'''

# Generic ThreadBorderRouter proxy helper script.
THREAD_BORDER_ROUTER_PROXY_HELPER = r'''
import os, select, socket, subprocess, sys, time

CONTROL_PORT = int(os.environ.get("CIRQUE_TBR_CONTROL_PORT", 5541))
SERVICE_PORT = int(os.environ.get("CIRQUE_TBR_SERVICE_PORT", 5540))
DEFAULT_TARGET_IP = os.environ.get("CIRQUE_TBR_TARGET_IP", "fd11:33::2")
DEFAULT_TARGET_PORT = int(os.environ.get("CIRQUE_TBR_TARGET_PORT", 5540))

target_endpoint = (DEFAULT_TARGET_IP, DEFAULT_TARGET_PORT)
client_endpoint = None

def publish_avahi_service(instance_name, service_type="_matter._tcp", port=5540):
  try:
    os.makedirs("/etc/avahi/services", exist_ok=True)
    xml_content = f"""<?xml version="1.0" standalone='no'?>
<!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group>
  <name replace-wildcards="yes">{instance_name}</name>
  <service>
    <type>{service_type}</type>
    <port>{port}</port>
  </service>
</service-group>
"""
    svc_path = f"/etc/avahi/services/tbr_{instance_name}.service"
    with open(svc_path, "w", encoding="utf-8") as f:
      f.write(xml_content)
    subprocess.run("avahi-daemon -r || killall -HUP avahi-daemon || true", shell=True, check=False)
    print(f"Published Avahi service {instance_name} ({service_type}) on port {port}", flush=True)
  except Exception as e:
    print(f"Failed to publish Avahi service: {e}", flush=True)

ctrl_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
try:
  ctrl_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
except (AttributeError, OSError) as e:
  sys.stderr.write(f"Note: setsockopt IPV6_V6ONLY ignored: {e}\n")
ctrl_sock.bind(("::", CONTROL_PORT))

data_sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
try:
  data_sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
except (AttributeError, OSError) as e:
  sys.stderr.write(f"Note: setsockopt IPV6_V6ONLY ignored: {e}\n")
data_sock.bind(("::", SERVICE_PORT))

print(f"ThreadBorderRouter Proxy Helper started on ports {CONTROL_PORT} and {SERVICE_PORT}", flush=True)
sockets = [ctrl_sock, data_sock]

while True:
  try:
    readable, _, _ = select.select(sockets, [], [], 1.0)
    for s in readable:
      if s is ctrl_sock:
        data, addr = ctrl_sock.recvfrom(4096)
        text = data.decode("utf-8", "replace").strip()
        print(f"Control packet from {addr}: {text}", flush=True)
        if text.startswith("REGISTER"):
          parts = text.split()
          if len(parts) >= 4:
            inst = parts[1]
            tip = parts[2]
            tport = int(parts[3])
            stype = parts[4] if len(parts) > 4 else "_matter._tcp"
            target_endpoint = (tip, tport)
            publish_avahi_service(inst, service_type=stype, port=SERVICE_PORT)
      elif s is data_sock:
        data, addr = data_sock.recvfrom(65535)
        sender_ip = addr[0]
        if sender_ip == target_endpoint[0] or sender_ip.endswith(target_endpoint[0]):
          if client_endpoint is not None:
            data_sock.sendto(data, client_endpoint)
        else:
          client_endpoint = addr
          data_sock.sendto(data, target_endpoint)
  except Exception as e:
    print(f"Proxy helper error: {e}", flush=True)
    time.sleep(0.5)
'''


@dataclass(frozen=True)
class VirtualHomeNodeSpec:
  """Specification for a containerized node in a Cirque Virtual Home."""

  name: str
  device_type: str
  base_image: str = 'cirque-device-base:latest'
  enable_bluetooth: bool = True
  enable_wifi: bool = True
  enable_thread: bool = False
  wifi_auto_connect: bool = False
  bd_addr: Optional[str] = None
  docker_network: str = 'Ipv6'
  mount_pairs: Optional[Sequence[Sequence[str]]] = None
  rcp_mode: bool = False
  custom_capabilities: Optional[Sequence[str]] = None
  extra_capabilities: Optional[Sequence[str]] = None

  def capabilities_list(self) -> List[str]:
    """Returns the ordered list of enabled Cirque capability names."""
    if self.custom_capabilities is not None:
      return list(self.custom_capabilities)
    capabilities: List[str] = []
    if self.enable_bluetooth:
      capabilities.append('Bluetooth')
    if self.enable_wifi:
      capabilities.append('WiFi')
    if self.enable_thread:
      capabilities.append('Thread')
    if self.mount_pairs:
      capabilities.append('Mount')
    if self.extra_capabilities:
      for cap in self.extra_capabilities:
        if cap not in capabilities:
          capabilities.append(cap)
    return capabilities

  def to_device_config(self) -> Dict[str, object]:
    """Converts this immutable spec into a `CirqueHome` device dictionary."""
    config: Dict[str, object] = {
        'type': self.device_type,
        'base_image': self.base_image,
        'capability': self.capabilities_list(),
        'docker_network': self.docker_network,
        'use_virtual_bt_tcp': True,
        'use_virtual_wifi_tcp': True,
        'wifi_auto_connect': self.wifi_auto_connect,
    }
    if self.bd_addr:
      config['bd_addr'] = self.bd_addr
    if self.mount_pairs:
      config['mount_pairs'] = [list(p) for p in self.mount_pairs]
    if self.enable_thread or self.rcp_mode:
      config['rcp_mode'] = True
    if (
        isinstance(config.get('capability'), list)
        and 'TrafficControl' in config['capability']
        and 'traffic_control' not in config
    ):
      config['traffic_control'] = {'latencyMs': 0, 'loss': 0}
    return config


@dataclass(frozen=True)
class VirtualHomeApSpec:
  """Specification for a Virtual Wi-Fi Access Point node in a Cirque Home."""

  name: str = 'wifi_ap'
  ssid: str = 'CIRQUE_HOME_AP'
  wifi_psk: str = 'cirque_home_psk'
  base_image: str = 'cirque-device-base:latest'
  docker_network: str = 'Ipv6'

  def is_wpa2_enabled(self) -> bool:
    """Returns True when a non-empty WPA2 pre-shared key is configured."""
    return bool(self.wifi_psk)

  def to_device_config(self) -> Dict[str, object]:
    """Converts this AP spec into a `CirqueHome` `wifi_ap` configuration."""
    return {
        'type': 'wifi_ap',
        'base_image': self.base_image,
        'ssid': self.ssid,
        'psk': self.wifi_psk,
        'docker_network': self.docker_network,
        'use_virtual_wifi_tcp': self.is_wpa2_enabled(),
    }


class VirtualHomeTopology:
  """Builder and E2E verification harness for Cirque Virtual Homes."""

  def __init__(self, cirque_home: Optional[object] = None):
    self.cirque_home = cirque_home

  @staticmethod
  def build_home_config(
      nodes: Sequence[VirtualHomeNodeSpec],
      ap_spec: Optional[VirtualHomeApSpec] = None,
  ) -> Dict[str, Dict[str, object]]:
    """Constructs a complete `CirqueHome.create_home()` topology dictionary."""
    home_config: Dict[str, Dict[str, object]] = {}
    if ap_spec is not None:
      home_config[ap_spec.name] = ap_spec.to_device_config()
    for node_spec in nodes:
      node_cfg = node_spec.to_device_config()
      if ap_spec is not None and node_spec.enable_wifi:
        node_cfg.setdefault('ssid', ap_spec.ssid)
        node_cfg.setdefault('psk', ap_spec.wifi_psk)
      home_config[node_spec.name] = node_cfg
    return home_config

  @classmethod
  def get_default_controller_bin(
      cls, binary_name: str = 'controller-cli'
  ) -> str:
    """Returns the default in-container path to the controller CLI binary."""
    return os.environ.get(
        'CIRQUE_CONTROLLER_BIN',
        os.environ.get(
            'CHIP_TOOL_BIN',
            f'/cirque-build/out/{binary_name}',
        ),
    )

  @classmethod
  def get_default_chip_tool_bin(cls) -> str:
    """Backward-compatible alias for get_default_controller_bin."""
    return cls.get_default_controller_bin()

  @classmethod
  def get_default_device_app_bin(
      cls, binary_name: str = 'device-app'
  ) -> str:
    """Returns the default in-container path to the device application binary."""
    return os.environ.get(
        'CIRQUE_DEVICE_APP_BIN',
        os.environ.get(
            'CHIP_APP_BIN',
            f'/cirque-build/out/{binary_name}',
        ),
    )

  @classmethod
  def get_default_chip_app_bin(cls) -> str:
    """Backward-compatible alias for get_default_device_app_bin."""
    return cls.get_default_device_app_bin()

  @classmethod
  def get_all_clusters_app_bin(cls) -> str:
    """Backward-compatible alias for get_default_device_app_bin."""
    return cls.get_default_device_app_bin()

  @classmethod
  def resolve_host_build_mount(
      cls,
      binary_name: Optional[str] = None,
      subpath: Optional[str] = None,
  ) -> Optional[Tuple[str, str]]:
    """Resolves host build directory and container mount point."""
    host_root = os.environ.get(
        'CIRQUE_HOST_BUILD_DIR',
        os.environ.get('CHIP_BUILD_ROOT', os.environ.get('CHIP_VBT_PATH', '')),
    )
    if not host_root or not os.path.isdir(host_root):
      rel_out = os.path.abspath(
          os.path.join(
              os.path.dirname(__file__), '..', '..', '..', '..', 'out'
          )
      )
      if os.path.isdir(rel_out):
        target = os.environ.get('CIRQUE_CONTAINER_MOUNT', '/cirque-build/out')
        return (rel_out, target)
      return None

    container_mount = os.environ.get('CIRQUE_CONTAINER_MOUNT')
    if container_mount:
      container_target = container_mount
    elif (
        not os.environ.get('CIRQUE_HOST_BUILD_DIR')
        and not os.environ.get('CHIP_BUILD_ROOT')
        and os.environ.get('CHIP_VBT_PATH')
    ):
      container_target = '/chip-vbt'
    elif binary_name and os.path.exists(os.path.join(host_root, binary_name)):
      container_target = '/cirque-build/out'
    elif subpath and os.path.exists(os.path.join(host_root, subpath)):
      container_target = '/cirque-build/out'
    elif os.path.isdir(os.path.join(host_root, 'out')):
      container_target = '/cirque-build'
    else:
      container_target = '/cirque-build/out'

    return (host_root, container_target)

  @classmethod
  def resolve_chip_mount(
      cls, *args, **kwargs
  ) -> Optional[Tuple[str, str]]:
    """Backward-compatible alias for resolve_host_build_mount."""
    return cls.resolve_host_build_mount(*args, **kwargs)

  @classmethod
  def resolve_chip_build_mount(
      cls, *args, **kwargs
  ) -> Optional[Tuple[str, str]]:
    """Backward-compatible alias for resolve_host_build_mount."""
    return cls.resolve_host_build_mount(*args, **kwargs)

  @classmethod
  def default_two_node_ble_wifi_config(
      cls,
      base_image: str = 'cirque-device-base:latest',
      ssid: str = 'CIRQUE_HOME_AP',
      wifi_psk: str = 'cirque_home_psk',
  ) -> Dict[str, Dict[str, object]]:
    """Builds the canonical 2-Docker-node (Mobile + IoT) + AP topology."""
    ap_spec = VirtualHomeApSpec(
        name='wifi_ap', ssid=ssid, wifi_psk=wifi_psk, base_image=base_image
    )
    evidence_host = os.environ.get('CIRQUE_EVIDENCE_DIR', '')
    pairs = []
    chip_mount = cls.resolve_chip_build_mount()
    if chip_mount:
      pairs.append(chip_mount)
      if chip_mount[1].endswith('/out'):
        pairs.append((chip_mount[0], '/chip-vbt/out'))
      else:
        pairs.append((chip_mount[0], '/chip-vbt'))
    if evidence_host:
      os.makedirs(evidence_host, exist_ok=True)
      pairs.append((evidence_host, '/evidence'))
    mount_pairs = tuple(pairs) if pairs else None
    nodes = (
        VirtualHomeNodeSpec(
            name='mobile_controller',
            device_type='MobileController',
            base_image=base_image,
            bd_addr='AA:BB:CC:DD:EE:01',
            mount_pairs=mount_pairs,
        ),
        VirtualHomeNodeSpec(
            name='iot_end_device',
            device_type='IoTEndDevice',
            base_image=base_image,
            bd_addr='AA:BB:CC:DD:EE:02',
            mount_pairs=mount_pairs,
        ),
    )
    return cls.build_home_config(nodes, ap_spec)

  @classmethod
  def default_android_two_node_ble_wifi_config(
      cls,
      base_image: str = 'cirque-device-base:latest',
      ssid: str = 'CIRQUE_HOME_AP',
      psk: str = 'matter-wifi-pass-123',
      wifi_psk: Optional[str] = None,
  ) -> Dict[str, Dict[str, object]]:
    """Builds the 2-Docker Android Controller + Matter Device + AP topology."""
    effective_psk = wifi_psk if wifi_psk is not None else psk
    ap_spec = VirtualHomeApSpec(
        name='wifi_ap', ssid=ssid, wifi_psk=effective_psk, base_image=base_image
    )
    pairs = []
    chip_mount = cls.resolve_chip_build_mount()
    if chip_mount:
      pairs.append(chip_mount)
      if chip_mount[1].endswith('/out'):
        pairs.append((chip_mount[0], '/chip-vbt/out'))
      else:
        pairs.append((chip_mount[0], '/chip-vbt'))
    mount_pairs = tuple(pairs) if pairs else None
    nodes = (
        VirtualHomeNodeSpec(
            name='android_controller',
            device_type='android_controller',
            base_image=base_image,
            bd_addr='AA:BB:CC:DD:EE:01',
            mount_pairs=mount_pairs,
        ),
        VirtualHomeNodeSpec(
            name='matter_device',
            device_type='IoTEndDevice',
            base_image=base_image,
            bd_addr='AA:BB:CC:DD:EE:02',
            mount_pairs=mount_pairs,
        ),
    )
    return cls.build_home_config(nodes, ap_spec)

  @classmethod
  def default_android_emulator_ble_wifi_config(
      cls,
      base_image: str = 'cirque-android-runner:latest',
      device_base_image: str = 'cirque-device-base:latest',
      ssid: str = 'CIRQUE_HOME_AP',
      wifi_psk: str = 'cirque_home_psk',
      avd_name: str = 'Pixel_6_API_34',
      tap_interface: str = 'cirque_tap0',
      pcap_dir: Optional[str] = None,
      wifi_auto_connect: bool = False,
  ) -> Dict[str, Dict[str, object]]:
    """Builds the Android KVM Emulator + Matter Device + AP topology."""
    if pcap_dir:
      os.environ['CIRQUE_PCAP_DIR'] = pcap_dir
    ap_spec = VirtualHomeApSpec(
        name='wifi_ap',
        ssid=ssid,
        wifi_psk=wifi_psk,
        base_image=device_base_image,
    )
    pairs = []
    chip_mount = cls.resolve_chip_build_mount()
    if chip_mount:
      pairs.append(chip_mount)
      if chip_mount[1].endswith('/out'):
        pairs.append((chip_mount[0], '/chip-vbt/out'))
      else:
        pairs.append((chip_mount[0], '/chip-vbt'))
    mount_pairs = tuple(pairs) if pairs else None
    nodes = (
        VirtualHomeNodeSpec(
            name='android_emulator',
            device_type='android_emulator',
            base_image=base_image,
            bd_addr='AA:BB:CC:DD:EE:01',
            mount_pairs=mount_pairs,
        ),
        VirtualHomeNodeSpec(
            name='matter_device',
            device_type='IoTEndDevice',
            base_image=device_base_image,
            bd_addr='AA:BB:CC:DD:EE:02',
            mount_pairs=mount_pairs,
            wifi_auto_connect=wifi_auto_connect,
        ),
    )
    config = cls.build_home_config(nodes, ap_spec)
    for dev_cfg in config.values():
      if isinstance(dev_cfg, dict):
        dev_cfg.setdefault('labels', {})['owner'] = 't9'
    if 'android_emulator' in config:
      config['android_emulator']['tap_interface'] = tap_interface
      config['android_emulator']['is_tap_station'] = True
      config['android_emulator']['avd_name'] = avd_name
      config['android_emulator']['preferred_mode'] = 'kvm_emulator'
      config['android_emulator']['ssid'] = ssid
      config['android_emulator']['psk'] = wifi_psk
    return config

  @classmethod
  def default_android_emulator_ble_thread_config(
      cls,
      base_image: str = 'cirque-android-runner:latest',
      device_base_image: str = 'cirque-device-base:latest',
      ssid: str = 'CIRQUE_HOME_AP',
      wifi_psk: str = 'cirque_home_psk',
      avd_name: str = 'Pixel_6_API_34',
      tap_interface: str = 'cirque_tap0',
      pcap_dir: Optional[str] = None,
      wifi_auto_connect: bool = True,
  ) -> Dict[str, Dict[str, object]]:
    """Builds the Android KVM Emulator + Thread Matter Device + AP topology."""
    if pcap_dir:
      os.environ['CIRQUE_PCAP_DIR'] = pcap_dir
    ap_spec = VirtualHomeApSpec(
        name='wifi_ap',
        ssid=ssid,
        wifi_psk=wifi_psk,
        base_image=device_base_image,
    )
    pairs = []
    chip_mount = cls.resolve_chip_build_mount()
    if chip_mount:
      pairs.append(chip_mount)
      if chip_mount[1].endswith('/out'):
        pairs.append((chip_mount[0], '/chip-vbt/out'))
      else:
        pairs.append((chip_mount[0], '/chip-vbt'))
    mount_pairs = tuple(pairs) if pairs else None
    nodes = (
        VirtualHomeNodeSpec(
            name='android_emulator',
            device_type='android_emulator',
            base_image=base_image,
            bd_addr='AA:BB:CC:DD:EE:01',
            mount_pairs=mount_pairs,
        ),
        VirtualHomeNodeSpec(
            name='thread_border_router',
            device_type='ThreadBorderRouter',
            base_image=device_base_image,
            enable_bluetooth=False,
            enable_wifi=True,
            enable_thread=True,
            custom_capabilities=['Thread', 'WiFi', 'TrafficControl'],
            rcp_mode=True,
            wifi_auto_connect=True,
        ),
        VirtualHomeNodeSpec(
            name='matter_device',
            device_type='IoTEndDevice',
            base_image=device_base_image,
            bd_addr='AA:BB:CC:DD:EE:02',
            mount_pairs=mount_pairs,
            enable_bluetooth=True,
            enable_wifi=False,
            enable_thread=True,
            custom_capabilities=(
                ['Thread', 'Bluetooth', 'TrafficControl', 'Mount']
                if mount_pairs
                else ['Thread', 'Bluetooth', 'TrafficControl']
            ),
            rcp_mode=True,
            wifi_auto_connect=False,
        ),
    )
    config = cls.build_home_config(nodes, ap_spec)
    for dev_cfg in config.values():
      if isinstance(dev_cfg, dict):
        dev_cfg.setdefault('labels', {})['owner'] = 't10'
    if 'android_emulator' in config:
      config['android_emulator']['tap_interface'] = tap_interface
      config['android_emulator']['is_tap_station'] = True
      config['android_emulator']['avd_name'] = avd_name
      config['android_emulator']['preferred_mode'] = 'kvm_emulator'
      config['android_emulator']['ssid'] = ssid
      config['android_emulator']['psk'] = wifi_psk
    return config

  @classmethod
  def form_thread_border_router_network(
      cls,
      cirque_home: object,
      tbr_id: str,
      channel: int = 15,
      pan_id: str = '0x1234',
      ext_pan_id: str = '1111111122222222',
      network_key: str = '00112233445566778899aabbccddeeff',
      mesh_local_prefix: str = 'fdde:ad00:beef:0::',
      on_mesh_prefix: str = 'fd11:33::/64',
      tbr_wpan_ip: str = 'fd11:33::1/64',
  ) -> Dict[str, Any]:
    """Forms a Thread network on the ThreadBorderRouter node as leader."""
    cls._exec_in_node(
        cirque_home,
        tbr_id,
        'if ! pidof otbr-agent >/dev/null 2>&1; then '
        'otbr-agent -I wpan0 "spinel+hdlc+uart:///dev/ttyUSB0" '
        '>/tmp/otbr-agent.log 2>&1 & sleep 1; fi',
    )
    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl factoryreset || true')
    time.sleep(1.0)
    for _ in range(20):
      out = cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl state').strip()
      if 'disabled' in out:
        break
      time.sleep(0.5)

    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl thread stop || true')
    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl dataset init new')
    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl dataset activetimestamp 1')
    cls._exec_in_node(cirque_home, tbr_id, f'ot-ctl dataset channel {channel}')
    cls._exec_in_node(cirque_home, tbr_id, f'ot-ctl dataset panid {pan_id}')
    cls._exec_in_node(cirque_home, tbr_id, f'ot-ctl dataset extpanid {ext_pan_id}')
    cls._exec_in_node(cirque_home, tbr_id, f'ot-ctl dataset networkkey {network_key}')
    cls._exec_in_node(cirque_home, tbr_id, f'ot-ctl dataset meshlocalprefix {mesh_local_prefix}')
    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl dataset networkname CirqueTBR')
    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl dataset commit active')
    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl ifconfig up')
    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl thread start')
    time.sleep(0.5)
    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl state leader')
    time.sleep(1.0)

    cls._exec_in_node(cirque_home, tbr_id, f'ot-ctl prefix add {on_mesh_prefix} paros med')
    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl route add fd11:22::/64 s med')
    cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl netdata register')

    cls._exec_in_node(cirque_home, tbr_id, f'ip -6 addr replace {tbr_wpan_ip} dev wpan0 nodad')
    cls._exec_in_node(cirque_home, tbr_id, 'ip -6 route replace fd11:22::/64 dev wlan0 || true')

    return cls.get_thread_active_dataset(cirque_home, tbr_id)

  @classmethod
  def get_thread_active_dataset(
      cls, cirque_home: object, tbr_id: str
  ) -> Dict[str, Any]:
    """Queries ot-ctl dataset active and returns parsed parameters."""
    act_out = cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl dataset active')
    act_hex = cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl dataset active -x').strip()
    state = cls._exec_in_node(cirque_home, tbr_id, 'ot-ctl state').strip()

    chan_m = re.search(r'Channel:\s*(\d+)', act_out)
    pan_m = re.search(r'(?<!Ext )PAN ID:\s*(0x[0-9a-fA-F]+|\d+)', act_out)
    xpan_m = re.search(r'Ext PAN ID:\s*([0-9a-fA-F]+)', act_out)
    key_m = re.search(r'Network Key:\s*([0-9a-fA-F]+)', act_out)
    mlp_m = re.search(r'Mesh Local Prefix:\s*([0-9a-fA-F:]+)', act_out)

    pan_val = pan_m.group(1) if pan_m else '0x1234'
    if not pan_val.startswith('0x'):
      try:
        pan_val = hex(int(pan_val))
      except ValueError:
        pan_val = '0x1234'

    hex_lines = [line.strip() for line in act_hex.splitlines() if line.strip() and 'Done' not in line]
    tlvs_hex = ''.join(hex_lines)

    return {
        'channel': int(chan_m.group(1)) if chan_m else 15,
        'pan_id': pan_val,
        'ext_pan_id': xpan_m.group(1) if xpan_m else '1111111122222222',
        'network_key': key_m.group(1) if key_m else '00112233445566778899aabbccddeeff',
        'mesh_local_prefix': mlp_m.group(1) if mlp_m else 'fdde:ad00:beef:0::',
        'dataset_tlvs_hex': tlvs_hex,
        'state': state,
    }

  @classmethod
  def start_thread_border_router_proxy(
      cls,
      cirque_home: object,
      tbr_id: str,
      default_target_ip: str = 'fd11:33::2',
      service_port: int = 5540,
      control_port: int = 5541,
  ) -> None:
    """Starts the ThreadBorderRouter proxy helper on the TBR node."""
    import base64

    b64_proxy = base64.b64encode(
        THREAD_BORDER_ROUTER_PROXY_HELPER.encode('utf-8')
    ).decode('ascii')
    cmd = (
        'kill -9 $(cat /tmp/tbr_proxy.pid 2>/dev/null) 2>/dev/null || true; '
        f'echo "{b64_proxy}" | base64 -d > /tmp/tbr_proxy_helper.py && '
        f'CIRQUE_TBR_CONTROL_PORT={control_port} CIRQUE_TBR_SERVICE_PORT={service_port} '
        f'CIRQUE_TBR_TARGET_IP={default_target_ip} CIRQUE_TBR_TARGET_PORT={service_port} '
        'nohup python3 /tmp/tbr_proxy_helper.py >/tmp/tbr_proxy.log 2>&1 & '
        'echo $! > /tmp/tbr_proxy.pid'
    )
    cls._exec_in_node(cirque_home, tbr_id, cmd)

  @classmethod
  def prepare_thread_end_device_joiner(
      cls,
      cirque_home: object,
      device_id: str,
      end_device_wpan_ip: str = 'fd11:33::2/64',
      tbr_wpan_ip: str = 'fd11:33::1',
  ) -> None:
    """Prepares and starts the Thread joiner attach helper on the end device."""
    import base64

    b64_helper = base64.b64encode(
        THREAD_JOINER_ATTACH_HELPER.encode('utf-8')
    ).decode('ascii')
    cmd = (
        'kill -9 $(cat /tmp/dataset_helper.pid 2>/dev/null) 2>/dev/null || true; '
        f'echo "{b64_helper}" | base64 -d > /tmp/dataset_helper.py && '
        f'CIRQUE_TBR_CONTROL_ADDR={tbr_wpan_ip} '
        'nohup python3 /tmp/dataset_helper.py >/tmp/dataset_helper.log 2>&1 & '
        'echo $! > /tmp/dataset_helper.pid'
    )
    cls._exec_in_node(cirque_home, device_id, cmd)

  @staticmethod
  def _exec_in_node_with_exit_code(
      cirque_home, node_id: str, cmd: str
  ) -> Tuple[int, str]:
    """Executes a command inside a Cirque node and returns (exit_code, output_text)."""
    # Always wrap in sh -c so globs (*), redirects, pipes, and compound commands work
    if not (
        cmd.startswith("sh -c '")
        or cmd.startswith('sh -c "')
        or cmd.startswith("/bin/sh -c '")
        or cmd.startswith('/bin/sh -c "')
    ):
      escaped_cmd = cmd.replace("'", "'\"'\"'")
      cmd = f"sh -c '{escaped_cmd}'"
    result = cirque_home.execute_device_cmd(cmd, node_id, stream=False)
    exit_code = getattr(result, 'exit_code', 0)
    output = getattr(result, 'output', result)
    if isinstance(output, (bytes, bytearray)):
      output_str = bytes(output).decode('utf-8', errors='replace')
    else:
      output_str = str(output)
    return exit_code, output_str

  @classmethod
  def _exec_in_node(cls, cirque_home, node_id: str, cmd: str) -> str:
    """Executes a shell command inside a Cirque node and returns UTF-8 text."""
    return cls._exec_in_node_with_exit_code(cirque_home, node_id, cmd)[1]

  @classmethod
  def _read_wpa_state(cls, cirque_home, node_id: str) -> str:
    """Queries fi.w1.wpa_supplicant1 for the live interface State property."""
    state_cmd = (
        'gdbus call --system --dest fi.w1.wpa_supplicant1 '
        '--object-path /fi/w1/wpa_supplicant1/Interfaces/0 '
        '--method org.freedesktop.DBus.Properties.Get '
        'fi.w1.wpa_supplicant1.Interface State'
    )
    return cls._exec_in_node(cirque_home, node_id, state_cmd).strip()

  @classmethod
  def verify_virtual_bt_between_nodes(
      cls, cirque_home, controller_id: str, device_id: str
  ) -> Dict[str, str]:
    """Verifies BlueZ D-Bus adapter discovery between two Docker containers.

    Steps executed inside the containers:
      1. Power on `/org/bluez/${BLE_ADAPT:-hci0}` via `Properties.Set`.
      2. Register BLE advertising (`/chipoble/adv0`) on `device_id` via
         `org.bluez.LEAdvertisingManager1.RegisterAdvertisement`.
      3. Trigger active BLE scanning on `controller_id` via
         `org.bluez.Adapter1.StartDiscovery`.
      4. Query `org.freedesktop.DBus.ObjectManager.GetManagedObjects` to verify
         that `controller_id` discovers `device_id` as an `org.bluez.Device1`
         object (`dev_AA_BB_CC_DD_EE_0X`).
    """
    power_cmd = (
        "sh -c 'dbus-send --system --dest=org.bluez --print-reply "
        '/org/bluez/${BLE_ADAPT:-hci0} '
        'org.freedesktop.DBus.Properties.Set '
        "string:org.bluez.Adapter1 string:Powered variant:boolean:true'"
    )
    adv_cmd = (
        "sh -c 'gdbus call --system --dest org.bluez "
        '--object-path /org/bluez/${BLE_ADAPT:-hci1} '
        '--method org.bluez.LEAdvertisingManager1.RegisterAdvertisement '
        '/chipoble/adv0 "{}"\' '
    )
    scan_cmd = (
        "sh -c 'dbus-send --system --dest=org.bluez --print-reply "
        '/org/bluez/${BLE_ADAPT:-hci0} '
        "org.bluez.Adapter1.StartDiscovery'"
    )
    managed_objs_cmd = (
        'dbus-send --system --dest=org.bluez --print-reply / '
        'org.freedesktop.DBus.ObjectManager.GetManagedObjects'
    )
    cls._exec_in_node(cirque_home, device_id, power_cmd)
    cls._exec_in_node(cirque_home, device_id, adv_cmd)
    cls._exec_in_node(cirque_home, controller_id, power_cmd)
    cls._exec_in_node(cirque_home, controller_id, scan_cmd)
    time.sleep(0.3)
    ctrl_info = cls._exec_in_node(cirque_home, controller_id, managed_objs_cmd)
    dev_info = cls._exec_in_node(cirque_home, device_id, managed_objs_cmd)
    return {
        'controller_bt': ctrl_info.strip(),
        'device_bt': dev_info.strip(),
    }

  @classmethod
  def _associate_wpa_and_dhcp(
      cls, cirque_home, node_id: str, ssid: str, wifi_psk: str
  ) -> str:
    """Associates a node over fi.w1.wpa_supplicant1 D-Bus and runs dhcpcd.

    Mirrors the exact 4-step D-Bus sequence performed by Matter's Linux
    `NetworkCommissioningWiFiDriver`:
      1. `GetInterface("wlan0")` -> `/fi/w1/wpa_supplicant1/Interfaces/0`
      2. `Interface.Scan({'Type': 'active'})`
      3. `Interface.AddNetwork({'ssid': ssid, 'psk': wifi_psk})`
      4. `Interface.SelectNetwork(.../Interfaces/0/Networks/0)`
    """
    iface_path = '/fi/w1/wpa_supplicant1/Interfaces/0'
    cls._exec_in_node(
        cirque_home,
        node_id,
        'ip link set dev wlan0 up 2>/dev/null || true',
    )
    get_iface_out = cls._exec_in_node(
        cirque_home,
        node_id,
        (
            'gdbus call --system --dest fi.w1.wpa_supplicant1 '
            '--object-path /fi/w1/wpa_supplicant1 '
            '--method fi.w1.wpa_supplicant1.GetInterface wlan0'
        ),
    )
    if 'Error' in get_iface_out or 'Interfaces' not in get_iface_out:
      cls._exec_in_node(
          cirque_home,
          node_id,
          (
              'gdbus call --system --dest fi.w1.wpa_supplicant1 '
              '--object-path /fi/w1/wpa_supplicant1 '
              '--method fi.w1.wpa_supplicant1.CreateInterface '
              '"{\'Ifname\': <\'wlan0\'>}"'
          ),
      )
    cls._exec_in_node(
        cirque_home,
        node_id,
        (
            'gdbus call --system --dest fi.w1.wpa_supplicant1 '
            f'--object-path {iface_path} '
            '--method fi.w1.wpa_supplicant1.Interface.Scan '
            "\"{'Type': <'active'>}\""
        ),
    )
    add_net_cmd = (
        'gdbus call --system --dest fi.w1.wpa_supplicant1 '
        f'--object-path {iface_path} '
        '--method fi.w1.wpa_supplicant1.Interface.AddNetwork '
        f"\"{{'ssid': <'{ssid}'>, 'psk': <'{wifi_psk}'>}}\""
    )
    add_net_out = cls._exec_in_node(cirque_home, node_id, add_net_cmd)
    match = re.search(
        r'(/fi/w1/wpa_supplicant1/Interfaces/\d+/Networks/\d+)', add_net_out
    )
    net_path = match.group(1) if match else f'{iface_path}/Networks/0'
    cls._exec_in_node(
        cirque_home,
        node_id,
        (
            'gdbus call --system --dest fi.w1.wpa_supplicant1 '
            f'--object-path {iface_path} '
            f'--method fi.w1.wpa_supplicant1.Interface.SelectNetwork {net_path}'
        ),
    )
    wpa_state = cls._read_wpa_state(cirque_home, node_id)
    cls._exec_in_node(
        cirque_home,
        node_id,
        'dhcpcd -n -4 wlan0 2>/dev/null || '
        'dhcpcd -b -4 --noipv4ll wlan0 2>/dev/null || true',
    )
    # Wait up to 10 seconds for IP configuration if needed
    for _ in range(20):
      if cls._read_wlan0_ipv4(cirque_home, node_id):
        break
      time.sleep(0.5)
    return wpa_state

  @classmethod
  def _read_wlan0_ipv4(cls, cirque_home, node_id: str) -> str:
    """Returns the IPv4 address assigned to wlan0 inside a container node."""
    addr_out = cls._exec_in_node(
        cirque_home, node_id, 'ip -4 addr show dev wlan0'
    )
    ip_match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)', addr_out)
    return ip_match.group(1) if ip_match else ''

  @classmethod
  def _read_wlan0_ipv6(
      cls, cirque_home, node_id: str, scope: str = 'global'
  ) -> str:
    """Returns the dynamic SLAAC IPv6 address on wlan0 inside a container node."""
    addr_out = cls._exec_in_node(
        cirque_home, node_id, f'ip -6 addr show dev wlan0 scope {scope}'
    )
    ip_match = re.search(r'inet6\s+(fd11:22:[0-9a-fA-F:]+)/\d+', addr_out)
    if not ip_match:
      ip_match = re.search(r'inet6\s+([0-9a-fA-F:]+)/\d+', addr_out)
    return ip_match.group(1) if ip_match else ''

  @staticmethod
  def _android_hci_frame_count(bt_server: object, bind_id: str) -> int:
    """Returns HCI packets exchanged so far by the emulator's controller."""
    ctrl = None
    if bt_server is not None and hasattr(bt_server, 'get_controller'):
      ctrl = bt_server.get_controller(bind_id)
    if ctrl is None or not hasattr(ctrl, 'to_dict'):
      return 0
    info = ctrl.to_dict()
    if not isinstance(info, dict):
      return 0
    return int(info.get('tx_packets', 0)) + int(info.get('rx_packets', 0))

  @classmethod
  def _android_radio_path(
      cls,
      android_node: object,
      bt_server: object,
      hci_frames_before: int,
      bind_id: str = 'android_hci0',
  ) -> Dict[str, object]:
    """Reports how the emulator radios reach cirque's virtual servers.

    The evidence is positive: the emulator command line disables the
    emulator's built-in Bluetooth emulation and bridges guest Wi-Fi onto
    the tap interface, the cirque controller bound by pty_bridge exists,
    and that controller exchanged HCI packets during the flow.
    """
    path: Dict[str, object] = {}
    if android_node is not None and hasattr(
        android_node, 'describe_radio_path'
    ):
      described = android_node.describe_radio_path()
      if isinstance(described, dict):
        path.update(described)
    ctrl = None
    if bt_server is not None and hasattr(bt_server, 'get_controller'):
      ctrl = bt_server.get_controller(bind_id)
    path['bt_controller_bound'] = ctrl is not None
    path['android_hci_frames'] = max(
        0,
        cls._android_hci_frame_count(bt_server, bind_id) - hci_frames_before,
    )
    return path

  @classmethod
  def verify_virtual_wifi_commissioning_and_data_plane(
      cls,
      cirque_home: object,
      controller_id: str,
      device_id: str,
      ssid: str = 'CIRQUE_HOME_AP',
      psk: str = 'cirque_home_psk',
  ) -> Dict[str, object]:
    """Executes D-Bus Wi-Fi scan, WPA2 association, DHCP, and ping."""
    ctrl_wpa = cls._associate_wpa_and_dhcp(
        cirque_home, controller_id, ssid, psk
    )
    dev_wpa = cls._associate_wpa_and_dhcp(cirque_home, device_id, ssid, psk)
    time.sleep(0.5)
    ctrl_ip = cls._read_wlan0_ipv4(cirque_home, controller_id)
    dev_ip = cls._read_wlan0_ipv4(cirque_home, device_id)
    ping_out = cls._exec_in_node(
        cirque_home, controller_id, f'ping -c 2 -W 2 {dev_ip}'
    )
    return {
        'controller_wpa': ctrl_wpa,
        'device_wpa': dev_wpa,
        'controller_ip': ctrl_ip,
        'device_ip': dev_ip,
        'ping_output': ping_out.strip(),
        'packet_loss_zero': bool(
            re.search(r'(?<!\d)0%\s+packet\s+loss', ping_out)
        ),
    }

  @classmethod
  def _enforce_eth0_mdns_isolation(
      cls, cirque_home: object, node_id: str
  ) -> None:
    """Enforces mDNS (UDP 5353) isolation on eth0 idempotently and verifies it.
    """
    cmds = (
        'iptables -C OUTPUT -o eth0 -p udp --dport 5353 -j DROP 2>/dev/null '
        '|| iptables -I OUTPUT -o eth0 -p udp --dport 5353 -j DROP; '
        'iptables -C INPUT -i eth0 -p udp --dport 5353 -j DROP 2>/dev/null '
        '|| iptables -I INPUT -i eth0 -p udp --dport 5353 -j DROP; '
        'ip6tables -C OUTPUT -o eth0 -p udp --dport 5353 -j DROP 2>/dev/null '
        '|| ip6tables -I OUTPUT -o eth0 -p udp --dport 5353 -j DROP; '
        'ip6tables -C INPUT -i eth0 -p udp --dport 5353 -j DROP 2>/dev/null '
        '|| ip6tables -I INPUT -i eth0 -p udp --dport 5353 -j DROP; '
        'iptables -S OUTPUT; iptables -S INPUT'
    )
    rules_out = cls._exec_in_node(cirque_home, node_id, cmds)
    if (
        '-A OUTPUT -o eth0 -p udp' not in rules_out
        or '-A INPUT -i eth0 -p udp' not in rules_out
        or '5353 -j DROP' not in rules_out
    ):
      raise RuntimeError(
          f'Node {node_id} failed to isolate eth0 mDNS in'
          f' iptables:\n{rules_out}'
      )

  @classmethod
  def clean_device_state_and_restart(
      cls,
      cirque_home: object,
      device_id: str,
      controller_id: Optional[str] = None,
      discriminator: int = 3840,
      passcode: int = 20202021,
      chip_app_bin: Optional[str] = None,
      app_bin: Optional[str] = None,
      timeout_sec: float = 15.0,
  ) -> None:
    """Resets device state and starts a fresh device application.

    Enforces strict operational preconditions:
      1. Kills any running device application and dhcpcd.
      2. Flushes wlan0 and disconnects wpa_supplicant networks on device.
      3. Waits for old process death.
      4. Waits for port 5540 release on device.
      5. Cleans KVS storage (/tmp/chip_*) and previous logs.
      6. If controller_id is provided, cleans controller KVS and kills controller.
      7. Launches fresh device application binary.
      8. Verifies advertising / GATT registration precondition in logs, raising
         RuntimeError if not met.
    """
    effective_app_bin = (
        app_bin
        if app_bin is not None
        else (chip_app_bin if chip_app_bin is not None else cls.get_default_device_app_bin())
    )
    app_proc = os.path.basename(effective_app_bin) if effective_app_bin else 'device-app'

    reset_cmd = (
        '# _exec_in_node in-container wpa reset\n'
        'pkill -9 dhcpcd || true; gdbus call --system --dest'
        ' fi.w1.wpa_supplicant1 --object-path'
        ' /fi/w1/wpa_supplicant1/Interfaces/0 --method'
        ' fi.w1.wpa_supplicant1.Interface.RemoveAllNetworks || true; gdbus'
        ' call --system --dest fi.w1.wpa_supplicant1 --object-path'
        ' /fi/w1/wpa_supplicant1/Interfaces/0 --method'
        ' fi.w1.wpa_supplicant1.Interface.Disconnect || true; ip -4 addr flush'
        ' dev wlan0 || true; ip -6 addr flush dev wlan0 scope global || true;'
        f' killall -9 {app_proc} 2>/dev/null || true;'
        f' pkill -9 -f {app_proc} 2>/dev/null || true; pkill -9 -f all-clusters 2>/dev/null || true;'
        ' fuser -k 5540/tcp 5540/udp || true; rm -rf /tmp/chip_* /tmp/chip-all-clusters.log;'
        ' sysctl -w net.ipv6.conf.wlan0.accept_ra=2 >/dev/null 2>&1 || true;'
        ' sysctl -w net.ipv6.conf.wlan0.autoconf=1 >/dev/null 2>&1 || true;'
        ' (which dhcpcd >/dev/null 2>&1 && dhcpcd -b -4 --noipv4ll wlan0 || true)'
    )
    cls._exec_in_node(cirque_home, device_id, reset_cmd)
    if controller_id:
      ctrl_bin = cls.get_default_controller_bin()
      ctrl_proc = os.path.basename(ctrl_bin) if ctrl_bin else 'controller-cli'
      cls._exec_in_node(
          cirque_home,
          controller_id,
          f'pkill -9 -f {ctrl_proc} || true; pkill -9 -f "tool" 2>/dev/null || true; rm -rf /tmp/chip_*',
      )

    # Wait for process death
    start_time = time.time()
    while time.time() - start_time < timeout_sec:
      ec, out = cls._exec_in_node_with_exit_code(
          cirque_home, device_id, f'pidof {app_proc}'
      )
      if ec != 0 or not out.strip():
        break
      cls._exec_in_node(
          cirque_home,
          device_id,
          f'killall -9 {app_proc} 2>/dev/null || true; pkill -9 -f {app_proc} 2>/dev/null || true; pkill -9 -f all-clusters 2>/dev/null || true',
      )
      time.sleep(0.15)

    # Wait for port 5540 release
    while time.time() - start_time < timeout_sec:
      out = cls._exec_in_node(cirque_home, device_id, 'ss -lntu | grep :5540')
      if not out.strip():
        break
      cls._exec_in_node(
          cirque_home, device_id, 'fuser -k 5540/tcp 5540/udp || true'
      )
      time.sleep(0.2)

    # CRITICAL: Wipe KVS storage and previous logs AFTER old process is completely dead
    cls._exec_in_node(
        cirque_home,
        device_id,
        'rm -rf /tmp/chip_* /tmp/chip-all-clusters.log',
    )
    if controller_id:
      ctrl_bin = cls.get_default_controller_bin()
      ctrl_proc = os.path.basename(ctrl_bin) if ctrl_bin else 'controller-cli'
      cls._exec_in_node(
          cirque_home,
          controller_id,
          f'pkill -9 -f {ctrl_proc} || true; pkill -9 -f "tool" 2>/dev/null || true; rm -rf /tmp/chip_*',
      )

    # Clean any stale virtual Bluetooth components across runs
    try:
      from cirque.capabilities.bluetoothcapability import BlueToothCapability

      if BlueToothCapability._SHARED_BLUEZ_DBUS is not None:
        BlueToothCapability._SHARED_BLUEZ_DBUS.reset_connections()
      if BlueToothCapability._SHARED_VIRTUAL_SERVER is not None:
        BlueToothCapability._SHARED_VIRTUAL_SERVER.reset_all_controllers()
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.warning('Failed to reset shared Bluetooth components: %s', exc)

    # Restrict mDNS (UDP 5353) to wlan0 idempotently and verify drop rules
    for target_node in (device_id, controller_id):
      if target_node:
        cls._enforce_eth0_mdns_isolation(cirque_home, target_node)

    wlan0_ifindex_out = cls._exec_in_node(
        cirque_home,
        device_id,
        'cat /sys/class/net/wlan0/ifindex 2>/dev/null || echo 0',
    ).strip()
    wlan0_ifindex = wlan0_ifindex_out if wlan0_ifindex_out.isdigit() else '0'

    # Launch fresh device application binary with clean KVS and bound to wlan0
    app_cmd = (
        f'nohup {effective_app_bin} --wifi=wlan0'
        f' --interface-id {wlan0_ifindex} --discriminator {discriminator}'
        f' --passcode {passcode} --ble-controller 1 --KVS /tmp/chip_kvs 2>&1'
        ' | tee /tmp/chip-all-clusters.log > /proc/1/fd/1 &'
    )
    cls._exec_in_node(cirque_home, device_id, app_cmd)

    # Assert GATT registration precondition
    gatt_ready = False
    for _ in range(40):
      ec, out = cls._exec_in_node_with_exit_code(
          cirque_home,
          device_id,
          'grep -E "GATT application registered|BLE advertisement started|SET'
          ' service data|CHIP:DL: BLE adv start" /tmp/chip-all-clusters.log',
      )
      if ec == 0 and out.strip():
        gatt_ready = True
        break
      time.sleep(0.25)

    if not gatt_ready:
      log_content = cls._exec_in_node(
          cirque_home,
          device_id,
          'cat /tmp/chip-all-clusters.log',
      )
      raise RuntimeError(
          f'{app_proc} failed to initialize or register'
          f' GATT:\n{log_content}'
      )

  @classmethod
  def clean_chip_device_state_and_restart(cls, *args, **kwargs) -> None:
    """Backward-compatible alias for clean_device_state_and_restart."""
    return cls.clean_device_state_and_restart(*args, **kwargs)

  @classmethod
  def verify_real_chip_ble_wifi_commissioning(
      cls,
      cirque_home: object,
      controller_id: str,
      device_id: str,
      node_id: int = 1001,
      discriminator: int = 3840,
      passcode: int = 20202021,
      setup_pin_code: Optional[int] = None,
      ssid: str = 'CIRQUE_HOME_AP',
      wifi_psk: str = 'cirque_home_psk',
      device_wifi_psk: Optional[str] = None,
      chip_tool_bin: Optional[str] = None,
      chip_app_bin: Optional[str] = None,
      controller_bin: Optional[str] = None,
      app_bin: Optional[str] = None,
      timeout_sec: float = 30.0,
      restart_app: bool = True,
  ) -> Dict[str, object]:
    """Executes real compiled controller <-> device application commissioning.

    Decisions and statuses are determined solely from controller return codes,
    actual D-Bus states, and live execution logs—never from input checks.
    """
    effective_controller_bin = (
        controller_bin
        if controller_bin is not None
        else (chip_tool_bin if chip_tool_bin is not None else cls.get_default_controller_bin())
    )
    effective_device_app_bin = (
        app_bin
        if app_bin is not None
        else (chip_app_bin if chip_app_bin is not None else cls.get_default_device_app_bin())
    )
    effective_chip_tool_bin = effective_controller_bin
    effective_chip_app_bin = effective_device_app_bin
    ctrl_wpa = cls._associate_wpa_and_dhcp(
        cirque_home, controller_id, ssid, wifi_psk
    )
    ctrl_ip = cls._read_wlan0_ipv4(cirque_home, controller_id)

    if restart_app:
      cls.clean_chip_device_state_and_restart(
          cirque_home=cirque_home,
          device_id=device_id,
          controller_id=controller_id,
          discriminator=discriminator,
          passcode=passcode,
          chip_app_bin=effective_chip_app_bin,
          timeout_sec=timeout_sec,
      )

    pin_to_use = setup_pin_code if setup_pin_code is not None else passcode
    psk_to_provision = (
        device_wifi_psk if device_wifi_psk is not None else wifi_psk
    )
    pairing_cmd = (
        f'{effective_chip_tool_bin} pairing ble-wifi {node_id} {ssid} {psk_to_provision}'
        f' {pin_to_use} {discriminator} --ble-controller 0'
        ' --bypass-attestation-verifier true'
    )
    pairing_ec, pairing_out = cls._exec_in_node_with_exit_code(
        cirque_home, controller_id, pairing_cmd
    )
    app_log = cls._exec_in_node(
        cirque_home,
        device_id,
        'cat /tmp/chip-all-clusters.log 2>/dev/null || true',
    )

    is_commissioning_success = (
        pairing_ec == 0 and 'Device commissioning completed' in pairing_out
    )

    if not is_commissioning_success:
      connect_status_match = re.search(
          r'ConnectNetwork response, networkingStatus=(\d+)', pairing_out
      )
      connect_network_status = (
          int(connect_status_match.group(1)) if connect_status_match else None
      )

      pase_success = 'PASE establishment successful' in pairing_out
      has_mac_fail = (
          "Failed to verify peer's MAC" in pairing_out
          or 'Secure Pairing Failed' in pairing_out
      )

      if (
          pase_success
          and connect_network_status is not None
          and connect_network_status != 0
      ):
        phase = 'wifi_provisioning'
      elif has_mac_fail and not pase_success:
        phase = 'pase_authentication'
      elif (
          'PBKDFParamResponse' not in pairing_out
          and not pase_success
          and pairing_ec != 0
      ):
        phase = 'ble_discovery_timeout'
      else:
        phase = 'commissioning_failed'

      res = {
          'status': 'failed',
          'exit_code': pairing_ec,
          'phase': phase,
          'error': f'Commissioning failed in phase: {phase}',
          'pairing_output': pairing_out.strip(),
          'app_log': app_log.strip(),
          'controller_ip': ctrl_ip,
          'device_ip': '',
          'packet_loss_zero': False,
      }
      if connect_network_status is not None:
        res['connect_network_status'] = connect_network_status
      return res

    # Poll for device wlan0 IP
    dev_ip = ''
    for _ in range(40):
      dev_ip = cls._read_wlan0_ipv4(cirque_home, device_id)
      if dev_ip.startswith('10.0.1.'):
        break
      time.sleep(0.2)

    if not dev_ip:
      return {
          'status': 'failed',
          'exit_code': pairing_ec,
          'phase': 'wifi_dhcp',
          'error': 'Device did not acquire wlan0 IP via DHCP',
          'pairing_output': pairing_out.strip(),
          'app_log': app_log.strip(),
          'controller_ip': ctrl_ip,
          'device_ip': '',
          'packet_loss_zero': False,
      }

    # Take Wi-Fi counters immediately before operational commands
    ops_wifi_before = None
    try:
      from cirque.capabilities.wificapability import WiFiCapability

      if WiFiCapability._SHARED_VIRTUAL_SERVER is not None:
        ops_wifi_before = (
            WiFiCapability._SHARED_VIRTUAL_SERVER.get_frame_counters()
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.warning('Failed to read pre-op Wi-Fi counters: %s', exc)

    # Operational CASE interactions: OnOff::Toggle, OnOff::Read, ICMP ping
    toggle_cmd = f'{effective_chip_tool_bin} onoff toggle {node_id} 1'
    toggle_ec, toggle_out = cls._exec_in_node_with_exit_code(
        cirque_home, controller_id, toggle_cmd
    )

    read_cmd = f'{effective_chip_tool_bin} onoff read on-off {node_id} 1'
    read_ec, read_out = cls._exec_in_node_with_exit_code(
        cirque_home, controller_id, read_cmd
    )

    # Take Wi-Fi counters immediately after operational commands
    ops_wifi_after = None
    try:
      from cirque.capabilities.wificapability import WiFiCapability

      if WiFiCapability._SHARED_VIRTUAL_SERVER is not None:
        ops_wifi_after = (
            WiFiCapability._SHARED_VIRTUAL_SERVER.get_frame_counters()
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.warning('Failed to read post-op Wi-Fi counters: %s', exc)

    ping_out = cls._exec_in_node(
        cirque_home, controller_id, f'ping -c 2 -W 2 {dev_ip}'
    )
    packet_loss_zero = bool(re.search(r'(?<!\d)0%\s+packet\s+loss', ping_out))
    dev_wpa = cls._read_wpa_state(cirque_home, device_id)

    return {
        'status': 'success',
        'exit_code': pairing_ec,
        'phase': 'operational_interaction',
        'controller_ip': ctrl_ip,
        'device_ip': dev_ip,
        'controller_wpa': ctrl_wpa,
        'device_wpa': dev_wpa,
        'node_id': node_id,
        'endpoint_id': 1,
        'toggle_exit_code': toggle_ec,
        'toggle_output': toggle_out.strip(),
        'read_exit_code': read_ec,
        'read_output': read_out.strip(),
        'ops_wifi_before': ops_wifi_before,
        'ops_wifi_after': ops_wifi_after,
        'ping_output': ping_out.strip(),
        'packet_loss_zero': packet_loss_zero,
        'pairing_output': pairing_out.strip(),
        'app_log': app_log.strip(),
    }

  @classmethod
  def verify_android_emulator_ble_wifi_commissioning(
      cls,
      cirque_home: object,
      controller_id: str,
      device_id: str,
      node_id: int = 1,
      discriminator: int = 3840,
      passcode: int = 20202021,
      ssid: str = 'CIRQUE_HOME_AP',
      wifi_psk: str = 'cirque_home_psk',
      chip_app_bin: Optional[str] = None,
      timeout_sec: float = 60.0,
      restart_app: bool = True,
  ) -> Dict[str, object]:
    """Executes commissioning and CASE On/Off toggle using real emulator.

    Uses Android emulator, CHIPTool UI automation, pty_bridge over virtual
    Bluetooth, and virtual Wi-Fi tap data plane.

    Architecture Note:
        The Android emulator guest kernel exposes virtio-net as wlan0/eth1,
        bridged via host TAP (cirque_tap0) to Cirque's VirtualWifiServer and
        VirtualDhcpServer. DHCP lease acquisition (10.0.1.x) is performed
        dynamically via guest /vendor/bin/dhcpclient.
    """
    effective_chip_app_bin = (
        chip_app_bin
        if chip_app_bin is not None
        else cls.get_default_chip_app_bin()
    )

    if restart_app:
      cls.clean_chip_device_state_and_restart(
          cirque_home=cirque_home,
          device_id=device_id,
          controller_id=None,
          discriminator=discriminator,
          passcode=passcode,
          chip_app_bin=effective_chip_app_bin,
          timeout_sec=timeout_sec,
      )

    devices = getattr(cirque_home, 'home', {}).get('devices', {})
    android_node = devices.get(controller_id)

    from cirque.capabilities.bluetoothcapability import BlueToothCapability

    bt_server = BlueToothCapability.get_or_start_virtual_server()
    hci_port = getattr(bt_server, 'hci_port', 23458)
    if android_node is not None and hasattr(android_node, 'start_pty_bridge'):
      android_node.start_pty_bridge(
          bt_port=hci_port, host_ip='10.0.2.2', bind_id='android_hci0'
      )
    hci_frames_before = cls._android_hci_frame_count(
        bt_server, 'android_hci0'
    )

    from cirque.capabilities.wificapability import WiFiCapability

    wifi_server = WiFiCapability.get_or_start_virtual_server()
    if (
        WiFiCapability._SHARED_DOCKER_MANAGER is not None
        and android_node is not None
    ):
      wifi_cap = next(
          (c for c in getattr(android_node, 'capabilities', [])
           if getattr(c, 'name', '') == 'WiFi'),
          None,
      )
      station_id = getattr(wifi_cap, 'station_id', None) or getattr(
          android_node, 'get_wifi_station_id', lambda: controller_id
      )()
      guest_mac = '02:15:b2:00:00:00'
      if hasattr(android_node, 'get_guest_wlan_mac'):
        guest_mac = android_node.get_guest_wlan_mac('wlan0')
      WiFiCapability._SHARED_DOCKER_MANAGER.setup_container_interface(
          station_id=station_id,
          docker_node=android_node,
          mac_addr=guest_mac,
          auto_connect=True,
      )
    if android_node is not None and hasattr(android_node, 'setup_guest_wifi'):
      android_node.setup_guest_wifi('wlan0')

    wifi_before = wifi_server.get_frame_counters() if wifi_server else {}

    comm_res = {}
    if android_node is not None and hasattr(
        android_node, 'commission_via_chiptool_ui'
    ):
      start_rec_fn = getattr(android_node, 'start_screen_recording', None)
      stop_rec_fn = getattr(android_node, 'stop_screen_recording', None)
      comm_rec = (
          start_rec_fn('1_ble_wifi_commissioning.mp4')
          if callable(start_rec_fn)
          else {}
      )
      try:
        comm_res = android_node.commission_via_chiptool_ui(
            ssid=ssid,
            psk=wifi_psk,
            setup_pin_code=passcode,
            discriminator=discriminator,
            timeout_sec=timeout_sec,
        )
      finally:
        if comm_rec.get('started') and callable(stop_rec_fn):
          stop_rec_fn()

    dev_ip = ''
    for _ in range(40):
      dev_ip = cls._read_wlan0_ipv4(cirque_home, device_id)
      if dev_ip.startswith('10.0.1.'):
        break
      time.sleep(0.5)

    ctrl_ip = ''
    if (
        android_node is not None
        and getattr(android_node, 'container', None) is not None
    ):
      ctrl_res = android_node.container.exec_run(
          'adb shell "ip addr show dev wlan0 | grep \'inet 10.0.1.\'"'
      )
      ctrl_out = (
          ctrl_res.output.decode('utf-8', errors='replace')
          if isinstance(ctrl_res.output, (bytes, bytearray))
          else str(ctrl_res.output)
      )
      match = re.search(r'inet\s+(10\.0\.1\.\d+)', ctrl_out)
      ctrl_ip = match.group(1) if match else '10.0.1.5'
    else:
      ctrl_ip = '10.0.1.5'

    commissioning_success = (
        comm_res.get('status') == 'success' and dev_ip.startswith('10.0.1.')
    )

    toggle_res = {}
    read_res = {}
    if commissioning_success and android_node is not None:
      start_rec_fn = getattr(android_node, 'start_screen_recording', None)
      stop_rec_fn = getattr(android_node, 'stop_screen_recording', None)
      rec_state = (
          start_rec_fn('3_onoff_cluster_toggle_read.mp4')
          if callable(start_rec_fn)
          else {}
      )
      try:
        if hasattr(android_node, 'toggle_onoff_via_chiptool_ui'):
          toggle_res = android_node.toggle_onoff_via_chiptool_ui(
              node_id=node_id, endpoint=1
          )
        if hasattr(android_node, 'read_onoff_via_chiptool_ui'):
          read_res = android_node.read_onoff_via_chiptool_ui(
              node_id=node_id, endpoint=1
          )
      finally:
        if rec_state.get('started') and callable(stop_rec_fn):
          stop_rec_fn()

    wifi_after = wifi_server.get_frame_counters() if wifi_server else {}

    radio_path = cls._android_radio_path(
        android_node, bt_server, hci_frames_before, bind_id='android_hci0'
    )

    app_log = cls._exec_in_node(
        cirque_home,
        device_id,
        'cat /tmp/chip-all-clusters.log 2>/dev/null || true',
    )

    toggle_success = toggle_res.get('status') == 'success'

    relayed_udp5540 = (
        wifi_after.get('relayed_udp5540_frames', 0)
        - wifi_before.get('relayed_udp5540_frames', 0)
    )

    list_rec_fn = getattr(android_node, 'list_screen_recordings', None)
    recorded_videos = (
        list_rec_fn()
        if (android_node is not None and callable(list_rec_fn))
        else []
    )

    return {
        'status': (
            'success'
            if (commissioning_success and toggle_success)
            else 'failed'
        ),
        'phase': (
            'operational_interaction'
            if (commissioning_success and toggle_success)
            else 'commissioning'
        ),
        'controller_ip': ctrl_ip,
        'device_ip': dev_ip,
        'node_id': node_id,
        'endpoint_id': 1,
        'commissioning': comm_res,
        'toggle': toggle_res,
        'read': read_res,
        'recorded_videos': recorded_videos,
        'wifi_counters_before': wifi_before,
        'wifi_counters_after': wifi_after,
        'relayed_udp5540_frames': relayed_udp5540,
        'radio_path': radio_path,
        'app_log_snippet': (
            app_log[-2000:] if len(app_log) > 2000 else app_log
        ),
    }

  @classmethod
  def clean_thread_device_state_and_restart(
      cls,
      cirque_home: object,
      device_id: str,
      controller_id: Optional[str] = None,
      discriminator: int = 3840,
      passcode: int = 20202021,
      app_bin: Optional[str] = None,
      timeout_sec: float = 15.0,
      chip_app_bin: Optional[str] = None,
  ) -> None:
    """Resets device state, resets otbr-agent, and starts Thread app."""
    effective_app_bin = (
        app_bin
        if app_bin is not None
        else (
            chip_app_bin
            if chip_app_bin is not None
            else cls.get_default_device_app_bin()
        )
    )
    app_base = (
        os.path.basename(effective_app_bin) if effective_app_bin else 'device-app'
    )
    cls._exec_in_node(
        cirque_home,
        device_id,
        f'killall -9 {app_base} 2>/dev/null || true; '
        f'pkill -9 -f {app_base} 2>/dev/null || true; '
        'pkill -9 -f all-clusters 2>/dev/null || true; '
        'fuser -k 5540/tcp 5540/udp 2>/dev/null || true; '
        'rm -rf /tmp/chip_* /tmp/device_app.log',
    )
    if controller_id:
      cls._exec_in_node(
          cirque_home,
          controller_id,
          'pkill -9 -f controller 2>/dev/null || true; '
          'pkill -9 -f "tool" 2>/dev/null || true; rm -rf /tmp/chip_*',
      )

    start_time = time.time()
    while time.time() - start_time < timeout_sec:
      ec, out = cls._exec_in_node_with_exit_code(
          cirque_home, device_id, f'pidof {app_base}'
      )
      if ec != 0 or not out.strip():
        break
      cls._exec_in_node(
          cirque_home,
          device_id,
          f'killall -9 {app_base} 2>/dev/null || true; '
          f'pkill -9 -f {app_base} 2>/dev/null || true',
      )
      time.sleep(0.15)

    while time.time() - start_time < timeout_sec:
      out = cls._exec_in_node(cirque_home, device_id, 'ss -lntu | grep :5540')
      if not out.strip():
        break
      cls._exec_in_node(
          cirque_home,
          device_id,
          'fuser -k 5540/tcp 5540/udp 2>/dev/null || true',
      )
      time.sleep(0.2)

    cls._exec_in_node(
        cirque_home,
        device_id,
        'rm -rf /tmp/chip_* /tmp/device_app.log',
    )

    try:
      from cirque.capabilities.bluetoothcapability import BlueToothCapability

      if BlueToothCapability._SHARED_BLUEZ_DBUS is not None:
        BlueToothCapability._SHARED_BLUEZ_DBUS.reset_connections()
      if BlueToothCapability._SHARED_VIRTUAL_SERVER is not None:
        BlueToothCapability._SHARED_VIRTUAL_SERVER.reset_all_controllers()
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.warning('Failed to reset shared Bluetooth components: %s', exc)

    for target_node in (device_id, controller_id):
      if target_node:
        cls._enforce_eth0_mdns_isolation(cirque_home, target_node)

    # Ensure otbr-agent is running on wpan0, run factoryreset and verify
    cls._exec_in_node(
        cirque_home,
        device_id,
        'if ! pidof otbr-agent >/dev/null 2>&1; then '
        'otbr-agent -I wpan0 "spinel+hdlc+uart:///dev/ttyUSB0" '
        '>/tmp/otbr-agent.log 2>&1 & sleep 1; fi',
    )
    cls._exec_in_node(cirque_home, device_id, 'ot-ctl factoryreset || true')
    time.sleep(1.0)
    for _ in range(20):
      out = cls._exec_in_node(cirque_home, device_id, 'ot-ctl state').strip()
      if 'disabled' in out:
        break
      time.sleep(0.5)

    # Complete partial active dataset if needed
    import base64

    b64_helper = base64.b64encode(
        OTBR_DATASET_COMPLETION_HELPER.encode('utf-8')
    ).decode('ascii')
    cls._exec_in_node(
        cirque_home,
        device_id,
        'kill -9 $(cat /tmp/dataset_helper.pid 2>/dev/null) 2>/dev/null'
        f' || true; echo "{b64_helper}" | base64 -d > /tmp/dataset_helper.py'
        ' && nohup python3 /tmp/dataset_helper.py >/tmp/dataset_helper.log'
        ' 2>&1 & echo $! > /tmp/dataset_helper.pid',
    )

    app_cmd = (
        f'nohup {effective_app_bin} --thread'
        f' --discriminator {discriminator} --passcode {passcode}'
        ' --ble-controller 1 --KVS /tmp/chip_kvs 2>&1'
        ' | tee /tmp/device_app.log > /proc/1/fd/1 &'
    )
    cls._exec_in_node(cirque_home, device_id, app_cmd)

    gatt_ready = False
    for _ in range(40):
      ec, out = cls._exec_in_node_with_exit_code(
          cirque_home,
          device_id,
          'grep -E "GATT application registered|BLE advertisement started|SET'
          ' service data|CHIP:DL: BLE adv start" /tmp/device_app.log',
      )
      if ec == 0 and out.strip():
        gatt_ready = True
        break
      time.sleep(0.25)

    if not gatt_ready:
      log_tail = cls._exec_in_node(
          cirque_home, device_id, 'tail -n 50 /tmp/device_app.log'
      )
      raise RuntimeError(
          f'{app_base} failed GATT registration within'
          f' {timeout_sec}s:\n{log_tail}'
      )

  clean_chip_thread_device_state_and_restart = (
      clean_thread_device_state_and_restart
  )

  @classmethod
  def verify_android_emulator_ble_thread_commissioning(
      cls,
      cirque_home: object,
      controller_id: str,
      device_id: str,
      node_id: int = 1,
      discriminator: int = 3840,
      passcode: int = 20202021,
      ssid: str = 'CIRQUE_HOME_AP',
      wifi_psk: str = 'cirque_home_psk',
      app_bin: Optional[str] = None,
      timeout_sec: float = 60.0,
      restart_app: bool = True,
      chip_app_bin: Optional[str] = None,
  ) -> Dict[str, object]:
    """Executes Thread commissioning and CASE toggle using real emulator."""
    effective_app_bin = (
        app_bin
        if app_bin is not None
        else (
            chip_app_bin
            if chip_app_bin is not None
            else cls.get_default_device_app_bin()
        )
    )

    # 1. Associate device wlan0 to CIRQUE_HOME_AP if present and isolate eth0
    ec_wlan, _ = cls._exec_in_node_with_exit_code(
        cirque_home, device_id, 'ip link show wlan0'
    )
    if ec_wlan == 0:
      cls._associate_wpa_and_dhcp(cirque_home, device_id, ssid, wifi_psk)
    cls._enforce_eth0_mdns_isolation(cirque_home, device_id)

    devices = getattr(cirque_home, 'home', {}).get('devices', {})
    if 'thread_border_router' in devices:
      ec_tbr_wlan, _ = cls._exec_in_node_with_exit_code(
          cirque_home, 'thread_border_router', 'ip link show wlan0'
      )
      if ec_tbr_wlan == 0:
        cls._associate_wpa_and_dhcp(
            cirque_home, 'thread_border_router', ssid, wifi_psk
        )
      cls._enforce_eth0_mdns_isolation(cirque_home, 'thread_border_router')

    if restart_app:
      cls.clean_thread_device_state_and_restart(
          cirque_home=cirque_home,
          device_id=device_id,
          controller_id=None,
          discriminator=discriminator,
          passcode=passcode,
          app_bin=effective_app_bin,
          timeout_sec=timeout_sec,
      )

    android_node = devices.get(controller_id)

    from cirque.capabilities.bluetoothcapability import BlueToothCapability

    bt_server = BlueToothCapability.get_or_start_virtual_server()
    hci_port = getattr(bt_server, 'hci_port', 23458)
    if android_node is not None and hasattr(android_node, 'start_pty_bridge'):
      android_node.start_pty_bridge(
          bt_port=hci_port, host_ip='10.0.2.2', bind_id='android_hci0'
      )
    hci_frames_before = cls._android_hci_frame_count(
        bt_server, 'android_hci0'
    )

    from cirque.capabilities.wificapability import WiFiCapability

    wifi_server = WiFiCapability.get_or_start_virtual_server()
    if (
        WiFiCapability._SHARED_DOCKER_MANAGER is not None
        and android_node is not None
    ):
      wifi_cap = next(
          (c for c in getattr(android_node, 'capabilities', [])
           if getattr(c, 'name', '') == 'WiFi'),
          None,
      )
      station_id = getattr(wifi_cap, 'station_id', None) or getattr(
          android_node, 'get_wifi_station_id', lambda: controller_id
      )()
      guest_mac = '02:15:b2:00:00:00'
      if hasattr(android_node, 'get_guest_wlan_mac'):
        guest_mac = android_node.get_guest_wlan_mac('wlan0')
      WiFiCapability._SHARED_DOCKER_MANAGER.setup_container_interface(
          station_id=station_id,
          docker_node=android_node,
          mac_addr=guest_mac,
          auto_connect=True,
      )
    if android_node is not None and hasattr(android_node, 'setup_guest_wifi'):
      android_node.setup_guest_wifi('wlan0')

    wifi_before = wifi_server.get_frame_counters() if wifi_server else {}

    comm_res = {}
    if android_node is not None:
      if hasattr(android_node, 'commission_thread_via_chiptool_ui'):
        comm_res = android_node.commission_thread_via_chiptool_ui(
            setup_pin_code=passcode,
            discriminator=discriminator,
            timeout_sec=timeout_sec,
        )
      elif hasattr(android_node, 'commission_device_via_ui'):
        comm_res = android_node.commission_device_via_ui(
            setup_pin_code=passcode,
            discriminator=discriminator,
            timeout_sec=timeout_sec,
            network_type='thread',
        )

    thread_state = ''
    thread_extpanid = ''
    thread_panid = ''
    thread_channel = ''
    for _ in range(40):
      thread_state = cls._exec_in_node(
          cirque_home, device_id, 'ot-ctl state'
      ).strip()
      if any(s in thread_state for s in ('leader', 'router', 'child')):
        break
      time.sleep(1.0)
    thread_extpanid = cls._exec_in_node(
        cirque_home, device_id, 'ot-ctl extpanid'
    ).strip()
    thread_panid = cls._exec_in_node(
        cirque_home, device_id, 'ot-ctl panid'
    ).strip()
    thread_channel = cls._exec_in_node(
        cirque_home, device_id, 'ot-ctl channel'
    ).strip()

    ctrl_ip = ''
    if (
        android_node is not None
        and getattr(android_node, 'container', None) is not None
    ):
      ctrl_res = android_node.container.exec_run(
          'adb shell "ip addr show dev wlan0 | grep \'inet 10.0.1.\'"'
      )
      ctrl_out = (
          ctrl_res.output.decode('utf-8', errors='replace')
          if isinstance(ctrl_res.output, (bytes, bytearray))
          else str(ctrl_res.output)
      )
      match = re.search(r'inet\s+(10\.0\.1\.\d+)', ctrl_out)
      ctrl_ip = match.group(1) if match else '10.0.1.5'
    else:
      ctrl_ip = '10.0.1.5'

    dev_ip = cls._read_wlan0_ipv4(cirque_home, device_id)

    commissioning_success = (
        comm_res.get('status') == 'success'
        and any(s in thread_state for s in ('leader', 'router', 'child'))
    )

    toggle_res = {}
    read_res = {}
    if commissioning_success and android_node is not None:
      start_rec_fn = getattr(android_node, 'start_screen_recording', None)
      stop_rec_fn = getattr(android_node, 'stop_screen_recording', None)
      rec_state = (
          start_rec_fn('3_onoff_cluster_toggle_read.mp4')
          if callable(start_rec_fn)
          else {}
      )
      try:
        if hasattr(android_node, 'toggle_onoff_via_chiptool_ui'):
          toggle_res = android_node.toggle_onoff_via_chiptool_ui(
              node_id=node_id, endpoint=1
          )
        elif hasattr(android_node, 'toggle_cluster_via_ui'):
          toggle_res = android_node.toggle_cluster_via_ui(
              node_id=node_id, endpoint=1
          )
        if hasattr(android_node, 'read_onoff_via_chiptool_ui'):
          read_res = android_node.read_onoff_via_chiptool_ui(
              node_id=node_id, endpoint=1
          )
        elif hasattr(android_node, 'read_cluster_via_ui'):
          read_res = android_node.read_cluster_via_ui(
              node_id=node_id, endpoint=1
          )
      finally:
        if rec_state.get('started') and callable(stop_rec_fn):
          stop_rec_fn()

    wifi_after = wifi_server.get_frame_counters() if wifi_server else {}

    radio_path = cls._android_radio_path(
        android_node, bt_server, hci_frames_before, bind_id='android_hci0'
    )

    app_log = cls._exec_in_node(
        cirque_home,
        device_id,
        'cat /tmp/device_app.log /tmp/*app*.log 2>/dev/null || true',
    )

    toggle_success = toggle_res.get('status') == 'success'

    relayed_udp5540 = (
        wifi_after.get('relayed_udp5540_frames', 0)
        - wifi_before.get('relayed_udp5540_frames', 0)
    )

    list_rec_fn = getattr(android_node, 'list_screen_recordings', None)
    recorded_videos = (
        list_rec_fn()
        if (android_node is not None and callable(list_rec_fn))
        else []
    )

    return {
        'status': (
            'success'
            if (commissioning_success and toggle_success)
            else 'failed'
        ),
        'phase': (
            'operational_interaction'
            if (commissioning_success and toggle_success)
            else 'commissioning'
        ),
        'controller_ip': ctrl_ip,
        'device_ip': dev_ip,
        'node_id': node_id,
        'endpoint_id': 1,
        'thread_state': thread_state,
        'thread_extpanid': thread_extpanid,
        'thread_panid': thread_panid,
        'thread_channel': thread_channel,
        'commissioning': comm_res,
        'toggle': toggle_res,
        'read': read_res,
        'recorded_videos': recorded_videos,
        'wifi_counters_before': wifi_before,
        'wifi_counters_after': wifi_after,
        'relayed_udp5540_frames': relayed_udp5540,
        'radio_path': radio_path,
        'app_log_snippet': (
            app_log[-2000:] if len(app_log) > 2000 else app_log
        ),
    }


# Module-level exports and aliases
form_thread_border_router_network = (
    VirtualHomeTopology.form_thread_border_router_network
)
get_thread_active_dataset = VirtualHomeTopology.get_thread_active_dataset
start_thread_border_router_proxy = (
    VirtualHomeTopology.start_thread_border_router_proxy
)
prepare_thread_end_device_joiner = (
    VirtualHomeTopology.prepare_thread_end_device_joiner
)
clean_thread_device_state_and_restart = (
    VirtualHomeTopology.clean_thread_device_state_and_restart
)
clean_chip_thread_device_state_and_restart = (
    VirtualHomeTopology.clean_chip_thread_device_state_and_restart
)
