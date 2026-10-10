# Copyright 2020 Google LLC
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

import atexit
import os
import time
import uuid

from cirque.capabilities.bluetoothcapability import BlueToothCapability
from cirque.capabilities.dockernetworkcapability import DockerNetworkCapability
from cirque.capabilities.interactivecapability import InteractiveCapability
from cirque.capabilities.lanaccesscapability import LanAccessCapability
from cirque.capabilities.mountcapability import MountCapability
from cirque.capabilities.pcapcapability import PcapCapability
from cirque.capabilities.threadcapability import ThreadCapability
from cirque.capabilities.trafficcontrolcapability import TrafficControlCapability
from cirque.capabilities.weavecapability import WeaveCapability
from cirque.capabilities.wificapability import WiFiCapability
from cirque.capabilities.xvnccapability import XvncCapability
from cirque.common.cirquelog import CirqueLog
from cirque.connectivity.homelan import HomeLan
from cirque.connectivity.threadsimpipe import ThreadSimPipe
import cirque.nodes as nodes
from cirque.nodes.androiddockernode import AndroidDockerNode
from cirque.nodes.dockernode import DockerNode
from cirque.nodes.wifiapnode import WiFiAPNode
import docker


_ACTIVE_HOMES_SET = set()


class CirqueHome:

  _ACTIVE_HOMES = _ACTIVE_HOMES_SET

  def __init__(self, home_id=None):
    self.docker_client = docker.from_env()
    if home_id is None:
      self.home_id = str(uuid.uuid4())
    else:
      self.home_id = home_id
    self.home = {'home_id': self.home_id, 'devices': {}}
    self.thread_petitions = {}
    # network
    self.external_lan = None
    self.internal_lan = None
    self.ipv6_lan = None
    self.ipvlan_lan = None
    atexit.register(self.destroy_home)
    self.logger = CirqueLog.get_cirque_logger('home')
    CirqueHome._ACTIVE_HOMES.add(self)

  def _next_thread_node_id(self, petition):
    if petition in self.thread_petitions:
      petition_id = self.thread_petitions[petition]['petition_id']
    else:
      petition_id = ThreadSimPipe.get_next_petition()
      self.thread_petitions[petition] = {
          'petition_id': petition_id,
          'ncp_id': 0,
      }
    self.thread_petitions[petition]['ncp_id'] += 1
    return self.thread_petitions[petition]['ncp_id']

  def create_home(self, home_config):
    self.logger.info('creating home: {}'.format(self.home_id))
    bt_server_active = (
        getattr(BlueToothCapability, '_SHARED_VIRTUAL_SERVER', None) is not None
    )
    wifi_server_active = (
        getattr(WiFiCapability, '_SHARED_VIRTUAL_SERVER', None) is not None
    )
    other_active_homes = [
        h for h in CirqueHome._ACTIVE_HOMES if h is not self and getattr(h, 'home', None)
    ]
    if not (bt_server_active or wifi_server_active or other_active_homes):
      BlueToothCapability.BLE_ADAPTS_LIST.clear()
      WiFiCapability.WIFI_STATIONS_LIST.clear()
    devices = (
        list(home_config.values())
        if hasattr(home_config, 'values')
        else list(home_config)
    )
    ap_devices = [d for d in devices if d.get('type') == 'wifi_ap']
    other_devices = [d for d in devices if d.get('type') != 'wifi_ap']
    for device_config in ap_devices + other_devices:
      self.add_device(device_config)
    return self.home_id

  def _append_docker_network_capability(self, device_config, capabilities):
    """Appends the appropriate Docker network capability to capabilities."""
    cirque_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    btvirt_bin = os.path.join(cirque_root, 'bluez', 'emulator', 'btvirt')
    use_legacy_btvirt = (
        'Bluetooth' in device_config.get('capability', [])
        and not device_config.get('use_virtual_bt_tcp', True)
        and os.path.exists(btvirt_bin)
    )
    if use_legacy_btvirt:
      return
    net_type = device_config.get('docker_network')
    if net_type == 'Internal':
      if not self.internal_lan:
        self.internal_lan = HomeLan(f'{self.home_id}_internal', internal=True)
      capabilities.append(self._make_internal_network_capability())
    elif net_type == 'Ipv6':
      if not self.ipv6_lan:
        self.ipv6_lan = HomeLan(f'{self.home_id}_ipv6', ipv6=True)
      capabilities.append(self._make_ipv6_network_capability())
    elif net_type == 'IpvLan':
      if not self.ipvlan_lan:
        self.ipvlan_lan = HomeLan(f'{self.home_id}_ipvlan')
      capabilities.append(self._make_ipvlan_network_capability())
    else:
      if not self.external_lan:
        self.external_lan = HomeLan(f'{self.home_id}_external')
      capabilities.append(self._make_external_network_capability())

  def add_device(self, device_config):
    self.logger.info(
        'Adding device to home {}: {}'.format(self.home_id, device_config)
    )
    if 'type' not in device_config:
      self.logger.critical('Cannot create device, type unspecified')
      return
    capabilities = []
    device_type = device_config['type']
    base_image = device_config.get('base_image', device_type)
    self._append_docker_network_capability(device_config, capabilities)
    for capability_name in device_config.get('capability', []):
      capability = self._make_capability(capability_name, device_config)
      if capability is not None:
        capabilities.append(capability)
    labels = device_config.get('labels')
    if device_type in ('wifi_ap', 'APWifi'):
      device_node = WiFiAPNode(
          self.docker_client,
          ssid=device_config.get('ssid'),
          password=device_config.get('psk') or device_config.get('password'),
          base_image=base_image,
          capabilities=capabilities,
          use_virtual_wifi_tcp=device_config.get('use_virtual_wifi_tcp', True),
          labels=labels,
      )
    elif str(device_type).lower() in (
        'android_emulator',
        'android_controller',
        'android_device',
    ):
      device_node = AndroidDockerNode(
          self.docker_client,
          node_type=device_type,
          capabilities=capabilities,
          base_image=base_image,
          avd_name=device_config.get('avd_name', 'emulator'),
          adb_port=device_config.get('adb_port', 5554),
          enable_kvm=device_config.get('enable_kvm', True),
          preferred_mode=device_config.get('preferred_mode', None),
          labels=labels,
          tap_interface=device_config.get('tap_interface', 'cirque_tap0'),
          is_tap_station=device_config.get('is_tap_station', True),
          chiptool_apk=device_config.get('chiptool_apk'),
          extra_apks=device_config.get('extra_apks'),
          mac_address=device_config.get('mac_address'),
          ipv4_addr=device_config.get('ipv4_addr'),
      )
    else:
      device_node = DockerNode(
          self.docker_client,
          device_type,
          capabilities,
          base_image=base_image,
          labels=labels,
      )
    if 'wifi_ssid' in device_config:
      device_node.wifi_ssid = device_config['wifi_ssid']
    elif 'ssid' in device_config and device_type not in ('wifi_ap', 'APWifi'):
      device_node.wifi_ssid = device_config['ssid']
    if 'wifi_psk' in device_config:
      device_node.wifi_psk = device_config['wifi_psk']
    elif 'psk' in device_config and device_type not in ('wifi_ap', 'APWifi'):
      device_node.wifi_psk = device_config['psk']
    device_node.run()
    if device_node.id is not None:
      self.home['devices'][device_node.id] = device_node
    return device_node.id

  def _make_capability(self, capability, device_config):
    factory_functions = {
        'Bluetooth': self._make_bluetooth_capability,
        'Interactive': self._make_interactive_capability,
        'LanAccess': self._make_lan_access_capability,
        'Mount': self._make_mount_capability,
        'Pcap': self._make_pcap_capability,
        'Thread': self._make_thread_capability,
        'TrafficControl': self._make_trafficcontrolcapability,
        'Weave': self._make_weave_capability,
        'WiFi': self._make_wifi_capability,
        'Xvnc': self._make_xvnc_capability,
    }
    if capability not in factory_functions:
      self.logger.critical('Unsupported capability {}'.format(capability))
      return None
    else:
      return factory_functions[capability](capability, device_config)

  # 4 network settings
  def _make_external_network_capability(self):
    return DockerNetworkCapability(self.external_lan.name, 'external')

  def _make_internal_network_capability(self):
    return DockerNetworkCapability(self.internal_lan.name, 'internal')

  def _make_ipv6_network_capability(self):
    return DockerNetworkCapability(self.ipv6_lan.name, 'ipv6')

  def _make_ipvlan_network_capability(self):
    return DockerNetworkCapability(self.ipvlan_lan.name, 'ipvlan')

  def _resolve_pcap_dir(self, device_config):
    pcap_cfg = device_config.get('pcap', {})
    cfg_dir = (
        pcap_cfg.get('dir', device_config.get('pcap_dir'))
        if isinstance(pcap_cfg, dict)
        else device_config.get('pcap_dir')
    )
    return (
        cfg_dir
        or os.environ.get('CIRQUE_PCAP_DIR')
        or os.environ.get('DEVICE_LOG_DIR')
    )

  def _make_bluetooth_capability(self, capability, device_config):
    num_infs = device_config.get('num_infs', 2)
    use_virtual_bt_tcp = device_config.get('use_virtual_bt_tcp', True)
    control_port = device_config.get('virtual_bt_control_port', 0)
    hci_port = device_config.get('virtual_bt_hci_port', 0)
    phy_port = device_config.get('virtual_bt_phy_port', 0)
    bd_addr = device_config.get('bd_addr', None)
    cap = BlueToothCapability(
        num_btvirts=num_infs,
        use_virtual_bt_tcp=use_virtual_bt_tcp,
        control_port=control_port,
        hci_port=hci_port,
        phy_port=phy_port,
        bd_addr=bd_addr,
    )
    resolved_pcap_dir = self._resolve_pcap_dir(device_config)
    shared_bt_srv = getattr(
        BlueToothCapability, '_SHARED_VIRTUAL_SERVER', None
    )
    if resolved_pcap_dir and shared_bt_srv is not None:
      shared_bt_srv.enable_pcap(resolved_pcap_dir)
    return cap

  def _make_interactive_capability(self, capability, device_config):
    return InteractiveCapability()

  def _make_lan_access_capability(self, capability, device_config):
    if (
        'docker_network' in device_config
        and device_config['docker_network'] == 'internal'
    ):
      home_lan = self.internal_lan
    else:
      home_lan = self.external_lan
    return LanAccessCapability(home_lan)

  def _make_mount_capability(self, capability, device_config):
    mount_pairs = device_config['mount_pairs']
    return MountCapability(mount_pairs)

  def _make_pcap_capability(self, capability, device_config):
    pcap_cfg = device_config.get('pcap', {})
    if isinstance(pcap_cfg, dict):
      pcap_dir = pcap_cfg.get('dir', device_config.get('pcap_dir'))
      bt = pcap_cfg.get('bt', True)
      wifi = pcap_cfg.get('wifi', True)
    else:
      pcap_dir = device_config.get('pcap_dir')
      bt = True
      wifi = True
    resolved_pcap_dir = self._resolve_pcap_dir(device_config)
    if resolved_pcap_dir:
      bt_server = getattr(BlueToothCapability, '_SHARED_VIRTUAL_SERVER', None)
      if bt and bt_server is not None:
        bt_server.enable_pcap(resolved_pcap_dir)
      wifi_server = getattr(WiFiCapability, '_SHARED_VIRTUAL_SERVER', None)
      if wifi and wifi_server is not None:
        wifi_server.enable_pcap(resolved_pcap_dir)
    return PcapCapability(pcap_dir=pcap_dir, bt=bt, wifi=wifi)

  def _make_thread_capability(self, capability, device_config):
    petition = (
        device_config['thread_petition']
        if 'thread_petition' in device_config
        else 0
    )
    daemons = (
        device_config['thread_daemon']
        if 'thread_daemon' in device_config
        else ['wpantund']
    )
    rcp = 'rcp_mode' in device_config and device_config['rcp_mode']
    node_id = self._next_thread_node_id(petition)
    return ThreadCapability(node_id, petition, daemons=daemons, rcp=rcp)

  def _make_trafficcontrolcapability(self, capability, device_config):
    tc_cfg = device_config.get('traffic_control') or {}
    return TrafficControlCapability(
        latencyMs=tc_cfg.get('latencyMs', tc_cfg.get('latency', 0)),
        loss=tc_cfg.get('loss', 0),
    )

  def _make_weave_capability(self, capability, device_config):
    if 'weave_config_file' not in device_config:
      self.logger.critical(
          'Weave configuration file not found,                 cannot'
          ' initialize Weave capability'
      )
      return None
    weave_provision_path = os.path.expanduser(
        device_config['weave_config_file']
    )
    target_path = (
        device_config['weave_config_target_path']
        if 'weave_config_target_path' in device_config
        else None
    )
    return WeaveCapability(weave_provision_path, target_path)

  def _make_wifi_capability(self, capability, device_config):
    cap = WiFiCapability(
        use_virtual_wifi_tcp=device_config.get('use_virtual_wifi_tcp', True),
        auto_connect=device_config.get('wifi_auto_connect', False),
        ssid=device_config.get('wifi_ssid') or device_config.get('ssid'),
        psk=device_config.get('wifi_psk') or device_config.get('psk'),
    )
    resolved_pcap_dir = self._resolve_pcap_dir(device_config)
    wifi_server = getattr(WiFiCapability, '_SHARED_VIRTUAL_SERVER', None)
    if resolved_pcap_dir and wifi_server is not None:
      wifi_server.enable_pcap(resolved_pcap_dir)
    return cap

  def _make_xvnc_capability(self, capability, device_config):
    localhost = (
        device_config['xvnc_localhost']
        if 'xvnc_localhost' in device_config
        else True
    )
    display_id = (
        device_config['display_id'] if 'display_id' in device_config else 0
    )
    docker_display_id = (
        device_config['docker_display_id']
        if 'docker_display_id' in device_config
        else 0
    )
    return XvncCapability(localhost, display_id, docker_display_id)

  def get_wifiap_ssid_psk(self, node_id=None):

    def ssid_psk(node):
      ssid = node.get_wifi_ssid()
      psk = node.get_wifi_password()
      return (ssid, psk)

    if node_id and node_id in self.home['devices']:
      node = self.home['devices'][node_id]
      return ssid_psk(node)
    for node in self.home['devices'].values():
      if node.type == 'wifi_ap':
        return ssid_psk(node)
    return ''

  def get_home_devices(self):
    return {
        node.id: self.get_device_state(node.id)
        for node in self.home['devices'].values()
    }

  def get_device_state(self, node_id):
    if node_id in self.home['devices']:
      node = self.home['devices'][node_id]
      return {
          'name': node.name,
          'type': node.type,
          'base_image': node.base_image,
          'id': node.id,
          'capability': {
              cap.name: cap.description for cap in node.capabilities
          },
          'description': node.description,
      }
    else:
      return None

  def stop_device(self, node_id):
    if node_id not in self.home['devices']:
      return ''
    self.home['devices'][node_id].stop()
    del self.home['devices'][node_id]
    return node_id

  def get_device_log(self, node_id, tail='all'):
    if node_id not in self.home['devices']:
      return ''
    return self.home['devices'][node_id].get_device_log(tail)

  def destroy_home(self):
    CirqueHome._ACTIVE_HOMES.discard(self)
    if not self.home:
      return
    for node in self.home['devices'].values():
      node.stop()
    for lan in ('external_lan', 'internal_lan', 'ipv6_lan', 'ipvlan_lan'):
      if getattr(self, lan):
        getattr(self, lan).close()
    if os.environ.get('CIRQUE_SKIP_GLOBAL_PRUNE') != '1':
      self.docker_client.containers.prune()
      self.docker_client.networks.prune()
    self.home = None
    return self.home_id

  @property
  def devices(self):
    return self.home['devices']

  def execute_device_cmd(self, cmd, node_id=None, stream=False):
    ret = None
    if node_id is not None:
      device_node = self.home['devices'][node_id]
      ret = device_node.container.exec_run(cmd, stream=stream)
      logged_ret = ret
      if isinstance(logged_ret, bytes):
        logged_ret = logged_ret.decode('utf-8', errors='replace')
        if len(logged_ret) > 2000:
          logged_ret = logged_ret[:2000] + f"...[truncated {len(logged_ret) - 2000} bytes]"
      elif isinstance(logged_ret, tuple) and len(logged_ret) >= 2:
        output = logged_ret[1]
        if isinstance(output, bytes):
          output = output.decode('utf-8', errors='replace')
        if isinstance(output, str) and len(output) > 2000:
          output = output[:2000] + f"...[truncated {len(output) - 2000} bytes]"
        logged_ret = (logged_ret[0], output)
      self.logger.info('cmd is: {} and ret: {}'.format(cmd, logged_ret))
    return ret

  _CirqueHome__next_thread_node_id = _next_thread_node_id
  _CirqueHome__make_internal_network_capability = (
      _make_internal_network_capability
  )
  _CirqueHome__make_ipv6_network_capability = _make_ipv6_network_capability
  _CirqueHome__make_ipvlan_network_capability = _make_ipvlan_network_capability
  _CirqueHome__make_external_network_capability = (
      _make_external_network_capability
  )
  _CirqueHome__make_capability = _make_capability
  _CirqueHome__resolve_pcap_dir = _resolve_pcap_dir
  _CirqueHome__make_bluetooth_capability = _make_bluetooth_capability
  _CirqueHome__make_interactive_capability = _make_interactive_capability
  _CirqueHome__make_lan_access_capability = _make_lan_access_capability
  _CirqueHome__make_mount_capability = _make_mount_capability
  _CirqueHome__make_pcap_capability = _make_pcap_capability
  _CirqueHome__make_thread_capability = _make_thread_capability
  _CirqueHome__make_trafficcontrolcapability = _make_trafficcontrolcapability
  _CirqueHome__make_weave_capability = _make_weave_capability
  _CirqueHome__make_wifi_capability = _make_wifi_capability
  _CirqueHome__make_xvnc_capability = _make_xvnc_capability
