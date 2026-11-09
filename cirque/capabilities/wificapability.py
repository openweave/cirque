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

from collections import namedtuple
import os
import re
import time

from cirque.capabilities.basecapability import BaseCapability
from cirque.capabilities.bluetoothcapability import BlueToothCapability
from cirque.common.cirquelog import CirqueLog
from cirque.common.docker_transport import prepare_container_dbus_socket
from cirque.common.exceptions import (
    IpNetnsExecError,
    LoadKernelError,
    NameSpaceOperatingError,
    PHYDeviceError,
)
import cirque.common.utils as utils
from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager
from cirque.virtual_wifi.server import VirtualWiFiServer
from cirque.virtual_wifi.wpa_dbus_daemon import WpaSupplicantDbusService
from pyroute2 import NetNS

ExecResult = namedtuple("ExecResult", ["exit_code", "output"])


_WIFI_STATIONS_LIST = []


class WiFiCapability(BaseCapability):
  """Cirque Wi-Fi Capability.

  Supports TCP/D-Bus Virtual Wi-Fi and mac80211_hwsim.
  """

  RUNTIME_NAMESPACE = "/var/run/netns"
  DEFAULT_RADIOS = 20
  WIFI_STATIONS_LIST = _WIFI_STATIONS_LIST
  _SHARED_VIRTUAL_SERVER = None
  _SHARED_DOCKER_MANAGER = None
  _SHARED_WPA_DBUS = None

  @classmethod
  def get_or_start_virtual_server(
      cls,
      host="127.0.0.1",
      control_port=0,
      mgmt_port=0,
      data_port=0,
      pcap_dir=None,
  ):
    """Starts or returns the singleton VirtualWiFiServer.

    The first call also starts the wpa_supplicant1 D-Bus router.
    """
    resolved_pcap_dir = (
        pcap_dir
        or os.environ.get("CIRQUE_PCAP_DIR")
        or os.environ.get("DEVICE_LOG_DIR")
    )
    if cls._SHARED_VIRTUAL_SERVER is None:
      cls._SHARED_VIRTUAL_SERVER = VirtualWiFiServer(
          host=host,
          control_port=control_port,
          mgmt_port=mgmt_port,
          data_port=data_port,
          pcap_dir=resolved_pcap_dir,
      )
      cls._SHARED_VIRTUAL_SERVER.start()
      cls._SHARED_DOCKER_MANAGER = DockerVirtualWiFiManager(
          server=cls._SHARED_VIRTUAL_SERVER,
      )
      cls._SHARED_WPA_DBUS = WpaSupplicantDbusService(
          cls._SHARED_DOCKER_MANAGER
      )
      cls._SHARED_WPA_DBUS.start()
    elif resolved_pcap_dir:
      cls._SHARED_VIRTUAL_SERVER.enable_pcap(resolved_pcap_dir)
    return cls._SHARED_VIRTUAL_SERVER

  @classmethod
  def stop_virtual_server(cls):
    """Stops the singleton Wi-Fi services.

    Stops the wpa_supplicant1 D-Bus service, the Docker Wi-Fi manager, and the
    VirtualWiFiServer, in that order.
    """
    if cls._SHARED_WPA_DBUS is not None:
      cls._SHARED_WPA_DBUS.stop()
      cls._SHARED_WPA_DBUS = None
    if cls._SHARED_DOCKER_MANAGER is not None:
      cls._SHARED_DOCKER_MANAGER.stop_all()
      cls._SHARED_DOCKER_MANAGER = None
    if cls._SHARED_VIRTUAL_SERVER is not None:
      cls._SHARED_VIRTUAL_SERVER.stop()
      cls._SHARED_VIRTUAL_SERVER = None

  @classmethod
  def register_virtual_ap(cls, ssid, psk, ap_id=None):
    """Registers an Access Point on the active VirtualWiFiServer if running."""
    if cls._SHARED_VIRTUAL_SERVER is not None:
      return cls._SHARED_VIRTUAL_SERVER.register_ap(
          ssid=ssid, psk=psk, ap_id=ap_id
      )
    return None

  def __init__(
      self,
      use_virtual_wifi_tcp=None,
      auto_connect=False,
      is_ap=False,
      *,
      control_port=0,
      mgmt_port=0,
      data_port=0,
      ssid=None,
      psk=None,
  ):
    """Initializes a Wi-Fi capability instance for a Cirque DockerNode."""
    self.logger = CirqueLog.get_cirque_logger(self.__class__.__name__)
    self.ssid = ssid
    self.psk = psk
    self.phy_device = None
    if use_virtual_wifi_tcp is None:
      legacy_env = (
          os.environ.get("CIRQUE_USE_LEGACY_HWSIM", "0").strip().lower()
      )
      use_virtual_wifi_tcp = legacy_env not in ("1", "true", "yes")
    self.use_virtual_wifi_tcp = bool(use_virtual_wifi_tcp)
    self.auto_connect = auto_connect
    self.is_ap = is_ap
    self.virtual_wifi_host = "127.0.0.1"
    self.control_port = control_port
    self.mgmt_port = mgmt_port
    self.data_port = data_port
    self.station_id = ""
    self.station_idx = 0
    self.mac_addr = ""
    self.ipv4_addr = ""
    self.ipv6_addr = ""
    self._shared_bt_adapt = None

    if not self.use_virtual_wifi_tcp:
      if not WiFiCapability.is_mac80211_hwsim_loaded():
        try:
          WiFiCapability.load_kernel_mac80211_hwsim()
        except Exception:  # pylint: disable=broad-exception-caught
          self.logger.warning(
              "mac80211_hwsim unavailable; falling back to TCP VirtualWiFi"
          )
          self.use_virtual_wifi_tcp = True

    if self.use_virtual_wifi_tcp:
      self._setup_virtual_wifi_station()

  def _setup_virtual_wifi_station(self):
    server = self.get_or_start_virtual_server(
        host=self.virtual_wifi_host,
        control_port=self.control_port,
        mgmt_port=self.mgmt_port,
        data_port=self.data_port,
    )
    self.control_port = server.control_port
    self.mgmt_port = server.mgmt_port
    self.data_port = server.data_port

    idx = 0
    while f"wifi{idx}" in WiFiCapability.WIFI_STATIONS_LIST:
      idx += 1
    self.station_idx = idx
    self.station_id = f"wifi{idx}"
    WiFiCapability.WIFI_STATIONS_LIST.append(self.station_id)

    if WiFiCapability._SHARED_DOCKER_MANAGER is not None:
      self.mac_addr, self.ipv4_addr, self.ipv6_addr = (
          WiFiCapability._SHARED_DOCKER_MANAGER.register_station(
              station_id=self.station_id,
              idx=idx,
              is_ap=self.is_ap,
          )
      )

  @property
  def name(self):
    return "WiFi"

  @property
  def description(self):
    if self.use_virtual_wifi_tcp:
      return {
          "wifi_interface": "wlan0",
          "station_id": self.station_id,
          "mac_addr": self.mac_addr,
          "wifi_ipv4": self.ipv4_addr,
          "wifi_ipv6": self.ipv6_addr,
          "mode": "virtual_wifi_tcp",
          "host": self.virtual_wifi_host,
          "control_port": self.control_port,
          "mgmt_port": self.mgmt_port,
          "data_port": self.data_port,
      }
    return {}

  def get_docker_run_args(self, docker_node):
    if not self.use_virtual_wifi_tcp:
      return {"privileged": True}
    env = {
        "DBUS_SYSTEM_BUS_ADDRESS": "unix:path=/var/run/dbus/system_bus_socket",
        "VIRTUAL_WIFI_ENABLED": "1",
        "VIRTUAL_WIFI_HOST": self.virtual_wifi_host,
        "VIRTUAL_WIFI_STATION_ID": self.station_id,
        "VIRTUAL_WIFI_MAC": self.mac_addr,
        "VIRTUAL_WIFI_IPV4": self.ipv4_addr,
        "VIRTUAL_WIFI_IPV6": self.ipv6_addr,
        "VIRTUAL_WIFI_CONTROL_PORT": str(self.control_port),
        "VIRTUAL_WIFI_MGMT_PORT": str(self.mgmt_port),
        "VIRTUAL_WIFI_DATA_PORT": str(self.data_port),
    }
    volumes = []
    # Coexistence Invariant: When a DockerNode enables both `Bluetooth` and
    # `WiFi` capabilities, `BlueToothCapability` already mounts a dedicated
    # per-container `/run/dbus` directory. Detect that capability here so both
    # `org.bluez` and `fi.w1.wpa_supplicant1` attach to the exact same
    # `/run/dbus/system_bus_socket` without duplicate Docker volume mounts.
    bt_cap = None
    for cap in getattr(docker_node, "capabilities", []):
      if getattr(cap, "name", "") == "Bluetooth" and getattr(
          cap, "use_virtual_bt_tcp", False
      ):
        bt_cap = cap
        break
    if bt_cap is not None:
      self._shared_bt_adapt = bt_cap.ble_adapt
    if WiFiCapability._SHARED_DOCKER_MANAGER is not None:
      mgr = WiFiCapability._SHARED_DOCKER_MANAGER
      if bt_cap is None:
        c_dbus_dir = mgr.get_container_dbus_dir(self.station_id)
        volumes.append(f"{c_dbus_dir}:/run/dbus")
      volumes.extend([
          (
              f"{mgr.wpa_conf_path}:"
              "/etc/dbus-1/system.d/fi.w1.wpa_supplicant1.conf:ro"
          ),
          f"{mgr.runtime_dir}:/dev/virtual_wifi",
          f"{mgr.iwlist_path}:/sbin/iwlist:ro",
          f"{mgr.iwlist_path}:/usr/sbin/iwlist:ro",
      ])
    return {"privileged": True, "environment": env, "volumes": volumes}

  @staticmethod
  def _prepare_container_dbus_socket(
      container, sock_path, stop_wpa=True, timeout_s=5.0
  ):
    """Ensures host UID exists in container and D-Bus socket is writable."""
    prepare_container_dbus_socket(
        container=container,
        sock_path=sock_path,
        stop_wpa=stop_wpa,
        timeout_s=timeout_s,
    )

  def _enable_virtual_wifi_tcp(self, docker_node):
    """Configures the container wlan0 interface.

    Station containers are also attached to the wpa_supplicant1 D-Bus service.
    """
    docker_node.wlan_interface = "wlan0"
    docker_node.wifi_ipv4 = self.ipv4_addr
    docker_node.wifi_ipv6 = self.ipv6_addr
    if self.ssid and not getattr(docker_node, "wifi_ssid", None):
      docker_node.wifi_ssid = self.ssid
    if self.psk and not getattr(docker_node, "wifi_psk", None):
      docker_node.wifi_psk = self.psk
    is_ap_node = getattr(docker_node, "type", "") == "wifi_ap" or self.is_ap
    is_android_node = (
        getattr(docker_node, "type", "")
        in ("android_emulator", "android_device")
        or docker_node.__class__.__name__ == "AndroidDockerNode"
    )
    mgr = WiFiCapability._SHARED_DOCKER_MANAGER
    if mgr is not None:
      mgr.setup_container_interface(
          station_id=self.station_id,
          docker_node=docker_node,
          mac_addr=self.mac_addr,
          ipv4_addr=self.ipv4_addr,
          ipv6_addr=self.ipv6_addr,
          auto_connect=(is_ap_node or self.auto_connect),
      )
      if is_android_node:
        return 0
      bt_cap = None
      for cap in getattr(docker_node, "capabilities", []):
        if getattr(cap, "name", "") == "Bluetooth":
          bt_cap = cap
          break
      bt_mgr = (
          getattr(bt_cap, "_SHARED_DOCKER_MANAGER", None)
          or BlueToothCapability._SHARED_DOCKER_MANAGER
      )
      if self._shared_bt_adapt and bt_mgr is not None:
        c_dbus_dir = os.path.join(
            bt_mgr.containers_dir, self._shared_bt_adapt, "dbus"
        )
      else:
        c_dbus_dir = os.path.join(mgr.containers_dir, self.station_id, "dbus")
      sock_path = os.path.join(c_dbus_dir, "system_bus_socket")
      self._prepare_container_dbus_socket(
          getattr(docker_node, "container", None), sock_path
      )
      if WiFiCapability._SHARED_WPA_DBUS is not None and not is_ap_node:
        WiFiCapability._SHARED_WPA_DBUS.attach_container_bus(
            self.station_id, sock_path
        )
    return 0

  def enable_capability(self, docker_node):
    if self.use_virtual_wifi_tcp:
      return self._enable_virtual_wifi_tcp(docker_node)
    if not WiFiCapability.is_mac80211_hwsim_loaded():
      WiFiCapability.load_kernel_mac80211_hwsim()
    try:
      self._get_available_phy_device(docker_node)
      self._phy_namespace_setup(docker_node)
      if docker_node.type != "wifi_ap":
        self.start_wpa_supplicant_service(docker_node)
    except Exception as e:
      self.logger.exception("%r", e)
      return -1
    self.logger.info(
        "Node: %s successfully enabled wifi capability", docker_node.name
    )

  def disable_capability(self, docker_node):
    if self.station_id in WiFiCapability.WIFI_STATIONS_LIST:
      WiFiCapability.WIFI_STATIONS_LIST.remove(self.station_id)
    if self.use_virtual_wifi_tcp:
      if WiFiCapability._SHARED_DOCKER_MANAGER is not None:
        WiFiCapability._SHARED_DOCKER_MANAGER.unregister_station(
            self.station_id
        )
      if not WiFiCapability.WIFI_STATIONS_LIST:
        WiFiCapability.stop_virtual_server()
      return
    try:
      docker_node.container.exec_run("killall wpa_supplicant")
      self._phy_namespace_restore(docker_node)
    except Exception as e:
      self.logger.exception("%r", e)
    self.logger.info(
        "Node: %s successfully disabled wifi capability",
        docker_node.name,
    )

  def start_wpa_supplicant_service(self, docker_node):
    if not self.use_virtual_wifi_tcp:
      command = (
          "wpa_supplicant -B -i wlan0 "
          "-c /etc/wpa_supplicant/wpa_supplicant.conf "
          "-f /var/log/wpa_supplicant.log -t -dd"
      )
      return docker_node.container.exec_run(command)
    container = getattr(docker_node, "container", None)
    mgr = WiFiCapability._SHARED_DOCKER_MANAGER
    if container is None or mgr is None:
      return ExecResult(exit_code=0, output=b"")
    ret = container.exec_run("cat /etc/wpa_supplicant/wpa_supplicant.conf")
    conf_text = (
        ret.output.decode("utf-8", errors="replace") if ret.output else ""
    )
    ssids = re.findall(r'ssid="([^"]+)"', conf_text)
    psks = re.findall(r'#psk="([^"]+)"', conf_text) or re.findall(
        r'psk="([^"]+)"', conf_text
    )
    ssid = ssids[-1] if ssids else ""
    psk = psks[-1] if psks else ""
    if not ssid and WiFiCapability._SHARED_VIRTUAL_SERVER is not None:
      aps = WiFiCapability._SHARED_VIRTUAL_SERVER.list_aps()
      if aps:
        ssid, psk = aps[0].ssid, aps[0].psk
    if ssid:
      mgr.connect_station_to_ap(self.station_id, ssid, psk)
    return ExecResult(exit_code=0, output=b"")

  def _get_available_phy_device(self, docker_node):
    ret = utils.host_run(self.logger, "iw dev")
    if ret.stderr != b"":
      raise PHYDeviceError("Error:{}".format(ret.stderr))

    if ret.returncode == 1:
      raise PHYDeviceError("run out of all the phy devices!")

    lines = ret.stdout.decode("utf-8").split("\n")
    lines = [line.strip() for line in lines]
    lines = [
        line
        for line in lines
        if line.startswith("phy") or line.startswith("Interface")
    ]
    devices = [
        (l1, l2.split()[-1])
        for l1, l2 in zip(lines, lines[1:])
        if l1.startswith("phy")
    ]
    phy_device, interface = devices.pop()
    phy_device = "".join(phy_device.split("#"))
    docker_node.wlan_phy_device = phy_device
    docker_node.wlan_interface = interface
    self.logger.info(
        "container %s: phy device %s interface %s",
        docker_node.name,
        docker_node.wlan_phy_device,
        docker_node.wlan_interface,
    )

  def _phy_namespace_setup(self, docker_node):
    try:
      self._mount_container_namespace_to_host(docker_node)
      self._add_phy_device_to_container_namespace(docker_node)
      self._bring_up_wifi_interface(docker_node)
    except Exception as e:
      docker_node.logger.exception("%r", e)
      self._phy_namespace_restore(docker_node)
      raise NameSpaceOperatingError("{!r}".format(e)) from e

  def _mount_container_namespace_to_host(self, docker_node):
    if not os.path.isdir(self.RUNTIME_NAMESPACE):
      os.makedirs(self.RUNTIME_NAMESPACE)
    if not os.path.isdir(self.RUNTIME_NAMESPACE):
      raise RuntimeError(
          "unable to create target folder: {}".format(self.RUNTIME_NAMESPACE)
      )

    pid = docker_node.get_container_pid()
    sym_src = "/proc/{}/ns/net".format(pid)
    sym_dst = "/var/run/netns/{}".format(docker_node.name)
    os.symlink(sym_src, sym_dst)
    if not os.path.isfile(sym_dst):
      raise NameSpaceOperatingError(
          "unable mounting container namespace: {} to host".format(
              docker_node.name
          )
      )

  def _add_phy_device_to_container_namespace(self, docker_node):
    ret = utils.host_run(
        docker_node.logger,
        "iw phy {} set netns name {}".format(
            docker_node.wlan_phy_device, docker_node.name
        ),
    )
    if ret.returncode != 0:
      raise NameSpaceOperatingError(
          "failed adding {} to container namespace: {}".format(
              docker_node.wlan_phy_device, docker_node.name
          )
      )

  def _bring_up_wifi_interface(self, docker_node):
    commands = [
        "ip link set {} down".format(docker_node.wlan_interface),
        "ip link set {} name wlan0".format(docker_node.wlan_interface),
        "ip link set wlan0 up",
    ]
    for command in commands:
      ret = utils.netns_run(docker_node.logger, command, docker_node.name)
      if ret.returncode != 0:
        raise IpNetnsExecError(
            "Error: {} on command: {}".format(ret.stderr, command)
        )

  def _phy_namespace_restore(self, docker_node):
    self.logger.debug("running phy device namespace restore...")
    if not os.path.isfile(
        os.path.join(self.RUNTIME_NAMESPACE, docker_node.name)
    ):
      return
    phy_device = getattr(docker_node, "phy_device", None)
    if phy_device and NetNS(docker_node.name).link_lookup(ifname="wlan0"):
      commands = [
          "ip addr flush dev wlan0",
          "ip link set wlan0 down",
          "ip link set wlan0 name {}".format(docker_node.wlan_interface),
          "iw phy {} set netns 1".format(phy_device),
      ]
      for command in commands:
        ret = utils.netns_run(docker_node.logger, command, docker_node.name)
        if ret.returncode != 0:
          raise IpNetnsExecError(
              "Error: {} on command: {}".format(ret.stderr, command)
          )
    self.logger.debug("removing explored namespace: %s", docker_node.name)
    ret = utils.host_run(
        docker_node.logger, "ip netns del {}".format(docker_node.name)
    )
    if ret.returncode != 0:
      raise NameSpaceOperatingError(
          "Error: {} on delete netns: {}".format(ret.stderr, docker_node.name)
      )

  # Backward compatibility aliases for double-underscore methods
  _WiFiCapability__setup_virtual_wifi_station = _setup_virtual_wifi_station
  _WiFiCapability__get_available_phy_device = _get_available_phy_device
  _WiFiCapability__phy_namespace_setup = _phy_namespace_setup
  _WiFiCapability__mount_container_namespace_to_host = (
      _mount_container_namespace_to_host
  )
  _WiFiCapability__add_phy_device_to_container_namespace = (
      _add_phy_device_to_container_namespace
  )
  _WiFiCapability__bring_up_wifi_interface = _bring_up_wifi_interface
  _WiFiCapability__phy_namespace_restore = _phy_namespace_restore

  @staticmethod
  def is_mac80211_hwsim_loaded():
    ret = utils.host_run(
        CirqueLog.get_cirque_logger(), "lsmod | grep mac80211_hwsim"
    )
    return ret.returncode == 0

  @staticmethod
  def load_kernel_mac80211_hwsim(radios=DEFAULT_RADIOS):
    logger = CirqueLog.get_cirque_logger()
    logger.info("kernel module mac80211_hwsim is not loaded, loading now...")
    ret = utils.host_run(
        logger, "modprobe mac80211_hwsim radios={}".format(radios)
    )
    if ret.returncode != 0:
      raise LoadKernelError("unable to load module mac80211_hwsim!!")
    utils.sleep_time(logger, 5, "loading mac80211_hwsim module")
