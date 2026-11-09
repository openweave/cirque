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

import os
import random
import time

from cirque.capabilities.wificapability import WiFiCapability
from cirque.common.exceptions import (
    ContainerExecError,
    IpNetnsExecError,
)
import cirque.common.utils as utils
from cirque.nodes.dockernode import DockerNode

RUNTIME_NAMESPACE = "/var/run/netns"
CHAR_SRC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"


class WiFiAPNode(DockerNode):
  """Simulated Wi-Fi Access Point node with Virtual Wi-Fi and legacy hostapd.

  In default userspace Virtual Wi-Fi mode (`use_virtual_wifi_tcp=True`):
    - Registers the Access Point SSID, WPA2 PSK, BSSID (`02:00:00:00:01:01`),
      and gateway addresses (`10.0.1.1/24`, `fd11:22::1/64`) with the host
      `VirtualWiFiServer`.
    - Does not require `mac80211_hwsim.ko` or `mac80211_ap_image` (gracefully
      falls back to `cirque-device-base:latest` if
      `mac80211_ap_image` is not built locally).

  In legacy kernel mode (`use_virtual_wifi_tcp=False` or
  `CIRQUE_USE_LEGACY_HWSIM=1`):
    - Moves a `mac80211_hwsim` `phyX` radio into the container's network
      namespace and starts `hostapd` and `dnsmasq` inside the container.
  """

  def __init__(
      self,
      docker_client,
      ssid=None,
      password=None,
      container_name=None,
      base_image="mac80211_ap_image",
      *,
      capabilities=None,
      use_virtual_wifi_tcp=None,
      labels=None,
  ):
    """Initializes WiFiAPNode container and registers AP on VirtualWiFiServer.
    """
    if use_virtual_wifi_tcp is None:
      legacy_env = (
          os.environ.get("CIRQUE_USE_LEGACY_HWSIM", "0").strip().lower()
      )
      use_virtual_wifi_tcp = legacy_env not in ("1", "true", "yes")
    resolved_image = self._resolve_ap_base_image(docker_client, base_image)
    init_caps = list(capabilities) if capabilities else []
    super().__init__(
        docker_client,
        node_type="wifi_ap",
        capabilities=init_caps,
        base_image=resolved_image,
        labels=labels,
    )
    random.seed(time.time())
    self.ssid = ssid
    self.password = password
    self.container_name = container_name
    self.wifi_capability = None
    for cap in self.capabilities:
      if getattr(cap, "name", "") == "WiFi":
        self.wifi_capability = cap
        self.wifi_capability.is_ap = True
        self.wifi_capability.auto_connect = True
        break
    if self.wifi_capability is None:
      self.wifi_capability = WiFiCapability(
          use_virtual_wifi_tcp=use_virtual_wifi_tcp,
          auto_connect=True,
          is_ap=True,
      )
      self.capabilities.append(self.wifi_capability)
    if not self.ssid:
      self.ssid = self.get_wifi_ssid()
    if not self.password:
      self.password = self.get_wifi_password()
    if self.wifi_capability.use_virtual_wifi_tcp:
      WiFiCapability.register_virtual_ap(
          ssid=self.ssid,
          psk=self.password,
      )

  @staticmethod
  def _resolve_ap_base_image(docker_client, requested_image):
    try:
      docker_client.images.get(requested_image)
      return requested_image
    except Exception:  # pylint: disable=broad-exception-caught
      fallback = os.environ.get("CIRQUE_BASE_IMAGE") or os.environ.get(
          "CHIP_CIRQUE_BASE_IMAGE"
      )
      candidates = [fallback] if fallback else []
      candidates.extend((
          "cirque-device-base:latest",
          "cirque-virtual-rf-node:latest",
          "generic_node_image",
      ))
      for cand in candidates:
        try:
          docker_client.images.get(cand)
          return cand
        except Exception:
          continue
      return fallback or "cirque-device-base:latest"

  def __del__(self):
    if hasattr(self, "container") and self.container:
      self.stop()

  @property
  def type(self):
    return "wifi_ap"

  @property
  def description(self):
    return {
        "type": "wifi_ap",
        "ssid": self.ssid,
        "psk": self.password,
        "ipv4_addr": "10.0.1.1",
        "ipv6_addr": "fd11:22::1",
    }

  def stop(self):
    if hasattr(self, "container") and self.container:
      self._teardown()
      self.container.stop(timeout=0)
      try:
        self.container.remove(force=True)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        self.logger.debug("WiFiAPNode container remove failed: %s", exc)
      self.container = None

  def run(self):
    kwargs = {"stdin_open": True, "cap_add": ["NET_ADMIN"]}

    if self.container_name:
      kwargs.update({"name": self.container_name})

    super().run(**kwargs)
    self.logger.info("Creating WiFi AP node: %s", self.name)
    if self.wifi_capability.use_virtual_wifi_tcp:
      WiFiCapability.register_virtual_ap(
          ssid=self.ssid,
          psk=self.password,
          ap_id=self.name or "ap0",
      )
      try:
        self._setup_network_forward_rules()
      except Exception as exc:  # pylint: disable=broad-exception-caught
        self.logger.debug(
            "Forward rule setup skipped in virtual Wi-Fi: %s", exc
        )
      return

    self._setup_namespace_networking_env()
    self._setup_network_forward_rules()
    self._update_hostapd_ssid()
    self._update_hostapd_password()
    self._run_hostapd()
    self._run_dnsmasq()
    utils.sleep_time(self.logger, 2, "creating WiFi AP node")

  def get_wifi_ssid(self):
    return (
        self.ssid
        if self.ssid
        else "-".join(
            ["wifiap", "".join(random.choice(CHAR_SRC) for _ in range(5))]
        )
    )

  def get_wifi_password(self):
    return (
        self.password
        if self.password
        else "".join(random.choice(CHAR_SRC) for _ in range(8))
    )

  def _run_hostapd(self):
    ret = self.container.exec_run(
        "/usr/sbin/hostapd -B /etc/hostapd/hostapd.conf"
    )
    if ret.exit_code != 0:
      raise ContainerExecError("unable to start up hostapd server!!")

  def _run_dnsmasq(self):
    ret = self.container.exec_run("/usr/sbin/dnsmasq -C /etc/dnsmasq.conf")
    if ret.exit_code != 0:
      raise ContainerExecError("unable to start up dnsmasq server!!")

  def _setup_namespace_networking_env(self):
    network_commands = [
        "ip addr flush dev wlan0",
        "ip addr add 10.0.1.1/24 dev wlan0",
    ]

    for command in network_commands:
      ret = utils.netns_run(self.logger, command, self.name)
      if ret.returncode != 0:
        raise IpNetnsExecError(
            "failed to run cmd: {}\n {}".format(command, ret.stderr)
        )

    ret = self.container.exec_run("route add -net 10.0.1.0/24 gw 10.0.1.1")
    if ret.exit_code != 0:
      raise ContainerExecError("unable to set default gw for wlan0")

  def _setup_network_forward_rules(self):
    forward_rules = [
        "iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE",
        (
            "iptables -A FORWARD -i eth0 -o wlan0 -m "
            "state --state RELATED,ESTABLISHED -j ACCEPT"
        ),
        "iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT",
    ]

    for rule in forward_rules:
      ret = self.container.exec_run(rule)
      if ret.exit_code != 0 and not self.wifi_capability.use_virtual_wifi_tcp:
        raise ContainerExecError("unable to set forward rule: {}".format(rule))

  def _update_hostapd_ssid(self):
    ret = self.container.exec_run(
        "sed -i 's/ssid=/ssid={}/' /etc/hostapd/hostapd.conf".format(self.ssid)
    )
    if ret.exit_code != 0:
      raise ContainerExecError(
          "failed to set wifi ap ssid: {}".format(self.ssid)
      )

  def _update_hostapd_password(self):
    ret = self.container.exec_run(
        "sed -i 's/wpa_passphrase=/wpa_passphrase={}/' "
        "/etc/hostapd/hostapd.conf".format(self.password)
    )
    if ret.exit_code != 0:
      raise ContainerExecError(
          "failed to set wifi ap password: {}".format(self.password)
      )

  def _teardown(self):
    if not self.wifi_capability.use_virtual_wifi_tcp:
      self.logger.info("stopping hostapd...")
      self.container.exec_run("killall hostapd")
      self.logger.info("stopping dnsmasq...")
      self.container.exec_run("killall dnsmasq")
    self.wifi_capability.disable_capability(self)

  _WiFiAPNode__run_hostapd = _run_hostapd
  _WiFiAPNode__run_dnsmasq = _run_dnsmasq
  _WiFiAPNode__setup_namespace_networking_env = _setup_namespace_networking_env
  _WiFiAPNode__setup_network_forward_rules = _setup_network_forward_rules
  _WiFiAPNode__update_hostapd_ssid = _update_hostapd_ssid
  _WiFiAPNode__update_hostapd_password = _update_hostapd_password
  _WiFiAPNode__teardown = _teardown
