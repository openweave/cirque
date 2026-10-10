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
"""Kernel-module-free Virtual Wi-Fi emulation subsystem for Cirque.

This package replaces the Linux kernel `mac80211_hwsim.ko` module with a 100%
userspace Virtual Wi-Fi architecture designed for unprivileged CI runners
(such as GitHub Actions `ubuntu-latest`) and containerized Matter testbeds:

1. `VirtualWiFiServer` (`server.py`):
   Host-side 3-port TCP daemon implementing:
   - Control Plane (`control_port`): AP registration (`REGISTER_AP`), active
     802.11 scan discovery (`SCAN`), WPA2-PSK authentication (`CONNECT`),
     disassociation (`DISCONNECT`), and station state inspection (`GET_STATE`).
   - Management Plane (`mgmt_port`): Asynchronous 802.11 state transition and
     WPA2 4-way handshake event stream (`SCAN_DONE`, `STATE_CHANGE`).
   - Data Plane (`data_port`): Virtual IEEE 802.11 / Ethernet L2 switch that
     relays unicast, multicast (mDNS `224.0.0.251` / `ff02::fb`), and broadcast
     Ethernet frames strictly between stations whose WPA2 state is `completed`.

2. `DockerVirtualWiFiManager` (`docker_wifi_bridge.py`):
   Manages per-container `wlan0` TAP/veth L2 network interfaces, Unix domain
   socket proxies (`/dev/virtual_wifi/control.sock`,
   `/dev/virtual_wifi/data.sock`),
   and container-local `vwifi_l2_agent.py` frame forwarders.

3. `WpaSupplicantDbusService` (`wpa_dbus_daemon.py`):
   Per-container `fi.w1.wpa_supplicant1` D-Bus service attached to each
   container's system D-Bus (`unix:path=/var/run/dbus/system_bus_socket`),
   exposing `Interface`, `BSS`, and `Network` objects compatible with
   unmodified Matter Linux `ConnectivityManagerImpl` and `WpaSupplicantClient`.
"""

from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager
from cirque.virtual_wifi.server import VirtualWiFiServer
from cirque.virtual_wifi.wpa_dbus_daemon import WpaSupplicantDbusService

__all__ = [
    'DockerVirtualWiFiManager',
    'VirtualWiFiServer',
    'WpaSupplicantDbusService',
]
