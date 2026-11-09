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
"""fi.w1.wpa_supplicant1 D-Bus daemon backed by TCP VirtualWiFiServer.

Implements the exact D-Bus object hierarchy, methods, properties, and signals
consumed by unmodified Matter Linux `ConnectivityManagerImpl` and
`NetworkCommissioningWiFiDriver` (`src/platform/Linux/`).

# SIMULATION-DISCLOSURE: The WPA2 supplicant state machine runs in the
# host-side manager rather than inside the container. EAPOL-Key frames (0x888E)
# are exchanged over the TCP data socket directly between the host-side
# supplicant and the VirtualWiFiServer AP authenticator, rather than crossing
# container wlan0. The container wlan0 interface receives standard L2 data frames
# once authentication completes.
"""

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from cirque.common.docker_transport import wait_for_socket_file
from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager
try:
    from gi.repository import Gio
except ImportError:
    Gio = None
try:
    from gi.repository import GLib
except ImportError:
    GLib = None


@dataclass
class _WpaStationState:
  """Typed station state for fi.w1.wpa_supplicant1 D-Bus object hierarchy."""

  state: str = 'disconnected'
  scanning: bool = False
  current_bss: str = '/'
  current_network: str = '/'
  current_auth_mode: str = 'WPA2-PSK'
  bss_paths: List[str] = field(default_factory=list)
  bsss: Dict[str, Dict[str, object]] = field(default_factory=dict)
  network_paths: List[str] = field(default_factory=list)
  networks: Dict[str, Dict[str, object]] = field(default_factory=dict)
  next_net_idx: int = 0
  disconnect_reason: int = 0
  auth_status_code: int = 0
  assoc_status_code: int = 0

  def __getitem__(self, key: str) -> object:
    return getattr(self, key)

  def __setitem__(self, key: str, val: object) -> None:
    setattr(self, key, val)

  def update(self, mapping: Dict[str, object]) -> None:
    for k, v in mapping.items():
      setattr(self, k, v)

logger = logging.getLogger('VirtualWiFiWpaDbus')

WPA_INTROSPECT_XML = """<node>
  <interface name="fi.w1.wpa_supplicant1">
    <method name="CreateInterface">
      <arg name="args" type="a{sv}" direction="in"/>
      <arg name="path" type="o" direction="out"/>
    </method>
    <method name="RemoveInterface">
      <arg name="path" type="o" direction="in"/>
    </method>
    <method name="GetInterface">
      <arg name="ifname" type="s" direction="in"/>
      <arg name="path" type="o" direction="out"/>
    </method>
    <signal name="PropertiesChanged">
      <arg name="properties" type="a{sv}"/>
    </signal>
    <property name="Interfaces" type="ao" access="read"/>
  </interface>
  <interface name="fi.w1.wpa_supplicant1.Interface">
    <method name="Scan">
      <arg name="args" type="a{sv}" direction="in"/>
    </method>
    <method name="Disconnect"/>
    <method name="RemoveAllNetworks"/>
    <method name="SaveConfig"/>
    <method name="AddNetwork">
      <arg name="args" type="a{sv}" direction="in"/>
      <arg name="path" type="o" direction="out"/>
    </method>
    <method name="RemoveNetwork">
      <arg name="path" type="o" direction="in"/>
    </method>
    <method name="SelectNetwork">
      <arg name="path" type="o" direction="in"/>
    </method>
    <signal name="ScanDone">
      <arg name="success" type="b"/>
    </signal>
    <signal name="PropertiesChanged">
      <arg name="properties" type="a{sv}"/>
    </signal>
    <property name="State" type="s" access="read"/>
    <property name="Scanning" type="b" access="read"/>
    <property name="CurrentBSS" type="o" access="read"/>
    <property name="CurrentNetwork" type="o" access="read"/>
    <property name="CurrentAuthMode" type="s" access="read"/>
    <property name="BSSs" type="ao" access="read"/>
    <property name="Networks" type="ao" access="read"/>
    <property name="DisconnectReason" type="i" access="read"/>
    <property name="AuthStatusCode" type="i" access="read"/>
    <property name="AssocStatusCode" type="i" access="read"/>
  </interface>
  <interface name="fi.w1.wpa_supplicant1.BSS">
    <signal name="PropertiesChanged">
      <arg name="properties" type="a{sv}"/>
    </signal>
    <property name="SSID" type="ay" access="read"/>
    <property name="BSSID" type="ay" access="read"/>
    <property name="WPA" type="a{sv}" access="read"/>
    <property name="RSN" type="a{sv}" access="read"/>
    <property name="WPS" type="a{sv}" access="read"/>
    <property name="Frequency" type="q" access="read"/>
    <property name="Signal" type="n" access="read"/>
    <property name="Rates" type="au" access="read"/>
  </interface>
  <interface name="fi.w1.wpa_supplicant1.Network">
    <signal name="PropertiesChanged">
      <arg name="properties" type="a{sv}"/>
    </signal>
    <property name="Properties" type="a{sv}" access="read"/>
    <property name="Enabled" type="b" access="readwrite"/>
  </interface>
</node>"""

WPA_ROOT_PATH = '/fi/w1/wpa_supplicant1'
WPA_IFACE_PATH = '/fi/w1/wpa_supplicant1/Interfaces/0'


def _decode_dbus_bytes_or_str(raw_value: object) -> str:
  """Normalizes a D-Bus byte array, list of ints, or quoted string."""
  if isinstance(raw_value, (bytes, bytearray)):
    return bytes(raw_value).decode('utf-8', errors='replace')
  if isinstance(raw_value, list):
    return bytes(int(b) & 0xFF for b in raw_value).decode(
        'utf-8', errors='replace'
    )
  text = str(raw_value)
  if len(text) >= 2 and text.startswith('"') and text.endswith('"'):
    return text[1:-1]
  return text


class WpaSupplicantDbusService:
  """Exposes fi.w1.wpa_supplicant1 on container D-Bus sockets."""

  def __init__(self, docker_manager: DockerVirtualWiFiManager):
    self.docker_manager = docker_manager
    self._running = False
    self._loop: Optional[GLib.MainLoop] = None
    self._thread: Optional[threading.Thread] = None
    self._lock = threading.RLock()
    self._conns: Dict[str, object] = {}
    self._conn_station: Dict[int, str] = {}
    self._exported_by_conn: Dict[int, set] = {}
    self._owner_ids: List[int] = []
    self._reg_ids: List[int] = []
    self._station_state: Dict[str, _WpaStationState] = {}

  def start(self) -> bool:
    """Starts the background GLib main loop thread."""
    if self._running:
      return True
    self._loop = GLib.MainLoop()
    self._running = True
    self._thread = threading.Thread(
        target=self._loop.run, name='virtual-wifi-wpa-dbus', daemon=True
    )
    self._thread.start()
    return True

  def stop(self) -> None:
    """Stops the background GLib main loop."""
    self._running = False
    if self._loop is not None:
      self._loop.quit()
      self._loop = None

  def _get_or_create_station_dict(self, station_id: str) -> _WpaStationState:
    with self._lock:
      st = self._station_state.get(station_id)
      if st is None:
        st = _WpaStationState()
        self._station_state[station_id] = st
      return st

  def attach_container_bus(
      self, station_id: str, socket_path: str, timeout_s: float = 8.0
  ) -> bool:
    """Attaches fi.w1.wpa_supplicant1 onto a container's D-Bus socket."""
    if not self._running:
      self.start()
    if not wait_for_socket_file(socket_path, timeout_s=timeout_s):
      logger.warning('Container D-Bus socket not found: %s', socket_path)
      return False
    try:
      flags = (
          Gio.DBusConnectionFlags.AUTHENTICATION_CLIENT
          | Gio.DBusConnectionFlags.MESSAGE_BUS_CONNECTION
      )
      conn = Gio.DBusConnection.new_for_address_sync(
          f'unix:path={socket_path}', flags, None, None
      )
      with self._lock:
        self._conns[station_id] = conn
        self._conn_station[id(conn)] = station_id
        self._get_or_create_station_dict(station_id)
        self._register_wpa_objects_on_conn(conn)
        self._refresh_bsss_for_station(conn, station_id)
      return True
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.warning(
          'Failed to attach wpa_supplicant1 for %s: %s', station_id, exc
      )
      return False

  def _export_obj(self, conn, obj_path: str, iface_name: str) -> None:
    exported = self._exported_by_conn.setdefault(id(conn), set())
    if obj_path not in exported:
      node_info = Gio.DBusNodeInfo.new_for_xml(WPA_INTROSPECT_XML)
      reg_id = conn.register_object(
          obj_path,
          node_info.lookup_interface(iface_name),
          self._handle_method_call,
          self._handle_get_property,
          self._handle_set_property,
      )
      self._reg_ids.append(reg_id)
      exported.add(obj_path)

  def _register_wpa_objects_on_conn(self, conn) -> None:
    self._export_obj(conn, WPA_ROOT_PATH, 'fi.w1.wpa_supplicant1')
    self._export_obj(conn, WPA_IFACE_PATH, 'fi.w1.wpa_supplicant1.Interface')
    flags = (
        Gio.BusNameOwnerFlags.ALLOW_REPLACEMENT | Gio.BusNameOwnerFlags.REPLACE
    )
    owner_id = Gio.bus_own_name_on_connection(
        conn, 'fi.w1.wpa_supplicant1', flags, None, None
    )
    self._owner_ids.append(owner_id)

  def _refresh_bsss_for_station(
      self, conn, station_id: str, filter_ssids: Optional[List[str]] = None
  ) -> List[str]:
    server = self.docker_manager.server
    aps = server.list_aps()
    st = self._get_or_create_station_dict(station_id)
    if filter_ssids is not None:
      allowed = set(filter_ssids)
      aps = [ap for ap in aps if ap.ssid in allowed]
    bss_paths, bsss_dict = [], {}
    for idx, ap in enumerate(aps):
      bpath = f'{WPA_IFACE_PATH}/BSSs/{idx}'
      bss_paths.append(bpath)
      bsss_dict[bpath] = {
          'ssid': ap.ssid,
          'bssid': ap.bssid,
          'frequency': ap.frequency,
          'signal': server.scan_signal_dbm(station_id, ap),
      }
      self._export_obj(conn, bpath, 'fi.w1.wpa_supplicant1.BSS')
    st.update({'bss_paths': bss_paths, 'bsss': bsss_dict})
    return bss_paths

  def _emit_iface_props_changed(self, conn, changed: Dict[str, object]) -> None:
    """Emits both standard freedesktop and legacy wpa_supplicant1 signals.

    Why both signals are emitted:
      - Standard GDBus proxies (and Matter's generated `WpaSupplicant1` proxy)
        subscribe to `org.freedesktop.DBus.Properties.PropertiesChanged`.
      - Legacy `wpa_cli` / `wpa_supplicant` D-Bus listeners subscribe to the
        interface-specific `fi.w1.wpa_supplicant1.Interface.PropertiesChanged`
        signal. Emitting both guarantees 100% compatibility.
    """
    iface = 'fi.w1.wpa_supplicant1.Interface'
    conn.emit_signal(
        None,
        WPA_IFACE_PATH,
        'org.freedesktop.DBus.Properties',
        'PropertiesChanged',
        GLib.Variant('(sa{sv}as)', (iface, changed, [])),
    )
    conn.emit_signal(
        None,
        WPA_IFACE_PATH,
        iface,
        'PropertiesChanged',
        GLib.Variant('(a{sv})', (changed,)),
    )

  @staticmethod
  def _extract_scan_filter_ssids(params) -> Optional[List[str]]:
    """Extracts the optional SSIDs filter list from a D-Bus Scan(a{sv}) call."""
    if params is None:
      return None
    try:
      args_dict = params.unpack()[0]
      if isinstance(args_dict, dict) and 'SSIDs' in args_dict:
        return [
            _decode_dbus_bytes_or_str(s) for s in args_dict['SSIDs']
        ]
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.debug('Could not parse scan filter args: %s', exc)
    return None

  def _handle_scan_method(
      self,
      conn,
      station_id: str,
      st: _WpaStationState,
      invocation,
      params=None,
  ) -> None:
    filter_ssids = self._extract_scan_filter_ssids(params)

    bss_paths = self._refresh_bsss_for_station(
        conn, station_id, filter_ssids=filter_ssids
    )
    st.scanning = True
    self._emit_iface_props_changed(
        conn,
        {
            'BSSs': GLib.Variant('ao', bss_paths),
            'Scanning': GLib.Variant('b', True),
        },
    )
    invocation.return_value(GLib.Variant('()', ()))

    def _emit_scan_done() -> bool:
      with self._lock:
        st.scanning = False
        self._emit_iface_props_changed(
            conn, {'Scanning': GLib.Variant('b', False)}
        )
        conn.emit_signal(
            None,
            WPA_IFACE_PATH,
            'fi.w1.wpa_supplicant1.Interface',
            'ScanDone',
            GLib.Variant('(b)', (True,)),
        )
      return False

    GLib.timeout_add(20, _emit_scan_done)

  def _handle_add_network(
      self, conn, st: Dict[str, object], params, invocation
  ) -> None:
    args_dict = params.unpack()[0] if params is not None else {}
    ssid_str = _decode_dbus_bytes_or_str(args_dict.get('ssid', ''))
    psk_str = _decode_dbus_bytes_or_str(args_dict.get('psk', ''))
    idx = int(st['next_net_idx'])
    st['next_net_idx'] = idx + 1
    net_path = f'{WPA_IFACE_PATH}/Networks/{idx}'
    self._export_obj(conn, net_path, 'fi.w1.wpa_supplicant1.Network')
    net_props = {
        'ssid': GLib.Variant('s', f'"{ssid_str}"'),
        'psk': GLib.Variant('s', f'"{psk_str}"'),
        'key_mgmt': GLib.Variant('s', 'WPA-PSK'),
    }
    st['networks'][net_path] = {
        'ssid': ssid_str,
        'psk': psk_str,
        'enabled': True,
        'properties': net_props,
    }
    if net_path not in st['network_paths']:
      st['network_paths'].append(net_path)
    self._emit_iface_props_changed(
        conn, {'Networks': GLib.Variant('ao', list(st['network_paths']))}
    )
    invocation.return_value(GLib.Variant('(o)', (net_path,)))

  def _handle_remove_network(
      self, conn, st: Dict[str, object], params, invocation
  ) -> None:
    net_path = params.unpack()[0]
    st['networks'].pop(net_path, None)
    if net_path in st['network_paths']:
      st['network_paths'].remove(net_path)
    if st['current_network'] == net_path:
      st['current_network'] = '/'
    self._emit_iface_props_changed(
        conn, {'Networks': GLib.Variant('ao', list(st['network_paths']))}
    )
    invocation.return_value(GLib.Variant('()', ()))

  def _complete_network_selection(
      self, conn, station_id: str, st: Dict[str, object], net_path: str
  ) -> bool:
    """Validates WPA2 PSK, unlocks L2 switch, and emits State signals."""
    net_info = st['networks'].get(net_path, {'ssid': '', 'psk': ''})
    bss_paths = self._refresh_bsss_for_station(conn, station_id)
    bss_path = bss_paths[0] if bss_paths else '/'

    emitted_states: List[str] = []

    def on_state_change(new_state: str) -> None:
      emitted_states.append(new_state)
      st['state'] = new_state
      props = {'State': GLib.Variant('s', new_state)}
      if new_state in ('associated', 'completed'):
        props.update({
            'CurrentBSS': GLib.Variant('o', bss_path),
            'CurrentNetwork': GLib.Variant('o', net_path),
            'CurrentAuthMode': GLib.Variant('s', 'WPA2-PSK'),
        })
      self._emit_iface_props_changed(conn, props)

    res = self.docker_manager.connect_station_to_ap(
        station_id,
        str(net_info.get('ssid', '')),
        str(net_info.get('psk', '')),
        on_state_change=on_state_change,
    )
    if res.get('ok'):
      if 'completed' not in emitted_states:
        logger.error(
            'connect_station_to_ap reported ok but supplicant state machine'
            ' never emitted completed state for %s',
            station_id,
        )
        st.update({
            'state': 'disconnected',
            'assoc_status_code': 0,
            'disconnect_reason': -15,
        })
        self._emit_iface_props_changed(
            conn,
            {
                'State': GLib.Variant('s', 'disconnected'),
                'AssocStatusCode': GLib.Variant('i', 0),
                'DisconnectReason': GLib.Variant('i', -15),
            },
        )
        return False
      st.update({
          'state': 'completed',
          'current_bss': bss_path,
          'current_auth_mode': 'WPA2-PSK',
          'assoc_status_code': 0,
          'auth_status_code': 0,
          'disconnect_reason': 0,
      })
      return False
    code = int(res.get('status_code', 15))
    reason = -15 if code == 15 else -code
    st.update({
        'state': 'disconnected',
        'assoc_status_code': 0,
        'disconnect_reason': reason,
    })
    self._emit_iface_props_changed(
        conn,
        {
            'State': GLib.Variant('s', 'disconnected'),
            'AssocStatusCode': GLib.Variant('i', 0),
            'DisconnectReason': GLib.Variant('i', reason),
        },
    )
    return False

  def _handle_select_network(
      self, conn, station_id: str, st: Dict[str, object], params
  ) -> None:
    net_path = params.unpack()[0]
    st['current_network'] = net_path
    st['state'] = 'associating'
    self._emit_iface_props_changed(
        conn,
        {
            'State': GLib.Variant('s', 'associating'),
            'CurrentNetwork': GLib.Variant('o', net_path),
        },
    )
    self._complete_network_selection(conn, station_id, st, net_path)

  def _handle_method_call(
      self,
      conn: object,
      sender: str,
      obj_path: str,
      iface_name: str,
      method_name: str,
      params: object,
      invocation: object,
      *user_data: object,
  ) -> None:
    del sender, obj_path, user_data
    with self._lock:
      station_id = self._conn_station.get(id(conn), 'wifi0')
      st = self._get_or_create_station_dict(station_id)
      if iface_name == 'fi.w1.wpa_supplicant1':
        if method_name in ('GetInterface', 'CreateInterface'):
          self._refresh_bsss_for_station(conn, station_id)
          invocation.return_value(GLib.Variant('(o)', (WPA_IFACE_PATH,)))
          return
        invocation.return_value(GLib.Variant('()', ()))
        return
      if iface_name == 'fi.w1.wpa_supplicant1.Interface':
        if method_name == 'Scan':
          self._handle_scan_method(conn, station_id, st, invocation, params)
          return
        if method_name == 'AddNetwork':
          self._handle_add_network(conn, st, params, invocation)
          return
        if method_name == 'RemoveNetwork':
          self._handle_remove_network(conn, st, params, invocation)
          return
        if method_name == 'RemoveAllNetworks':
          st['networks'].clear()
          st['network_paths'].clear()
          st['current_network'] = '/'
          self._emit_iface_props_changed(
              conn,
              {
                  'Networks': GLib.Variant('ao', []),
                  'CurrentNetwork': GLib.Variant('o', '/'),
              },
          )
        elif method_name == 'SelectNetwork':
          self._handle_select_network(conn, station_id, st, params)
        elif method_name == 'Disconnect':
          self.docker_manager.disconnect_station(station_id)
          st.update({'state': 'disconnected', 'current_bss': '/'})
          self._emit_iface_props_changed(
              conn,
              {
                  'State': GLib.Variant('s', 'disconnected'),
                  'CurrentBSS': GLib.Variant('o', '/'),
              },
          )
      invocation.return_value(GLib.Variant('()', ()))

  def _get_interface_property(
      self, conn, station_id: str, st: Dict[str, object], prop_name: str
  ):
    if prop_name == 'BSSs':
      self._refresh_bsss_for_station(conn, station_id)
      return GLib.Variant('ao', list(st['bss_paths']))
    prop_map = {
        'State': ('s', str(st['state'])),
        'Scanning': ('b', bool(st['scanning'])),
        'CurrentBSS': ('o', str(st['current_bss'])),
        'CurrentNetwork': ('o', str(st['current_network'])),
        'CurrentAuthMode': ('s', str(st['current_auth_mode'])),
        'Networks': ('ao', list(st['network_paths'])),
        'DisconnectReason': ('i', int(st['disconnect_reason'])),
        'AuthStatusCode': ('i', int(st['auth_status_code'])),
        'AssocStatusCode': ('i', int(st['assoc_status_code'])),
    }
    if prop_name in prop_map:
      vtype, vval = prop_map[prop_name]
      return GLib.Variant(vtype, vval)
    return None

  def _get_bss_property(
      self, st: Dict[str, object], obj_path: str, prop_name: str
  ):
    if obj_path not in st['bsss']:
      return None
    bss_info = st['bsss'][obj_path]
    ssid = str(bss_info.get('ssid', ''))
    bssid = str(bss_info.get('bssid', ''))
    bss_map = {
        'SSID': ('ay', [ord(c) & 0xFF for c in ssid]),
        'BSSID': ('ay', [int(x, 16) for x in bssid.split(':')]),
        'Frequency': ('q', int(bss_info.get('frequency', 2437))),
        'Signal': ('n', int(bss_info.get('signal', -40))),
        'Rates': ('au', [54000000, 48000000, 36000000, 24000000]),
        'WPA': ('a{sv}', {'KeyMgmt': GLib.Variant('as', ['wpa-psk'])}),
        'RSN': ('a{sv}', {'KeyMgmt': GLib.Variant('as', ['wpa-psk'])}),
        'WPS': ('a{sv}', {}),
    }
    if prop_name in bss_map:
      vtype, vval = bss_map[prop_name]
      return GLib.Variant(vtype, vval)
    return None

  def _get_network_property(
      self, st: Dict[str, object], obj_path: str, prop_name: str
  ):
    net_info = st['networks'].get(obj_path, {})
    if prop_name == 'Enabled':
      return GLib.Variant('b', bool(net_info.get('enabled', True)))
    if prop_name == 'Properties':
      default_props = {
          'ssid': GLib.Variant('s', '""'),
          'key_mgmt': GLib.Variant('s', 'WPA-PSK'),
      }
      return GLib.Variant('a{sv}', net_info.get('properties', default_props))
    return None

  def _handle_get_property(
      self,
      conn: object,
      sender: str,
      obj_path: str,
      iface_name: str,
      prop_name: str,
      *user_data: object,
  ) -> object:
    del sender, user_data
    with self._lock:
      station_id = self._conn_station.get(id(conn), 'wifi0')
      st = self._get_or_create_station_dict(station_id)
      if iface_name == 'fi.w1.wpa_supplicant1' and prop_name == 'Interfaces':
        return GLib.Variant('ao', [WPA_IFACE_PATH])
      if iface_name == 'fi.w1.wpa_supplicant1.Interface':
        return self._get_interface_property(
            conn, station_id, st, str(prop_name)
        )
      if iface_name == 'fi.w1.wpa_supplicant1.BSS':
        return self._get_bss_property(st, obj_path, str(prop_name))
      if iface_name == 'fi.w1.wpa_supplicant1.Network':
        return self._get_network_property(st, obj_path, str(prop_name))
      return None

  def _handle_set_property(
      self,
      conn: object,
      sender: str,
      obj_path: str,
      iface_name: str,
      prop_name: str,
      value: object,
      *user_data: object,
  ) -> bool:
    del sender, user_data
    with self._lock:
      station_id = self._conn_station.get(id(conn), 'wifi0')
      st = self._get_or_create_station_dict(station_id)
      if (
          iface_name == 'fi.w1.wpa_supplicant1.Network'
          and prop_name == 'Enabled'
          and obj_path in st['networks']
      ):
        st['networks'][obj_path]['enabled'] = bool(value.unpack())
      return True
