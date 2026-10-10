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
"""Docker HCI PTY, Unix control proxy, hciconfig, and BlueZ bridge."""

import logging
import os
import pty
import select
import socket
import threading
import time
import tty
from typing import Dict, Optional, Tuple

from cirque.common.docker_transport import (
    UnixToTcpProxy,
    prepare_container_dbus_dir,
    write_executable_script,
)
from cirque.virtual_bt.adapter_bridge import (
    ATT_CID,
    VirtualBluezAdapterBridge,
)
from cirque.virtual_bt.att_db import (
    ATT_OP_HANDLE_VALUE_CFM,
    ATT_OP_HANDLE_VALUE_IND,
    ATT_OP_WRITE_REQ,
    ATT_OP_WRITE_RSP,
)
from cirque.virtual_bt.gatt_profile import BleGattProfile

logger = logging.getLogger('VirtualBtDockerBridge')

__all__ = [
    'ATT_CID',
    'ATT_OP_HANDLE_VALUE_CFM',
    'ATT_OP_HANDLE_VALUE_IND',
    'ATT_OP_WRITE_REQ',
    'ATT_OP_WRITE_RSP',
    'DockerVirtualBtManager',
    'VirtualBluezAdapterBridge',
    'VirtualPtyHciBridge',
]


# Matter BLE names that older callers imported from this module. They are
# resolved lazily from cirque.protocols.matter.ble_bridge so that importing the
# virtual Bluetooth core does not import any application protocol.
_LEGACY_MATTER_NAMES = frozenset({
    'MATTER_C1_UUID_STR',
    'MATTER_C2_UUID_STR',
    'MATTER_SERVICE_UUID_SHORT',
    'MATTER_SERVICE_UUID_STR',
    'build_matter_ble_adv_payload',
    'parse_matter_ble_service_data',
})


def __getattr__(name):
  if name in _LEGACY_MATTER_NAMES:
    from cirque.protocols.matter import ble_bridge  # pylint: disable=g-import-not-at-top
    return getattr(ble_bridge, name)
  raise AttributeError(f'module {__name__!r} has no attribute {name!r}')

_ORG_BLUEZ_DBUS_CONF_XML = (
    '<!DOCTYPE busconfig PUBLIC\n'
    ' "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"\n'
    ' "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">\n'
    '<busconfig>\n'
    '  <policy context="default">\n'
    '    <allow own="org.bluez"/>\n'
    '    <allow send_destination="org.bluez"/>\n'
    '    <allow send_interface="org.bluez.Adapter1"/>\n'
    '    <allow send_interface="org.bluez.GattManager1"/>\n'
    '    <allow send_interface="org.bluez.LEAdvertisingManager1"/>\n'
    '    <allow send_interface="org.bluez.Device1"/>\n'
    '    <allow send_interface="org.bluez.GattService1"/>\n'
    '    <allow send_interface="org.bluez.GattCharacteristic1"/>\n'
    '    <allow send_interface="org.bluez.GattDescriptor1"/>\n'
    '    <allow send_interface="org.bluez.GattProfile1"/>\n'
    '    <allow send_interface="org.bluez.LEAdvertisement1"/>\n'
    '    <allow send_interface="org.freedesktop.DBus.ObjectManager"/>\n'
    '    <allow send_interface="org.freedesktop.DBus.Properties"/>\n'
    '    <allow send_interface="org.freedesktop.DBus.Introspectable"/>\n'
    '  </policy>\n'
    '</busconfig>\n'
)

_HCICONFIG_SHIM_TEMPLATE = """#!/usr/bin/env python3
import json, os, socket, struct, sys

HOST = os.environ.get('VIRTUAL_BT_HOST', '{host}')
PORT = int(os.environ.get('VIRTUAL_BT_CONTROL_PORT', '{control_port}'))
RUNTIME_DIR = '{runtime_dir}'
UNIX_CONTROL_SOCKS = ('/dev/virtual_bt/control.sock', '{control_sock_path}')

def rpc(cmd, **params):
  payload = (json.dumps({{'cmd': cmd, **params}}) + '\\n').encode('utf-8')
  for usock in UNIX_CONTROL_SOCKS:
    if os.path.exists(usock):
      try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
          s.settimeout(3.0)
          s.connect(usock)
          s.sendall(payload)
          return json.loads(s.makefile('r', encoding='utf-8').readline())
      except OSError as e:
        if os.environ.get('VIRTUAL_BT_DEBUG'):
          sys.stderr.write(f'Unix control sock error: {{e}}\\n')
  try:
    with socket.create_connection((HOST, PORT), timeout=3.0) as s:
      s.sendall(payload)
      return json.loads(s.makefile('r', encoding='utf-8').readline())
  except OSError as e:
    if os.environ.get('VIRTUAL_BT_DEBUG'):
      sys.stderr.write(f'TCP control port error: {{e}}\\n')
    return {{}}

def send_h4_cmd(sock, opcode, params=b''):
  cmd_pdu = bytes([1]) + struct.pack('<HB', opcode, len(params)) + params
  sock.sendall(cmd_pdu)
  buf = b''
  sock.settimeout(2.0)
  while len(buf) < 3:
    chunk = sock.recv(64)
    if not chunk:
      return None
    buf += chunk
  if buf[0] != 4:
    return None
  param_len = buf[2]
  while len(buf) < 3 + param_len:
    chunk = sock.recv(64)
    if not chunk:
      break
    buf += chunk
  if len(buf) >= 6 and buf[1] == 0x0E:
    return buf[6:]
  return None

def query_h4_for_controller(cid, port=None):
  candidates = [
      '/dev/virtual_bt/hci_bridge.sock',
      f'{{RUNTIME_DIR}}/containers/{{cid}}/hci_bridge.sock',
  ]
  sock = None
  for c_sock in candidates:
    if os.path.exists(c_sock):
      try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(c_sock)
        sock = s
        break
      except OSError as e:
        if os.environ.get('VIRTUAL_BT_DEBUG'):
          sys.stderr.write(f'Failed to connect {{c_sock}}: {{e}}\\n')
  if sock is None and port:
    try:
      s = socket.create_connection((HOST, port), timeout=2.0)
      sock = s
    except OSError as e:
      if os.environ.get('VIRTUAL_BT_DEBUG'):
        sys.stderr.write(f'Failed to connect {{HOST}}:{{port}}: {{e}}\\n')

  if sock is None:
    sys.stderr.write(f"Can't connect to H4 transport for device {{cid}}\\n")
    return None

  try:
    bd_resp = send_h4_cmd(sock, 0x1009)
    bd_addr = None
    if bd_resp and len(bd_resp) >= 7 and bd_resp[0] == 0:
      bd_addr = ':'.join(f'{{b:02X}}' for b in reversed(bd_resp[1:7]))

    ver_resp = send_h4_cmd(sock, 0x1001)
    version_info = None
    if ver_resp and len(ver_resp) >= 9 and ver_resp[0] == 0:
      hci_ver = ver_resp[1]
      hci_rev = struct.unpack('<H', ver_resp[2:4])[0]
      lmp_ver = ver_resp[4]
      mfg = struct.unpack('<H', ver_resp[5:7])[0]
      lmp_subver = struct.unpack('<H', ver_resp[7:9])[0]
      version_info = (hci_ver, hci_rev, lmp_ver, mfg, lmp_subver)

    buf_resp = send_h4_cmd(sock, 0x1005)
    mtu_info = None
    if buf_resp and len(buf_resp) >= 8 and buf_resp[0] == 0:
      acl_len = struct.unpack('<H', buf_resp[1:3])[0]
      sco_len = buf_resp[3]
      num_acl = struct.unpack('<H', buf_resp[4:6])[0]
      num_sco = struct.unpack('<H', buf_resp[6:8])[0]
      mtu_info = (acl_len, num_acl, sco_len, num_sco)

    scan_resp = send_h4_cmd(sock, 0x0C19)
    scan_flags = None
    if scan_resp and len(scan_resp) >= 2 and scan_resp[0] == 0:
      scan_flags = scan_resp[1]

    return {{
        'bd_addr': bd_addr,
        'version': version_info,
        'mtu': mtu_info,
        'scan_flags': scan_flags,
    }}
  except OSError as e:
    sys.stderr.write(f'H4 command failed for device {{cid}}: {{e}}\\n')
    return None
  finally:
    try:
      sock.close()
    except OSError as e:
      if os.environ.get('VIRTUAL_BT_DEBUG'):
        sys.stderr.write(f'Error closing H4 socket: {{e}}\\n')

def format_ctrl(c, verbose=False):
  cid = c.get('controller_id', 'hci0')
  port = c.get('dedicated_hci_port')
  h4_info = query_h4_for_controller(cid, port)

  if not h4_info or not h4_info.get('bd_addr') or not h4_info.get('mtu'):
    sys.stderr.write(f"Can't read info for device {{cid}}: H4 query failed\\n")
    return None

  bd = h4_info['bd_addr']
  acl_len, num_acl, sco_len, num_sco = h4_info['mtu']
  acl_mtu_str = f'{{acl_len}}:{{num_acl}}'
  sco_mtu_str = f'{{sco_len}}:{{num_sco}}'

  flags = ['UP', 'RUNNING']
  scan_val = h4_info.get('scan_flags')
  if scan_val is not None:
    if scan_val & 0x02:
      flags.append('PSCAN')
    if scan_val & 0x01:
      flags.append('ISCAN')
  flags_str = ' '.join(flags)

  rx = c.get('rx_packets', 0)
  tx = c.get('tx_packets', 0)
  arx = c.get('acl_rx_packets', 0)
  atx = c.get('acl_tx_packets', 0)

  lines = [
      f'{{cid}}:\\tType: Primary  Bus: Virtual',
      f'\\tBD Address: {{bd}}'
      f'  ACL MTU: {{acl_mtu_str}}  SCO MTU: {{sco_mtu_str}}',
      f'\\t{{flags_str}}',
      f'\\tRX acl:{{arx}} events:{{tx}}',
      f'\\tTX acl:{{atx}} commands:{{rx}}',
  ]
  if verbose and h4_info.get('version'):
    hci_ver, hci_rev, lmp_ver, mfg, lmp_subver = h4_info['version']
    lines.append(
        f'\\tHCI Version: {{hci_ver}} (0x{{hci_ver:x}})'
        f'  Revision: 0x{{hci_rev:04x}}'
    )
    lines.append(
        f'\\tLMP Version: {{lmp_ver}} (0x{{lmp_ver:x}})'
        f'  Subversion: 0x{{lmp_subver:04x}}'
    )
    mfg_str = f'Google LLC ({{mfg}})' if mfg == 0x00E0 else f'({{mfg}})'
    lines.append(f'\\tManufacturer: {{mfg_str}}')

  return '\\n'.join(lines) + '\\n'

def main():
  verbose = '-a' in sys.argv
  args = [a for a in sys.argv[1:] if not a.startswith('-')]
  ctrls = rpc('list_controllers').get('controllers', [])
  if not ctrls:
    sys.stderr.write("Can't find any virtual controllers\\n")
    return 1
  if not args:
    for c in ctrls:
      out = format_ctrl(c, verbose=verbose)
      if out is None:
        return 1
      print(out, end='')
    return 0
  for c in ctrls:
    if c.get('controller_id') == args[0]:
      out = format_ctrl(c, verbose=verbose)
      if out is None:
        return 1
      print(out, end='')
      return 0
  sys.stderr.write(f"Can't get device info: No such device ({{args[0]}})\\n")
  return 1

if __name__ == '__main__':
  sys.exit(main())
"""


class VirtualPtyHciBridge:
  """Bridges a POSIX PTY device (/tmp/cirque_virtual_bt/hciX) to TCP H4."""

  def __init__(
      self,
      controller_id: str,
      host: str,
      hci_tcp_port: int,
      runtime_dir: str = '/tmp/cirque_virtual_bt',
  ):
    self.controller_id = controller_id
    self.host = host
    self.hci_tcp_port = hci_tcp_port
    self.runtime_dir = runtime_dir
    self.master_fd: Optional[int] = None
    self.slave_fd: Optional[int] = None
    self.slave_name: str = ''
    self.symlink_path: str = os.path.join(runtime_dir, controller_id)
    self._running = False
    self._thread: Optional[threading.Thread] = None
    self._sock: Optional[socket.socket] = None

  def start(self) -> str:
    """Starts the PTY-to-TCP H4 relay thread and returns the device symlink."""
    os.makedirs(self.runtime_dir, exist_ok=True)
    self.master_fd, self.slave_fd = pty.openpty()
    tty.setraw(self.slave_fd)
    os.set_blocking(self.master_fd, False)
    self.slave_name = os.ttyname(self.slave_fd)
    try:
      os.chmod(self.slave_name, 0o666)
    except OSError as exc:
      logger.debug('chmod pty failed: %s', exc)
    if os.path.lexists(self.symlink_path):
      try:
        os.unlink(self.symlink_path)
      except OSError as exc:
        logger.debug('unlink old pty symlink failed: %s', exc)
    os.symlink(self.slave_name, self.symlink_path)
    # The controller's dedicated H4 port may still be coming up; retry
    # refused connections for up to ~10 s before a final attempt.
    for _ in range(20):
      try:
        self._sock = socket.create_connection(
            (self.host, self.hci_tcp_port), timeout=5.0
        )
        break
      except ConnectionRefusedError:
        time.sleep(0.5)
    else:
      self._sock = socket.create_connection(
          (self.host, self.hci_tcp_port), timeout=5.0
      )
    self._sock.settimeout(None)
    self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    self._running = True
    self._thread = threading.Thread(
        target=self._pump_loop, name=f'pty-h4-{self.controller_id}', daemon=True
    )
    self._thread.start()
    return self.symlink_path

  def _relay_single_fd(
      self, fd: int, master_fd: int, sock: socket.socket
  ) -> bool:
    """Relays one ready file descriptor; returns False when stream closes."""
    if fd == master_fd:
      try:
        data = os.read(master_fd, 4096)
        if not data:
          return False
        sock.sendall(data)
        return True
      except OSError:
        return False
    try:
      data = sock.recv(4096)
      if not data:
        self._running = False
        return False
      try:
        os.write(master_fd, data)
      except BlockingIOError as exc:
        logger.debug('Master fd write would block: %s', exc)
      return True
    except OSError:
      self._running = False
      return False

  def _pump_loop(self) -> None:
    master_fd, sock = self.master_fd, self._sock
    if master_fd is None or sock is None:
      return
    try:
      sock_fd = sock.fileno()
    except OSError:
      return
    while self._running:
      try:
        rlist, _, _ = select.select([master_fd, sock_fd], [], [], 0.1)
      except (ValueError, OSError):
        break
      for fd in rlist:
        if not self._running or not self._relay_single_fd(fd, master_fd, sock):
          break

  def stop(self) -> None:
    self._running = False
    if self._sock is not None:
      try:
        self._sock.close()
      except OSError as exc:
        logger.debug('PTY sock close: %s', exc)
      self._sock = None
    for fd in (self.master_fd, self.slave_fd):
      if fd is not None:
        try:
          os.close(fd)
        except OSError as exc:
          logger.debug('PTY fd close: %s', exc)
    self.master_fd = None
    self.slave_fd = None
    if os.path.lexists(self.symlink_path):
      try:
        os.unlink(self.symlink_path)
      except OSError as exc:
        logger.debug('PTY symlink unlink: %s', exc)
    if self._thread is not None and self._thread.is_alive():
      self._thread.join(timeout=1.5)


class DockerVirtualBtManager:
  """Manages Docker-visible HCI PTYs, Unix control socket, and hciconfig."""

  def __init__(
      self,
      host: str,
      control_port: int,
      hci_port: int,
      phy_port: int = 0,
      runtime_dir: Optional[str] = None,
      gatt_profile: Optional[BleGattProfile] = None,
  ) -> None:
    """Starts the Unix control socket proxy and writes the hciconfig shim.

    Args:
      host: Host of the VirtualBluetoothServer.
      control_port: TCP port of the server's JSON control channel.
      hci_port: TCP port of the server's shared H4 channel.
      phy_port: TCP port of the server's link-layer PHY channel.
      runtime_dir: Host directory for sockets, PTY links, and generated files.
        Defaults to $CIRQUE_VIRTUAL_BT_RUNTIME_DIR or /tmp/cirque_virtual_bt
        (falling back to /tmp/cirque_virtual_bt_<uid> when unwritable).
      gatt_profile: BLE GATT profile the adapter bridges emulate. Defaults to
        cirque.virtual_bt.gatt_profile.get_default_profile(), resolved when a
        bridge first needs it.
    """
    if runtime_dir is None:
      env_runtime_dir = os.environ.get('CIRQUE_VIRTUAL_BT_RUNTIME_DIR')
      if env_runtime_dir:
        runtime_dir = env_runtime_dir
      else:
        default_dir = '/tmp/cirque_virtual_bt'
        if os.path.lexists(default_dir) and not os.access(
            default_dir, os.W_OK
        ):
          runtime_dir = f'/tmp/cirque_virtual_bt_{os.getuid()}'
        else:
          runtime_dir = default_dir
    self.host = host
    self.host_gateway = host
    self.control_port = control_port
    self.hci_port = hci_port
    self.phy_port = phy_port
    self.runtime_dir = runtime_dir
    self.gatt_profile = gatt_profile
    self.bin_dir = os.path.join(runtime_dir, 'bin')
    self.dbus_dir = os.path.join(runtime_dir, 'dbus')
    self.containers_dir = os.path.join(runtime_dir, 'containers')
    self.org_bluez_conf_path = os.path.join(runtime_dir, 'org.bluez.conf')
    self.control_sock_path = os.path.join(runtime_dir, 'control.sock')
    self.shared_hci_sock_path = os.path.join(runtime_dir, 'shared_hci.sock')
    self.hciconfig_path = os.path.join(self.bin_dir, 'hciconfig')
    self.tcp_relay_path = os.path.join(self.bin_dir, 'bt_tcp_to_unix_relay.py')
    self.pty_bridges: Dict[str, VirtualPtyHciBridge] = {}
    self.adapter_bridges: Dict[str, VirtualBluezAdapterBridge] = {}
    self.hci_proxies: Dict[str, UnixToTcpProxy] = {}
    self._lock = threading.RLock()
    self._control_proxy = UnixToTcpProxy(
        self.control_sock_path,
        host,
        control_port,
        backlog=16,
        connect_timeout_s=3.0,
        io_timeout_s=3.0,
        name='virtual-bt-unix-proxy',
    )
    self._shared_hci_proxy: Optional[UnixToTcpProxy] = None
    if hci_port > 0:
      self._shared_hci_proxy = UnixToTcpProxy(
          self.shared_hci_sock_path,
          host,
          hci_port,
          backlog=16,
          bidirectional=True,
          name='virtual-bt-shared-hci-proxy',
      )
    os.makedirs(self.dbus_dir, exist_ok=True)
    os.makedirs(self.containers_dir, exist_ok=True)
    self._generate_org_bluez_dbus_conf()
    self._control_proxy.start()
    if self._shared_hci_proxy is not None:
      self._shared_hci_proxy.start()
    try:
      self._generate_hciconfig_shim()
      self._generate_tcp_relay_script()
    except BaseException:
      if self._shared_hci_proxy is not None:
        self._shared_hci_proxy.stop()
      self._control_proxy.stop()
      raise

  def _generate_tcp_relay_script(self) -> None:
    """Writes a helper that relays container TCP to a mounted Unix socket."""
    script = (
        '#!/usr/bin/env python3\n'
        'import select, socket, sys, threading\n'
        'def pump(a, b):\n'
        '  try:\n'
        '    while True:\n'
        '      r, _, _ = select.select([a, b], [], [], 1.0)\n'
        '      for s in r:\n'
        '        d = s.recv(4096)\n'
        '        if not d: return\n'
        '        (b if s is a else a).sendall(d)\n'
        '  except OSError: pass\n'
        '  finally:\n'
        '    for s in (a, b):\n'
        '      try: s.close()\n'
        '      except OSError: pass\n'
        'def main():\n'
        '  port, usock = int(sys.argv[1]), sys.argv[2]\n'
        '  srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n'
        '  srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n'
        '  srv.bind(("0.0.0.0", port))\n'
        '  srv.listen(16)\n'
        '  while True:\n'
        '    c, _ = srv.accept()\n'
        '    c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)\n'
        '    u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n'
        '    u.connect(usock)\n'
        '    threading.Thread(target=pump, args=(c, u), daemon=True).start()\n'
        'if __name__ == "__main__": main()\n'
    )
    write_executable_script(self.tcp_relay_path, script, mode=0o755)

  def _generate_org_bluez_dbus_conf(self) -> str:
    """Writes /tmp/cirque_virtual_bt/org.bluez.conf for container D-Bus."""
    os.makedirs(self.runtime_dir, exist_ok=True)
    try:
      if os.path.exists(self.org_bluez_conf_path):
        os.unlink(self.org_bluez_conf_path)
    except OSError as exc:
      logger.debug('unlink org.bluez.conf: %s', exc)
    try:
      with open(self.org_bluez_conf_path, 'w', encoding='utf-8') as f:
        f.write(_ORG_BLUEZ_DBUS_CONF_XML)
    except PermissionError:
      fallback_dir = f'/tmp/cirque_virtual_bt_{os.getuid()}'
      os.makedirs(fallback_dir, exist_ok=True)
      self.org_bluez_conf_path = os.path.join(fallback_dir, 'org.bluez.conf')
      with open(self.org_bluez_conf_path, 'w', encoding='utf-8') as f:
        f.write(_ORG_BLUEZ_DBUS_CONF_XML)
    try:
      os.chmod(self.org_bluez_conf_path, 0o644)
    except OSError as exc:
      logger.debug('chmod org.bluez.conf: %s', exc)
    return self.org_bluez_conf_path

  def get_container_dbus_dir(self, controller_id: str) -> str:
    """Returns a dedicated /run/dbus host directory for a single container."""
    return prepare_container_dbus_dir(
        os.path.join(self.containers_dir, controller_id, 'dbus')
    )

  def _generate_hciconfig_shim(self) -> None:
    """Generates a drop-in hciconfig binary script backed by Unix/TCP socket."""
    script = _HCICONFIG_SHIM_TEMPLATE.format(
        host=self.host,
        control_port=self.control_port,
        control_sock_path=self.control_sock_path,
        runtime_dir=self.runtime_dir,
    )
    write_executable_script(self.hciconfig_path, script, mode=0o755)

  def register_controller(
      self, controller_id: str, bd_addr: str, dedicated_hci_port: int
  ) -> Tuple[str, VirtualBluezAdapterBridge]:
    """Starts PTY device + VirtualBluezAdapterBridge for a controller."""
    with self._lock:
      self._generate_hciconfig_shim()
      pty_bridge = VirtualPtyHciBridge(
          controller_id=controller_id,
          host=self.host,
          hci_tcp_port=dedicated_hci_port,
          runtime_dir=self.runtime_dir,
      )
      pty_path = pty_bridge.start()
      self.pty_bridges[controller_id] = pty_bridge

      adapter_bridge = VirtualBluezAdapterBridge(
          controller_id=controller_id,
          bd_addr=bd_addr,
          host=self.host,
          dedicated_hci_port=dedicated_hci_port,
          profile=self.gatt_profile,
      )
      adapter_bridge.start()
      self.adapter_bridges[controller_id] = adapter_bridge

      container_dir = os.path.join(self.containers_dir, controller_id)
      os.makedirs(container_dir, exist_ok=True)
      hci_sock_path = os.path.join(container_dir, 'hci_bridge.sock')
      hci_proxy = UnixToTcpProxy(
          hci_sock_path,
          self.host_gateway,
          dedicated_hci_port,
          bidirectional=True,
          name=f'virtual-bt-hci-proxy-{controller_id}',
      )
      hci_proxy.start()
      self.hci_proxies[controller_id] = hci_proxy

      symlink_hci = os.path.join(self.runtime_dir, 'hci_bridge.sock')
      if not os.path.lexists(symlink_hci):
        try:
          os.symlink(hci_sock_path, symlink_hci)
        except OSError as exc:
          logger.debug('symlink hci_bridge.sock: %s', exc)

      return pty_path, adapter_bridge

  def get_container_mounts(self, controller_id: str) -> list[str]:
    """Returns bind mounts for container HCI bridge socket."""
    c_dir = os.path.join(self.containers_dir, controller_id)
    hci_sock = os.path.join(c_dir, 'hci_bridge.sock')
    return [f'{hci_sock}:/dev/virtual_bt/hci_bridge.sock']

  def unregister_controller(self, controller_id: str) -> None:
    with self._lock:
      proxy = self.hci_proxies.pop(controller_id, None)
      if proxy is not None:
        proxy.stop()
      adapter = self.adapter_bridges.pop(controller_id, None)
      if adapter is not None:
        adapter.stop()
      pty_bridge = self.pty_bridges.pop(controller_id, None)
      if pty_bridge is not None:
        pty_bridge.stop()

  def stop_all(self) -> None:
    if self._shared_hci_proxy is not None:
      self._shared_hci_proxy.stop()
    self._control_proxy.stop()
    with self._lock:
      for proxy in list(self.hci_proxies.values()):
        proxy.stop()
      self.hci_proxies.clear()
      for cid in list(self.adapter_bridges.keys()):
        self.unregister_controller(cid)
