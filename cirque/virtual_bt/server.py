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
"""Multi-Channel TCP/IP Virtual Bluetooth Controller System for Linux."""

import json
import logging
import os
import queue
import socket
import threading
from typing import Callable, Dict, List, Optional, Set, Tuple

from cirque.common.docker_transport import bind_tcp_listener
from cirque.virtual_bt.client import H4TcpClient, VirtualBtControlClient
from cirque.virtual_bt.controller import VirtualBluetoothController
from cirque.virtual_bt.hci_h4 import H4StreamParser
from cirque.virtual_bt.link_layer import (
    LinkLayerFrame,
    LinkLayerHub,
    LinkLayerPduType,
    LinkLayerStreamReader,
)

__all__ = [
    'H4TcpClient',
    'VirtualBluetoothController',
    'VirtualBluetoothServer',
    'VirtualBtControlClient',
]

logger = logging.getLogger('VirtualBtServer')

_H4_SINK_QUEUE_MAX = 4096

# Optional ASCII preamble of a shared-port H4 stream: `BIND <controller_id>\n`.
_BIND_PREAMBLE_PREFIX = b'BIND '
# Controller ids are short, so a line that has not terminated within this many
# bytes is not a BIND preamble.
_BIND_PREAMBLE_MAX_BYTES = 128
# How long to wait for the rest of a BIND line whose first bytes arrived in a
# separate TCP segment before treating the stream as raw H4.
_BIND_PREAMBLE_TIMEOUT_S = 2.0


def _recv_bind_preamble(
    conn: socket.socket, first_chunk: bytes
) -> Tuple[Optional[str], bytes]:
  """Splits an optional `BIND <controller_id>\\n` preamble off an H4 stream.

  Args:
    conn: Connected H4 client socket; read further only while the bytes seen
      so far are still a prefix of a BIND line.
    first_chunk: Bytes already received from `conn`.

  Returns:
    `(controller_id, remaining_bytes)`. `controller_id` is None when the
    stream does not start with a BIND line, in which case every byte is raw
    H4. A BIND line split across TCP segments is reassembled, bounded by
    `_BIND_PREAMBLE_MAX_BYTES` and `_BIND_PREAMBLE_TIMEOUT_S`.
  """
  buf = first_chunk
  prefix_len = len(_BIND_PREAMBLE_PREFIX)
  while b'\n' not in buf and len(buf) < _BIND_PREAMBLE_MAX_BYTES:
    if not _BIND_PREAMBLE_PREFIX.startswith(buf[:prefix_len]):
      break
    conn.settimeout(_BIND_PREAMBLE_TIMEOUT_S)
    try:
      more = conn.recv(4096)
    except (socket.timeout, OSError):
      break
    finally:
      conn.settimeout(None)
    if not more:
      break
    buf += more
  if buf.startswith(_BIND_PREAMBLE_PREFIX) and b'\n' in buf:
    nl_idx = buf.find(b'\n')
    ident = buf[prefix_len:nl_idx].decode('utf-8', errors='ignore').strip()
    return ident, buf[nl_idx + 1 :]
  return None, buf


def _stop_writer_queue(out_queue: 'queue.Queue[Optional[bytes]]') -> None:
  """Wakes a per-client H4 writer thread and asks it to exit."""
  while True:
    try:
      out_queue.put_nowait(None)
      return
    except queue.Full:
      try:
        out_queue.get_nowait()
      except queue.Empty:
        pass


class VirtualBluetoothServer:
  """Standalone Linux Virtual Bluetooth Controller System with 3 TCP Channels.

  Exposes three independent TCP listener ports on `self.host`:
    1. `control_port`: Newline-delimited JSON-RPC control plane for creating or
       destroying virtual controllers (`hci0`, `hci1`, ...), inspecting packet
       counters, and configuring PHY impairments (RSSI, packet loss, latency,
       RF isolation).
    2. `hci_port` (plus optional per-controller `dedicated_hci_port`): Binary
       Bluetooth H4 UART-over-TCP transport carrying HCI Command, Event, and
       ACL/L2CAP packets. Supports an optional `BIND <controller_id>\\n` ASCII
       preamble on the shared `hci_port`.
    3. `phy_port`: Length-prefixed (`!I`) JSON LinkLayerFrame stream for
       bridging multiple `VirtualBluetoothServer` instances across hosts.
  """

  _SERVER_SEQ = 0
  _SERVER_SEQ_LOCK = threading.Lock()

  def __init__(
      self,
      host: str = '127.0.0.1',
      control_port: int = 0,
      hci_port: int = 0,
      phy_port: int = 0,
      pcap_dir: Optional[str] = None,
  ):
    # Assign a unique 8-bit server sequence number so parallel test servers in
    # the same process generate non-overlapping default BD_ADDRs (`AA:BB:seq:`).
    with VirtualBluetoothServer._SERVER_SEQ_LOCK:
      VirtualBluetoothServer._SERVER_SEQ = (
          VirtualBluetoothServer._SERVER_SEQ + 1
      ) & 0xFF
      self._server_instance_id = VirtualBluetoothServer._SERVER_SEQ

    self.host = host
    self.control_port = control_port
    self.hci_port = hci_port
    self.phy_port = phy_port
    self.phy_hub = LinkLayerHub(
        hub_id=(
            f'hub_{os.getpid()}_{self._server_instance_id:02x}_'
            f'{id(self) & 0xFFFF:04x}'
        )
    )
    self._lock = threading.RLock()
    self._controllers: Dict[str, VirtualBluetoothController] = {}
    self._bdaddr_index: Dict[str, VirtualBluetoothController] = {}
    self._dedicated_listeners: Dict[str, socket.socket] = {}
    self._next_idx: int = 1
    self._running = False
    self.relay_enabled = True
    self._control_sock: Optional[socket.socket] = None
    self._hci_sock: Optional[socket.socket] = None
    self._phy_sock: Optional[socket.socket] = None
    self._remote_phy_socks: List[socket.socket] = []
    self._active_h4_clients: Set[socket.socket] = set()
    self.pcap_dir = (
        pcap_dir
        or os.environ.get('CIRQUE_PCAP_DIR')
        or os.environ.get('DEVICE_LOG_DIR')
    )
    self._pcap_medium_writer = None
    if self.pcap_dir:
      self.enable_pcap(self.pcap_dir)

  def enable_pcap(self, pcap_dir: str) -> None:
    """Enables PCAP logging for Bluetooth controllers (DLT 201) and PHY.

    Link layer frames are captured as DLT 256.
    """
    with self._lock:
      dir_changed = bool(self.pcap_dir and os.path.abspath(self.pcap_dir) != os.path.abspath(pcap_dir))
      self.pcap_dir = pcap_dir
      os.makedirs(self.pcap_dir, exist_ok=True)
      from cirque.capabilities.pcapcapability import (
          DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
          DLT_BLUETOOTH_LE_LL_WITH_PHDR,
          PcapWriter,
      )
      if dir_changed and self._pcap_medium_writer is not None:
        self._pcap_medium_writer.close()
        self._pcap_medium_writer = None
      if self._pcap_medium_writer is None:
        self._pcap_medium_writer = PcapWriter(
            os.path.join(self.pcap_dir, 'bt_medium.pcap'),
            dlt=DLT_BLUETOOTH_LE_LL_WITH_PHDR,
        )
        self.phy_hub.set_pcap_writer(self._pcap_medium_writer)
      for cid, ctrl in self._controllers.items():
        if dir_changed and ctrl.pcap_writer is not None:
          ctrl.pcap_writer.close()
          ctrl.set_pcap_writer(None)
        if ctrl.pcap_writer is None:
          ctrl.set_pcap_writer(
              PcapWriter(
                  os.path.join(self.pcap_dir, f'bt_hci_{cid}.pcap'),
                  dlt=DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
              )
          )

  def set_relay_enabled(self, enabled: bool) -> None:
    """Enables or disables packet relaying across virtual controllers."""
    with self._lock:
      self.relay_enabled = bool(enabled)
      if hasattr(self, 'phy_hub') and self.phy_hub is not None:
        self.phy_hub.relay_enabled = bool(enabled)

  def start(self) -> Tuple[int, int, int]:
    """Starts the Control, HCI (H4), and Link Layer (PHY) TCP servers."""
    if self._running:
      return (self.control_port, self.hci_port, self.phy_port)
    self._running = True
    self._control_sock = self._bind_listener(self.control_port)
    self.control_port = self._control_sock.getsockname()[1]
    self._hci_sock = self._bind_listener(self.hci_port)
    self.hci_port = self._hci_sock.getsockname()[1]
    self._phy_sock = self._bind_listener(self.phy_port)
    self.phy_port = self._phy_sock.getsockname()[1]
    for sock, handler in (
        (self._control_sock, self._handle_control_client),
        (self._hci_sock, self._handle_hci_client),
        (self._phy_sock, self._handle_phy_client),
    ):
      threading.Thread(
          target=self._accept_loop, args=(sock, handler), daemon=True
      ).start()
    return (self.control_port, self.hci_port, self.phy_port)

  def stop(self) -> None:
    """Stops all TCP listeners and cleans up virtual controller instances."""
    self._running = False
    for sock in (self._control_sock, self._hci_sock, self._phy_sock):
      if sock is not None:
        try:
          sock.close()
        except OSError:
          pass
    with self._lock:
      for client in list(self._active_h4_clients):
        try:
          client.close()
        except OSError:
          pass
      self._active_h4_clients.clear()
      for sock in list(self._dedicated_listeners.values()) + list(
          self._remote_phy_socks
      ):
        try:
          sock.close()
        except OSError:
          pass
      self._dedicated_listeners.clear()
      self._remote_phy_socks.clear()
      for ctrl in list(self._controllers.values()):
        ctrl.close()
      self._controllers.clear()
      self._bdaddr_index.clear()
      if self._pcap_medium_writer is not None:
        self._pcap_medium_writer.close()
        self._pcap_medium_writer = None

  def _bind_listener(self, port: int) -> socket.socket:
    return bind_tcp_listener(self.host, port, backlog=64)

  def _accept_loop(
      self,
      listener: socket.socket,
      handler: Callable[[socket.socket, Tuple[str, int]], None],
  ) -> None:
    while self._running:
      try:
        conn, addr = listener.accept()
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=handler, args=(conn, addr), daemon=True).start()
      except OSError:
        break

  def create_controller(
      self,
      controller_id: Optional[str] = None,
      bd_addr: Optional[str] = None,
      local_name: Optional[str] = None,
      dedicated_port: bool = False,
      acl_mtu: int = 1024,
      acl_max_pkt: int = 16,
      sco_mtu: int = 64,
      sco_max_pkt: int = 8,
      manufacturer_id: int = 0x00E0,
  ) -> VirtualBluetoothController:
    """Creates and registers a new virtual Bluetooth controller instance."""
    with self._lock:
      idx = self._next_idx
      self._next_idx += 1
      cid = controller_id or f'hci{idx - 1}'
      if cid in self._controllers:
        return self._controllers[cid]
      default_bd = (
          f'AA:BB:{self._server_instance_id:02X}:'
          f'{(idx >> 8) & 0xFF:02X}:{idx & 0xFF:02X}:01'
      )
      addr = bd_addr.upper() if bd_addr else default_bd
      ctrl = VirtualBluetoothController(
          cid,
          addr,
          self.phy_hub,
          local_name or f'CirqueVirtualBT-{cid}',
          acl_mtu=acl_mtu,
          acl_max_pkt=acl_max_pkt,
          sco_mtu=sco_mtu,
          sco_max_pkt=sco_max_pkt,
          manufacturer_id=manufacturer_id,
      )
      if self.pcap_dir:
        from cirque.capabilities.pcapcapability import (
            DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
            PcapWriter,
        )
        ctrl.set_pcap_writer(
            PcapWriter(
                os.path.join(self.pcap_dir, f'bt_hci_{cid}.pcap'),
                dlt=DLT_BLUETOOTH_HCI_H4_WITH_PHDR,
            )
        )
      if dedicated_port:
        ded_sock = self._bind_listener(0)
        ctrl.dedicated_hci_port = ded_sock.getsockname()[1]
        self._dedicated_listeners[cid] = ded_sock
        threading.Thread(
            target=self._accept_loop,
            args=(ded_sock, lambda c, a, t=ctrl: self._serve_h4_stream(c, t)),
            daemon=True,
        ).start()
      self._controllers[cid] = ctrl
      self._bdaddr_index[addr] = ctrl
      return ctrl

  def destroy_controller(self, identifier: str) -> bool:
    """Destroys a virtual controller by ID or BD_ADDR."""
    with self._lock:
      ctrl = self._controllers.pop(identifier, None)
      if ctrl is None:
        ctrl = self._bdaddr_index.pop(identifier.upper(), None)
        if ctrl is not None:
          self._controllers.pop(ctrl.state.controller_id, None)
      else:
        self._bdaddr_index.pop(ctrl.state.bd_addr, None)
      ded_sock = self._dedicated_listeners.pop(
          ctrl.state.controller_id if ctrl else identifier, None
      )
      if ded_sock:
        try:
          ded_sock.close()
        except OSError:
          pass
    if ctrl:
      ctrl.close()
      return True
    return False

  def get_controller(
      self, identifier: str
  ) -> Optional[VirtualBluetoothController]:
    with self._lock:
      if identifier in self._controllers:
        return self._controllers[identifier]
      return self._bdaddr_index.get(identifier.upper())

  def list_controllers(self) -> List[Dict[str, object]]:
    with self._lock:
      return [c.to_dict() for c in self._controllers.values()]

  def reset_all_controllers(self) -> None:
    """Resets connections, state, and medium for all active controllers."""
    with self._lock:
      ctrls = list(self._controllers.values())
    for ctrl in ctrls:
      with ctrl._lock:
        ctrl.state.adv_enabled = False
        ctrl.state.scan_enabled = False
        ctrl.state.connections.clear()
        ctrl._peer_to_handle.clear()
        ctrl._next_handle = 0x0040
    if hasattr(self, 'phy_hub') and self.phy_hub is not None:
      self.phy_hub.reset_medium()

  def connect_remote_phy(self, remote_host: str, remote_port: int) -> bool:
    """Bridges this server's Link Layer PHY bus with a remote PHY port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.connect((remote_host, remote_port))
    with self._lock:
      self._remote_phy_socks.append(sock)
    threading.Thread(
        target=self._handle_phy_client,
        args=(sock, (remote_host, remote_port)),
        daemon=True,
    ).start()
    return True

  def _drain_control_buffer(self, conn: socket.socket, buf: bytes) -> bytes:
    """Processes complete newline-delimited JSON commands from buf."""
    while b'\n' in buf:
      line, buf = buf.split(b'\n', 1)
      line_str = line.decode('utf-8', errors='ignore').strip()
      if line_str:
        resp = self._execute_control_command(line_str)
        conn.sendall((json.dumps(resp) + '\n').encode('utf-8'))
    return buf

  def _handle_control_client(
      self, conn: socket.socket, _addr: Tuple[str, int]
  ) -> None:
    buf = b''
    try:
      while self._running:
        chunk = conn.recv(4096)
        if not chunk:
          break
        buf = self._drain_control_buffer(conn, buf + chunk)
    except OSError:
      pass
    finally:
      try:
        conn.close()
      except OSError:
        pass

  def _handle_phy_control_command(
      self, cmd: str, req: Dict[str, object]
  ) -> Optional[Dict[str, object]]:
    """Handles PHY impairment, isolation, and injection control commands."""
    if cmd == 'set_rssi':
      src, dst = str(req.get('src_bd_addr', '')), str(
          req.get('dst_bd_addr', '')
      )
      rssi = int(req.get('rssi', -45))
      if src and dst:
        self.phy_hub.set_rssi(src, dst, rssi)
      else:
        self.phy_hub.set_default_rssi(rssi)
      return {'status': 'ok', 'rssi': rssi}
    if cmd == 'set_packet_loss':
      loss_rate = float(req.get('loss_rate', 0.0))
      self.phy_hub.set_packet_loss_rate(loss_rate)
      return {'status': 'ok', 'loss_rate': loss_rate}
    if cmd == 'set_latency_ms':
      latency_ms = float(req.get('latency_ms', 0.0))
      self.phy_hub.set_latency_ms(latency_ms)
      return {'status': 'ok', 'latency_ms': latency_ms}
    if cmd == 'isolate_controller':
      ident = str(req.get('bd_addr') or req.get('controller_id') or '')
      ctrl = self.get_controller(ident)
      bd_addr = ctrl.state.bd_addr if ctrl else ident
      isolated = bool(req.get('isolated', True))
      self.phy_hub.set_isolated(bd_addr, isolated)
      return {'status': 'ok', 'bd_addr': bd_addr, 'isolated': isolated}
    if cmd == 'bridge_remote_phy':
      r_host, r_port = str(req.get('host', '127.0.0.1')), int(
          req.get('port', 0)
      )
      self.connect_remote_phy(r_host, r_port)
      return {'status': 'ok', 'bridged_to': f'{r_host}:{r_port}'}
    if cmd == 'inject_advertisement':
      self.phy_hub.transmit(
          LinkLayerFrame(
              pdu_type=LinkLayerPduType.ADV_IND.value,
              src_bd_addr=str(req.get('src_bd_addr', 'AA:BB:CC:99:99:99')),
              rssi=int(req.get('rssi', -42)),
              payload_hex=str(req.get('adv_data_hex', '020106')),
          )
      )
      return {'status': 'ok'}
    return None

  def _handle_controller_lifecycle_cmd(
      self, cmd: str, req: Dict[str, object]
  ) -> Optional[Dict[str, object]]:
    """Handles create/destroy/get/list controller control commands."""
    if cmd in ('create_controller', 'create_device'):
      ctrl = self.create_controller(
          controller_id=req.get('controller_id'),
          bd_addr=req.get('bd_addr'),
          local_name=req.get('local_name'),
          dedicated_port=bool(req.get('dedicated_port', True)),
          acl_mtu=int(req.get('acl_mtu', 1024)),
          acl_max_pkt=int(req.get('acl_max_pkt', 16)),
          sco_mtu=int(req.get('sco_mtu', 64)),
          sco_max_pkt=int(req.get('sco_max_pkt', 8)),
          manufacturer_id=int(req.get('manufacturer_id', 0x00E0)),
      )
      return {
          'status': 'ok',
          'controller': ctrl.to_dict(),
          'hci_port': ctrl.dedicated_hci_port or self.hci_port,
      }
    if cmd in ('destroy_controller', 'destroy_device'):
      ident = str(req.get('controller_id') or req.get('bd_addr') or '')
      removed = self.destroy_controller(ident)
      return {'status': 'ok' if removed else 'not_found', 'removed': removed}
    if cmd in ('list_controllers', 'list_devices'):
      return {'status': 'ok', 'controllers': self.list_controllers()}
    if cmd in ('get_controller', 'get_device'):
      ident = str(req.get('controller_id') or req.get('bd_addr') or '')
      ctrl = self.get_controller(ident)
      return (
          {'status': 'ok', 'controller': ctrl.to_dict()}
          if ctrl
          else {'status': 'not_found'}
      )
    return None

  def get_frame_counters(self) -> Dict[str, int]:
    """Returns aggregated LinkLayer, ACL, and ATT frame counters."""
    with self._lock:
      return {
          'phy_frames_routed': self.phy_hub.total_frames_routed,
          'phy_frames_dropped': self.phy_hub.total_frames_dropped,
          'acl_tx_packets': sum(
              c.state.acl_tx_packets for c in self._controllers.values()
          ),
          'acl_rx_packets': sum(
              c.state.acl_rx_packets for c in self._controllers.values()
          ),
          'att_write_packets': sum(
              c.state.att_write_packets for c in self._controllers.values()
          ),
          'att_indication_packets': sum(
              c.state.att_indication_packets for c in self._controllers.values()
          ),
      }

  def _execute_control_command(self, line_str: str) -> Dict[str, object]:
    try:
      req = json.loads(line_str)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      return {'status': 'error', 'error': f'Invalid JSON: {exc}'}

    cmd = str(req.get('cmd', req.get('command', ''))).lower()
    if cmd == 'ping':
      return {
          'status': 'ok',
          'control_port': self.control_port,
          'hci_port': self.hci_port,
          'phy_port': self.phy_port,
      }
    for handler in (
        self._handle_controller_lifecycle_cmd,
        self._handle_phy_control_command,
    ):
      resp = handler(cmd, req)
      if resp is not None:
        return resp
    if cmd in ('set_relay_enabled', 'relay_control'):
      self.set_relay_enabled(bool(req.get('enabled', True)))
      return {'status': 'ok', 'relay_enabled': self.relay_enabled}
    if cmd in ('reset_controllers', 'reset_all_controllers'):
      self.reset_all_controllers()
      return {'status': 'ok'}
    if cmd == 'reset_environment':
      self.phy_hub.reset_medium()
      with self._lock:
        self.relay_enabled = True
        ids = list(self._controllers.keys())
      for cid in ids:
        self.destroy_controller(cid)
      return {'status': 'ok'}
    if cmd in ('get_frame_counters', 'frame_counters'):
      return {'status': 'ok', 'counters': self.get_frame_counters()}
    if cmd == 'get_stats':
      return {
          'status': 'ok',
          'control_port': self.control_port,
          'hci_port': self.hci_port,
          'phy_port': self.phy_port,
          'total_controllers': len(self._controllers),
          'phy_frames_routed': self.phy_hub.total_frames_routed,
          'phy_frames_dropped': self.phy_hub.total_frames_dropped,
          'controllers': self.list_controllers(),
          'frame_counters': self.get_frame_counters(),
      }
    return {'status': 'error', 'error': f'Unknown command: {cmd}'}

  def _handle_hci_client(
      self, conn: socket.socket, addr: Tuple[str, int]
  ) -> None:
    """Handles an H4-over-TCP connection with optional BIND preamble."""
    ctrl: Optional[VirtualBluetoothController] = None
    spawned_ephemeral = False
    try:
      first_chunk = conn.recv(4096)
      if not first_chunk:
        conn.close()
        return
      ident, initial_h4_bytes = _recv_bind_preamble(conn, first_chunk)
      if ident is not None:
        ctrl = self.get_controller(ident) or self.create_controller(
            controller_id=ident
        )
        logger.info(
            'H4 client %s bound to controller %s',
            addr,
            ctrl.state.controller_id,
        )
      if ctrl is None:
        ctrl, spawned_ephemeral = self.create_controller(), True
        # A stream without a BIND line is served, but only by a controller
        # that disappears with the connection. Make that visible: a pty_bridge
        # whose BIND line was lost shows up here, not as a bound controller.
        logger.warning(
            'H4 client %s sent no BIND preamble (first bytes %r); serving it '
            'with ephemeral controller %s',
            addr,
            bytes(initial_h4_bytes[:24]),
            ctrl.state.controller_id,
        )
      self._serve_h4_stream(conn, ctrl, initial_h4_bytes, spawned_ephemeral)
    except OSError:
      try:
        conn.close()
      except OSError:
        pass

  def _serve_h4_stream(
      self,
      conn: socket.socket,
      ctrl: VirtualBluetoothController,
      initial_bytes: bytes = b'',
      destroy_on_disconnect: bool = False,
  ) -> None:
    parser = H4StreamParser()
    out_q: 'queue.Queue[Optional[bytes]]' = queue.Queue(_H4_SINK_QUEUE_MAX)

    def _sink(raw_bytes: bytes) -> None:
      try:
        out_q.put_nowait(raw_bytes)
      except queue.Full:
        pass

    def _writer() -> None:
      while True:
        item = out_q.get()
        if item is None:
          return
        try:
          conn.sendall(item)
        except OSError:
          return

    threading.Thread(target=_writer, daemon=True).start()
    ctrl.add_h4_sink(_sink)
    with self._lock:
      self._active_h4_clients.add(conn)
    try:
      for pkt in parser.feed(initial_bytes) if initial_bytes else ():
        ctrl.process_h4_packet(pkt)
      while self._running:
        data = conn.recv(4096)
        if not data:
          break
        for pkt in parser.feed(data):
          ctrl.process_h4_packet(pkt)
    except OSError:
      pass
    finally:
      with self._lock:
        self._active_h4_clients.discard(conn)
      ctrl.remove_h4_sink(_sink)
      _stop_writer_queue(out_q)
      if destroy_on_disconnect:
        self.destroy_controller(ctrl.state.controller_id)
      try:
        conn.close()
      except OSError:
        pass

  def _handle_phy_client(
      self, conn: socket.socket, _addr: Tuple[str, int]
  ) -> None:
    fd = self.phy_hub.add_peer_socket(conn)
    reader = LinkLayerStreamReader()
    try:
      while self._running:
        chunk = conn.recv(4096)
        if not chunk:
          break
        for frame in reader.feed(chunk):
          self.phy_hub.transmit(frame, exclude_peer_fd=fd)
    except OSError:
      pass
    finally:
      self.phy_hub.remove_peer_socket(fd)
      try:
        conn.close()
      except OSError:
        pass
