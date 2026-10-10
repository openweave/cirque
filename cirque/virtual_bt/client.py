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
"""Client SDKs for Control/Test and HCI (H4-over-TCP) Virtual BT Channels."""

import json
import logging
import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger('VirtualBtClient')

from cirque.virtual_bt.hci_h4 import (
    H4Packet,
    H4PacketType,
    H4StreamParser,
    HciEventCode,
    HciOpcode,
    LeSubEventCode,
    bdaddr_bytes_to_str,
    build_acl_packet,
    parse_acl_packet,
    str_to_bdaddr_bytes,
)


class VirtualBtControlClient:
  """Client for the Control/Test TCP Channel."""

  def __init__(self, host: str, port: int, timeout: float = 5.0):
    self.host = host
    self.port = port
    self.timeout = timeout

  def request(self, payload: Dict[str, object]) -> Dict[str, object]:
    with socket.create_connection(
        (self.host, self.port), timeout=self.timeout
    ) as sock:
      sock.sendall((json.dumps(payload) + '\n').encode('utf-8'))
      buf = b''
      while b'\n' not in buf:
        chunk = sock.recv(4096)
        if not chunk:
          break
        buf += chunk
      return json.loads(buf.decode('utf-8').strip())

  def create_controller(
      self,
      controller_id: Optional[str] = None,
      bd_addr: Optional[str] = None,
      local_name: Optional[str] = None,
      dedicated_port: bool = True,
  ) -> Dict[str, object]:
    return self.request({
        'cmd': 'create_controller',
        'controller_id': controller_id,
        'bd_addr': bd_addr,
        'local_name': local_name,
        'dedicated_port': dedicated_port,
    })

  def destroy_controller(self, controller_id: str) -> Dict[str, object]:
    return self.request(
        {'cmd': 'destroy_controller', 'controller_id': controller_id}
    )

  def list_controllers(self) -> List[Dict[str, object]]:
    resp = self.request({'cmd': 'list_controllers'})
    return list(resp.get('controllers', []))

  def set_rssi(
      self, rssi: int, src_bd_addr: str = '', dst_bd_addr: str = ''
  ) -> Dict[str, object]:
    return self.request({
        'cmd': 'set_rssi',
        'rssi': rssi,
        'src_bd_addr': src_bd_addr,
        'dst_bd_addr': dst_bd_addr,
    })

  def set_packet_loss(self, loss_rate: float) -> Dict[str, object]:
    return self.request({'cmd': 'set_packet_loss', 'loss_rate': loss_rate})

  def set_latency_ms(self, latency_ms: float) -> Dict[str, object]:
    return self.request({'cmd': 'set_latency_ms', 'latency_ms': latency_ms})

  def isolate_controller(
      self, identifier: str, isolated: bool = True
  ) -> Dict[str, object]:
    return self.request({
        'cmd': 'isolate_controller',
        'controller_id': identifier,
        'isolated': isolated,
    })

  def bridge_remote_phy(self, host: str, port: int) -> Dict[str, object]:
    return self.request(
        {'cmd': 'bridge_remote_phy', 'host': host, 'port': port}
    )

  def get_stats(self) -> Dict[str, object]:
    return self.request({'cmd': 'get_stats'})

  def reset_controllers(self) -> Dict[str, object]:
    return self.request({'cmd': 'reset_controllers'})


class H4TcpClient:
  """Bluetooth Host Stack Client speaking standard H4-over-TCP."""

  def __init__(
      self,
      host: str,
      port: int,
      bind_controller_id: Optional[str] = None,
      timeout: float = 5.0,
  ):
    self.host = host
    self.port = port
    self.sock = socket.create_connection((host, port), timeout=timeout)
    self.sock.settimeout(None)
    self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    self.parser = H4StreamParser()
    self._lock = threading.RLock()
    self._events: List[H4Packet] = []
    self._acl_packets: List[Tuple[int, int, bytes]] = []
    self._adv_reports: List[Dict[str, object]] = []
    self._connections: Dict[int, Dict[str, object]] = {}
    self._cv = threading.Condition(self._lock)
    self._running = True

    if bind_controller_id:
      self.sock.sendall(f'BIND {bind_controller_id}\n'.encode('utf-8'))

    self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
    self._rx_thread.start()

  def close(self) -> None:
    self._running = False
    try:
      self.sock.close()
    except OSError as exc:
      logger.debug('Error closing client socket: %s', exc)

  def _ingest_rx_packets(self, packets: List[H4Packet]) -> None:
    with self._cv:
      for pkt in packets:
        if pkt.packet_type == H4PacketType.EVENT:
          self._events.append(pkt)
          self._parse_le_meta(pkt.payload)
        elif pkt.packet_type == H4PacketType.ACL_DATA:
          self._acl_packets.append(parse_acl_packet(pkt.payload))
      self._cv.notify_all()

  def _rx_loop(self) -> None:
    while self._running:
      try:
        chunk = self.sock.recv(4096)
        if not chunk:
          break
        self._ingest_rx_packets(self.parser.feed(chunk))
      except OSError:
        break

  def _parse_le_meta(self, event_payload: bytes) -> None:
    if len(event_payload) < 3:
      return
    ev_code = event_payload[0]
    if ev_code == HciEventCode.LE_META_EVENT:
      subcode = event_payload[2]
      if (
          subcode == LeSubEventCode.ADVERTISING_REPORT
          and len(event_payload) >= 12
      ):
        data_len = event_payload[12]
        adv_data = event_payload[13 : 13 + data_len]
        rssi = (
            struct.unpack_from('<b', event_payload, 13 + data_len)[0]
            if len(event_payload) > 13 + data_len
            else -45
        )
        self._adv_reports.append({
            'event_type': event_payload[4],
            'addr_type': event_payload[5],
            'bd_addr': bdaddr_bytes_to_str(event_payload[6:12]),
            'adv_data': adv_data,
            'rssi': rssi,
        })
      elif (
          subcode
          in (
              LeSubEventCode.CONNECTION_COMPLETE,
              LeSubEventCode.ENHANCED_CONNECTION_COMPLETE,
          )
          and len(event_payload) >= 14
      ):
        status = event_payload[3]
        handle = struct.unpack_from('<H', event_payload, 4)[0] & 0x0FFF
        if status == 0x00:
          self._connections[handle] = {
              'handle': handle,
              'role': event_payload[6],
              'peer_addr_type': event_payload[7],
              'peer_bd_addr': bdaddr_bytes_to_str(event_payload[8:14]),
          }
    elif (
        ev_code == HciEventCode.DISCONNECTION_COMPLETE
        and len(event_payload) >= 6
    ):
      handle = struct.unpack_from('<H', event_payload, 3)[0] & 0x0FFF
      self._connections.pop(handle, None)

  def _pop_matching_opcode_event(self, opcode: int) -> Optional[bytes]:
    """Pops and returns the response payload for opcode if queued."""
    for i, ev in enumerate(self._events):
      p = ev.payload
      if len(p) >= 5 and p[0] == HciEventCode.COMMAND_COMPLETE:
        if struct.unpack_from('<H', p, 3)[0] == opcode:
          self._events.pop(i)
          return p[5:]
      elif len(p) >= 6 and p[0] == HciEventCode.COMMAND_STATUS:
        if struct.unpack_from('<H', p, 4)[0] == opcode:
          self._events.pop(i)
          return bytes([p[2]])
    return None

  def send_command(
      self, opcode: int, params: bytes = b'', timeout: float = 3.0
  ) -> bytes:
    """Sends an H4 HCI Command and waits for Command_Complete or Status."""
    cmd_payload = struct.pack('<HB', opcode, len(params)) + params
    pkt = H4Packet(H4PacketType.COMMAND, cmd_payload)
    self.sock.sendall(pkt.to_bytes())

    deadline = time.time() + timeout
    with self._cv:
      while time.time() < deadline:
        matched = self._pop_matching_opcode_event(opcode)
        if matched is not None:
          return matched
        rem = deadline - time.time()
        if rem > 0:
          self._cv.wait(rem)
    raise TimeoutError(f'HCI opcode 0x{opcode:04X} timed out')

  def reset(self) -> None:
    with self._cv:
      self._connections.clear()
      self._acl_packets.clear()
      self._adv_reports.clear()
      self._events.clear()
    self.send_command(HciOpcode.RESET)

  def read_bd_addr(self) -> str:
    res = self.send_command(HciOpcode.READ_BD_ADDR)
    return bdaddr_bytes_to_str(res[1:7])

  def start_advertising(
      self,
      adv_data: bytes,
      scan_rsp_data: bytes = b'',
      bd_addr: Optional[str] = None,
  ) -> None:
    if bd_addr:
      try:
        self.send_command(
            HciOpcode.LE_SET_RANDOM_ADDRESS, str_to_bdaddr_bytes(bd_addr)
        )
      except Exception as exc:
        logger.debug('LE_SET_RANDOM_ADDRESS notice: %s', exc)

    # Set Adv Params (interval 20ms..20ms, non-directed, public/random addr, all channels)
    adv_params = bytes.fromhex('200020000000000000000000000700')
    try:
      self.send_command(HciOpcode.LE_SET_ADVERTISING_PARAMETERS, adv_params)
    except Exception as exc:
      logger.debug('LE_SET_ADVERTISING_PARAMETERS notice: %s', exc)

    padded_adv = (
        bytes([len(adv_data)]) + adv_data + b'\x00' * max(0, 31 - len(adv_data))
    )
    self.send_command(HciOpcode.LE_SET_ADVERTISING_DATA, padded_adv[:32])
    if scan_rsp_data:
      padded_rsp = (
          bytes([len(scan_rsp_data)])
          + scan_rsp_data
          + b'\x00' * max(0, 31 - len(scan_rsp_data))
      )
      self.send_command(HciOpcode.LE_SET_SCAN_RESPONSE_DATA, padded_rsp[:32])
    self.send_command(HciOpcode.LE_SET_ADVERTISING_ENABLE, b'\x01')

  def start_scanning(self, active: bool = True) -> None:
    scan_params = struct.pack(
        '<BHHBB', 0x01 if active else 0x00, 0x0010, 0x0010, 0x00, 0x00
    )
    self.send_command(HciOpcode.LE_SET_SCAN_PARAMETERS, scan_params)
    self.send_command(HciOpcode.LE_SET_SCAN_ENABLE, b'\x01\x00')

  def wait_for_advertisement(
      self, target_bd_addr: Optional[str] = None, timeout: float = 3.0
  ) -> Dict[str, object]:
    deadline = time.time() + timeout
    with self._cv:
      while time.time() < deadline:
        for r in self._adv_reports:
          if (
              target_bd_addr is None
              or str(r['bd_addr']).upper() == target_bd_addr.upper()
          ):
            if r.get('event_type') != 0x04 or r.get('adv_data'):
              return r
        rem = deadline - time.time()
        if rem > 0:
          self._cv.wait(rem)
      for r in self._adv_reports:
        if (
            target_bd_addr is None
            or str(r['bd_addr']).upper() == target_bd_addr.upper()
        ):
          return r
    raise TimeoutError('Timed out waiting for LE Advertising Report')

  def connect(self, peer_bd_addr: str, timeout: float = 3.0) -> int:
    peer_le = str_to_bdaddr_bytes(peer_bd_addr)
    conn_params = struct.pack(
        '<HHBB6sBHHHHHH',
        0x0060,
        0x0030,
        0x00,
        0x00,
        peer_le,
        0x00,
        0x0018,
        0x0028,
        0x0000,
        0x01F4,
        0x0000,
        0x0000,
    )
    self.send_command(HciOpcode.LE_CREATE_CONNECTION, conn_params)
    return self.wait_for_connection(peer_bd_addr, timeout=timeout)

  def wait_for_connection(
      self, peer_bd_addr: Optional[str] = None, timeout: float = 3.0
  ) -> int:
    deadline = time.time() + timeout
    with self._cv:
      while time.time() < deadline:
        for handle, info in self._connections.items():
          if (
              peer_bd_addr is None
              or str(info['peer_bd_addr']).upper() == peer_bd_addr.upper()
          ):
            return handle
        rem = deadline - time.time()
        if rem > 0:
          self._cv.wait(rem)
    raise TimeoutError('Timed out waiting for LE Connection Complete')

  def send_acl_l2cap(
      self, handle: int, l2cap_cid: int, l2cap_payload: bytes
  ) -> None:
    pkt = build_acl_packet(handle, l2cap_cid, l2cap_payload)
    self.sock.sendall(pkt.to_bytes())

  def receive_acl_l2cap(self, timeout: float = 3.0) -> Tuple[int, int, bytes]:
    deadline = time.time() + timeout
    with self._cv:
      while time.time() < deadline:
        if self._acl_packets:
          return self._acl_packets.pop(0)
        rem = deadline - time.time()
        if rem > 0:
          self._cv.wait(rem)
    raise TimeoutError('Timed out waiting for ACL L2CAP packet')
