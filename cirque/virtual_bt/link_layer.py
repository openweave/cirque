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
"""Bluetooth Link Layer (PHY & Baseband) Simulation Hub and TCP Peer Channel."""

from dataclasses import dataclass, field
from enum import Enum
import json
import logging
import random
import socket
import struct
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from cirque.connectivity.rf_channel_simulator import RfChannelSimulator

logger = logging.getLogger('VirtualBtLinkLayer')


class LinkLayerPduType(str, Enum):
  """Simulated Bluetooth LE Link Layer / Baseband PDU Types."""

  ADV_IND = 'ADV_IND'
  SCAN_REQ = 'SCAN_REQ'
  SCAN_RSP = 'SCAN_RSP'
  CONNECT_IND = 'CONNECT_IND'
  CONNECT_RSP = 'CONNECT_RSP'
  LL_DATA = 'LL_DATA'
  LL_TERMINATE_IND = 'LL_TERMINATE_IND'
  PHY_ANNOUNCE = 'PHY_ANNOUNCE'


@dataclass
class LinkLayerFrame:
  """Represents a Link Layer baseband frame transmitted across the virtual PHY."""

  pdu_type: str
  src_bd_addr: str
  dst_bd_addr: str = 'FF:FF:FF:FF:FF:FF'
  src_addr_type: int = 0x00
  dst_addr_type: int = 0x00
  channel: int = 37
  rssi: int = -45
  payload_hex: str = ''
  conn_interval: int = 0x0018
  conn_latency: int = 0x0000
  supervision_timeout: int = 0x01F4
  reason: int = 0x13
  origin_hub_id: str = ''
  frame_id: str = ''

  @property
  def payload(self) -> bytes:
    return bytes.fromhex(self.payload_hex) if self.payload_hex else b''

  def to_wire_bytes(self) -> bytes:
    """Serializes the Link Layer frame with a 4-byte big-endian length header."""
    body = json.dumps({
        'pdu_type': self.pdu_type,
        'src_bd_addr': self.src_bd_addr,
        'dst_bd_addr': self.dst_bd_addr,
        'src_addr_type': self.src_addr_type,
        'dst_addr_type': self.dst_addr_type,
        'channel': self.channel,
        'rssi': self.rssi,
        'payload_hex': self.payload_hex,
        'conn_interval': self.conn_interval,
        'conn_latency': self.conn_latency,
        'supervision_timeout': self.supervision_timeout,
        'reason': self.reason,
        'origin_hub_id': self.origin_hub_id,
        'frame_id': self.frame_id,
    }).encode('utf-8')
    return struct.pack('!I', len(body)) + body

  @classmethod
  def from_json_bytes(cls, data: bytes) -> 'LinkLayerFrame':
    obj = json.loads(data.decode('utf-8'))
    return cls(
        pdu_type=obj.get('pdu_type', LinkLayerPduType.ADV_IND.value),
        src_bd_addr=obj.get('src_bd_addr', '00:00:00:00:00:00'),
        dst_bd_addr=obj.get('dst_bd_addr', 'FF:FF:FF:FF:FF:FF'),
        src_addr_type=int(obj.get('src_addr_type', 0)),
        dst_addr_type=int(obj.get('dst_addr_type', 0)),
        channel=int(obj.get('channel', 37)),
        rssi=int(obj.get('rssi', -45)),
        payload_hex=obj.get('payload_hex', ''),
        conn_interval=int(obj.get('conn_interval', 0x0018)),
        conn_latency=int(obj.get('conn_latency', 0x0000)),
        supervision_timeout=int(obj.get('supervision_timeout', 0x01F4)),
        reason=int(obj.get('reason', 0x13)),
        origin_hub_id=obj.get('origin_hub_id', ''),
        frame_id=obj.get('frame_id', ''),
    )


class LinkLayerStreamReader:
  """Stateful reader for length-prefixed LinkLayerFrame TCP streams."""

  def __init__(self):
    self._buffer = bytearray()

  def feed(self, chunk: bytes) -> List[LinkLayerFrame]:
    if chunk:
      self._buffer.extend(chunk)
    frames: List[LinkLayerFrame] = []
    while len(self._buffer) >= 4:
      msg_len = struct.unpack_from('!I', self._buffer, 0)[0]
      if msg_len > 1024 * 1024:
        del self._buffer[:4]
        continue
      if len(self._buffer) < 4 + msg_len:
        break
      raw_json = bytes(self._buffer[4 : 4 + msg_len])
      del self._buffer[: 4 + msg_len]
      try:
        frames.append(LinkLayerFrame.from_json_bytes(raw_json))
      except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning('Malformed LinkLayer frame JSON: %s', exc)
        continue
    return frames


class LinkLayerHub:
  """Simulates the Bluetooth RF/PHY medium and Link Layer TCP Peer Channel.

  Acts as a virtual 2.4 GHz BLE air interface connecting:
    1. In-process `VirtualBluetoothController` endpoints (`_local_listeners`),
    2. Remote `LinkLayerHub` instances bridged over TCP (`_peer_sockets`).

  Supports configurable per-pair RSSI attenuation (`_rssi_matrix`), uniform
  packet loss (`_packet_loss_rate`), propagation latency (`_latency_ms`), and
  RF chamber isolation (`_isolated_addrs`).
  """

  def __init__(self, hub_id: str = 'hub_0'):
    self.hub_id = hub_id
    self._lock = threading.RLock()
    self._local_listeners: Dict[str, Callable[[LinkLayerFrame], None]] = {}
    self._peer_sockets: Dict[int, socket.socket] = {}
    self._rssi_matrix: Dict[Tuple[str, str], int] = {}
    self._default_rssi: int = -45
    self._packet_loss_rate: float = 0.0
    self._latency_ms: float = 0.0
    self._isolated_addrs: Set[str] = set()
    self.relay_enabled: bool = True
    self._seen_frame_ids: List[str] = []
    self._frame_seq: int = 0
    self.total_frames_routed: int = 0
    self.total_frames_dropped: int = 0
    self._pcap_writer = None
    self._pcap_encoder = None
    self._rf_simulator: Optional[RfChannelSimulator] = (
        RfChannelSimulator.get_shared()
    )

  @property
  def rf_simulator(self) -> Optional[RfChannelSimulator]:
    return self._rf_simulator

  def set_rf_simulator(self, simulator: Optional[RfChannelSimulator]) -> None:
    with self._lock:
      self._rf_simulator = simulator

  @property
  def pcap_writer(self):
    return self._pcap_writer

  @property
  def pcap_encoder(self):
    return self._pcap_encoder

  def set_pcap_writer(self, writer) -> None:
    encoder = None
    if writer is not None:
      from cirque.capabilities.pcapcapability import LeLinkLayerPcapEncoder

      encoder = LeLinkLayerPcapEncoder()
    with self._lock:
      self._pcap_writer = writer
      self._pcap_encoder = encoder

  def register_local_endpoint(
      self, bd_addr: str, callback: Callable[[LinkLayerFrame], None]
  ) -> None:
    with self._lock:
      self._local_listeners[bd_addr.upper()] = callback

  def unregister_local_endpoint(self, bd_addr: str) -> None:
    with self._lock:
      self._local_listeners.pop(bd_addr.upper(), None)

  def add_peer_socket(self, sock: socket.socket) -> int:
    with self._lock:
      fd = sock.fileno()
      self._peer_sockets[fd] = sock
      return fd

  def remove_peer_socket(self, fd: int) -> None:
    with self._lock:
      self._peer_sockets.pop(fd, None)

  def set_rssi(self, src_bd_addr: str, dst_bd_addr: str, rssi: int) -> None:
    with self._lock:
      key = (src_bd_addr.upper(), dst_bd_addr.upper())
      self._rssi_matrix[key] = max(-127, min(20, int(rssi)))

  def get_rssi(self, src_bd_addr: str, dst_bd_addr: str) -> int:
    """Returns directional RSSI or falls back to stochastic/default RSSI."""
    with self._lock:
      key = (src_bd_addr.upper(), dst_bd_addr.upper())
      rev_key = (dst_bd_addr.upper(), src_bd_addr.upper())
      if key in self._rssi_matrix:
        return self._rssi_matrix[key]
      if rev_key in self._rssi_matrix:
        return self._rssi_matrix[rev_key]
      if self._rf_simulator is not None and self._rf_simulator.config.enabled:
        sample = self._rf_simulator.evaluate_packet(
            'ble',
            src_bd_addr.upper(),
            dst_bd_addr.upper(),
            channel=self._rf_simulator.config.ble_channel,
            frame_len_bytes=32,
            record_telemetry=False,
        )
        return sample.rssi_dbm
      return self._default_rssi

  def set_default_rssi(self, rssi: int) -> None:
    with self._lock:
      self._default_rssi = max(-127, min(20, int(rssi)))

  def set_packet_loss_rate(self, loss_rate: float) -> None:
    with self._lock:
      self._packet_loss_rate = max(0.0, min(1.0, float(loss_rate)))

  def set_latency_ms(self, latency_ms: float) -> None:
    with self._lock:
      self._latency_ms = max(0.0, float(latency_ms))

  def set_isolated(self, bd_addr: str, isolated: bool = True) -> None:
    with self._lock:
      if isolated:
        self._isolated_addrs.add(bd_addr.upper())
      else:
        self._isolated_addrs.discard(bd_addr.upper())

  def reset_medium(self) -> None:
    with self._lock:
      self.relay_enabled = True
      self._rssi_matrix.clear()
      self._default_rssi = -45
      self._packet_loss_rate = 0.0
      self._latency_ms = 0.0
      self._isolated_addrs.clear()

  def transmit(
      self, frame: LinkLayerFrame, exclude_peer_fd: Optional[int] = None
  ) -> bool:
    """Broadcasts or unicasts a LinkLayerFrame across local and remote PHY endpoints."""
    with self._lock:
      src = frame.src_bd_addr.upper()
      dst = frame.dst_bd_addr.upper()

      # Stamp origin hub and monotonic sequence ID so multi-hub TCP topologies
      # can detect and drop looped frames via `_seen_frame_ids`.
      if not frame.origin_hub_id:
        frame.origin_hub_id = self.hub_id
      if not frame.frame_id:
        self._frame_seq += 1
        frame.frame_id = f'{self.hub_id}:{self._frame_seq}'

      if frame.frame_id in self._seen_frame_ids:
        return False
      self._seen_frame_ids.append(frame.frame_id)
      if len(self._seen_frame_ids) > 512:
        self._seen_frame_ids = self._seen_frame_ids[-256:]

      if not self.relay_enabled:
        self.total_frames_dropped += 1
        return False

      # Drop frame if either source or unicast destination is RF-isolated.
      if src in self._isolated_addrs or (
          dst != 'FF:FF:FF:FF:FF:FF' and dst in self._isolated_addrs
      ):
        self.total_frames_dropped += 1
        return False

      if (
          self._packet_loss_rate > 0.0
          and random.random() < self._packet_loss_rate
      ):
        self.total_frames_dropped += 1
        return False

      if self._rf_simulator is not None and self._rf_simulator.config.enabled:
        rf_sample = self._rf_simulator.evaluate_packet(
            'ble',
            src,
            dst,
            channel=frame.channel,
            frame_len_bytes=max(16, len(frame.payload) + 10),
            record_telemetry=True,
        )
        if (src, dst) not in self._rssi_matrix and (
            dst,
            src,
        ) not in self._rssi_matrix:
          frame.rssi = rf_sample.rssi_dbm
        if rf_sample.dropped and frame.pdu_type not in (
            LinkLayerPduType.PHY_ANNOUNCE.value,
            LinkLayerPduType.CONNECT_IND.value,
            LinkLayerPduType.CONNECT_RSP.value,
            LinkLayerPduType.LL_TERMINATE_IND.value,
        ):
          self.total_frames_dropped += 1
          return False

      latency_s = self._latency_ms / 1000.0
      local_targets: List[Tuple[str, Callable[[LinkLayerFrame], None]]] = []
      for target_addr, cb in self._local_listeners.items():
        if target_addr == src:
          continue
        if target_addr in self._isolated_addrs:
          continue
        if dst == 'FF:FF:FF:FF:FF:FF' or target_addr == dst:
          local_targets.append((target_addr, cb))

      peer_socks = [
          (fd, s)
          for fd, s in self._peer_sockets.items()
          if fd != exclude_peer_fd
      ]
      self.total_frames_routed += 1
      pcap_writer = self._pcap_writer
      pcap_encoder = self._pcap_encoder

    if pcap_writer is not None and pcap_encoder is not None:
      try:
        for ll_bytes in pcap_encoder.encode(frame):
          pcap_writer.write_frame(ll_bytes)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning('Failed to record LinkLayer pcap frame: %s', exc)

    # Deliver frames outside `self._lock` so recipient callbacks (e.g. an
    # immediate SCAN_REQ or CONNECT_RSP reply) can re-enter `transmit()`.
    if latency_s > 0:
      time.sleep(min(latency_s, 0.5))

    self._deliver_to_targets_and_peers(frame, src, local_targets, peer_socks)
    return True

  def _deliver_to_targets_and_peers(
      self, frame: LinkLayerFrame, src: str, local_targets, peer_socks
  ) -> None:
    """Delivers a routed LinkLayerFrame to local callbacks and remote TCP peers."""
    for target_addr, cb in local_targets:
      if (
          self._rf_simulator is not None
          and self._rf_simulator.config.enabled
          and (src, target_addr) not in self._rssi_matrix
          and (target_addr, src) not in self._rssi_matrix
      ):
        rx_rssi = frame.rssi
      else:
        rx_rssi = self.get_rssi(src, target_addr)
      delivered = LinkLayerFrame(
          pdu_type=frame.pdu_type,
          src_bd_addr=src,
          dst_bd_addr=frame.dst_bd_addr,
          src_addr_type=frame.src_addr_type,
          dst_addr_type=frame.dst_addr_type,
          channel=frame.channel,
          rssi=rx_rssi,
          payload_hex=frame.payload_hex,
          conn_interval=frame.conn_interval,
          conn_latency=frame.conn_latency,
          supervision_timeout=frame.supervision_timeout,
          reason=frame.reason,
          origin_hub_id=frame.origin_hub_id,
          frame_id=frame.frame_id,
      )
      try:
        cb(delivered)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning('Error in LinkLayer frame delivery callback: %s', exc)

    wire = frame.to_wire_bytes()
    dead_fds = []
    for fd, sock in peer_socks:
      try:
        sock.sendall(wire)
      except OSError as exc:
        logger.warning(
            'Error sending wire bytes to peer socket %d: %s', fd, exc
        )
        dead_fds.append(fd)

    for fd in dead_fds:
      self.remove_peer_socket(fd)
