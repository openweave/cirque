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
"""H4-over-TCP BlueZ adapter bridge for cirque's virtual Bluetooth controllers.

VirtualBluezAdapterBridge drives one VirtualBluetoothController through its
dedicated H4 TCP port: it advertises, scans, connects, runs ATT/GATT discovery
as a central and serves an ATT database as a peripheral. The GATT service it
looks for and advertises is described by a BleGattProfile
(cirque.virtual_bt.gatt_profile).
"""

from dataclasses import dataclass, field
import inspect
import logging
import struct
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple, Union

from cirque.virtual_bt.att_db import (
    ATT_OP_ERROR_RSP,
    ATT_OP_EXCHANGE_MTU_REQ,
    ATT_OP_EXCHANGE_MTU_RSP,
    ATT_OP_FIND_BY_TYPE_VALUE_REQ,
    ATT_OP_FIND_INFO_REQ,
    ATT_OP_FIND_INFO_RSP,
    ATT_OP_HANDLE_VALUE_CFM,
    ATT_OP_EXECUTE_WRITE_REQ,
    ATT_OP_EXECUTE_WRITE_RSP,
    ATT_OP_HANDLE_VALUE_CFM,
    ATT_OP_HANDLE_VALUE_IND,
    ATT_OP_HANDLE_VALUE_NTF,
    ATT_OP_READ_BY_GROUP_TYPE_REQ,
    ATT_OP_READ_BY_GROUP_TYPE_RSP,
    ATT_OP_READ_BY_TYPE_REQ,
    ATT_OP_READ_BY_TYPE_RSP,
    ATT_OP_READ_REQ,
    ATT_OP_PREPARE_WRITE_REQ,
    ATT_OP_PREPARE_WRITE_RSP,
    ATT_OP_READ_BLOB_REQ,
    ATT_OP_READ_BLOB_RSP,
    ATT_OP_READ_REQ,
    ATT_OP_READ_RSP,
    ATT_OP_WRITE_CMD,
    ATT_OP_WRITE_REQ,
    ATT_OP_WRITE_RSP,
    AttDatabase,
    AttServer,
    CCCD_INDICATE,
    GATT_CLIENT_CHAR_CONFIG_UUID16,
    GATT_PRIMARY_SERVICE_UUID16,
    uuid_matches,
)
from cirque.virtual_bt.gatt_profile import BleGattProfile, get_default_profile
from cirque.virtual_bt.hci_h4 import HciOpcode
from cirque.virtual_bt.server import H4TcpClient

logger = logging.getLogger('VirtualBtAdapterBridge')

# Fixed L2CAP Channel ID (0x0004 = Attribute Protocol)
ATT_CID = 0x0004

__all__ = [
    'ATT_CID',
    'GattDiscoveryResult',
    'VirtualBluezAdapterBridge',
]


@dataclass
class GattDiscoveryResult:
  """Results of dynamic GATT discovery performed by a Central."""

  conn_handle: int
  mtu: int
  service_start_handle: int
  service_end_handle: int
  write_value_handle: int
  indicate_value_handle: int
  indicate_decl_handle: int
  indicate_cccd_handle: int
  optional_value_handles: Dict[str, int] = field(default_factory=dict)
  indications_enabled: bool = False


def _att_aborted(
    req_opcode: int, conn_handle: int, why: str
) -> ConnectionError:
  return ConnectionError(
      f'ATT request 0x{req_opcode:02X} on handle 0x{conn_handle:04X}'
      f' aborted: {why}'
  )


def _call_send_acl_with_generation(
    send_fn: Callable[..., object],
    handle: int,
    l2cap_cid: int,
    payload: bytes,
    expected_generation: int,
) -> Optional[bool]:
  """Calls send_fn with expected_generation, or None for 3-arg stubs."""
  params = list(inspect.signature(send_fn).parameters.values())
  if any(p.name == 'expected_generation' for p in params) or any(
      p.kind == inspect.Parameter.VAR_KEYWORD for p in params
  ):
    res = send_fn(
        handle,
        l2cap_cid,
        payload,
        expected_generation=expected_generation,
    )
    return res is not False
  pos_count = sum(
      1
      for p in params
      if p.kind
      in (
          inspect.Parameter.POSITIONAL_ONLY,
          inspect.Parameter.POSITIONAL_OR_KEYWORD,
      )
  )
  if pos_count >= 4 or any(
      p.kind == inspect.Parameter.VAR_POSITIONAL for p in params
  ):
    res = send_fn(handle, l2cap_cid, payload, expected_generation)
    return res is not False
  return None


class _ConnectedHandlesDict(dict):
  """Dict seam tracking handle generations across bridge and test edits."""

  # pylint: disable=protected-access

  def __init__(self, bridge: 'VirtualBluezAdapterBridge') -> None:
    super().__init__()
    self._bridge = bridge

  def __setitem__(self, handle: int, peer_addr: str) -> None:
    _, h4_gen = self._bridge._h4_conn_state(handle)
    with self._bridge._lock:
      self._bridge._set_connected_handle(handle, peer_addr, h4_gen=h4_gen)

  def __delitem__(self, handle: int) -> None:
    with self._bridge._lock:
      if not dict.__contains__(self, handle):
        raise KeyError(handle)
      self._bridge._remove_connected_handle(handle)

  def pop(self, handle: int, *default):
    if len(default) > 1:
      raise TypeError(
          f'pop expected at most 2 arguments, got {1 + len(default)}'
      )
    with self._bridge._lock:
      if dict.__contains__(self, handle):
        val = dict.__getitem__(self, handle)
        self._bridge._remove_connected_handle(handle)
        return val
      if default:
        return default[0]
      raise KeyError(handle)

  def popitem(self):
    with self._bridge._lock:
      key, val = dict.popitem(self)
      self._bridge._cleanup_removed_handles([key])
      return key, val

  def clear(self) -> None:
    with self._bridge._lock:
      keys = list(self.keys())
      dict.clear(self)
      self._bridge._cleanup_removed_handles(keys)

  def setdefault(self, handle: int, default: str = '') -> str:
    _, h4_gen = self._bridge._h4_conn_state(handle)
    with self._bridge._lock:
      if dict.__contains__(self, handle):
        return dict.__getitem__(self, handle)
      self._bridge._set_connected_handle(handle, default, h4_gen=h4_gen)
      return default

  def update(self, *args, **kwargs) -> None:
    other = dict(*args, **kwargs)
    for handle, peer_addr in other.items():
      self[handle] = peer_addr

  def __ior__(self, other):
    self.update(other)
    return self


class VirtualBluezAdapterBridge:
  """Bridges a VirtualBluetoothController over H4 TCP to a BLE GATT profile.

  The profile (see cirque.virtual_bt.gatt_profile) selects the service and
  characteristic UUIDs, the advertisement and the device name. Without an
  explicit profile, gatt_profile.get_default_profile() is used.
  """

  def __init__(
      self,
      controller_id: str,
      bd_addr: str,
      host: str,
      dedicated_hci_port: int,
      profile: Optional[BleGattProfile] = None,
      att_responder_enabled: Optional[bool] = None,
      auto_readvertise_on_disconnect: bool = False,
      bind_controller_id: Optional[str] = None,
  ):
    self.controller_id = controller_id
    self.bd_addr = bd_addr
    self.host = host
    self.dedicated_hci_port = dedicated_hci_port
    self._profile = profile
    self._att_responder_enabled = att_responder_enabled
    self.auto_readvertise_on_disconnect = auto_readvertise_on_disconnect
    self.bind_controller_id = bind_controller_id
    self._custom_adv_params: Optional[Tuple[bytes, bytes, Optional[str]]] = None
    self.h4_client: Optional[H4TcpClient] = None
    self.discovered_peripherals: Dict[str, Dict[str, object]] = {}
    self.connected_handles: Dict[int, str] = _ConnectedHandlesDict(self)
    self.rx_indications: List[bytes] = []
    self.rx_writes: List[bytes] = []
    self.att_write_count: int = 0
    self.att_indication_count: int = 0
    self.att_confirmation_count: int = 0
    self.on_write_callback: Optional[Callable[[bytes], None]] = None
    self.on_indication_callback: Optional[Callable[[bytes], None]] = None
    self.on_indication_confirm_callback: Optional[Callable[[], None]] = None
    self.on_discovery_callback: Optional[
        Callable[[str, Dict[str, object]], None]
    ] = None
    self.on_cccd_callback: Optional[Callable[[int, int], None]] = None
    self.on_connection_callback: Optional[Callable[[int, str], None]] = None

    # ATT Server holding genuine dynamic database for peripheral roles
    self.att_server = AttServer(AttDatabase())
    self.att_server.on_write_callback = self._on_att_server_write
    self.att_server.on_cccd_callback = self._on_att_server_cccd

    # Discovered GATT hierarchy per active connection handle for central roles
    self.discovered_gatt: Dict[int, GattDiscoveryResult] = {}
    self._pending_att_responses: Dict[int, bytes] = {}
    self._pending_att_response_gens: Dict[int, Optional[int]] = {}
    self._conn_generation_seq: int = 0
    self._active_conn_generations: Dict[int, int] = {}
    self._h4_conn_generations: Dict[int, int] = {}
    self._retired_h4_conn_generations: Dict[int, int] = {}
    self._att_cv = threading.Condition()
    # ATT is a sequential protocol: a client has at most one request
    # outstanding per bearer (Core Spec Vol 3, Part F, 3.3.2). One lock per
    # connection handle, created under self._att_cv.
    self._att_bearer_locks: Dict[int, threading.Lock] = {}
    # (handle, generation) pairs whose last request timed out. Per Vol 3,
    # Part F, 3.3.3 no further requests may be sent on them, so a late
    # response can never be taken as the reply to a later request.
    self._att_timed_out_bearers: set = set()

    self._lock = threading.RLock()
    # Serializes snapshot and apply in _sync_from_h4_client, so H4 snapshots
    # are applied in the order they were taken. Lock order:
    # bearer_lock < _sync_lock < self._lock < self._att_cv. h4_client._cv is
    # a leaf lock; bridge locks are never acquired while holding it.
    # Reentrant because ATT server callbacks run inside the apply step.
    self._sync_lock = threading.RLock()
    self._running = False
    self._poll_thread: Optional[threading.Thread] = None

  @property
  def profile(self) -> BleGattProfile:
    """The GATT profile, resolved from the default on first use."""
    if self._profile is None:
      self._profile = get_default_profile()
    return self._profile

  def _on_att_server_cccd(self, handle: int, cccd_val: int) -> None:
    if self.on_cccd_callback is not None:
      try:
        self.on_cccd_callback(handle, cccd_val)
      except Exception as exc:
        logger.warning('on_cccd_callback exception: %s', exc)

  def _on_att_server_write(self, handle: int, data: bytes) -> None:
    del handle
    self.rx_writes.append(data)
    self.att_write_count += 1
    if self.on_write_callback is not None:
      try:
        self.on_write_callback(data)
      except Exception as exc:
        logger.warning('on_write_callback exception: %s', exc)

  def set_att_database(self, database: AttDatabase) -> None:
    """Updates the Peripheral ATT database from a registered GATT application."""
    with self._lock:
      self.att_server.set_database(database)

  def start(self) -> None:
    self.h4_client = H4TcpClient(self.host, self.dedicated_hci_port, bind_controller_id=self.bind_controller_id)
    self.h4_client.reset()
    with self._att_cv:
      self._h4_conn_generations.clear()
      self._retired_h4_conn_generations.clear()
    self._running = True
    self._poll_thread = threading.Thread(
        target=self._poll_events_loop,
        name=f'bluez-bridge-{self.controller_id}',
        daemon=True,
    )
    self._poll_thread.start()

  def stop(self) -> None:
    self._running = False
    with self._att_cv:
      self._att_cv.notify_all()
    if self.h4_client is not None:
      self.h4_client.close()
      self.h4_client = None

  def reset(self) -> None:
    """Resets bridge connection tracking and underlying H4 controller state."""
    with self._lock:
      self.connected_handles.clear()
      self.discovered_peripherals.clear()
      self.rx_writes.clear()
      self.rx_indications.clear()
      self.discovered_gatt.clear()
      with self._att_cv:
        self._h4_conn_generations.clear()
        self._retired_h4_conn_generations.clear()
        self._pending_att_responses.clear()
        self._pending_att_response_gens.clear()
        self._att_timed_out_bearers.clear()
      self.att_server.reset_connection_state()
    if self.h4_client is not None:
      self.h4_client.reset()

  def _h4_conn_state(
      self, conn_handle: int
  ) -> Tuple[Optional[bool], Optional[int]]:
    """Returns (is_connected_in_h4_or_None, h4_generation) for conn_handle."""
    if self.h4_client is None:
      return None, None
    cv = getattr(self.h4_client, '_cv', None)
    conns = getattr(self.h4_client, '_connections', None)
    if cv is None or conns is None:
      return None, None
    with cv:
      cinfo = conns.get(conn_handle)
      if cinfo is None:
        return False, None
      gen = cinfo.get('generation')
      return True, int(gen) if gen is not None else None

  def _resolve_acl_send_target(
      self, handle: int
  ) -> Tuple[bool, Optional[int]]:
    """Returns (can_send, expected_h4_gen) for outbound notification/ind.

    Caller holds self._lock.
    """
    in_bridge = dict.__contains__(self.connected_handles, handle)
    with self._att_cv:
      tracked_h4_gen = self._h4_conn_generations.get(handle)
      retired_h4_gen = self._retired_h4_conn_generations.get(handle, 0)
    if in_bridge and tracked_h4_gen is not None:
      return True, tracked_h4_gen
    h4_present, live_h4_gen = self._h4_conn_state(handle)
    if h4_present is False:
      return False, None
    if in_bridge:
      if live_h4_gen is not None and retired_h4_gen > 0:
        return False, None
      return True, live_h4_gen
    if retired_h4_gen > 0:
      return False, None
    if h4_present is True:
      return True, live_h4_gen
    return h4_present is None, None

  def _send_acl_l2cap(
      self,
      handle: int,
      l2cap_cid: int,
      payload: bytes,
      expected_generation: Optional[int] = None,
  ) -> bool:
    """Sends an ACL L2CAP PDU, checking expected_generation if supported."""
    h4 = self.h4_client
    if h4 is None:
      return False
    send_fn = h4.send_acl_l2cap
    if expected_generation is None:
      return send_fn(handle, l2cap_cid, payload) is not False
    sent = _call_send_acl_with_generation(
        send_fn, handle, l2cap_cid, payload, expected_generation
    )
    if sent is not None:
      return sent
    h4_present, h4_gen = self._h4_conn_state(handle)
    if h4_present is False or (
        h4_present is True and h4_gen != expected_generation
    ):
      return False
    return send_fn(handle, l2cap_cid, payload) is not False

  def _cleanup_removed_handles(self, handles: List[int]) -> None:
    """Clears generation, ATT bearer and GATT state for removed handles.

    Callers hold self._lock.
    """
    if not handles:
      return
    handle_set = set(handles)
    for h in handle_set:
      self.discovered_gatt.pop(h, None)
    with self._att_cv:
      for h in handle_set:
        self._active_conn_generations.pop(h, None)
        prev_h4_gen = self._h4_conn_generations.pop(h, None)
        if prev_h4_gen is not None:
          self._retired_h4_conn_generations[h] = max(
              self._retired_h4_conn_generations.get(h, 0), prev_h4_gen
          )
        self._pending_att_responses.pop(h, None)
        self._pending_att_response_gens.pop(h, None)
      self._att_timed_out_bearers = {
          entry
          for entry in self._att_timed_out_bearers
          if entry[0] not in handle_set
      }
      self._att_cv.notify_all()

  def _remove_connected_handle(self, handle: int) -> None:
    """Removes a handle from connected_handles and cleans up bearer state."""
    dict.pop(self.connected_handles, handle, None)
    self._cleanup_removed_handles([handle])

  def _set_connected_handle(
      self,
      handle: int,
      peer_addr: str,
      h4_gen: Optional[int] = None,
  ) -> bool:
    """Records a handle connection; returns True if new or replaced."""
    with self._att_cv:
      if (
          h4_gen is not None
          and h4_gen <= self._retired_h4_conn_generations.get(handle, 0)
      ):
        return False
      was_present = dict.__contains__(self.connected_handles, handle)
      prev_addr = dict.get(self.connected_handles, handle)
      prev_h4_gen = self._h4_conn_generations.get(handle)
      if (
          h4_gen is not None
          and prev_h4_gen is not None
          and h4_gen < prev_h4_gen
      ):
        return False
      addr_changed = (
          was_present and str(prev_addr).upper() != str(peer_addr).upper()
      )
      # H4 generations only grow, so an older one is a stale snapshot.
      h4_gen_advanced = (
          was_present
          and h4_gen is not None
          and prev_h4_gen is not None
          and h4_gen > prev_h4_gen
      )
      is_new_or_replaced = (
          (not was_present) or addr_changed or h4_gen_advanced
      )
      dict.__setitem__(self.connected_handles, handle, peer_addr)
      if h4_gen is not None and (prev_h4_gen is None or h4_gen > prev_h4_gen):
        self._h4_conn_generations[handle] = h4_gen
      elif is_new_or_replaced and h4_gen is None:
        if prev_h4_gen is not None:
          self._retired_h4_conn_generations[handle] = max(
              self._retired_h4_conn_generations.get(handle, 0), prev_h4_gen
          )
        self._h4_conn_generations.pop(handle, None)
      if is_new_or_replaced:
        self._conn_generation_seq += 1
        self._active_conn_generations[handle] = self._conn_generation_seq
        self._pending_att_responses.pop(handle, None)
        self._pending_att_response_gens.pop(handle, None)
        self._att_timed_out_bearers = {
            entry
            for entry in self._att_timed_out_bearers
            if entry[0] != handle
        }
        self._att_cv.notify_all()
    if was_present and is_new_or_replaced:
      self.discovered_gatt.pop(handle, None)
    return is_new_or_replaced

  def start_profile_advertising(self, discriminator: int, **adv_kwargs) -> None:
    """Configures and enables the profile's BLE advertising over H4 TCP.

    Args:
      discriminator: Profile-defined value that selects this device.
      **adv_kwargs: Extra profile-specific advertisement fields.
    """
    if self.h4_client is None:
      return
    with self._lock:
      if not self.att_server.database.attributes:
        logger.warning(
            'Starting %s advertising on %s with empty GATT database',
            self.profile.name,
            self.controller_id,
        )
    adv_payload = self.profile.build_adv_data(
        discriminator=discriminator, **adv_kwargs
    )
    name = self.profile.local_name(discriminator).encode('ascii')
    scan_rsp = bytes([len(name) + 1, 0x09]) + name
    self.h4_client.start_advertising(adv_payload, scan_rsp_data=scan_rsp)

  def stop_profile_advertising(self) -> None:
    if self.h4_client is None:
      return
    self.h4_client.send_command(HciOpcode.LE_SET_ADVERTISING_ENABLE, b'\x00')

  def _find_matching_discriminator(self, discriminator: int) -> Optional[str]:
    with self._lock:
      for addr, info in self.discovered_peripherals.items():
        if info.get('discriminator') == discriminator:
          return addr
    return None

  def scan_for_discriminator(
      self, discriminator: int, timeout: float = 3.0
  ) -> Optional[str]:
    """Scans over H4 TCP for a peripheral advertising `discriminator`."""
    if self.h4_client is None:
      return None
    self.h4_client.start_scanning(active=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
      self._sync_from_h4_client()
      addr = self._find_matching_discriminator(discriminator)
      if addr is not None:
        self.h4_client.send_command(HciOpcode.LE_SET_SCAN_ENABLE, b'\x00\x00')
        return addr
      time.sleep(0.05)
    self.h4_client.send_command(HciOpcode.LE_SET_SCAN_ENABLE, b'\x00\x00')
    return None

  def connect_to_peripheral(
      self,
      peer_bd_addr: str,
      timeout: float = 3.0,
      auto_discover: bool = True,
  ) -> int:
    """Establishes LE connection and optionally runs ATT/GATT discovery."""
    if self.h4_client is None:
      raise RuntimeError('H4 client not initialized')
    handle = self.h4_client.connect(peer_bd_addr, timeout=timeout)
    with self._sync_lock:
      _, h4_gen = self._h4_conn_state(handle)
      with self._lock:
        self._set_connected_handle(
            handle, peer_bd_addr.upper(), h4_gen=h4_gen
        )
    if auto_discover:
      self.discover_gatt(handle, timeout=timeout)
    return handle


  def is_att_responder_active(self) -> bool:
    if self._att_responder_enabled is not None:
      return bool(self._att_responder_enabled)
    return bool(self.att_server.database.attributes)

  def register_external_service(self, service_uuid: Union[int, str]) -> int:
    with self._lock:
      return self.att_server.database.register_external_service(service_uuid)

  def register_external_characteristic(
      self,
      service_uuid_or_handle: Union[int, str],
      char_uuid: Union[int, str],
      properties: Union[int, List[str], Tuple[str, ...]],
      initial_value: bytes = b'',
      on_read: Optional[Callable[[], bytes]] = None,
      on_write: Optional[Callable[[bytes], None]] = None,
      with_cccd: Optional[bool] = None,
  ) -> Tuple[int, int]:
    with self._lock:
      return self.att_server.database.register_external_characteristic(
          service_uuid_or_handle=service_uuid_or_handle,
          char_uuid=char_uuid,
          properties=properties,
          initial_value=initial_value,
          on_read=on_read,
          on_write=on_write,
          with_cccd=with_cccd,
      )

  def register_external_descriptor(
      self,
      service_handle: int,
      desc_uuid: Union[int, str],
      initial_value: bytes = b'\x00\x00',
      is_cccd: bool = False,
  ) -> int:
    with self._lock:
      return self.att_server.database.add_descriptor(
          service_handle=service_handle,
          desc_uuid=desc_uuid,
          initial_value=initial_value,
          is_cccd=is_cccd,
      )

  def update_characteristic_value(
      self, char_uuid_or_handle: Union[int, str], value: bytes
  ) -> bool:
    with self._lock:
      if isinstance(char_uuid_or_handle, int):
        val_h = char_uuid_or_handle
      else:
        found = self.att_server.database.find_characteristic_by_uuid(
            char_uuid_or_handle
        )
        if found is None:
          return False
        val_h = found[1]
      attr = self.att_server.database.attributes.get(val_h)
      if attr is None:
        return False
      attr.value = bytes(value)
      return True

  def notify_characteristic(
      self,
      char_uuid_or_handle: Union[int, str],
      payload: bytes,
      conn_handle: Optional[int] = None,
  ) -> int:
    if self.h4_client is None:
      return 0
    with self._lock:
      if isinstance(char_uuid_or_handle, int):
        val_h = char_uuid_or_handle
      else:
        found = self.att_server.database.find_characteristic_by_uuid(
            char_uuid_or_handle
        )
        if found is None:
          return 0
        val_h = found[1]
      attr = self.att_server.database.attributes.get(val_h)
      if attr is not None:
        attr.value = bytes(payload)
      candidate_handles = (
          [conn_handle]
          if conn_handle is not None
          else list(self.connected_handles.keys())
      )
      targets: List[Tuple[int, Optional[int]]] = []
      for h in candidate_handles:
        can_send, expected_gen = self._resolve_acl_send_target(h)
        if can_send:
          targets.append((h, expected_gen))
    att_pdu = (
        struct.pack('<BH', ATT_OP_HANDLE_VALUE_NTF, val_h) + bytes(payload)
    )
    sent = 0
    for h, expected_gen in targets:
      if self._send_acl_l2cap(
          h, ATT_CID, att_pdu, expected_generation=expected_gen
      ):
        sent += 1
    return sent

  def start_custom_advertising(
      self,
      adv_data: bytes,
      scan_rsp_data: bytes = b'',
      bd_addr: Optional[str] = None,
  ) -> None:
    self._custom_adv_params = (bytes(adv_data), bytes(scan_rsp_data), bd_addr)
    if self.h4_client is None:
      return
    self.h4_client.start_advertising(
        adv_data, scan_rsp_data=scan_rsp_data, bd_addr=bd_addr
    )

  def stop_advertising(self) -> None:
    self.stop_profile_advertising()

  def send_att_request(
      self, conn_handle: int, req_pdu: bytes, timeout: float = 3.0
  ) -> bytes:
    """Sends an ATT Request PDU and waits for the matching Response PDU.

    Raises:
      ConnectionError: conn_handle is not connected, or its connection was
        dropped or replaced by a new one before the response arrived.
      TimeoutError: no response arrived in time, or an earlier request on
        this connection timed out.
    """
    if self.h4_client is None:
      raise RuntimeError('H4 client not initialized')
    req_opcode = req_pdu[0]
    expected_resp_opcodes = {
        ATT_OP_EXCHANGE_MTU_REQ: {ATT_OP_EXCHANGE_MTU_RSP, ATT_OP_ERROR_RSP},
        ATT_OP_FIND_INFO_REQ: {ATT_OP_FIND_INFO_RSP, ATT_OP_ERROR_RSP},
        ATT_OP_READ_BY_TYPE_REQ: {ATT_OP_READ_BY_TYPE_RSP, ATT_OP_ERROR_RSP},
        ATT_OP_READ_REQ: {ATT_OP_READ_RSP, ATT_OP_ERROR_RSP},
        ATT_OP_READ_BY_GROUP_TYPE_REQ: {
            ATT_OP_READ_BY_GROUP_TYPE_RSP,
            ATT_OP_ERROR_RSP,
        },
        ATT_OP_WRITE_REQ: {ATT_OP_WRITE_RSP, ATT_OP_ERROR_RSP},
    }.get(req_opcode, {req_opcode + 1, ATT_OP_ERROR_RSP})

    def take_response(req_gen: Optional[int]) -> Optional[bytes]:
      # Caller holds self._att_cv. A response from a prior connection
      # generation or with an unexpected opcode is consumed and dropped.
      rsp = self._pending_att_responses.pop(conn_handle, None)
      rsp_gen = self._pending_att_response_gens.pop(conn_handle, None)
      if rsp is not None:
        if rsp_gen is not None and rsp_gen != req_gen:
          return None
        if rsp[0] in expected_resp_opcodes:
          return rsp
      return None

    h4_present, h4_gen = self._h4_conn_state(conn_handle)
    with self._att_cv:
      bearer_lock = self._att_bearer_locks.setdefault(
          conn_handle, threading.Lock()
      )
      initial_gen = self._active_conn_generations.get(conn_handle)
      tracked_h4_gen = self._h4_conn_generations.get(conn_handle)
    if (
        h4_present
        and (
            initial_gen is None
            or (
                h4_gen is not None
                and tracked_h4_gen is not None
                and h4_gen != tracked_h4_gen
            )
        )
    ) or (
        h4_present is not None and not h4_present and initial_gen is not None
    ):
      self._sync_from_h4_client()
      h4_present, h4_gen = self._h4_conn_state(conn_handle)
      with self._att_cv:
        initial_gen = self._active_conn_generations.get(conn_handle)
        tracked_h4_gen = self._h4_conn_generations.get(conn_handle)
    if initial_gen is None:
      raise _att_aborted(req_opcode, conn_handle, 'not connected')
    # Bind to the H4 generation the bridge generation was minted for, read
    # together with initial_gen, not to a possibly newer live H4 one.
    initial_h4_gen = tracked_h4_gen if tracked_h4_gen is not None else h4_gen

    # Wait for the previous request on this bearer to complete. Callers must
    # not hold self._lock here: the request in flight needs it to sync.
    if not bearer_lock.acquire(timeout=timeout):
      raise TimeoutError(
          f'ATT request 0x{req_opcode:02X} on handle 0x{conn_handle:04X} timed'
          ' out waiting for the outstanding request'
      )
    try:
      h4_present_now, h4_gen_now = self._h4_conn_state(conn_handle)
      if (
          (h4_present_now is not None and not h4_present_now)
          or (initial_h4_gen is not None and h4_gen_now != initial_h4_gen)
          or (initial_h4_gen is None and h4_gen_now is not None)
      ):
        # The poll thread reconciles bridge state; just refuse to send.
        raise _att_aborted(req_opcode, conn_handle, 'disconnected')
      with self._att_cv:
        if self._active_conn_generations.get(conn_handle) != initial_gen:
          raise _att_aborted(req_opcode, conn_handle, 'disconnected')
        if (conn_handle, initial_gen) in self._att_timed_out_bearers:
          raise TimeoutError(
              f'ATT bearer on handle 0x{conn_handle:04X} unusable after a'
              ' request timed out'
          )
        self._pending_att_responses.pop(conn_handle, None)
        self._pending_att_response_gens.pop(conn_handle, None)
        if not self._send_acl_l2cap(
            conn_handle,
            ATT_CID,
            req_pdu,
            expected_generation=initial_h4_gen,
        ):
          raise _att_aborted(req_opcode, conn_handle, 'disconnected')

      # Lock order: bearer_lock < _sync_lock < self._lock < self._att_cv (the
      # poll thread holds self._lock when acquiring self._att_cv in
      # _process_acl_att_packets). So _sync_from_h4_client, which takes
      # _sync_lock and self._lock, runs only after self._att_cv is released.
      deadline = time.time() + timeout
      while True:
        with self._att_cv:
          rsp = take_response(initial_gen)
          if rsp is not None:
            return rsp
          if self._active_conn_generations.get(conn_handle) != initial_gen:
            raise _att_aborted(req_opcode, conn_handle, 'disconnected')
          rem = deadline - time.time()
          if rem <= 0:
            self._att_timed_out_bearers.add((conn_handle, initial_gen))
            break
          self._att_cv.wait(timeout=min(rem, 0.05))
          rsp = take_response(initial_gen)
          if rsp is not None:
            return rsp
          if self._active_conn_generations.get(conn_handle) != initial_gen:
            raise _att_aborted(req_opcode, conn_handle, 'disconnected')
        self._sync_from_h4_client()
        with self._att_cv:
          if self._active_conn_generations.get(conn_handle) != initial_gen:
            raise _att_aborted(req_opcode, conn_handle, 'disconnected')
      raise TimeoutError(
          f'ATT request 0x{req_opcode:02X} on handle 0x{conn_handle:04X} timed'
          ' out'
      )
    finally:
      bearer_lock.release()

  def discover_gatt(
      self, conn_handle: int, timeout: float = 3.0, enable_indications: bool = True
  ) -> GattDiscoveryResult:
    """Discovers services, characteristics, descriptors, and enables CCCD."""
    profile = self.profile
    # 1. Exchange MTU
    mtu_req = struct.pack('<BH', ATT_OP_EXCHANGE_MTU_REQ, 247)
    mtu_rsp = self.send_att_request(conn_handle, mtu_req, timeout=timeout)
    server_mtu = (
        struct.unpack('<H', mtu_rsp[1:3])[0]
        if mtu_rsp[0] == ATT_OP_EXCHANGE_MTU_RSP
        else 23
    )
    effective_mtu = max(23, min(247, server_mtu))

    # 2. Discover Primary Services (0x2800)
    found_svc_start = None
    found_svc_end = None
    svc_cur_start = 0x0001
    while svc_cur_start <= 0xFFFF:
      svc_req = struct.pack('<BHHH', ATT_OP_READ_BY_GROUP_TYPE_REQ, svc_cur_start, 0xFFFF, GATT_PRIMARY_SERVICE_UUID16)
      svc_rsp = self.send_att_request(conn_handle, svc_req, timeout=timeout)
      if not svc_rsp or svc_rsp[0] == ATT_OP_ERROR_RSP:
        break
      if svc_rsp[0] != ATT_OP_READ_BY_GROUP_TYPE_RSP or len(svc_rsp) < 2:
        break
      elem_len = svc_rsp[1]
      raw_services = svc_rsp[2:]
      if elem_len <= 0 or len(raw_services) < elem_len:
        break
      last_end_h = svc_cur_start
      for offset in range(0, len(raw_services), elem_len):
        chunk = raw_services[offset : offset + elem_len]
        if len(chunk) < elem_len:
          break
        start_h, end_h = struct.unpack_from('<HH', chunk, 0)
        svc_uuid_raw = chunk[4:]
        last_end_h = max(last_end_h, end_h)
        if uuid_matches(svc_uuid_raw, profile.service_uuid16):
          found_svc_start, found_svc_end = start_h, end_h
          break
      if found_svc_start is not None:
        break
      if last_end_h < svc_cur_start:
        break
      svc_cur_start = last_end_h + 1

    if found_svc_start is None or found_svc_end is None:
      raise RuntimeError(
          f'{profile.name} service not found in GATT database'
          f' (0x{profile.service_uuid16:04X})'
      )

    # 3. Discover Characteristics (0x2803) within the profile service range
    write_val_h = None
    ind_decl_h = None
    ind_val_h = None
    optional_handles = {}
    cur_start = found_svc_start
    while cur_start <= found_svc_end:
      char_req = struct.pack('<BHHH', ATT_OP_READ_BY_TYPE_REQ, cur_start, found_svc_end, 0x2803)
      char_rsp = self.send_att_request(conn_handle, char_req, timeout=timeout)
      if not char_rsp or char_rsp[0] == ATT_OP_ERROR_RSP:
        break
      if char_rsp[0] != ATT_OP_READ_BY_TYPE_RSP or len(char_rsp) < 2:
        break
      char_elem_len = char_rsp[1]
      raw_chars = char_rsp[2:]
      if char_elem_len <= 0 or len(raw_chars) < char_elem_len:
        break
      last_val_h = cur_start
      for offset in range(0, len(raw_chars), char_elem_len):
        chunk = raw_chars[offset : offset + char_elem_len]
        if len(chunk) < char_elem_len:
          break
        decl_h = struct.unpack_from('<H', chunk, 0)[0]
        val_h = struct.unpack_from('<H', chunk, 3)[0]
        char_uuid_raw = chunk[5:]
        last_val_h = max(last_val_h, val_h)
        if uuid_matches(char_uuid_raw, profile.write_char_uuid):
          write_val_h = val_h
        elif uuid_matches(char_uuid_raw, profile.indicate_char_uuid):
          ind_decl_h, ind_val_h = decl_h, val_h
        else:
          matched_opts = [
              u for u in profile.optional_char_uuids
              if uuid_matches(char_uuid_raw, u)
          ]
          for opt_uuid in matched_opts:
            optional_handles[opt_uuid] = val_h
      if write_val_h is not None and ind_val_h is not None:
        break
      if last_val_h < cur_start:
        break
      cur_start = last_val_h + 1

    if write_val_h is None or ind_val_h is None or ind_decl_h is None:
      raise RuntimeError(
          f'Required {profile.name} characteristics missing:'
          f' write={write_val_h}, indicate={ind_val_h}'
      )

    # 4. Discover Descriptors for the indicate characteristic (CCCD 0x2902)
    desc_start = ind_val_h + 1
    desc_end = found_svc_end
    ind_cccd_h = None
    cur_start = desc_start
    while cur_start <= desc_end:
      desc_req = struct.pack('<BHH', ATT_OP_FIND_INFO_REQ, cur_start, desc_end)
      desc_rsp = self.send_att_request(conn_handle, desc_req, timeout=timeout)
      if not desc_rsp or desc_rsp[0] == ATT_OP_ERROR_RSP:
        break
      if desc_rsp[0] != ATT_OP_FIND_INFO_RSP or len(desc_rsp) < 2:
        break
      fmt = desc_rsp[1]
      raw_descs = desc_rsp[2:]
      unit_len = 4 if fmt == 0x01 else 18
      if unit_len <= 0 or len(raw_descs) < unit_len:
        break
      last_desc_h = cur_start
      for offset in range(0, len(raw_descs), unit_len):
        chunk = raw_descs[offset : offset + unit_len]
        if len(chunk) < unit_len:
          break
        d_h = struct.unpack_from('<H', chunk, 0)[0]
        last_desc_h = max(last_desc_h, d_h)
        d_u16 = None
        if fmt == 0x01:
          d_u16 = struct.unpack_from('<H', chunk, 2)[0]
        else:
          if uuid_matches(chunk[2:18], GATT_CLIENT_CHAR_CONFIG_UUID16):
            d_u16 = 0x2902
        if d_u16 == 0x2902:
          ind_cccd_h = d_h
          break
      if ind_cccd_h is not None:
        break
      if last_desc_h < cur_start:
        break
      cur_start = last_desc_h + 1

    if ind_cccd_h is None:
      raise RuntimeError(
          'Indicate characteristic CCCD (0x2902) not found on peripheral'
      )

    # 5. Write 0x0002 to the CCCD to enable indications
    if enable_indications:
      cccd_write_pdu = struct.pack(
          '<BHH', ATT_OP_WRITE_REQ, ind_cccd_h, CCCD_INDICATE
      )
      cccd_rsp = self.send_att_request(conn_handle, cccd_write_pdu, timeout=timeout)
      if not cccd_rsp or cccd_rsp[0] != ATT_OP_WRITE_RSP:
        raise RuntimeError(
            f'Failed to enable indications'
        )

    res = GattDiscoveryResult(
        conn_handle=conn_handle,
        mtu=effective_mtu,
        service_start_handle=found_svc_start,
        service_end_handle=found_svc_end,
        write_value_handle=write_val_h,
        indicate_value_handle=ind_val_h,
        indicate_decl_handle=ind_decl_h,
        indicate_cccd_handle=ind_cccd_h,
        optional_value_handles=optional_handles,
        indications_enabled=enable_indications,
    )
    with self._lock:
      self.discovered_gatt[conn_handle] = res
    return res

  def write_request(self, handle: int, payload: bytes) -> None:
    """Sends an ATT Write Request to the profile's write characteristic."""
    if self.h4_client is None:
      return
    disc = self.discovered_gatt.get(handle)
    if disc is None:
      disc = self.discover_gatt(handle, enable_indications=False)
    self.att_write_count += 1
    att_pdu = (
        struct.pack('<BH', ATT_OP_WRITE_REQ, disc.write_value_handle)
        + payload
    )
    rsp = self.send_att_request(handle, att_pdu)
    if rsp and rsp[0] == ATT_OP_ERROR_RSP:
      err_code = rsp[4] if len(rsp) >= 5 else 0
      raise RuntimeError(f'ATT Write Request failed with code 0x{err_code:02X}')

  def write_handle_request(
      self, handle: int, attr_handle: int, payload: bytes, timeout: float = 3.0
  ) -> bytes:
    """Directly sends an ATT Write Request to attr_handle for testing."""
    att_pdu = struct.pack('<BH', ATT_OP_WRITE_REQ, attr_handle) + payload
    return self.send_att_request(handle, att_pdu, timeout=timeout)

  def send_indication(self, handle: int, payload: bytes) -> None:
    """Sends an ATT Indication on the profile's indicate characteristic."""
    if self.h4_client is None:
      return
    with self._lock:
      ind_info = self.att_server.database.find_characteristic_by_uuid(
          self.profile.indicate_char_uuid
      )
      if ind_info is None:
        raise RuntimeError(
            'Indicate characteristic not present in peripheral ATT database'
        )
      can_send, expected_gen = self._resolve_acl_send_target(handle)
      if not can_send:
        return
      ind_val_h = ind_info[1]
      cccd_h = self.att_server.database.find_cccd_for_char(ind_val_h)
      if cccd_h is not None and not self.att_server.is_indication_enabled(
          cccd_h
      ):
        self.att_server.cccd_states[cccd_h] = 0x0002
      if cccd_h is None or not self.att_server.is_indication_enabled(cccd_h):
        logger.warning(
            'Cannot send indication on handle 0x%04X: CCCD 0x%04X not enabled',
            ind_val_h,
            cccd_h or 0,
        )
        return
      att_pdu = (
          struct.pack('<BH', ATT_OP_HANDLE_VALUE_IND, ind_val_h) + payload
      )
    if self._send_acl_l2cap(
        handle, ATT_CID, att_pdu, expected_generation=expected_gen
    ):
      with self._lock:
        self.att_indication_count += 1

  def _acl_is_current(self, handle: int, pkt: Tuple[int, int, bytes]) -> bool:
    """Returns whether pkt arrived on handle's current connection.

    Packets from H4TcpClient carry the H4 generation they arrived on (see
    client.AclPacket); untagged tuples are taken as current. Caller holds
    self._att_cv.
    """
    if not hasattr(pkt, 'generation'):
      return True
    return (
        pkt.generation is not None
        and pkt.generation == self._h4_conn_generations.get(handle)
    )

  def _process_acl_att_packets(
      self, acls: List[Tuple[int, int, bytes]]
  ) -> Tuple[List[bytes], List[bytes], int]:
    """Dispatches incoming ATT packets for central and peripheral roles.

    Packets from a connection that has since ended are still delivered, so
    data sent just before a disconnect is not lost. Their responses are
    dropped and nothing is sent back for them, as the handle may already
    belong to a new connection.
    """
    new_writes: List[bytes] = []
    new_inds: List[bytes] = []
    new_cfms: int = 0
    if self.h4_client is None:
      return new_writes, new_inds, new_cfms

    for pkt in acls:
      handle, cid, att_pdu = pkt
      if cid != ATT_CID or not att_pdu:
        continue
      opcode = att_pdu[0]

      # 1. Central Responses to outstanding requests
      if opcode in (
          ATT_OP_ERROR_RSP,
          ATT_OP_EXCHANGE_MTU_RSP,
          ATT_OP_FIND_INFO_RSP,
          ATT_OP_READ_BY_TYPE_RSP,
          ATT_OP_PREPARE_WRITE_RSP,
          ATT_OP_EXECUTE_WRITE_RSP,
          ATT_OP_READ_BLOB_RSP,
          ATT_OP_READ_RSP,
          ATT_OP_READ_BY_GROUP_TYPE_RSP,
          ATT_OP_WRITE_RSP,
      ):
        with self._att_cv:
          if self._acl_is_current(handle, pkt):
            self._pending_att_responses[handle] = att_pdu
            self._pending_att_response_gens[handle] = (
                self._active_conn_generations.get(handle, 0)
            )
            self._att_cv.notify_all()
        continue

      with self._att_cv:
        current = self._acl_is_current(handle, pkt)
        expected_gen = (
            pkt.generation
            if hasattr(pkt, 'generation')
            else self._h4_conn_generations.get(handle)
        )

      # 2. Central receiving peripheral Indication
      if opcode == ATT_OP_HANDLE_VALUE_IND and len(att_pdu) >= 3:
        val = att_pdu[3:]
        self.rx_indications.append(val)
        new_inds.append(val)
        self.att_indication_count += 1
        if current:
          self._send_acl_l2cap(
              handle,
              ATT_CID,
              struct.pack('<B', ATT_OP_HANDLE_VALUE_CFM),
              expected_generation=expected_gen,
          )
        continue

      if opcode == ATT_OP_HANDLE_VALUE_NTF and len(att_pdu) >= 3:
        val = att_pdu[3:]
        self.rx_indications.append(val)
        new_inds.append(val)
        continue

      # 3. Peripheral receiving central Confirmation
      if opcode == ATT_OP_HANDLE_VALUE_CFM:
        if current:
          new_cfms += 1
          self.att_confirmation_count += 1
        continue

      # 4. Peripheral receiving ATT Requests from Central
      if opcode in (
          ATT_OP_EXCHANGE_MTU_REQ,
          ATT_OP_READ_BY_GROUP_TYPE_REQ,
          ATT_OP_FIND_BY_TYPE_VALUE_REQ,
          ATT_OP_READ_BY_TYPE_REQ,
          ATT_OP_FIND_INFO_REQ,
          ATT_OP_READ_REQ,
          ATT_OP_WRITE_REQ,
          ATT_OP_WRITE_CMD,
          ATT_OP_READ_BLOB_REQ,
          ATT_OP_PREPARE_WRITE_REQ,
          ATT_OP_EXECUTE_WRITE_REQ,
      ):
        if not self.is_att_responder_active():
          continue
        if not current:
          if opcode in (
              ATT_OP_EXCHANGE_MTU_REQ,
              ATT_OP_PREPARE_WRITE_REQ,
              ATT_OP_EXECUTE_WRITE_REQ,
          ):
            continue
          if (
              opcode in (ATT_OP_WRITE_REQ, ATT_OP_WRITE_CMD)
              and len(att_pdu) >= 3
          ):
            attr_h = struct.unpack_from('<H', att_pdu, 1)[0]
            attr = self.att_server.database.attributes.get(attr_h)
            if attr is not None and attr.is_cccd:
              continue
          saved_mtu = self.att_server.effective_mtu
          saved_cccd = dict(self.att_server.cccd_states)
          # pylint: disable=protected-access
          saved_prep = list(self.att_server._prepare_write_queue)
          try:
            self.att_server.handle_request(handle, att_pdu)
          finally:
            self.att_server.effective_mtu = saved_mtu
            self.att_server.cccd_states = saved_cccd
            # pylint: disable=protected-access
            self.att_server._prepare_write_queue = saved_prep
          continue
        rsp = self.att_server.handle_request(handle, att_pdu)
        if rsp is not None:
          self._send_acl_l2cap(
              handle, ATT_CID, rsp, expected_generation=expected_gen
          )
        continue

    return new_writes, new_inds, new_cfms

  def _dispatch_bridge_callbacks(
      self,
      new_discoveries,
      new_writes: List[bytes],
      new_inds: List[bytes],
      new_cfms: int = 0,
      new_conns: Optional[List[Tuple[int, str]]] = None,
  ) -> None:
    """Invokes registered callbacks without swallowing unexpected failures."""
    if self.on_connection_callback is not None and new_conns:
      for conn_handle, peer_bd in new_conns:
        try:
          self.on_connection_callback(conn_handle, peer_bd)
        except Exception as exc:
          logger.warning('on_connection_callback error: %s', exc)
    if self.on_discovery_callback is not None:
      for addr, info in new_discoveries:
        try:
          self.on_discovery_callback(addr, info)
        except Exception as exc:
          logger.warning('on_discovery_callback error: %s', exc)
    if self.on_write_callback is not None:
      for val in new_writes:
        try:
          self.on_write_callback(val)
        except Exception as exc:
          logger.warning('on_write_callback error: %s', exc)
    if self.on_indication_callback is not None:
      for val in new_inds:
        try:
          self.on_indication_callback(val)
        except Exception as exc:
          logger.warning('on_indication_callback error: %s', exc)
    if self.on_indication_confirm_callback is not None:
      for _ in range(new_cfms):
        try:
          self.on_indication_confirm_callback()
        except Exception as exc:
          logger.warning('on_indication_confirm_callback error: %s', exc)

  def _sync_from_h4_client(self) -> None:
    if self.h4_client is None:
      return
    # Snapshots must be applied in the order taken; see _sync_lock.
    with self._sync_lock:
      with self.h4_client._cv:
        advs = list(self.h4_client._adv_reports)
        conns = dict(self.h4_client._connections)
        snapshot_seq = getattr(
            self.h4_client, '_conn_generation_seq', None
        )
        acls = list(self.h4_client._acl_packets)
        self.h4_client._acl_packets.clear()

      new_discoveries = []
      with self._lock:
        for rep in advs:
          addr = str(rep['bd_addr'])
          adv_data = bytes(rep['adv_data'])
          svc_data = self.profile.parse_service_data(adv_data)
          disc = (
              self.profile.discriminator_from_service_data(svc_data)
              if svc_data
              else None
          )
          if disc is None and addr in self.discovered_peripherals:
            disc = self.discovered_peripherals[addr].get('discriminator')
          if not svc_data and addr in self.discovered_peripherals:
            svc_data = self.discovered_peripherals[addr].get('service_data')
          is_new = addr not in self.discovered_peripherals
          info = {
              'bd_addr': addr,
              'rssi': rep.get('rssi', -45),
              'adv_data': adv_data,
              'service_data': svc_data,
              'discriminator': disc,
          }
          self.discovered_peripherals[addr] = info
          if is_new:
            new_discoveries.append((addr, info))
        stale_handles = [
            h
            for h in self.connected_handles
            if h not in conns
            and (
                snapshot_seq is None
                or (self._h4_conn_generations.get(h) or 0) <= snapshot_seq
            )
        ]
        for h in stale_handles:
          self.connected_handles.pop(h, None)
          self.discovered_gatt.pop(h, None)
        if (
            stale_handles
            and self.auto_readvertise_on_disconnect
            and self._custom_adv_params is not None
        ):
          self.start_custom_advertising(*self._custom_adv_params)
        new_conns = []
        for h, cinfo in conns.items():
          p_addr = str(cinfo['peer_bd_addr'])
          h4_gen = cinfo.get('generation')
          if self._set_connected_handle(h, p_addr, h4_gen=h4_gen):
            new_conns.append((h, p_addr))
        if stale_handles or new_conns:
          self.att_server.reset_connection_state()
        new_writes, new_inds, new_cfms = self._process_acl_att_packets(acls)

    self._dispatch_bridge_callbacks(
        new_discoveries, new_writes, new_inds, new_cfms, new_conns
    )

  def _poll_events_loop(self) -> None:
    while self._running:
      try:
        self._sync_from_h4_client()
      except Exception as exc:
        logger.debug('Poll events iteration notice: %s', exc)
      time.sleep(0.02)
