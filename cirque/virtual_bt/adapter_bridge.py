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
    self.connected_handles: Dict[int, str] = {}
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
    self._att_cv = threading.Condition()

    self._lock = threading.RLock()
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
      self._pending_att_responses.clear()
      self.att_server.reset_connection_state()
    if self.h4_client is not None:
      self.h4_client.reset()

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
    with self._lock:
      self.connected_handles[handle] = peer_bd_addr.upper()
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
      handles = (
          [conn_handle]
          if conn_handle is not None
          else list(self.connected_handles.keys())
      )
    att_pdu = struct.pack('<BH', ATT_OP_HANDLE_VALUE_NTF, val_h) + bytes(payload)
    sent = 0
    for h in handles:
      self.h4_client.send_acl_l2cap(h, ATT_CID, att_pdu)
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
    """Sends an ATT Request PDU and waits for the matching Response PDU."""
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

    def take_response() -> Optional[bytes]:
      # Caller holds self._att_cv. A response with an unexpected opcode is
      # consumed and dropped.
      rsp = self._pending_att_responses.pop(conn_handle, None)
      if rsp is not None and rsp[0] in expected_resp_opcodes:
        return rsp
      return None

    with self._att_cv:
      self._pending_att_responses.pop(conn_handle, None)
      self.h4_client.send_acl_l2cap(conn_handle, ATT_CID, req_pdu)

    # Lock order: self._lock may be held while acquiring self._att_cv (the
    # poll thread does so in _process_acl_att_packets), never the reverse.
    # So _sync_from_h4_client, which takes self._lock, runs only after
    # self._att_cv has been released.
    deadline = time.time() + timeout
    while True:
      with self._att_cv:
        rsp = take_response()
        if rsp is not None:
          return rsp
        rem = deadline - time.time()
        if rem <= 0:
          break
        self._att_cv.wait(timeout=min(rem, 0.05))
        rsp = take_response()
        if rsp is not None:
          return rsp
      self._sync_from_h4_client()
    raise TimeoutError(
        f'ATT request 0x{req_opcode:02X} on handle 0x{conn_handle:04X} timed out'
    )

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
    ind_info = self.att_server.database.find_characteristic_by_uuid(
        self.profile.indicate_char_uuid
    )
    if ind_info is None:
      raise RuntimeError(
          'Indicate characteristic not present in peripheral ATT database'
      )
    ind_val_h = ind_info[1]
    cccd_h = self.att_server.database.find_cccd_for_char(ind_val_h)
    if cccd_h is not None and not self.att_server.is_indication_enabled(cccd_h):
      self.att_server.cccd_states[cccd_h] = 0x0002
    if cccd_h is None or not self.att_server.is_indication_enabled(cccd_h):
      logger.warning(
          'Cannot send indication on handle 0x%04X: CCCD 0x%04X not enabled',
          ind_val_h,
          cccd_h or 0,
      )
      return
    self.att_indication_count += 1
    att_pdu = struct.pack('<BH', ATT_OP_HANDLE_VALUE_IND, ind_val_h) + payload
    self.h4_client.send_acl_l2cap(handle, ATT_CID, att_pdu)

  def _process_acl_att_packets(
      self, acls: List[Tuple[int, int, bytes]]
  ) -> Tuple[List[bytes], List[bytes], int]:
    """Dispatches incoming ATT packets for central and peripheral roles."""
    new_writes: List[bytes] = []
    new_inds: List[bytes] = []
    new_cfms: int = 0
    if self.h4_client is None:
      return new_writes, new_inds, new_cfms

    for handle, cid, att_pdu in acls:
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
          self._pending_att_responses[handle] = att_pdu
          self._att_cv.notify_all()
        continue

      # 2. Central receiving peripheral Indication
      if opcode == ATT_OP_HANDLE_VALUE_IND and len(att_pdu) >= 3:
        val = att_pdu[3:]
        self.rx_indications.append(val)
        new_inds.append(val)
        self.att_indication_count += 1
        self.h4_client.send_acl_l2cap(
            handle, ATT_CID, struct.pack('<B', ATT_OP_HANDLE_VALUE_CFM)
        )
        continue

      if opcode == ATT_OP_HANDLE_VALUE_NTF and len(att_pdu) >= 3:
        val = att_pdu[3:]
        self.rx_indications.append(val)
        new_inds.append(val)
        continue

      # 3. Peripheral receiving central Confirmation
      if opcode == ATT_OP_HANDLE_VALUE_CFM:
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
        rsp = self.att_server.handle_request(handle, att_pdu)
        if rsp is not None:
          self.h4_client.send_acl_l2cap(handle, ATT_CID, rsp)
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
    with self.h4_client._cv:
      advs = list(self.h4_client._adv_reports)
      conns = dict(self.h4_client._connections)
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
          h for h in self.connected_handles if h not in conns
      ]
      for h in stale_handles:
        self.connected_handles.pop(h, None)
        self.discovered_gatt.pop(h, None)
      if stale_handles and self.auto_readvertise_on_disconnect and self._custom_adv_params is not None:
        self.start_custom_advertising(*self._custom_adv_params)
      new_conns = []
      for h, cinfo in conns.items():
        p_addr = str(cinfo['peer_bd_addr'])
        if h not in self.connected_handles:
          new_conns.append((h, p_addr))
        self.connected_handles[h] = p_addr
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
