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
"""Bluetooth ATT Protocol Database, ATT Server, and PDU Encoders/Decoders.

Implements the Attribute Protocol (ATT) database, PDU serialization, and
GATT server request dispatch per Bluetooth Core Specification Vol 3, Part F.
"""

from dataclasses import dataclass, field
import logging
import struct
from typing import Callable, Dict, List, Optional, Tuple, Union
import uuid

logger = logging.getLogger('VirtualBtAtt')

# ATT Opcodes (Bluetooth Core Spec Vol 3, Part F, Section 3.4)
ATT_OP_ERROR_RSP = 0x01
ATT_OP_EXCHANGE_MTU_REQ = 0x02
ATT_OP_EXCHANGE_MTU_RSP = 0x03
ATT_OP_FIND_INFO_REQ = 0x04
ATT_OP_FIND_INFO_RSP = 0x05
ATT_OP_FIND_BY_TYPE_VALUE_REQ = 0x06
ATT_OP_FIND_BY_TYPE_VALUE_RSP = 0x07
ATT_OP_READ_BY_TYPE_REQ = 0x08
ATT_OP_READ_BY_TYPE_RSP = 0x09
ATT_OP_READ_REQ = 0x0A
ATT_OP_READ_RSP = 0x0B
ATT_OP_READ_BLOB_REQ = 0x0C
ATT_OP_READ_BLOB_RSP = 0x0D
ATT_OP_READ_BY_GROUP_TYPE_REQ = 0x10
ATT_OP_READ_BY_GROUP_TYPE_RSP = 0x11
ATT_OP_WRITE_REQ = 0x12
ATT_OP_WRITE_RSP = 0x13
ATT_OP_PREPARE_WRITE_REQ = 0x16
ATT_OP_PREPARE_WRITE_RSP = 0x17
ATT_OP_EXECUTE_WRITE_REQ = 0x18
ATT_OP_EXECUTE_WRITE_RSP = 0x19
ATT_OP_WRITE_CMD = 0x52
ATT_OP_HANDLE_VALUE_NTF = 0x1B
ATT_OP_HANDLE_VALUE_IND = 0x1D
ATT_OP_HANDLE_VALUE_CFM = 0x1E

# ATT Error Codes (Section 3.4.1.1)
ATT_ERR_INVALID_HANDLE = 0x01
ATT_ERR_READ_NOT_PERMITTED = 0x02
ATT_ERR_WRITE_NOT_PERMITTED = 0x03
ATT_ERR_INVALID_PDU = 0x04
ATT_ERR_INSUFFICIENT_AUTHEN = 0x05
ATT_ERR_REQ_NOT_SUPPORTED = 0x06
ATT_ERR_INVALID_OFFSET = 0x07
ATT_ERR_INSUFFICIENT_AUTHOR = 0x08
ATT_ERR_PREPARE_QUEUE_FULL = 0x09
ATT_ERR_ATTRIBUTE_NOT_FOUND = 0x0A
ATT_ERR_ATTRIBUTE_NOT_LONG = 0x0B
ATT_ERR_INSUFFICIENT_ENCR_KEY_SIZE = 0x0C
ATT_ERR_INVALID_ATTR_VALUE_LEN = 0x0D
ATT_ERR_UNLIKELY_ERROR = 0x0E
ATT_ERR_UNSUPPORTED_GROUP_TYPE = 0x10
ATT_ERR_INSUFFICIENT_RESOURCES = 0x11

# Standard GATT Attribute Type UUIDs (16-bit)
GATT_PRIMARY_SERVICE_UUID16 = 0x2800
GATT_SECONDARY_SERVICE_UUID16 = 0x2801
GATT_INCLUDE_UUID16 = 0x2802
GATT_CHARACTERISTIC_UUID16 = 0x2803
GATT_CLIENT_CHAR_CONFIG_UUID16 = 0x2902  # CCCD

# Characteristic Properties bitmask (Bluetooth Core Spec Vol 3, Part G, 3.3.1.1)
CHAR_PROP_BROADCAST = 0x01
CHAR_PROP_READ = 0x02
CHAR_PROP_WRITE_WITHOUT_RSP = 0x04
CHAR_PROP_WRITE = 0x08
CHAR_PROP_NOTIFY = 0x10
CHAR_PROP_INDICATE = 0x20
CHAR_PROP_AUTH_SIGNED_WRITES = 0x40
CHAR_PROP_EXTENDED_PROPS = 0x80

# CCCD Values
CCCD_DISABLED = 0x0000
CCCD_NOTIFY = 0x0001
CCCD_INDICATE = 0x0002

# Bluetooth Base UUID suffix for 16-bit UUID expansion
BLUETOOTH_BASE_UUID_SUFFIX = '-0000-1000-8000-00805f9b34fb'


def uuid_to_bytes(uuid_val: Union[int, str]) -> bytes:
  """Converts a 16-bit int or UUID string into little-endian wire bytes."""
  if isinstance(uuid_val, int):
    return struct.pack('<H', uuid_val & 0xFFFF)
  u_str = str(uuid_val).strip().lower()
  if len(u_str) <= 6 and '-' not in u_str:
    val = int(u_str, 16)
    return struct.pack('<H', val & 0xFFFF)
  if u_str.startswith('0000') and u_str.endswith(BLUETOOTH_BASE_UUID_SUFFIX):
    val = int(u_str[4:8], 16)
    return struct.pack('<H', val & 0xFFFF)
  parsed = uuid.UUID(u_str)
  return bytes(reversed(parsed.bytes))


def bytes_to_uuid_str(raw: bytes) -> str:
  """Converts little-endian wire bytes (2 or 16 octets) to canonical UUID str."""
  if len(raw) == 2:
    val = struct.unpack('<H', raw)[0]
    return f'0000{val:04x}{BLUETOOTH_BASE_UUID_SUFFIX}'
  if len(raw) == 16:
    return str(uuid.UUID(bytes=bytes(reversed(raw))))
  raise ValueError(f'Invalid UUID wire byte length: {len(raw)}')


def uuid_matches(u1: Union[int, str, bytes], u2: Union[int, str, bytes]) -> bool:
  """Compares two UUID representations for semantic equality."""
  b1 = uuid_to_bytes(u1) if not isinstance(u1, bytes) else u1
  b2 = uuid_to_bytes(u2) if not isinstance(u2, bytes) else u2
  if len(b1) == len(b2):
    return b1 == b2
  s1 = bytes_to_uuid_str(b1)
  s2 = bytes_to_uuid_str(b2)
  return s1 == s2


@dataclass
class AttAttribute:
  """Single attribute record in the ATT database."""

  handle: int
  type_uuid: bytes
  value: bytes
  end_group_handle: int = 0
  char_uuid_str: Optional[str] = None
  service_uuid_str: Optional[str] = None
  is_cccd: bool = False
  dbus_path: Optional[str] = None
  properties: int = 0
  on_read: Optional[Callable[[], bytes]] = None
  on_write: Optional[Callable[[bytes], None]] = None


class AttDatabase:
  """Dynamically constructed ATT attribute database with contiguous handles."""

  def __init__(self, start_handle: int = 1):
    self.start_handle = start_handle
    self.attributes: Dict[int, AttAttribute] = {}
    self._next_handle = start_handle

  def clear(self) -> None:
    self.attributes.clear()
    self._next_handle = self.start_handle

  def add_primary_service(
      self,
      service_uuid: Union[int, str],
      dbus_path: Optional[str] = None,
  ) -> int:
    """Allocates a Primary Service declaration attribute (UUID 0x2800)."""
    handle = self._next_handle
    self._next_handle += 1
    uuid_bytes = uuid_to_bytes(service_uuid)
    uuid_str = (
        service_uuid
        if isinstance(service_uuid, str)
        else bytes_to_uuid_str(uuid_bytes)
    )
    attr = AttAttribute(
        handle=handle,
        type_uuid=uuid_to_bytes(GATT_PRIMARY_SERVICE_UUID16),
        value=uuid_bytes,
        end_group_handle=handle,
        service_uuid_str=uuid_str,
        dbus_path=dbus_path,
    )
    self.attributes[handle] = attr
    return handle

  def add_characteristic(
      self,
      service_handle: int,
      char_uuid: Union[int, str],
      properties: int,
      initial_value: bytes = b'',
      dbus_path: Optional[str] = None,
      on_read: Optional[Callable[[], bytes]] = None,
      on_write: Optional[Callable[[bytes], None]] = None,
      with_cccd: bool = False,
  ) -> Tuple[int, int]:
    """Allocates Characteristic Declaration (0x2803) and Value attributes."""
    decl_handle = self._next_handle
    val_handle = decl_handle + 1
    self._next_handle += 2

    char_uuid_b = uuid_to_bytes(char_uuid)
    char_uuid_str = (
        char_uuid
        if isinstance(char_uuid, str)
        else bytes_to_uuid_str(char_uuid_b)
    )
    decl_value = struct.pack('<BH', properties, val_handle) + char_uuid_b

    decl_attr = AttAttribute(
        handle=decl_handle,
        type_uuid=uuid_to_bytes(GATT_CHARACTERISTIC_UUID16),
        value=decl_value,
        char_uuid_str=char_uuid_str,
        dbus_path=dbus_path,
        properties=properties,
    )
    val_attr = AttAttribute(
        handle=val_handle,
        type_uuid=char_uuid_b,
        value=initial_value,
        char_uuid_str=char_uuid_str,
        dbus_path=dbus_path,
        properties=properties,
        on_read=on_read,
        on_write=on_write,
    )
    self.attributes[decl_handle] = decl_attr
    self.attributes[val_handle] = val_attr

    # Extend service end_group_handle
    if service_handle in self.attributes:
      self.attributes[service_handle].end_group_handle = max(
          self.attributes[service_handle].end_group_handle, val_handle
      )
    if with_cccd:
      self.add_descriptor(
          service_handle,
          GATT_CLIENT_CHAR_CONFIG_UUID16,
          initial_value=b'\x00\x00',
          dbus_path=f'{dbus_path}/cccd' if dbus_path else None,
          is_cccd=True,
      )
    return decl_handle, val_handle

  def register_external_service(
      self,
      service_uuid: Union[int, str],
  ) -> int:
    """Finds an existing primary service by UUID or allocates a new one."""
    for handle, attr in self.attributes.items():
      if uuid_matches(attr.type_uuid, GATT_PRIMARY_SERVICE_UUID16):
        if uuid_matches(attr.value, service_uuid):
          return handle
    return self.add_primary_service(service_uuid)

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
    """Registers an external GATT characteristic with optional callbacks."""
    if (
        isinstance(service_uuid_or_handle, int)
        and service_uuid_or_handle in self.attributes
        and uuid_matches(
            self.attributes[service_uuid_or_handle].type_uuid,
            GATT_PRIMARY_SERVICE_UUID16,
        )
    ):
      service_handle = service_uuid_or_handle
    else:
      service_handle = self.register_external_service(service_uuid_or_handle)

    if isinstance(properties, (list, tuple)):
      prop_mask = flags_to_properties([str(p) for p in properties])
    else:
      prop_mask = int(properties)

    should_add_cccd = (
        bool(prop_mask & (CHAR_PROP_NOTIFY | CHAR_PROP_INDICATE))
        if with_cccd is None
        else bool(with_cccd)
    )
    return self.add_characteristic(
        service_handle=service_handle,
        char_uuid=char_uuid,
        properties=prop_mask,
        initial_value=initial_value,
        on_read=on_read,
        on_write=on_write,
        with_cccd=should_add_cccd,
    )

  def add_descriptor(
      self,
      service_handle: int,
      desc_uuid: Union[int, str],
      initial_value: bytes = b'\x00\x00',
      dbus_path: Optional[str] = None,
      is_cccd: bool = False,
  ) -> int:
    """Allocates a Descriptor attribute (e.g. CCCD 0x2902)."""
    desc_handle = self._next_handle
    self._next_handle += 1
    desc_uuid_b = uuid_to_bytes(desc_uuid)
    if is_cccd or uuid_matches(desc_uuid, GATT_CLIENT_CHAR_CONFIG_UUID16):
      is_cccd = True
    attr = AttAttribute(
        handle=desc_handle,
        type_uuid=desc_uuid_b,
        value=initial_value,
        is_cccd=is_cccd,
        dbus_path=dbus_path,
    )
    self.attributes[desc_handle] = attr
    if service_handle in self.attributes:
      self.attributes[service_handle].end_group_handle = max(
          self.attributes[service_handle].end_group_handle, desc_handle
      )
    return desc_handle

  def find_characteristic_by_uuid(
      self, char_uuid: Union[int, str]
  ) -> Optional[Tuple[int, int]]:
    """Returns (decl_handle, val_handle) for a characteristic UUID."""
    for handle, attr in self.attributes.items():
      if attr.type_uuid != uuid_to_bytes(GATT_CHARACTERISTIC_UUID16):
        continue
      if len(attr.value) < 3:
        continue
      val_h = struct.unpack('<H', attr.value[1:3])[0]
      c_uuid_raw = attr.value[3:]
      if uuid_matches(c_uuid_raw, char_uuid):
        return handle, val_h
    return None

  def find_cccd_for_char(self, val_handle: int) -> Optional[int]:
    """Finds the CCCD descriptor handle associated with val_handle."""
    # Look at subsequent descriptor attributes before the next char declaration
    char_decl_uuid = uuid_to_bytes(GATT_CHARACTERISTIC_UUID16)
    svc_decl_uuid = uuid_to_bytes(GATT_PRIMARY_SERVICE_UUID16)
    for h in sorted(self.attributes.keys()):
      if h <= val_handle:
        continue
      attr = self.attributes[h]
      if attr.type_uuid in (char_decl_uuid, svc_decl_uuid):
        break
      if attr.is_cccd or uuid_matches(attr.type_uuid, GATT_CLIENT_CHAR_CONFIG_UUID16):
        return h
    return None


class AttServer:
  """ATT Protocol Server handling incoming requests against an AttDatabase."""

  def __init__(self, database: Optional[AttDatabase] = None, mtu: int = 517):
    self.database = database or AttDatabase()
    self.mtu = mtu
    self.effective_mtu = 23
    self.cccd_states: Dict[int, int] = {}
    self._prepare_write_queue: List[Tuple[int, int, bytes]] = []
    self.on_write_callback: Optional[Callable[[int, bytes], None]] = None
    self.on_cccd_callback: Optional[Callable[[int, int], None]] = None

  def reset_connection_state(self) -> None:
    """Resets per-connection ATT state (default MTU 23 and CCCD flags)."""
    self.effective_mtu = 23
    self.cccd_states.clear()
    self._prepare_write_queue.clear()

  def set_database(self, database: AttDatabase) -> None:
    self.database = database
    self.reset_connection_state()

  def is_indication_enabled(self, cccd_handle: int) -> bool:
    """Returns True if CCCD at cccd_handle has indications (0x0002) enabled."""
    return bool(self.cccd_states.get(cccd_handle, 0) & CCCD_INDICATE)

  def is_notification_enabled(self, cccd_handle: int) -> bool:
    """Returns True if CCCD at cccd_handle has notifications (0x0001) enabled."""
    return bool(self.cccd_states.get(cccd_handle, 0) & CCCD_NOTIFY)

  def handle_request(
      self, conn_handle: int, att_pdu: bytes
  ) -> Optional[bytes]:
    """Dispatches an incoming ATT PDU and returns the response PDU or None."""
    del conn_handle
    if not att_pdu:
      return None
    opcode = att_pdu[0]
    payload = att_pdu[1:]

    if opcode == ATT_OP_EXCHANGE_MTU_REQ:
      return self._handle_exchange_mtu(payload)
    if opcode == ATT_OP_READ_BY_GROUP_TYPE_REQ:
      return self._handle_read_by_group_type(payload)
    if opcode == ATT_OP_FIND_BY_TYPE_VALUE_REQ:
      return self._handle_find_by_type_value(payload)
    if opcode == ATT_OP_READ_BY_TYPE_REQ:
      return self._handle_read_by_type(payload)
    if opcode == ATT_OP_FIND_INFO_REQ:
      return self._handle_find_info(payload)
    if opcode == ATT_OP_READ_REQ:
      return self._handle_read(payload)
    if opcode == ATT_OP_READ_BLOB_REQ:
      return self._handle_read_blob(payload)
    if opcode == ATT_OP_WRITE_REQ:
      return self._handle_write(payload, need_response=True)
    if opcode == ATT_OP_WRITE_CMD:
      self._handle_write(payload, need_response=False)
      return None
    if opcode == ATT_OP_PREPARE_WRITE_REQ:
      return self._handle_prepare_write(payload)
    if opcode == ATT_OP_EXECUTE_WRITE_REQ:
      return self._handle_execute_write(payload)
    # Unknown or unsupported opcode
    return struct.pack(
        '<BBHB', ATT_OP_ERROR_RSP, opcode, 0x0000, ATT_ERR_REQ_NOT_SUPPORTED
    )

  def handle_pdu(
      self, att_pdu: bytes, conn_handle: int = 0
  ) -> Optional[bytes]:
    """Convenience alias for handle_request."""
    return self.handle_request(conn_handle, att_pdu)

  def _handle_exchange_mtu(self, payload: bytes) -> bytes:
    if len(payload) < 2:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_EXCHANGE_MTU_REQ,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )
    client_mtu = struct.unpack('<H', payload[:2])[0]
    self.effective_mtu = max(23, min(client_mtu, self.mtu))
    return struct.pack('<BH', ATT_OP_EXCHANGE_MTU_RSP, self.mtu)

  def _handle_read_by_group_type(self, payload: bytes) -> bytes:
    if len(payload) < 6:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_BY_GROUP_TYPE_REQ,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )
    start_h, end_h = struct.unpack_from('<HH', payload, 0)
    group_type_raw = payload[4:]
    if start_h == 0 or start_h > end_h:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_BY_GROUP_TYPE_REQ,
          start_h,
          ATT_ERR_INVALID_HANDLE,
      )
    if not uuid_matches(group_type_raw, GATT_PRIMARY_SERVICE_UUID16):
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_BY_GROUP_TYPE_REQ,
          start_h,
          ATT_ERR_UNSUPPORTED_GROUP_TYPE,
      )
    matches = []
    for h in sorted(self.database.attributes.keys()):
      if h < start_h:
        continue
      if h > end_h:
        break
      attr = self.database.attributes[h]
      if uuid_matches(attr.type_uuid, GATT_PRIMARY_SERVICE_UUID16):
        matches.append(attr)

    if not matches:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_BY_GROUP_TYPE_REQ,
          start_h,
          ATT_ERR_ATTRIBUTE_NOT_FOUND,
      )
    elem_len = 4 + len(matches[0].value)
    packed_items = bytearray()
    max_payload = self.effective_mtu - 2  # Opcode (1) + Length (1)
    for m in matches:
      if 4 + len(m.value) != elem_len:
        break
      if len(packed_items) + elem_len > max_payload:
        break
      packed_items.extend(struct.pack('<HH', m.handle, m.end_group_handle))
      packed_items.extend(m.value)

    return (
        struct.pack('<BB', ATT_OP_READ_BY_GROUP_TYPE_RSP, elem_len)
        + bytes(packed_items)
    )

  def _handle_find_by_type_value(self, payload: bytes) -> bytes:
    if len(payload) < 6:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_FIND_BY_TYPE_VALUE_REQ,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )
    start_h, end_h, attr_type = struct.unpack_from('<HHH', payload, 0)
    expected_val = payload[6:]
    if start_h == 0 or start_h > end_h:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_FIND_BY_TYPE_VALUE_REQ,
          start_h,
          ATT_ERR_INVALID_HANDLE,
      )
    type_bytes = struct.pack('<H', attr_type)
    matches = []
    for h in sorted(self.database.attributes.keys()):
      if h < start_h:
        continue
      if h > end_h:
        break
      attr = self.database.attributes[h]
      if uuid_matches(attr.type_uuid, type_bytes) and uuid_matches(
          attr.value, expected_val
      ):
        matches.append(attr)

    if not matches:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_FIND_BY_TYPE_VALUE_REQ,
          start_h,
          ATT_ERR_ATTRIBUTE_NOT_FOUND,
      )
    packed_items = bytearray()
    max_payload = self.effective_mtu - 1  # Opcode (1)
    for m in matches:
      if len(packed_items) + 4 > max_payload:
        break
      packed_items.extend(struct.pack('<HH', m.handle, m.end_group_handle))

    return struct.pack('<B', ATT_OP_FIND_BY_TYPE_VALUE_RSP) + bytes(packed_items)

  def _handle_read_by_type(self, payload: bytes) -> bytes:
    if len(payload) < 6:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_BY_TYPE_REQ,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )
    start_h, end_h = struct.unpack_from('<HH', payload, 0)
    type_raw = payload[4:]
    if start_h == 0 or start_h > end_h:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_BY_TYPE_REQ,
          start_h,
          ATT_ERR_INVALID_HANDLE,
      )
    is_char_decl = uuid_matches(type_raw, GATT_CHARACTERISTIC_UUID16)
    matches = []
    for h in sorted(self.database.attributes.keys()):
      if h < start_h:
        continue
      if h > end_h:
        break
      attr = self.database.attributes[h]
      if uuid_matches(attr.type_uuid, type_raw):
        if not is_char_decl and attr.on_read is not None:
          try:
            attr.value = bytes(attr.on_read())
          except Exception as exc:
            logger.warning(
                'ATT on_read callback exception on handle 0x%04x: %s',
                attr.handle,
                exc,
            )
        matches.append(attr)

    if not matches:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_BY_TYPE_REQ,
          start_h,
          ATT_ERR_ATTRIBUTE_NOT_FOUND,
      )
    max_val_len = min(253, max(1, self.effective_mtu - 4))
    first_val = matches[0].value[:max_val_len]
    elem_len = 2 + len(first_val)
    packed_items = bytearray()
    max_payload = self.effective_mtu - 2
    for m in matches:
      m_val = m.value[:max_val_len]
      if 2 + len(m_val) != elem_len:
        break
      if len(packed_items) + elem_len > max_payload:
        break
      packed_items.extend(struct.pack('<H', m.handle))
      packed_items.extend(m_val)

    return (
        struct.pack('<BB', ATT_OP_READ_BY_TYPE_RSP, elem_len)
        + bytes(packed_items)
    )

  def _handle_find_info(self, payload: bytes) -> bytes:
    if len(payload) < 4:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_FIND_INFO_REQ,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )
    start_h, end_h = struct.unpack_from('<HH', payload, 0)
    if start_h == 0 or start_h > end_h:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_FIND_INFO_REQ,
          start_h,
          ATT_ERR_INVALID_HANDLE,
      )
    matches = []
    for h in sorted(self.database.attributes.keys()):
      if h < start_h:
        continue
      if h > end_h:
        break
      matches.append(self.database.attributes[h])

    if not matches:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_FIND_INFO_REQ,
          start_h,
          ATT_ERR_ATTRIBUTE_NOT_FOUND,
      )
    first_len = len(matches[0].type_uuid)
    fmt = 0x01 if first_len == 2 else 0x02
    elem_len = 2 + first_len
    max_payload = self.effective_mtu - 2
    packed_items = bytearray()
    for m in matches:
      if len(m.type_uuid) != first_len:
        break
      if len(packed_items) + elem_len > max_payload:
        break
      packed_items.extend(struct.pack('<H', m.handle))
      packed_items.extend(m.type_uuid)

    return struct.pack('<BB', ATT_OP_FIND_INFO_RSP, fmt) + bytes(packed_items)

  def _handle_read(self, payload: bytes) -> bytes:
    if len(payload) < 2:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_REQ,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )
    handle = struct.unpack('<H', payload[:2])[0]
    if handle not in self.database.attributes:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_REQ,
          handle,
          ATT_ERR_INVALID_HANDLE,
      )
    attr = self.database.attributes[handle]
    if attr.on_read is not None:
      try:
        attr.value = bytes(attr.on_read())
      except Exception as exc:
        logger.warning(
            'ATT on_read callback exception on handle 0x%04x: %s', handle, exc
        )
    val = attr.value
    max_len = self.effective_mtu - 1
    return struct.pack('<B', ATT_OP_READ_RSP) + val[:max_len]

  def _handle_read_blob(self, payload: bytes) -> bytes:
    if len(payload) < 4:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_BLOB_REQ,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )
    handle, offset = struct.unpack_from('<HH', payload, 0)
    if handle not in self.database.attributes:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_BLOB_REQ,
          handle,
          ATT_ERR_INVALID_HANDLE,
      )
    attr = self.database.attributes[handle]
    if offset == 0 and attr.on_read is not None:
      try:
        attr.value = bytes(attr.on_read())
      except Exception as exc:
        logger.warning(
            'ATT on_read callback exception on handle 0x%04x: %s', handle, exc
        )
    val = attr.value
    if offset > len(val):
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_READ_BLOB_REQ,
          handle,
          ATT_ERR_INVALID_OFFSET,
      )
    max_len = self.effective_mtu - 1
    return (
        struct.pack('<B', ATT_OP_READ_BLOB_RSP)
        + val[offset : offset + max_len]
    )

  def _handle_write(self, payload: bytes, need_response: bool) -> Optional[bytes]:
    req_opcode = ATT_OP_WRITE_REQ if need_response else ATT_OP_WRITE_CMD
    if len(payload) < 2:
      if not need_response:
        return None
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          req_opcode,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )
    handle = struct.unpack_from('<H', payload, 0)[0]
    data = payload[2:]
    if handle not in self.database.attributes:
      if not need_response:
        return None
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          req_opcode,
          handle,
          ATT_ERR_INVALID_HANDLE,
      )
    attr = self.database.attributes[handle]
    if attr.is_cccd:
      if len(data) != 2:
        if not need_response:
          return None
        return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          req_opcode,
          handle,
          ATT_ERR_INVALID_ATTR_VALUE_LEN,
        )
      cccd_val = struct.unpack('<H', data)[0]
      attr.value = data
      self.cccd_states[handle] = cccd_val
      if self.on_cccd_callback is not None:
        try:
          self.on_cccd_callback(handle, cccd_val)
        except Exception as exc:
          logger.warning('CCCD callback exception: %s', exc)
      if need_response:
        return struct.pack('<B', ATT_OP_WRITE_RSP)
      return None

    attr.value = data
    if attr.on_write is not None:
      try:
        attr.on_write(data)
      except Exception as exc:
        logger.warning(
            'ATT attr.on_write callback exception on handle 0x%04x: %s',
            handle,
            exc,
        )
    if self.on_write_callback is not None:
      try:
        self.on_write_callback(handle, data)
      except Exception as exc:
        logger.warning('ATT write callback exception: %s', exc)
    if need_response:
      return struct.pack('<B', ATT_OP_WRITE_RSP)
    return None

  def _handle_prepare_write(self, payload: bytes) -> bytes:
    if len(payload) < 4:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_PREPARE_WRITE_REQ,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )
    handle, offset = struct.unpack_from('<HH', payload, 0)
    chunk = payload[4:]
    if handle not in self.database.attributes:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_PREPARE_WRITE_REQ,
          handle,
          ATT_ERR_INVALID_HANDLE,
      )
    self._prepare_write_queue.append((handle, offset, chunk))
    return struct.pack('<B', ATT_OP_PREPARE_WRITE_RSP) + payload

  def _handle_execute_write(self, payload: bytes) -> bytes:
    if len(payload) < 1:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_EXECUTE_WRITE_REQ,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )
    flags = payload[0]
    queued = list(self._prepare_write_queue)
    self._prepare_write_queue.clear()
    if flags == 0x00:
      return struct.pack('<B', ATT_OP_EXECUTE_WRITE_RSP)
    if flags != 0x01:
      return struct.pack(
          '<BBHB',
          ATT_OP_ERROR_RSP,
          ATT_OP_EXECUTE_WRITE_REQ,
          0x0000,
          ATT_ERR_INVALID_PDU,
      )

    staged: Dict[int, bytearray] = {}
    ordered_handles: List[int] = []
    for handle, offset, chunk in queued:
      if handle not in self.database.attributes:
        return struct.pack(
            '<BBHB',
            ATT_OP_ERROR_RSP,
            ATT_OP_EXECUTE_WRITE_REQ,
            handle,
            ATT_ERR_INVALID_HANDLE,
        )
      if handle not in staged:
        ordered_handles.append(handle)
        if offset == 0:
          staged[handle] = bytearray()
        else:
          staged[handle] = bytearray(self.database.attributes[handle].value)
      buf = staged[handle]
      if offset > len(buf):
        return struct.pack(
            '<BBHB',
            ATT_OP_ERROR_RSP,
            ATT_OP_EXECUTE_WRITE_REQ,
            handle,
            ATT_ERR_INVALID_OFFSET,
        )
      buf[offset : offset + len(chunk)] = chunk

    for handle in ordered_handles:
      attr = self.database.attributes[handle]
      data = bytes(staged[handle])
      attr.value = data
      if attr.on_write is not None:
        try:
          attr.on_write(data)
        except Exception as exc:
          logger.warning(
              'ATT attr.on_write callback exception on handle 0x%04x: %s',
              handle,
              exc,
          )
      if self.on_write_callback is not None:
        try:
          self.on_write_callback(handle, data)
        except Exception as exc:
          logger.warning('ATT write callback exception: %s', exc)
    return struct.pack('<B', ATT_OP_EXECUTE_WRITE_RSP)


def flags_to_properties(flags: List[str]) -> int:
  """Converts BlueZ GATT string flags to Bluetooth characteristic bitmask."""
  props = 0
  for f in flags:
    f_low = str(f).lower()
    if 'broadcast' in f_low:
      props |= CHAR_PROP_BROADCAST
    if 'read' in f_low:
      props |= CHAR_PROP_READ
    if 'write-without-response' in f_low:
      props |= CHAR_PROP_WRITE_WITHOUT_RSP
    elif 'write' in f_low:
      props |= CHAR_PROP_WRITE
    if 'notify' in f_low:
      props |= CHAR_PROP_NOTIFY
    if 'indicate' in f_low:
      props |= CHAR_PROP_INDICATE
    if 'authenticated-signed-writes' in f_low:
      props |= CHAR_PROP_AUTH_SIGNED_WRITES
    if 'extended-properties' in f_low:
      props |= CHAR_PROP_EXTENDED_PROPS
  return props


def build_att_database_from_gatt_objects(
    objects: Dict[str, Dict[str, Dict[str, object]]],
    start_handle: int = 1,
) -> AttDatabase:
  """Builds an AttDatabase from registered D-Bus GATT objects."""
  db = AttDatabase(start_handle=start_handle)
  services = []
  characteristics = []
  descriptors = []

  for path, ifaces in objects.items():
    if 'org.bluez.GattService1' in ifaces:
      services.append((path, ifaces['org.bluez.GattService1']))
    if 'org.bluez.GattCharacteristic1' in ifaces:
      characteristics.append((path, ifaces['org.bluez.GattCharacteristic1']))
    if 'org.bluez.GattDescriptor1' in ifaces:
      descriptors.append((path, ifaces['org.bluez.GattDescriptor1']))

  if not services:
    raise ValueError('No GattService1 objects found in registered application')

  for svc_path, svc_props in services:
    raw_u = svc_props.get('UUID')
    if not raw_u:
      raise ValueError(
          f'GattService1 at {svc_path} is missing required UUID property'
      )
    uuid_str = (
        raw_u.unpack() if hasattr(raw_u, 'unpack') else str(raw_u)
    )
    svc_h = db.add_primary_service(uuid_str, dbus_path=svc_path)

    chars_for_svc = []
    for c_path, c_props in characteristics:
      svc_prop = c_props.get('Service')
      svc_ref = (
          svc_prop.unpack() if hasattr(svc_prop, 'unpack') else svc_prop
      )
      if svc_ref == svc_path or c_path.startswith(svc_path + '/'):
        chars_for_svc.append((c_path, c_props))

    for c_path, c_props in chars_for_svc:
      raw_cu = c_props.get('UUID')
      if not raw_cu:
        raise ValueError(
            f'GattCharacteristic1 at {c_path} is missing required UUID'
            ' property'
        )
      c_uuid = raw_cu.unpack() if hasattr(raw_cu, 'unpack') else str(raw_cu)
      raw_flags = c_props.get('Flags')
      if not raw_flags:
        raise ValueError(
            f'GattCharacteristic1 at {c_path} is missing required Flags'
            ' property'
        )
      if hasattr(raw_flags, 'unpack'):
        raw_flags = raw_flags.unpack()
      if not isinstance(raw_flags, (list, tuple)) or not raw_flags:
        raise ValueError(
            f'GattCharacteristic1 at {c_path} has invalid Flags: {raw_flags!r}'
        )
      flags = [str(f) for f in raw_flags]
      props = flags_to_properties(flags)
      raw_val = c_props.get('Value', b'')
      if hasattr(raw_val, 'unpack'):
        raw_val = raw_val.unpack()
      init_val = (
          bytes(raw_val)
          if isinstance(raw_val, (bytes, bytearray, list))
          else b''
      )
      _, val_h = db.add_characteristic(
          svc_h,
          c_uuid,
          properties=props,
          initial_value=init_val,
          dbus_path=c_path,
      )

      descs_for_char = []
      for d_path, d_props in descriptors:
        char_prop = d_props.get('Characteristic')
        char_ref = (
            char_prop.unpack()
            if hasattr(char_prop, 'unpack')
            else char_prop
        )
        if char_ref == c_path or d_path.startswith(c_path + '/'):
          descs_for_char.append((d_path, d_props))

      has_cccd = False
      for d_path, d_props in descs_for_char:
        raw_du = d_props.get('UUID')
        if not raw_du:
          raise ValueError(
              f'GattDescriptor1 at {d_path} is missing required UUID'
              ' property'
          )
        d_uuid = raw_du.unpack() if hasattr(raw_du, 'unpack') else str(raw_du)
        raw_dv = d_props.get('Value', b'\x00\x00')
        if hasattr(raw_dv, 'unpack'):
          raw_dv = raw_dv.unpack()
        d_val = (
            bytes(raw_dv)
            if isinstance(raw_dv, (bytes, bytearray, list))
            else b'\x00\x00'
        )
        is_cccd = uuid_matches(d_uuid, GATT_CLIENT_CHAR_CONFIG_UUID16)
        if is_cccd:
          has_cccd = True
        db.add_descriptor(
            svc_h,
            d_uuid,
            initial_value=d_val,
            dbus_path=d_path,
            is_cccd=is_cccd,
        )

      if (props & (CHAR_PROP_NOTIFY | CHAR_PROP_INDICATE)) and not has_cccd:
        db.add_descriptor(
            svc_h,
            GATT_CLIENT_CHAR_CONFIG_UUID16,
            initial_value=b'\x00\x00',
            is_cccd=True,
            dbus_path=f'{c_path}/cccd',
        )

  return db


def encode_exchange_mtu_req(client_mtu: int) -> bytes:
  """Encodes an ATT Exchange MTU Request PDU (0x02)."""
  return struct.pack('<BH', ATT_OP_EXCHANGE_MTU_REQ, client_mtu)


def encode_read_by_group_type_req(
    start_handle: int, end_handle: int, group_type_uuid: Union[int, str]
) -> bytes:
  """Encodes an ATT Read By Group Type Request PDU (0x10)."""
  return (
      struct.pack(
          '<BHH', ATT_OP_READ_BY_GROUP_TYPE_REQ, start_handle, end_handle
      )
      + uuid_to_bytes(group_type_uuid)
  )


def encode_read_by_type_req(
    start_handle: int, end_handle: int, type_uuid: Union[int, str]
) -> bytes:
  """Encodes an ATT Read By Type Request PDU (0x08)."""
  return (
      struct.pack('<BHH', ATT_OP_READ_BY_TYPE_REQ, start_handle, end_handle)
      + uuid_to_bytes(type_uuid)
  )


def encode_find_info_req(start_handle: int, end_handle: int) -> bytes:
  """Encodes an ATT Find Information Request PDU (0x04)."""
  return struct.pack('<BHH', ATT_OP_FIND_INFO_REQ, start_handle, end_handle)


def encode_find_by_type_value_req(
    start_handle: int,
    end_handle: int,
    attr_type_uuid: Union[int, str],
    attr_value: Union[int, str, bytes],
) -> bytes:
  """Encodes an ATT Find By Type Value Request PDU (0x06)."""
  val_bytes = (
      attr_value
      if isinstance(attr_value, bytes)
      else uuid_to_bytes(attr_value)
  )
  type_int = (
      attr_type_uuid
      if isinstance(attr_type_uuid, int)
      else struct.unpack('<H', uuid_to_bytes(attr_type_uuid)[:2])[0]
  )
  return (
      struct.pack(
          '<BHHH',
          ATT_OP_FIND_BY_TYPE_VALUE_REQ,
          start_handle,
          end_handle,
          type_int & 0xFFFF,
      )
      + val_bytes
  )


def encode_read_req(handle: int) -> bytes:
  """Encodes an ATT Read Request PDU (0x0A)."""
  return struct.pack('<BH', ATT_OP_READ_REQ, handle)


def encode_read_blob_req(handle: int, offset: int) -> bytes:
  """Encodes an ATT Read Blob Request PDU (0x0C)."""
  return struct.pack('<BHH', ATT_OP_READ_BLOB_REQ, handle, offset)


def encode_write_req(handle: int, value: bytes) -> bytes:
  """Encodes an ATT Write Request PDU (0x12)."""
  return struct.pack('<BH', ATT_OP_WRITE_REQ, handle) + value


def encode_write_cmd(handle: int, value: bytes) -> bytes:
  """Encodes an ATT Write Command PDU (0x52)."""
  return struct.pack('<BH', ATT_OP_WRITE_CMD, handle) + value


def encode_prepare_write_req(handle: int, offset: int, value: bytes) -> bytes:
  """Encodes an ATT Prepare Write Request PDU (0x16)."""
  return struct.pack('<BHH', ATT_OP_PREPARE_WRITE_REQ, handle, offset) + value


def encode_execute_write_req(flags: int = 0x01) -> bytes:
  """Encodes an ATT Execute Write Request PDU (0x18)."""
  return struct.pack('<BB', ATT_OP_EXECUTE_WRITE_REQ, flags & 0xFF)


def decode_error_rsp(pdu: bytes) -> Tuple[int, int, int]:
  """Decodes an ATT Error Response PDU (0x01).

  Returns: (request_opcode_in_error, handle_in_error, error_code)
  """
  if len(pdu) < 5 or pdu[0] != ATT_OP_ERROR_RSP:
    raise ValueError(f'Invalid ATT Error Response PDU: {pdu!r}')
  req_opcode, handle, err_code = struct.unpack_from('<BHB', pdu, 1)
  return req_opcode, handle, err_code


def decode_read_by_group_type_rsp(
    pdu: bytes,
) -> List[Tuple[int, int, bytes]]:
  """Decodes an ATT Read By Group Type Response PDU (0x11).

  Returns: list of (start_handle, end_group_handle, value_bytes)
  """
  if len(pdu) < 2 or pdu[0] != ATT_OP_READ_BY_GROUP_TYPE_RSP:
    raise ValueError(f'Invalid ATT Read By Group Type Response: {pdu!r}')
  elem_len = pdu[1]
  items = []
  raw = pdu[2:]
  for offset in range(0, len(raw), elem_len):
    chunk = raw[offset : offset + elem_len]
    if len(chunk) < elem_len:
      break
    s_h, e_h = struct.unpack_from('<HH', chunk, 0)
    items.append((s_h, e_h, chunk[4:]))
  return items


def decode_find_by_type_value_rsp(
    pdu: bytes,
) -> List[Tuple[int, int]]:
  """Decodes an ATT Find By Type Value Response PDU (0x07).

  Returns: list of (found_attribute_handle, group_end_handle)
  """
  if len(pdu) < 5 or pdu[0] != ATT_OP_FIND_BY_TYPE_VALUE_RSP:
    raise ValueError(f'Invalid ATT Find By Type Value Response: {pdu!r}')
  items = []
  raw = pdu[1:]
  for offset in range(0, len(raw), 4):
    chunk = raw[offset : offset + 4]
    if len(chunk) < 4:
      break
    found_h, group_end_h = struct.unpack_from('<HH', chunk, 0)
    items.append((found_h, group_end_h))
  return items


def decode_read_by_type_rsp(
    pdu: bytes,
) -> List[Tuple[int, int, int, bytes]]:
  """Decodes an ATT Read By Type Response PDU (0x09) for characteristics.

  Returns: list of (declaration_handle, properties, value_handle, uuid_bytes)
  """
  if len(pdu) < 2 or pdu[0] != ATT_OP_READ_BY_TYPE_RSP:
    raise ValueError(f'Invalid ATT Read By Type Response: {pdu!r}')
  elem_len = pdu[1]
  items = []
  raw = pdu[2:]
  for offset in range(0, len(raw), elem_len):
    chunk = raw[offset : offset + elem_len]
    if len(chunk) < elem_len:
      break
    decl_h = struct.unpack_from('<H', chunk, 0)[0]
    props = chunk[2]
    val_h = struct.unpack_from('<H', chunk, 3)[0]
    char_uuid_b = chunk[5:]
    items.append((decl_h, props, val_h, char_uuid_b))
  return items


def decode_find_info_rsp(pdu: bytes) -> List[Tuple[int, bytes]]:
  """Decodes an ATT Find Information Response PDU (0x05).

  Returns: list of (handle, uuid_bytes)
  """
  if len(pdu) < 2 or pdu[0] != ATT_OP_FIND_INFO_RSP:
    raise ValueError(f'Invalid ATT Find Info Response: {pdu!r}')
  fmt = pdu[1]
  unit_len = 4 if fmt == 0x01 else 18
  items = []
  raw = pdu[2:]
  for offset in range(0, len(raw), unit_len):
    chunk = raw[offset : offset + unit_len]
    if len(chunk) < unit_len:
      break
    h = struct.unpack_from('<H', chunk, 0)[0]
    u = chunk[2:]
    items.append((h, u))
  return items

