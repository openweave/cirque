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
"""Bluetooth H4 UART Transport Framing, HCI Command/Event Engine, and L2CAP/ATT/BTP."""

from dataclasses import dataclass, field
from enum import IntEnum
import os
import struct
from typing import Callable, Dict, List, Optional, Tuple


class H4PacketType(IntEnum):
  """Standard Bluetooth H4 UART Transport packet indicators (Vol 4, Part A)."""

  COMMAND = 0x01
  ACL_DATA = 0x02
  SCO_DATA = 0x03
  EVENT = 0x04
  ISO_DATA = 0x05


class HciOpcode(IntEnum):
  """Standard Bluetooth HCI Command Opcodes (OGF << 10 | OCF)."""

  # Link Control Commands (OGF = 0x01)
  DISCONNECT = 0x0406
  READ_REMOTE_VERSION_INFO = 0x041D

  # Link Policy Commands (OGF = 0x02)
  WRITE_DEFAULT_LINK_POLICY_SETTINGS = 0x080F

  # Controller & Baseband Commands (OGF = 0x03)
  SET_EVENT_MASK = 0x0C01
  RESET = 0x0C03
  READ_STORED_LINK_KEY = 0x0C0D
  DELETE_STORED_LINK_KEY = 0x0C12
  WRITE_LOCAL_NAME = 0x0C13
  READ_LOCAL_NAME = 0x0C14
  WRITE_PAGE_TIMEOUT = 0x0C18
  READ_SCAN_ENABLE = 0x0C19
  WRITE_SCAN_ENABLE = 0x0C1A
  READ_PAGE_SCAN_ACTIVITY = 0x0C1B
  WRITE_PAGE_SCAN_ACTIVITY = 0x0C1C
  WRITE_INQUIRY_SCAN_ACTIVITY = 0x0C1E
  READ_CLASS_OF_DEV = 0x0C23
  WRITE_CLASS_OF_DEV = 0x0C24
  READ_VOICE_SETTING = 0x0C25
  WRITE_VOICE_SETTING = 0x0C26
  READ_NUM_SUPPORTED_IAC = 0x0C38
  READ_PAGE_SCAN_TYPE = 0x0C46
  WRITE_SIMPLE_PAIRING_MODE = 0x0C56
  READ_INQ_RSP_TX_POWER = 0x0C58
  READ_DEF_ERR_DATA_REPORTING = 0x0C5A
  WRITE_DEF_ERR_DATA_REPORTING = 0x0C5B
  SET_EVENT_MASK_PAGE_2 = 0x0C63
  READ_FLOW_CONTROL_MODE = 0x0C66
  READ_LE_HOST_SUPPORT = 0x0C6C
  WRITE_LE_HOST_SUPPORT = 0x0C6D
  READ_AUTH_PAYLOAD_TO = 0x0C7B
  SET_MIN_ENCRYPTION_KEY_SIZE = 0x0C84

  # Informational Parameters (OGF = 0x04)
  READ_LOCAL_VERSION_INFO = 0x1001
  READ_LOCAL_SUPPORTED_COMMANDS = 0x1002
  READ_LOCAL_SUPPORTED_FEATURES = 0x1003
  READ_LOCAL_EXT_FEATURES = 0x1004
  READ_BUFFER_SIZE = 0x1005
  READ_BD_ADDR = 0x1009
  READ_DATA_BLOCK_SIZE = 0x100A
  READ_LOCAL_PAIRING_OPTS = 0x100C
  READ_LOCAL_SUPPORTED_CODECS = 0x100D

  # Status Parameters (OGF = 0x05)
  READ_RSSI = 0x1405
  GET_MWS_TRANSPORT_LAYER_CONFIGURATION = 0x140C

  # LE Controller Commands (OGF = 0x08)
  LE_SET_EVENT_MASK = 0x2001
  LE_READ_BUFFER_SIZE = 0x2002
  LE_READ_LOCAL_SUPPORTED_FEATURES = 0x2003
  LE_SET_RANDOM_ADDRESS = 0x2005
  LE_SET_ADVERTISING_PARAMETERS = 0x2006
  LE_READ_ADVERTISING_CHANNEL_TX_POWER = 0x2007
  LE_SET_ADVERTISING_DATA = 0x2008
  LE_SET_SCAN_RESPONSE_DATA = 0x2009
  LE_SET_ADVERTISING_ENABLE = 0x200A
  LE_SET_SCAN_PARAMETERS = 0x200B
  LE_SET_SCAN_ENABLE = 0x200C
  LE_CREATE_CONNECTION = 0x200D
  LE_CREATE_CONNECTION_CANCEL = 0x200E
  LE_READ_FILTER_ACCEPT_LIST_SIZE = 0x200F
  LE_CLEAR_FILTER_ACCEPT_LIST = 0x2010
  LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST = 0x2011
  LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST = 0x2012
  LE_CONNECTION_UPDATE = 0x2013
  LE_READ_REMOTE_FEATURES = 0x2016
  LE_ENCRYPT = 0x2017
  LE_RAND = 0x2018
  LE_READ_SUPPORTED_STATES = 0x201C
  LE_SET_DATA_LENGTH = 0x2022
  LE_READ_DEF_DATA_LEN = 0x2023
  LE_WRITE_DEF_DATA_LEN = 0x2024
  LE_CLEAR_RESOLVING_LIST = 0x2029
  LE_READ_RESOLV_LIST_SIZE = 0x202A
  LE_SET_RPA_TIMEOUT = 0x202E
  LE_READ_MAX_DATA_LEN = 0x202F
  LE_SET_DEFAULT_PHY = 0x2031
  LE_SET_EXTENDED_ADVERTISING_PARAMETERS = 0x2036
  LE_SET_EXTENDED_ADVERTISING_DATA = 0x2037
  LE_SET_EXTENDED_SCAN_RESPONSE_DATA = 0x2038
  LE_SET_EXTENDED_ADVERTISING_ENABLE = 0x2039
  LE_READ_NUM_SUPPORTED_ADV_SETS = 0x203B
  LE_SET_EXTENDED_SCAN_PARAMETERS = 0x2041
  LE_SET_EXTENDED_SCAN_ENABLE = 0x2042
  LE_EXTENDED_CREATE_CONNECTION = 0x2043
  LE_READ_TRANSMIT_POWER = 0x204B
  LE_READ_BUFFER_SIZE_V2 = 0x2060


# Commands whose Command Complete event carries only a Status (Core Spec
# Vol 4 Part E 7.2.12, 7.3.x and 7.8.x). Host stacks send them while
# configuring the controller; the virtual controller acknowledges them with
# Success and otherwise ignores them. Any opcode outside this set that has
# no explicit handler is answered with Unknown HCI Command (0x01).
STATUS_ONLY_HCI_OPCODES = frozenset({
    HciOpcode.WRITE_DEFAULT_LINK_POLICY_SETTINGS,
    HciOpcode.WRITE_PAGE_TIMEOUT,
    HciOpcode.WRITE_SCAN_ENABLE,
    HciOpcode.WRITE_PAGE_SCAN_ACTIVITY,
    HciOpcode.WRITE_INQUIRY_SCAN_ACTIVITY,
    HciOpcode.WRITE_CLASS_OF_DEV,
    HciOpcode.WRITE_VOICE_SETTING,
    HciOpcode.WRITE_SIMPLE_PAIRING_MODE,
    HciOpcode.WRITE_DEF_ERR_DATA_REPORTING,
    HciOpcode.SET_EVENT_MASK_PAGE_2,
    HciOpcode.SET_MIN_ENCRYPTION_KEY_SIZE,
    HciOpcode.LE_WRITE_DEF_DATA_LEN,
    HciOpcode.LE_CLEAR_RESOLVING_LIST,
    HciOpcode.LE_SET_RPA_TIMEOUT,
    HciOpcode.LE_SET_DEFAULT_PHY,
})


class HciEventCode(IntEnum):
  """Standard Bluetooth HCI Event Codes (Vol 4, Part E, Section 7.7)."""

  DISCONNECTION_COMPLETE = 0x05
  READ_REMOTE_VERSION_INFO_COMPLETE = 0x0C
  COMMAND_COMPLETE = 0x0E
  COMMAND_STATUS = 0x0F
  NUMBER_OF_COMPLETED_PACKETS = 0x13
  LE_META_EVENT = 0x3E


class LeSubEventCode(IntEnum):
  """Standard Bluetooth LE Meta Event Subcodes."""

  CONNECTION_COMPLETE = 0x01
  ADVERTISING_REPORT = 0x02
  CONNECTION_UPDATE_COMPLETE = 0x03
  READ_REMOTE_FEATURES_COMPLETE = 0x04
  DATA_LENGTH_CHANGE = 0x07
  ENHANCED_CONNECTION_COMPLETE = 0x0A
  EXTENDED_ADVERTISING_REPORT = 0x0D


def str_to_bdaddr_bytes(bdaddr_str: str) -> bytes:
  """Converts 'AA:BB:CC:DD:EE:FF' to little-endian 6-byteHCI BD_ADDR."""
  parts = [int(part, 16) for part in bdaddr_str.strip().split(':')]
  if len(parts) != 6:
    raise ValueError(f'Invalid BD_ADDR string: {bdaddr_str}')
  return bytes(reversed(parts))


def bdaddr_bytes_to_str(bdaddr_le: bytes) -> str:
  """Converts little-endian 6-byte HCI BD_ADDR to 'AA:BB:CC:DD:EE:FF'."""
  if len(bdaddr_le) != 6:
    raise ValueError('BD_ADDR bytes must be 6 bytes')
  return ':'.join(f'{b:02X}' for b in reversed(bdaddr_le))


@dataclass
class H4Packet:
  """Represents a framed H4 packet."""

  packet_type: H4PacketType
  payload: bytes

  def to_bytes(self) -> bytes:
    return bytes([int(self.packet_type)]) + self.payload

  @classmethod
  def from_bytes(cls, raw: bytes) -> 'H4Packet':
    if not raw:
      raise ValueError('Empty H4 packet bytes')
    return cls(H4PacketType(raw[0]), raw[1:])


class H4StreamParser:
  """Stateful H4 byte stream deframer tolerant of TCP chunk fragmentation.

  Bluetooth H4 over UART/TCP prepends a 1-byte packet indicator before each
  HCI frame without an outer length envelope. Because TCP may split or coalesce
  arbitrary byte boundaries, `H4StreamParser` inspects the inner protocol header
  of the buffered packet type to compute the exact frame length:

    - COMMAND (0x01): [0x01][Opcode:2B LE][ParamLen:1B][Params:ParamLen B]
                      Total length = 4 + buffer[3]
    - ACL_DATA (0x02): [0x02][Handle+Flags:2B LE][DataLen:2B LE][Data:DataLen B]
                       Total length = 5 + uint16_le(buffer[3:5])
    - SCO_DATA (0x03): [0x03][Handle+Flags:2B LE][DataLen:1B][Data:DataLen B]
                       Total length = 4 + buffer[3]
    - EVENT (0x04):    [0x04][EventCode:1B][ParamLen:1B][Params:ParamLen B]
                       Total length = 3 + buffer[2]
    - ISO_DATA (0x05): [0x05][Handle+Flags:2B LE][DataLen:14b LE][Data]
                       Total length = 5 + (uint16_le(buffer[3:5]) & 0x3FFF)
  """

  def __init__(self):
    self._buffer = bytearray()

  def _next_packet_frame(self) -> Optional[Tuple[H4PacketType, int]]:
    """Returns (packet_type, total_frame_len) or None if header incomplete."""
    pkt_type_val = self._buffer[0]
    buf_len = len(self._buffer)
    if pkt_type_val == H4PacketType.COMMAND:
      return (
          (H4PacketType.COMMAND, 4 + self._buffer[3]) if buf_len >= 4 else None
      )
    if pkt_type_val == H4PacketType.ACL_DATA:
      if buf_len < 5:
        return None
      return (
          H4PacketType.ACL_DATA,
          5 + struct.unpack_from('<H', self._buffer, 3)[0],
      )
    if pkt_type_val == H4PacketType.SCO_DATA:
      return (
          (H4PacketType.SCO_DATA, 4 + self._buffer[3]) if buf_len >= 4 else None
      )
    if pkt_type_val == H4PacketType.EVENT:
      return (H4PacketType.EVENT, 3 + self._buffer[2]) if buf_len >= 3 else None
    if pkt_type_val == H4PacketType.ISO_DATA:
      if buf_len < 5:
        return None
      # ISO_DATA length occupies the lower 14 bits of bytes 3..4 (Core v5.3).
      data_len = struct.unpack_from('<H', self._buffer, 3)[0] & 0x3FFF
      return H4PacketType.ISO_DATA, 5 + data_len
    return None

  def feed(self, data: bytes) -> List[H4Packet]:
    """Feeds raw TCP stream bytes and returns complete H4Packet frames."""
    if data:
      self._buffer.extend(data)
    packets: List[H4Packet] = []
    valid_types = {int(t) for t in H4PacketType}
    while self._buffer:
      # Discard any leading desynchronized bytes until a valid H4 type byte.
      if self._buffer[0] not in valid_types:
        del self._buffer[0]
        continue
      frame_spec = self._next_packet_frame()
      if frame_spec is None:
        break
      pkt_type, total_len = frame_spec
      # Wait for the next TCP recv() if the full payload has not arrived yet.
      if len(self._buffer) < total_len:
        break
      payload = bytes(self._buffer[1:total_len])
      del self._buffer[:total_len]
      packets.append(H4Packet(pkt_type, payload))
    return packets


def build_command_complete_event(
    opcode: int, status: int = 0x00, return_params: bytes = b''
) -> H4Packet:
  """Builds an HCI Command Complete event (0x0E) wrapped in H4.

  Wire layout:
    [0x04][0x0E][ParamLen][Num_HCI_Command_Packets=1][Opcode:2B LE][Status:1B]
    [Return_Parameters...]
  """
  params = struct.pack('<BHB', 1, opcode, status) + return_params
  event_payload = (
      struct.pack('<BB', HciEventCode.COMMAND_COMPLETE, len(params)) + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)


def build_command_status_event(opcode: int, status: int = 0x00) -> H4Packet:
  """Builds an HCI Command Status event (0x0F) wrapped in H4.

  Used by asynchronous baseband operations (such as `LE_Create_Connection` and
  `Disconnect`) to acknowledge command receipt before the Link Layer handshake
  completes.
  """
  params = struct.pack('<BBH', status, 1, opcode)
  event_payload = (
      struct.pack('<BB', HciEventCode.COMMAND_STATUS, len(params)) + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)


def build_disconnection_complete_event(
    handle: int, reason: int = 0x13, status: int = 0x00
) -> H4Packet:
  """Builds an HCI Disconnection Complete event wrapped in H4."""
  params = struct.pack('<BHB', status, handle & 0x0FFF, reason)
  event_payload = (
      struct.pack('<BB', HciEventCode.DISCONNECTION_COMPLETE, len(params))
      + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)


def build_number_of_completed_packets_event(
    handle: int, num_completed: int = 1
) -> H4Packet:
  """Builds an HCI Number Of Completed Packets event wrapped in H4."""
  params = struct.pack('<BHH', 1, handle & 0x0FFF, num_completed)
  event_payload = (
      struct.pack('<BB', HciEventCode.NUMBER_OF_COMPLETED_PACKETS, len(params))
      + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)


def build_le_advertising_report_event(
    event_type: int,
    addr_type: int,
    bdaddr_str: str,
    adv_data: bytes,
    rssi: int = -45,
) -> H4Packet:
  """Builds an HCI LE Meta Event: LE Advertising Report (0x02)."""
  bdaddr_le = str_to_bdaddr_bytes(bdaddr_str)
  clipped_adv = adv_data[:31]
  rssi_byte = struct.pack('<b', max(-127, min(20, rssi)))
  params = (
      struct.pack(
          '<BBBB6sB',
          LeSubEventCode.ADVERTISING_REPORT,
          1,  # Num_Reports
          event_type,
          addr_type,
          bdaddr_le,
          len(clipped_adv),
      )
      + clipped_adv
      + rssi_byte
  )
  event_payload = (
      struct.pack('<BB', HciEventCode.LE_META_EVENT, len(params)) + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)


def build_le_extended_advertising_report_event(
    event_type: int,
    addr_type: int,
    bdaddr_str: str,
    adv_data: bytes,
    rssi: int = -45,
) -> H4Packet:
  """Builds an HCI LE Meta Event: LE Extended Advertising Report (0x0D)."""
  bdaddr_le = str_to_bdaddr_bytes(bdaddr_str)
  clipped_adv = adv_data[:229]
  report_hdr = struct.pack(
      '<H B 6s B B B b b H B 6s B',
      event_type,
      addr_type,
      bdaddr_le,
      0x01,  # Primary PHY: LE 1M
      0x00,  # Secondary PHY: None
      0xFF,  # SID: None
      0x7F,  # Tx Power: Not available
      max(-127, min(20, rssi)),
      0x0000,  # Periodic Advertising Interval
      0x00,  # Direct Address Type
      b'\x00' * 6,  # Direct Address
      len(clipped_adv),
  )
  params = (
      struct.pack('<BB', LeSubEventCode.EXTENDED_ADVERTISING_REPORT, 1)
      + report_hdr
      + clipped_adv
  )
  event_payload = (
      struct.pack('<BB', HciEventCode.LE_META_EVENT, len(params)) + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)


def build_le_connection_complete_event(
    status: int,
    handle: int,
    role: int,
    peer_addr_type: int,
    peer_bdaddr_str: str,
    *,
    conn_interval: int = 0x0018,
    conn_latency: int = 0x0000,
    supervision_timeout: int = 0x01F4,
) -> H4Packet:
  """Builds an HCI LE Meta Event: LE Connection Complete (0x01)."""
  peer_le = str_to_bdaddr_bytes(peer_bdaddr_str)
  params = struct.pack(
      '<BBHBB6sHHHB',
      LeSubEventCode.CONNECTION_COMPLETE,
      status,
      handle & 0x0FFF,
      role,  # 0x00 = Central/Master, 0x01 = Peripheral/Slave
      peer_addr_type,
      peer_le,
      conn_interval,
      conn_latency,
      supervision_timeout,
      0x00,  # Central_Clock_Accuracy
  )
  event_payload = (
      struct.pack('<BB', HciEventCode.LE_META_EVENT, len(params)) + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)


def build_le_enhanced_connection_complete_event(
    status: int,
    handle: int,
    role: int,
    peer_addr_type: int,
    peer_bdaddr_str: str,
    *,
    conn_interval: int = 0x0018,
    conn_latency: int = 0x0000,
    supervision_timeout: int = 0x01F4,
) -> H4Packet:
  """Builds an HCI LE Meta Event: LE Enhanced Connection Complete (0x0A)."""
  peer_le = str_to_bdaddr_bytes(peer_bdaddr_str)
  params = struct.pack(
      '<BBHBB6s6s6sHHHB',
      LeSubEventCode.ENHANCED_CONNECTION_COMPLETE,
      status,
      handle & 0x0FFF,
      role,  # 0x00 = Central/Master, 0x01 = Peripheral/Slave
      peer_addr_type,
      peer_le,
      b'\x00' * 6,  # Local_Resolvable_Private_Address
      b'\x00' * 6,  # Peer_Resolvable_Private_Address
      conn_interval,
      conn_latency,
      supervision_timeout,
      0x00,  # Central_Clock_Accuracy
  )
  event_payload = (
      struct.pack('<BB', HciEventCode.LE_META_EVENT, len(params)) + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)


def build_le_read_remote_features_complete_event(
    handle: int,
    features: bytes = b'\xff\x01\x00\x00\x00\x00\x00\x00',
    status: int = 0x00,
) -> H4Packet:
  """Builds an HCI LE Meta Event: LE Read Remote Features Complete (0x04)."""
  params = struct.pack(
      '<BBH8s',
      LeSubEventCode.READ_REMOTE_FEATURES_COMPLETE,
      status,
      handle & 0x0FFF,
      features[:8].ljust(8, b'\x00'),
  )
  event_payload = (
      struct.pack('<BB', HciEventCode.LE_META_EVENT, len(params)) + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)


def build_read_remote_version_info_complete_event(
    handle: int,
    version: int = 0x0D,
    manufacturer: int = 0x00E0,
    subversion: int = 0x0001,
    status: int = 0x00,
) -> H4Packet:
  """Builds an HCI Read Remote Version Information Complete event (0x0C)."""
  params = struct.pack(
      '<BHBHH',
      status,
      handle & 0x0FFF,
      version,
      manufacturer,
      subversion,
  )
  event_payload = (
      struct.pack(
          '<BB', HciEventCode.READ_REMOTE_VERSION_INFO_COMPLETE, len(params)
      )
      + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)


def build_le_connection_update_complete_event(
    handle: int,
    conn_interval: int = 0x0018,
    conn_latency: int = 0x0000,
    supervision_timeout: int = 0x01F4,
    status: int = 0x00,
) -> H4Packet:
  """Builds an HCI LE Meta Event: LE Connection Update Complete (0x03)."""
  params = struct.pack(
      '<BBHHHH',
      LeSubEventCode.CONNECTION_UPDATE_COMPLETE,
      status,
      handle & 0x0FFF,
      conn_interval,
      conn_latency,
      supervision_timeout,
  )
  event_payload = (
      struct.pack('<BB', HciEventCode.LE_META_EVENT, len(params)) + params
  )
  return H4Packet(H4PacketType.EVENT, event_payload)




def build_acl_packet(
    handle: int, l2cap_cid: int, l2cap_payload: bytes, pb_flag: int = 0x02
) -> H4Packet:
  """Builds an H4 ACL Data packet encapsulating an L2CAP PDU.

  ACL + L2CAP wire layout:
    [0x02 (ACL_DATA)]
    [Handle (12b) | PB_Flag (2b) | BC_Flag (2b) : 2B LE]
    [ACL_Data_Total_Length : 2B LE]
      [L2CAP_Length : 2B LE]
      [L2CAP_CID    : 2B LE (e.g. 0x0004 for BLE ATT)]
      [L2CAP_Payload: N bytes]
  """
  l2cap_hdr = struct.pack('<HH', len(l2cap_payload), l2cap_cid)
  acl_body = l2cap_hdr + l2cap_payload
  # pb_flag=0x02 marks the start of a non-automatically-flushable L2CAP PDU.
  handle_flags = (handle & 0x0FFF) | ((pb_flag & 0x03) << 12)
  acl_hdr = struct.pack('<HH', handle_flags, len(acl_body))
  return H4Packet(H4PacketType.ACL_DATA, acl_hdr + acl_body)


def parse_acl_packet(payload: bytes) -> Tuple[int, int, bytes]:
  """Parses an H4 ACL payload into (conn_handle, l2cap_cid, l2cap_payload)."""
  if len(payload) < 8:
    raise ValueError('ACL payload too short for L2CAP header')
  handle_flags, acl_len = struct.unpack_from('<HH', payload, 0)
  handle = handle_flags & 0x0FFF
  l2cap_len, l2cap_cid = struct.unpack_from('<HH', payload, 4)
  l2cap_payload = payload[8 : 8 + min(acl_len - 4, l2cap_len)]
  return handle, l2cap_cid, l2cap_payload


@dataclass
class VirtualControllerState:
  """Internal state of an emulated Bluetooth LE Controller."""

  controller_id: str
  bd_addr: str
  random_addr: str = 'C0:00:00:00:00:01'
  local_name: str = 'CirqueVirtualBT'
  event_mask: bytes = b'\xff\xff\xff\xff\xff\xff\xff\xff'
  le_event_mask: bytes = b'\xff\x07\x00\x00\x00\x00\x00\x00'
  le_host_support: int = 1
  adv_enabled: bool = False
  adv_params: bytes = b''
  adv_data: bytes = b''
  scan_rsp_data: bytes = b''
  scan_enabled: bool = False
  scan_type: int = 0x01  # Active scan by default
  own_addr_type: int = 0x00
  filter_accept_list: Dict[str, int] = field(default_factory=dict)
  initiating: bool = False
  initiating_params: Dict[str, object] = field(default_factory=dict)
  extended_conn: bool = False
  connections: Dict[int, Dict[str, object]] = field(default_factory=dict)
  tx_packets: int = 0
  rx_packets: int = 0
  acl_tx_packets: int = 0
  acl_rx_packets: int = 0
  att_write_packets: int = 0
  att_indication_packets: int = 0
  acl_mtu: int = 1024
  acl_max_pkt: int = 16
  sco_mtu: int = 64
  sco_max_pkt: int = 8
  manufacturer_id: int = 0x00E0


def controller_state_to_dict(
    state: VirtualControllerState, dedicated_hci_port: int = 0
) -> Dict[str, object]:
  """Serializes the controller state into a JSON-compatible dictionary."""
  return {
      'controller_id': state.controller_id,
      'bd_addr': state.bd_addr,
      'random_addr': state.random_addr,
      'local_name': state.local_name,
      'adv_enabled': state.adv_enabled,
      'adv_data_hex': state.adv_data.hex(),
      'scan_enabled': state.scan_enabled,
      'dedicated_hci_port': dedicated_hci_port,
      'active_connections': list(state.connections.values()),
      'tx_packets': state.tx_packets,
      'rx_packets': state.rx_packets,
      'acl_tx_packets': state.acl_tx_packets,
      'acl_rx_packets': state.acl_rx_packets,
      'att_write_packets': state.att_write_packets,
      'att_indication_packets': state.att_indication_packets,
      'acl_mtu': state.acl_mtu,
      'acl_max_pkt': state.acl_max_pkt,
      'sco_mtu': state.sco_mtu,
      'sco_max_pkt': state.sco_max_pkt,
      'manufacturer_id': state.manufacturer_id,
  }


def build_static_hci_reply(
    opcode: int, state: VirtualControllerState
) -> Optional[bytes]:
  """Returns the static HCI Command Complete payload for read opcodes."""
  raw_name = state.local_name.encode('utf-8')[:248]
  replies = {
      HciOpcode.READ_BD_ADDR: str_to_bdaddr_bytes(state.bd_addr),
      HciOpcode.READ_LOCAL_VERSION_INFO: struct.pack(
          '<BHBHH', 0x0D, 0x0001, 0x0D, state.manufacturer_id, 0x0001
      ),
      # SIMULATION-DISCLOSURE: the Supported_Commands bitmask (Vol 4 Part E
      # 6.27) claims every opcode. Hosts gate command selection on it (the
      # Android stack picks LE_Extended_Create_Connection this way), so the
      # controller answers each opcode it does not implement with Unknown
      # HCI Command (0x01) rather than publishing a hand-written bit table.
      HciOpcode.READ_LOCAL_SUPPORTED_COMMANDS: bytes([0xFF] * 64),
      HciOpcode.READ_LOCAL_SUPPORTED_FEATURES: bytes(
          [0, 0, 0, 0, 0x60, 0, 0, 0]
      ),
      HciOpcode.READ_BUFFER_SIZE: struct.pack(
          '<HBHH',
          state.acl_mtu,
          state.sco_mtu,
          state.acl_max_pkt,
          state.sco_max_pkt,
      ),
      # Per Bluetooth Core Spec Vol 4 Part E Section 7.3.17/7.3.18: Scan_Enable
      # bit 0 is Inquiry Scan and bit 1 is Page Scan (both BR/EDR). For this
      # LE-only controller (BR/EDR Not Supported per byte 4 = 0x60),
      # Scan_Enable is always 0x00 (no BR/EDR inquiry or page scan).
      HciOpcode.READ_SCAN_ENABLE: bytes([0x00]),
      HciOpcode.READ_LOCAL_NAME: raw_name + b'\x00' * (248 - len(raw_name)),
      HciOpcode.READ_STORED_LINK_KEY: struct.pack('<HH', 0, 0),
      HciOpcode.DELETE_STORED_LINK_KEY: struct.pack('<H', 0),
      HciOpcode.READ_PAGE_SCAN_ACTIVITY: struct.pack('<HH', 0x0800, 0x0012),
      HciOpcode.READ_PAGE_SCAN_TYPE: struct.pack('<B', 0),
      HciOpcode.READ_CLASS_OF_DEV: bytes([0, 0x1F, 0]),
      HciOpcode.READ_VOICE_SETTING: struct.pack('<H', 0x0060),
      HciOpcode.READ_NUM_SUPPORTED_IAC: struct.pack('<B', 1),
      HciOpcode.READ_INQ_RSP_TX_POWER: struct.pack('<b', 0),
      HciOpcode.READ_DEF_ERR_DATA_REPORTING: struct.pack('<B', 0),
      HciOpcode.READ_FLOW_CONTROL_MODE: struct.pack('<B', 0),
      HciOpcode.READ_AUTH_PAYLOAD_TO: struct.pack('<HH', 0x0040, 0x0BB8),
      HciOpcode.READ_LOCAL_EXT_FEATURES: struct.pack(
          '<BB8s', 0, 0, bytes([0, 0, 0, 0, 0x60, 0, 0, 0])
      ),
      HciOpcode.READ_DATA_BLOCK_SIZE: struct.pack('<HHH', 1024, 1024, 16),
      HciOpcode.READ_LOCAL_PAIRING_OPTS: struct.pack('<BB', 0, 0),
      HciOpcode.READ_LE_HOST_SUPPORT: struct.pack(
          '<BB', state.le_host_support, 0
      ),
      HciOpcode.LE_READ_BUFFER_SIZE: struct.pack('<HB', 251, 16),
      HciOpcode.LE_READ_LOCAL_SUPPORTED_FEATURES: bytes(
          [0xFF, 1, 0, 0, 0, 0, 0, 0]
      ),
      HciOpcode.LE_READ_SUPPORTED_STATES: bytes([0xFF] * 5 + [3, 0, 0]),
      HciOpcode.LE_READ_ADVERTISING_CHANNEL_TX_POWER: struct.pack('<b', 0),
      HciOpcode.LE_READ_FILTER_ACCEPT_LIST_SIZE: struct.pack('<B', 16),
      HciOpcode.LE_READ_DEF_DATA_LEN: struct.pack('<HH', 251, 2120),
      HciOpcode.LE_READ_RESOLV_LIST_SIZE: struct.pack('<B', 16),
      HciOpcode.LE_READ_MAX_DATA_LEN: struct.pack('<HHHH', 251, 2120, 251, 2120),
      HciOpcode.LE_READ_NUM_SUPPORTED_ADV_SETS: struct.pack('<B', 1),
      HciOpcode.LE_READ_TRANSMIT_POWER: struct.pack('<bb', -20, 10),
      HciOpcode.LE_READ_BUFFER_SIZE_V2: struct.pack('<HBBHB', 251, 16, 0, 0, 0),
      HciOpcode.LE_RAND: os.urandom(8),
      # Vol 4 Part E 7.4.8: Num_Supported_Standard_Codecs = 0,
      # Num_Supported_Vendor_Specific_Codecs = 0 (LE-only, no SCO/ISO codecs).
      HciOpcode.READ_LOCAL_SUPPORTED_CODECS: struct.pack('<BB', 0, 0),
      # Vol 4 Part E 7.5.11: Num_Transports = 0 (no MWS coexistence
      # transport layers on a virtual controller).
      HciOpcode.GET_MWS_TRANSPORT_LAYER_CONFIGURATION: struct.pack('<B', 0),
  }
  return replies.get(opcode)
