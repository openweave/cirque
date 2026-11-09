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
"""Virtual Bluetooth LE Controller state machine over H4 and Link Layer PHY."""

import logging
import struct
import threading
import time
from typing import Callable, Dict, List, Optional

from cirque.virtual_bt.hci_h4 import (
    H4Packet,
    H4PacketType,
    HciOpcode,
    STATUS_ONLY_HCI_OPCODES,
    VirtualControllerState,
    bdaddr_bytes_to_str,
    build_command_complete_event,
    build_command_status_event,
    build_disconnection_complete_event,
    build_le_advertising_report_event,
    build_le_extended_advertising_report_event,
    build_le_connection_complete_event,
    build_le_enhanced_connection_complete_event,
    build_le_read_remote_features_complete_event,
    build_read_remote_version_info_complete_event,
    build_le_connection_update_complete_event,
    build_number_of_completed_packets_event,
    build_static_hci_reply,
    controller_state_to_dict,
)
from cirque.virtual_bt.link_layer import (
    LinkLayerFrame,
    LinkLayerHub,
    LinkLayerPduType,
)

logger = logging.getLogger('VirtualBtController')


class VirtualBluetoothController:
  """Emulates a Bluetooth LE Controller over H4 and Link Layer PHY."""

  def __init__(
      self,
      controller_id: str,
      bd_addr: str,
      phy_hub: LinkLayerHub,
      local_name: str = 'CirqueVirtualBT',
      acl_mtu: int = 1024,
      acl_max_pkt: int = 16,
      sco_mtu: int = 64,
      sco_max_pkt: int = 8,
      manufacturer_id: int = 0x00E0,
  ):
    self.state = VirtualControllerState(
        controller_id=controller_id,
        bd_addr=bd_addr.upper(),
        local_name=local_name,
        acl_mtu=acl_mtu,
        acl_max_pkt=acl_max_pkt,
        sco_mtu=sco_mtu,
        sco_max_pkt=sco_max_pkt,
        manufacturer_id=manufacturer_id,
    )
    self.phy_hub = phy_hub
    self._lock = threading.RLock()
    self._h4_sinks: List[Callable[[bytes], None]] = []
    self._next_handle: int = 0x0040
    self._peer_to_handle: Dict[str, int] = {}
    # Host-to-controller ACL fragments (PB=0b01) pending a full L2CAP PDU.
    self._acl_rx_reassembly: Dict[int, bytearray] = {}
    self._adv_thread: Optional[threading.Thread] = None
    self._adv_stop_event = threading.Event()
    self.dedicated_hci_port: int = 0
    self._pcap_writer = None
    self.phy_hub.register_local_endpoint(self.state.bd_addr, self.on_phy_frame)

  @property
  def pcap_writer(self):
    return self._pcap_writer

  def set_pcap_writer(self, writer) -> None:
    with self._lock:
      self._pcap_writer = writer

  def _effective_bd_addr(self) -> str:
    with self._lock:
      if (
          self.state.own_addr_type == 0x01
          and self.state.random_addr
          and self.state.random_addr != '00:00:00:00:00:00'
      ):
        return self.state.random_addr.upper()
      return self.state.bd_addr.upper()

  def close(self) -> None:
    self._adv_stop_event.set()
    self.phy_hub.unregister_local_endpoint(self.state.bd_addr)
    if (
        self.state.random_addr
        and self.state.random_addr != '00:00:00:00:00:00'
    ):
      self.phy_hub.unregister_local_endpoint(self.state.random_addr.upper())
    if self._pcap_writer is not None:
      self._pcap_writer.close()
      self._pcap_writer = None

  def add_h4_sink(self, sink: Callable[[bytes], None]) -> None:
    with self._lock:
      self._h4_sinks.append(sink)

  def remove_h4_sink(self, sink: Callable[[bytes], None]) -> None:
    with self._lock:
      if sink in self._h4_sinks:
        self._h4_sinks.remove(sink)

  def emit_h4(self, packet: H4Packet) -> None:
    """Serializes `packet` and dispatches it to all registered H4 TCP sinks."""
    raw = packet.to_bytes()
    if self._pcap_writer is not None:
      # Direction 1 = Controller to Host (Received by Host)
      self._pcap_writer.write_frame(struct.pack('!I', 1) + raw)
    # Snapshot `_h4_sinks` under lock and invoke callbacks outside lock so a
    # disconnecting TCP client can safely call `remove_h4_sink()` without
    # deadlocking against an incoming PHY frame.
    with self._lock:
      if packet.packet_type in (H4PacketType.EVENT, H4PacketType.ACL_DATA):
        self.state.tx_packets += 1
      sinks = list(self._h4_sinks)
    for sink in sinks:
      try:
        sink(raw)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning('Error dispatching H4 packet to sink: %s', exc)

  def broadcast_advertising_once(self) -> None:
    """Broadcasts an ADV_IND frame onto the Link Layer PHY bus."""
    with self._lock:
      if not self.state.adv_enabled:
        return
      adv_payload, addr_type = self.state.adv_data, self.state.own_addr_type
      src_addr = self._effective_bd_addr()
    self.phy_hub.transmit(
        LinkLayerFrame(
            pdu_type=LinkLayerPduType.ADV_IND.value,
            src_bd_addr=src_addr,
            dst_bd_addr='FF:FF:FF:FF:FF:FF',
            src_addr_type=addr_type,
            payload_hex=adv_payload.hex(),
        )
    )

  def _adv_beacon_loop(self) -> None:
    """Periodically rebroadcasts `ADV_IND` every 80ms while advertising is on.

    This ensures a Central controller that enables scanning *after* the
    Peripheral called `LE_Set_Advertising_Enable(1)` still discovers the
    peripheral without waiting for an explicit `SCAN_REQ`.
    """
    while not self._adv_stop_event.is_set():
      with self._lock:
        enabled = self.state.adv_enabled
      if not enabled:
        break
      self.broadcast_advertising_once()
      self._adv_stop_event.wait(0.8)

  def _start_adv_beacon_loop(self) -> None:
    if self._adv_thread and self._adv_thread.is_alive():
      return
    self._adv_stop_event.clear()
    self._adv_thread = threading.Thread(
        target=self._adv_beacon_loop, daemon=True
    )
    self._adv_thread.start()

  def process_h4_packet(self, packet: H4Packet) -> None:
    """Processes an incoming H4 packet from the Host over the HCI TCP channel."""
    if self._pcap_writer is not None:
      # Direction 0 = Host to Controller (Sent by Host)
      self._pcap_writer.write_frame(struct.pack('!I', 0) + packet.to_bytes())
    with self._lock:
      if packet.packet_type in (H4PacketType.COMMAND, H4PacketType.ACL_DATA):
        self.state.rx_packets += 1
    if packet.packet_type == H4PacketType.COMMAND:
      self._handle_hci_command(packet.payload)
    elif packet.packet_type == H4PacketType.ACL_DATA:
      self._handle_hci_acl_data(packet.payload)

  def _handle_info_or_baseband_command(
      self, opcode: int, params: bytes
  ) -> bool:
    """Handles informational, baseband, and LE capability read HCI opcodes."""
    if opcode == HciOpcode.RESET:
      with self._lock:
        self.state.adv_enabled = False
        self.state.scan_enabled = False
        self.state.connections.clear()
        self._peer_to_handle.clear()
        self._next_handle = 0x0040
      self.emit_h4(build_command_complete_event(opcode, 0x00))
      return True
    reply = build_static_hci_reply(opcode, self.state)
    if reply is not None:
      self.emit_h4(build_command_complete_event(opcode, 0x00, reply))
      return True
    if opcode == HciOpcode.SET_EVENT_MASK and len(params) >= 8:
      self.state.event_mask = params[:8]
    elif opcode == HciOpcode.WRITE_LOCAL_NAME:
      self.state.local_name = params.split(b'\x00', 1)[0].decode(
          'utf-8', errors='ignore'
      )
    elif opcode == HciOpcode.WRITE_LE_HOST_SUPPORT and params:
      self.state.le_host_support = params[0]
    elif opcode == HciOpcode.LE_SET_EVENT_MASK and len(params) >= 8:
      self.state.le_event_mask = params[:8]
    elif opcode not in (
        HciOpcode.SET_EVENT_MASK,
        HciOpcode.WRITE_LE_HOST_SUPPORT,
        HciOpcode.LE_SET_EVENT_MASK,
    ):
      return False
    self.emit_h4(build_command_complete_event(opcode, 0x00))
    return True

  def _handle_le_adv_or_scan_command(self, opcode: int, params: bytes) -> bool:
    """Handles LE advertising and scanning configuration HCI opcodes."""
    if opcode == HciOpcode.LE_SET_RANDOM_ADDRESS and len(params) >= 6:
      new_rand = bdaddr_bytes_to_str(params[:6]).upper()
      with self._lock:
        old_rand = self.state.random_addr.upper()
        self.state.random_addr = new_rand
      if (
          old_rand
          and old_rand != '00:00:00:00:00:00'
          and old_rand != self.state.bd_addr
      ):
        self.phy_hub.unregister_local_endpoint(old_rand)
      if new_rand and new_rand != '00:00:00:00:00:00':
        self.phy_hub.register_local_endpoint(new_rand, self.on_phy_frame)
    elif opcode == HciOpcode.LE_SET_ADVERTISING_PARAMETERS:
      if len(params) < 15:
        self.emit_h4(build_command_complete_event(opcode, 0x12))
        return True
      self.state.adv_params = params
      # Byte 5 of LE_Set_Advertising_Parameters is Own_Address_Type.
      self.state.own_addr_type = params[5]
    elif opcode in (
        HciOpcode.LE_SET_ADVERTISING_DATA,
        HciOpcode.LE_SET_EXTENDED_ADVERTISING_DATA,
    ):
      # Legacy LE_Set_Advertising_Data (0x2008) has a 1-byte length header
      # (`[Adv_Data_Len][Adv_Data:31B]`), whereas Extended Advertising Data
      # (0x2037) has a 4-byte header (`[Adv_Handle][Op][Frag_Pref][Len]`).
      off = 1 if opcode == HciOpcode.LE_SET_ADVERTISING_DATA else 4
      if len(params) >= off:
        self.state.adv_data = params[
            off : off + min(params[off - 1], len(params) - off)
        ]
    elif opcode in (
        HciOpcode.LE_SET_SCAN_RESPONSE_DATA,
        HciOpcode.LE_SET_EXTENDED_SCAN_RESPONSE_DATA,
    ):
      off = 1 if opcode == HciOpcode.LE_SET_SCAN_RESPONSE_DATA else 4
      if len(params) >= off:
        self.state.scan_rsp_data = params[
            off : off + min(params[off - 1], len(params) - off)
        ]
    elif opcode in (
        HciOpcode.LE_SET_SCAN_PARAMETERS,
        HciOpcode.LE_SET_EXTENDED_SCAN_PARAMETERS,
    ):
      if params:
        self.state.scan_type = params[0]
    elif opcode in (
        HciOpcode.LE_SET_ADVERTISING_ENABLE,
        HciOpcode.LE_SET_EXTENDED_ADVERTISING_ENABLE,
        HciOpcode.LE_SET_SCAN_ENABLE,
        HciOpcode.LE_SET_EXTENDED_SCAN_ENABLE,
    ):
      return self._handle_le_enable_toggle(opcode, params)
    elif opcode != HciOpcode.LE_SET_RANDOM_ADDRESS:
      return False
    self.emit_h4(build_command_complete_event(opcode, 0x00))
    return True

  def _handle_le_enable_toggle(self, opcode: int, params: bytes) -> bool:
    """Handles LE advertising or scan enable/disable HCI commands."""
    enable = bool(params[0]) if params else False
    is_adv = opcode in (
        HciOpcode.LE_SET_ADVERTISING_ENABLE,
        HciOpcode.LE_SET_EXTENDED_ADVERTISING_ENABLE,
    )
    with self._lock:
      if is_adv:
        self.state.adv_enabled = enable
      else:
        self.state.scan_enabled = enable
        self.state.extended_scan = (
            opcode == HciOpcode.LE_SET_EXTENDED_SCAN_ENABLE
        )
    self.emit_h4(build_command_complete_event(opcode, 0x00))
    if enable and is_adv:
      self.broadcast_advertising_once()
      self._start_adv_beacon_loop()
    elif enable:
      # When scanning starts, broadcast an immediate SCAN_REQ onto the virtual
      # PHY so any already-advertising peripherals respond immediately with
      # ADV_IND + optional SCAN_RSP.
      self.phy_hub.transmit(
          LinkLayerFrame(
              pdu_type=LinkLayerPduType.SCAN_REQ.value,
              src_bd_addr=self._effective_bd_addr(),
              dst_bd_addr='FF:FF:FF:FF:FF:FF',
              src_addr_type=self.state.own_addr_type,
          )
      )
    return True

  def _handle_le_create_conn(self, opcode: int, params: bytes) -> None:
    """Parses LE_Create_Connection parameters and transmits CONNECT_IND.

    Per Bluetooth Core Spec Vol 4, Part E, Section 7.8.12 and Section 7.8.64:
      1. `LE_Create_Connection` (0x200D) / `LE_Extended_Create_Connection` (0x2043)
      2. If Initiator_Filter_Policy == 0x01, the Filter Accept List is used and
         the Peer_Address / Peer_Address_Type parameters are ignored by the host.
      3. Controller immediately replies with `HCI_Command_Status (0x0F)` (`status=0x00`).
      4. If target peer is known or present in Filter Accept List, transmits `CONNECT_IND`.
      5. Once the peripheral replies with `CONNECT_RSP`, both sides emit connection complete event.
    """
    if opcode == HciOpcode.LE_CREATE_CONNECTION and len(params) >= 12:
      filter_policy = params[4]
      peer_type, peer_addr = params[5], bdaddr_bytes_to_str(params[6:12]).upper()
      interval = (
          struct.unpack_from('<H', params, 13)[0] if len(params) >= 15 else 24
      )
      latency = (
          struct.unpack_from('<H', params, 17)[0] if len(params) >= 19 else 0
      )
      timeout = (
          struct.unpack_from('<H', params, 19)[0] if len(params) >= 21 else 500
      )
    elif len(params) >= 9:
      # LE_Extended_Create_Connection (0x2043) places Initiator_Filter_Policy at
      # byte 0, Own_Address_Type at byte 1, Peer_Address_Type at byte 2,
      # and Peer_Address at bytes 3..9.
      filter_policy = params[0]
      peer_type, peer_addr = params[2], bdaddr_bytes_to_str(params[3:9]).upper()
      interval, latency, timeout = 0x0018, 0x0000, 0x01F4
    else:
      self.emit_h4(build_command_status_event(opcode, 0x12))
      return

    # When Filter Accept List is active (filter_policy == 0x01), resolve target
    # peer address from filter_accept_list if already added by host.
    if filter_policy == 0x01:
      with self._lock:
        if self.state.filter_accept_list:
          first_addr = next(iter(self.state.filter_accept_list))
          peer_addr = first_addr
          peer_type = self.state.filter_accept_list[first_addr]

    with self._lock:
      self.state.extended_conn = (
          opcode == HciOpcode.LE_EXTENDED_CREATE_CONNECTION
      )
      self.state.initiating = True
      self.state.initiating_params = {
          'filter_policy': filter_policy,
          'peer_addr': peer_addr,
          'peer_type': peer_type,
          'interval': interval,
          'latency': latency,
          'timeout': timeout,
      }
    self.emit_h4(build_command_status_event(opcode, 0x00))

    if peer_addr and peer_addr != '00:00:00:00:00:00':
      with self._lock:
        self.state.initiating = False
      self.phy_hub.transmit(
          LinkLayerFrame(
              pdu_type=LinkLayerPduType.CONNECT_IND.value,
              src_bd_addr=self._effective_bd_addr(),
              dst_bd_addr=peer_addr,
              src_addr_type=self.state.own_addr_type,
              dst_addr_type=peer_type,
              conn_interval=interval,
              conn_latency=latency,
              supervision_timeout=timeout,
          )
      )

  def _handle_le_conn_command(self, opcode: int, params: bytes) -> bool:
    """Handles LE connection, disconnection, and RSSI HCI opcodes."""
    if opcode in (
        HciOpcode.LE_CREATE_CONNECTION,
        HciOpcode.LE_EXTENDED_CREATE_CONNECTION,
    ):
      self._handle_le_create_conn(opcode, params)
      return True
    if opcode == HciOpcode.LE_CLEAR_FILTER_ACCEPT_LIST:
      with self._lock:
        self.state.filter_accept_list.clear()
      self.emit_h4(build_command_complete_event(opcode, 0x00))
      return True
    if opcode == HciOpcode.LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST:
      if len(params) >= 7:
        addr_type = params[0]
        addr = bdaddr_bytes_to_str(params[1:7]).upper()
        with self._lock:
          self.state.filter_accept_list[addr] = addr_type
      self.emit_h4(build_command_complete_event(opcode, 0x00))
      return True
    if opcode == HciOpcode.LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST:
      if len(params) >= 7:
        addr = bdaddr_bytes_to_str(params[1:7]).upper()
        with self._lock:
          self.state.filter_accept_list.pop(addr, None)
      self.emit_h4(build_command_complete_event(opcode, 0x00))
      return True
    if opcode == HciOpcode.LE_CREATE_CONNECTION_CANCEL:
      with self._lock:
        self.state.initiating = False
      self.emit_h4(build_command_complete_event(opcode, 0x00))
      return True
    if opcode == HciOpcode.LE_READ_REMOTE_FEATURES:
      if len(params) < 2:
        self.emit_h4(build_command_status_event(opcode, 0x12))
        return True
      handle = struct.unpack_from('<H', params, 0)[0]
      self.emit_h4(build_command_status_event(opcode, 0x00))
      self.emit_h4(build_le_read_remote_features_complete_event(handle))
      return True
    if opcode == HciOpcode.READ_REMOTE_VERSION_INFO:
      if len(params) < 2:
        self.emit_h4(build_command_status_event(opcode, 0x12))
        return True
      handle = struct.unpack_from('<H', params, 0)[0]
      self.emit_h4(build_command_status_event(opcode, 0x00))
      self.emit_h4(build_read_remote_version_info_complete_event(handle))
      return True
    if opcode == HciOpcode.LE_CONNECTION_UPDATE:
      if len(params) < 10:
        self.emit_h4(build_command_status_event(opcode, 0x12))
        return True
      handle = struct.unpack_from('<H', params, 0)[0]
      interval_min = struct.unpack_from('<H', params, 2)[0]
      latency = struct.unpack_from('<H', params, 6)[0]
      timeout = struct.unpack_from('<H', params, 8)[0]
      self.emit_h4(build_command_status_event(opcode, 0x00))
      self.emit_h4(
          build_le_connection_update_complete_event(
              handle,
              conn_interval=interval_min,
              conn_latency=latency,
              supervision_timeout=timeout,
          )
      )
      return True
    if opcode == HciOpcode.DISCONNECT:
      handle, reason = (
          struct.unpack_from('<HB', params, 0)
          if len(params) >= 3
          else (0x0040, 0x13)
      )
      self.emit_h4(build_command_status_event(opcode, 0x00))
      with self._lock:
        conn = self.state.connections.pop(handle, None)
        peer_addr = str(conn.get('peer_bd_addr', '')) if conn else ''
        self._peer_to_handle.pop(peer_addr, None)
        if not self.state.connections:
          self._next_handle = 0x0040
      if peer_addr:
        self.phy_hub.transmit(
            LinkLayerFrame(
                pdu_type=LinkLayerPduType.LL_TERMINATE_IND.value,
                src_bd_addr=self._effective_bd_addr(),
                dst_bd_addr=peer_addr,
                reason=reason,
            )
        )
      self.emit_h4(build_disconnection_complete_event(handle, reason, 0x00))
      return True
    if opcode == HciOpcode.READ_RSSI:
      handle = (
          struct.unpack_from('<H', params, 0)[0] if len(params) >= 2 else 0x0040
      )
      with self._lock:
        conn = self.state.connections.get(handle)
        peer_addr = str(conn.get('peer_bd_addr', '')) if conn else ''
      rssi = (
          self.phy_hub.get_rssi(peer_addr, self.state.bd_addr)
          if peer_addr
          else -45
      )
      self.emit_h4(
          build_command_complete_event(
              opcode, 0x00, struct.pack('<Hb', handle, rssi)
          )
      )
      return True
    if opcode == HciOpcode.LE_SET_DATA_LENGTH:
      # Vol 4 Part E 7.8.33: the Command Complete carries Status and
      # Connection_Handle. The virtual link already runs at the maximum
      # 251-octet / 2120 us payload that LE_Read_Maximum_Data_Length reports,
      # so the request never changes the effective length and no
      # LE_Data_Length_Change event follows.
      handle = struct.unpack_from('<H', params, 0)[0] if len(params) >= 2 else 0
      if len(params) < 6:
        status = 0x12
      else:
        with self._lock:
          status = 0x00 if handle in self.state.connections else 0x02
      self.emit_h4(
          build_command_complete_event(
              opcode, status, struct.pack('<H', handle)
          )
      )
      return True
    return False

  def _handle_hci_command(self, payload: bytes) -> None:
    if len(payload) < 3:
      return
    opcode, param_len = struct.unpack_from('<HB', payload, 0)
    params = payload[3 : 3 + param_len]
    for handler in (
        self._handle_info_or_baseband_command,
        self._handle_le_adv_or_scan_command,
        self._handle_le_conn_command,
    ):
      if handler(opcode, params):
        return
    ogf = opcode >> 10
    if ogf == 0x3F:
      # Vendor-Specific Command (VSC): return Unknown HCI Command (0x01) so
      # the host stack knows this controller implements no proprietary VSCs
      # (for example the Android LE_Get_Vendor_Capabilities command 0xFD53).
      self.emit_h4(build_command_complete_event(opcode, 0x01))
      return
    if opcode in STATUS_ONLY_HCI_OPCODES:
      # SIMULATION-DISCLOSURE: these configuration commands return only a
      # Status. They are acknowledged with Success without changing
      # controller state; the BR/EDR ones configure a transport this LE-only
      # controller does not implement, and the LE ones (default PHY, default
      # data length, resolving list, RPA timeout) have no observable effect
      # on the virtual link layer.
      self.emit_h4(build_command_complete_event(opcode, 0x00))
      return
    # Core Spec Vol 1 Part F, error code 0x01: the controller does not
    # implement the opcode. Answering Unknown HCI Command instead of a
    # fabricated Success keeps the host informed and the capture honest.
    logger.warning(
        'Rejecting unimplemented HCI opcode 0x%04x with Unknown HCI Command',
        opcode,
    )
    self.emit_h4(build_command_complete_event(opcode, 0x01))

  def _update_acl_att_stats(self, payload: bytes) -> None:
    if len(payload) < 9:
      return
    _, cid = struct.unpack_from('<HH', payload, 4)
    if cid != 0x0004:
      return
    opcode = payload[8]
    if opcode in (0x12, 0x52):
      self.state.att_write_packets += 1
    elif opcode == 0x1D:
      self.state.att_indication_packets += 1

  def _handle_hci_acl_data(self, payload: bytes) -> None:
    if len(payload) < 4:
      return
    handle_flags, data_len = struct.unpack_from('<HH', payload, 0)
    handle = handle_flags & 0x0FFF
    pb_flag = (handle_flags >> 12) & 0x03
    data = payload[4 : 4 + data_len]
    with self._lock:
      self.state.acl_tx_packets += 1
      conn = self.state.connections.get(handle)
      peer_addr = str(conn['peer_bd_addr']) if conn else None
      if pb_flag == 0x01:  # Continuing fragment (Vol 4 Part E 5.4.2).
        buf = self._acl_rx_reassembly.get(handle)
        if buf is None:
          data = b''  # Continuation without a start fragment: drop.
        else:
          buf.extend(data)
          data = bytes(buf)
      l2cap_pdu = None
      if len(data) >= 4:
        l2cap_len = struct.unpack_from('<H', data, 0)[0]
        if len(data) >= 4 + l2cap_len:
          l2cap_pdu = data[: 4 + l2cap_len]
          self._acl_rx_reassembly.pop(handle, None)
        else:
          self._acl_rx_reassembly[handle] = bytearray(data)
      if l2cap_pdu is not None:
        self._update_acl_att_stats(payload[:4] + l2cap_pdu)
    self.emit_h4(build_number_of_completed_packets_event(handle, 1))
    if peer_addr and l2cap_pdu is not None:
      self.phy_hub.transmit(
          LinkLayerFrame(
              pdu_type=LinkLayerPduType.LL_DATA.value,
              src_bd_addr=self._effective_bd_addr(),
              dst_bd_addr=peer_addr,
              payload_hex=l2cap_pdu.hex(),
          )
      )

  def _allocate_connection(
      self, peer_bd_addr: str, peer_addr_type: int, role: int
  ) -> int:
    with self._lock:
      peer_upper = peer_bd_addr.upper()
      if peer_upper in self._peer_to_handle:
        return self._peer_to_handle[peer_upper]
      if not self.state.connections:
        self._next_handle = 0x0040
      handle = self._next_handle
      self._next_handle += 1
      self.state.connections[handle] = {
          'handle': handle,
          'peer_bd_addr': peer_upper,
          'peer_addr_type': peer_addr_type,
          'role': role,
          'connected_at': time.time(),
      }
      self._peer_to_handle[peer_upper] = handle
      return handle

  def _on_phy_adv_or_scan(self, frame: LinkLayerFrame) -> bool:
    """Processes ADV_IND, SCAN_REQ, and SCAN_RSP frames from the PHY."""
    pdu = frame.pdu_type
    if pdu in (LinkLayerPduType.ADV_IND.value, LinkLayerPduType.SCAN_RSP.value):
      with self._lock:
        scanning, active = self.state.scan_enabled, self.state.scan_type == 0x01
        initiating = getattr(self.state, 'initiating', False)
        init_params = dict(getattr(self.state, 'initiating_params', {}))
        filter_list = dict(self.state.filter_accept_list)
      if initiating and pdu == LinkLayerPduType.ADV_IND.value and init_params:
        match = False
        target_addr = init_params.get('peer_addr', '')
        target_type = init_params.get('peer_type', frame.src_addr_type)
        if init_params.get('filter_policy') == 0x01:
          if frame.src_bd_addr.upper() in filter_list:
            match = True
            target_addr = frame.src_bd_addr.upper()
            target_type = filter_list[target_addr]
        elif target_addr and target_addr == frame.src_bd_addr.upper():
          match = True
        if match:
          with self._lock:
            self.state.initiating = False
          self.phy_hub.transmit(
              LinkLayerFrame(
                  pdu_type=LinkLayerPduType.CONNECT_IND.value,
                  src_bd_addr=self._effective_bd_addr(),
                  dst_bd_addr=target_addr,
                  src_addr_type=self.state.own_addr_type,
                  dst_addr_type=target_type,
                  conn_interval=init_params.get('interval', 24),
                  conn_latency=init_params.get('latency', 0),
                  supervision_timeout=init_params.get('timeout', 500),
              )
          )
      if scanning:
        ev_type = 0x00 if pdu == LinkLayerPduType.ADV_IND.value else 0x04
        if getattr(self.state, 'extended_scan', False):
          ext_ev_type = (
              0x0013 if pdu == LinkLayerPduType.ADV_IND.value else 0x001A
          )
          self.emit_h4(
              build_le_extended_advertising_report_event(
                  ext_ev_type,
                  frame.src_addr_type,
                  frame.src_bd_addr,
                  frame.payload,
                  frame.rssi,
              )
          )
        else:
          self.emit_h4(
              build_le_advertising_report_event(
                  ev_type,
                  frame.src_addr_type,
                  frame.src_bd_addr,
                  frame.payload,
                  frame.rssi,
              )
          )
        if active and ev_type == 0x00:
          self.phy_hub.transmit(
              LinkLayerFrame(
                  pdu_type=LinkLayerPduType.SCAN_REQ.value,
                  src_bd_addr=self._effective_bd_addr(),
                  dst_bd_addr=frame.src_bd_addr,
                  src_addr_type=self.state.own_addr_type,
              )
          )
      return True
    if pdu == LinkLayerPduType.SCAN_REQ.value:
      with self._lock:
        adv_enabled, scan_rsp = (
            self.state.adv_enabled,
            self.state.scan_rsp_data or b'',
        )
      if adv_enabled:
        if frame.dst_bd_addr.upper() == 'FF:FF:FF:FF:FF:FF':
          self.broadcast_advertising_once()
        self.phy_hub.transmit(
            LinkLayerFrame(
                pdu_type=LinkLayerPduType.SCAN_RSP.value,
                src_bd_addr=self._effective_bd_addr(),
                dst_bd_addr=frame.src_bd_addr,
                src_addr_type=self.state.own_addr_type,
                payload_hex=scan_rsp.hex() if scan_rsp else '',
            )
        )
      return True
    return False

  def _on_phy_conn_frame(self, frame: LinkLayerFrame) -> None:
    """Processes CONNECT_IND and CONNECT_RSP frames from the PHY."""
    is_periph = frame.pdu_type == LinkLayerPduType.CONNECT_IND.value
    role = 0x01 if is_periph else 0x00
    if is_periph:
      with self._lock:
        self.state.adv_enabled = False
    else:
      with self._lock:
        self.state.initiating = False
    handle = self._allocate_connection(
        frame.src_bd_addr, frame.src_addr_type, role=role
    )
    timing = {
        'conn_interval': frame.conn_interval,
        'conn_latency': frame.conn_latency,
        'supervision_timeout': frame.supervision_timeout,
    }
    if not is_periph and getattr(self.state, 'extended_conn', False):
      self.emit_h4(
          build_le_enhanced_connection_complete_event(
              0x00,
              handle,
              role,
              frame.src_addr_type,
              frame.src_bd_addr,
              **timing,
          )
      )
    else:
      self.emit_h4(
          build_le_connection_complete_event(
              0x00,
              handle,
              role,
              frame.src_addr_type,
              frame.src_bd_addr,
              **timing,
          )
      )
    if is_periph:
      self.phy_hub.transmit(
          LinkLayerFrame(
              pdu_type=LinkLayerPduType.CONNECT_RSP.value,
              src_bd_addr=self._effective_bd_addr(),
              dst_bd_addr=frame.src_bd_addr,
              src_addr_type=self.state.own_addr_type,
              dst_addr_type=frame.src_addr_type,
              **timing,
          )
      )

  def on_phy_frame(self, frame: LinkLayerFrame) -> None:
    """Handles an incoming Link Layer PDU from the virtual PHY TCP Channel."""
    if self._on_phy_adv_or_scan(frame):
      return
    pdu = frame.pdu_type
    if pdu in (
        LinkLayerPduType.CONNECT_IND.value,
        LinkLayerPduType.CONNECT_RSP.value,
    ):
      self._on_phy_conn_frame(frame)
    elif pdu == LinkLayerPduType.LL_DATA.value:
      with self._lock:
        handle = self._peer_to_handle.get(frame.src_bd_addr.upper())
        if handle is None and len(self.state.connections) == 1:
          handle = next(iter(self.state.connections))
        if handle is not None:
          self.state.acl_rx_packets += 1
          if len(frame.payload) >= 4:
            _, cid = struct.unpack_from('<HH', frame.payload, 0)
            if cid == 0x0004 and len(frame.payload) >= 5:
              opcode = frame.payload[4]
              if opcode in (0x12, 0x52):
                self.state.att_write_packets += 1
              elif opcode == 0x1D:
                self.state.att_indication_packets += 1
      if handle is not None:
        hdr = struct.pack(
            '<HH', (handle & 0x0FFF) | (0x02 << 12), len(frame.payload)
        )
        self.emit_h4(H4Packet(H4PacketType.ACL_DATA, hdr + frame.payload))
    elif pdu == LinkLayerPduType.LL_TERMINATE_IND.value:
      with self._lock:
        handle = self._peer_to_handle.pop(frame.src_bd_addr.upper(), None)
        if handle is None and len(self.state.connections) == 1:
          handle = next(iter(self.state.connections))
        if handle is not None:
          self.state.connections.pop(handle, None)
        if not self.state.connections:
          self._next_handle = 0x0040
      if handle is not None:
        self.emit_h4(
            build_disconnection_complete_event(handle, frame.reason, 0x00)
        )

  def to_dict(self) -> Dict[str, object]:
    with self._lock:
      return controller_state_to_dict(self.state, self.dedicated_hci_port)
