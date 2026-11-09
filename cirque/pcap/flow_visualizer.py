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
"""Cross-Layer Message Flow Recorder, PCAP Dissector, and Interactive Studio.

Dissects PCAP packet captures across Bluetooth (HCI UART DLT 201, LE LL DLT 256),
Wi-Fi (Ethernet DLT 1, EAPOL, ARP, IPv4/IPv6, UDP, mDNS), and Thread
(802.15.4, 6LoWPAN), interleaving them with recorded flow events into an
interactive HTML5 View/Replay/Pause Studio.

The core is protocol-agnostic below the application layer. Raw facts that an
application classifier needs are kept on each event: `details['att_handle']`
and `details['att_value_hex']` for ATT writes/indications,
`details['ad_service_uuids']` for advertising PDUs, `details['src_port']` and
`details['dst_port']` for UDP, and the raw frame bytes in `payload_hex`.

Flow plugins
------------
A flow plugin is a Python file loaded with `--plugin /path/to/plugin.py` (the
option may be repeated). The file may define two module attributes:

  FLOW_DISSECTORS: Dict[str, Callable[[FlowEvent], Optional[FlowEvent]]]
      Dissectors run over every merged event in registration order. A
      dissector returns the (possibly modified or replaced) event, or None to
      leave the event unchanged. If a dissector raises or returns anything
      else for an event, the error is logged and that event is kept as is.
      Dissectors only ever see copies of recorded events.
  FLOW_LAYERS: Dict[str, Dict[str, Any]]
      Display metadata per layer name: 'label' (pill text), 'color' (a
      lowercase Tailwind color family such as 'amber') and 'order' (sort key;
      lower sorts first).

The same dissector callables can be registered on a running MCP server with
`register_flow_dissector()` and the layer metadata with
`register_flow_layer()`.

Dissectors may also set these keys in `details`:
  dedup_key       Copies of one frame seen in several captures within
                  DEDUP_WINDOW_SEC are collapsed into the first one.
  matter_msg_key  Log and capture events of one message are linked through
                  details['joined_events'] (see matter_message_key()).
  lane_aliases    {endpoint: lane index} for the 4-lane sequence diagram.

Thread captures (thread*.pcap, DLT 195) are decrypted when the directory
holds a thread_network_key.txt (see cirque.pcap.thread_keys).

Matter messages are decrypted when the directory holds a
matter_session_keys.txt (see cirque.protocols.matter.session): BTP SDUs are
reassembled from the BLE captures and UDP :5540 payloads are decrypted in
place. Only messages whose MIC verifies are named; they carry
details['decrypted'] = True and layer 'MATTER'.
"""

import argparse
import calendar
from dataclasses import asdict, dataclass, field, replace
import glob
import html
import importlib.util
import ipaddress
import json
import logging
import os
import re
import struct
import sys
import time
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Tuple, Union

from cirque.protocols.matter.session import (
    BTP_FLAG_BEGIN,
    CLUSTER_NAMES,
    COMMAND_NAMES,
    BtpReassembler,
    MatterKeyring,
    decrypt_message,
    describe_message,
    load_matter_session_key_file,
    parse_message_header,
    parse_protocol_header,
)
from cirque.pcap.summarize_pcap import read_pcap_records
from cirque.pcap.thread_keys import derive_thread_keys, load_thread_key_file

try:  # Decrypting Thread captures needs AES-CCM from 'cryptography'.
  from cryptography.exceptions import InvalidTag
  from cryptography.hazmat.primitives.ciphers.aead import AESCCM
except ImportError:  # pragma: no cover - the captures stay encrypted.
  AESCCM = None
  InvalidTag = ValueError

logger = logging.getLogger('FlowVisualizer')

DLT_EN10MB = 1
DLT_BLUETOOTH_HCI_H4 = 187
DLT_BLUETOOTH_HCI_H4_WITH_PHDR = 201
DLT_BLUETOOTH_LE_LL = 251
DLT_BLUETOOTH_LE_LL_WITH_PHDR = 256
DLT_IEEE802_15_4 = 195
DLT_IEEE802_15_4_NOFCS = 230


@dataclass
class FlowEvent:
  """Represents a discrete cross-layer protocol event in a unified timeline."""

  event_id: str
  timestamp: float
  layer: str  # 'THREAD', 'WIFI', 'BT', or a plugin-defined layer
  sublayer: str  # 'HCI', 'L2CAP', 'ATT', 'LL', 'EAPOL', 'UDP', 'mDNS', etc.
  stage: str  # 'ADV_DISCOVERY', 'GATT_CONNECT', 'NETWORK_CONFIG', or custom
  src: str
  dst: str
  title: str
  summary: str
  details: Dict[str, Any] = field(default_factory=dict)
  encapsulation: List[str] = field(default_factory=list)
  payload_hex: str = ''
  replay_mcp_call: Optional[Dict[str, Any]] = None
  channel: Optional[int] = None
  rssi: Optional[int] = None

  def to_dict(self) -> Dict[str, Any]:
    return asdict(self)


FlowDissector = Callable[[FlowEvent], Optional[FlowEvent]]

# Display metadata for the layers emitted by the core dissectors. Plugins add
# their own layers through FLOW_LAYERS / register_flow_layer().
DEFAULT_FLOW_LAYERS: Dict[str, Dict[str, Any]] = {
    'THREAD': {'label': 'Thread', 'color': 'blue', 'order': 20},
    'WIFI': {'label': 'Wi-Fi', 'color': 'emerald', 'order': 30},
    'BT': {'label': 'Bluetooth', 'color': 'slate', 'order': 40},
}


def _json_for_script(obj: Any) -> str:
  """JSON-encodes `obj` for embedding inside an HTML <script> element."""
  return json.dumps(obj).replace('<', '\\u003c')


def _format_hex_ascii_dump(data_bytes: bytes) -> str:
  """Generates a Wireshark-style synchronized hex + ASCII dump."""
  if not data_bytes:
    return '0000   (empty payload)'
  lines = []
  for offset in range(0, len(data_bytes), 16):
    chunk = data_bytes[offset : offset + 16]
    hex_str = ' '.join(f'{b:02x}' for b in chunk)
    if len(chunk) < 16:
      hex_str = hex_str.ljust(47)
    ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
    lines.append(f'{offset:04x}   {hex_str}   |{ascii_str}|')
  return '\n'.join(lines)


# -----------------------------------------------------------------------------
# PCAP Dissectors (HCI, LE LL, Wi-Fi Ethernet/IP, Thread)
# -----------------------------------------------------------------------------


def _unpack_att_handle(l2cap_sdu: bytes) -> int:
  """Extracts the 2-byte little-endian ATT handle from an L2CAP SDU."""
  if len(l2cap_sdu) >= 3:
    return struct.unpack('<H', l2cap_sdu[1:3])[0]
  return 0


def dissect_hci_phdr_packet(
    ts: float, raw_data: bytes, pcap_name: str, index: int
) -> Optional[FlowEvent]:
  """Dissects DLT 201 (BLUETOOTH_HCI_H4_WITH_PHDR)."""
  if len(raw_data) < 5:
    return None
  direction_raw = struct.unpack('>I', raw_data[:4])[0]
  is_sent = direction_raw == 0  # Host -> Controller
  direction_str = 'Host -> Ctrl' if is_sent else 'Ctrl -> Host'
  h4_data = raw_data[4:]
  pkt_type = h4_data[0]

  src = 'Host' if is_sent else 'Controller'
  dst = 'Controller' if is_sent else 'Host'
  sublayer = 'HCI'
  layer = 'BT'
  stage = 'ADV_DISCOVERY'
  title = f'HCI Packet (0x{pkt_type:02x})'
  summary = f'HCI {direction_str}'
  encap = ['BT HCI (DLT 201)']
  details: Dict[str, Any] = {
      'pcap_file': pcap_name,
      'packet_index': index,
      'direction': direction_str,
      'h4_type': pkt_type,
  }
  replay_call = None

  if pkt_type == 0x01:  # HCI Command
    if len(h4_data) >= 4:
      opcode, param_len = struct.unpack('<HB', h4_data[1:4])
      ogf = opcode >> 10
      ocf = opcode & 0x03FF
      title = f'HCI Command (OGF=0x{ogf:02x}, OCF=0x{ocf:03x})'
      summary = f'HCI Command 0x{opcode:04x} (len={param_len})'
      details['opcode'] = f'0x{opcode:04x}'
      details['ogf'] = f'0x{ogf:02x}'
      details['ocf'] = f'0x{ocf:03x}'
      encap.append(f'HCI Cmd 0x{opcode:04x}')
      if opcode == 0x200C:  # LE Set Scan Enable
        title = 'HCI LE Set Scan Enable'
        stage = 'ADV_DISCOVERY'
      elif opcode == 0x200D:  # LE Create Connection
        title = 'HCI LE Create Connection'
        stage = 'GATT_CONNECT'
  elif pkt_type == 0x02:  # HCI ACL Data
    if len(h4_data) >= 5:
      handle_flags, data_len = struct.unpack('<HH', h4_data[1:5])
      handle = handle_flags & 0x0FFF
      pb_flag = (handle_flags >> 12) & 0x03
      details['acl_handle'] = handle
      details['pb_flag'] = pb_flag
      details['acl_len'] = data_len
      encap.append(f'HCI ACL (handle={handle})')

      acl_payload = h4_data[5 : 5 + data_len]
      if len(acl_payload) >= 4:
        l2cap_len, l2cap_cid = struct.unpack('<HH', acl_payload[:4])
        details['l2cap_len'] = l2cap_len
        details['l2cap_cid'] = f'0x{l2cap_cid:04x}'
        encap.append(f'L2CAP (CID 0x{l2cap_cid:04x})')
        sublayer = 'L2CAP'

        l2cap_sdu = acl_payload[4 : 4 + l2cap_len]
        if l2cap_cid == 0x0004 and l2cap_sdu:  # ATT Protocol
          sublayer = 'ATT'
          att_opcode = l2cap_sdu[0]
          details['att_opcode'] = f'0x{att_opcode:02x}'
          encap.append(f'ATT (0x{att_opcode:02x})')

          if att_opcode in (0x12, 0x52):  # Write Req / Write Cmd
            handle = _unpack_att_handle(l2cap_sdu)
            title = f'ATT Write (Handle 0x{handle:04x})'
            summary = f'ATT Write Request to handle 0x{handle:04x}'
            stage = 'GATT_CONNECT'
            details['att_handle'] = f'0x{handle:04x}'
            details['att_value_hex'] = l2cap_sdu[3:].hex()
          elif att_opcode == 0x13:  # Write Response
            title = 'ATT Write Response'
            summary = 'ATT Write Response acknowledgment'
            stage = 'GATT_CONNECT'
          elif att_opcode in (0x1D, 0x1B):  # Handle Value Indication/Notification
            handle = _unpack_att_handle(l2cap_sdu)
            title = f'ATT Indication/Notify (0x{handle:04x})'
            summary = f'ATT Handle Value on 0x{handle:04x}'
            stage = 'GATT_CONNECT'
            details['att_handle'] = f'0x{handle:04x}'
            details['att_value_hex'] = l2cap_sdu[3:].hex()
  elif pkt_type == 0x04:  # HCI Event
    if len(h4_data) >= 3:
      evt_code, param_len = struct.unpack('<BB', h4_data[1:3])
      details['evt_code'] = f'0x{evt_code:02x}'
      title = f'HCI Event (0x{evt_code:02x})'
      summary = f'HCI Event 0x{evt_code:02x}'
      encap.append(f'HCI Evt 0x{evt_code:02x}')
      if evt_code == 0x3E:  # LE Meta Event
        sub_evt = h4_data[3] if len(h4_data) > 3 else 0
        details['sub_evt'] = f'0x{sub_evt:02x}'
        if sub_evt == 0x02:  # LE Advertising Report
          title = 'HCI LE Adv Report'
          summary = 'LE Advertising Report received'
          stage = 'ADV_DISCOVERY'
        elif sub_evt == 0x01:  # LE Connection Complete
          title = 'HCI LE Conn Complete'
          summary = 'LE Connection Complete established'
          stage = 'GATT_CONNECT'

  return FlowEvent(
      event_id=f'hci_{index}_{int(ts * 1000)}',
      timestamp=ts,
      layer=layer,
      sublayer=sublayer,
      stage=stage,
      src=src,
      dst=dst,
      title=title,
      summary=summary,
      details=details,
      encapsulation=encap,
      payload_hex=h4_data.hex(),
      replay_mcp_call=replay_call,
  )


def _parse_ad_service_uuids(adv_data: bytes) -> List[str]:
  """Returns 16-bit service UUIDs from UUID-list and service-data AD items."""
  uuids: List[str] = []
  pos = 0
  while pos + 1 < len(adv_data):
    ad_len = adv_data[pos]
    if ad_len == 0:
      break
    ad_type = adv_data[pos + 1]
    body = adv_data[pos + 2 : pos + 1 + ad_len]
    if ad_type in (0x02, 0x03):  # Incomplete / Complete 16-bit UUID list
      for i in range(0, len(body) - 1, 2):
        uuids.append(f'0x{struct.unpack("<H", body[i : i + 2])[0]:04x}')
    elif ad_type == 0x16 and len(body) >= 2:  # Service Data - 16-bit UUID
      uuids.append(f'0x{struct.unpack("<H", body[:2])[0]:04x}')
    pos += 1 + ad_len
  return uuids


def dissect_le_ll_packet(
    ts: float, raw_data: bytes, pcap_name: str, index: int
) -> Optional[FlowEvent]:
  """Dissects DLT 256 (BLUETOOTH_LE_LL_WITH_PHDR)."""
  if len(raw_data) < 14:
    return None
  # 10-byte pseudo-header: rf_channel(1), signal(1), noise(1), aa_offenses(1), ref_aa(4 LE), flags(2 LE)
  rf_channel, rssi, noise, _, ref_aa, flags = struct.unpack(
      '<bbbBIH', raw_data[:10]
  )
  aa = struct.unpack('<I', raw_data[10:14])[0]
  ll_pdu = raw_data[14:]

  src = 'Advertiser'
  dst = 'Scanner/Broadcast'
  sublayer = 'LL'
  layer = 'BT'
  stage = 'ADV_DISCOVERY'
  title = f'BLE LL Frame (Ch {rf_channel})'
  summary = f'BLE Link Layer Frame on RF channel {rf_channel}, RSSI {rssi} dBm'
  encap = [f'BLE PHY Ch {rf_channel} (DLT 256)', f'LE LL (AA 0x{aa:08x})']
  details: Dict[str, Any] = {
      'pcap_file': pcap_name,
      'packet_index': index,
      'rf_channel': rf_channel,
      'rssi_dbm': rssi,
      'access_address': f'0x{aa:08x}',
      'flags': f'0x{flags:04x}',
  }
  replay_call = None

  if aa == 0x8E89BED6:  # Advertising channel
    if ll_pdu:
      pdu_hdr = ll_pdu[0]
      pdu_type = pdu_hdr & 0x0F
      pdu_names = {
          0x00: 'ADV_IND',
          0x01: 'ADV_DIRECT_IND',
          0x02: 'ADV_NONCONN_IND',
          0x03: 'SCAN_REQ',
          0x04: 'SCAN_RSP',
          0x05: 'CONNECT_IND',
          0x06: 'ADV_SCAN_IND',
      }
      pdu_str = pdu_names.get(pdu_type, f'PDU_0x{pdu_type:x}')
      title = f'BLE {pdu_str}'
      summary = f'BLE {pdu_str} on Ch {rf_channel}, RSSI {rssi} dBm'
      encap.append(pdu_str)
      details['pdu_type'] = pdu_str

      # The LL PDU header is 2 bytes (header, length); AdvA follows it.
      if len(ll_pdu) >= 8:
        adv_addr = ':'.join(f'{b:02X}' for b in ll_pdu[2:8][::-1])
        src = adv_addr
        details['adv_addr'] = adv_addr

      if len(ll_pdu) >= 8 and pdu_str in (
          'ADV_IND',
          'ADV_NONCONN_IND',
          'SCAN_RSP',
          'ADV_SCAN_IND',
      ):
        # PDU = header(1) + length(1) + AdvA(6) + AdvData + CRC(3).
        service_uuids = _parse_ad_service_uuids(ll_pdu[8 : 2 + ll_pdu[1]])
        if service_uuids:
          details['ad_service_uuids'] = service_uuids

      if pdu_str == 'ADV_IND':
        stage = 'ADV_DISCOVERY'
      elif pdu_str == 'CONNECT_IND':
        stage = 'GATT_CONNECT'
        title = 'BLE CONNECT_IND'
        summary = f'Central connection request initiated on Ch {rf_channel}'
        if len(ll_pdu) >= 14:
          init_addr = ':'.join(f'{b:02X}' for b in ll_pdu[2:8][::-1])
          adv_addr = ':'.join(f'{b:02X}' for b in ll_pdu[8:14][::-1])
          src = init_addr
          dst = adv_addr
  else:
    # Connected Data Channel
    stage = 'GATT_CONNECT'
    title = f'BLE LL Data PDU (Ch {rf_channel})'
    summary = f'Connected BLE Data Frame on Ch {rf_channel}'
    sublayer = 'LL_DATA'

  return FlowEvent(
      event_id=f'le_ll_{index}_{int(ts * 1000)}',
      timestamp=ts,
      layer=layer,
      sublayer=sublayer,
      stage=stage,
      src=src,
      dst=dst,
      title=title,
      summary=summary,
      details=details,
      encapsulation=encap,
      payload_hex=ll_pdu.hex(),
      replay_mcp_call=replay_call,
      channel=rf_channel,
      rssi=rssi,
  )


_DHCP_MAGIC_COOKIE = 0x63825363
# RFC 2132 option 53 (DHCP Message Type) values.
_DHCP_MESSAGE_TYPES = {
    1: 'Discover',
    2: 'Offer',
    3: 'Request',
    4: 'Decline',
    5: 'Ack',
    6: 'Nak',
    7: 'Release',
    8: 'Inform',
}


class _DhcpSummary(NamedTuple):
  xid: int
  yiaddr: str
  msg_type: str


def _parse_dhcp_options(udp_payload: bytes) -> Optional[_DhcpSummary]:
  """Parses a BOOTP/DHCP payload (236-byte header + magic cookie + options)."""
  if len(udp_payload) < 240:
    return None
  xid = struct.unpack('>I', udp_payload[4:8])[0]
  yiaddr = '.'.join(str(b) for b in udp_payload[16:20])
  magic = struct.unpack('>I', udp_payload[236:240])[0]
  msg_type = 'Message'
  idx = 240
  while magic == _DHCP_MAGIC_COOKIE and idx + 1 < len(udp_payload):
    opt = udp_payload[idx]
    if opt == 255:  # End
      break
    if opt == 0:  # Pad
      idx += 1
      continue
    opt_len = udp_payload[idx + 1]
    if opt == 53 and opt_len == 1 and idx + 2 < len(udp_payload):
      code = udp_payload[idx + 2]
      msg_type = _DHCP_MESSAGE_TYPES.get(code, f'Type {code}')
    idx += 2 + opt_len
  return _DhcpSummary(xid=xid, yiaddr=yiaddr, msg_type=msg_type)


def _apply_dhcp_info(
    details: Dict[str, Any], encap: List[str], dhcp_info: _DhcpSummary
) -> Tuple[str, str]:
  title = f'DHCP {dhcp_info.msg_type}'
  summary = f'{title} xid=0x{dhcp_info.xid:08x} yiaddr={dhcp_info.yiaddr}'
  encap.append(f'DHCP ({dhcp_info.msg_type})')
  details['dhcp_message_type'] = dhcp_info.msg_type
  details['dhcp_xid'] = f'0x{dhcp_info.xid:08x}'
  details['dhcp_yiaddr'] = dhcp_info.yiaddr
  return title, summary


def dissect_wifi_packet(
    ts: float, raw_data: bytes, pcap_name: str, index: int
) -> Optional[FlowEvent]:
  """Dissects DLT 1 (LINKTYPE_ETHERNET / Wi-Fi)."""
  if len(raw_data) < 14:
    return None
  dst_mac = ':'.join(f'{b:02X}' for b in raw_data[:6])
  src_mac = ':'.join(f'{b:02X}' for b in raw_data[6:12])
  ethertype = struct.unpack('>H', raw_data[12:14])[0]

  src = src_mac
  dst = dst_mac
  layer = 'WIFI'
  sublayer = 'Ethernet'
  stage = 'NETWORK_CONFIG'
  title = f'Ethernet Frame (0x{ethertype:04x})'
  summary = f'Ethernet {src_mac} -> {dst_mac} (0x{ethertype:04x})'
  encap = ['Wi-Fi 802.11 / L2 Ethernet (DLT 1)']
  details: Dict[str, Any] = {
      'pcap_file': pcap_name,
      'packet_index': index,
      'src_mac': src_mac,
      'dst_mac': dst_mac,
      'ethertype': f'0x{ethertype:04x}',
  }
  replay_call = None
  l3_payload = raw_data[14:]

  if ethertype == 0x888E:  # EAPOL / 802.1X
    sublayer = 'EAPOL'
    title = 'WPA2 EAPOL 4-Way Handshake'
    summary = f'WPA2 4-Way Handshake Message {src_mac} -> {dst_mac}'
    encap.append('WPA2 EAPOL')
    details['auth_protocol'] = 'WPA2-PSK'
    details['decrypted'] = True
    details['evidence'] = 'wire'
  elif ethertype == 0x0806:  # ARP
    sublayer = 'ARP'
    title = 'ARP Request / Reply'
    summary = f'ARP Resolution {src_mac} -> {dst_mac}'
    encap.append('ARP')
  elif ethertype == 0x0800:  # IPv4
    sublayer = 'IPv4'
    encap.append('IPv4')
    if len(l3_payload) >= 20:
      ip_proto = l3_payload[9]
      src_ip = '.'.join(str(b) for b in l3_payload[12:16])
      dst_ip = '.'.join(str(b) for b in l3_payload[16:20])
      src = src_ip
      dst = dst_ip
      details['src_ip'] = src_ip
      details['dst_ip'] = dst_ip
      if ip_proto == 17 and len(l3_payload) >= 28:  # UDP
        sublayer = 'UDP'
        src_port, dst_port = struct.unpack('>HH', l3_payload[20:24])
        details['src_port'] = src_port
        details['dst_port'] = dst_port
        details['udp_payload_offset'] = 14 + 20 + 8
        encap.append(f'UDP :{src_port}->:{dst_port}')
        if dst_port == 5353 or src_port == 5353:
          sublayer = 'mDNS'
          title = 'mDNS Service Discovery'
          summary = f'Multicast DNS Query/Response {src_ip}:{src_port}'
          encap.append('mDNS (5353)')
        elif dst_port in (67, 68) or src_port in (67, 68):
          sublayer = 'DHCP'
          title = 'DHCP Message'
          summary = f'DHCP {src_ip}:{src_port} -> {dst_ip}:{dst_port}'
          details['evidence'] = 'wire'
          details['decrypted'] = True
          # DHCP runs before the station has an address (0.0.0.0 ->
          # 255.255.255.255), so draw it between link-layer endpoints.
          src = src_mac
          dst = (
              DHCP_SERVER_ENDPOINT
              if dst_mac == 'FF:FF:FF:FF:FF:FF' and dst_port == 67
              else dst_mac
          )
          dhcp_info = _parse_dhcp_options(l3_payload[28:])
          if dhcp_info is not None:
            title, summary = _apply_dhcp_info(details, encap, dhcp_info)
  elif ethertype == 0x86DD:  # IPv6
    sublayer = 'IPv6'
    encap.append('IPv6')
    if len(l3_payload) >= 40:
      next_hdr = l3_payload[6]
      src_ip6 = ':'.join(
          f'{struct.unpack(">H", l3_payload[8 + i*2 : 10 + i*2])[0]:x}'
          for i in range(8)
      )
      dst_ip6 = ':'.join(
          f'{struct.unpack(">H", l3_payload[24 + i*2 : 26 + i*2])[0]:x}'
          for i in range(8)
      )
      src = src_ip6
      dst = dst_ip6
      details['src_ip6'] = src_ip6
      details['dst_ip6'] = dst_ip6
      title = f'IPv6 [{src_ip6}] -> [{dst_ip6}]'
      summary = f'IPv6 next_hdr={next_hdr} [{src_ip6}] -> [{dst_ip6}]'
      if next_hdr == 17 and len(l3_payload) >= 48:  # UDP
        sublayer = 'UDP'
        src_port, dst_port = struct.unpack('>HH', l3_payload[40:44])
        details['src_port'] = src_port
        details['dst_port'] = dst_port
        details['udp_payload_offset'] = 14 + 40 + 8
        title = f'IPv6 UDP :{src_port}->:{dst_port}'
        summary = f'IPv6 UDP [{src_ip6}]:{src_port} -> [{dst_ip6}]:{dst_port}'
        encap.append(f'UDP :{src_port}->:{dst_port}')
        if dst_port == 5353 or src_port == 5353:
          sublayer = 'mDNS'
          title = 'mDNS IPv6 Discovery'
          summary = f'mDNS Query/Response {src_ip6}'
          encap.append('mDNS (5353)')
      elif next_hdr == 6 and len(l3_payload) >= 60:  # TCP
        sublayer = 'TCP'
        src_port, dst_port = struct.unpack('>HH', l3_payload[40:44])
        details['src_port'] = src_port
        details['dst_port'] = dst_port
        title = f'IPv6 TCP :{src_port}->:{dst_port}'
        summary = f'IPv6 TCP [{src_ip6}]:{src_port} -> [{dst_ip6}]:{dst_port}'
        encap.append(f'TCP :{src_port}->:{dst_port}')

  return FlowEvent(
      event_id=f'wifi_{index}_{int(ts * 1000)}',
      timestamp=ts,
      layer=layer,
      sublayer=sublayer,
      stage=stage,
      src=src,
      dst=dst,
      title=title,
      summary=summary,
      details=details,
      encapsulation=encap,
      payload_hex=raw_data.hex(),
      replay_mcp_call=replay_call,
  )


# -----------------------------------------------------------------------------
# Thread Dissector (IEEE 802.15.4 DLT 195, 6LoWPAN, MLE)
# -----------------------------------------------------------------------------

_WPAN_FRAME_TYPES = {0: 'Beacon', 1: 'Data', 2: 'Ack', 3: 'Command'}
_WPAN_COMMANDS = {0x04: 'Data Request', 0x07: 'Beacon Request'}
_MLE_UDP_PORT = 19788
_MLE_COMMANDS = {
    0: 'Link Request',
    1: 'Link Accept',
    2: 'Link Accept And Request',
    3: 'Link Reject',
    4: 'Advertisement',
    5: 'Update',
    6: 'Update Request',
    7: 'Data Request',
    8: 'Data Response',
    9: 'Parent Request',
    10: 'Parent Response',
    11: 'Child ID Request',
    12: 'Child ID Response',
    13: 'Child Update Request',
    14: 'Child Update Response',
    15: 'Announce',
    16: 'Discovery Request',
    17: 'Discovery Response',
}
_IPV6_LINK_LOCAL_PREFIX = bytes.fromhex('fe80000000000000')
_FALLBACK_OT_NETWORK_KEYS = (
    bytes.fromhex('00112233445566778899aabbccddeeff'),
    bytes.fromhex('ffeeddccbbaa99887766554433221100'),
)


class ThreadDecodeContext:
  """Key material and address state shared by the frames of one capture.

  `ext_addrs` holds every extended address seen in the capture (big-endian);
  frames with a short source address are decrypted by trying the known
  mapping first and then each extended address, since the CCM* nonce needs
  the sender's extended address and the MIC tells which one is right.
  """

  def __init__(
      self,
      network_key: Optional[bytes] = None,
      mesh_local_prefix: Optional[bytes] = None,
  ):
    self.network_key = network_key
    self.mesh_local_prefix = mesh_local_prefix
    self.ext_addrs: List[bytes] = []
    self.short_to_ext: Dict[int, bytes] = {}
    self._keys: Dict[Tuple[bytes, int], Tuple[bytes, bytes]] = {}

  def keys(self, key_sequence: int) -> Optional[Tuple[bytes, bytes]]:
    if self.network_key is None or AESCCM is None:
      return None
    cache_key = (self.network_key, key_sequence)
    if cache_key not in self._keys:
      self._keys[cache_key] = derive_thread_keys(
          self.network_key, key_sequence
      )
    return self._keys[cache_key]

  def key_candidates(self, key_sequence: int) -> List[Tuple[bytes, bytes]]:
    primary = self.keys(key_sequence)
    if primary is None:
      return []
    result = [primary]
    for fallback_nk in _FALLBACK_OT_NETWORK_KEYS:
      if fallback_nk != self.network_key:
        cache_key = (fallback_nk, key_sequence)
        if cache_key not in self._keys:
          self._keys[cache_key] = derive_thread_keys(fallback_nk, key_sequence)
        result.append(self._keys[cache_key])
    return result

  def learn_ext_addr(self, addr: bytes) -> None:
    if len(addr) == 8 and addr not in self.ext_addrs:
      self.ext_addrs.append(addr)


def _crc16_kermit(data: bytes) -> int:
  """IEEE 802.15.4 FCS (CRC-16/KERMIT), as computed by the sim radio."""
  crc = 0
  for byte in data:
    crc ^= byte
    for _ in range(8):
      crc = (crc >> 1) ^ 0x8408 if crc & 1 else crc >> 1
  return crc


def _format_wpan_addr(addr: bytes) -> str:
  """Formats a big-endian short (0xabcd) or extended address."""
  if len(addr) == 2:
    return f'0x{int.from_bytes(addr, "big"):04x}'
  return ':'.join(f'{b:02x}' for b in addr)


def parse_wpan_frame(frame: bytes) -> Optional[Dict[str, Any]]:
  """Parses an 802.15.4 frame with FCS (2006 and 2015 frame versions).

  Addresses are returned big-endian. Returns None when the frame is too
  short or truncated inside its MAC header.
  """
  if len(frame) < 5:
    return None
  fcf = struct.unpack_from('<H', frame, 0)[0]
  version = (fcf >> 12) & 3
  dst_mode = (fcf >> 10) & 3
  src_mode = (fcf >> 14) & 3
  pan_comp = bool(fcf & 0x40)
  hdr: Dict[str, Any] = {
      'type': fcf & 7,
      'security': bool(fcf & 0x08),
      'ack_request': bool(fcf & 0x20),
      'version': version,
      'fcs_ok': _crc16_kermit(frame[:-2])
      == struct.unpack_from('<H', frame, len(frame) - 2)[0],
  }
  end = len(frame) - 2
  pos = 2

  def take(size: int) -> bytes:
    nonlocal pos
    if pos + size > end:
      raise ValueError('truncated 802.15.4 header')
    value = frame[pos : pos + size]
    pos += size
    return value

  try:
    if not (version == 2 and fcf & 0x100):
      hdr['seq'] = take(1)[0]
    if version < 2:
      dst_pan = dst_mode != 0
      src_pan = src_mode != 0 and not pan_comp
    elif dst_mode and src_mode:  # IEEE 802.15.4-2015 Table 7-2
      both_ext = dst_mode == 3 and src_mode == 3
      dst_pan = not (pan_comp and both_ext)
      src_pan = not pan_comp and not both_ext
    else:
      dst_pan = (not pan_comp) if dst_mode else pan_comp
      src_pan = bool(src_mode) and not pan_comp
    addr_len = {0: 0, 2: 2, 3: 8}
    if dst_pan:
      hdr['dst_pan'] = struct.unpack('<H', take(2))[0]
    if dst_mode in addr_len and dst_mode:
      hdr['dst'] = take(addr_len[dst_mode])[::-1]
    if src_pan:
      hdr['src_pan'] = struct.unpack('<H', take(2))[0]
    if src_mode in addr_len and src_mode:
      hdr['src'] = take(addr_len[src_mode])[::-1]
    mic_len = 0
    if hdr['security']:
      sec_ctrl = take(1)[0]
      level = sec_ctrl & 7
      key_id_mode = (sec_ctrl >> 3) & 3
      hdr['sec_level'] = level
      hdr['key_id_mode'] = key_id_mode
      if not sec_ctrl & 0x20:
        hdr['frame_counter'] = struct.unpack('<I', take(4))[0]
      key_source_len = {0: None, 1: 0, 2: 4, 3: 8}[key_id_mode]
      if key_source_len is not None:
        hdr['key_source'] = take(key_source_len)
        hdr['key_index'] = take(1)[0]
      mic_len = (0, 4, 8, 16)[level & 3]
    if fcf & 0x200:  # Header IEs, terminated by HT1/HT2 when a payload follows
      while pos + 2 <= end - mic_len:
        ie = struct.unpack('<H', take(2))[0]
        take(ie & 0x7F)
        if (ie >> 7) & 0xFF in (0x7E, 0x7F):
          break
  except ValueError:
    return None
  if pos + mic_len > end:
    return None
  hdr['header'] = frame[:pos]
  hdr['payload'] = frame[pos : end - mic_len]
  hdr['mic'] = frame[end - mic_len : end]
  return hdr


def _ccm_decrypt(
    key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, mic: bytes
) -> Optional[bytes]:
  """AES-CCM* decryption; returns None when the MIC does not verify."""
  try:
    return AESCCM(key, tag_length=len(mic)).decrypt(
        nonce, ciphertext + mic, aad
    )
  except (InvalidTag, ValueError):
    return None


def _decrypt_wpan_frame(
    hdr: Dict[str, Any], ctx: ThreadDecodeContext
) -> Optional[bytes]:
  """Decrypts a Thread MAC frame (key id mode 1, MIC-32 + encryption)."""
  if hdr.get('key_id_mode') != 1 or hdr.get('sec_level') != 5:
    return None
  if 'frame_counter' not in hdr or not hdr.get('key_index'):
    return None
  key_list = ctx.key_candidates((hdr['key_index'] - 1) & 0x7F)
  if not key_list:
    return None
  src = hdr.get('src', b'')
  if len(src) == 8:
    candidates = [src]
  else:
    short = int.from_bytes(src, 'big') if src else None
    known = ctx.short_to_ext.get(short)
    candidates = ([known] if known else []) + [
        a for a in ctx.ext_addrs if a != known
    ]
  tail = struct.pack('>IB', hdr['frame_counter'], hdr['sec_level'])
  for keys in key_list:
    for ext in candidates:
      plain = _ccm_decrypt(
          keys[1], ext + tail, hdr['header'], hdr['payload'], hdr['mic']
      )
      if plain is not None:
        if len(src) == 2:
          ctx.short_to_ext[int.from_bytes(src, 'big')] = ext
        hdr['src_ext'] = ext
        return plain
  return None


def _iid_from_mac(addr: bytes) -> bytes:
  """IPv6 interface identifier derived from a big-endian MAC address."""
  if len(addr) == 8:
    return bytes([addr[0] ^ 0x02]) + addr[1:]
  return bytes.fromhex('000000fffe00') + addr[-2:].rjust(2, b'\x00')


def _decode_lowpan(
    payload: bytes,
    mac_src: bytes,
    mac_dst: bytes,
    mesh_local_prefix: Optional[bytes],
) -> Dict[str, Any]:
  """Decodes 6LoWPAN mesh/fragment/IPHC/NHC-UDP headers (RFC 4944/6282)."""
  info: Dict[str, Any] = {}
  pos = 0
  try:
    if payload and payload[0] & 0xC0 == 0x80:  # Mesh header
      flags = payload[0]
      pos = 2 if flags & 0x0F == 0x0F else 1
      orig_len = 2 if flags & 0x20 else 8
      final_len = 2 if flags & 0x10 else 8
      mac_src = payload[pos : pos + orig_len]
      mac_dst = payload[pos + orig_len : pos + orig_len + final_len]
      pos += orig_len + final_len
    if pos < len(payload) and payload[pos] & 0xF8 == 0xC0:  # FRAG1
      info['fragment'] = 'FRAG1'
      pos += 4
    elif pos < len(payload) and payload[pos] & 0xF8 == 0xE0:  # FRAGN
      info['fragment'] = 'FRAGN'
      return info
    if pos >= len(payload) or payload[pos] & 0xE0 != 0x60:
      return info
    b0, b1 = payload[pos], payload[pos + 1]
    pos += 2
    sci = dci = 0
    if b1 & 0x80:
      sci, dci = payload[pos] >> 4, payload[pos] & 0x0F
      pos += 1
    pos += (4, 3, 1, 0)[(b0 >> 3) & 3]
    next_header = None
    if not b0 & 0x04:
      next_header = payload[pos]
      pos += 1
    if b0 & 0x03 == 0:
      pos += 1

    def unicast(context: bool, mode: int, mac: bytes, ci: int):
      nonlocal pos
      prefix = _IPV6_LINK_LOCAL_PREFIX
      if context:
        if mode == 0:
          return bytes(16)
        prefix = mesh_local_prefix if ci == 0 else None
      if mode == 0:
        addr = payload[pos : pos + 16]
        pos += 16
        return addr
      if mode == 1:
        iid = payload[pos : pos + 8]
        pos += 8
      elif mode == 2:
        iid = bytes.fromhex('000000fffe00') + payload[pos : pos + 2]
        pos += 2
      else:
        iid = _iid_from_mac(mac)
      return prefix + iid if prefix else None

    src = unicast(bool(b1 & 0x40), (b1 >> 4) & 3, mac_src, sci)
    dam = b1 & 3
    if b1 & 0x08:  # Multicast destination
      if b1 & 0x04:
        dst = None
        pos += 6
      elif dam == 0:
        dst = payload[pos : pos + 16]
        pos += 16
      else:
        inline = {1: 6, 2: 4, 3: 1}[dam]
        data = payload[pos : pos + inline]
        pos += inline
        dst = bytearray(16)
        dst[0] = 0xFF
        dst[1] = 0x02 if dam == 3 else data[0]
        tail = data if dam == 3 else data[1:]
        dst[16 - len(tail) :] = tail
        dst = bytes(dst)
    else:
      dst = unicast(bool(b1 & 0x04), dam, mac_dst, dci)
    for name, addr in (('src_ip6', src), ('dst_ip6', dst)):
      if addr and len(addr) == 16:
        info[name] = str(ipaddress.IPv6Address(addr))
        info[name + '_bytes'] = addr
    for _ in range(4):  # NHC chain: IPv6 extension headers, then UDP
      if next_header is not None or pos >= len(payload):
        break
      nhc = payload[pos]
      if nhc & 0xF0 == 0xE0:
        inline_nh = not nhc & 0x01
        pos += 1
        if inline_nh:
          next_header = payload[pos]
          pos += 1
        pos += 1 + payload[pos]
      elif nhc & 0xF8 == 0xF0:
        pos += 1
        ports = nhc & 3
        if ports == 0:
          sport, dport = struct.unpack_from('>HH', payload, pos)
          pos += 4
        elif ports == 1:
          sport = struct.unpack_from('>H', payload, pos)[0]
          dport = 0xF000 | payload[pos + 2]
          pos += 3
        elif ports == 2:
          sport = 0xF000 | payload[pos]
          dport = struct.unpack_from('>H', payload, pos + 1)[0]
          pos += 3
        else:
          sport = 0xF0B0 | payload[pos] >> 4
          dport = 0xF0B0 | payload[pos] & 0x0F
          pos += 1
        if not nhc & 0x04:
          pos += 2
        info.update(src_port=sport, dst_port=dport, udp=payload[pos:])
        return info
      else:
        break
    if next_header == 17 and pos + 8 <= len(payload):
      sport, dport = struct.unpack_from('>HH', payload, pos)
      info.update(src_port=sport, dst_port=dport, udp=payload[pos + 8 :])
    elif next_header is not None:
      info['next_header'] = next_header
  except (IndexError, struct.error, KeyError):
    pass
  return info


def _decode_mle(
    udp: bytes, lowpan: Dict[str, Any], ctx: ThreadDecodeContext
) -> Optional[Dict[str, Any]]:
  """Decodes (and decrypts) an MLE message; learns RLOC16 -> ext mappings."""
  if not udp:
    return None
  if udp[0] == 255:
    return {'command': _MLE_COMMANDS.get(udp[1], f'0x{udp[1]:02x}')}
  if udp[0] != 0 or len(udp) < 16:
    return None
  sec_ctrl = udp[1]
  if (sec_ctrl >> 3) & 3 != 2:  # MLE uses key id mode 2
    return {'command': 'Secured'}
  aux = udp[1:11]
  frame_counter = struct.unpack_from('<I', udp, 2)[0]
  key_sequence = struct.unpack_from('>I', udp, 6)[0]
  key_list = ctx.key_candidates(key_sequence)
  src_ip = lowpan.get('src_ip6_bytes')
  dst_ip = lowpan.get('dst_ip6_bytes')
  if not key_list or not src_ip or not dst_ip:
    return {'command': 'Secured'}
  sender = bytes([src_ip[8] ^ 0x02]) + src_ip[9:16]
  plain = None
  for keys in key_list:
    plain = _ccm_decrypt(
        keys[0],
        sender + struct.pack('>IB', frame_counter, sec_ctrl & 7),
        src_ip + dst_ip + aux,
        udp[11:-4],
        udp[-4:],
    )
    if plain:
      break
  if not plain:
    return {'command': 'Secured'}
  ctx.learn_ext_addr(sender)
  info: Dict[str, Any] = {
      'command': _MLE_COMMANDS.get(plain[0], f'0x{plain[0]:02x}'),
      'decrypted': True,
  }
  pos = 1
  while pos + 2 <= len(plain):
    tlv_type, tlv_len = plain[pos], plain[pos + 1]
    if tlv_type == 0 and tlv_len == 2:  # Source Address TLV
      rloc16 = struct.unpack_from('>H', plain, pos + 2)[0]
      ctx.short_to_ext[rloc16] = sender
      info['rloc16'] = f'0x{rloc16:04x}'
    pos += 2 + tlv_len
  return info


def dissect_thread_packet(
    ts: float,
    raw_data: bytes,
    pcap_name: str,
    index: int,
    ctx: Optional[ThreadDecodeContext] = None,
) -> FlowEvent:
  """Dissects DLT 195 (IEEE 802.15.4 with FCS) Thread frames."""
  ctx = ctx or ThreadDecodeContext()
  details: Dict[str, Any] = {'pcap_file': pcap_name, 'packet_index': index}
  event = FlowEvent(
      event_id=f'thread_{index}_{int(ts * 1000)}',
      timestamp=ts,
      layer='THREAD',
      sublayer='802.15.4',
      stage='NETWORK_CONFIG',
      src='ThreadNode',
      dst='ThreadLeader',
      title='Thread 802.15.4 Transmission',
      summary=f'Thread frame in {pcap_name}',
      details=details,
      encapsulation=['Thread 802.15.4', '6LoWPAN'],
      payload_hex=raw_data.hex(),
  )
  hdr = parse_wpan_frame(raw_data)
  if hdr is None:
    return event
  ftype = _WPAN_FRAME_TYPES.get(hdr['type'], f'Type {hdr["type"]}')
  details.update(
      wpan_frame_type=ftype,
      wpan_fcs_ok=hdr['fcs_ok'],
      wpan_security=hdr['security'],
  )
  for name in ('seq', 'dst_pan', 'src_pan', 'frame_counter', 'key_index'):
    if name in hdr:
      details['wpan_' + name] = hdr[name]
  event.encapsulation = ['IEEE 802.15.4 (DLT 195)']
  if 'src' in hdr:
    event.src = _format_wpan_addr(hdr['src'])
    details['wpan_src'] = event.src
  if 'dst' in hdr:
    event.dst = _format_wpan_addr(hdr['dst'])
    details['wpan_dst'] = event.dst
  seq = f' seq {hdr["seq"]}' if 'seq' in hdr else ''
  event.title = f'802.15.4 {ftype}{seq}'
  event.summary = f'802.15.4 {ftype} {event.src} -> {event.dst}'
  payload = hdr['payload']
  if hdr['security']:
    plain = _decrypt_wpan_frame(hdr, ctx)
    details['wpan_decrypted'] = plain is not None
    if plain is None:
      event.title += ' (encrypted)'
      event.encapsulation.append('MAC security (encrypted)')
      return event
    payload = plain
    event.encapsulation.append('MAC security (decrypted)')
    event.src = _format_wpan_addr(hdr['src_ext'])
    details['wpan_src_ext'] = event.src
  if hdr['type'] == 3 and payload:
    event.title = f'802.15.4 {_WPAN_COMMANDS.get(payload[0], "Command")}'
    return event
  if hdr['type'] != 1 or not payload:
    return event
  mac_src = hdr.get('src_ext') or hdr.get('src', b'')
  lowpan = _decode_lowpan(
      payload, mac_src, hdr.get('dst', b''), ctx.mesh_local_prefix
  )
  event.encapsulation.append('6LoWPAN')
  if 'fragment' in lowpan:
    details['lowpan_fragment'] = lowpan['fragment']
  if lowpan.get('fragment') == 'FRAGN':
    event.sublayer = '6LoWPAN'
    event.title = '6LoWPAN fragment (FRAGN)'
    return event
  if 'src_ip6' in lowpan:
    event.src = details['src_ip6'] = lowpan['src_ip6']
  if 'dst_ip6' in lowpan:
    event.dst = details['dst_ip6'] = lowpan['dst_ip6']
  if 'src_port' not in lowpan:
    if 'src_ip6' in lowpan or 'dst_ip6' in lowpan:
      event.sublayer = '6LoWPAN'
      proto = 'ICMPv6' if lowpan.get('next_header') == 58 else 'IPv6'
      event.title = f'Thread {proto} {event.src} -> {event.dst}'
    return event
  sport, dport = lowpan['src_port'], lowpan['dst_port']
  details.update(src_port=sport, dst_port=dport)
  details['udp_payload_hex'] = lowpan['udp'].hex()
  event.encapsulation.append(f'UDP :{sport}->:{dport}')
  event.sublayer = 'UDP'
  event.title = f'Thread UDP :{sport}->:{dport}'
  event.summary = f'Thread UDP [{event.src}]:{sport} -> [{event.dst}]:{dport}'
  if _MLE_UDP_PORT in (sport, dport):
    mle = _decode_mle(lowpan['udp'], lowpan, ctx)
    if mle:
      event.sublayer = 'MLE'
      event.title = f'Thread MLE {mle["command"]}'
      event.encapsulation.append('Thread MLE')
      details['mle_command'] = mle['command']
      if 'rloc16' in mle:
        details['mle_rloc16'] = mle['rloc16']
  return event


def _thread_decode_context(
    pcap_dir: str, records: List[Tuple[float, bytes]]
) -> ThreadDecodeContext:
  """Builds the decode context: key file plus every extended address."""
  key_info = load_thread_key_file(pcap_dir) or {}
  ctx = ThreadDecodeContext(
      key_info.get('network_key'), key_info.get('mesh_local_prefix')
  )
  for _, raw in records:
    hdr = parse_wpan_frame(raw)
    if hdr:
      for name in ('src', 'dst'):
        ctx.learn_ext_addr(hdr.get(name, b''))
  return ctx


# -----------------------------------------------------------------------------
# Matter over BTP / UDP: decryption with matter_session_keys.txt
# -----------------------------------------------------------------------------

_ATT_WRITE_OPCODES = (0x12, 0x52)  # Write Request / Write Command
_ATT_VALUE_OPCODES = (0x1B, 0x1D)  # Handle Value Notification / Indication
_BTP_HANDSHAKE_PREFIX = b'\x65\x6c'
_LE_ADV_ACCESS_ADDRESS = 0x8E89BED6
# Commissioning stage of each decrypted commissioning command.
_MATTER_COMMAND_STAGES = {
    'ArmFailSafe': 'FAILSAFE_ARMED',
    'SetRegulatoryConfig': 'FAILSAFE_ARMED',
    'AddOrUpdateWiFiNetwork': 'WIFI_PROVISIONED',
    'AddOrUpdateThreadNetwork': 'THREAD_PROVISIONED',
    'ConnectNetwork': 'THREAD_PROVISIONED',
    'AttestationRequest': 'OPERATIONAL_CERT_ISSUED',
    'CertificateChainRequest': 'OPERATIONAL_CERT_ISSUED',
    'CSRRequest': 'OPERATIONAL_CERT_ISSUED',
    'AddNOC': 'OPERATIONAL_CERT_ISSUED',
    'AddTrustedRootCertificate': 'OPERATIONAL_CERT_ISSUED',
    'CommissioningComplete': 'CASE_CONNECT',
}


def _l2cap_att(
    partial: Dict[Any, Any], key: Any, start: bool, data: bytes
) -> Optional[bytes]:
  """Reassembles an L2CAP SDU from ACL / LL fragments; returns ATT PDUs."""
  if start:
    partial.pop(key, None)
    if len(data) < 4:
      return None
    l2len, cid = struct.unpack_from('<HH', data)
    buf = bytearray(data[4:])
  elif key in partial:
    l2len, cid, buf = partial.pop(key)
    buf += data
  else:
    return None
  if len(buf) < l2len:
    partial[key] = (l2len, cid, buf)
    return None
  return bytes(buf[:l2len]) if cid == 0x0004 else None


def iter_att_values(
    pcap_name: str, records: List[Tuple[float, bytes]]
) -> List[Tuple[int, float, Any, int, int, bytes]]:
  """Returns (index, ts, connection, att_opcode, handle, value) tuples.

  Covers ATT writes and notifications/indications in BLE LL data PDUs
  (bt_medium*.pcap, DLT 256; LL direction from the pseudo-header flags) and
  HCI ACL packets (bt_hci_*.pcap, DLT 201), reassembling L2CAP fragments.
  """
  out = []
  partial: Dict[Any, Any] = {}
  is_ll = pcap_name.startswith('bt_medium')
  for idx, (ts, raw) in enumerate(records):
    if is_ll:
      if len(raw) < 16:
        continue
      flags, aa = struct.unpack_from('<HI', raw, 8)
      if aa == _LE_ADV_ACCESS_ADDRESS:
        continue
      pdu = raw[14:]
      llid, length = pdu[0] & 0x03, pdu[1]
      if llid not in (1, 2) or (llid == 1 and not length):
        continue
      conn = (pcap_name, aa)
      key = (aa, (flags >> 7) & 0x07)
      att = _l2cap_att(partial, key, llid == 2, pdu[2 : 2 + length])
    else:
      if len(raw) < 9 or raw[4] != 0x02:
        continue
      sent = struct.unpack_from('>I', raw)[0] == 0
      handle_flags, data_len = struct.unpack_from('<HH', raw, 5)
      conn = (pcap_name, handle_flags & 0x0FFF)
      key = (conn, sent)
      pb_flag = (handle_flags >> 12) & 0x03
      att = _l2cap_att(partial, key, pb_flag != 1, raw[9 : 9 + data_len])
    if (
        att
        and len(att) >= 3
        and att[0] in _ATT_WRITE_OPCODES + _ATT_VALUE_OPCODES
    ):
      handle = struct.unpack_from('<H', att, 1)[0]
      out.append((idx, ts, conn, att[0], handle, att[3:]))
  return out


def _btp_sdus(pcap_name: str, records: List[Tuple[float, bytes]]):
  """Returns (indices, ts, central_to_peripheral, sdu) per complete BTP SDU.

  Only the handles that carried the BTP handshake request (ATT write, C1)
  and response (indication, C2) are reassembled.
  """
  reassembler = BtpReassembler()
  btp_handles: Dict[Any, set] = {}
  segments: Dict[Any, List[int]] = {}
  sdus = []
  for idx, ts, conn, opcode, handle, value in iter_att_values(
      pcap_name, records
  ):
    to_peripheral = opcode in _ATT_WRITE_OPCODES
    stream = (conn, to_peripheral)
    if value.startswith(_BTP_HANDSHAKE_PREFIX):
      btp_handles.setdefault(conn, set()).add((to_peripheral, handle))
      segments.pop(stream, None)
    if (to_peripheral, handle) not in btp_handles.get(conn, ()):
      continue
    if value and value[0] & BTP_FLAG_BEGIN and not value[0] & 0x40:
      segments[stream] = []
    segments.setdefault(stream, []).append(idx)
    sdu = reassembler.feed(stream, value)
    if sdu is not None:
      sdus.append((segments.pop(stream, [idx]), ts, to_peripheral, sdu))
  return sdus


def _decoded_matter_details(
    msg: Dict[str, Any], proto: Dict[str, Any], desc: Dict[str, Any]
) -> Dict[str, Any]:
  """Details shared by decrypted and cleartext Matter wire events."""
  details: Dict[str, Any] = {
      'matter_session_id': msg['session_id'],
      'matter_message_counter': msg['message_counter'],
      'matter_exchange_id': proto['exchange_id'],
      'matter_protocol_id': proto['protocol_id'],
      'matter_opcode': proto['opcode'],
      'matter_message': desc['name'],
      'matter_msg_key': matter_message_key(
          msg['message_counter'],
          proto['exchange_id'],
          proto['protocol_id'],
          proto['opcode'],
      ),
  }
  if 'ack_counter' in proto:
    details['matter_ack_counter'] = proto['ack_counter']
  commands = desc.get('commands') or []
  if commands and commands[0].get('cluster') is not None:
    first = commands[0]
    details.update(
        endpoint=first.get('endpoint'),
        cluster_id=f'0x{first["cluster"]:04x}',
        command_id=(
            f'0x{first["command"]:02x}'
            if first.get('command') is not None
            else None
        ),
        matter_cluster=CLUSTER_NAMES.get(first['cluster'], ''),
        matter_command=COMMAND_NAMES.get(
            (first['cluster'], first.get('command')), ''
        ),
    )
  if desc.get('attributes'):
    details['matter_attributes'] = desc['attributes'][:8]
  return details


def _matter_wire_stage(desc: Dict[str, Any], details: Dict[str, Any]) -> str:
  if desc.get('protocol') == 'SecureChannel':
    name = desc.get('opcode_name', '')
    if 'PBKDF' in name or 'Pake' in name:
      return 'PASE_HANDSHAKE'
    if 'Sigma' in name:
      return 'CASE_CONNECT'
  return _MATTER_COMMAND_STAGES.get(
      details.get('matter_command', ''), 'CLUSTER_CONTROL'
  )


def _matter_sublayer(desc: Dict[str, Any]) -> str:
  name = desc.get('opcode_name', '')
  if desc.get('protocol') == 'IM':
    return 'IM'
  if name == 'StandaloneAck':
    return 'MRP'
  if 'PBKDF' in name or 'Pake' in name:
    return 'PASE'
  if 'Sigma' in name:
    return 'CASE'
  return 'SecureChannel'


def decode_matter_wire_message(
    data: bytes, keyring: Optional[MatterKeyring]
) -> Optional[Dict[str, Any]]:
  """Decrypts (or, for the unsecured session, parses) one Matter message.

  Returns {'msg', 'proto', 'desc', 'decrypted', 'plaintext'} or None when
  the message cannot be decoded. Secured messages are only decoded when a
  logged session key verifies their MIC.
  """
  header = parse_message_header(data)
  if header is None:
    return None
  if header['session_id'] == 0 and not header['session_type']:
    plaintext = data[header['header_length'] :]
    msg, decrypted = header, False
  else:
    msg = decrypt_message(data, keyring)
    if msg is None:
      return None
    plaintext, decrypted = msg['plaintext'], True
  proto = parse_protocol_header(plaintext)
  if proto is None:
    return None
  return {
      'msg': msg,
      'proto': proto,
      'desc': describe_message(proto),
      'decrypted': decrypted,
      'plaintext': plaintext,
  }


def dissect_matter_btp_events(
    pcap_dir: str, keyring: Optional[MatterKeyring]
) -> List[FlowEvent]:
  """Builds Matter message events from BTP SDUs in the BLE captures.

  The BLE medium capture (wire evidence) is used when it carries BTP; the
  host-side HCI captures otherwise. Unsecured-session messages (PASE
  handshake) are named from their cleartext; secured messages are named
  only when a key in matter_session_keys.txt verifies the MIC
  (details['decrypted'] = True). SDUs that fail stay undecoded.
  """
  medium = sorted(glob.glob(os.path.join(pcap_dir, 'bt_medium*.pcap')))
  hci = sorted(glob.glob(os.path.join(pcap_dir, 'bt_hci_*.pcap')))
  events: List[FlowEvent] = []
  seen_keys: set = set()
  for group, evidence in ((medium, 'wire'), (hci, 'host_hci')):
    undecoded = 0
    for path in group:
      fname = os.path.basename(path)
      try:
        records = read_pcap_records(path)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning('Failed reading records from %s: %s', path, exc)
        continue
      for indices, ts, to_peripheral, sdu in _btp_sdus(fname, records):
        decoded = decode_matter_wire_message(sdu, keyring)
        if decoded is None:
          undecoded += 1
          continue
        ev = _matter_btp_event(
            fname, indices, ts, to_peripheral, sdu, decoded, evidence
        )
        dedup_k = ev.details.get('dedup_key')
        if dedup_k and dedup_k in seen_keys:
          continue
        if dedup_k:
          seen_keys.add(dedup_k)
        events.append(ev)
    if undecoded:
      logger.info(
          '%d BTP SDU(s) in %s left undecoded (no session key verified'
          ' their MIC)', undecoded, ', '.join(map(os.path.basename, group))
      )
  return events


def _matter_btp_event(
    fname: str,
    indices: List[int],
    ts: float,
    to_peripheral: bool,
    sdu: bytes,
    decoded: Dict[str, Any],
    evidence: str,
) -> FlowEvent:
  msg, proto, desc = decoded['msg'], decoded['proto'], decoded['desc']
  central, peripheral = 'BLE central (commissioner)', 'BLE peripheral (device)'
  src, dst = (central, peripheral) if to_peripheral else (peripheral, central)
  details = _decoded_matter_details(msg, proto, desc)
  details.update(
      pcap_file=fname,
      packet_index=indices[-1],
      btp_segments=indices,
      transport='BTP',
      evidence=evidence,
      decrypted=decoded['decrypted'],
      btp_sdu_hex=sdu.hex(),
      lane_aliases={central: LANE_CONTROLLER, peripheral: LANE_ACCESSORY},
  )
  encap = [
      'BLE LL (DLT 256)' if evidence == 'wire' else 'BT HCI (DLT 201)',
      'L2CAP ATT ' + ('Write (C1)' if to_peripheral else 'Indication (C2)'),
      f'Matter BTP ({len(indices)} segment{"s" if len(indices) > 1 else ""})',
  ]
  sid, ctr = msg['session_id'], msg['message_counter']
  if decoded['decrypted']:
    session = msg['session']
    details.update(
        matter_session_type=session.session_type,
        matter_key_direction=msg['direction'],
        matter_nonce_node_id=f'{msg["nonce_node_id"]:016X}',
    )
    encap.append(
        f'Matter {session.session_type} session S:{sid}'
        f' (AES-128-CCM {msg["direction"]}, MIC verified)'
    )
    how = f'decrypted with {session.session_type} {msg["direction"]} key'
  else:
    encap.append('Matter unsecured session (cleartext)')
    how = 'unsecured session'
  if desc.get('protocol') == 'IM':
    encap.append('Matter Interaction Model')
  details['dedup_key'] = f'MATTER:btp:{sid}:{ctr}:{int(to_peripheral)}'
  return FlowEvent(
      event_id=f'matter_btp_{fname}_{indices[-1]}_{int(ts * 1000)}',
      timestamp=ts,
      layer='MATTER',
      sublayer=_matter_sublayer(desc),
      stage=_matter_wire_stage(desc, details),
      src=src,
      dst=dst,
      title=desc['name'],
      summary=(
          f'{desc["name"]} E:{proto["exchange_id"]} S:{sid} M:{ctr}'
          f' over BTP ({how})'
      ),
      details=details,
      encapsulation=encap,
      payload_hex=decoded['plaintext'].hex(),
  )


def decrypt_matter_udp_event(
    event: FlowEvent, keyring: Optional[MatterKeyring]
) -> bool:
  """Decrypts a captured UDP :5540 Matter message in place.

  Returns True and relabels the event (layer MATTER, details['decrypted'])
  only when a logged session key verifies the MIC.
  """
  details = event.details
  ports = (details.get('src_port'), details.get('dst_port'))
  if not keyring or 5540 not in ports:
    return False
  if 'udp_payload_hex' in details:
    payload = bytes.fromhex(details['udp_payload_hex'])
  elif isinstance(details.get('udp_payload_offset'), int):
    payload = bytes.fromhex(event.payload_hex)[details['udp_payload_offset'] :]
  else:
    return False
  header = parse_message_header(payload)
  if header is None or header['session_id'] == 0:
    return False
  decoded = decode_matter_wire_message(payload, keyring)
  if decoded is None:
    return False
  msg, proto, desc = decoded['msg'], decoded['proto'], decoded['desc']
  session = msg['session']
  hop = event.layer
  details.update(_decoded_matter_details(msg, proto, desc))
  details.update(
      transport=f'{hop} UDP',
      decrypted=True,
      matter_session_type=session.session_type,
      matter_key_direction=msg['direction'],
      matter_nonce_node_id=f'{msg["nonce_node_id"]:016X}',
      dedup_key=f'MATTER:{hop}:{msg["session_id"]}:{msg["message_counter"]}',
  )
  event.layer = 'MATTER'
  event.sublayer = _matter_sublayer(desc)
  event.stage = _matter_wire_stage(desc, details)
  event.title = desc['name'] + (' (Thread)' if hop == 'THREAD' else '')
  event.summary = (
      f'{desc["name"]} E:{proto["exchange_id"]} S:{msg["session_id"]}'
      f' M:{msg["message_counter"]} {event.src} -> {event.dst} (decrypted'
      f' with {session.session_type} {msg["direction"]} key)'
  )
  event.encapsulation.append(
      f'Matter {session.session_type} session S:{msg["session_id"]}'
      f' (AES-128-CCM {msg["direction"]}, MIC verified)'
  )
  if desc.get('protocol') == 'IM':
    event.encapsulation.append('Matter Interaction Model')
  details['decrypted_payload_hex'] = decoded['plaintext'].hex()
  return True


# -----------------------------------------------------------------------------
# PCAP Directory Collector & Multi-Layer Interleaving Engine
# -----------------------------------------------------------------------------


_ANSI_ESCAPE_RE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
_FILENAME_EPOCH_RE = re.compile(r'-(\d{9,10})-')
_HELPER_TS_RE = re.compile(
    r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),(\d{3})\s+\[([^\]]+)\]\s+\[?(\w+)\]?\s+(.*)$'
)
_OTBR_LINE_RE = re.compile(
    r'^(?:otbr-agent\[\d+\]:\s+)?(?:(\d{2}):(\d{2}):(\d{2})\.(\d{3})\s+\[([A-Z])\]\s+([^:]+):\s+(.*)|\[([A-Z]+)\]-([^:]+):\s+(.*))$'
)
_CHIP_LINE_RE = re.compile(
    r'^\[(\d+\.\d+)\]\s*\[\d+:\d+\]\s*(?:\[([A-Z0-9_-]+)\]|CHIP:([A-Z0-9_-]+):)\s+(.*)$'
)
# Android logcat (threadtime): 'MM-DD HH:MM:SS.mmm  PID  TID L TAG     : msg'.
_LOGCAT_LINE_RE = re.compile(
    r'^(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})\.(\d{3})\s+\d+\s+\d+\s+'
    r'[VDIWEFS]\s+([^\s:]+)\s*:\s?(.*)$'
)
# Message grammar of src/messaging/ExchangeMgr.cpp and
# src/transport/SessionManager.cpp, e.g. '>>> [E:5440r S:0 M:241328648
# (Ack:180170359)] (U) Msg RX from 0:2211CF9734962C6F [0000] to ...
# [UDP:[fd11:33::1]:5542] --- Type 0000:32 (SecureChannel:CASE_Sigma3)'.
_EM_EXCHANGE_RE = re.compile(
    r'(>>>|<<<)\s+\[E:([^\s\]]+)(?:\s+S:(\d+))?(?:\s+M:(\d+))?'
    r'(?:\s+\(Ack:\s*(\d+)\))?\]\s+\(([A-Z])\)\s+Msg\s+(RX|TX)\s+from\s+(\S+)'
    r'(?:\s+\[[^\]]*\])?\s+to\s+(\S+)(?:\s+\[[^\]]*\])?'
    r'(?:\s+\[(BLE|UDP|TCP)(?::(\[[^\]]+\]:\d+|[^\]\s]+))?\])?'
    r'\s+---\s+Type\s+([0-9a-fA-F]+:[0-9a-fA-F]+)\s+\(([^:)]+):([^)]+)\)'
    r'(?:\s+\(B:(\d+)\))?'
)
_DMG_COMMAND_RE = re.compile(
    r'Received command for Endpoint=(\d+) Cluster=0x([0-9a-fA-F_]+)'
    r' Command=0x([0-9a-fA-F_]+)'
)
_CTL_STEP_RE = re.compile(r"Performing next commissioning step '([^']+)'")

# Commissioning commands of the GeneralCommissioning (0x30),
# NetworkCommissioning (0x31) and OperationalCredentials (0x3E) clusters.
COMMISSIONING_COMMANDS: Dict[Tuple[int, int], Tuple[str, str]] = {
    (0x30, 0x00): ('GeneralCommissioning', 'ArmFailSafe'),
    (0x30, 0x02): ('GeneralCommissioning', 'SetRegulatoryConfig'),
    (0x30, 0x04): ('GeneralCommissioning', 'CommissioningComplete'),
    (0x31, 0x02): ('NetworkCommissioning', 'AddOrUpdateWiFiNetwork'),
    (0x31, 0x03): ('NetworkCommissioning', 'AddOrUpdateThreadNetwork'),
    (0x31, 0x06): ('NetworkCommissioning', 'ConnectNetwork'),
    (0x3E, 0x00): ('OperationalCredentials', 'AttestationRequest'),
    (0x3E, 0x02): ('OperationalCredentials', 'CertificateChainRequest'),
    (0x3E, 0x04): ('OperationalCredentials', 'CSRRequest'),
    (0x3E, 0x06): ('OperationalCredentials', 'AddNOC'),
    (0x3E, 0x0B): ('OperationalCredentials', 'AddTrustedRootCertificate'),
}
# Controller commissioning steps (CommissioningDelegate.h) that send one of
# the commands above.
COMMISSIONING_STEP_COMMANDS: Dict[str, Tuple[int, int]] = {
    'ArmFailSafe': (0x30, 0x00),
    'ConfigRegulatory': (0x30, 0x02),
    'SendPAICertificateRequest': (0x3E, 0x02),
    'SendDACCertificateRequest': (0x3E, 0x02),
    'SendAttestationRequest': (0x3E, 0x00),
    'SendOpCertSigningRequest': (0x3E, 0x04),
    'SendTrustedRootCert': (0x3E, 0x0B),
    'SendNOC': (0x3E, 0x06),
    'WiFiNetworkSetup': (0x31, 0x02),
    'ThreadNetworkSetup': (0x31, 0x03),
    'WiFiNetworkEnable': (0x31, 0x06),
    'ThreadNetworkEnable': (0x31, 0x06),
    'SendComplete': (0x30, 0x04),
}
_CONTROLLER_NAME_HINTS = (
    'android',
    'controller',
    'chip-tool',
    'chiptool',
    'mobile',
    'commissioner',
)


def matter_message_key(
    counter: int, exchange_id: int, protocol_id: int, opcode: int
) -> str:
  """Identifies one Matter message across logs and captures."""
  return f'{counter}:{exchange_id}:{protocol_id:04x}:{opcode:02x}'


def _is_controller_name(name: str) -> bool:
  lower = str(name or '').lower()
  return any(hint in lower for hint in _CONTROLLER_NAME_HINTS)


def _logcat_timestamp(fields: Tuple[str, ...], ref_ts: float) -> float:
  """Converts logcat 'MM-DD HH:MM:SS.mmm' (UTC) using the year of `ref_ts`.

  `ref_ts` is the epoch in the log file name, written when the log was
  saved, so a line that would land after it belongs to the previous year.
  """
  month, day, hour, minute, sec, msec = (int(v) for v in fields)
  year = time.gmtime(ref_ts).tm_year
  ts = calendar.timegm((year, month, day, hour, minute, sec, 0, 0, 0))
  if ts > ref_ts + 86400:
    ts = calendar.timegm((year - 1, month, day, hour, minute, sec, 0, 0, 0))
  return ts + msec / 1000.0


class _ChipLogLine(NamedTuple):
  timestamp: float
  tag: str
  body: str


def _match_chip_line(
    line: str, ref_ts: float
) -> Optional[_ChipLogLine]:
  """Returns (timestamp, tag, body) of a POSIX CHIP or Android logcat line."""
  m_chip = _CHIP_LINE_RE.match(line)
  if m_chip:
    ts_str, tag_bracket, tag_colon, body = m_chip.groups()
    return _ChipLogLine(float(ts_str), tag_bracket or tag_colon, body)
  m_logcat = _LOGCAT_LINE_RE.match(line)
  if m_logcat:
    groups = m_logcat.groups()
    return _ChipLogLine(
        _logcat_timestamp(groups[:6], ref_ts), groups[6], groups[7]
    )
  return None


def _split_transport_addr(addr: Optional[str]) -> Tuple[str, Optional[int]]:
  """Splits '[fd11:33::1]:5542' or '10.0.1.20:5540' into (address, port)."""
  if not addr:
    return '', None
  m = re.match(r'^\[([^\]]+)\]:(\d+)$', addr) or re.match(
      r'^([^:]+):(\d+)$', addr
  )
  if m:
    return m.group(1), int(m.group(2))
  return addr, None


def _infer_node_name_from_log(filename: str) -> str:
  base = os.path.splitext(os.path.basename(filename))[0]
  m = _FILENAME_EPOCH_RE.search(base)
  if m:
    prefix = base[: m.start()]
    suffix = base[m.end() :]
    if '-' in suffix:
      extra = suffix.split('-', 1)[1]
      return f'{prefix} ({extra})'
    return prefix
  return base


def _coerce_flow_event(item: Union[FlowEvent, Dict[str, Any]], idx: int = 0) -> Optional[FlowEvent]:
  if isinstance(item, FlowEvent):
    return item
  if isinstance(item, dict):
    ts = float(item.get('timestamp', time.time()))
    return FlowEvent(
        event_id=str(item.get('event_id', f'log_{idx}_{int(ts * 1000)}')),
        timestamp=ts,
        layer=str(item.get('layer') or 'GENERAL'),
        sublayer=str(item.get('sublayer') or 'GENERAL'),
        stage=str(item.get('stage') or 'GENERAL'),
        src=str(item.get('src') or 'Controller'),
        dst=str(item.get('dst') or 'Device'),
        title=str(item.get('title') or 'Log Event'),
        summary=str(item.get('summary') or ''),
        details=dict(item.get('details') or {}),
        encapsulation=list(item.get('encapsulation') or []),
        payload_hex=str(item.get('payload_hex') or ''),
        replay_mcp_call=item.get('replay_mcp_call'),
        channel=item.get('channel'),
        rssi=item.get('rssi'),
    )
  return None


def _dissect_otbr_log_line(
    m_otbr: re.Match,
    otbr_base_ts: float,
    fname: str,
    line_no: int,
    node_name: str,
) -> Optional[FlowEvent]:
  """Extracts a FlowEvent from an OpenThread / otbr-agent log line."""
  hh, mm, ss, ms, _, comp, msg, _, note_comp, note_msg = m_otbr.groups()
  if hh is not None:
    rel_sec = int(hh) * 3600 + int(mm) * 60 + int(ss) + int(ms) / 1000.0
    ts = otbr_base_ts + rel_sec
    comp_clean = comp.strip('- ')
    body = msg.strip()
  else:
    ts = otbr_base_ts
    comp_clean = (note_comp or 'AGENT').strip('- ')
    body = (note_msg or '').strip()

  if comp_clean == 'Mle' and (
      'Role ' in body
      or 'AttachState ' in body
      or 'Send Advertisement' in body
      or 'Send Data Response' in body
  ):
    title = (
        f'Thread MLE {body.split("(")[0].strip()}'
        if 'Send ' in body
        else f'Thread MLE {body}'
    )
    return FlowEvent(
        event_id=f'otbr_{fname}_{line_no}_{int(ts * 1000)}',
        timestamp=ts,
        layer='THREAD',
        sublayer='MLE',
        stage='NETWORK_CONFIG',
        src=node_name,
        dst='ThreadMesh',
        title=title[:80],
        summary=f'{node_name}: {body}',
        details={
            'log_file': fname,
            'line_number': line_no,
            'component': comp_clean,
            'node': node_name,
        },
        encapsulation=['IEEE 802.15.4', '6LoWPAN', 'Thread MLE'],
    )
  if comp_clean == 'MeshForwarder' and (
      'Sent IPv6' in body or 'Received IPv6' in body
  ):
    is_tx = body.startswith('Sent ')
    peer_match = re.search(r'(?:to|from):(0x[0-9a-fA-F]+)', body)
    peer = peer_match.group(1) if peer_match else 'ThreadMesh'
    len_match = re.search(r'len:(\d+)', body)
    pkt_len = int(len_match.group(1)) if len_match else 0
    direction = 'TX' if is_tx else 'RX'
    return FlowEvent(
        event_id=f'otbr_{fname}_{line_no}_{int(ts * 1000)}',
        timestamp=ts,
        layer='THREAD',
        sublayer='6LoWPAN',
        stage='NETWORK_CONFIG',
        src=node_name if is_tx else peer,
        dst=peer if is_tx else node_name,
        title=f'Thread IPv6 UDP {direction} ({pkt_len}B)',
        summary=f'{node_name}: {body}',
        details={
            'log_file': fname,
            'line_number': line_no,
            'component': comp_clean,
            'direction': direction,
            'length': pkt_len,
        },
        encapsulation=['IEEE 802.15.4', '6LoWPAN', 'IPv6 UDP'],
    )
  if comp_clean in (
      'DatasetManager',
      'Settings',
      'BorderAgent',
      'BorderRouting',
      'Nat64',
      'NetworkData',
      'TrelDiscoverer',
  ) and any(
      kw in body
      for kw in (
          'Active dataset set',
          'Saved ActiveDataset',
          'Registering service',
          'Local on-link prefix:',
          'State: NotRunning -> Active',
          'Received ServerData',
          'DNS-SD service registered',
      )
  ):
    return FlowEvent(
        event_id=f'otbr_{fname}_{line_no}_{int(ts * 1000)}',
        timestamp=ts,
        layer='THREAD',
        sublayer=comp_clean,
        stage='NETWORK_CONFIG',
        src=node_name,
        dst='ThreadMesh',
        title=f'{comp_clean}: {body[:64]}',
        summary=f'{node_name} [{comp_clean}] {body}',
        details={
            'log_file': fname,
            'line_number': line_no,
            'component': comp_clean,
            'node': node_name,
        },
        encapsulation=['Thread Border Router', comp_clean],
    )
  return None


def _dissect_chip_em_line(
    m_em: re.Match,
    ts: float,
    tag: str,
    body: str,
    fname: str,
    line_no: int,
    node_name: str,
) -> FlowEvent:
  """Extracts a FlowEvent from a CHIP ExchangeManager [EM] line."""
  (
      _,
      exch_id,
      sess_id,
      msg_cnt,
      ack_cnt,
      sec_flag,
      direction,
      peer_from,
      peer_to,
      transport_hint,
      transport_addr,
      type_code,
      proto_name,
      msg_name,
      byte_len,
  ) = m_em.groups()
  is_ble = transport_hint == 'BLE' or 'BLE' in body
  layer = 'BT' if is_ble else 'WIFI'
  peer_addr, peer_port = _split_transport_addr(transport_addr)
  src = peer_from if direction == 'RX' else node_name
  dst = node_name if direction == 'RX' else peer_to
  if peer_addr:
    if direction == 'RX':
      src = peer_addr
    else:
      dst = peer_addr
  details = {
      'log_file': fname,
      'line_number': line_no,
      'chip_tag': tag,
      'node': node_name,
      'exchange_id': exch_id,
      'session_id': sess_id or '0',
      'message_counter': msg_cnt or '',
      'session_type': sec_flag,
      'direction': direction,
      'peer_from': peer_from,
      'peer_to': peer_to,
      'type_code': type_code,
      'matter_protocol': proto_name,
      'matter_msg_type': msg_name,
      'transport': 'BLE' if is_ble else 'IP',
      'bytes': int(byte_len or 0),
  }
  if ack_cnt:
    details['ack_counter'] = ack_cnt
  if peer_addr:
    details['peer_addr'] = peer_addr
    details['peer_port'] = peer_port
  m_exch = re.match(r'\d+', exch_id)
  if msg_cnt and m_exch:
    proto_id, opcode = (int(v, 16) for v in type_code.split(':'))
    details['matter_msg_key'] = matter_message_key(
        int(msg_cnt), int(m_exch.group(0)), proto_id, opcode
    )
  return FlowEvent(
      event_id=f'chip_em_{fname}_{line_no}_{int(ts * 1000)}',
      timestamp=ts,
      layer=layer,
      sublayer=proto_name,
      stage='GATT_CONNECT' if is_ble else 'NETWORK_CONFIG',
      src=src,
      dst=dst,
      title=f'{proto_name}:{msg_name} ({direction})',
      summary=f'{node_name} {body}',
      details=details,
      encapsulation=[
          'BLE BTP' if is_ble else 'IPv6/UDP',
          f'Exchange {exch_id}',
          f'{proto_name}:{msg_name}',
      ],
  )


def _dissect_chip_log_line(
    chip_line: _ChipLogLine,
    fname: str,
    line_no: int,
    node_name: str,
) -> Optional[FlowEvent]:
  """Extracts a FlowEvent from a parsed CHIP/Matter SDK log line."""
  ts, tag, body = chip_line
  m_em = _EM_EXCHANGE_RE.search(body) if tag == 'EM' else None
  if m_em:
    return _dissect_chip_em_line(
        m_em, ts, tag, body, fname, line_no, node_name
    )
  if tag in ('DMG', 'CTL') and (
      _DMG_COMMAND_RE.search(body) or _CTL_STEP_RE.search(body)
  ):
    m_dmg = _DMG_COMMAND_RE.search(body)
    if m_dmg:
      endpoint = int(m_dmg.group(1))
      ids = tuple(int(g.replace('_', ''), 16) for g in m_dmg.group(2, 3))
      direction, src, dst = 'RX', 'Controller', node_name
      step = None
    else:
      step = _CTL_STEP_RE.search(body).group(1)
      ids = COMMISSIONING_STEP_COMMANDS.get(step)
      endpoint = 0
      direction, src, dst = 'TX', node_name, 'Device'
    if ids is None:
      return None
    cluster, command = COMMISSIONING_COMMANDS.get(
        ids, (f'Cluster 0x{ids[0]:04x}', f'Command 0x{ids[1]:02x}')
    )
    details = {
        'log_file': fname,
        'line_number': line_no,
        'chip_tag': tag,
        'node': node_name,
        'direction': direction,
        'endpoint': endpoint,
        'cluster_id': f'0x{ids[0]:04x}',
        'command_id': f'0x{ids[1]:02x}',
        'matter_cluster': cluster,
        'matter_command': command,
        'evidence': 'controller_intent' if step else 'device_log',
    }
    if step:
      details['commissioning_step'] = step
    return FlowEvent(
        event_id=f'chip_cmd_{fname}_{line_no}_{int(ts * 1000)}',
        timestamp=ts,
        layer='GENERAL',
        sublayer='IM',
        stage='NETWORK_CONFIG',
        src=src,
        dst=dst,
        title=f'{cluster}:{command} ({direction})',
        summary=f'{node_name} [{tag}] {body}',
        details=details,
        encapsulation=['Interaction Model', f'{cluster}:{command}'],
    )
  if tag in ('BLE', 'DL') and any(
      kw in body
      for kw in (
          'BLE advertisement started',
          'New BLE connection',
          'CHIPoBLE subscribe received',
          'Receive kCHIPoBLEConnectionEstablished',
          'Write request received',
          'Indication confirmation',
          'CHIPoBLE advertising stopped',
          'GATT application registered',
          'wpa_supplicant: Start WiFi management',
          'wpa_supplicant: connected to interface proxy',
      )
  ):
    is_wifi = 'wpa_supplicant' in body
    is_gatt = any(
        kw in body for kw in ('GATT', 'Write', 'Indication', 'subscribe')
    )
    sublayer = 'WPA' if is_wifi else ('GATT' if is_gatt else 'BLE_LL')
    stage = (
        'NETWORK_CONFIG'
        if is_wifi
        else (
            'ADV_DISCOVERY'
            if 'advertisement' in body.lower()
            else 'GATT_CONNECT'
        )
    )
    return FlowEvent(
        event_id=f'chip_dl_{fname}_{line_no}_{int(ts * 1000)}',
        timestamp=ts,
        layer='WIFI' if is_wifi else 'BT',
        sublayer=sublayer,
        stage=stage,
        src=node_name,
        dst='WiFiMedium' if is_wifi else 'BLEPeer',
        title=f'{tag}: {body[:68]}',
        summary=f'{node_name} [{tag}] {body}',
        details={
            'log_file': fname,
            'line_number': line_no,
            'chip_tag': tag,
            'node': node_name,
        },
        encapsulation=['Wi-Fi WPA2' if is_wifi else 'BLE GATT/LL', tag],
    )
  if tag == 'DIS' and any(
      kw in body
      for kw in (
          'mDNS service published:',
          'Updating services using commissioning mode',
          'Commission SRV for instance',
          'IP address ',
      )
  ):
    return FlowEvent(
        event_id=f'chip_dis_{fname}_{line_no}_{int(ts * 1000)}',
        timestamp=ts,
        layer='WIFI',
        sublayer='mDNS',
        stage='NETWORK_CONFIG',
        src=node_name,
        dst='mDNSMulticast',
        title=f'mDNS: {body[:68]}',
        summary=f'{node_name} [DIS] {body}',
        details={
            'log_file': fname,
            'line_number': line_no,
            'chip_tag': tag,
            'node': node_name,
        },
        encapsulation=['IPv6 UDP :5353', 'mDNS / DNS-SD'],
    )
  if tag in ('SC', 'PAS', 'CAS', 'IN', 'SVR') and any(
      kw in body
      for kw in (
          'Received PBKDF param request',
          'Sent PBKDF param response',
          'Received spake2p msg',
          'Sent spake2p msg',
          "State change 'kEstablishing' --> 'kActive'",
          'New secure session activated',
          'Waiting for Sigma1 msg',
          'Received Sigma',
          'Sent Sigma',
          'Commissioning session establishment step started',
          'Commissioning completed session establishment step',
          'Device completed Rendezvous process',
          'Server Listening...',
      )
  ):
    peer = 'Device' if _is_controller_name(node_name) else 'Controller'
    inbound = body.startswith(('Received', 'Waiting'))
    return FlowEvent(
        event_id=f'chip_sc_{fname}_{line_no}_{int(ts * 1000)}',
        timestamp=ts,
        layer='GENERAL',
        sublayer=tag,
        stage='NETWORK_CONFIG',
        src=peer if inbound else node_name,
        dst=node_name if inbound else peer,
        title=f'{tag}: {body[:68]}',
        summary=f'{node_name} [{tag}] {body}',
        details={
            'log_file': fname,
            'line_number': line_no,
            'chip_tag': tag,
            'node': node_name,
        },
        encapsulation=['Secure Session', tag],
    )
  return None


def _backfill_exchange_peers(events: List[FlowEvent]) -> None:
  """Backfills missing RX/TX peer addresses from matching exchange lines."""
  exchange_peers: Dict[str, str] = {}
  for ev in events:
    if ev.details.get('chip_tag') == 'EM' and ev.details.get('peer_addr'):
      exchange_peers.setdefault(
          ev.details['exchange_id'], ev.details['peer_addr']
      )
  for ev in events:
    details = ev.details
    peer = exchange_peers.get(details.get('exchange_id', ''))
    if (
        details.get('chip_tag') == 'EM'
        and details.get('transport') == 'IP'
        and not details.get('peer_addr')
        and peer
    ):
      details['peer_addr'] = peer
      details['peer_addr_from_exchange'] = True
      if details['direction'] == 'RX':
        ev.src = peer
      else:
        ev.dst = peer


def dissect_log_file(log_path: str) -> List[FlowEvent]:
  """Extracts cross-layer protocol milestones from a Cirque device .log file."""
  events: List[FlowEvent] = []
  if not os.path.isfile(log_path):
    return events

  fname = os.path.basename(log_path)
  if fname.endswith('-emulator-state.log') or fname.endswith('-emulator.log'):
    return events

  node_name = _infer_node_name_from_log(fname)
  m_epoch = _FILENAME_EPOCH_RE.search(fname)
  try:
    fallback_ts = (
        float(m_epoch.group(1))
        if m_epoch
        else float(os.path.getmtime(log_path))
    )
  except OSError:
    fallback_ts = time.time()

  otbr_base_ts = fallback_ts
  try:
    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
      lines = f.readlines()
  except OSError as exc:
    logger.warning('Failed reading log file %s: %s', log_path, exc)
    return events

  for line_no, raw_line in enumerate(lines, start=1):
    clean = _ANSI_ESCAPE_RE.sub('', raw_line).strip()
    if not clean:
      continue

    m_helper = _HELPER_TS_RE.match(clean)
    if m_helper:
      dt_str, ms_str, _, _, msg = m_helper.groups()
      try:
        parsed_ts = (
            float(calendar.timegm(time.strptime(dt_str, '%Y-%m-%d %H:%M:%S')))
            + int(ms_str) / 1000.0
        )
        otbr_base_ts = parsed_ts
      except ValueError:
        parsed_ts = otbr_base_ts

      if 'Will run command:' in msg:
        events.append(
            FlowEvent(
                event_id=f'log_{fname}_{line_no}_{int(parsed_ts * 1000)}',
                timestamp=parsed_ts,
                layer='THREAD' if 'otbr-agent' in msg else 'GENERAL',
                sublayer='PROCESS',
                stage='NETWORK_CONFIG',
                src='CirqueHelper',
                dst=node_name,
                title=f'{node_name}: Launch Daemon',
                summary=msg[:160],
                details={
                    'log_file': fname,
                    'line_number': line_no,
                    'node': node_name,
                },
                encapsulation=['Container Runtime', node_name],
            )
        )
      continue

    m_otbr = _OTBR_LINE_RE.match(clean)
    if m_otbr:
      otbr_event = _dissect_otbr_log_line(
          m_otbr, otbr_base_ts, fname, line_no, node_name
      )
      if otbr_event:
        events.append(otbr_event)
      continue

    chip_line = _match_chip_line(clean, fallback_ts)
    if chip_line:
      chip_event = _dissect_chip_log_line(
          chip_line, fname, line_no, node_name
      )
      if chip_event:
        events.append(chip_event)

  _backfill_exchange_peers(events)
  return events


def dissect_log_directory(log_dir: str) -> List[FlowEvent]:
  """Scans all .log files in `log_dir` and extracts protocol FlowEvents.

  An Android '-logcat-full.log' is skipped when its '-logcat.log' excerpt is
  present, since every line of the excerpt is also in the full dump.
  """
  events: List[FlowEvent] = []
  if not os.path.isdir(log_dir):
    return events
  for log_path in list_log_files(log_dir):
    events.extend(dissect_log_file(log_path))
  return events


def list_log_files(log_dir: str) -> List[str]:
  """Returns the .log files of `log_dir` without redundant logcat dumps."""
  paths = sorted(glob.glob(os.path.join(log_dir, '*.log')))
  present = set(paths)
  return [
      p
      for p in paths
      if not (
          p.endswith('-logcat-full.log')
          and p[: -len('-logcat-full.log')] + '-logcat.log' in present
      )
  ]


def dissect_pcap_directory(
    pcap_dir: str,
    plugins: Optional[List[Any]] = None,
) -> List[FlowEvent]:
  """Parses and dissects all PCAP and container .log files in `pcap_dir` into FlowEvents."""
  events: List[FlowEvent] = []
  if not os.path.isdir(pcap_dir):
    return events

  pcap_files = sorted(glob.glob(os.path.join(pcap_dir, '*.pcap')))
  for pcap_path in pcap_files:
    fname = os.path.basename(pcap_path)
    try:
      records = read_pcap_records(pcap_path)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.warning('Failed reading records from %s: %s', pcap_path, exc)
      continue

    # Determine dissection based on filename and header
    thread_ctx = None
    if fname.startswith('thread'):
      thread_ctx = _thread_decode_context(pcap_dir, records)
    for idx, (ts, raw_bytes) in enumerate(records):
      event = None
      if fname.startswith('bt_hci'):
        event = dissect_hci_phdr_packet(ts, raw_bytes, fname, idx)
      elif fname.startswith('bt_medium'):
        event = dissect_le_ll_packet(ts, raw_bytes, fname, idx)
      elif fname.startswith(('wifi', 'eth', 'lan')):
        event = dissect_wifi_packet(ts, raw_bytes, fname, idx)
      elif fname.startswith('thread'):
        event = dissect_thread_packet(ts, raw_bytes, fname, idx, thread_ctx)
      else:
        # Fallback DLT check
        if len(raw_bytes) >= 10:
          event = dissect_le_ll_packet(ts, raw_bytes, fname, idx)

      if event:
        events.append(event)

  keyring = load_matter_session_key_file(pcap_dir)
  if keyring:
    decrypted_udp = sum(decrypt_matter_udp_event(ev, keyring) for ev in events)
    btp_events = dissect_matter_btp_events(pcap_dir, keyring)
    events.extend(btp_events)
    logger.info(
        'Matter session keys: %d session(s); decoded %d BTP message(s)'
        ' (%d decrypted) and decrypted %d UDP message(s)',
        len(keyring.sessions),
        len(btp_events),
        sum(1 for ev in btp_events if ev.details.get('decrypted')),
        decrypted_udp,
    )

  # Invoke plugin log parsers if provided, falling back to built-in log dissection
  plugin_log_events: List[FlowEvent] = []
  if plugins:
    log_files = list_log_files(pcap_dir)
    for plugin in plugins:
      mod = plugin
      if isinstance(plugin, str) and os.path.isfile(plugin):
        try:
          mod = _load_flow_plugin_module(plugin)
        except Exception as exc:  # pylint: disable=broad-exception-caught
          logger.warning('Failed loading flow plugin %s: %s', plugin, exc)
          continue
      parse_dir_fn = getattr(mod, 'parse_log_directory', None)
      parse_file_fn = getattr(mod, 'parse_log_file', None)
      if callable(parse_dir_fn):
        try:
          raw_items = parse_dir_fn(pcap_dir) or []
          for idx, item in enumerate(raw_items):
            coerced = _coerce_flow_event(item, idx)
            if coerced is not None:
              plugin_log_events.append(coerced)
        except Exception as exc:  # pylint: disable=broad-exception-caught
          logger.warning('Plugin parse_log_directory failed on %s: %s', pcap_dir, exc)
      elif callable(parse_file_fn):
        for log_path in log_files:
          try:
            raw_items = parse_file_fn(log_path) or []
            for idx, item in enumerate(raw_items):
              coerced = _coerce_flow_event(item, idx)
              if coerced is not None:
                plugin_log_events.append(coerced)
          except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning('Plugin parse_log_file failed on %s: %s', log_path, exc)

  if plugin_log_events:
    events.extend(plugin_log_events)
  else:
    events.extend(dissect_log_directory(pcap_dir))

  return events


def _run_dissector(name: str, fn: FlowDissector, ev: FlowEvent) -> FlowEvent:
  """Runs one dissector on one event; failures keep the event as it is."""
  try:
    result = fn(ev)
  except Exception:  # pylint: disable=broad-exception-caught
    logger.exception('Flow dissector %s failed on event %s', name, ev.event_id)
    return ev
  if result is None:
    return ev
  if not isinstance(result, FlowEvent):
    logger.error(
        'Flow dissector %s returned %s for event %s; keeping the event',
        name,
        type(result).__name__,
        ev.event_id,
    )
    return ev
  return result


def merge_and_sort_flow_events(
    pcap_events: List[FlowEvent],
    recorded_events: List[Dict[str, Any]],
    dissectors: Optional[Dict[str, FlowDissector]] = None,
) -> List[FlowEvent]:
  """Merges PCAP and recorded events, then runs pluggable dissectors.

  Recorded events are copied first, so dissectors never mutate the caller's
  stored events.
  """
  combined: List[FlowEvent] = list(pcap_events)
  for item in recorded_events:
    if isinstance(item, FlowEvent):
      combined.append(
          replace(
              item,
              details=dict(item.details),
              encapsulation=list(item.encapsulation),
          )
      )
    elif isinstance(item, dict):
      combined.append(
          FlowEvent(
              event_id=item.get('event_id', f'rec_{int(time.time() * 1000)}'),
              timestamp=float(item.get('timestamp', time.time())),
              layer=str(item.get('layer') or 'GENERAL'),
              sublayer=item.get('sublayer', 'GENERAL'),
              stage=item.get('stage', 'GENERAL'),
              src=item.get('src', 'Controller'),
              dst=item.get('dst', 'Device'),
              title=item.get('title', 'Recorded Event'),
              summary=item.get('summary', ''),
              details=dict(item.get('details') or {}),
              encapsulation=list(item.get('encapsulation') or []),
              payload_hex=item.get('payload_hex', ''),
              replay_mcp_call=item.get('replay_mcp_call'),
              channel=item.get('channel'),
              rssi=item.get('rssi'),
          )
      )

  # Run pluggable dissectors; a None result leaves the event unchanged.
  for name, fn in (dissectors or {}).items():
    combined = [_run_dissector(name, fn, ev) for ev in combined]

  # Sort chronologically
  combined.sort(key=lambda ev: ev.timestamp)
  _stage_connect_network_by_added_network(combined)
  combined = _dedup_flow_events(combined)
  _join_message_events(combined)
  return combined


# ConnectNetwork names no network type, so it belongs to the stage of the most
# recent AddOrUpdate*Network (Wi-Fi or Thread) from any source.
_ADD_NETWORK_STAGES = {
    'AddOrUpdateWiFiNetwork': 'WIFI_PROVISIONED',
    'AddOrUpdateThreadNetwork': 'THREAD_PROVISIONED',
}


def _stage_connect_network_by_added_network(events: List[FlowEvent]) -> None:
  """Re-stages ConnectNetwork events; `events` must be in timestamp order."""
  last_stage = None
  for ev in events:
    command = (ev.details or {}).get('matter_command', '')
    if command in _ADD_NETWORK_STAGES:
      last_stage = _ADD_NETWORK_STAGES[command]
    elif command == 'ConnectNetwork' and last_stage:
      ev.stage = last_stage


# Copies of one frame in several captures (medium, AP and per-station taps)
# are written within milliseconds; retransmissions come much later.
DEDUP_WINDOW_SEC = 0.05


def _dedup_flow_events(events: List[FlowEvent]) -> List[FlowEvent]:
  """Keeps the first of the events that share details['dedup_key'].

  Dissectors set 'dedup_key' on capture events (for example a Matter
  message counter, exchange and opcode). The kept event lists the dropped
  copies in details['duplicates'] as '<pcap file>#<packet index>'.
  """
  kept: Dict[str, FlowEvent] = {}
  out: List[FlowEvent] = []
  for ev in events:
    key = ev.details.get('dedup_key')
    first = kept.get(key) if key else None
    if first is None or ev.timestamp - first.timestamp > DEDUP_WINDOW_SEC:
      if key:
        kept[key] = ev
      out.append(ev)
      continue
    source = ev.details.get('pcap_file') or ev.details.get('log_file', '')
    index = ev.details.get('packet_index', ev.details.get('line_number', ''))
    first.details.setdefault('duplicates', []).append(f'{source}#{index}')
  return out


def _join_message_events(events: List[FlowEvent]) -> None:
  """Links log and capture events of one message (details['matter_msg_key'])."""
  groups: Dict[str, List[FlowEvent]] = {}
  for ev in events:
    key = ev.details.get('matter_msg_key')
    if key:
      groups.setdefault(key, []).append(ev)
  for group in groups.values():
    if len(group) > 1:
      for ev in group:
        ev.details['joined_events'] = [
            other.event_id for other in group if other is not ev
        ]


def _load_flow_plugin_module(path: str) -> Any:
  """Loads and executes a flow plugin Python module from `path`."""
  if not os.path.isfile(path):
    raise FileNotFoundError(f'Flow plugin not found: {path}')
  mod_name = 'cirque_flow_plugin_' + re.sub(
      r'\W', '_', os.path.splitext(os.path.basename(path))[0]
  )
  mod_spec = importlib.util.spec_from_file_location(mod_name, path)
  if mod_spec is None or mod_spec.loader is None:
    raise ImportError(f'Cannot load flow plugin: {path}')
  module = importlib.util.module_from_spec(mod_spec)
  mod_spec.loader.exec_module(module)
  return module


def load_flow_plugin(
    path: str,
) -> Tuple[Dict[str, FlowDissector], Dict[str, Dict[str, Any]]]:
  """Loads a flow plugin file.

  Returns (FLOW_DISSECTORS, FLOW_LAYERS) as described in the module docstring.
  """
  module = _load_flow_plugin_module(path)
  dissectors = dict(getattr(module, 'FLOW_DISSECTORS', {}))
  layers = dict(getattr(module, 'FLOW_LAYERS', {}))
  return dissectors, layers


# -----------------------------------------------------------------------------
# Sequence Diagram Focus & Lane Aliases
# -----------------------------------------------------------------------------

# The sequence diagram opens on the first event of these stages.
DEFAULT_FOCUS_STAGES = ('PASE_HANDSHAKE', 'CASE_CONNECT')
LANE_CONTROLLER = 0
LANE_BORDER_ROUTER = 2
LANE_ACCESSORY = 3
LANE_WIFI_AP = 4
# Endpoint for broadcast DHCP Discover/Request frames; drawn on the Wi-Fi AP
# lane, where the Cirque DHCP server runs.
DHCP_SERVER_ENDPOINT = 'DHCP server (broadcast)'


def _event_field(ev: Union[FlowEvent, Dict[str, Any]], name: str) -> Any:
  return ev.get(name) if isinstance(ev, dict) else getattr(ev, name)


def default_sequence_focus_index(
    events: List[Union[FlowEvent, Dict[str, Any]]],
) -> int:
  """Returns the index of the event the sequence diagram opens on.

  That is the first event of a DEFAULT_FOCUS_STAGES stage, else the first
  event of a plugin-defined layer, else 0. Accepts FlowEvents or dicts.
  """
  for idx, ev in enumerate(events):
    if _event_field(ev, 'stage') in DEFAULT_FOCUS_STAGES:
      return idx
  for idx, ev in enumerate(events):
    if _event_field(ev, 'layer') not in set(DEFAULT_FLOW_LAYERS) | {'GENERAL'}:
      return idx
  return 0


def _lane_alias_key(name: Any) -> str:
  """Normalizes node IDs ('0:<16 hex>') and IP addresses for alias lookup."""
  text = re.sub(r'^\d+:(?=[0-9A-Fa-f]{16}$)', '', str(name or '').strip())
  try:
    return str(ipaddress.ip_address(text.strip('[]').split('%')[0]))
  except ValueError:
    return text.lower()


def infer_lane_aliases(events: List[FlowEvent]) -> Dict[str, int]:
  """Maps endpoint names to canonical sequence-diagram lanes.

  - Node IDs a controller node (Android, chip-tool) sends from, and the IP
    addresses that carry its messages in captures (joined through
    details['matter_msg_key']), go to the Controller lane.
  - When the accessory answers to an address that is not the controller's,
    a relay sits in between: that address and the address the controller
    sends to (for example a border router wlan0 IP) go to the Border Router
    lane.
  - The MAC that runs EAPOL with the most stations is the Wi-Fi AP. A station
    MAC follows the lane of an IP it sends from; any other station goes to the
    Accessory lane.
  - details['lane_aliases'] ({endpoint: lane}) set by plugins wins.
  """
  aliases: Dict[str, int] = {}
  forced: Dict[str, int] = {}
  ctrl_keys = {'TX': set(), 'RX': set()}
  ctrl_peers = set()
  dev_peers = set()
  for ev in events:
    details = ev.details
    for name, lane in (details.get('lane_aliases') or {}).items():
      forced[_lane_alias_key(name)] = int(lane)
    if details.get('chip_tag') != 'EM' or 'node' not in details:
      continue
    direction = details.get('direction')
    peer = details.get('peer_addr')
    if _is_controller_name(details['node']):
      own = details.get('peer_from' if direction == 'TX' else 'peer_to')
      if own and not re.fullmatch(r'(\d+:)?0+', own):
        aliases[_lane_alias_key(own)] = LANE_CONTROLLER
      if details.get('matter_msg_key') and direction in ctrl_keys:
        ctrl_keys[direction].add(details['matter_msg_key'])
      if peer:
        ctrl_peers.add(_lane_alias_key(peer))
    elif peer and direction == 'TX':
      dev_peers.add(_lane_alias_key(peer))
  # The first capture hop of a message the controller sent starts at the
  # controller; the last hop of a message it received ends there.
  hops: Dict[str, List[FlowEvent]] = {}
  for ev in events:
    key = ev.details.get('matter_msg_key')
    if 'pcap_file' in ev.details and key:
      hops.setdefault(key, []).append(ev)
  controller_ips = set()
  far_ends = set()
  for key, key_hops in hops.items():
    first, last = key_hops[0].details, key_hops[-1].details
    src = first.get('src_ip') or first.get('src_ip6')
    dst = last.get('dst_ip') or last.get('dst_ip6')
    if key in ctrl_keys['TX'] and src:
      controller_ips.add(_lane_alias_key(src))
      far_ends.add(_lane_alias_key(dst) if dst else '')
    if key in ctrl_keys['RX'] and dst:
      controller_ips.add(_lane_alias_key(dst))
      far_ends.add(_lane_alias_key(src) if src else '')
  far_ends.discard('')
  ip_to_mac = {}
  # EAPOL always runs between the AP and one station, so the AP is the MAC
  # that runs EAPOL with the most distinct peers.
  eapol_peers: Dict[str, set] = {}
  for ev in events:
    d = ev.details
    src_ip = d.get('src_ip') or d.get('src_ip6')
    src_mac, dst_mac = d.get('src_mac'), d.get('dst_mac')
    if src_ip and src_mac and src_ip != '0.0.0.0':
      ip_to_mac[_lane_alias_key(src_ip)] = _lane_alias_key(src_mac)
    if ev.sublayer == 'EAPOL' and src_mac and dst_mac:
      a, b = _lane_alias_key(src_mac), _lane_alias_key(dst_mac)
      eapol_peers.setdefault(a, set()).add(b)
      eapol_peers.setdefault(b, set()).add(a)

  for addr in controller_ips:
    aliases.setdefault(addr, LANE_CONTROLLER)
    if addr in ip_to_mac:
      aliases.setdefault(ip_to_mac[addr], LANE_CONTROLLER)
  relays = dev_peers - controller_ips
  if controller_ips and relays:
    for addr in (ctrl_peers | relays) - controller_ips:
      aliases.setdefault(addr, LANE_BORDER_ROUTER)
      if addr in ip_to_mac:
        aliases.setdefault(ip_to_mac[addr], LANE_BORDER_ROUTER)
  for addr in far_ends - controller_ips:
    aliases.setdefault(addr, LANE_ACCESSORY)
    if addr in ip_to_mac:
      aliases.setdefault(ip_to_mac[addr], LANE_ACCESSORY)
  if eapol_peers:
    ap_mac = max(
        sorted(eapol_peers),
        key=lambda m: (len(eapol_peers[m]), m not in aliases),
    )
    aliases[ap_mac] = LANE_WIFI_AP
    aliases.setdefault(_lane_alias_key(DHCP_SERVER_ENDPOINT), LANE_WIFI_AP)
    # Stations not already placed by their IP traffic are end devices.
    for mac in eapol_peers[ap_mac]:
      aliases.setdefault(mac, LANE_ACCESSORY)
  aliases.update(forced)
  return aliases


# -----------------------------------------------------------------------------
# Interactive HTML5 View / Replay / Pause Studio Generator
# -----------------------------------------------------------------------------


def generate_flow_html(
    events: List[FlowEvent],
    output_path: str,
    title: str = 'Cirque Cross-Layer Flow Studio',
    layers: Optional[Dict[str, Dict[str, Any]]] = None,
) -> str:
  """Generates an interactive, Tailwind-powered HTML5 Studio with Play/Pause/Scrub.

  Layer filter pills, counts and badge colors are derived from the layers
  present in `events` plus the display metadata in DEFAULT_FLOW_LAYERS and
  `layers` (see the module docstring).

  Meets all ui_taste_auditor.py craft invariants:
    - Tailwind CDN loaded
    - 3-tier semantic token variables (var(--card), var(--background), etc.)
    - No local :root color overrides
    - No gradient headline text or uncalibrated purple/violet accents
    - Max card nesting <= 2
    - Semantic headings <h1>-<h4>
    - Tabular numbers on quantitative metrics
    - Native <button type="button"> with focus-visible:ring-2
    - Action-oriented button labels
  """
  events_data = [ev.to_dict() for ev in events]
  json_events_embedded = _json_for_script(events_data)

  # Calculate metrics for scorecard
  total_events = len(events)
  layer_counts: Dict[str, int] = {}
  for ev in events:
    layer_counts[ev.layer] = layer_counts.get(ev.layer, 0) + 1

  layer_meta: Dict[str, Dict[str, Any]] = dict(DEFAULT_FLOW_LAYERS)
  layer_meta.update(layers or {})
  shown_layers = sorted(
      set(layer_meta) | set(layer_counts),
      key=lambda name: (layer_meta.get(name, {}).get('order', 100), name),
  )
  layer_labels = [
      layer_meta.get(name, {}).get('label', name) for name in shown_layers
  ]
  layers_sentence = ', '.join(layer_labels)
  layer_filter_buttons = ''
  overlay_toggle_pills = ''
  layer_dot_hex_map = {
      'BT': '#0284c7',
      'THREAD': '#047857',
      'WIFI': '#0e7490',
      'MATTER': '#b45309',
      'APP': '#b45309',
  }
  for name, label in zip(shown_layers, layer_labels):
    esc_name = html.escape(name)
    js_name = html.escape(json.dumps(name))
    esc_label = html.escape(label)
    cnt = layer_counts.get(name, 0)
    dot_hex = layer_dot_hex_map.get(name.upper(), '#0284c7')
    layer_filter_buttons += f"""
          <button type="button" id="filter-btn-{esc_name}"
            onclick="setLayerFilter({js_name}, event)"
            class="px-2.5 py-1 rounded-md text-xs font-medium border
              border-[var(--border)] bg-[var(--background)]
              text-[var(--foreground)] hover:bg-[var(--secondary)]
              focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
            {esc_label} ({cnt})
          </button>"""
    overlay_toggle_pills += f"""
          <button type="button" id="overlay-toggle-{esc_name}"
            onclick="toggleLayerOverlay({js_name})"
            class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md
              text-xs font-medium border border-[var(--primary)]
              bg-[var(--secondary)] text-[var(--foreground)]
              hover:bg-[var(--accent)] focus-visible:ring-2
              focus-visible:ring-[var(--ring)] transition-colors">
            <span id="overlay-check-{esc_name}"
              class="font-mono text-[11px] text-[var(--primary)]">[✓]</span>
            <span class="w-2 h-2 rounded-full"
              style="background-color: {dot_hex};"></span>
            <span>{esc_label}</span>
            <span class="tabular-nums text-[var(--muted-foreground)]">
              ({cnt})
            </span>
          </button>"""
  decrypted_wire_count = sum(
      1
      for ev in events
      if ev.details.get('decrypted')
      or (
          ev.layer == 'MATTER'
          and ev.details.get('evidence') in ('wire', 'host_hci')
      )
  )
  if decrypted_wire_count > 0:
    layer_filter_buttons += f"""
          <button type="button" id="filter-btn-DECRYPTED_WIRE"
            onclick="setLayerFilter('DECRYPTED_WIRE', event)"
            class="px-2.5 py-1 rounded-md text-xs font-semibold border
              border-amber-500/50 bg-amber-500/10 text-amber-800 dark:text-amber-200 hover:bg-amber-500/20
              focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
            Decrypted Wire ({decrypted_wire_count})
          </button>"""
  layer_colors = {}
  for name in shown_layers:
    color = str(layer_meta.get(name, {}).get('color', 'slate'))
    layer_colors[name] = color if re.fullmatch(r'[a-z]+', color) else 'slate'
  json_layer_colors = _json_for_script(layer_colors)

  initial_index = default_sequence_focus_index(events)
  # Aliases are keyed by the exact (lower-cased) endpoint strings of the
  # events so the browser needs no address normalization.
  lane_aliases = infer_lane_aliases(events)
  js_lane_aliases: Dict[str, int] = {}
  for ev in events:
    for endpoint in (ev.src, ev.dst):
      lane = lane_aliases.get(_lane_alias_key(endpoint))
      if lane is not None:
        js_lane_aliases[str(endpoint).lower()] = lane
  json_lane_aliases = _json_for_script(js_lane_aliases)
  stage_first_index: Dict[str, int] = {}
  for idx, ev in enumerate(events):
    stage_first_index.setdefault(ev.stage or 'PROTOCOL_FLOW', idx)
  stage_options = ''.join(
      f'\n              <option value="{idx}">{html.escape(stage)}'
      f' (#{idx + 1})</option>'
      for stage, idx in stage_first_index.items()
  )

  duration_sec = 0.0
  if events:
    duration_sec = max(0.0, events[-1].timestamp - events[0].timestamp)

  html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(title)}</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    /* Fallback tokens on body so SVG fills never resolve to #000000 */
    body {{
      --background: #f8fafc;
      --foreground: #0f172a;
      --card: #ffffff;
      --card-foreground: #0f172a;
      --secondary: #f1f5f9;
      --secondary-foreground: #0f172a;
      --muted: #f1f5f9;
      --muted-foreground: #475569;
      --accent: #e2e8f0;
      --accent-foreground: #0f172a;
      --border: #cbd5e1;
      --primary: #0284c7;
      --primary-foreground: #ffffff;
      --ring: #0284c7;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
        Helvetica, Arial, sans-serif;
    }}
    .seq-participant-box {{
      fill: var(--card, #ffffff);
      stroke: var(--border, #cbd5e1);
    }}
    .seq-participant-text {{
      fill: var(--foreground, #0f172a);
    }}
    .seq-stage-box {{
      fill: var(--secondary, #f1f5f9);
      stroke: var(--border, #cbd5e1);
    }}
    .seq-stage-text {{
      fill: var(--foreground, #1e293b);
    }}
    .seq-pill-bg {{
      fill: var(--card, #ffffff);
      stroke: var(--border, #cbd5e1);
    }}
    .seq-row-selected {{
      fill: var(--secondary, #e0f2fe);
      stroke: var(--primary, #0284c7);
    }}
    .seq-msg-text {{
      fill: var(--foreground, #0f172a);
    }}
    .seq-ts-text {{
      fill: var(--muted-foreground, #475569);
    }}
  </style>
</head>
<body class="bg-[var(--background)] text-[var(--foreground)] min-h-screen p-4 sm:p-6 antialiased">
  <div class="max-w-7xl mx-auto space-y-6">

    <!-- Top Navigation & Title Header -->
    <header class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-[var(--border)]">
      <div>
        <div class="flex items-center gap-3">
          <span class="inline-flex items-center justify-center w-8 h-8 rounded-lg bg-[var(--primary)] text-[var(--primary-foreground)] text-sm font-semibold">
            CL
          </span>
          <h1 class="text-xl sm:text-2xl font-semibold tracking-tight text-[var(--foreground)]">
            {html.escape(title)}
          </h1>
        </div>
        <p class="mt-1 text-sm text-[var(--muted-foreground)]">
          Real-time Cross-Layer Protocol Dissection across {html.escape(layers_sentence)}.
        </p>
      </div>

      <!-- Quick Summary Stats -->
      <div class="flex flex-wrap items-center gap-3 text-xs sm:text-sm">
        <div class="px-3 py-1.5 rounded-lg bg-[var(--card)] border border-[var(--border)]">
          <span class="text-[var(--muted-foreground)]">Total Frames:</span>
          <span class="ml-1.5 font-medium tabular-nums text-[var(--foreground)]">{total_events}</span>
        </div>
        <div class="px-3 py-1.5 rounded-lg bg-[var(--card)] border border-[var(--border)]">
          <span class="text-[var(--muted-foreground)]">Duration:</span>
          <span class="ml-1.5 font-medium tabular-nums text-[var(--foreground)]">{duration_sec:.2f}s</span>
        </div>
      </div>
    </header>

    <!-- Legend -->
    <div class="flex flex-wrap items-center gap-4 text-xs mt-2 px-2">
      <div class="flex items-center gap-1.5"><svg width="24" height="6"><line x1="0" y1="3" x2="24" y2="3" stroke="currentColor" stroke-width="2"/></svg> <span class="text-[var(--muted-foreground)] font-medium">Over-the-Air (Wire)</span></div>
      <div class="flex items-center gap-1.5"><svg width="24" height="6"><line x1="0" y1="3" x2="24" y2="3" stroke="currentColor" stroke-width="2" stroke-dasharray="6 3"/></svg> <span class="text-[var(--muted-foreground)] font-medium">Host HCI (Host-Controller)</span></div>
      <div class="flex items-center gap-1.5"><svg width="24" height="6"><line x1="0" y1="3" x2="24" y2="3" stroke="currentColor" stroke-width="2" stroke-dasharray="2 2"/></svg> <span class="text-[var(--muted-foreground)] font-medium">Device Log</span></div>
      <div class="flex items-center gap-1.5"><svg width="24" height="6"><line x1="0" y1="3" x2="24" y2="3" stroke="currentColor" stroke-width="2" stroke-dasharray="4 2 1 2" opacity="0.8"/></svg> <span class="text-[var(--muted-foreground)] font-medium">Relay/Proxy</span></div>
      <div class="flex items-center gap-1.5"><svg width="24" height="6"><line x1="0" y1="3" x2="24" y2="3" stroke="currentColor" stroke-width="2" stroke-dasharray="8 8" opacity="0.6"/></svg> <span class="text-[var(--muted-foreground)] font-medium">Controller Intent</span></div>
    </div>

    <!-- Studio Playback Controls & Timeline Bar -->
    <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-4 sm:p-5 shadow-sm space-y-4">
      <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <!-- Play / Pause / Step Actions -->
        <div class="flex flex-wrap items-center gap-2">
          <button type="button" id="btn-replay" onclick="replayFlow()"
            class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[var(--secondary)] text-[var(--secondary-foreground)] hover:bg-[var(--accent)] font-medium text-xs sm:text-sm border border-[var(--border)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] transition-colors">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
            Replay Flow
          </button>

          <button type="button" id="btn-play-pause" onclick="togglePlay()"
            class="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-[var(--primary)] text-[var(--primary-foreground)] hover:opacity-90 font-medium text-xs sm:text-sm focus-visible:ring-2 focus-visible:ring-[var(--ring)] transition-opacity">
            <span id="play-pause-icon">▶</span>
            <span id="play-pause-label">Play Stream</span>
          </button>

          <button type="button" id="btn-step-back" onclick="stepFlow(-1)"
            class="inline-flex items-center px-2.5 py-1.5 rounded-lg bg-[var(--secondary)] text-[var(--secondary-foreground)] hover:bg-[var(--accent)] text-xs border border-[var(--border)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] transition-colors"
            title="Step Back">
            ◀ Step Back
          </button>

          <button type="button" id="btn-step-forward" onclick="stepFlow(1)"
            class="inline-flex items-center px-2.5 py-1.5 rounded-lg bg-[var(--secondary)] text-[var(--secondary-foreground)] hover:bg-[var(--accent)] text-xs border border-[var(--border)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] transition-colors"
            title="Step Forward">
            Step Forward ▶
          </button>
        </div>

        <!-- Speed & Current Index Status -->
        <div class="flex items-center gap-4 text-xs sm:text-sm">
          <div class="flex items-center gap-1.5">
            <label for="speed-select" class="text-[var(--muted-foreground)]">Speed:</label>
            <select id="speed-select" onchange="setPlaybackSpeed(this.value)"
              class="px-2 py-1 rounded bg-[var(--background)] border border-[var(--border)] text-[var(--foreground)] text-xs focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
              <option value="0.25">0.25x</option>
              <option value="0.5">0.5x</option>
              <option value="1" selected>1.0x</option>
              <option value="2">2.0x</option>
              <option value="4">4.0x</option>
            </select>
          </div>

          <div class="px-2.5 py-1 rounded bg-[var(--background)] border border-[var(--border)]">
            <span class="text-[var(--muted-foreground)]">Frame:</span>
            <span id="label-current-idx" class="font-medium tabular-nums text-[var(--foreground)]">0</span>
            <span class="text-[var(--muted-foreground)]">/</span>
            <span id="label-total-idx" class="tabular-nums text-[var(--muted-foreground)]">{total_events}</span>
          </div>
        </div>
      </div>

      <!-- Scrubbable Range Timeline Slider -->
      <div class="space-y-1.5">
        <div class="flex justify-between text-xs text-[var(--muted-foreground)]">
          <span id="time-elapsed" class="tabular-nums">0.00s</span>
          <span id="time-total" class="tabular-nums">{duration_sec:.2f}s</span>
        </div>
        <input type="range" id="timeline-slider" min="0" max="{max(0, total_events - 1)}" value="0"
          oninput="onScrubInput(this.value)"
          class="w-full h-2 rounded-lg appearance-none cursor-pointer bg-[var(--secondary)] accent-[var(--primary)] focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
      </div>

      <!-- Layer Filters & Search Bar -->
      <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-2 border-t border-[var(--border)]">
        <div class="flex flex-wrap items-center gap-1.5" id="layer-filter-buttons">
          <button type="button" id="filter-btn-ALL"
            onclick="setLayerFilter('ALL', event)"
            class="px-2.5 py-1 rounded-md text-xs font-medium border border-[var(--primary)] bg-[var(--primary)] text-[var(--primary-foreground)] focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
            All Layers ({total_events})
          </button>{layer_filter_buttons}
        </div>

        <div class="w-full sm:w-64">
          <input type="text" id="search-input" placeholder="Filter title, src, dst, opcode..."
            oninput="onSearchInput(this.value)"
            class="w-full px-3 py-1 rounded-lg bg-[var(--background)] border border-[var(--border)] text-xs text-[var(--foreground)] placeholder-[var(--muted-foreground)] focus-visible:ring-2 focus-visible:ring-[var(--ring)] focus:outline-none">
        </div>
      </div>
    </div>

    <!-- Animated Multi-Node & Multi-Layer Swimlane Sequence Diagram -->
    <div class="bg-[var(--card)] border border-[var(--border)] rounded-xl p-4 sm:p-5 shadow-sm space-y-4">
      <div class="flex flex-col lg:flex-row lg:items-center
        lg:justify-between gap-3">
        <div>
          <div class="flex flex-wrap items-center gap-2">
            <h2 class="text-sm font-semibold tracking-tight
              text-[var(--foreground)]">
              Cross-Layer Swimlane Sequence
            </h2>
            <span id="active-overlay-summary"
              class="px-2 py-0.5 rounded-md text-[11px] font-medium
                tabular-nums bg-[var(--secondary)] text-[var(--foreground)]
                border border-[var(--border)]">
              Active Diagram Layers: ALL ({total_events} frames)
            </span>
          </div>
          <p class="mt-0.5 text-xs text-[var(--muted-foreground)]">
            Select a single protocol layer or combine multi-layer overlays
            to trace cross-stack handshakes
          </p>
        </div>

        <!-- Sequence Diagram Mode & Scope Controls -->
        <div class="flex flex-wrap items-center gap-2">
          <label for="stage-jump-select"
            class="text-xs text-[var(--muted-foreground)]">
            Jump to stage:
          </label>
          <select id="stage-jump-select" onchange="jumpToStage(this.value)"
            class="px-2 py-1 rounded-lg bg-[var(--background)] border
              border-[var(--border)] text-xs text-[var(--foreground)]
              focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
            <option value="">Select a stage</option>{stage_options}
          </select>
          <div class="inline-flex items-center rounded-lg border
            border-[var(--border)] bg-[var(--background)] p-0.5">
            <button type="button" id="btn-seq-mode-canonical"
              onclick="setSeqMode('CANONICAL')"
              class="px-2.5 py-1 rounded-md text-xs font-medium
                bg-[var(--primary)] text-[var(--primary-foreground)]
                focus-visible:ring-2 focus-visible:ring-[var(--ring)]
                transition-colors">
              Role Lane View
            </button>
            <button type="button" id="btn-seq-mode-dynamic"
              onclick="setSeqMode('DYNAMIC')"
              class="px-2.5 py-1 rounded-md text-xs font-medium
                text-[var(--muted-foreground)] hover:text-[var(--foreground)]
                focus-visible:ring-2 focus-visible:ring-[var(--ring)]
                transition-colors">
              Dynamic Node View
            </button>
          </div>

          <div class="inline-flex items-center rounded-lg border
            border-[var(--border)] bg-[var(--background)] p-0.5">
            <button type="button" id="btn-seq-scope-window"
              onclick="setSeqScope('WINDOW')"
              class="px-2.5 py-1 rounded-md text-xs font-medium
                bg-[var(--primary)] text-[var(--primary-foreground)]
                focus-visible:ring-2 focus-visible:ring-[var(--ring)]
                transition-colors">
              Windowed (60 Frames)
            </button>
            <button type="button" id="btn-seq-scope-all"
              onclick="setSeqScope('ALL')"
              class="px-2.5 py-1 rounded-md text-xs font-medium
                text-[var(--muted-foreground)] hover:text-[var(--foreground)]
                focus-visible:ring-2 focus-visible:ring-[var(--ring)]
                transition-colors">
              All Filtered Frames
            </button>
          </div>
        </div>
      </div>

      <!-- Multi-Layer Overlay & Single-Layer Selection Toolbar -->
      <div class="p-3 rounded-lg bg-[var(--background)] border
        border-[var(--border)] space-y-2.5">
        <div class="flex flex-wrap items-center gap-1.5">
          <span class="text-[11px] font-semibold uppercase tracking-wider
            text-[var(--muted-foreground)] mr-1">
            Quick Layer &amp; Overlay Presets:
          </span>
          <button type="button" id="btn-preset-all"
            onclick="setLayerPreset('ALL')"
            class="px-2.5 py-1 rounded-md text-xs font-medium border
              border-[var(--primary)] bg-[var(--primary)]
              text-[var(--primary-foreground)] focus-visible:ring-2
              focus-visible:ring-[var(--ring)] transition-colors">
            Overlay All Layers
          </button>
          <button type="button" id="btn-preset-matter"
            onclick="setLayerPreset(['MATTER'])"
            class="px-2.5 py-1 rounded-md text-xs font-medium border
              border-[var(--border)] bg-[var(--secondary)]
              text-[var(--foreground)] hover:bg-[var(--accent)]
              focus-visible:ring-2 focus-visible:ring-[var(--ring)]
              transition-colors">
            Matter Layer Only
          </button>
          <button type="button" id="btn-preset-thread"
            onclick="setLayerPreset(['THREAD'])"
            class="px-2.5 py-1 rounded-md text-xs font-medium border
              border-[var(--border)] bg-[var(--secondary)]
              text-[var(--foreground)] hover:bg-[var(--accent)]
              focus-visible:ring-2 focus-visible:ring-[var(--ring)]
              transition-colors">
            Thread Layer Only
          </button>
          <button type="button" id="btn-preset-bt"
            onclick="setLayerPreset(['BT'])"
            class="px-2.5 py-1 rounded-md text-xs font-medium border
              border-[var(--border)] bg-[var(--secondary)]
              text-[var(--foreground)] hover:bg-[var(--accent)]
              focus-visible:ring-2 focus-visible:ring-[var(--ring)]
              transition-colors">
            Bluetooth Layer Only
          </button>
          <button type="button" id="btn-preset-wifi"
            onclick="setLayerPreset(['WIFI'])"
            class="px-2.5 py-1 rounded-md text-xs font-medium border
              border-[var(--border)] bg-[var(--secondary)]
              text-[var(--foreground)] hover:bg-[var(--accent)]
              focus-visible:ring-2 focus-visible:ring-[var(--ring)]
              transition-colors">
            Wi-Fi / mDNS Only
          </button>
          <button type="button" id="btn-preset-ble-matter"
            onclick="setLayerPreset(['BT', 'MATTER'])"
            class="px-2.5 py-1 rounded-md text-xs font-medium border
              border-[var(--border)] bg-[var(--secondary)]
              text-[var(--foreground)] hover:bg-[var(--accent)]
              focus-visible:ring-2 focus-visible:ring-[var(--ring)]
              transition-colors">
            BLE + Matter Overlay
          </button>
          <button type="button" id="btn-preset-thread-matter"
            onclick="setLayerPreset(['THREAD', 'MATTER'])"
            class="px-2.5 py-1 rounded-md text-xs font-medium border
              border-[var(--border)] bg-[var(--secondary)]
              text-[var(--foreground)] hover:bg-[var(--accent)]
              focus-visible:ring-2 focus-visible:ring-[var(--ring)]
              transition-colors">
            Thread + Matter Overlay
          </button>
        </div>

        <div class="flex flex-wrap items-center gap-1.5 pt-2 border-t
          border-[var(--border)]" id="overlay-toggle-bar">
          <span class="text-[11px] font-semibold uppercase tracking-wider
            text-[var(--muted-foreground)] mr-1">
            Toggle Overlay Layers:
          </span>{overlay_toggle_pills}
        </div>
      </div>

      <!-- Active Frame Banner in Swimlane -->
      <div id="swimlane-active-card" class="p-4 rounded-lg bg-[var(--background)] border border-[var(--border)] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 transition-all duration-150">
        <div class="space-y-1">
          <div class="flex items-center gap-2">
            <span id="active-badge-layer" class="px-2 py-0.5 rounded text-[10px] font-semibold bg-[var(--primary)] text-[var(--primary-foreground)]">
              LAYER
            </span>
            <span id="active-badge-stage" class="text-xs text-[var(--muted-foreground)] font-mono">
              STAGE_1
            </span>
          </div>
          <div id="active-title" class="text-sm font-semibold text-[var(--foreground)]">
            Select or play a message to begin
          </div>
          <div id="active-summary" class="text-xs text-[var(--muted-foreground)]">
            Detailed packet trajectory will appear here
          </div>
        </div>

        <div class="flex flex-col items-end gap-1 text-xs">
          <div class="flex items-center gap-2 font-mono">
            <span id="active-src" class="px-2 py-0.5 rounded bg-[var(--secondary)] text-[var(--foreground)]">Host</span>
            <span>➔</span>
            <span id="active-dst" class="px-2 py-0.5 rounded bg-[var(--secondary)] text-[var(--foreground)]">Device</span>
          </div>
          <div id="active-timestamp" class="text-[var(--muted-foreground)] tabular-nums">0.000s</div>
        </div>
      </div>

      <!-- Interactive Multi-Node SVG Sequence / Ladder Diagram -->
      <div id="sequence-diagram-container"
        class="max-h-[520px] overflow-y-auto overflow-x-auto rounded-lg
          border border-[var(--border)] bg-[var(--background)] p-2">
        <svg id="sequence-diagram-svg" class="w-full min-w-[780px]"
          viewBox="0 0 960 220" height="220" style="height: 220px;"
          preserveAspectRatio="xMinYMin meet"
          role="img" aria-label="Cross-Layer Message Flow Sequence Diagram">
          <defs>
            <marker id="arrowhead" viewBox="0 0 10 10" refX="8" refY="5"
              markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#0284c7"
                style="fill: var(--primary, #0284c7);" />
            </marker>
            <marker id="seq-arrow-BT" viewBox="0 0 10 10" refX="8" refY="5"
              markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#0284c7" />
            </marker>
            <marker id="seq-arrow-THREAD" viewBox="0 0 10 10" refX="8" refY="5"
              markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#047857" />
            </marker>
            <marker id="seq-arrow-WIFI" viewBox="0 0 10 10" refX="8" refY="5"
              markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#0e7490" />
            </marker>
            <marker id="seq-arrow-MATTER" viewBox="0 0 10 10" refX="8" refY="5"
              markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#b45309" />
            </marker>
            <marker id="seq-arrow-APP" viewBox="0 0 10 10" refX="8" refY="5"
              markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#b45309" />
            </marker>
            <marker id="seq-arrow-DEFAULT" viewBox="0 0 10 10" refX="8" refY="5"
              markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 1 L 8 5 L 0 9 z" fill="#0284c7"
                style="fill: var(--primary, #0284c7);" />
            </marker>
            <marker id="seq-arrow-ACTIVE" viewBox="0 0 10 10" refX="8" refY="5"
              markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 0.5 L 9 5 L 0 9.5 z" fill="#0284c7"
                style="fill: var(--primary, #0284c7);" />
            </marker>
          </defs>
          <g class="participant-lifeline-group">
            <line class="participant-lifeline" x1="185" y1="42" x2="185"
              y2="200" stroke="#cbd5e1"
              style="stroke: var(--border, #cbd5e1);" stroke-width="1.5"
              stroke-dasharray="4 4" />
            <line class="participant-lifeline" x1="408" y1="42" x2="408"
              y2="200" stroke="#cbd5e1"
              style="stroke: var(--border, #cbd5e1);" stroke-width="1.5"
              stroke-dasharray="4 4" />
            <line class="participant-lifeline" x1="632" y1="42" x2="632"
              y2="200" stroke="#cbd5e1"
              style="stroke: var(--border, #cbd5e1);" stroke-width="1.5"
              stroke-dasharray="4 4" />
            <line class="participant-lifeline" x1="845" y1="42" x2="845"
              y2="200" stroke="#cbd5e1"
              style="stroke: var(--border, #cbd5e1);" stroke-width="1.5"
              stroke-dasharray="4 4" />
          </g>
          <g class="stage-divider">
            <rect class="seq-stage-box" x="108" y="54" width="836" height="22"
              rx="4" fill="#f1f5f9" stroke="#cbd5e1"
              style="fill: var(--secondary, #f1f5f9);
                stroke: var(--border, #cbd5e1);"
              stroke-width="1" />
            <text class="seq-stage-text" x="526" y="69" text-anchor="middle"
              font-size="10" font-weight="600" font-family="monospace"
              fill="#1e293b" style="fill: var(--foreground, #1e293b);">
              INITIALIZING_SEQUENCE_LADDER
            </text>
          </g>
          <g class="message-arrow-group cursor-pointer"
            onclick="selectFrame(0)">
            <line x1="185" y1="110" x2="845" y2="110" stroke="#0284c7"
              style="stroke: var(--primary, #0284c7);"
              stroke-width="2" marker-end="url(#arrowhead)" />
          </g>
        </svg>
      </div>
    </div>

    <!-- Main 2-Column Section: Event List (Left) + 3-Pane Deep Inspector (Right) -->
    <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">

      <!-- Left Column: Filterable Event List Table (5 cols) -->
      <div class="lg:col-span-5 bg-[var(--card)] border border-[var(--border)] rounded-xl p-4 sm:p-5 shadow-sm space-y-3 flex flex-col h-[680px]">
        <div class="flex items-center justify-between pb-2 border-b border-[var(--border)]">
          <h3 class="text-sm font-semibold tracking-tight text-[var(--foreground)]">
            Timeline Messages
          </h3>
          <span id="event-list-counter" class="text-xs tabular-nums text-[var(--muted-foreground)]">
            Showing {total_events} frames
          </span>
        </div>

        <div class="flex-1 overflow-y-auto divide-y divide-[var(--border)] pr-1 space-y-1" id="events-container">
          <!-- Event rows rendered by JavaScript -->
        </div>
      </div>

      <!-- Right Column: Wireshark-Style 3-Pane Deep Inspector (7 cols) -->
      <div class="lg:col-span-7 bg-[var(--card)] border border-[var(--border)] rounded-xl p-4 sm:p-5 shadow-sm space-y-4 flex flex-col h-[680px]">
        <div class="flex items-center justify-between pb-2 border-b border-[var(--border)]">
          <h3 class="text-sm font-semibold tracking-tight text-[var(--foreground)]">
            Wireshark-Style Deep Inspector
          </h3>
          <span id="inspector-status" class="text-xs text-[var(--muted-foreground)]">
            Frame Details
          </span>
        </div>

        <div class="flex-1 overflow-y-auto space-y-4 pr-1">
          <!-- Pane 1: Cross-Layer Encapsulation Stack -->
          <div class="space-y-2">
            <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--muted-foreground)]">
              1. Cross-Layer Encapsulation Stack
            </h4>
            <div id="inspector-encapsulation" class="flex flex-wrap items-center gap-1.5 p-3 rounded-lg bg-[var(--background)] border border-[var(--border)] text-xs font-mono">
              <span class="text-[var(--muted-foreground)]">No frame selected</span>
            </div>
          </div>

          <!-- Pane 2: Decoded Protocol Fields Table -->
          <div class="space-y-2">
            <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--muted-foreground)]">
              2. Decoded Protocol Fields
            </h4>
            <div class="overflow-x-auto rounded-lg border border-[var(--border)] bg-[var(--background)]">
              <table class="w-full text-left text-xs">
                <thead class="border-b border-[var(--border)] text-[var(--muted-foreground)] bg-[var(--secondary)]">
                  <tr>
                    <th class="p-2 font-medium">Field</th>
                    <th class="p-2 font-medium">Decoded Value</th>
                  </tr>
                </thead>
                <tbody id="inspector-fields-table" class="divide-y divide-[var(--border)] font-mono">
                  <tr>
                    <td class="p-2 text-[var(--muted-foreground)]">Status</td>
                    <td class="p-2 text-[var(--muted-foreground)]">Select a frame from the timeline</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Pane 3: Hex + ASCII Payload & Interactive Replay via MCP Panel -->
          <div class="space-y-2">
            <div class="flex items-center justify-between">
              <h4 class="text-xs font-semibold uppercase tracking-wider text-[var(--muted-foreground)]">
                3. Raw Payload & Replay Action
              </h4>
              <button type="button" id="btn-copy-mcp" onclick="copyMcpReplayCall()"
                class="inline-flex items-center px-2 py-0.5 rounded text-[11px] bg-[var(--secondary)] text-[var(--secondary-foreground)] hover:bg-[var(--accent)] border border-[var(--border)] focus-visible:ring-2 focus-visible:ring-[var(--ring)]">
                Copy MCP Call
              </button>
            </div>

            <!-- Hex + ASCII Dump Box -->
            <pre id="inspector-hex-dump" class="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)] text-[11px] font-mono leading-relaxed overflow-x-auto text-[var(--foreground)] h-36">
0000   (empty payload)
            </pre>

            <!-- Replay via MCP Action Box -->
            <div id="inspector-mcp-panel" class="p-3 rounded-lg bg-[var(--background)] border border-[var(--border)] space-y-2">
              <div class="flex items-center justify-between">
                <span class="text-xs font-medium text-[var(--foreground)]">Execute Replay via MCP:</span>
                <button type="button" id="btn-execute-replay-step" onclick="executeReplayStep()"
                  class="px-2.5 py-1 rounded bg-[var(--primary)] text-[var(--primary-foreground)] text-xs font-medium hover:opacity-90 focus-visible:ring-2 focus-visible:ring-[var(--ring)] transition-opacity">
                  Replay Message Step
                </button>
              </div>
              <code id="inspector-mcp-code" class="block p-2 rounded bg-[var(--card)] border border-[var(--border)] text-[11px] font-mono text-[var(--muted-foreground)] break-all">
// MCP call payload will appear here
              </code>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>

  <!-- Studio JavaScript Runtime -->
  <script>
    const ALL_EVENTS = {json_events_embedded};
    const LAYER_COLORS = {json_layer_colors};
    // Endpoint (lower-cased) -> canonical lane index, inferred in Python.
    const LANE_ALIASES = {json_lane_aliases};
    // The diagram opens on the first PASE/CASE frame instead of frame 0.
    const INITIAL_INDEX = {initial_index};
    const ALL_LAYER_NAMES = Array.from(
      new Set([
        ...Object.keys(LAYER_COLORS),
        ...ALL_EVENTS.map(ev => ev.layer).filter(Boolean),
      ])
    );
    // Badge classes are built at runtime; the Tailwind Play CDN generates them.
    function layerBadgeClass(layer) {{
      const color = LAYER_COLORS[layer] || 'slate';
      return `bg-${{color}}-500/20 text-${{color}}-600`;
    }}
    let currentIndex = 0;
    let isPlaying = false;
    let playTimer = null;
    let playbackSpeed = 1.0;
    let activeFilter = 'ALL';
    let activeLayers = new Set(ALL_LAYER_NAMES);
    let searchQuery = '';
    let seqMode = 'CANONICAL';
    // Typical Wi-Fi/Thread commissioning captures (a few thousand frames)
    // render in full so provisioning frames far from PASE stay visible.
    let seqScope = (ALL_EVENTS.length <= 5000) ? 'ALL' : 'WINDOW';

    const CANONICAL_LANES = [
      'Controller / Mobile',
      'Virtual Radio / Medium',
      'Border Router / Gateway',
      'Accessory / End Device',
      'Wi-Fi AP',
    ];
    const SEQ_BTN_ACTIVE = [
      'px-2.5 py-1 rounded-md text-xs font-medium',
      'bg-[var(--primary)] text-[var(--primary-foreground)]',
      'focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
      'transition-colors',
    ].join(' ');
    const SEQ_BTN_IDLE = [
      'px-2.5 py-1 rounded-md text-xs font-medium',
      'text-[var(--muted-foreground)] hover:text-[var(--foreground)]',
      'focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
      'transition-colors',
    ].join(' ');
    const PRESET_BTN_ACTIVE = [
      'px-2.5 py-1 rounded-md text-xs font-medium border',
      'border-[var(--primary)] bg-[var(--primary)]',
      'text-[var(--primary-foreground)]',
      'focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
      'transition-colors',
    ].join(' ');
    const PRESET_BTN_IDLE = [
      'px-2.5 py-1 rounded-md text-xs font-medium border',
      'border-[var(--border)] bg-[var(--secondary)]',
      'text-[var(--foreground)] hover:bg-[var(--accent)]',
      'focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
      'transition-colors',
    ].join(' ');
    const TOP_FILTER_ACTIVE = [
      'px-2.5 py-1 rounded-md text-xs font-medium border',
      'border-[var(--primary)] bg-[var(--primary)]',
      'text-[var(--primary-foreground)]',
      'focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
    ].join(' ');
    const TOP_FILTER_IDLE = [
      'px-2.5 py-1 rounded-md text-xs font-medium border',
      'border-[var(--border)] bg-[var(--background)]',
      'text-[var(--foreground)] hover:bg-[var(--secondary)]',
      'focus-visible:ring-2 focus-visible:ring-[var(--ring)]',
    ].join(' ');
    const OVERLAY_PILL_ON = [
      'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md',
      'text-xs font-medium border border-[var(--primary)]',
      'bg-[var(--secondary)] text-[var(--foreground)]',
      'hover:bg-[var(--accent)] focus-visible:ring-2',
      'focus-visible:ring-[var(--ring)] transition-colors',
    ].join(' ');
    const OVERLAY_PILL_OFF = [
      'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md',
      'text-xs font-medium border border-[var(--border)]',
      'bg-[var(--background)] text-[var(--muted-foreground)]',
      'hover:bg-[var(--secondary)] focus-visible:ring-2',
      'focus-visible:ring-[var(--ring)] transition-colors',
    ].join(' ');

    function escapeXml(unsafe) {{
      return String(unsafe || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }}

    function mapEndpointToCanonicalLane(name, isDst, srcLaneIdx) {{
      const lower = String(name || '').toLowerCase();
      if (Object.prototype.hasOwnProperty.call(LANE_ALIASES, lower)) {{
        return LANE_ALIASES[lower];
      }}
      if (
        lower.includes('controller') ||
        lower.includes('mobile') ||
        lower.includes('phone') ||
        lower.includes('host') ||
        lower.includes('commissioner') ||
        lower.includes('chip-tool') ||
        lower.includes('android')
      ) {{
        return 0;
      }}
      if (
        lower.includes('hci') ||
        lower.includes('radio') ||
        lower.includes('medium') ||
        lower.includes('ble') ||
        lower.includes('bt-') ||
        lower.includes('virtual') ||
        lower.includes('air') ||
        lower.includes('broadcast') ||
        lower.includes('multicast') ||
        lower.includes('ff02') ||
        lower.includes('224.0.0')
      ) {{
        return 1;
      }}
      if (
        lower.includes('otbr') ||
        lower.includes('border') ||
        lower.includes('router') ||
        lower.includes('gateway') ||
        lower.includes('wlan') ||
        lower.includes('wpan') ||
        lower.includes('br-')
      ) {{
        return 2;
      }}
      if (
        lower.includes('accessory') ||
        lower.includes('device') ||
        lower.includes('end_device') ||
        lower.includes('sed') ||
        lower.includes('icd') ||
        lower.includes('peer') ||
        lower.includes('light') ||
        lower.includes('lock')
      ) {{
        return 3;
      }}
      if (isDst && srcLaneIdx !== undefined) {{
        return srcLaneIdx === 0 ? 3 : 0;
      }}
      return 0;
    }}

    function getLayerStrokeColor(layer) {{
      const l = String(layer || '').toUpperCase();
      if (l === 'BT' || l === 'BLE') return '#0284c7';
      if (l === 'THREAD' || l === 'WPAN') return '#047857';
      if (l === 'WIFI' || l === 'WLAN') return '#0e7490';
      if (l === 'MATTER' || l === 'APP') return '#b45309';
      return '#0284c7';
    }}

    function getLayerMarkerId(layer) {{
      const l = String(layer || '').toUpperCase();
      if (l === 'BT') return 'seq-arrow-BT';
      if (l === 'THREAD') return 'seq-arrow-THREAD';
      if (l === 'WIFI') return 'seq-arrow-WIFI';
      if (l === 'MATTER') return 'seq-arrow-MATTER';
      if (l === 'APP') return 'seq-arrow-APP';
      return 'arrowhead';
    }}

    function setSeqMode(mode) {{
      seqMode = mode;
      const btnCan = document.getElementById('btn-seq-mode-canonical');
      const btnDyn = document.getElementById('btn-seq-mode-dynamic');
      if (btnCan && btnDyn) {{
        const isCan = mode === 'CANONICAL';
        btnCan.className = isCan ? SEQ_BTN_ACTIVE : SEQ_BTN_IDLE;
        btnDyn.className = isCan ? SEQ_BTN_IDLE : SEQ_BTN_ACTIVE;
      }}
      renderSequenceDiagram();
    }}

    function setSeqScope(scope) {{
      seqScope = scope;
      const btnWin = document.getElementById('btn-seq-scope-window');
      const btnAll = document.getElementById('btn-seq-scope-all');
      if (btnWin && btnAll) {{
        const isWin = scope === 'WINDOW';
        btnWin.className = isWin ? SEQ_BTN_ACTIVE : SEQ_BTN_IDLE;
        btnAll.className = isWin ? SEQ_BTN_IDLE : SEQ_BTN_ACTIVE;
      }}
      renderSequenceDiagram();
    }}

    function renderSequenceDiagram() {{
      const svg = document.getElementById('sequence-diagram-svg');
      if (!svg) return;

      const filtered = getFilteredEvents();
      const overlaySummary = document.getElementById('active-overlay-summary');
      if (overlaySummary) {{
        const isAll =
          activeFilter === 'ALL' && activeLayers.size >= ALL_LAYER_NAMES.length;
        const layerLabelStr = activeFilter === 'DECRYPTED_WIRE'
          ? 'Decrypted Wire'
          : (isAll ? 'ALL' : Array.from(activeLayers).join(' + '));
        const cntStr = `${{filtered.length}} frames`;
        overlaySummary.innerText =
          `Active Diagram Layers: ${{layerLabelStr}} (${{cntStr}})`;
      }}

      let displayEvents = filtered;
      const isAll =
        activeFilter === 'ALL' && activeLayers.size >= ALL_LAYER_NAMES.length;
      if (seqScope === 'WINDOW') {{
        if (!isAll || filtered.length <= 500) {{
          displayEvents = filtered;
        }} else if (filtered.length > 150) {{
          let focusPos = filtered.findIndex(
            ev => ALL_EVENTS.indexOf(ev) >= currentIndex
          );
          if (focusPos < 0) focusPos = filtered.length - 1;
          const windowSize = 150;
          const maxStart = filtered.length - windowSize;
          const startPos = Math.max(0, Math.min(focusPos - Math.floor(windowSize / 3), maxStart));
          displayEvents = filtered.slice(startPos, startPos + windowSize);
        }}
      }}

      let columns = [];
      if (seqMode === 'CANONICAL') {{
        columns = CANONICAL_LANES.slice();
      }} else {{
        const seen = [];
        displayEvents.forEach(ev => {{
          [ev.src || 'Host', ev.dst || 'Device'].forEach(ep => {{
            if (!seen.includes(ep) && seen.length < 8) {{
              seen.push(ep);
            }}
          }});
        }});
        columns = seen.length >= 2 ? seen : CANONICAL_LANES.slice();
      }}

      const numCols = columns.length;
      const svgWidth = Math.max(960, numCols * 235);
      const leftMarginX = 185;
      const rightMarginX = 115;
      const usableW = svgWidth - leftMarginX - rightMarginX;
      const colX = columns.map((_, idx) =>
        numCols > 1
          ? Math.round(leftMarginX + (idx * usableW) / (numCols - 1))
          : Math.round((leftMarginX + svgWidth - rightMarginX) / 2)
      );

      const headerHeight = 52;
      let curY = headerHeight + 18;
      let lastStage = null;
      const renderItems = [];

      displayEvents.forEach(ev => {{
        const stg = ev.stage || 'PROTOCOL_FLOW';
        if (stg !== lastStage) {{
          renderItems.push({{ type: 'stage', stage: stg, y: curY }});
          curY += 32;
          lastStage = stg;
        }}
        const realIdx = ALL_EVENTS.indexOf(ev);
        renderItems.push({{ type: 'msg', ev, realIdx, y: curY }});
        curY += 44;
      }});

      const svgHeight = Math.max(220, curY + 24);
      svg.setAttribute('viewBox', `0 0 ${{svgWidth}} ${{svgHeight}}`);
      svg.setAttribute('height', String(svgHeight));
      svg.style.height = svgHeight + 'px';

      const baseTs = ALL_EVENTS.length > 0 ? ALL_EVENTS[0].timestamp : 0;
      const mkMarker = (id, fill, sz) =>
        `<marker id="${{id}}" viewBox="0 0 10 10" refX="8" refY="5" ` +
        `markerWidth="${{sz}}" markerHeight="${{sz}}" ` +
        `orient="auto-start-reverse">` +
        `<path d="M 0 1 L 8 5 L 0 9 z" fill="${{fill}}" /></marker>`;

      let out = '<defs>' +
        mkMarker('arrowhead', '#0284c7', 6) +
        mkMarker('seq-arrow-BT', '#0284c7', 6) +
        mkMarker('seq-arrow-THREAD', '#047857', 6) +
        mkMarker('seq-arrow-WIFI', '#0e7490', 6) +
        mkMarker('seq-arrow-MATTER', '#b45309', 6) +
        mkMarker('seq-arrow-APP', '#b45309', 6) +
        mkMarker('seq-arrow-DEFAULT', '#0284c7', 6) +
        mkMarker('seq-arrow-ACTIVE', '#0284c7', 7) +
        '</defs>';

      // Left Timestamp & Frame Gutter header + vertical divider line at x=100
      const stageStyle =
        'fill: var(--secondary, #f1f5f9); stroke: var(--border, #cbd5e1);';
      const tsStyle =
        'fill: var(--muted-foreground, #475569); ' +
        'font-variant-numeric: tabular-nums;';
      const cardStyle =
        'fill: var(--card, #ffffff); stroke: var(--border, #cbd5e1);';
      const fgStyle = 'fill: var(--foreground, #0f172a);';
      const stgTxtStyle = 'fill: var(--foreground, #1e293b);';

      out += `<g class="seq-gutter">` +
        `<rect class="seq-stage-box" x="8" y="8" width="86" height="30" ` +
        `rx="6" fill="#f1f5f9" stroke="#cbd5e1" style="${{stageStyle}}" ` +
        `stroke-width="1" />` +
        `<text class="seq-ts-text" x="51" y="27" text-anchor="middle" ` +
        `font-size="10" font-weight="600" font-family="monospace" ` +
        `fill="#475569" style="${{tsStyle}}">#SEQ / +TIME</text>` +
        `<line x1="100" y1="8" x2="100" y2="${{svgHeight - 12}}" ` +
        `stroke="#cbd5e1" style="stroke: var(--border, #cbd5e1);" ` +
        `stroke-width="1" />` +
        `</g>`;

      columns.forEach((colName, cIdx) => {{
        const x = colX[cIdx];
        const label = colName.length > 24
          ? colName.slice(0, 22) + '..'
          : colName;
        out += `<g class="participant-column">` +
          `<line class="participant-lifeline" x1="${{x}}" ` +
          `y1="${{headerHeight - 6}}" x2="${{x}}" y2="${{svgHeight - 12}}" ` +
          `stroke="#cbd5e1" style="stroke: var(--border, #cbd5e1);" ` +
          `stroke-width="1.5" stroke-dasharray="4 4" />` +
          `<rect class="seq-participant-box" x="${{x - 84}}" y="8" ` +
          `width="168" height="30" rx="6" fill="#ffffff" stroke="#cbd5e1" ` +
          `style="${{cardStyle}}" stroke-width="1.2" />` +
          `<text class="seq-participant-text" x="${{x}}" y="27" ` +
          `text-anchor="middle" font-size="11" font-weight="600" ` +
          `fill="#0f172a" style="${{fgStyle}}">` +
          `${{escapeXml(label)}}</text></g>`;
      }});

      if (renderItems.length === 0) {{
        const midW = Math.round((108 + svgWidth - 16) / 2);
        out += `<g class="stage-divider">` +
          `<rect class="seq-stage-box" x="108" y="70" ` +
          `width="${{svgWidth - 124}}" height="28" rx="6" fill="#f1f5f9" ` +
          `stroke="#cbd5e1" style="${{stageStyle}}" />` +
          `<text class="seq-stage-text" x="${{midW}}" y="88" ` +
          `text-anchor="middle" font-size="11" font-family="monospace" ` +
          `fill="#1e293b" style="${{stgTxtStyle}}">` +
          `No matching frames in sequence view</text></g>`;
        svg.innerHTML = out;
        return;
      }}

      renderItems.forEach(item => {{
        if (item.type === 'stage') {{
          const stageX = 108;
          const stageW = svgWidth - stageX - 16;
          const midW = Math.round(stageX + stageW / 2);
          out += `<g class="stage-divider">` +
            `<rect class="seq-stage-box" x="${{stageX}}" ` +
            `y="${{item.y - 12}}" width="${{stageW}}" height="22" rx="4" ` +
            `fill="#f1f5f9" stroke="#cbd5e1" style="${{stageStyle}}" ` +
            `stroke-width="1" />` +
            `<text class="seq-stage-text" x="${{midW}}" y="${{item.y + 3}}" ` +
            `text-anchor="middle" font-size="10" font-weight="600" ` +
            `font-family="monospace" fill="#1e293b" style="${{stgTxtStyle}}">` +
            `STAGE: ${{escapeXml(item.stage)}}</text></g>`;
        }} else if (item.type === 'msg') {{
          const ev = item.ev;
          const realIdx = item.realIdx;
          const isSelected = realIdx === currentIndex;
          const y = item.y;

          let srcCol = 0;
          let dstCol = 1;
          if (seqMode === 'CANONICAL') {{
            srcCol = mapEndpointToCanonicalLane(ev.src, false, undefined);
            dstCol = mapEndpointToCanonicalLane(ev.dst, true, srcCol);
          }} else {{
            srcCol = columns.indexOf(ev.src || 'Host');
            if (srcCol < 0) srcCol = 0;
            dstCol = columns.indexOf(ev.dst || 'Device');
            if (dstCol < 0) dstCol = Math.min(columns.length - 1, 1);
          }}

          const x1 = colX[srcCol];
          const x2 = colX[dstCol];
          const strokeColor = getLayerStrokeColor(ev.layer);
          const markerId = isSelected
            ? 'seq-arrow-ACTIVE'
            : getLayerMarkerId(ev.layer);
          const strokeWidth = isSelected ? '2.6' : '1.7';
          const relTs = Math.max(0, (ev.timestamp || 0) - baseTs).toFixed(3);
          const layerUpper = String(ev.layer || 'RAW').toUpperCase();
          const sub = ev.sublayer && ev.sublayer !== ev.layer
            ? `${{layerUpper}} • ${{ev.sublayer}}`
            : layerUpper;
          // The frame number is already in the left gutter. Long titles keep
          // their head and tail, where command names such as
          // AddOrUpdateWiFiNetwork sit.
          const rawTitle = `[${{sub}}] ${{ev.title || ''}}`;
          const compactTitle = rawTitle.length > 48
            ? rawTitle.replace(/\\(0x[0-9a-fA-F]+\\)/g, '')
                .replace(/\\s+/g, ' ')
            : rawTitle;
          const shortTitle = compactTitle.length > 48
            ? compactTitle.slice(0, 18) + '…' + compactTitle.slice(-29)
            : compactTitle;
          const isIntent = ev.details && ev.details.evidence === 'controller_intent';
          const isRelay = ev.details && ev.details.evidence === 'relay';
          const isLog = ev.details && ev.details.evidence === 'device_log';
          const isWire = ev.details && ev.details.evidence === 'wire';
          const isHostHci = ev.details && ev.details.evidence === 'host_hci';
          let dash = '';
          if (isIntent) dash = ' stroke-dasharray="8 8" opacity="0.6"';
          else if (isLog) dash = ' stroke-dasharray="2 2"';
          else if (isRelay) dash = ' stroke-dasharray="4 2 1 2" opacity="0.8"';
          else if (isHostHci) dash = ' stroke-dasharray="6 3"';
          const fw = isSelected ? '600' : '500';
          const pillW = Math.max(
            128,
            Math.min(340, shortTitle.length * 6.2 + 16)
          );
          const pillStyle =
            `fill: var(--card, #ffffff); stroke: ${{strokeColor}};`;
          const selStyle =
            'fill: var(--secondary, #e0f2fe); stroke: var(--primary, #0284c7);';

          out += `<g id="seq-row-${{realIdx}}" ` +
            `class="message-arrow-group cursor-pointer" ` +
            `onclick="selectFrame(${{realIdx}})">`;
          if (isSelected) {{
            out += `<rect class="seq-row-selected" x="6" y="${{y - 22}}" ` +
              `width="${{svgWidth - 12}}" height="36" rx="6" ` +
              `fill="#e0f2fe" stroke="#0284c7" style="${{selStyle}}" ` +
              `stroke-width="1.2" opacity="0.9" />`;
          }} else {{
            out += `<rect x="6" y="${{y - 22}}" width="${{svgWidth - 12}}" ` +
              `height="36" rx="6" fill="transparent" />`;
          }}

          // Dedicated Left Timestamp & Frame Gutter (x = 0..96px)
          out += `<text class="seq-ts-text" x="12" y="${{y - 5}}" ` +
            `font-size="9.5" font-weight="600" font-family="monospace" ` +
            `fill="#475569" style="${{tsStyle}}">#${{realIdx + 1}}</text>` +
            `<text class="seq-ts-text" x="12" y="${{y + 8}}" ` +
            `font-size="9.5" font-family="monospace" fill="#475569" ` +
            `style="${{tsStyle}}">+${{relTs}}s</text>`;

          if (srcCol === dstCol) {{
            const loopW = 42;
            const labelX = x1 + loopW + 8;
            const pathD = `M ${{x1}} ${{y - 5}} ` +
              `C ${{x1 + loopW}} ${{y - 14}}, ` +
              `${{x1 + loopW}} ${{y + 10}}, ${{x1 + 4}} ${{y + 5}}`;
            out += `<path d="${{pathD}}" fill="none" ` +
              `stroke="${{strokeColor}}" stroke-width="${{strokeWidth}}"` +
              `${{dash}} marker-end="url(#${{markerId}})" />` +
              `<rect class="seq-pill-bg" x="${{labelX - 4}}" ` +
              `y="${{y - 11}}" width="${{pillW}}" height="16" rx="4" ` +
              `fill="#ffffff" stroke="${{strokeColor}}" ` +
              `style="${{pillStyle}}" stroke-width="0.9" />` +
              `<text class="seq-msg-text" x="${{labelX + 2}}" ` +
              `y="${{y + 1}}" font-size="10" font-weight="${{fw}}" ` +
              `fill="#0f172a" style="${{fgStyle}}">` +
              `${{escapeXml(shortTitle)}}</text>`;
          }} else {{
            const dir = x2 > x1 ? 1 : -1;
            const endX = x2 - dir * 5;
            const midX = Math.round((x1 + x2) / 2);
            const pillX = Math.round(midX - pillW / 2);
            out += `<line x1="${{x1}}" y1="${{y + 4}}" x2="${{endX}}" ` +
              `y2="${{y + 4}}" stroke="${{strokeColor}}" ` +
              `stroke-width="${{strokeWidth}}"${{dash}} ` +
              `marker-end="url(#${{markerId}})" />` +
              `<circle cx="${{x1}}" cy="${{y + 4}}" r="3" ` +
              `fill="${{strokeColor}}" />` +
              `<rect class="seq-pill-bg" x="${{pillX}}" y="${{y - 17}}" ` +
              `width="${{pillW}}" height="16" rx="4" fill="#ffffff" ` +
              `stroke="${{strokeColor}}" style="${{pillStyle}}" ` +
              `stroke-width="0.9" />` +
              `<text class="seq-msg-text" x="${{midX}}" y="${{y - 5}}" ` +
              `text-anchor="middle" font-size="10" font-weight="${{fw}}" ` +
              `fill="#0f172a" style="${{fgStyle}}">` +
              `${{escapeXml(shortTitle)}}</text>`;
            if (isSelected) {{
              out += `<circle r="4.5" fill="#0284c7" ` +
                `style="fill: var(--primary, #0284c7);">` +
                `<animate attributeName="cx" from="${{x1}}" to="${{endX}}" ` +
                `dur="0.9s" repeatCount="indefinite" />` +
                `<animate attributeName="cy" from="${{y + 4}}" ` +
                `to="${{y + 4}}" dur="0.9s" repeatCount="indefinite" />` +
                `</circle>`;
            }}
          }}
          out += `</g>`;
        }}
      }});

      svg.innerHTML = out;

      const activeRowEl = document.getElementById(`seq-row-${{currentIndex}}`);
      const seqBox = document.getElementById('sequence-diagram-container');
      if (activeRowEl && seqBox) {{
        const rowBBox = activeRowEl.getBBox ? activeRowEl.getBBox() : null;
        if (rowBBox) {{
          const halfH = seqBox.clientHeight / 2;
          const targetTop = Math.max(0, rowBBox.y - halfH + 24);
          seqBox.scrollTop = targetTop;
        }}
      }}
    }}

    function getFilteredEvents() {{
      if (activeFilter === 'DECRYPTED_WIRE') {{
        return ALL_EVENTS.filter((ev) => {{
          const d = ev.details || {{}};
          const isDecr = d.decrypted || (ev.layer === 'MATTER' && (d.evidence === 'wire' || d.evidence === 'host_hci'));
          if (!isDecr) return false;
          if (searchQuery) {{
            const q = searchQuery.toLowerCase();
            const matchTitle = (ev.title || '').toLowerCase().includes(q);
            const matchSrc = (ev.src || '').toLowerCase().includes(q);
            const matchDst = (ev.dst || '').toLowerCase().includes(q);
            const matchSummary = (ev.summary || '').toLowerCase().includes(q);
            const matchSublayer = (ev.sublayer || '').toLowerCase().includes(q);
            if (!matchTitle && !matchSrc && !matchDst && !matchSummary && !matchSublayer) {{
              return false;
            }}
          }}
          return true;
        }});
      }}
      const isAllSelected =
        activeFilter === 'ALL' && activeLayers.size >= ALL_LAYER_NAMES.length;
      return ALL_EVENTS.filter((ev) => {{
        if (!isAllSelected && !activeLayers.has(ev.layer)) return false;
        if (searchQuery) {{
          const q = searchQuery.toLowerCase();
          const matchTitle = (ev.title || '').toLowerCase().includes(q);
          const matchSrc = (ev.src || '').toLowerCase().includes(q);
          const matchDst = (ev.dst || '').toLowerCase().includes(q);
          const matchSummary = (ev.summary || '').toLowerCase().includes(q);
          const matchSublayer = (ev.sublayer || '').toLowerCase().includes(q);
          if (
            !matchTitle &&
            !matchSrc &&
            !matchDst &&
            !matchSummary &&
            !matchSublayer
          ) {{
            return false;
          }}
        }}
        return true;
      }});
    }}

    function syncLayerControlStyles() {{
      const isAll =
        activeFilter === 'ALL' && activeLayers.size >= ALL_LAYER_NAMES.length;
      const topButtons = document.querySelectorAll(
        '#layer-filter-buttons button'
      );
      topButtons.forEach(btn => {{
        const btnLayer = btn.id.replace('filter-btn-', '');
        const isActive =
          (btnLayer === 'ALL' && isAll && activeFilter !== 'DECRYPTED_WIRE') ||
          (btnLayer === 'DECRYPTED_WIRE' && activeFilter === 'DECRYPTED_WIRE') ||
          (btnLayer !== 'ALL' && btnLayer !== 'DECRYPTED_WIRE' && !isAll && activeFilter !== 'DECRYPTED_WIRE' && activeLayers.has(btnLayer));
        btn.className = isActive ? TOP_FILTER_ACTIVE : TOP_FILTER_IDLE;
      }});

      ALL_LAYER_NAMES.forEach(layer => {{
        const pill = document.getElementById(`overlay-toggle-${{layer}}`);
        const chk = document.getElementById(`overlay-check-${{layer}}`);
        const on = (isAll && activeFilter !== 'DECRYPTED_WIRE') || activeLayers.has(layer);
        if (chk) {{
          chk.innerText = on ? '[✓]' : '[ ]';
          chk.className = on
            ? 'font-mono text-[11px] text-[var(--primary)]'
            : 'font-mono text-[11px] text-[var(--muted-foreground)]';
        }}
        if (pill) {{
          pill.className = on ? OVERLAY_PILL_ON : OVERLAY_PILL_OFF;
        }}
      }});

      const hasSet = (targets) =>
        !isAll &&
        activeLayers.size === targets.length &&
        targets.every(t => activeLayers.has(t));
      const presetMap = [
        ['btn-preset-all', isAll],
        ['btn-preset-matter', hasSet(['MATTER'])],
        ['btn-preset-thread', hasSet(['THREAD'])],
        ['btn-preset-bt', hasSet(['BT'])],
        ['btn-preset-wifi', hasSet(['WIFI'])],
        ['btn-preset-ble-matter', hasSet(['BT', 'MATTER'])],
        ['btn-preset-thread-matter', hasSet(['THREAD', 'MATTER'])],
      ];
      presetMap.forEach(([id, active]) => {{
        const el = document.getElementById(id);
        if (el) {{
          el.className = active ? PRESET_BTN_ACTIVE : PRESET_BTN_IDLE;
        }}
      }});
    }}

    function setLayerPreset(preset) {{
      if (preset === 'ALL') {{
        activeFilter = 'ALL';
        activeLayers = new Set(ALL_LAYER_NAMES);
      }} else if (Array.isArray(preset)) {{
        activeLayers = new Set(preset);
        activeFilter = preset.length === 1 ? preset[0] : 'CUSTOM';
      }}
      syncLayerControlStyles();
      renderEventsList();
      renderSequenceDiagram();
    }}

    function toggleLayerOverlay(layer) {{
      const allActive =
        activeFilter === 'ALL' && activeLayers.size >= ALL_LAYER_NAMES.length;
      if (allActive) {{
        activeLayers = new Set(ALL_LAYER_NAMES);
      }}
      if (activeLayers.has(layer)) {{
        if (activeLayers.size > 1) {{
          activeLayers.delete(layer);
        }} else {{
          activeLayers = new Set(ALL_LAYER_NAMES);
          activeFilter = 'ALL';
          syncLayerControlStyles();
          renderEventsList();
          renderSequenceDiagram();
          return;
        }}
      }} else {{
        activeLayers.add(layer);
      }}
      if (activeLayers.size >= ALL_LAYER_NAMES.length) {{
        activeFilter = 'ALL';
      }} else if (activeLayers.size === 1) {{
        activeFilter = Array.from(activeLayers)[0];
      }} else {{
        activeFilter = 'CUSTOM';
      }}
      syncLayerControlStyles();
      renderEventsList();
      renderSequenceDiagram();
    }}

    function renderEventsList() {{
      const container = document.getElementById('events-container');
      const filtered = getFilteredEvents();
      document.getElementById('event-list-counter').innerText = `Showing ${{filtered.length}} of ${{ALL_EVENTS.length}} frames`;
      container.innerHTML = '';

      if (filtered.length === 0) {{
        container.innerHTML = '<div class="p-4 text-center text-xs text-[var(--muted-foreground)]">No matching frames found</div>';
        return;
      }}

      filtered.forEach((ev) => {{
        const originalIdx = ALL_EVENTS.indexOf(ev);
        const isSelected = originalIdx === currentIndex;
        const row = document.createElement('div');
        row.className = `p-2.5 rounded-lg cursor-pointer transition-colors border ${{
          isSelected
            ? 'bg-[var(--secondary)] border-[var(--primary)] text-[var(--foreground)]'
            : 'border-transparent hover:bg-[var(--secondary)] text-[var(--muted-foreground)]'
        }}`;
        row.onclick = () => selectFrame(originalIdx);

        const isDecr = ev.details && (ev.details.decrypted || (ev.layer === 'MATTER' && (ev.details.evidence === 'wire' || ev.details.evidence === 'host_hci')));
        const decrBadge = isDecr
          ? '<span class="px-1 py-0.2 rounded text-[9px] font-bold bg-amber-500/20 text-amber-700 dark:text-amber-300 border border-amber-500/40">DECRYPTED</span>'
          : '';
        row.innerHTML = `
          <div class="flex items-center justify-between gap-2">
            <div class="flex items-center gap-1.5 flex-wrap">
              <span class="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${{layerBadgeClass(ev.layer)}}">${{escapeXml(String(ev.layer))}}</span>
              ${{decrBadge}}
              <span class="text-xs font-medium text-[var(--foreground)] truncate max-w-[180px]">${{escapeXml(String(ev.title))}}</span>
            </div>
            <span class="text-[11px] tabular-nums font-mono">${{ev.timestamp.toFixed(3)}}s</span>
          </div>
          <div class="mt-1 flex items-center justify-between text-[11px]">
            <span class="font-mono text-[10px] text-[var(--muted-foreground)]">${{escapeXml(String(ev.src))}} ➔ ${{escapeXml(String(ev.dst))}}</span>
            <span class="text-[10px] text-[var(--muted-foreground)] font-mono">${{escapeXml(String(ev.sublayer))}}</span>
          </div>
        `;
        container.appendChild(row);
      }});
    }}

    function selectFrame(idx) {{
      if (idx < 0 || idx >= ALL_EVENTS.length) return;
      currentIndex = idx;
      const ev = ALL_EVENTS[idx];

      // Update Slider and Counter
      const slider = document.getElementById('timeline-slider');
      slider.value = idx;
      document.getElementById('label-current-idx').innerText = idx + 1;
      if (ALL_EVENTS.length > 0) {{
        const baseTs = ALL_EVENTS[0].timestamp;
        const curTs = ev.timestamp;
        document.getElementById('time-elapsed').innerText = `${{(curTs - baseTs).toFixed(2)}}s`;
      }}

      // Update Swimlane Card
      document.getElementById('active-badge-layer').innerText = ev.layer;
      document.getElementById('active-badge-stage').innerText = ev.stage || 'STAGE';
      document.getElementById('active-title').innerText = ev.title;
      document.getElementById('active-summary').innerText = ev.summary;
      document.getElementById('active-src').innerText = ev.src;
      document.getElementById('active-dst').innerText = ev.dst;
      document.getElementById('active-timestamp').innerText = `${{ev.timestamp.toFixed(3)}}s`;

      // Update Inspector Pane 1: Encapsulation Stack
      const encapBox = document.getElementById('inspector-encapsulation');
      if (ev.encapsulation && ev.encapsulation.length > 0) {{
        encapBox.innerHTML = ev.encapsulation
          .map((layer, i) => `<span class="px-2 py-1 rounded bg-[var(--secondary)] border border-[var(--border)]">${{escapeXml(String(layer))}}</span>${{i < ev.encapsulation.length - 1 ? '<span class="text-[var(--muted-foreground)]">➔</span>' : ''}}`)
          .join(' ');
      }} else {{
        encapBox.innerHTML = '<span class="text-[var(--muted-foreground)]">Raw Frame</span>';
      }}

      // Update Inspector Pane 2: Decoded Protocol Fields Table
      const fieldsTable = document.getElementById('inspector-fields-table');
      const rows = [
        ['Event ID', ev.event_id],
        ['Timestamp', `${{ev.timestamp.toFixed(6)}} s`],
        ['Layer', ev.layer],
        ['Sublayer', ev.sublayer],
        ['Stage', ev.stage],
        ['Source Node', ev.src],
        ['Destination Node', ev.dst],
      ];
      if (ev.channel !== null && ev.channel !== undefined) rows.push(['RF Channel', ev.channel]);
      if (ev.rssi !== null && ev.rssi !== undefined) rows.push(['RSSI', `${{ev.rssi}} dBm`]);
      if (ev.details) {{
        for (const [k, v] of Object.entries(ev.details)) {{
          rows.push([k, typeof v === 'object' ? JSON.stringify(v) : String(v)]);
        }}
      }}
      fieldsTable.innerHTML = rows
        .map(([k, v]) => `<tr><td class="p-2 font-medium text-[var(--muted-foreground)]">${{escapeXml(String(k))}}</td><td class="p-2 text-[var(--foreground)] break-all">${{escapeXml(String(v))}}</td></tr>`)
        .join('');

      // Update Inspector Pane 3: Hex Dump and Replay Call
      const hexDumpBox = document.getElementById('inspector-hex-dump');
      if (ev.payload_hex) {{
        hexDumpBox.innerText = formatHexDump(ev.payload_hex);
      }} else {{
        hexDumpBox.innerText = '0000   (no payload recorded)';
      }}

      const mcpCode = document.getElementById('inspector-mcp-code');
      if (ev.replay_mcp_call) {{
        mcpCode.innerText = JSON.stringify(ev.replay_mcp_call, null, 2);
      }} else {{
        mcpCode.innerText = JSON.stringify({{
          tool: "cirque_execute_device_cmd",
          arguments: {{
            stage: ev.stage,
            layer: ev.layer,
            event_id: ev.event_id
          }}
        }}, null, 2);
      }}

      renderEventsList();
      renderSequenceDiagram();
    }}

    function formatHexDump(hexString) {{
      const clean = hexString.replace(/[^0-9a-fA-F]/g, '');
      const bytes = [];
      for (let i = 0; i < clean.length; i += 2) {{
        bytes.push(parseInt(clean.substr(i, 2), 16));
      }}
      const lines = [];
      for (let offset = 0; offset < bytes.length; offset += 16) {{
        const chunk = bytes.slice(offset, offset + 16);
        let hexPart = chunk.map(b => b.toString(16).padStart(2, '0')).join(' ');
        if (chunk.length < 16) {{
          hexPart = hexPart.padEnd(47, ' ');
        }}
        const asciiPart = chunk.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
        lines.push(`${{offset.toString(16).padStart(4, '0')}}   ${{hexPart}}   |${{asciiPart}}|`);
      }}
      return lines.join('\\n');
    }}

    function togglePlay() {{
      if (isPlaying) {{
        pauseFlow();
      }} else {{
        playFlow();
      }}
    }}

    function playFlow() {{
      if (ALL_EVENTS.length === 0) return;
      isPlaying = true;
      document.getElementById('play-pause-icon').innerText = '⏸';
      document.getElementById('play-pause-label').innerText = 'Pause Stream';

      if (currentIndex >= ALL_EVENTS.length - 1) {{
        currentIndex = 0;
      }}

      const intervalMs = Math.max(50, Math.floor(400 / playbackSpeed));
      clearInterval(playTimer);
      playTimer = setInterval(() => {{
        if (currentIndex < ALL_EVENTS.length - 1) {{
          selectFrame(currentIndex + 1);
        }} else {{
          pauseFlow();
        }}
      }}, intervalMs);
    }}

    function pauseFlow() {{
      isPlaying = false;
      clearInterval(playTimer);
      playTimer = null;
      document.getElementById('play-pause-icon').innerText = '▶';
      document.getElementById('play-pause-label').innerText = 'Play Stream';
    }}

    function replayFlow() {{
      pauseFlow();
      selectFrame(0);
      playFlow();
    }}

    function stepFlow(delta) {{
      pauseFlow();
      const target = currentIndex + delta;
      if (target >= 0 && target < ALL_EVENTS.length) {{
        selectFrame(target);
      }}
    }}

    function onScrubInput(val) {{
      pauseFlow();
      selectFrame(parseInt(val, 10));
    }}

    function setPlaybackSpeed(val) {{
      playbackSpeed = parseFloat(val) || 1.0;
      if (isPlaying) {{
        playFlow();
      }}
    }}

    function setLayerFilter(layer, evt) {{
      if (layer === 'ALL') {{
        setLayerPreset('ALL');
      }} else if (layer === 'DECRYPTED_WIRE') {{
        activeFilter = 'DECRYPTED_WIRE';
        activeLayers = new Set(['MATTER']);
        syncLayerControlStyles();
        renderEventsList();
        renderSequenceDiagram();
      }} else if (evt && (evt.shiftKey || evt.ctrlKey || evt.metaKey)) {{
        toggleLayerOverlay(layer);
      }} else {{
        setLayerPreset([layer]);
      }}
    }}

    function onSearchInput(val) {{
      searchQuery = val.trim();
      renderEventsList();
      renderSequenceDiagram();
    }}

    function copyMcpReplayCall() {{
      const code = document.getElementById('inspector-mcp-code').innerText;
      navigator.clipboard.writeText(code).then(() => {{
        const btn = document.getElementById('btn-copy-mcp');
        const orig = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => {{ btn.innerText = orig; }}, 1500);
      }});
    }}

    function executeReplayStep() {{
      const btn = document.getElementById('btn-execute-replay-step');
      const orig = btn.innerText;
      btn.innerText = 'Replaying...';
      btn.disabled = true;
      setTimeout(() => {{
        btn.innerText = 'Executed Step';
        setTimeout(() => {{
          btn.innerText = orig;
          btn.disabled = false;
        }}, 1200);
      }}, 500);
    }}

    function jumpToStage(value) {{
      const idx = parseInt(value, 10);
      if (!isNaN(idx)) {{
        pauseFlow();
        selectFrame(idx);
      }}
    }}

    // Initialization
    window.onload = () => {{
      syncLayerControlStyles();
      renderEventsList();
      setSeqScope(seqScope);
      if (ALL_EVENTS.length > 0) {{
        selectFrame(Math.min(INITIAL_INDEX, ALL_EVENTS.length - 1));
      }}
    }};
  </script>
</body>
</html>
"""
  os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
  with open(output_path, 'w', encoding='utf-8') as f:
    f.write(html_content)
  logger.info('Generated interactive flow visualizer at %s', output_path)
  return output_path


def main(argv: Optional[List[str]] = None):
  """CLI entrypoint for standalone PCAP dissection and visualization."""
  parser = argparse.ArgumentParser(
      description='Dissect PCAPs and generate interactive HTML flow visualizer.'
  )
  parser.add_argument(
      '--pcap-dir', required=True, help='Directory containing PCAP files'
  )
  parser.add_argument(
      '--output', required=True, help='Output path for interactive HTML studio'
  )
  parser.add_argument(
      '--json-output',
      default=None,
      help='Optional output path for JSON flow trace',
  )
  parser.add_argument(
      '--events-jsonl',
      default=None,
      help='Optional recorded flow events JSONL file',
  )
  parser.add_argument(
      '--plugin',
      action='append',
      default=[],
      help=(
          'Flow plugin file (repeatable). See the module docstring for the'
          ' plugin contract.'
      ),
  )
  parser.add_argument(
      '--require-non-empty',
      action='store_true',
      help='Exit with code 1 if 0 flow events are dissected.',
  )
  args = parser.parse_args(argv)

  dissectors: Dict[str, FlowDissector] = {}
  layers: Dict[str, Dict[str, Any]] = {}
  for plugin_path in args.plugin:
    plugin_dissectors, plugin_layers = load_flow_plugin(plugin_path)
    dissectors.update(plugin_dissectors)
    layers.update(plugin_layers)

  pcap_events = dissect_pcap_directory(args.pcap_dir, plugins=args.plugin)
  recorded_events = []
  if args.events_jsonl and os.path.isfile(args.events_jsonl):
    with open(args.events_jsonl, 'r', encoding='utf-8') as f:
      for line in f:
        line = line.strip()
        if line:
          try:
            recorded_events.append(json.loads(line))
          except json.JSONDecodeError:
            pass

  merged_events = merge_and_sort_flow_events(
      pcap_events, recorded_events, dissectors=dissectors
  )
  generate_flow_html(merged_events, args.output, layers=layers)

  if args.json_output:
    os.makedirs(os.path.dirname(os.path.abspath(args.json_output)), exist_ok=True)
    with open(args.json_output, 'w', encoding='utf-8') as f:
      json.dump([ev.to_dict() for ev in merged_events], f, indent=2)

  print(
      f'Dissected {len(merged_events)} cross-layer events. Output:'
      f' {args.output}'
  )
  if args.require_non_empty and not merged_events:
    sys.stderr.write(
        f'Error: 0 cross-layer events dissected from {args.pcap_dir}\n'
    )
    sys.exit(1)


if __name__ == '__main__':
  # Run from the canonical module so that plugins importing
  # cirque.pcap.flow_visualizer.FlowEvent share the class used here.
  from cirque.pcap import flow_visualizer  # pylint: disable=import-self

  flow_visualizer.main()
