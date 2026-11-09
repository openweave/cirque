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
"""Matter BLE commissioning transport (Matter Core Specification 5.4.2).

Provides the Matter BTP GATT profile for cirque's virtual Bluetooth stack: the
0xFFF6 service with the C1 (write) / C2 (indicate) / C3 (read) characteristics,
the 0xFFF6 Service Data advertisement and the MATTER-<discriminator> device
name. Importing this module registers MATTER_BLE_PROFILE as the default
cirque.virtual_bt.gatt_profile profile if none is set.

MatterBleAdapterBridge (also exported as VirtualBluezAdapterBridge for older
callers) is the generic adapter bridge with the Matter profile and the
Matter-named methods start_matter_advertising, stop_matter_advertising,
scan_for_matter_discriminator, write_c1_request and send_c2_indication.
"""

import struct
from typing import Optional

from cirque.virtual_bt.adapter_bridge import (
    ATT_CID,
    GattDiscoveryResult,
    VirtualBluezAdapterBridge as _GenericAdapterBridge,
)
from cirque.virtual_bt.att_db import (
    ATT_OP_ERROR_RSP,
    ATT_OP_EXCHANGE_MTU_REQ,
    ATT_OP_EXCHANGE_MTU_RSP,
    ATT_OP_FIND_INFO_REQ,
    ATT_OP_FIND_INFO_RSP,
    ATT_OP_HANDLE_VALUE_CFM,
    ATT_OP_HANDLE_VALUE_IND,
    ATT_OP_READ_BY_GROUP_TYPE_REQ,
    ATT_OP_READ_BY_GROUP_TYPE_RSP,
    ATT_OP_READ_BY_TYPE_REQ,
    ATT_OP_READ_BY_TYPE_RSP,
    ATT_OP_READ_REQ,
    ATT_OP_READ_RSP,
    ATT_OP_WRITE_CMD,
    ATT_OP_WRITE_REQ,
    ATT_OP_WRITE_RSP,
)
from cirque.virtual_bt.gatt_profile import (
    BleGattProfile,
    find_service_data_16,
    register_profile,
)

# Matter BLE Commissioning Service UUID (0xFFF6) and GATT Characteristic UUIDs
# defined in Matter Core Specification Section 5.4.2 ("Bluetooth LE").
MATTER_SERVICE_UUID_SHORT = 0xFFF6
MATTER_SERVICE_UUID_STR = '0000fff6-0000-1000-8000-00805f9b34fb'
# C1: Central -> Peripheral GATT Write Characteristic (BTP TX from Commissioner)
MATTER_C1_UUID_STR = '18ee2ef5-263d-4559-959f-4f9c429f9d11'
# C2: Peripheral -> Central GATT Indication Characteristic (BTP RX to Central)
MATTER_C2_UUID_STR = '18ee2ef5-263d-4559-959f-4f9c429f9d12'
# C3: Additional Commissioning Data (Optional Read Characteristic)
MATTER_C3_UUID_STR = '18ee2ef5-263d-4559-959f-4f9c429f9d13'

MATTER_DEFAULT_DISCRIMINATOR = 3840
# Service Data for an unseen peripheral: opcode 0, discriminator 3840 (0xF00),
# vendor 0xFFF1, product 0x8001, no flags.
MATTER_DEFAULT_SERVICE_DATA = b'\x00\x00\x0f\xf1\xff\x01\x80\x00'

__all__ = [
    'ATT_CID',
    'ATT_OP_ERROR_RSP',
    'ATT_OP_EXCHANGE_MTU_REQ',
    'ATT_OP_EXCHANGE_MTU_RSP',
    'ATT_OP_FIND_INFO_REQ',
    'ATT_OP_FIND_INFO_RSP',
    'ATT_OP_HANDLE_VALUE_CFM',
    'ATT_OP_HANDLE_VALUE_IND',
    'ATT_OP_READ_BY_GROUP_TYPE_REQ',
    'ATT_OP_READ_BY_GROUP_TYPE_RSP',
    'ATT_OP_READ_BY_TYPE_REQ',
    'ATT_OP_READ_BY_TYPE_RSP',
    'ATT_OP_READ_REQ',
    'ATT_OP_READ_RSP',
    'ATT_OP_WRITE_CMD',
    'ATT_OP_WRITE_REQ',
    'ATT_OP_WRITE_RSP',
    'GattDiscoveryResult',
    'MATTER_BLE_PROFILE',
    'MATTER_C1_UUID_STR',
    'MATTER_C2_UUID_STR',
    'MATTER_C3_UUID_STR',
    'MATTER_SERVICE_UUID_SHORT',
    'MATTER_SERVICE_UUID_STR',
    'MatterBleAdapterBridge',
    'VirtualBluezAdapterBridge',
    'build_matter_ble_adv_payload',
    'matter_discriminator_from_service_data',
    'parse_matter_ble_service_data',
]


def build_matter_ble_adv_payload(
    discriminator: int,
    vendor_id: int = 0xFFF1,
    product_id: int = 0x8001,
    additional_data: bool = False,
    extended_announcement: bool = False,
) -> bytes:
  """Builds Matter BLE 0xFFF6 Service Data AD payload (Core Spec 5.4.2.5.1)."""
  op_code = 0x00
  disc_and_version = discriminator & 0x0FFF
  flags = (0x01 if additional_data else 0x00) | (
      0x02 if extended_announcement else 0x00
  )
  vid = 0 if extended_announcement else (vendor_id & 0xFFFF)
  pid = 0 if extended_announcement else (product_id & 0xFFFF)
  service_data = struct.pack(
      '<BHHHB', op_code, disc_and_version, vid, pid, flags
  )
  ad_flags = bytes([0x02, 0x01, 0x06])
  ad_svc = bytes([len(service_data) + 3, 0x16, 0xF6, 0xFF]) + service_data
  return ad_flags + ad_svc


def parse_matter_ble_service_data(adv_data: bytes) -> Optional[bytes]:
  """Extracts 0xFFF6 service data bytes from raw BLE AD structures."""
  return find_service_data_16(adv_data, MATTER_SERVICE_UUID_SHORT)


def matter_discriminator_from_service_data(service_data: bytes) -> Optional[int]:
  """Returns the 12-bit discriminator from 0xFFF6 Service Data, or None."""
  if not service_data or len(service_data) < 3:
    return None
  return struct.unpack('<H', service_data[1:3])[0] & 0x0FFF


MATTER_BLE_PROFILE = BleGattProfile(
    name='Matter BTP',
    service_uuid=MATTER_SERVICE_UUID_STR,
    service_uuid16=MATTER_SERVICE_UUID_SHORT,
    write_char_uuid=MATTER_C1_UUID_STR,
    indicate_char_uuid=MATTER_C2_UUID_STR,
    optional_char_uuids=(MATTER_C3_UUID_STR,),
    build_adv_data=build_matter_ble_adv_payload,
    local_name=lambda discriminator: f'MATTER-{discriminator}',
    discriminator_from_service_data=matter_discriminator_from_service_data,
    default_discriminator=MATTER_DEFAULT_DISCRIMINATOR,
    default_service_data=MATTER_DEFAULT_SERVICE_DATA,
)
register_profile(MATTER_BLE_PROFILE)


class MatterBleAdapterBridge(_GenericAdapterBridge):
  """Adapter bridge using the Matter BTP profile, with Matter method names."""

  def __init__(
      self,
      controller_id: str,
      bd_addr: str,
      host: str,
      dedicated_hci_port: int,
      profile: Optional[BleGattProfile] = None,
  ):
    super().__init__(
        controller_id,
        bd_addr,
        host,
        dedicated_hci_port,
        profile=profile or MATTER_BLE_PROFILE,
    )

  def start_matter_advertising(
      self,
      discriminator: int,
      vendor_id: int = 0xFFF1,
      product_id: int = 0x8001,
  ) -> None:
    """Configures and enables Matter 0xFFF6 BLE advertising over H4 TCP."""
    self.start_profile_advertising(
        discriminator, vendor_id=vendor_id, product_id=product_id
    )

  def stop_matter_advertising(self) -> None:
    self.stop_profile_advertising()

  def scan_for_matter_discriminator(
      self, discriminator: int, timeout: float = 3.0
  ) -> Optional[str]:
    """Scans over H4 TCP for a Matter device matching discriminator."""
    return self.scan_for_discriminator(discriminator, timeout=timeout)

  def write_c1_request(self, handle: int, payload: bytes) -> None:
    """Sends a Matter BTP C1 ATT Write Request over discovered handles."""
    self.write_request(handle, payload)

  def send_c2_indication(self, handle: int, payload: bytes) -> None:
    """Sends a Matter BTP C2 ATT Indication using the database C2 handle."""
    self.send_indication(handle, payload)


# Older callers import VirtualBluezAdapterBridge from this module.
VirtualBluezAdapterBridge = MatterBleAdapterBridge
