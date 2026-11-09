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
"""BLE GATT profiles used by the virtual Bluetooth BlueZ emulation.

The virtual Bluetooth stack (VirtualBluezAdapterBridge and the userspace BlueZ
D-Bus service) emulates one GATT service with a write characteristic (central
to peripheral) and an indicate characteristic (peripheral to central), plus the
advertisement that announces it. Which UUIDs, advertisement payload and device
name are used is described by a BleGattProfile, so the core does not depend on
any application protocol.

Protocol packages provide profiles and register them, e.g.
cirque.protocols.matter.ble_bridge registers the Matter BTP profile. If no
default has been set, get_default_profile() imports the modules listed in
FALLBACK_PROFILE_MODULES, which register themselves as the default.
"""

import dataclasses
import importlib
import logging
import struct
import threading
from typing import Callable, Optional, Tuple

logger = logging.getLogger('VirtualBtGattProfile')

# Modules imported, in order, when no default profile has been set. Each is
# expected to call set_default_profile() (or register_profile(...,
# make_default=True)) at import time.
FALLBACK_PROFILE_MODULES: Tuple[str, ...] = ('cirque.protocols.matter.ble_bridge',)

AD_TYPE_SERVICE_DATA_16 = 0x16


def find_service_data_16(adv_data: bytes, uuid16: int) -> Optional[bytes]:
  """Returns the Service Data (16-bit UUID) body for uuid16, or None."""
  idx = 0
  n = len(adv_data)
  while idx < n:
    length = adv_data[idx]
    if length == 0 or idx + 1 + length > n:
      break
    ad_type = adv_data[idx + 1]
    ad_body = adv_data[idx + 2 : idx + 1 + length]
    if ad_type == AD_TYPE_SERVICE_DATA_16 and len(ad_body) >= 2:
      if struct.unpack('<H', ad_body[:2])[0] == uuid16:
        return ad_body[2:]
    idx += 1 + length
  return None


@dataclasses.dataclass(frozen=True)
class BleGattProfile:
  """Describes the GATT service a virtual adapter advertises and discovers.

  Attributes:
    name: Short profile name used in logs.
    service_uuid: 128-bit service UUID string.
    service_uuid16: 16-bit alias of the service UUID, used for primary service
      matching and for the advertisement Service Data AD structure.
    write_char_uuid: Characteristic the central writes (Write Request).
    indicate_char_uuid: Characteristic the peripheral indicates on.
    optional_char_uuids: Other characteristics recorded during discovery
      when present (by UUID, in GattDiscoveryResult.optional_value_handles).
    build_adv_data: Builds the advertising data for a discriminator; extra
      keyword arguments are profile specific.
    local_name: Device name for a discriminator (scan response, D-Bus Name).
    discriminator_from_service_data: Extracts the discriminator from the
      Service Data body, or returns None.
    default_discriminator: Discriminator reported when none is known.
    default_service_data: Service Data reported for peripherals whose
      advertisement has not been seen.
  """

  name: str
  service_uuid: str
  service_uuid16: int
  write_char_uuid: str
  indicate_char_uuid: str
  build_adv_data: Callable[..., bytes]
  local_name: Callable[[int], str]
  discriminator_from_service_data: Callable[[bytes], Optional[int]]
  optional_char_uuids: Tuple[str, ...] = ()
  default_discriminator: int = 0
  default_service_data: bytes = b''

  def parse_service_data(self, adv_data: bytes) -> Optional[bytes]:
    """Returns this profile's Service Data body from raw AD structures."""
    return find_service_data_16(adv_data, self.service_uuid16)

  def service_data_keys(self) -> Tuple[str, ...]:
    """Keys BlueZ clients may use for this service in ServiceData dicts."""
    short = f'{self.service_uuid16:04x}'
    return (self.service_uuid, short, f'0x{short}')


_lock = threading.Lock()
_default_profile: Optional[BleGattProfile] = None


def set_default_profile(profile: Optional[BleGattProfile]) -> None:
  """Sets (or clears, with None) the profile used when none is given."""
  global _default_profile
  with _lock:
    _default_profile = profile


def register_profile(profile: BleGattProfile, make_default: bool = False) -> None:
  """Registers a profile; becomes the default if requested or none is set."""
  global _default_profile
  with _lock:
    if make_default or _default_profile is None:
      _default_profile = profile


def get_default_profile() -> BleGattProfile:
  """Returns the default profile, importing fallback providers if needed."""
  with _lock:
    if _default_profile is not None:
      return _default_profile
  for module_name in FALLBACK_PROFILE_MODULES:
    try:
      importlib.import_module(module_name)
    except ImportError as exc:
      logger.debug('BLE GATT profile module %s unavailable: %s', module_name, exc)
      continue
    with _lock:
      if _default_profile is not None:
        return _default_profile
  raise RuntimeError(
      'No BLE GATT profile registered; call '
      'cirque.virtual_bt.gatt_profile.set_default_profile() or pass a profile '
      'to VirtualBluezAdapterBridge / DockerVirtualBtManager.'
  )
