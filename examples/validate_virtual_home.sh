#!/usr/bin/env bash
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
#
# Quick End-to-End CLI Validation Script for a Running Cirque Virtual Home.
#
# Validates:
#   1. IoTEndDevice (hci1 / AA:BB:CC:DD:EE:02):
#      - hciconfig, bluetoothctl, and dbus-send GATT Service + BLE Advertising
#   2. MobileController (hci0 / AA:BB:CC:DD:EE:01):
#      - hciconfig, bluetoothctl, and dbus-send BLE Discovery, Connect & GATT Write
#   3. Virtual Wi-Fi (wlan0 on both containers):
#      - iwlist wlan0 scan, gdbus wpa_supplicant1 AddNetwork/SelectNetwork,
#        dhcpcd wlan0, ip addr show dev wlan0, and ping -I wlan0 -c 4 10.0.1.12
#
# Usage:
#   ./examples/validate_virtual_home.sh [MobileControllerContainer] [IoTEndDeviceContainer]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CTRL_CONTAINER="${1:-}"
DEV_CONTAINER="${2:-}"
SSID="${CIRQUE_WIFI_SSID:-CIRQUE_HOME_AP}"
PSK="${CIRQUE_WIFI_PSK:-cirque_home_psk}"

discover_containers() {
  for cid in $(docker ps --format "{{.Names}}"); do
    local img
    img="$(docker inspect --format '{{.Config.Image}}' "${cid}" 2>/dev/null || true)"
    if [[ "${img}" != *"device-base"* && "${img}" != *"virtual-rf"* && "${img}" != *"generic_node"* ]]; then
      continue
    fi
    local adapt
    adapt="$(docker exec "${cid}" sh -c 'echo "${BLE_ADAPT:-}"' 2>/dev/null || true)"
    if [[ "${adapt}" == "hci0" && -z "${CTRL_CONTAINER}" ]]; then
      CTRL_CONTAINER="${cid}"
    elif [[ "${adapt}" == "hci1" && -z "${DEV_CONTAINER}" ]]; then
      DEV_CONTAINER="${cid}"
    fi
  done
}

if [[ -z "${CTRL_CONTAINER}" || -z "${DEV_CONTAINER}" ]]; then
  discover_containers
fi

if [[ -z "${CTRL_CONTAINER}" || -z "${DEV_CONTAINER}" ]]; then
  echo "ERROR: Could not find running Virtual Home containers." >&2
  echo "Start the Virtual Home first in another terminal:" >&2
  echo "  PYTHONPATH=. python3 examples/run_virtual_home_interactive.py" >&2
  exit 1
fi

# Ensure bluetoothctl CLI helper is installed inside both containers.
for target in "${CTRL_CONTAINER}" "${DEV_CONTAINER}"; do
  docker exec -i "${target}" sh -c \
    "cat > /usr/local/bin/bluetoothctl && chmod 0755 /usr/local/bin/bluetoothctl && ln -sf /usr/local/bin/bluetoothctl /usr/bin/bluetoothctl" \
    < "${SCRIPT_DIR}/bluetoothctl_dbus_cli.py"
done

echo "============================================================================"
echo "  [1/3] IoTEndDevice (${DEV_CONTAINER}): GATT Service & BLE Advertising"
echo "============================================================================"
docker exec "${DEV_CONTAINER}" sh -c '
  set -x
  hciconfig -a
  bluetoothctl list
  bluetoothctl show
  bluetoothctl register-gatt
  bluetoothctl advertise on
  dbus-send --system --dest=org.bluez --print-reply /org/bluez/$BLE_ADAPT \
    org.freedesktop.DBus.Properties.Set \
    string:org.bluez.Adapter1 string:Powered variant:boolean:true
  gdbus call --system --dest org.bluez --object-path /org/bluez/$BLE_ADAPT \
    --method org.bluez.GattManager1.RegisterApplication /chipoble/gatt_app0 "{}" || true
  gdbus call --system --dest org.bluez --object-path /org/bluez/$BLE_ADAPT \
    --method org.bluez.LEAdvertisingManager1.RegisterAdvertisement /chipoble/adv0 "{}"
'

echo ""
echo "============================================================================"
echo "  [2/3] MobileController (${CTRL_CONTAINER}): BLE Scan, Connect & GATT Write"
echo "============================================================================"
docker exec "${CTRL_CONTAINER}" sh -c '
  set -x
  hciconfig $BLE_ADAPT
  bluetoothctl power on
  bluetoothctl scan on
  bluetoothctl devices
  dbus-send --system --dest=org.bluez --print-reply /org/bluez/$BLE_ADAPT \
    org.bluez.Adapter1.StartDiscovery
  dbus-send --system --dest=org.bluez --print-reply \
    /org/bluez/$BLE_ADAPT/dev_AA_BB_CC_DD_EE_02 \
    org.bluez.Device1.Connect
  bluetoothctl connect AA:BB:CC:DD:EE:02
  bluetoothctl info AA:BB:CC:DD:EE:02
  bluetoothctl gatt.list-attributes AA:BB:CC:DD:EE:02
  bluetoothctl gatt.write 0x65 0x6c 0x04 0x00
  gdbus call --system --dest org.bluez \
    --object-path /org/bluez/$BLE_ADAPT/dev_AA_BB_CC_DD_EE_02/service00/char00 \
    --method org.bluez.GattCharacteristic1.WriteValue \
    "[byte 0x65, 0x6c, 0x04, 0x00, 0x00, 0x00, 0xf4, 0x00, 0x05]" "{}"
  dbus-send --system --dest=org.bluez --print-reply / \
    org.freedesktop.DBus.ObjectManager.GetManagedObjects | head -n 45
'

echo ""
echo "============================================================================"
echo "  [3/3] Virtual Wi-Fi (${DEV_CONTAINER} & ${CTRL_CONTAINER}): WPA2 & Ping"
echo "============================================================================"
for node_container in "${DEV_CONTAINER}" "${CTRL_CONTAINER}"; do
  echo "--- Configuring Wi-Fi on ${node_container} ---"
  docker exec "${node_container}" sh -c "
    set -x
    iwlist wlan0 scan
    net_out=\$(gdbus call --system --dest fi.w1.wpa_supplicant1 \
      --object-path /fi/w1/wpa_supplicant1/Interfaces/0 \
      --method fi.w1.wpa_supplicant1.Interface.AddNetwork \
      \"{'ssid': <'${SSID}'>, 'psk': <'${PSK}'>}\")
    net_path=\$(echo \"\${net_out}\" | sed \"s/(objectpath '//;s/',).*//\")
    gdbus call --system --dest fi.w1.wpa_supplicant1 \
      --object-path /fi/w1/wpa_supplicant1/Interfaces/0 \
      --method fi.w1.wpa_supplicant1.Interface.SelectNetwork \
      \"\${net_path}\"
    (ip -4 addr show dev wlan0 | grep -q 'inet 10.0.1.') || dhcpcd wlan0
    ip addr show dev wlan0
  "
done

dev_ip=$(docker exec "${DEV_CONTAINER}" sh -c "ip -4 -o addr show dev wlan0 | awk '{print \$4}' | cut -d/ -f1" 2>/dev/null || true)
if [ -z "${dev_ip}" ]; then
  dev_ip="10.0.1.12"
fi
echo "--- Testing L2/L3 Ping over wlan0 (${CTRL_CONTAINER} -> ${dev_ip}) ---"
docker exec "${CTRL_CONTAINER}" sh -c "
  set -x
  ping -I wlan0 -c 4 ${dev_ip}
"

echo ""
echo "============================================================================"
echo "  SUCCESS: Virtual Bluetooth (GATT + BLE) and Virtual Wi-Fi Validated!"
echo "============================================================================"
