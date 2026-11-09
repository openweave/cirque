# Cirque

## Introduction

Cirque simulates complex network topologies based upon docker nodes. On a single Linux machine, it can create multiple nodes with network stacks that are independent from each other. Some nodes may be connected to simulated Thread networks, others may connect to simulated BLE or WiFi. Cirque provides a service (gRPC or Flask REST) to create, destroy and manage multiple home environments with multiple virtual devices and radio capabilities between these devices.

## Installation:
### Prerequisites
```
sudo apt-get install bazel socat psmisc tigervnc-standalone-server tigervnc-viewer python3-pip python3-venv python3-setuptools
sudo pip3 install pycodestyle==2.5.0
```
### Make

```
make install
```

To install cirque without grpc support, just passing NO_GRPC environment variable to make:

```
make NO_GRPC=1 install
```

Note: You can consider running Cirque within a `virtualenv`

```
python3 -m venv venv
source venv/bin/activate
```

## Uninstallation:
```
make uninstall
```

## Features
- *Virtual Bluetooth (BLE & GATT)*: Provides a 100% kernel-module-free userspace
  Virtual Bluetooth H4/TCP medium (`cirque/virtual_bt/`) and container-local
  `org.bluez` D-Bus daemon + virtual `hci0` interface (`hciconfig`,
  `bluetoothctl`, `dbus-send`, `gdbus`), enabling multi-container BLE
  advertising, scanning, connection, GATT attribute read/write/notify, and
  Matter-over-BLE (`BTP`) commissioning without requiring `hci_vhci.ko` or host
  network mode (`use_legacy_btvirt=True` remains supported for legacy `btvirt`).

- *Virtual Wi-Fi*: Provides a 100% kernel-module-free userspace Virtual 802.11
  TCP medium + `fi.w1.wpa_supplicant1` D-Bus daemon + container-local `wlan0`
  TAP interface (`cirque/virtual_wifi/`), supporting 802.11 Beacon/Probe scan
  (`iwlist wlan0 scan`), WPA2-PSK 4-way handshake, `dhcpcd` IPv4/IPv6 leasing,
  and L2 Ethernet bridging between station containers only after association
  (`use_legacy_hwsim=True` remains supported for legacy `mac80211_hwsim`).

- *Thread*: Supports Thread protocol simulation via OpenThread RCP/NCP nodes,
  `socat` virtual serial pipes, and `SpinelHdlcRfProxy` (`ThreadSimPipe` in
  `cirque/connectivity/threadsimpipe.py`), which intercepts Spinel HDLC frames
  in userspace to inject realistic 802.15.4 RSSI, LQI, `SPINEL_STATUS_NO_ACK`
  frame drops, and ambient CCA energy without modifying OpenThread.

- *2.4 GHz Multi-Radio RF Channel & Coexistence Simulator*: `RfChannelSimulator`
  (`cirque/connectivity/rf_channel_simulator.py`) models shared 2.4 GHz ISM
  spectrum physics (log-distance + wall path loss, thermal noise, duty-cycled
  co-channel interference with spectral overlap SINR, and a logistic
  PER/LQI mapping) across BLE, Wi-Fi, and Thread with 2 built-in presets
  (`ideal`, `regime_c_cochannel_interference`) and live
  `/rf_channel` REST & MCP APIs. See
  [docs/rf_channel_simulation.md](docs/rf_channel_simulation.md).

- *Android Emulator Controller*: `AndroidDockerNode` (`cirque/nodes/`) runs a
  real headless KVM Android emulator with `CHIPTool.apk` inside a container and
  routes the guest Bluetooth HCI stream to the Virtual Bluetooth medium
  (`pty_bridge`, `cirque/virtual_bt/android/`) and the guest Wi-Fi frames to the
  Virtual Wi-Fi L2 relay (`-wifi-tap`), so CHIPTool commissions
  `chip-all-clusters-app` over BLE + Wi-Fi or BLE + Thread without the
  emulator's built-in radio simulators.

- *PCAP Capture*: `PcapCapability` (`cirque/capabilities/pcapcapability.py`)
  or the `CIRQUE_PCAP_DIR` environment variable writes Wireshark-readable pcap
  files for virtual BT HCI H4 (DLT 201), LE link-layer (DLT 251/256) and Wi-Fi
  L2 / EAPOL / DHCP / CASE frames (DLT 1);
  `python3 -m cirque.pcap.summarize_pcap` summarizes them without `tshark`.

- *IPvlan*: Allows users to create multiple real devices and multiple virtual
  devices within the same private network.


## Quick Start: Interactive Virtual Home (Virtual Bluetooth + Virtual Wi-Fi)

You can spin up a 2-Docker + Virtual AP home (`MobileController` +
`IoTEndDevice`) with both Virtual Bluetooth (`hci0` + `org.bluez`) and Virtual
Wi-Fi (`wlan0` + `fi.w1.wpa_supplicant1`) without loading any host kernel
modules:

### 1. Start the Interactive Virtual Home (Terminal 1)
```bash
PYTHONPATH=. python3 examples/run_virtual_home_interactive.py
```
This builds `cirque-virtual-rf-node:latest` automatically if missing, starts the
Virtual Bluetooth and Virtual Wi-Fi mediums, registers a sample BLE GATT
Device Info Service (`0x180A`) + Battery Service (`0x180F`) + Advertisement on
`IoTEndDevice`, and keeps the containers running until you press `Ctrl+C`.

### 2. Run One-Shot Automated CLI Validation (Terminal 2)
```bash
./examples/validate_virtual_home.sh
```
This script automatically discovers the running `MobileController` and
`IoTEndDevice` containers and validates:
1. `hciconfig -a` on both containers (`hci0 UP RUNNING`).
2. `bluetoothctl` (`devices`, `info`, `gatt.list-attributes`,
   `gatt.select-attribute`, `gatt.read`).
3. `dbus-send` & `gdbus` against `org.bluez` (`GetManagedObjects` and
   `ReadValue`).
4. `iwlist wlan0 scan`, `AddNetwork`, `SelectNetwork`, `dhcpcd wlan0`, and
   `ping -I wlan0` between `10.0.1.11` and `10.0.1.12`.

### 3. Step Inside the Docker Containers Manually
```bash
# Find the container names printed by run_virtual_home_interactive.py
docker exec -it <MobileController_Container> bash

# Inside the container:
hciconfig -a
bluetoothctl show
bluetoothctl scan on
bluetoothctl devices
bluetoothctl connect DC:A6:32:AA:BB:02
bluetoothctl gatt.list-attributes
CHAR_PATH=/org/bluez/hci0/dev_DC_A6_32_AA_BB_02/service0001/char0004
bluetoothctl gatt.select-attribute "$CHAR_PATH"
bluetoothctl gatt.read

# Validate Virtual Wi-Fi inside the container:
iwlist wlan0 scan
gdbus call --system --dest fi.w1.wpa_supplicant1 \
  --object-path /fi/w1/wpa_supplicant1/Interfaces/0 \
  --method org.freedesktop.DBus.Properties.Get \
  fi.w1.wpa_supplicant1.Interface State
ping -I wlan0 -c 4 10.0.1.12
```


## Quick Start: Android Emulator Virtual Home (BLE + Wi-Fi / BLE + Thread)

`AndroidDockerNode` boots a real headless Android emulator (`Pixel_6_API_34`,
`-no-window`, KVM) running `CHIPTool.apk` inside the `cirque-android-runner`
container. The guest's Bluetooth HCI stream is forwarded through
`pty_bridge` to `VirtualBluetoothServer`, and the guest's Wi-Fi frames leave the
emulator through `-wifi-tap cirque_tap0` into the Virtual Wi-Fi L2 relay, where
the station authenticates with the WPA2 EAPOL 4-way handshake and leases
`10.0.1.x` from `VirtualDhcpServer`. CHIPTool then commissions an
`IoTEndDevice` running `chip-all-clusters-app` over BLE PASE followed by CASE
and `OnOff` on `wlan0` (Wi-Fi) or over the simulated Thread network
(`chip-all-clusters-app --thread` with `otbr-agent`).

### Prerequisites
- `/dev/kvm` accessible by the current user and `/dev/net/tun` present.
- Android SDK with `emulator`, `platform-tools` and an x86_64 `Pixel_6_API_34`
  AVD (`ANDROID_SDK_ROOT`, defaults to `~/Android/Sdk`; `ANDROID_AVD_HOME`,
  defaults to `~/.android/avd`).
- `CHIPTOOL_APK` pointing at an x86_64 CHIPTool build. The default is
  `app-debug.apk` under `~/connectedhomeip/out/android-x64-chip-tool/`
  (`outputs/apk/debug/`).
- `CHIP_BUILD_ROOT` pointing at a `connectedhomeip/out` directory that holds
  `linux-x64-all-clusters/chip-all-clusters-app`.
- The `pty_bridge` Android binary, built once with
  `cirque/virtual_bt/android/build_pty_bridge.sh` (needs the Android NDK).

### 1. Run the Android Virtual Home E2E Test (in `connectedhomeip`)
```bash
CIRQUE_ANDROID_E2E=1 CIRQUE_PCAP_DIR=/tmp/cirque_pcaps \
  python3 \
  src/test_driver/linux-cirque/test_virtual_android_home_ble_wifi_e2e.py -v
```
Without `CIRQUE_ANDROID_E2E=1` only the hermetic unit tests of that module run;
the live classes are skipped.

### 2. Run One-Shot CLI Validation Against a Running Android Home
```bash
./examples/validate_virtual_android_home.sh --pcap-dir /tmp/cirque_pcaps
./examples/validate_virtual_android_home.sh --negative-psk
./examples/validate_virtual_android_home.sh --negative-bt
```
The script checks `adb devices`, the installed CHIPTool package, the running
`pty_bridge`, the guest `wlan0` DHCP lease, `chip-all-clusters-app` GATT
registration and BLE advertising, ICMP over `wlan0` / `cirque_tap0` between the
emulator and the device, and the BT / Wi-Fi pcap records. The negative options
must exit non-zero.

### 2b. Radio-Path Smoke Test Without CHIPTool or Matter Binaries
```bash
PYTHONPATH=. python3 examples/run_android_ci_smoke.py \
  --out-dir /tmp/android_smoke
```
`run_android_ci_smoke.py` boots the emulator in `cirque-android-runner`, starts
`pty_bridge`, and asserts refutable oracles that need neither `CHIPTOOL_APK`
nor `CHIP_BUILD_ROOT`: the `android_hci0` controller is bound on
`VirtualBluetoothServer` and has exchanged HCI packets, the emulator command
line pins its Bluetooth HAL to the external endpoint and its Wi-Fi to
`cirque_tap0`, both the guest `wlan0` and the `IoTEndDevice` `wlan0` hold
`10.0.1.x` leases from `VirtualDhcpServer`, and a guest-to-device ping through
the relay reports 0% loss. It then runs `validate_virtual_android_home.sh
--pcap-dir` on the live containers and writes `summary.json`, `logcat.txt`,
`device.log` and the pcaps to `--out-dir`. Exit code 2 means a precondition
(KVM, images, AVD) is missing. This is what the `android-emulator-virtual-home`
CI job runs on KVM-capable runners; see
[cirque/virtual_bt/android/README.md](cirque/virtual_bt/android/README.md)
for the bridge itself.

### 3. Drive the Same Flow Through the REST Service
`cirque/restservice/service.py` exposes `init_android_emulator`,
`commission_chiptool` (`network_type=wifi|thread`), `toggle_chiptool` and
`read_chiptool`; the connectedhomeip test drivers
`src/test_driver/linux-cirque/AndroidBleWiFiMobileDeviceTest.py` and
`AndroidBleThreadMobileDeviceTest.py` use them. See
[docs/VIRTUAL_RF_ARCHITECTURE.md](docs/VIRTUAL_RF_ARCHITECTURE.md) section 9
for the HCI, Wi-Fi and Thread data paths, the Thread dataset-completion helper
and the measured results.


## Test:
The below runs the unit test suite (including >=95% line coverage gates for
`cirque/virtual_bt` and `cirque/virtual_wifi`), the 2-Docker Virtual Home BLE +
Wi-Fi E2E test (`examples/test_virtual_home_ble_wifi_e2e.py`), and the
Flask/gRPC integration tests:

```bash
sh run_tests.sh
```

To run only the kernel-module-free Virtual Bluetooth & Virtual Wi-Fi unit and
2-Docker E2E tests directly:

```bash
PYTHONPATH=. python3 -m unittest -v \
  cirque/virtual_wifi/test_virtual_wifi_server.py
PYTHONPATH=. python3 -m unittest -v \
  cirque/capabilities/test/test_bluetooth_capability.py
PYTHONPATH=. python3 -m unittest -v \
  cirque/capabilities/test/test_wifi_capability.py
PYTHONPATH=. python3 -m unittest -v \
  examples/test_virtual_home_ble_wifi_e2e.py
```

That E2E test covers the radio path only. Commissioning a real
`chip-all-clusters-app` from `chip-tool` or an Android emulator over the same
topology needs connectedhomeip builds and lives in connectedhomeip
(`src/test_driver/linux-cirque/test_virtual_home_chip_ble_wifi_e2e.py`).

To run the Android emulator node, pcap, RF channel simulator, and Thread
dataset helper unit tests:

```bash
PYTHONPATH=. python3 -m unittest -v \
  cirque/connectivity/test_rf_channel_simulator.py
PYTHONPATH=. python3 -m unittest -v \
  cirque/nodes/test/test_androiddockernode.py
PYTHONPATH=. python3 -m unittest -v \
  cirque/capabilities/test/test_pcap_capability.py
PYTHONPATH=. python3 -m unittest -v \
  cirque/home/test_virtual_home_topology.py
```


# Directory Structure

The Cirque repository is structured as follows:

| File / Folder | Contents |
|----|----|
| `.github/workflows/main.yml` | GitHub Actions CI (coverage, E2E, Android). |
| `ARCHITECTURE.md` | High-level Cirque architecture overview. |
| `docs/VIRTUAL_RF_ARCHITECTURE.md` | Unified Virtual RF architecture. |
| `docs/rf_channel_simulation.md` | 2.4 GHz RF channel simulation design. |
| `docs/VIRTUAL_BT_DESIGN.md` | Virtual Bluetooth (`cirque/virtual_bt/`) doc. |
| `docs/VIRTUAL_WIFI_DESIGN.md` | Virtual Wi-Fi (`cirque/virtual_wifi/`) doc. |
| `cirque/` | Core implementation of Cirque. |
| `cirque/capabilities/` | Node capabilities (`BlueTooth`, `WiFi`, `Thread`). |
| `cirque/common/` | Cirque utility folder (logging, exceptions, helpers). |
| `cirque/connectivity/` | Connectivity handling (`HomeLan`, `SocatPipe`). |
| `cirque/grpc/` | gRPC service. |
| `cirque/home/` | Virtual home orchestration (`CirqueHome`). |
| `cirque/nodes/` | Docker, Wi-Fi AP and Android emulator node classes. |
| `cirque/pcap/` | pcap writer helpers and `summarize_pcap` CLI. |
| `cirque/proto/` | Cirque gRPC proto files. |
| `cirque/resources/` | Reference generic, Wi-Fi AP, and Virtual RF images. |
| `cirque/restservice/` | Cirque Flask REST service. |
| `cirque/virtual_bt/` | Virtual BT medium, `org.bluez`, `hci0`, PTY bridge. |
| `cirque/virtual_wifi/` | Userspace Virtual Wi-Fi, WPA2 EAPOL, DHCP, `wlan0`. |
| `dependency_modules.sh` | Script to prepare test docker nodes and emulator. |
| `examples/` | Integration examples, Virtual Home and Android validation. |
| `LICENSE` | Cirque license file (Apache 2.0). |
| `Makefile` | Build, install, and style-check targets. |
| `requirements.txt` | Python pip requirement file. |
| `utils/` | Cirque build utilities. |
| `contributing.md` | Guidelines for contributing to Cirque. |
| `setup.py` | Build script for setuptools. |
| `README.md` | This file. |
| `run_tests.sh` | Cirque unit and integration test script. |
| `version` | Release version tag. |
