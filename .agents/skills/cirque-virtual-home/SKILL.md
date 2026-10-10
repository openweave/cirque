---
name: cirque-virtual-home
description:
    Protocol-agnostic virtual home and RF network simulation in Cirque. Use
    when creating, managing, or diagnosing simulated RF topologies (Virtual
    Bluetooth LE/GATT, Virtual Wi-Fi WPA2, OpenThread mesh, Android emulator
    nodes), running cross-layer PCAP capture and flow visualizer generation,
    or extending Cirque base MCP tools. Don't use for Matter-specific
    PASE/CASE commissioning or CHIPTool cluster actions; use
    `cirque-virtual-testing` in `connectedhomeip` instead.
---

# Cirque Virtual Home: Protocol-Agnostic Virtual RF & Node Orchestration

## Overview

Cirque provides multi-node network simulation inside isolated Docker containers
on a single Linux host without requiring external hardware or physical RF
radios. It orchestrates virtual RF media entirely in userspace:
- **Virtual Bluetooth LE**: Userspace TCP H4 transport + BlueZ D-Bus integration
  + Android `virtio-console` bridge.
- **Virtual Wi-Fi**: Userspace 802.11 beacon/probe/data transport + WPA2-PSK
  4-way handshake state machine + userspace DHCP/SLAAC + container TAP bridge
  (`cirque_tap0`).
- **Virtual Thread**: OpenThread simulation (`ot-sim`) over POSIX pipes or UDP,
  plus dedicated Thread Border Router nodes (`ot-br-posix`).
- **Android Emulator Node**: Headless KVM-accelerated Android emulator running
  inside Docker with bridged virtual Bluetooth/Wi-Fi radios and MP4 screen
  recording.
- **Cross-Layer PCAP Flow Visualizer**: Interleaved packet dissector across HCI,
  Wi-Fi, Thread, and application layers rendering interactive HTML5 sequence
  diagrams.

Cirque exposes these capabilities through a native Model Context Protocol (MCP)
server conforming to JSON-RPC 2.0.

---

## Cirque Base MCP Tools (14 Tools)

The Cirque MCP server (`cirque/mcp/server.py`) registers 14 core
protocol-agnostic tools:

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `cirque_list_homes` | `{}` | Lists active Cirque virtual homes, device counts, and node types. |
| `cirque_create_virtual_home` | `preset`, `config`, `ssid`, `wifi_psk`, `avd_name`, `pcap_dir`, `wifi_auto_connect` | Creates a virtual home from a preset (`two_node_ble_wifi`, `android_ble_wifi`, `android_ble_thread`) or custom configuration dictionary. |
| `cirque_get_home_topology` | `home_id` | Returns full device descriptions, IPv4/IPv6 addresses, radio capabilities, and topology metadata for a virtual home. |
| `cirque_destroy_home` | `home_id` | Cleanly tears down a specific virtual home by ID or `"all"` virtual homes. |
| `cirque_execute_device_cmd` | `home_id`, `device_id`, `cmd`, `stream` | Executes a shell command inside a specific device container in a virtual home. |
| `cirque_get_radio_state` | `home_id`, `android_device_id` | Returns real-time Virtual Bluetooth and Virtual Wi-Fi server states, frame counters, and Android radio path status. |
| `cirque_summarize_pcaps` | `pcap_dir` | Summarizes all PCAP files (`bt_hci_*.pcap`, `bt_medium.pcap`, `wifi_medium.pcap`, `thread_*.pcap`) in a directory. |
| `cirque_inspect_thread_mesh` | `home_id` | Queries `ot-ctl` state, IPv6 addresses, PAN ID, ExtPANID, channel, child table, counters, and kernel routing table across Thread nodes. |
| `cirque_inject_rf_fault` | `recipe`, `bt_relay_enabled`, `bt_packet_loss_rate`, `bt_latency_ms`, `bt_rssi_dbm`, `bt_src_bd_addr`, `bt_dst_bd_addr`, `wifi_drop_station`, `wifi_deauth_station`, `wifi_reassociate_station` | Injects or clears deterministic RF faults across Bluetooth and Wi-Fi, or executes named chaos recipes (`ble_brownout`, `ble_restore`, `wifi_deauth_roam`, `clear_all_faults`). |
| `cirque_android_ui_and_video` | `home_id`, `device_id`, `action`, `resource_id`, `text`, `content_desc`, `fallback_coords`, `text_to_input`, `timeout_sec`, `recording_name`, `bit_rate` | Inspects Android UI hierarchy, finds elements, injects taps/text, handles system dialogs, or manages MP4 screen recordings (`dump_ui`, `find_element`, `tap`, `input_text`, `dismiss_dialogs`, `start_recording`, `stop_recording`, `list_recordings`). |
| `cirque_diagnose_home_health` | `home_id`, `android_device_id` | Evaluates cross-layer health oracles across containers, Bluetooth, Wi-Fi, and registered extension oracles. |
| `cirque_register_mcp_extension` | `module_or_path` | Dynamically registers and activates an external Cirque MCP extension module or file. |
| `cirque_list_mcp_extensions` | `{}` | Lists all dynamically registered Cirque MCP extensions, tools, resources, prompts, and health oracles. |
| `cirque_generate_flow_visualization` | `pcap_dir`, `output_html`, `output_json`, `title` | Dissects PCAP packet captures and merged flow events into an interactive HTML5 Studio and JSON trace. |

---

## Virtual RF Topology Recipes

### 1. Userspace Virtual Bluetooth (`cirque/virtual_bt/`)

The Virtual Bluetooth subsystem provides 100% kernel-module-free BLE and GATT
simulation without requiring `hci_vhci.ko` or privileged host networking:
- **H4 TCP Server (`cirque/virtual_bt/server.py`)**: Listens on TCP localhost
  (default port 10000 or dynamic). Nodes connect via H4 TCP client sockets
  (`cirque/virtual_bt/hci_h4.py`).
- **BlueZ D-Bus Daemon (`cirque/virtual_bt/bluez_dbus_daemon.py`)**: Runs an
  emulated BlueZ D-Bus service inside target containers, providing standard
  `org.bluez.Adapter1`, `org.bluez.Device1`, and `org.bluez.GattCharacteristic1`
  interfaces.
- **Android `virtio-console` HCI Bridge**
  (`cirque/virtual_bt/android/pty_bridge.c`): Bridges guest Android kernel
  Bluetooth HAL (`/dev/bluetooth0` or `/dev/ttyS1`) directly to the
  userspace H4 TCP socket.

**Workflow Recipe: Standalone Virtual BT Test**
```python
from cirque.virtual_bt.server import VirtualBluetoothServer
from cirque.virtual_bt.client import H4TcpClient

# 1. Start server with PCAP capture enabled
server = VirtualBluetoothServer(port=0)
server.start()
server.enable_pcap('/tmp/bt_pcaps')

# 2. Connect Central and Peripheral controllers
central = H4TcpClient(
    '127.0.0.1', server.hci_port, bind_controller_id='hci0'
)
peripheral = H4TcpClient(
    '127.0.0.1', server.hci_port, bind_controller_id='hci1'
)

# 3. Transmit BLE advertising & connect
peripheral.start_advertising(b'\x02\x01\x06\x03\x03\xf6\xff')
central.start_scanning(active=True)
report = central.wait_for_advertisement(timeout=5.0)
handle = central.connect(report['bd_addr'], timeout=5.0)
```

### 2. Userspace Virtual Wi-Fi (`cirque/virtual_wifi/`)

The Virtual Wi-Fi subsystem simulates 802.11 b/g/n infrastructure mode:
- **Wi-Fi Server (`cirque/virtual_wifi/server.py`)**: Handles Beacon frames,
  Probe Requests/Responses, and 802.11 Association.
- **WPA2 4-Way Handshake (`cirque/virtual_wifi/eapol.py`)**: Executes authentic
  EAPOL-Key exchanges (Message 1 through 4) to derive Pairwise Transient
  Keys (PTK).
- **L2 TAP Relay (`cirque/virtual_wifi/docker_wifi_bridge.py`)**: Bridges
  Ethernet frames between station TAP interfaces (`cirque_tap0`) only after
  WPA2 association completes.
- **WPA Supplicant D-Bus** (`cirque/virtual_wifi/wpa_dbus_daemon.py`):
  Implements `fi.w1.wpa_supplicant1` inside station containers.

### 3. OpenThread Mesh & Border Router
(`cirque/capabilities/threadcapability.py`)

Simulates Thread 1.3/1.4 mesh networks using native OpenThread simulation
binaries:
- Nodes execute `ot-sim` communicating via Unix sockets or UDP pipes.
- Thread Border Router (OTBR) nodes execute `ot-br-posix` with `wpan0` and
  `eth0` interfaces.
- The MCP tool `cirque_inspect_thread_mesh` evaluates partition roles
  (`leader`, `router`, `child`), ExtPANID, active operational dataset TLVs,
  and route tables.

### 4. Android Docker Node (`cirque/nodes/androiddockernode.py`)

Runs a full headless Android Virtual Device (AVD) inside a privileged Docker
container:
- Hardware KVM acceleration enabled via `/dev/kvm`.
- Screen recording via `screenrecord` captures live UI flows to MP4 files.
- UI inspection and manipulation via `cirque_android_ui_and_video` (`dump_ui`,
  `tap`, `input_text`).

---

## Cross-Layer PCAP Flow Visualizer (`cirque/pcap/flow_visualizer.py`)

Dissects captured PCAP files and recorded events into a standalone HTML5
Studio:
- **Supported Formats**: Bluetooth HCI UART (DLT 201), LE LL (DLT 256), Wi-Fi
  Ethernet (DLT 1), Thread IEEE 802.15.4 (DLT 195), and application log events.
- **Matter / Thread Decryption**: Supports
  `--session-keys matter_session_keys.txt` (PASE/CASE keys via
  `cirque/protocols/matter/session.py`) and `cirque/pcap/thread_keys.py`
  (`thread_network_key.txt`).
- **Filtering & Sequence Windowing**: Features a `#filter-btn-DECRYPTED_WIRE`
  pill, layer toggles, and 150-frame adaptive sequence windowing.

**CLI Recipe:**
```bash
python3 -m cirque.pcap.flow_visualizer \
    --pcap-dir /path/to/device_logs \
    --output /path/to/device_logs/cirque_flow_visualization.html \
    --json-output /path/to/device_logs/cirque_flow_trace.json \
    --require-non-empty
```

---

## Dynamic MCP Extension Contract

Cirque supports dynamic runtime extensions without modifying core code. An
extension module or script defines:

```python
def register_cirque_extension(server):
    """Entry point called by CirqueMcpServer during registration."""
    # 1. Register custom tools
    server.register_tool(
        schema_dict={
            'name': 'custom_tool',
            'description': 'Custom extension tool',
            'inputSchema': {'type': 'object', 'properties': {}},
        },
        handler_fn=lambda args: {'status': 'ok'},
        extension_name='my_extension',
    )
    # 2. Register health oracles, resources, or prompts
    server.register_health_oracle(
        'custom_health', my_oracle, extension_name='my_extension'
    )
```

Extensions can be loaded automatically via the `CIRQUE_MCP_EXTENSIONS`
environment variable:
```bash
export CIRQUE_MCP_EXTENSIONS="/path/to/extension_a.py,/path/to/extension_b.py"
```
or dynamically at runtime using the `cirque_register_mcp_extension` MCP tool.
