# Android Emulator Bluetooth Bridge (`cirque/virtual_bt/android`)

This directory contains the one piece of Cirque's virtual Bluetooth stack that
runs *inside the Android emulator guest* rather than on the host:
`pty_bridge`, a small static C program that hands the Android Bluetooth HAL
to Cirque's userspace `VirtualBluetoothServer`.

| File                  | Purpose                                            |
| --------------------- | -------------------------------------------------- |
| `pty_bridge.c`        | PTY <-> TCP HCI H4 bridge run in the Android guest |
| `build_pty_bridge.sh` | Cross-compiles `pty_bridge` with the NDK (x86_64)  |
| `pty_bridge`          | Build output (git-ignored); mounted into runner    |

## Why a bridge is needed

The emulator's Bluetooth HAL (`android.hardware.bluetooth-service.default`)
speaks HCI H4 to a character device. Out of the box that device is served by
the emulator's built-in Bluetooth simulator, which has no notion of Cirque's
virtual link layer. `AndroidDockerNode` therefore starts the emulator with
`-feature -BluetoothEmulation -feature -WiFiPacketStream` (so no built-in
radio simulator serves either radio and the emulator does not try to reach a
packet-streamer endpoint) and then runs `pty_bridge` in the guest to provide
the HCI transport itself:

```
Android BT stack / HAL
        | HCI H4
        v
/dev/bluetooth0  --symlink-->  PTY slave
                                  |
                           pty_bridge (PTY master)
                                  | TCP  "BIND android_hci0\n" + raw H4
                                  v
          VirtualBluetoothServer (host, cirque/virtual_bt/server.py)
                                  |
                      virtual controller  +  LE link layer relay
                                  |
                  Docker IoTEndDevice controllers (chip-all-clusters-app)
```

Nothing in this path loads a kernel module, runs `bluetoothd`, or depends on
any emulator radio daemon. The bridge is byte-transparent; H4 framing, HCI
command/event handling and advertising/connection relay all happen in the
Python server.

## Wire protocol

After connecting, `pty_bridge` writes exactly one ASCII line,
`BIND <bind_id>\n` (default `android_hci0`). The server binds the TCP stream
to the virtual controller with that id; every byte after the newline, in both
directions, is raw HCI H4.

## Usage

```
pty_bridge <pty_symlink_path> <host_ip> <port> [bind_id]
```

You normally never run it by hand. `AndroidDockerNode.start_pty_bridge()`
(`cirque/nodes/androiddockernode.py`):

1. ensures the binary exists (`ensure_pty_bridge_binary()` calls
   `build_pty_bridge.sh` if it is missing),
2. `adb push`es it to `/data/local/tmp/pty_bridge`,
3. launches `pty_bridge /dev/bluetooth0 <gateway_ip> <hci_port> android_hci0`
   inside the guest, pinning a `/32` route for the gateway via the emulator's
   `eth0` so the TCP link survives later guest Wi-Fi route changes,
4. restarts `bt_vhci_forwarder` and the Bluetooth HAL so they reopen
   `/dev/bluetooth0`, which now points at the bridge's PTY.

Exit codes and the full lifecycle are documented at the top of
`pty_bridge.c`.

## Building

```
./build_pty_bridge.sh            # auto-detects the newest NDK under the SDK
ANDROID_NDK_HOME=/path/to/ndk ./build_pty_bridge.sh
PTY_BRIDGE_API=34 ./build_pty_bridge.sh
./build_pty_bridge.sh --help
```

Requirements: an Android NDK with the `x86_64-linux-android<API>-clang`
toolchain. The output is a statically linked x86_64 ELF (API 34 by default,
matching the `Pixel_6_API_34` AVD) placed next to the source. CI builds it on
every run (`android-emulator-virtual-home` job in
`.github/workflows/main.yml`) and asserts the result is a static x86-64 ELF.

## Verifying the bridge on a live run

```
examples/run_android_ci_smoke.py --out-dir /tmp/android_smoke
examples/validate_virtual_android_home.sh --pcap-dir /tmp/android_smoke/pcap
```

The smoke test boots the emulator, starts the bridge, and asserts that the
`android_hci0` controller is bound on the server and has exchanged HCI
packets (the Android stack sends `HCI_Reset` as soon as the HAL attaches),
before checking the Wi-Fi tap data plane. With `CIRQUE_PCAP_DIR` set, the
server also writes `bt_hci_android_hci0.pcap` (DLT 201, H4 with direction
header), which Wireshark decodes directly.

## Related documentation

* `docs/VIRTUAL_BT_DESIGN.md` - server, controller and link-layer design
* `docs/VIRTUAL_RF_ARCHITECTURE.md` - how BT and Wi-Fi virtual media fit
  together, including the Android emulator topology
* `cirque/nodes/Dockerfile.android_runner` - the container image in which the
  emulator and `adb` run
