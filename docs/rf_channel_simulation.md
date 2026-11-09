# Cirque 2.4 GHz Multi-Radio RF Channel & Coexistence Simulation Design

> [!IMPORTANT]
> **Canonical Design Document**: This file mirrors [VIRTUAL_RF_CHANNEL_SIMULATION_DESIGN.md](./VIRTUAL_RF_CHANNEL_SIMULATION_DESIGN.md) for backward-compatible documentation links.
> - [Unified Virtual RF Architecture (`docs/VIRTUAL_RF_ARCHITECTURE.md`)](./VIRTUAL_RF_ARCHITECTURE.md)
> - [Virtual Bluetooth Design (`docs/VIRTUAL_BT_DESIGN.md`)](./VIRTUAL_BT_DESIGN.md)
> - [Virtual Wi-Fi Design (`docs/VIRTUAL_WIFI_DESIGN.md`)](./VIRTUAL_WIFI_DESIGN.md)

---

## 1. Overview & Motivation

By default, virtualized smart-home testbeds operate in an **idealized (`0%` loss, constant RSSI)** radio regime where every BLE advertisement, Wi-Fi L2 frame, and IEEE 802.15.4 Thread packet is delivered instantaneously with deterministic signal strength (`-38` to `-44 dBm`, `LQI = 255`, `PER = 0.0`). While effective for happy-path functional smoke tests, this ideal environment masks timing-sensitive protocol bugs, exchange-pool exhaustion, asymmetric link traps, and retransmission race conditions in upper-layer stacks such as Matter (`connectedhomeip`) and OpenThread.

`RfChannelSimulator` (`cirque/connectivity/rf_channel_simulator.py`) and `SpinelHdlcRfProxy` (`cirque/connectivity/threadsimpipe.py`) introduce a unified, literature-grounded **2.400–2.4835 GHz ISM Multi-Radio RF Channel & Coexistence Simulator** across all three virtual radios in Cirque—**Bluetooth Low Energy (BLE)**, **IEEE 802.11 (Wi-Fi)**, and **IEEE 802.15.4 (Thread)**—entirely within Cirque userspace and **with zero modifications to the OpenThread or Matter C++ codebases**.

---

## 2. 2.4 GHz Channel Model

1. **Log-Distance Path Loss + Wall Attenuation**:
   $$PL(d) = PL(d_0) + 10 \, n \, \log_{10}\!\left(\frac{\max(d, d_{\min})}{d_0}\right) + N_{\text{walls}} \, W$$
2. **Thermal Noise Floor and Spectral-Overlap Interference SINR** (each interferer on with probability $D_k$ per packet, seeded):
   $$\text{SINR}_{\text{dB}} = P_{\text{rx,dBm}} - 10 \log_{10}\!\left(10^{N_{0,\text{dBm}}/10} + \sum_{k \in \text{on}} \alpha_{ik} \, I_{k,\text{mW}}\right)$$
3. **Logistic PER** $= 1 / (1 + e^{(\text{SINR}_{\text{dB}} - \text{SINR}_{50}) / s})$ capped by `max_per_cap`, and linear SINR $\to$ IEEE 802.15.4 LQI (`0..255`) / OpenThread `LQ In` (`0..3`).

---

## 3. Built-In RF Presets

- `ideal`: Default `0%` loss deterministic baseline (`enabled=False`).
- `regime_c_cochannel_interference`: Fixed `d=20m`, $n=3.4$ link with one Wi-Fi Ch 4 (`+20 dBm`, `90%` duty cycle) interferer overlapping Thread Ch 15, BLE Ch 38 and Wi-Fi Ch 6 (`max_per_cap=0.45`).

---

## 4. Protocol-Level Race Conditions Exposed by RF Presets

For Matter (`connectedhomeip`) protocol-level tests that exercise packet loss, see `docs/testing/cirque_rf_lossy_link.md` in the `connectedhomeip` repository.
