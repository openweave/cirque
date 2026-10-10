# Cirque Agent Skills

This directory contains skills and instructions for AI agents to assist with
protocol-agnostic virtual RF simulation, topology management, and testing in
Cirque.

## Available Skills

### Cirque Virtual Home

-   **Location**: `.agents/skills/cirque-virtual-home/`
-   **Purpose**: Protocol-agnostic virtual home and RF network simulation in
    Cirque.
-   **Triggers**: Use when creating, managing, or diagnosing simulated RF
    topologies (Virtual Bluetooth LE/GATT, Virtual Wi-Fi WPA2, OpenThread
    mesh, Android emulator nodes), running cross-layer PCAP capture and flow
    visualizer generation, or extending Cirque base MCP tools. Don't use for
    Matter-specific PASE/CASE commissioning or CHIPTool cluster actions; use
    `cirque-virtual-testing` in `connectedhomeip` instead.
