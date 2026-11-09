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
# Cross-compile pty_bridge.c into a static Android x86_64 binary.
#
# pty_bridge runs inside the Android emulator guest and bridges the guest's
# Bluetooth HAL (HCI H4 over /dev/bluetooth0) to Cirque's userspace
# VirtualBluetoothServer over TCP. See pty_bridge.c for the design.
#
# Usage:
#   build_pty_bridge.sh [-h|--help]
#
# Environment (first match wins):
#   ANDROID_NDK_HOME / ANDROID_NDK_ROOT
#       Explicit NDK root. If unset or not a directory, the newest
#       <SDK>/ndk/<version> directory is used instead.
#   ANDROID_HOME / ANDROID_SDK_ROOT
#       SDK root used for NDK auto-discovery (default: $HOME/Android/Sdk).
#   PTY_BRIDGE_API
#       Android API level of the clang target triple (default: 34, which
#       matches the Pixel_6_API_34 AVD used by AndroidDockerNode).
#
# Output:
#   <this directory>/pty_bridge  (git-ignored). AndroidDockerNode mounts this
#   directory into the cirque-android-runner container at
#   /opt/virtual_bt_android and `adb push`es the binary to /data/local/tmp.
#   If the binary is missing at run time, androiddockernode.py invokes this
#   script automatically (ensure_pty_bridge_binary).
#
# Why static + x86_64:
#   The emulator system image used by Cirque is x86_64. Linking statically
#   against the NDK's Bionic avoids any dependency on the guest's shared
#   libraries so the same binary works from /data/local/tmp on any image of
#   the same ABI.
#
# Exit status:
#   0 on success; 1 if no NDK or no clang for the target can be found;
#   otherwise the compiler's exit status.
set -euo pipefail

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
    sed -n '16,50p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_DIR="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}}"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
API_LEVEL="${PTY_BRIDGE_API:-34}"

# Fall back to the newest NDK installed under the SDK (sort -V orders
# "25.2.9519653" before "26.1.10909125").
if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
    NDK=$(find "$SDK_DIR/ndk" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
        | sort -V | tail -n 1)
fi
if [ -z "$NDK" ] || [ ! -d "$NDK" ]; then
    echo "Error: Android NDK not found. Please set ANDROID_NDK_HOME." >&2
    exit 1
fi

CC="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
CC="$CC/x86_64-linux-android${API_LEVEL}-clang"
if [ ! -x "$CC" ]; then
    echo "Error: NDK clang for API ${API_LEVEL} not found at $CC" >&2
    exit 1
fi

echo "Compiling pty_bridge.c with $CC..."
"$CC" -O2 -static "$SCRIPT_DIR/pty_bridge.c" -o "$SCRIPT_DIR/pty_bridge"
echo "Cross-compilation successful:"
# `file` is informational only; do not fail the build if it is missing.
file "$SCRIPT_DIR/pty_bridge" 2>/dev/null || ls -l "$SCRIPT_DIR/pty_bridge"
