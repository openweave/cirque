#!/bin/bash
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

cleanup() {
  pkill -TERM -f emulator 2>/dev/null || true
  exit 0
}

trap cleanup TERM INT

ip_addr=$(ifconfig eth0 | awk '/inet / {print $2}')
base_ipaddr=$(echo "$ip_addr" | cut -d"." -f1-3)
network="$base_ipaddr.0"

ip tuntap add dev tap0 mode tap user "$(whoami)"
ip link add br0 type bridge
ip link set tap0 master br0
ip link set eth0 master br0
ip addr flush dev eth0
ip link set tap0 up
ip link set br0 up
ifconfig eth0 0.0.0.0 promisc
ifconfig tap0 0.0.0.0 promisc
ip addr add "$ip_addr/24" dev br0
route add default gw "$base_ipaddr.1" br0
sysctl -w net.ipv4.ip_forward=1

if ip link show tap0 >/dev/null 2>&1 && ip link show wlan0 >/dev/null 2>&1; then
  ip link set wlan0 master br0 2>/dev/null || true
  echo 0 > /sys/devices/virtual/net/br0/bridge/multicast_snooping 2>/dev/null \
    || ip link set dev br0 type bridge mcast_snooping 0 2>/dev/null || true
fi

cat <<EOT >> /etc/dnsmasq.conf
interface=br0
bind-interfaces
dhcp-option=3,$base_ipaddr.1
dhcp-option=6,8.8.8.8,8.8.4.4
dhcp-range=$base_ipaddr.5,$base_ipaddr.9,255.255.255.0,12h
no-hosts
EOT

/etc/init.d/dnsmasq restart

emulator -avd emulator -no-boot-anim -no-audio -net-tap tap0 -no-accel \
  -no-window &
EMULATOR_PID=$!

wait "$EMULATOR_PID"
