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

Note: You can consider running Cirque within a `virtualenv`

```
python3 -m venv venv
source venv/bin/activate
```

## Uninstallation:
```
make uninstall
```

## Command Line Interface:
supports tab command completion, here is how to run cli interface

```
sudo venv/python3/bin -m cirque.common.cirqueprompt
# you will see, prompt interface like this
Welcome to cirque shell <version>
cirque> 
```

supported commands

```
cirque> help
# print out
Documented commands (use 'help -v' for verbose/'help <topic>' for details):
===========================================================================
close_device   create_home   device_state  help     home_devices  run_exec
create_device  destroy_home  exit          history  homes         version
```

learn usage for a specific command

```
cirque> help close_device
# print out
close cirque device
Args:
    --home_id (str): device under specific home_id, if not
            given, automatically set to current home_id.
    --device_id (str): device id
Usage:
    close_device [--home_id <home_id>] --device_id <device_id>
```

examples of using all the supported commands and prints out

```
# create_home
cirque> create_home
home_id: 0 created!

# create a wifi_ap
cirque> create_device --type wifi_ap
wifi_ap created in home_id: 0!!
device id: 0130ef03dd24f4fbb76c332a776c9f50b7ecccf3feda786c1853f1e377845a2b

# create a generic node with WiFI, Thread, Interactive capabilities and set thread mode to rcp
cirque> create_device --type generic_node_image --capability WiFi,Thread,Interactive --thread_mode rcp
generic_node_image created in home_id: 0!!
device id: 3dbe0781bfb2a9ae52a4c4963108a40d9210d915165f262b58461e92afa82776

# list home devices
cirque> home_devices
home id: 0
home devices: { '0130ef03dd24f4fbb76c332a776c9f50b7ecccf3feda786c1853f1e377845a2b': { 'base_image': 'mac80211_ap_image',
                                                                        'capability': { 'WiFi': { }},
                                                                        'description': { 'psk': 'WQDO9RC2',
                                                                                         'ssid': 'wifiap-NMAT2',
                                                                                         'type': 'wifi_ap'},
                                                                        'id': '0130ef03dd24f4fbb76c332a776c9f50b7ecccf3feda786c1853f1e377845a2b',
                                                                        'name': 'compassionate_cannon',
                                                                        'type': 'wifi_ap'},
  '3dbe0781bfb2a9ae52a4c4963108a40d9210d915165f262b58461e92afa82776': { 'base_image': 'generic_node_image',
                                                                        'capability': { 'Interactive': { },
                                                                                        'Thread': { },
                                                                                        'WiFi': { },
                                                                                        'external': { }},
                                                                        'description': { 'ipv4_addr': '172.26.0.2'},
                                                                        'id': '3dbe0781bfb2a9ae52a4c4963108a40d9210d915165f262b58461e92afa82776',
                                                                        'name': 'loving_dubinsky',
                                                                        'type': 'generic_node_image'}}

# run wifi scan on generic node
cirque> run_exec --device_id 3dbe0781bfb2a9ae52a4c4963108a40d9210d915165f262b58461e92afa82776 --command iwlist wlan0 scanning
args.command: iwlist wlan0 scanning
command result:
ExecResult(exit_code=0, output=b'wlan0     Scan completed :\n          Cell 01 - Address: 02:00:00:00:00:00\n                    Channel:6\n                    Frequency:2.437 GHz (Channel 6)\n                    Quality=70/70  Signal level=-30 dBm  \n                    Encryption key:on\n                    ESSID:"wifiap-NMAT2"\n                    Bit Rates:1 Mb/s; 2 Mb/s; 5.5 Mb/s; 11 Mb/s; 6 Mb/s\n                              9 Mb/s; 12 Mb/s; 18 Mb/s\n                    Bit Rates:24 Mb/s; 36 Mb/s; 48 Mb/s; 54 Mb/s\n                    Mode:Master\n                    Extra:tsf=0005aa7174aea981\n                    Extra: Last beacon: 12ms ago\n                    IE: Unknown: 000C7769666961702D4E4D415432\n                    IE: Unknown: 010882848B960C121824\n                    IE: Unknown: 030106\n                    IE: Unknown: 2A0104\n                    IE: Unknown: 32043048606C\n                    IE: IEEE 802.11i/WPA2 Version 1\n                        Group Cipher : TKIP\n                        Pairwise Ciphers (1) : TKIP\n                        Authentication Suites (1) : PSK\n                    IE: Unknown: 3B025100\n                    IE: Unknown: 7F080400400000000040\n\n')

# checking device status and information
cirque> device_state --device_id 0130ef03dd24f4fbb76c332a776c9f50b7ecccf3feda786c1853f1e377845a2b
device state: { 'base_image': 'mac80211_ap_image',
  'capability': {'WiFi': {}},
  'description': {'psk': 'WQDO9RC2', 'ssid': 'wifiap-NMAT2', 'type': 'wifi_ap'},
  'id': '0130ef03dd24f4fbb76c332a776c9f50b7ecccf3feda786c1853f1e377845a2b',
  'name': 'compassionate_cannon',
  'type': 'wifi_ap'}

# close device
cirque> close_device --device_id 3dbe0781bfb2a9ae52a4c4963108a40d9210d915165f262b58461e92afa82776
device: 3dbe0781bfb2a9ae52a4c4963108a40d9210d915165f262b58461e92afa82776 closed!!

# create multiple homes
cirque> create_home
home_id: 1 created!

# list all created homes
cirque> homes
['0', '1']

# tear down a specific home
cirque> destroy_home --home_id 0
closing device: 0130ef03dd24f4fbb76c332a776c9f50b7ecccf3feda786c1853f1e377845a2b
successfully destroy home: 0

# list historical commands
cirque> history
    1  create_home
    2  create_device --type wifi_ap
    3  create_device --type generic_node_image --capability WiFi,Thread,Interactive --thread_mode rcp
    4  home_devices
    5  run_exec --device_id be7f400ddad67676247a76f39513097b841584f43cae9f86cdce755bc97fd708 --command iwlist wlan0 scanning
    6  device_state --device_id a8bf216323dfc459addad5fe2b4701e98dfa906f64d8f889187b87e0c84a47aa
    7  close_device --device_id be7f400ddad67676247a76f39513097b841584f43cae9f86cdce755bc97fd708
    8  create_home
    9  homes
   10  destroy_home --home_id 0

# list version
cirque> version
1.7.6

# tear down remaining homes and exit cirque cli
cirque> exit
successfully destroy home: 1
~/Github$
```





## Test:
The below runs unit tests and integration tests including `test_flask_virtual_home.py` and `test_grpc_virtual_home.py`

```
sudo sh run_tests.sh
```


# Directory Structure

The Cirque repository is structured as follows:

| File / Folder | Contents |
|----|----|
| `ARCHITECTURE.md` | Cirque architecture file. |
| `cirque/` | Implementation of Cirque. |
| `cirque/capabilities/` | Virtual node capabilities implementation.|
| `cirque/common/` | Cirque utility folder including logging, exception and etc.|
| `cirque/connectivity/` | Cirque connectivity handling implementation. |
| `cirque/grpc/` | gRPC service.|
| `cirque/home` | Virtual home implementation.|
| `cirque/nodes` | Cirque Docker node implementation. |
| `cirque/resources` | Reference generic node and wifi AP docker Files. |
| `cirque/restservice` | Cirque rest service. |
| `cirque/proto` | Cirque gRPC proto files. |
| `dependency_modules.sh` | Convenience script to prepare test docker nodes and radio emulator.|
| `LICENSE` | Cirque license file (Apache 2.0). |
| `requirements.txt` | Python pip requirement file. |
| `utils` | Cirque Build utilities. |
| `WORKSPACE` | Bazel workspace. |
| `BUILD` | Bazel Build file.|
| `contributing.md` | Guidelines for contributing to Cirque. |
| `examples/` | Cirque integration examples. |
| `setup.py` | Build script for setuptools. |
| `README.md` | This file. |
| `run_tests.sh` | Cirque unit and integration test script. |
| `version` | Release version tag. |
