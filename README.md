# Cirque

## Introduction

Cirque simulates complex network topologies based upon docker nodes. On a single Linux machine, it can create multiple nodes with network stacks that are independent from each other. Some nodes may be connected to simulated Thread networks, others may connect to simulated BLE or WiFi. Cirque provides a service (gRPC or Flask REST) to create, destroy and manage multiple home environments with multiple virtual devices and radio capabilities between these devices.

## Installation:

```
make install
```

Note: You can consider running Cirque within a `virtualenv`

```
python3 -m venv venv-test
source venv-test/bin/activate
```

## Unit Test:

```
sudo sh run_unit_tests.sh
```

## Integration Test:

It runs `test_flask_virtual_home.py` and `test_grpc_virtual_home.py`
```
sudo sh run_integration_tests.sh
```

## Uninstallation:
```
make uninstall
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
| `run_unit_test.sh ` | Cirque unit test script.|
| `utils` | Cirque Build utilities. |
| `WORKSPACE` | Bazel workspace. |
| `BUILD` | Bazel Build file.|
| `contributing.md` | Guidelines for contributing to Cirque. |
| `examples/` | Cirque integration examples. |
| `setup.py` | Build script for setuptools. |
| `README.md` | This file. |
| `run_integration_tests.sh` | Cirque integration example test script. |
| `version` | Release version tag. |
