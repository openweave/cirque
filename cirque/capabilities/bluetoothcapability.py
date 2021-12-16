# Copyright 2021 Google LLC
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
import os
import time
from os.path import abspath, dirname
from cirque.capabilities.basecapability import BaseCapability
from cirque.common.cirquelog import CirqueLog

import cirque.common.utils as utils

CIRQUE_ROOT = dirname(dirname(dirname(abspath(__file__))))
BLUEZ_DIR = os.path.join(CIRQUE_ROOT, "bluez")


class BlueToothCapability(BaseCapability):

    BLE_ADAPTS_LIST = list()

    def __init__(self, num_btvirts=2):
        self.num_btvirts = num_btvirts
        self.logger = CirqueLog.get_cirque_logger(self.__class__.__name__)
        self.__run_bluetoothd()
        self.__run_btvirt_infs()
        self.__get_ble_controller()
    @property
    def name(self):
        return "Bluetooth"

    def get_docker_run_args(self, docker_node):
        return {
            'environment': {
                'BLE_ADAPT': self.ble_adapt,
            },
            'volumes': [
                '/var/run/dbus:/var/run/dbus'
            ],
            'network_mode': 'host',
        }

    def disable_capability(self, docker_node):
        self.logger.warn("ble_adapt:{}".format(self.ble_adapt))
        self.logger.warn("BLE_ADAPTS_LIST: {}".format(
                BlueToothCapability.BLE_ADAPTS_LIST))
        BlueToothCapability.BLE_ADAPTS_LIST.remove(self.ble_adapt)
        if len(BlueToothCapability.BLE_ADAPTS_LIST):
            return
        utils.host_run(self.logger,
                       "killall btvirt")
        utils.host_run(self.logger,
                       "killall bluetoothd")

    def __get_ble_controller(self):
        self.logger.info("start getting ble adapters...")
        command = os.path.join(
                BLUEZ_DIR, "tools/hciconfig | awk '/Bus: Virtual/ {print $1}' | sort")
        ret = utils.host_run(self.logger, command)
        if ret.returncode != 0:
            self.logger.error("Unable to retrieve ble virtual interface, "
                              "please run btvirt command")
            raise RuntimeError(ret.stderr)
        self.logger.info("result from getting ble adapters: {}".format(ret.stdout))
        ble_adapts = ret.stdout.strip(b':\n').split(b':\n')
        self.logger.info(ble_adapts)
        for adapt in ble_adapts:
            if adapt in BlueToothCapability.BLE_ADAPTS_LIST:
                continue
            BlueToothCapability.BLE_ADAPTS_LIST.append(adapt)
            adapt = adapt.decode('utf-8')
            self.logger.info("assigned ble_adapt: {}".format(adapt))
            self.ble_adapt = adapt
            break
        else:
            self.logger.error("Run out of ble virtual interfaces, "
                              "please re-run btvirt to get more virtual interfaces")
        self.logger.info("BLE_ADAPTS_LIST: \n{}".format(BlueToothCapability.BLE_ADAPTS_LIST))

    def __is_btvirt_running(self):
        ret = utils.host_run(self.logger,
                             "ps aux | grep btvirt | grep -v grep | awk '{print $11}'").stdout
        self.logger.info("btvirt running: {}".format(ret))
        return CIRQUE_ROOT in ret.decode('utf-8')

    def __is_bluetoothd_running(self):
        ret = utils.host_run(self.logger,
                             "ps aux | grep bluetoothd | grep -v grep | awk '{print $11}'").stdout
        self.logger.warn("bluetoothd running: {}".format(ret))
        return CIRQUE_ROOT in ret.decode('utf-8')

    def __run_bluetoothd(self):
        if self.__is_bluetoothd_running():
            return
        self.logger.info("kill all bluetoothd")
        utils.host_run(self.logger,
                       'killall bluetoothd')
        time.sleep(3)
        self.logger.info("bringing up bluetoothd")
        os.system(os.path.join(
                BLUEZ_DIR, 'src/bluetoothd --experimental --debug &'))
        time.sleep(2)
        if not self.__is_bluetoothd_running():
            raise RuntimeError("Unable to run bluetoothd")

    def __run_btvirt_infs(self):
        if self.__is_btvirt_running():
            return
        utils.host_run(self.logger,
                       'killall btvirt')
        time.sleep(3)
        self.logger.info("creating virtual ble interfaces({})".format(
            self.num_btvirts))
        os.system(os.path.join(BLUEZ_DIR, "emulator/btvirt -L -l2 &"))
        time.sleep(2)
        self.logger.info("done creating virtual ble...")
        if not self.__is_btvirt_running():
            raise RuntimeError("Unable to run btvirt")
