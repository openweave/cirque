# Copyright 2020 Google LLC
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

import cmd
import pprint
import argparse

from cirque.home.home import CirqueHome

HOME = None
pp = pprint.PrettyPrinter(indent=2)

class CirquePrompt(cmd.Cmd):
    prompt = 'cirque> '
    home_id = 0

    def do_exit(self, inp):
        self.do_destroy_home(inp)
        return True

    def do_create_home(self, inp):
        global HOME
        HOME = CirqueHome(str(self.home_id))
        print("home_id: {} created!".format(HOME.home_id))

    def do_create_device(self, inp):
        parser = argparse.ArgumentParser()
        parser.add_argument('--type', type=str, required=True)
        parser.add_argument('--base_image', type=str)
        parser.add_argument('--capability', type=str)
        parser.add_argument('--rcp_mode', action='store_true', default=False)
        parser.add_argument('--weave_config_file', type=str)
        parser.add_argument('--weave_config_target_path', type=str)
        args = parser.parse_args(inp.split())

        config = dict()
        if args.type == 'wifi_ap':
            config.update({
                'type': args.type,
                'base_image': 'mac80211_ap_image'
            })
        elif args.type == 'mobile_node':
            config.update({
                'type': args.type,
                'base_image': 'mobile_node_image',
                'capability': ['Interactive', 'LanAccess']
            })
        else:
            capabilities = args.capability.split(',')
            config.update({
                'type': args.type,
                'base_image': args.base_image if args.base_image else None,
                'capability': capabilities,
                'rcp_mode': True if args.base_image else False,
                'weave_config_file': args.weave_config_file,
                'weave_config_target_path': args.weave_config_target_path
            })
        device_id = HOME.add_device(config)
        print("{} created!!".format(args.type))
        print("device id: {}".format(device_id))

    def do_close_device(self, inp):
        parser = argparse.ArgumentParser()
        parser.add_argument('--device_id', type=str, required=True)
        args = parser.parse_args(inp.split())
        ret = HOME.stop_device(args.device_id)
        print("device: {} closed!!".format(ret))

    def do_device_state(self, inp):
        parser = argparse.ArgumentParser()
        parser.add_argument('--device_id', type=str, required=True)
        args = parser.parse_args(inp.split())
        ret = HOME.get_device_state(args.device_id)
        print("device state: {}".format(pp.pformat(ret)))

    def do_destroy_home(self, inp):
        if not HOME.home:
            return

        device_ids = list(HOME.home['devices'].keys())
        for device_id in device_ids:
            print('closing device: {}'.format(device_id))
            HOME.stop_device(device_id)
        HOME.destroy_home()
        print("successfully destroy home: {}".format(HOME.home_id))

    def do_home_devices(self, inp):
        ret = HOME.get_home_devices()
        print("home devices: {}".format(pp.pformat(ret)))

    def do_run_exec(self, inp):
        parser = argparse.ArgumentParser()
        parser.add_argument('--device_id', type=str, required=True)
        parser.add_argument('--command', type=str, nargs='+', required=True)
        parser.add_argument('--stream', action='store_true', default=False)
        args = parser.parse_args(inp.split())
        args.command = " ".join(args.command)
        args.command = args.command.replace('__', '--')
        print("args.command: {}".format(args.command))
        ret = HOME.execute_device_cmd(args.command, args.device_id, args.stream)
        print("command result:\n{}".format(ret))

    def emptyline(self):
        pass


if __name__ == '__main__':
    CirquePrompt().cmdloop()
