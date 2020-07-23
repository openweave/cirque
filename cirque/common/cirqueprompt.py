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
import os
import sys
import cmd2
import pprint
import argparse
import textwrap
import pkg_resources

from cirque.home.home import CirqueHome

homes = dict()
pp = pprint.PrettyPrinter(indent=2)


class CirquePrompt(cmd2.Cmd):
    version = pkg_resources.get_distribution("cirque").version
    intro = 'Welcome to cirque shell {}'.format(version)
    prompt = 'cirque> '
    home_id = 0

    def __init__(self):
        cmd2.Cmd.__init__(self)
        self.hidden_commands += [
            'alias', 'edit', 'macro', 'py', 'quit', 'run_pyscript',
            'run_script', 'set', 'shell', 'shortcuts'
        ]

    def help_exit(self):
        print(
            textwrap.dedent("""\
                Exits cirque CLI prompt, tear down all the cirque homes created
                in the current session.

                Usage: exit
            """))

    def do_exit(self, inp):
        if len(homes):
            home_ids = list(homes.keys())
            for home_id in home_ids:
                self.do_destroy_home('--home_id {}'.format(home_id))
        return True

    def help_create_home(self):
        print(
            textwrap.dedent("""\
                create cirque home returns home id

                Usage: create_home
                Returns: home_id
            """))

    def do_create_home(self, inp):
        home = CirqueHome(str(self.home_id))
        homes[home.home_id] = home
        self.home_id += 1
        print("home_id: {} created!".format(home.home_id))

    def help_create_device(self):
        print(
            textwrap.dedent("""\
                create cirque devices returns device_type and device_id

                Args:
                    --home_id (str): created home id, if not given,
                            automatically set to current home_id.
                    --type (str): if base_image is not using, this should be
                            device docker image name otherwise random device
                            type that could be used to specified device could
                            be used.
                    --capability (str): capabilities would like to enabled for
                            the device.
                            e.g:
                            Weave,Thread,Interactive
                    --thread_mode (str): two options could be use either rcp
                            or ncp.
                            e.g,
                            --thread_mode rcp
                Usage:
                    create_device [--home_id <home_id>] --type
                            generic_node_image --capability
                            WiFi,Thread,Interactive [--thread_mode rcp]
                Returns:
                    device_type (str)
                    home_id (str)
                    device_id (str)
            """))

    def do_create_device(self, inp):
        parser = argparse.ArgumentParser()
        parser.add_argument('--home_id', type=str, default=None)
        parser.add_argument('--type', type=str, required=True)
        parser.add_argument('--base_image', type=str)
        parser.add_argument('--capability', type=str)
        parser.add_argument('--thread_mode', type=str, default=None)
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
            })
        if args.thread_mode:
            config.update({
                '{}_mode'.format(args.thread_mode): True,
            })
        if not args.home_id:
            args.home_id = str(self.home_id - 1)
        else:
            if not self._valid_home_id(args.home_id):
                print("home id: {} is not existing!!".format(args.home_id))
                return
        device_id = homes[args.home_id].add_device(config)
        print("{} created in home_id: {}!!".format(args.type, args.home_id))
        print("device id: {}".format(device_id))

    def help_close_device(self):
        print(
            textwrap.dedent("""\
                close cirque device
                Args:
                    --home_id (str): device under specific home_id, if not
                            given, automatically set to current home_id.
                    --device_id (str): device id
                Usage:
                    close_device [--home_id <home_id>] --device_id <device_id>
            """))

    def do_close_device(self, inp):
        parser = argparse.ArgumentParser()
        parser.add_argument('--home_id', type=str, default=None)
        parser.add_argument('--device_id', type=str, required=True)
        args = parser.parse_args(inp.split())
        if not args.home_id:
            args.home_id = str(self.home_id - 1)
        else:
            if not self._valid_home_id(args.home_id):
                print("home id: {} is not existing!!".format(args.home_id))
                return
        ret = homes[args.home_id].stop_device(args.device_id)
        print("device: {} closed!!".format(ret))

    def help_device_state(self):
        print(
            textwrap.dedent("""\
                device information and status

                Args:
                    --home_id (str): a specific home_id, if not given,
                            automatically set to current home_id.
                    --device_id (str): device id
                Usage:
                    device_state [--home_id <home_id>]> --device_id <device_id>
                Returns:
                    device information (dict)
            """))

    def do_device_state(self, inp):
        parser = argparse.ArgumentParser()
        parser.add_argument('--home_id', type=str, default=None)
        parser.add_argument('--device_id', type=str, required=True)
        args = parser.parse_args(inp.split())
        if not args.home_id:
            args.home_id = str(self.home_id - 1)
        else:
            if not self._valid_home_id(args.home_id):
                print("home id: {} is not existing!!".format(args.home_id))
                return
        ret = homes[args.home_id].get_device_state(args.device_id)
        print("device state: {}".format(pp.pformat(ret)))

    def help_destroy_home(self):
        print(
            textwrap.dedent("""\
                tear down cirque home

                Args:
                    --home_id (str): cirque home id. if not given
                            automatically set to current home id.
                Usage:
                    destroy_home [--home_id <home_id>]
            """))

    def do_destroy_home(self, inp):
        if not len(homes):
            return
        parser = argparse.ArgumentParser()
        parser.add_argument('--home_id', type=str, default=None)
        args = parser.parse_args(inp.split())
        if not args.home_id:
            args.home_id = str(self.home_id - 1)
        else:
            if not self._valid_home_id(args.home_id):
                print("home id: {} is not existing!!".format(args.home_id))
                return
        device_ids = list(homes[args.home_id].home['devices'].keys())
        for device_id in device_ids:
            print('closing device: {}'.format(device_id))
            homes[args.home_id].stop_device(device_id)
        homes[args.home_id].destroy_home()
        del homes[args.home_id]
        print("successfully destroy home: {}".format(args.home_id))

    def help_home_devices(self):
        print(
            textwrap.dedent("""\
                list home devices under specific home_id. if not given,
                            automatically set to current home id.

                Args:
                    --home_id (str): home_id. if not given, automatically
                            set to current home id.
                Usage:
                    home_devices [--home_id <home_id>]
                Returns:
                    dict of devices under specific home_id
            """))

    def do_home_devices(self, inp):
        parser = argparse.ArgumentParser()
        parser.add_argument('--home_id', type=str, default=None)
        args = parser.parse_args(inp.split())
        if not args.home_id:
            args.home_id = str(self.home_id - 1)
        else:
            if not self._valid_home_id(args.home_id):
                print("home id: {} is not existing!!".format(args.home_id))
                return
        ret = homes[args.home_id].get_home_devices()
        print("home id: {}".format(args.home_id))
        print("home devices: {}".format(pp.pformat(ret)))

    def help_homes(self):
        print(
            textwrap.dedent("""\
                list all the homes

                Usage:
                    homes
                Return:
                    home_id (list)
            """))

    def do_homes(self, inp):
        print(list(homes.keys()))

    def help_run_exec(self):
        print(
            textwrap.dedent("""\
                run command in a specific docker container(device id)

                Args:
                    --home_id (str): home_id. if not given, automatically
                            set to current home id.
                    --device_id (str): device id
                    --command (str): if command includes --(switch) repaces to
                            __(under line), the api will replace them back
                            automatically.
                    --stream (bool): default False, if switch is set, means
                            True
                Usage:
                    cirque> run_exec [--home_id <home_id>] --device_id
                            <device_id> --command <command> [--stream]
                Returns:
                    command exectue result (str)
            """))

    def do_run_exec(self, inp):
        parser = argparse.ArgumentParser()
        parser.add_argument('--home_id', type=str, default=None)
        parser.add_argument('--device_id', type=str, required=True)
        parser.add_argument('--command', type=str, nargs='+', required=True)
        parser.add_argument('--stream', action='store_true', default=False)
        args = parser.parse_args(inp.split())
        if not args.home_id:
            args.home_id = str(self.home_id - 1)
        else:
            if not self._valid_home_id(args.home_id):
                print("home id: {} is not existing!!".format(args.home_id))
                return
        args.command = " ".join(args.command)
        args.command = args.command.replace('__', '--')
        print("args.command: {}".format(args.command))
        ret = homes[args.home_id].execute_device_cmd(args.command,
                                                     args.device_id,
                                                     args.stream)
        print("command result:\n{}".format(ret.output.decode('utf-8')))

    def help_version(self):
        print(
            textwrap.dedent("""\
                displaycurrent cirque version.

                Usage:
                    version
                Returne:
                    version (str)
            """))

    def do_version(self, inp):
        print(self.version)

    def emptyline(self):
        pass

    def _valid_home_id(self, home_id):
        return home_id in homes


def sys_argv_parse():
    parser = argparse.ArgumentParser()
    parser.add_argument('--thread_path', type=str, default=None)
    args = parser.parse_args()

    if args.thread_path:
        os.environ['PATH'] += ':{}'.format(args.thread_path)

    sys.argv.clear()
    sys.argv.append('cirqueprompt')


if __name__ == '__main__':
    sys_argv_parse()
    sys.exit(CirquePrompt().cmdloop())
