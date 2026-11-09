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
"""Standalone Linux CLI Daemon Entrypoint for the Cirque Virtual Bluetooth Controller System."""

import argparse
import json
import signal
import sys
import time

from cirque.virtual_bt.server import VirtualBluetoothServer


def _parse_cli_args(argv=None):
  """Parses command-line arguments for the Virtual Bluetooth Controller daemon."""
  parser = argparse.ArgumentParser(
      description=(
          'Standalone Linux Virtual Bluetooth Controller System (Control, HCI'
          ' H4, and Link Layer TCP Channels)'
      )
  )
  parser.add_argument(
      '--host',
      default='127.0.0.1',
      help='Host address to bind TCP channels (default: 127.0.0.1)',
  )
  parser.add_argument(
      '--control-port',
      type=int,
      default=7301,
      help='Control/Test TCP channel port (0 for auto)',
  )
  parser.add_argument(
      '--hci-port',
      type=int,
      default=7302,
      help='HCI H4-over-TCP channel port (0 for auto)',
  )
  parser.add_argument(
      '--phy-port',
      type=int,
      default=7303,
      help='Link Layer PHY TCP channel port (0 for auto)',
  )
  parser.add_argument(
      '--num-controllers',
      type=int,
      default=2,
      help='Number of pre-created virtual Bluetooth controllers at startup',
  )
  parser.add_argument(
      '--connect-remote-phy',
      default='',
      help='Optional remote Link Layer PHY host:port to bridge at startup',
  )
  return parser.parse_args(argv)


def main(argv=None) -> int:
  args = _parse_cli_args(argv)

  server = VirtualBluetoothServer(
      host=args.host,
      control_port=args.control_port,
      hci_port=args.hci_port,
      phy_port=args.phy_port,
  )
  c_port, h_port, p_port = server.start()

  for i in range(args.num_controllers):
    server.create_controller(
        controller_id=f'hci{i}',
        bd_addr=f'AA:BB:CC:00:00:{i + 1:02X}',
        dedicated_port=True,
    )

  if args.connect_remote_phy and ':' in args.connect_remote_phy:
    r_host, r_port_str = args.connect_remote_phy.rsplit(':', 1)
    server.connect_remote_phy(r_host, int(r_port_str))

  status_banner = {
      'status': 'running',
      'host': args.host,
      'control_port': c_port,
      'hci_port': h_port,
      'phy_port': p_port,
      'controllers': server.list_controllers(),
  }
  print(json.dumps(status_banner), flush=True)

  stop_flag = False

  def _handle_sig(_signum, _frame):
    nonlocal stop_flag
    stop_flag = True

  signal.signal(signal.SIGINT, _handle_sig)
  signal.signal(signal.SIGTERM, _handle_sig)

  try:
    while not stop_flag:
      time.sleep(0.25)
  finally:
    server.stop()
  return 0


if __name__ == '__main__':
  sys.exit(main())
