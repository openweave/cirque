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

import atexit
import json
import os

from cirque.common.cirquelog import CirqueLog
from cirque.common.taskrunner import TaskRunner
from cirque.home.home import CirqueHome
from flask import Flask
from flask import jsonify
from flask import request
from flask import Response

app = Flask(__name__)
CirqueLog.setup_cirque_logger()
logger = CirqueLog.get_cirque_logger('service')

service_mode = os.environ.get('CIRQUE_DEBUG', 0)

homes = {}


@app.route('/create_home', methods=['POST'])
def create_home():
  home = CirqueHome()
  homes[home.home_id] = home
  return jsonify(home.create_home(request.json))


@app.route('/get_homes', methods=['GET'])
def get_homes():
  return jsonify(list(homes.keys()))


@app.route('/wifi_ssid_psk/<home_id>', methods=['GET'])
def get_wifi_ssid_psk(home_id):
  return jsonify(homes[home_id].get_wifiap_ssid_psk())


@app.route('/home_devices/<home_id>', methods=['GET'])
def get_home_devices(home_id):
  if home_id not in homes:
    return ''
  return jsonify(homes[home_id].get_home_devices())


@app.route('/device_state/<home_id>/<device_id>', methods=['GET'])
def get_device_state(home_id, device_id):
  if home_id not in homes:
    return ''
  return jsonify(homes[home_id].get_device_state(device_id))


@app.route('/device_cmd/<home_id>/<device_id>/<path:cmd>', methods=['GET'])
def execute_device_cmd(home_id, device_id, cmd):
  if home_id not in homes:
    return ''
  stream = request.args.get('stream')
  ret = homes[home_id].execute_device_cmd(cmd, device_id, stream == 'True')
  return (
      Response(ret.output, mimetype='text/plain')
      if stream == 'True'
      else jsonify(
          dict({
              'return_code': str(ret.exit_code),
              'output': ret.output.decode('utf-8', errors='replace'),
          })
      )
  )


@app.route('/stop_device/<home_id>/<device_id>', methods=['GET'])
def stop_device(home_id, device_id):
  if home_id not in homes:
    return ''
  return jsonify(homes[home_id].stop_device(device_id))


@app.route('/device_log/<home_id>/<device_id>', methods=['GET'])
def device_log(home_id, device_id):
  tail = request.args.get('tail', None)
  if tail is not None and tail.isdigit():
    tail = int(tail)
  else:
    tail = 'all'

  if home_id not in homes:
    return ''
  return homes[home_id].get_device_log(device_id, tail)


@app.route('/destroy_home/<home_id>', methods=['GET'])
def destroy_home(home_id):
  if home_id not in homes:
    return ''
  reply = jsonify(homes[home_id].destroy_home())
  del homes[home_id]
  return reply


@app.route('/virtual_bt_info', methods=['GET'])
def virtual_bt_info():
  from cirque.capabilities.bluetoothcapability import BlueToothCapability
  from cirque.connectivity.rf_channel_simulator import RfChannelSimulator

  server = BlueToothCapability.get_or_start_virtual_server()
  return jsonify({
      'host': server.host,
      'control_port': server.control_port,
      'hci_port': server.hci_port,
      'phy_port': server.phy_port,
      'controllers': server.list_controllers(),
      'rf_channel': RfChannelSimulator.get_shared().get_status(),
  })


@app.route('/virtual_wifi_register', methods=['POST'])
def virtual_wifi_register():
  from cirque.capabilities.wificapability import WiFiCapability
  req = request.get_json(silent=True) or {}
  mgr = WiFiCapability._SHARED_DOCKER_MANAGER
  if not mgr:
    return jsonify({'ok': False, 'reason': 'no_wifi_manager'})

  station_id = req.get('station_id')
  mac = req.get('mac_addr')
  ipv4 = req.get('ipv4_addr')
  if not station_id or not mac:
    return (
        jsonify({'ok': False, 'reason': 'station_id and mac_addr required'}),
        400,
    )

  with mgr._lock:
    mgr._station_ips[station_id] = (ipv4, '')
  mgr.server.register_station(
      station_id=station_id,
      ifname='wlan0',
      mac_addr=mac,
      ipv4_addr=ipv4,
      ipv6_addr='',
      is_ap_bridge=False,
  )
  return jsonify({'ok': True})


@app.route('/virtual_wifi_connect', methods=['POST'])
def virtual_wifi_connect():
  from cirque.capabilities.wificapability import WiFiCapability
  req = request.get_json(silent=True) or {}
  mgr = WiFiCapability._SHARED_DOCKER_MANAGER
  if not mgr:
    return jsonify({'ok': False, 'reason': 'no_wifi_manager'})
  if not req.get('station_id'):
    return jsonify({'ok': False, 'reason': 'station_id required'}), 400
  res = mgr.connect_station_to_ap(
      req.get('station_id'), req.get('ssid'), req.get('psk')
  )
  return jsonify(res)


@app.route('/virtual_wifi_info', methods=['GET'])
def virtual_wifi_info():
  from dataclasses import asdict
  from cirque.capabilities.wificapability import WiFiCapability
  from cirque.connectivity.rf_channel_simulator import RfChannelSimulator

  server = WiFiCapability.get_or_start_virtual_server()
  return jsonify({
      'host': server.host,
      'control_port': server.control_port,
      'mgmt_port': server.mgmt_port,
      'data_port': server.data_port,
      'aps': [asdict(ap) for ap in server.list_aps()],
      'stations': [asdict(st) for st in server.list_stations()],
      'frame_counters': server.get_frame_counters(),
      'rf_channel': RfChannelSimulator.get_shared().get_status(),
  })


@app.route('/rf_channel', methods=['GET', 'POST'])
def rf_channel_endpoint():
  from cirque.connectivity.rf_channel_simulator import RfChannelSimulator

  rf_sim = RfChannelSimulator.get_shared()
  if request.method == 'POST':
    payload = request.get_json(force=True, silent=True) or {}
    preset = payload.get('preset') or request.args.get('preset')
    if preset:
      status = rf_sim.apply_regime_preset(str(preset))
      if isinstance(payload, dict) and len(payload) > 1:
        extra = {k: v for k, v in payload.items() if k != 'preset'}
        status = rf_sim.update_config(extra)
      return jsonify(status)
    return jsonify(rf_sim.update_config(payload))
  preset = request.args.get('preset')
  if preset:
    return jsonify(rf_sim.apply_regime_preset(str(preset)))
  return jsonify(rf_sim.get_status())


@app.route('/rf_channel/reset', methods=['GET', 'POST'])
def rf_channel_reset_endpoint():
  from cirque.connectivity.rf_channel_simulator import RfChannelSimulator

  rf_sim = RfChannelSimulator.get_shared()
  preset = request.args.get('preset')
  if request.method == 'POST':
    payload = request.get_json(force=True, silent=True) or {}
    preset = payload.get('preset') or preset
  if preset:
    return jsonify(rf_sim.apply_regime_preset(str(preset)))
  rf_sim.reset_metrics()
  return jsonify(rf_sim.get_status())

@app.route('/rf_channel/fault', methods=['POST'])
def rf_channel_fault_endpoint():
  from cirque.connectivity.rf_channel_simulator import RfChannelSimulator, RfFaultRule
  import time
  rf_sim = RfChannelSimulator.get_shared()
  payload = request.get_json(force=True, silent=True) or {}
  if not payload or not payload.get('rule'):
      rf_sim.config.fault_rule = None
      return jsonify({'status': 'ok', 'fault_rule': None})
  
  rf_sim.config.fault_rule = RfFaultRule(
      rule=payload.get('rule', ''),
      src_ext=payload.get('src_ext', ''),
      src_short=payload.get('src_short', ''),
      window_s=float(payload.get('window_s', 5.0)),
      psdu_threshold=int(payload.get('psdu_threshold', 100)),
      armed_time=time.time(),
      trigger_time=0.0
  )
  rf_sim.config.enabled = True
  return jsonify({'status': 'ok', 'fault_rule': payload})

@app.route(
    '/init_android_emulator/<home_id>/<device_id>', methods=['GET', 'POST']
)
def init_android_emulator(home_id, device_id):
  if home_id not in homes:
    return jsonify({'status': 'failed', 'error': 'home not found'}), 404
  node = homes[home_id].devices.get(device_id)
  if not node or not hasattr(node, 'run_android_emulator'):
    return (
        jsonify({'status': 'failed', 'error': 'not an android emulator node'}),
        400,
    )
  timeout_sec = float(request.args.get('timeout', 90.0))
  res = node.run_android_emulator(timeout_sec=timeout_sec)
  return jsonify(res)


@app.route(
    '/commission_chiptool/<home_id>/<device_id>', methods=['GET', 'POST']
)
@app.route(
    '/commission_thread_chiptool/<home_id>/<device_id>', methods=['GET', 'POST']
)
def commission_chiptool(home_id, device_id):
  if home_id not in homes:
    return jsonify({'status': 'failed', 'error': 'home not found'}), 404
  node = homes[home_id].devices.get(device_id)
  if not node:
    return (
        jsonify({'status': 'failed', 'error': 'not an android emulator node'}),
        400,
    )
  default_network = (
      'thread' if 'commission_thread_chiptool' in request.path else 'wifi'
  )
  network_type = request.args.get('network_type', default_network)
  ssid = request.args.get('ssid', 'CHIP-VirtualWiFi-AP')
  psk = request.args.get('psk', 'ChipWiFiPassword123')
  discriminator = int(request.args.get('discriminator', 3840))
  setup_pin_code = int(request.args.get('setup_pin_code', 20202021))
  manual_code = request.args.get('manual_code', '34970112332')
  timeout_sec = float(request.args.get('timeout', 60.0))

  if network_type.lower() == 'thread':
    if not hasattr(node, 'commission_thread_via_chiptool_ui'):
      return (
          jsonify(
              {'status': 'failed', 'error': 'not an android emulator node'}
          ),
          400,
      )
    inject_thread_helper = request.args.get('inject_thread_helper', '0') == '1'
    if inject_thread_helper:
      import base64
      from cirque.home.virtual_home_topology import (
          OTBR_DATASET_COMPLETION_HELPER,
          THREAD_JOINER_ATTACH_HELPER,
      )
      import sys

      print(
          'WARNING: Using legacy THREAD_JOINER_ATTACH_HELPER shim for thread'
          ' commissioning!',
          file=sys.stderr,
          flush=True,
      )
      has_tbr = any(
          getattr(d, 'type', '') == 'ThreadBorderRouter'
          for d in homes[home_id].devices.values()
      )
      helper_script = (
          THREAD_JOINER_ATTACH_HELPER
          if has_tbr
          else OTBR_DATASET_COMPLETION_HELPER
      )
      b64_helper = base64.b64encode(helper_script.encode('utf-8')).decode(
          'ascii'
      )
      helper_cmd = (
          'sh -c "if kill -0 $(cat /tmp/joiner_helper.pid 2>/dev/null) '
          '2>/dev/null || kill -0 $(cat /tmp/thread_joiner_helper.pid '
          '2>/dev/null) 2>/dev/null; then exit 0; fi; '
          'kill -9 $(cat /tmp/dataset_helper.pid 2>/dev/null) '
          '2>/dev/null || true; '
          f'echo \\"{b64_helper}\\" | base64 -d > /tmp/dataset_helper.py && '
          'nohup python3 /tmp/dataset_helper.py >/tmp/dataset_helper.log '
          '2>&1 & echo $! > /tmp/dataset_helper.pid"'
      )
      for dev_id, dev_node in homes[home_id].devices.items():
        is_candidate = (
            dev_id != device_id
            and getattr(dev_node, 'type', '') != 'ThreadBorderRouter'
            and any(
                getattr(c, 'name', '') == 'Thread'
                for c in getattr(dev_node, 'capabilities', [])
            )
        )
        if not is_candidate:
          continue
        if getattr(dev_node, 'container', None) is not None:
          dev_node.container.exec_run(helper_cmd, detach=True)
        else:
          homes[home_id].execute_device_cmd(helper_cmd, dev_id)
    channel = request.args.get('channel', None)
    if channel is not None:
      channel = int(channel)
    pan_id = request.args.get('pan_id', None)
    xpan_id = request.args.get('xpan_id', None)
    master_key = request.args.get('master_key', None)
    dataset_tlvs_hex = request.args.get('dataset_tlvs_hex', None)
    trigger = request.args.get('trigger', 'ui')
    res = node.commission_thread_via_chiptool_ui(
        channel=channel,
        pan_id=pan_id,
        xpan_id=xpan_id,
        master_key=master_key,
        dataset_tlvs_hex=dataset_tlvs_hex,
        setup_pin_code=setup_pin_code,
        discriminator=discriminator,
        manual_code=manual_code,
        timeout_sec=timeout_sec,
        trigger=trigger,
    )
  else:
    if not hasattr(node, 'commission_via_chiptool_ui'):
      return (
          jsonify(
              {'status': 'failed', 'error': 'not an android emulator node'}
          ),
          400,
      )
    trigger = request.args.get('trigger', 'ui')
    res = node.commission_via_chiptool_ui(
        ssid=ssid,
        psk=psk,
        setup_pin_code=setup_pin_code,
        discriminator=discriminator,
        manual_code=manual_code,
        timeout_sec=timeout_sec,
        trigger=trigger,
    )
  return jsonify(res)


@app.route('/toggle_chiptool/<home_id>/<device_id>', methods=['GET', 'POST'])
def toggle_chiptool(home_id, device_id):
  if home_id not in homes:
    return jsonify({'status': 'failed', 'error': 'home not found'}), 404
  node = homes[home_id].devices.get(device_id)
  if not node or not hasattr(node, 'toggle_onoff_via_chiptool_ui'):
    return (
        jsonify({'status': 'failed', 'error': 'not an android emulator node'}),
        400,
    )
  node_id = int(request.args.get('node_id', 1))
  endpoint = int(request.args.get('endpoint', 1))
  timeout_sec = float(request.args.get('timeout', 15.0))
  res = node.toggle_onoff_via_chiptool_ui(
      node_id=node_id, endpoint=endpoint, timeout_sec=timeout_sec
  )
  return jsonify(res)


@app.route('/read_chiptool/<home_id>/<device_id>', methods=['GET', 'POST'])
def read_chiptool(home_id, device_id):
  if home_id not in homes:
    return jsonify({'status': 'failed', 'error': 'home not found'}), 404
  node = homes[home_id].devices.get(device_id)
  if not node or not hasattr(node, 'read_onoff_via_chiptool_ui'):
    return (
        jsonify({'status': 'failed', 'error': 'not an android emulator node'}),
        400,
    )
  node_id = int(request.args.get('node_id', 1))
  endpoint = int(request.args.get('endpoint', 1))
  timeout_sec = float(request.args.get('timeout', 15.0))
  res = node.read_onoff_via_chiptool_ui(
      node_id=node_id, endpoint=endpoint, timeout_sec=timeout_sec
  )
  return jsonify(res)


@app.route('/commission_app/<home_id>/<device_id>', methods=['GET', 'POST'])
def commission_app(home_id, device_id):
  return commission_chiptool(home_id, device_id)


@app.route('/commission_app/<device_id>', methods=['GET', 'POST'])
def commission_app_single(device_id):
  if not homes:
    return jsonify({'status': 'failed', 'error': 'no active homes'}), 404
  home_id = next(iter(homes.keys()))
  return commission_chiptool(home_id, device_id)


@app.route('/toggle_app/<home_id>/<device_id>', methods=['GET', 'POST'])
def toggle_app(home_id, device_id):
  return toggle_chiptool(home_id, device_id)


@app.route('/toggle_app/<device_id>', methods=['GET', 'POST'])
def toggle_app_single(device_id):
  if not homes:
    return jsonify({'status': 'failed', 'error': 'no active homes'}), 404
  home_id = next(iter(homes.keys()))
  return toggle_chiptool(home_id, device_id)


@app.route('/read_app/<home_id>/<device_id>', methods=['GET', 'POST'])
def read_app(home_id, device_id):
  return read_chiptool(home_id, device_id)


@app.route('/read_app/<device_id>', methods=['GET', 'POST'])
def read_app_single(device_id):
  if not homes:
    return jsonify({'status': 'failed', 'error': 'no active homes'}), 404
  home_id = next(iter(homes.keys()))
  return read_chiptool(home_id, device_id)


@app.route(
    '/start_screen_recording/<path:home_id>/<path:device_id>',
    methods=['GET', 'POST'],
)
def start_screen_recording(home_id, device_id):
  if home_id not in homes:
    return jsonify({'status': 'failed', 'error': 'home not found'}), 404
  node = homes[home_id].devices.get(device_id)
  if not node or not hasattr(node, 'start_screen_recording'):
    return (
        jsonify({'status': 'failed', 'error': 'not an android emulator node'}),
        400,
    )
  name = request.args.get('name', 'screen_recording.mp4')
  bit_rate = int(request.args.get('bit_rate', 4000000))
  time_limit = int(request.args.get('time_limit', 180))
  size = request.args.get('size', None)
  res = node.start_screen_recording(
      name=name, bit_rate=bit_rate, time_limit_sec=time_limit, size=size
  )
  return jsonify(res)


@app.route(
    '/stop_screen_recording/<path:home_id>/<path:device_id>',
    methods=['GET', 'POST'],
)
def stop_screen_recording(home_id, device_id):
  if home_id not in homes:
    return jsonify({'status': 'failed', 'error': 'home not found'}), 404
  node = homes[home_id].devices.get(device_id)
  if not node or not hasattr(node, 'stop_screen_recording'):
    return (
        jsonify({'status': 'failed', 'error': 'not an android emulator node'}),
        400,
    )
  res = node.stop_screen_recording()
  return jsonify(res)


@app.route(
    '/list_screen_recordings/<path:home_id>/<path:device_id>',
    methods=['GET'],
)
def list_screen_recordings(home_id, device_id):
  if home_id not in homes:
    return jsonify({'status': 'failed', 'error': 'home not found'}), 404
  node = homes[home_id].devices.get(device_id)
  if not node or not hasattr(node, 'list_screen_recordings'):
    return (
        jsonify({'status': 'failed', 'error': 'not an android emulator node'}),
        400,
    )
  return jsonify({'recordings': node.list_screen_recordings()})


@app.route(
    '/get_screen_recording/<path:home_id>/<path:device_id>/'
    '<path:recording_name>',
    methods=['GET'],
)
def get_screen_recording(home_id, device_id, recording_name):
  if home_id not in homes:
    return jsonify({'status': 'failed', 'error': 'home not found'}), 404
  node = homes[home_id].devices.get(device_id)
  if not node or not hasattr(node, 'get_screen_recording_bytes'):
    return (
        jsonify({'status': 'failed', 'error': 'not an android emulator node'}),
        400,
    )
  data = node.get_screen_recording_bytes(recording_name)
  if not data:
    return (
        jsonify({'status': 'failed', 'error': 'recording not found or empty'}),
        404,
    )
  return Response(data, mimetype='video/mp4')


@app.route('/mcp', methods=['POST'])
def mcp_endpoint():
  from cirque.mcp.server import CirqueMcpServer

  if not hasattr(app, '_cirque_mcp_server') or app._cirque_mcp_server is None:
    app._cirque_mcp_server = CirqueMcpServer(homes_provider=lambda: homes)
  req_data = request.get_json(force=True, silent=True)
  if req_data is None:
    return (
        jsonify({
            'jsonrpc': '2.0',
            'id': None,
            'error': {'code': -32700, 'message': 'Parse error'},
        }),
        400,
    )
  resp = app._cirque_mcp_server.handle_message(req_data)
  if resp is None:
    return Response('', status=204)
  return jsonify(resp)


@app.route('/mcp/tools', methods=['GET'])
def mcp_tools_discovery():
  from cirque.mcp.server import CirqueMcpServer

  if not hasattr(app, '_cirque_mcp_server') or app._cirque_mcp_server is None:
    app._cirque_mcp_server = CirqueMcpServer(homes_provider=lambda: homes)
  server = app._cirque_mcp_server
  tools_res = server.handle_message({
      'jsonrpc': '2.0',
      'id': 'tools',
      'method': 'tools/list',
  })
  resources_res = server.handle_message({
      'jsonrpc': '2.0',
      'id': 'resources',
      'method': 'resources/list',
  })
  prompts_res = server.handle_message({
      'jsonrpc': '2.0',
      'id': 'prompts',
      'method': 'prompts/list',
  })
  return jsonify({
      'tools': (
          tools_res.get('result', {}).get('tools', [])
          if isinstance(tools_res, dict)
          else []
      ),
      'resources': (
          resources_res.get('result', {}).get('resources', [])
          if isinstance(resources_res, dict)
          else []
      ),
      'prompts': (
          prompts_res.get('result', {}).get('prompts', [])
          if isinstance(prompts_res, dict)
          else []
      ),
  })


@app.route('/mcp/extensions', methods=['GET'])
def mcp_extensions_list():
  from cirque.mcp.server import CirqueMcpServer

  if not hasattr(app, '_cirque_mcp_server') or app._cirque_mcp_server is None:
    app._cirque_mcp_server = CirqueMcpServer(homes_provider=lambda: homes)
  server = app._cirque_mcp_server
  return jsonify(server.list_extensions())


@app.route('/mcp/extensions/register', methods=['POST'])
def mcp_extensions_register():
  from cirque.mcp.server import CirqueMcpServer

  if not hasattr(app, '_cirque_mcp_server') or app._cirque_mcp_server is None:
    app._cirque_mcp_server = CirqueMcpServer(homes_provider=lambda: homes)
  server = app._cirque_mcp_server

  payload = request.get_json(force=True, silent=True) or {}
  module_or_path = payload.get('module_or_path') or request.form.get(
      'module_or_path'
  )
  if not module_or_path:
    return jsonify({'error': 'Parameter "module_or_path" is required'}), 400

  try:
    ext_name = server.register_extension(module_or_path)
    return jsonify({
        'status': 'registered',
        'extension_name': ext_name,
        'extensions': server.list_extensions(),
    })
  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.exception('Failed registering extension via REST: %s', exc)
    return jsonify({'error': str(exc)}), 500


@app.route('/mcp/visualize', methods=['GET', 'POST'])
def mcp_visualize():
  from cirque.mcp.server import CirqueMcpServer

  if not hasattr(app, '_cirque_mcp_server') or app._cirque_mcp_server is None:
    app._cirque_mcp_server = CirqueMcpServer(homes_provider=lambda: homes)
  server = app._cirque_mcp_server

  args = {}
  if request.method == 'POST':
    args = request.get_json(force=True, silent=True) or {}
  else:
    args = {
        'pcap_dir': request.args.get('pcap_dir'),
        'output_html': request.args.get('output_html'),
        'output_json': request.args.get('output_json'),
        'title': request.args.get('title'),
    }
    args = {k: v for k, v in args.items() if v is not None}

  try:
    res = server.handle_message({
        'jsonrpc': '2.0',
        'id': 'visualize',
        'method': 'tools/call',
        'params': {
            'name': 'cirque_generate_flow_visualization',
            'arguments': args,
        },
    })
    if isinstance(res, dict) and 'result' in res:
      content = res['result'].get('content', [{}])[0].get('text', '{}')
      return jsonify(json.loads(content))
    return jsonify(res)
  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.exception('Failed generating flow visualization via REST: %s', exc)
    return jsonify({'error': str(exc)}), 500


def destroy_homes():
  global homes
  logger.info('removing all the homes..')
  temp_homes = list(homes.keys())
  for home_id in temp_homes:
    homes[home_id].destroy_home()
    del homes[home_id]
  del homes
  return ''


# becareful not to remove this part
atexit.register(lambda: TaskRunner.stop())
if service_mode:
  atexit.register(destroy_homes)
TaskRunner.start()

if __name__ == '__main__':
  cirque_host = os.environ.get('CIRQUE_HOST', '127.0.0.1')
  cirque_port = int(os.environ.get('CIRQUE_PORT', '5000'))
  app.run(host=cirque_host, port=cirque_port)
