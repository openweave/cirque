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
"""Native Model Context Protocol (MCP) Server for Cirque Virtual Home."""

import base64
from dataclasses import asdict
import glob
import importlib
import importlib.util
import json
import logging
import os
import re
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from cirque.capabilities.bluetoothcapability import BlueToothCapability
from cirque.capabilities.wificapability import WiFiCapability
from cirque.home.home import CirqueHome
from cirque.home.virtual_home_topology import (
    DEFAULT_HOME_PSK,
    DEFAULT_HOME_SSID,
    OTBR_DATASET_COMPLETION_HELPER,
    THREAD_JOINER_ATTACH_HELPER,
    VirtualHomeTopology,
)
from cirque.pcap.flow_visualizer import (
    FlowDissector,
    FlowEvent,
    dissect_pcap_directory,
    generate_flow_html,
    merge_and_sort_flow_events,
)
from cirque.pcap.summarize_pcap import summarize_pcap

logger = logging.getLogger('CirqueMcpServer')

MCP_PROTOCOL_VERSION = '2024-11-05'
SERVER_NAME = 'cirque-mcp-server'
SERVER_VERSION = '1.0.0'

# Chaos recipes accepted by cirque_inject_rf_fault. Both the advertised tool
# schema enum and the runtime validation derive from this tuple so they cannot
# drift apart.
RF_FAULT_RECIPES: Tuple[str, ...] = (
    'ble_brownout',
    'ble_restore',
    'wifi_deauth_roam',
    'rf_cochannel_interference',
    'clear_all_faults',
)


class CirqueMcpServer:
  """Cirque Virtual Home Model Context Protocol (MCP) JSON-RPC 2.0 Server."""

  def __init__(
      self,
      homes_provider: Optional[Callable[[], Dict[str, CirqueHome]]] = None,
      pcap_dir: Optional[str] = None,
  ) -> None:
    self._external_homes_provider = homes_provider
    self._local_homes: Dict[str, CirqueHome] = {}
    self._lock = threading.RLock()
    self._pcap_dir = (
        pcap_dir
        or os.environ.get('CIRQUE_PCAP_DIR')
        or os.environ.get('DEVICE_LOG_DIR')
        or '/tmp/cirque_pcaps'
    )
    self._initialized = False

    # Cross-Layer Flow Event Recording & Pluggable Dissectors
    self._recorded_flow_events: List[Dict[str, Any]] = []
    self._flow_dissectors: Dict[str, FlowDissector] = {}
    self._flow_layers: Dict[str, Dict[str, Any]] = {}
    self._last_flow_visualization: Optional[Dict[str, Any]] = None

    # Dynamic Extension Registries
    self._extension_tools: Dict[
        str, Tuple[Dict[str, Any], Callable[[Dict[str, Any]], Any], str]
    ] = {}
    self._extension_resources: Dict[
        str, Tuple[Dict[str, Any], Optional[Callable[[str], Any]], str]
    ] = {}
    self._extension_resource_templates: Dict[
        str,
        Tuple[Dict[str, Any], re.Pattern, Callable[[str, re.Match], Any], str],
    ] = {}
    self._extension_prompts: Dict[
        str, Tuple[Dict[str, Any], Callable[[Dict[str, Any]], str], str]
    ] = {}
    self._extension_health_oracles: Dict[
        str, Tuple[Callable[[CirqueHome, Optional[str]], Dict[str, Any]], str]
    ] = {}
    self._loaded_extensions: Dict[str, Any] = {}

    # Automatically load extensions configured via environment
    env_exts = os.environ.get('CIRQUE_MCP_EXTENSIONS', '')
    if env_exts:
      for ext_spec in re.split(r'[,;:]', env_exts):
        ext_spec = ext_spec.strip()
        if not ext_spec:
          continue
        try:
          self.register_extension(ext_spec)
        except Exception as exc:  # pylint: disable=broad-exception-caught
          logger.exception(
              'Failed loading extension from CIRQUE_MCP_EXTENSIONS: %s: %s',
              ext_spec,
              exc,
          )

  @property
  def homes(self) -> Dict[str, CirqueHome]:
    if self._external_homes_provider is not None:
      return self._external_homes_provider()
    return self._local_homes

  def _get_home(self, home_id: str) -> Optional[CirqueHome]:
    return self.homes.get(home_id)

  # ---------------------------------------------------------------------------
  # Dynamic Extension Registration API
  # ---------------------------------------------------------------------------

  def register_tool(
      self,
      schema_dict: Dict[str, Any],
      handler_fn: Callable[[Dict[str, Any]], Any],
      extension_name: str = 'custom',
  ) -> None:
    """Registers an extension tool dynamically."""
    name = schema_dict.get('name')
    if not name:
      raise ValueError('Tool schema must contain a "name" property.')
    with self._lock:
      self._extension_tools[name] = (schema_dict, handler_fn, extension_name)
      logger.info('Registered extension tool: %s (%s)', name, extension_name)

  def register_resource(
      self,
      resource_dict: Dict[str, Any],
      reader_fn: Optional[Callable[[str], Any]] = None,
      extension_name: str = 'custom',
  ) -> None:
    """Registers an extension static resource dynamically."""
    uri = resource_dict.get('uri')
    if not uri:
      raise ValueError('Resource schema must contain a "uri" property.')
    with self._lock:
      self._extension_resources[uri] = (
          resource_dict,
          reader_fn,
          extension_name,
      )
      logger.info('Registered extension resource: %s (%s)', uri, extension_name)

  def register_resource_template(
      self,
      template_dict: Dict[str, Any],
      pattern: Union[str, re.Pattern],
      reader_fn: Callable[[str, re.Match], Any],
      extension_name: str = 'custom',
  ) -> None:
    """Registers an extension dynamic resource template."""
    uri_template = template_dict.get('uriTemplate')
    if not uri_template:
      raise ValueError(
          'Resource template must contain a "uriTemplate" property.'
      )
    compiled_pattern = (
        re.compile(pattern) if isinstance(pattern, str) else pattern
    )
    with self._lock:
      self._extension_resource_templates[uri_template] = (
          template_dict,
          compiled_pattern,
          reader_fn,
          extension_name,
      )
      logger.info(
          'Registered extension resource template: %s (%s)',
          uri_template,
          extension_name,
      )

  def register_prompt(
      self,
      prompt_dict: Dict[str, Any],
      renderer_fn: Callable[[Dict[str, Any]], str],
      extension_name: str = 'custom',
  ) -> None:
    """Registers an extension prompt template dynamically."""
    name = prompt_dict.get('name')
    if not name:
      raise ValueError('Prompt schema must contain a "name" property.')
    with self._lock:
      self._extension_prompts[name] = (prompt_dict, renderer_fn, extension_name)
      logger.info('Registered extension prompt: %s (%s)', name, extension_name)

  def register_health_oracle(
      self,
      name: str,
      oracle_fn: Callable[[CirqueHome, Optional[str]], Dict[str, Any]],
      extension_name: str = 'custom',
  ) -> None:
    """Registers a health check oracle for cirque_diagnose_home_health."""
    with self._lock:
      self._extension_health_oracles[name] = (oracle_fn, extension_name)
      logger.info(
          'Registered extension health oracle: %s (%s)', name, extension_name
      )

  # ---------------------------------------------------------------------------
  # Cross-Layer Flow Recording & Dissection API
  # ---------------------------------------------------------------------------

  def record_flow_event(
      self, event_dict: Union[Dict[str, Any], FlowEvent]
  ) -> Dict[str, Any]:
    """Records a high-level or cross-layer flow event in the server timeline."""
    with self._lock:
      item = (
          asdict(event_dict)
          if isinstance(event_dict, FlowEvent)
          else dict(event_dict)
      )
      if 'timestamp' not in item:
        item['timestamp'] = time.time()
      if 'event_id' not in item:
        count = len(self._recorded_flow_events)
        ts_ms = int(item['timestamp'] * 1000)
        item['event_id'] = f'rec_{count}_{ts_ms}'
      self._recorded_flow_events.append(item)
      return item

  def get_flow_events(self) -> List[Dict[str, Any]]:
    """Returns a copy of all recorded cross-layer flow events."""
    with self._lock:
      return list(self._recorded_flow_events)

  def clear_flow_events(self) -> int:
    """Clears recorded flow events, returning the number of cleared events."""
    with self._lock:
      count = len(self._recorded_flow_events)
      self._recorded_flow_events.clear()
      return count

  def register_flow_dissector(
      self,
      name: str,
      dissector_fn: FlowDissector,
  ) -> None:
    """Registers a pluggable dissector to enrich or transform FlowEvents."""
    with self._lock:
      self._flow_dissectors[name] = dissector_fn
      logger.info('Registered flow dissector: %s', name)

  def register_flow_layer(self, name: str, metadata: Dict[str, Any]) -> None:
    """Registers display metadata (label, color, order) for a flow layer."""
    with self._lock:
      self._flow_layers[name] = dict(metadata)
      logger.info('Registered flow layer: %s', name)

  def register_extension(self, module_or_path: Union[str, Any]) -> str:
    """Dynamically loads and registers a Cirque extension module or object."""
    mod = None
    ext_name = 'unknown'
    if isinstance(module_or_path, str):
      ext_name = module_or_path
      if os.path.isfile(module_or_path):
        mod_name = f'cirque_ext_{abs(hash(module_or_path))}'
        spec = importlib.util.spec_from_file_location(mod_name, module_or_path)
        if spec is None or spec.loader is None:
          raise ImportError(
              f'Cannot create module spec from path: {module_or_path}'
          )
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
      else:
        mod = importlib.import_module(module_or_path)
    else:
      mod = module_or_path
      ext_name = getattr(mod, '__name__', str(mod))

    init_fn = getattr(mod, 'register_cirque_extension', None)
    if init_fn is None or not callable(init_fn):
      raise AttributeError(
          f'Extension {ext_name} does not define a callable'
          ' register_cirque_extension(server).'
      )

    init_fn(self)
    with self._lock:
      self._loaded_extensions[ext_name] = mod
    logger.info('Successfully activated Cirque MCP extension: %s', ext_name)
    return ext_name

  def list_extensions(self) -> Dict[str, Any]:
    """Returns a summary of dynamically registered extensions and items."""
    with self._lock:
      return {
          'loaded_extensions': list(self._loaded_extensions.keys()),
          'tools': {
              name: {
                  'extension': ext,
                  'description': schema.get('description', ''),
              }
              for name, (schema, _, ext) in self._extension_tools.items()
          },
          'resources': {
              uri: {'extension': ext, 'name': schema.get('name', '')}
              for uri, (schema, _, ext) in self._extension_resources.items()
          },
          'resource_templates': {
              templ: {'extension': ext, 'name': schema.get('name', '')}
              for templ, (
                  schema,
                  _,
                  _,
                  ext,
              ) in self._extension_resource_templates.items()
          },
          'prompts': {
              name: {
                  'extension': ext,
                  'description': schema.get('description', ''),
              }
              for name, (schema, _, ext) in self._extension_prompts.items()
          },
          'health_oracles': {
              name: {'extension': ext}
              for name, (_, ext) in self._extension_health_oracles.items()
          },
      }

  # ---------------------------------------------------------------------------
  # JSON-RPC 2.0 Dispatch & Stdio Protocol Handling
  # ---------------------------------------------------------------------------

  def handle_message(
      self, msg: Union[Dict[str, Any], List[Dict[str, Any]]]
  ) -> Optional[Union[Dict[str, Any], List[Dict[str, Any]]]]:
    """Handles an incoming JSON-RPC 2.0 request or batch."""
    if isinstance(msg, list):
      responses = []
      for req in msg:
        resp = self._dispatch_single_request(req)
        if resp is not None:
          responses.append(resp)
      return responses if responses else None
    return self._dispatch_single_request(msg)

  def _dispatch_single_request(
      self, req: Dict[str, Any]
  ) -> Optional[Dict[str, Any]]:
    if not isinstance(req, dict) or req.get('jsonrpc') != '2.0':
      return {
          'jsonrpc': '2.0',
          'id': req.get('id') if isinstance(req, dict) else None,
          'error': {'code': -32600, 'message': 'Invalid Request'},
      }

    req_id = req.get('id')
    method = req.get('method')
    params = req.get('params') or {}

    resp = self._dispatch_method(req_id, method, params)
    # JSON-RPC 2.0 section 4.1: a request without an "id" member is a
    # notification and the server MUST NOT reply to it, even on error.
    if 'id' not in req:
      return None
    return resp

  def _dispatch_method(
      self, req_id: Any, method: Any, params: Dict[str, Any]
  ) -> Optional[Dict[str, Any]]:
    # Notification handling
    if method == 'notifications/initialized':
      self._initialized = True
      return None

    if method == 'initialize':
      result = self._handle_initialize(params)
      return {'jsonrpc': '2.0', 'id': req_id, 'result': result}

    if method == 'ping':
      return {'jsonrpc': '2.0', 'id': req_id, 'result': {}}

    if method == 'tools/list':
      result = self._handle_tools_list(params)
      return {'jsonrpc': '2.0', 'id': req_id, 'result': result}

    if method == 'tools/call':
      return self._handle_tools_call(req_id, params)

    if method == 'resources/list':
      result = self._handle_resources_list(params)
      return {'jsonrpc': '2.0', 'id': req_id, 'result': result}

    if method == 'resources/templates/list':
      result = self._handle_resource_templates_list(params)
      return {'jsonrpc': '2.0', 'id': req_id, 'result': result}

    if method == 'resources/read':
      return self._handle_resources_read(req_id, params)

    if method == 'prompts/list':
      result = self._handle_prompts_list(params)
      return {'jsonrpc': '2.0', 'id': req_id, 'result': result}

    if method == 'prompts/get':
      return self._handle_prompts_get(req_id, params)

    return {
        'jsonrpc': '2.0',
        'id': req_id,
        'error': {'code': -32601, 'message': f'Method not found: {method}'},
    }

  def _handle_initialize(self, params: Dict[str, Any]) -> Dict[str, Any]:
    self._initialized = True
    return {
        'protocolVersion': MCP_PROTOCOL_VERSION,
        'capabilities': {
            'tools': {'listChanged': True},
            'resources': {'subscribe': False, 'listChanged': True},
            'prompts': {'listChanged': True},
        },
        'serverInfo': {
            'name': SERVER_NAME,
            'version': SERVER_VERSION,
        },
    }

  # ---------------------------------------------------------------------------
  # Iteration 1-5 Tool Definitions & Registrations
  # ---------------------------------------------------------------------------

  def _handle_tools_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
    tools = [
        # Iteration 1
        {
            'name': 'cirque_list_homes',
            'description': (
                'Lists active Cirque virtual homes, device counts, and node'
                ' types.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {},
                'additionalProperties': False,
            },
        },
        {
            'name': 'cirque_create_virtual_home',
            'description': (
                'Creates a virtual home from a preset or custom config'
                ' dictionary.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'preset': {
                        'type': 'string',
                        'enum': [
                            'two_node_ble_wifi',
                            'android_ble_wifi',
                            'android_ble_thread',
                        ],
                        'description': 'Topology preset name.',
                    },
                    'config': {
                        'type': 'object',
                        'description': (
                            'Custom Cirque home configuration dictionary.'
                        ),
                    },
                    'ssid': {'type': 'string', 'default': DEFAULT_HOME_SSID},
                    'wifi_psk': {'type': 'string', 'default': DEFAULT_HOME_PSK},
                    'avd_name': {'type': 'string', 'default': 'emulator'},
                    'pcap_dir': {'type': 'string'},
                    'wifi_auto_connect': {'type': 'boolean', 'default': True},
                },
                'additionalProperties': False,
            },
        },
        {
            'name': 'cirque_get_home_topology',
            'description': (
                'Returns full device descriptions, IPv4/IPv6 addresses,'
                ' capabilities, and topology metadata for a virtual home.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'home_id': {
                        'type': 'string',
                        'description': 'Target home ID.',
                    },
                },
                'required': ['home_id'],
                'additionalProperties': False,
            },
        },
        {
            'name': 'cirque_destroy_home',
            'description': 'Cleanly tears down a home_id or all virtual homes.',
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'home_id': {
                        'type': 'string',
                        'description': (
                            'Target home ID, or "all" to destroy all.'
                        ),
                    },
                },
                'additionalProperties': False,
            },
        },
        {
            'name': 'cirque_execute_device_cmd',
            'description': (
                'Executes a shell command inside a specific device container in'
                ' a virtual home.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'home_id': {
                        'type': 'string',
                        'description': 'Target home ID.',
                    },
                    'device_id': {
                        'type': 'string',
                        'description': 'Target device ID.',
                    },
                    'cmd': {
                        'type': 'string',
                        'description': 'Shell command string.',
                    },
                    'stream': {'type': 'boolean', 'default': False},
                },
                'required': ['home_id', 'device_id', 'cmd'],
                'additionalProperties': False,
            },
        },
        # Iteration 2
        {
            'name': 'cirque_get_radio_state',
            'description': (
                'Returns real-time Virtual Bluetooth and Virtual Wi-Fi server'
                ' states, frame counters, and Android radio path.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'home_id': {
                        'type': 'string',
                        'description': 'Optional target home ID.',
                    },
                    'android_device_id': {
                        'type': 'string',
                        'description': 'Optional Android node device ID.',
                    },
                },
                'additionalProperties': False,
            },
        },
        {
            'name': 'cirque_summarize_pcaps',
            'description': (
                'Summarizes all PCAP files (bt_hci_*.pcap, bt_medium.pcap,'
                ' wifi_medium.pcap, thread_*.pcap) in a directory.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'pcap_dir': {
                        'type': 'string',
                        'description': 'Directory containing PCAP files.',
                    },
                },
                'additionalProperties': False,
            },
        },
        {
            'name': 'cirque_inspect_thread_mesh',
            'description': (
                'Queries ot-ctl state, ipaddr, panid, extpanid, channel, child'
                ' table, counters, and ip -6 route across Thread nodes.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'home_id': {
                        'type': 'string',
                        'description': 'Target home ID.',
                    },
                },
                'required': ['home_id'],
                'additionalProperties': False,
            },
        },
        # Iteration 3
        {
            'name': 'cirque_inject_rf_fault',
            'description': (
                'Injects or clears deterministic RF faults across Bluetooth and'
                ' Wi-Fi, or executes named chaos recipes.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'recipe': {
                        'type': 'string',
                        'enum': list(RF_FAULT_RECIPES),
                        'description': 'Predefined chaos recipe.',
                    },
                    'rf_preset': {'type': 'string'},
                    'rf_config': {'type': 'object'},
                    'bt_relay_enabled': {'type': 'boolean'},
                    'bt_packet_loss_rate': {'type': 'number'},
                    'bt_latency_ms': {'type': 'number'},
                    'bt_rssi_dbm': {'type': 'integer'},
                    'bt_src_bd_addr': {'type': 'string'},
                    'bt_dst_bd_addr': {'type': 'string'},
                    'wifi_drop_station': {'type': 'string'},
                    'wifi_deauth_station': {'type': 'string'},
                    'wifi_reassociate_station': {'type': 'string'},
                },
                'additionalProperties': False,
            },
        },
        # Iteration 4
        {
            'name': 'cirque_android_ui_and_video',
            'description': (
                'Dumps Android UI hierarchy, finds elements, injects taps/text,'
                ' handles dialogs, or manages screen recordings.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'home_id': {
                        'type': 'string',
                        'description': 'Target home ID.',
                    },
                    'device_id': {
                        'type': 'string',
                        'description': 'Target Android device ID.',
                    },
                    'action': {
                        'type': 'string',
                        'enum': [
                            'dump_ui',
                            'find_element',
                            'tap',
                            'input_text',
                            'dismiss_dialogs',
                            'start_recording',
                            'stop_recording',
                            'list_recordings',
                        ],
                    },
                    'resource_id': {'type': 'string'},
                    'text': {'type': 'string'},
                    'content_desc': {'type': 'string'},
                    'fallback_coords': {
                        'type': 'array',
                        'items': {'type': 'integer'},
                    },
                    'text_to_input': {'type': 'string'},
                    'timeout_sec': {'type': 'number', 'default': 10.0},
                    'recording_name': {
                        'type': 'string',
                        'default': 'screen_recording.mp4',
                    },
                    'bit_rate': {'type': 'integer', 'default': 4000000},
                },
                'required': ['home_id', 'device_id', 'action'],
                'additionalProperties': False,
            },
        },
        # Iteration 5
        {
            'name': 'cirque_diagnose_home_health',
            'description': (
                'Runs automated cross-layer diagnostic checks on a virtual'
                ' home, returning oracles, root causes, and registered'
                ' extension findings.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'home_id': {
                        'type': 'string',
                        'description': 'Target home ID.',
                    },
                    'android_device_id': {
                        'type': 'string',
                        'description': 'Optional Android node device ID.',
                    },
                },
                'required': ['home_id'],
                'additionalProperties': False,
            },
        },
        # Extension dynamic registry tools
        {
            'name': 'cirque_register_mcp_extension',
            'description': (
                'Dynamically registers and activates an external Cirque MCP'
                ' extension module or file.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'module_or_path': {
                        'type': 'string',
                        'description': (
                            'Python module name or absolute filesystem path to'
                            ' extension script.'
                        ),
                    },
                },
                'required': ['module_or_path'],
                'additionalProperties': False,
            },
        },
        {
            'name': 'cirque_list_mcp_extensions',
            'description': (
                'Lists all dynamically registered Cirque MCP extensions, tools,'
                ' resources, prompts, and health oracles.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {},
                'additionalProperties': False,
            },
        },
        {
            'name': 'cirque_generate_flow_visualization',
            'description': (
                'Dissects PCAP packet captures and merged flow events into an'
                ' interactive HTML5 Studio and JSON trace.'
            ),
            'inputSchema': {
                'type': 'object',
                'properties': {
                    'pcap_dir': {
                        'type': 'string',
                        'description': (
                            'Directory containing PCAP files (defaults to'
                            ' server pcap_dir).'
                        ),
                    },
                    'output_html': {
                        'type': 'string',
                        'description': (
                            'Optional custom path for output HTML studio.'
                        ),
                    },
                    'output_json': {
                        'type': 'string',
                        'description': (
                            'Optional custom path for output JSON flow trace.'
                        ),
                    },
                    'title': {
                        'type': 'string',
                        'description': 'Custom title for visualization studio.',
                    },
                },
                'additionalProperties': False,
            },
        },
    ]

    # Append dynamic extension tools
    with self._lock:
      for schema_dict, _, _ in self._extension_tools.values():
        tools.append(schema_dict)

    return {'tools': tools}

  def _handle_tools_call(
      self, req_id: Any, params: Dict[str, Any]
  ) -> Dict[str, Any]:
    tool_name = params.get('name')
    arguments = params.get('arguments') or {}

    dispatch_map = {
        'cirque_list_homes': self._tool_list_homes,
        'cirque_create_virtual_home': self._tool_create_virtual_home,
        'cirque_get_home_topology': self._tool_get_home_topology,
        'cirque_destroy_home': self._tool_destroy_home,
        'cirque_execute_device_cmd': self._tool_execute_device_cmd,
        'cirque_get_radio_state': self._tool_get_radio_state,
        'cirque_summarize_pcaps': self._tool_summarize_pcaps,
        'cirque_inspect_thread_mesh': self._tool_inspect_thread_mesh,
        'cirque_inject_rf_fault': self._tool_inject_rf_fault,
        'cirque_android_ui_and_video': self._tool_android_ui_and_video,
        'cirque_diagnose_home_health': self._tool_diagnose_home_health,
        'cirque_diagnose_commissioning_health': (
            self._tool_diagnose_home_health
        ),  # backward compatibility alias
        'cirque_register_mcp_extension': self._tool_register_mcp_extension,
        'cirque_list_mcp_extensions': self._tool_list_mcp_extensions,
        'cirque_generate_flow_visualization': (
            self._tool_generate_flow_visualization
        ),
    }

    # Check core tools first
    handler = dispatch_map.get(tool_name)
    if handler is None:
      # Check dynamic extension tools
      with self._lock:
        if tool_name in self._extension_tools:
          handler = self._extension_tools[tool_name][1]

    if handler is None:
      return {
          'jsonrpc': '2.0',
          'id': req_id,
          'error': {'code': -32601, 'message': f'Unknown tool: {tool_name}'},
      }

    try:
      result_payload = handler(arguments)
      return {
          'jsonrpc': '2.0',
          'id': req_id,
          'result': {
              'content': [{
                  'type': 'text',
                  'text': json.dumps(result_payload, indent=2, default=str),
              }],
              'isError': False,
          },
      }
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.exception('Tool execution error in %s: %s', tool_name, exc)
      return {
          'jsonrpc': '2.0',
          'id': req_id,
          'result': {
              'content': [
                  {'type': 'text', 'text': f'Tool error ({tool_name}): {exc}'}
              ],
              'isError': True,
          },
      }

  # ---------------------------------------------------------------------------
  # Tool Implementations
  # ---------------------------------------------------------------------------

  def _tool_list_homes(self, args: Dict[str, Any]) -> Dict[str, Any]:
    active_homes = []
    for hid, home in self.homes.items():
      devices_summary = {}
      for did, dev in home.devices.items():
        devices_summary[did] = {
            'name': getattr(dev, 'name', did),
            'type': getattr(dev, 'type', 'unknown'),
            'base_image': getattr(dev, 'base_image', ''),
        }
      active_homes.append({
          'home_id': hid,
          'device_count': len(home.devices),
          'devices': devices_summary,
      })
    return {'homes': active_homes, 'total_count': len(active_homes)}

  def _tool_create_virtual_home(self, args: Dict[str, Any]) -> Dict[str, Any]:
    preset = args.get('preset')
    custom_config = args.get('config')
    ssid = args.get('ssid', DEFAULT_HOME_SSID)
    wifi_psk = args.get('wifi_psk', DEFAULT_HOME_PSK)
    avd_name = args.get('avd_name', 'emulator')
    pcap_dir = args.get('pcap_dir', self._pcap_dir)
    wifi_auto_connect = args.get('wifi_auto_connect', True)

    home_config = None
    if preset == 'two_node_ble_wifi':
      home_config = VirtualHomeTopology.default_two_node_ble_wifi_config(
          ssid=ssid, wifi_psk=wifi_psk
      )
    elif preset == 'android_ble_wifi':
      home_config = (
          VirtualHomeTopology.default_android_emulator_ble_wifi_config(
              ssid=ssid,
              wifi_psk=wifi_psk,
              avd_name=avd_name,
              pcap_dir=pcap_dir,
              wifi_auto_connect=wifi_auto_connect,
          )
      )
    elif preset == 'android_ble_thread':
      home_config = (
          VirtualHomeTopology.default_android_emulator_ble_thread_config(
              ssid=ssid,
              wifi_psk=wifi_psk,
              avd_name=avd_name,
              pcap_dir=pcap_dir,
          )
      )
    elif custom_config:
      home_config = custom_config
    else:
      raise ValueError('Either "preset" or "config" must be provided.')

    home = CirqueHome()
    home_id = home.create_home(home_config)
    with self._lock:
      self.homes[home_id] = home

    return {
        'status': 'created',
        'home_id': home_id,
        'preset': preset or 'custom',
        'device_ids': list(home.devices.keys()),
    }

  def _tool_get_home_topology(self, args: Dict[str, Any]) -> Dict[str, Any]:
    home_id = args.get('home_id')
    home = self._get_home(home_id)
    if not home:
      raise ValueError(f'Home not found: {home_id}')

    ssid_psk = home.get_wifiap_ssid_psk()
    devices = {}
    for dev_id, dev in home.devices.items():
      caps = {}
      for cap in getattr(dev, 'capabilities', []):
        caps[getattr(cap, 'name', type(cap).__name__)] = getattr(
            cap, 'description', {}
        )
      ipv4 = None
      ipv6 = None
      if hasattr(dev, 'get_docker_ip'):
        try:
          ipv4 = dev.get_docker_ip()
        except Exception as exc:  # pylint: disable=broad-exception-caught
          logger.debug('Could not resolve Docker IP for %s: %s', dev_id, exc)
      devices[dev_id] = {
          'id': dev_id,
          'name': getattr(dev, 'name', dev_id),
          'type': getattr(dev, 'type', 'unknown'),
          'base_image': getattr(dev, 'base_image', ''),
          'capabilities': caps,
          'ipv4': ipv4,
          'ipv6': ipv6,
          'description': getattr(dev, 'description', {}),
      }

    return {
        'home_id': home_id,
        'wifi_ssid_psk': ssid_psk,
        'device_count': len(devices),
        'devices': devices,
    }

  def _tool_destroy_home(self, args: Dict[str, Any]) -> Dict[str, Any]:
    home_id = args.get('home_id')
    with self._lock:
      if not home_id or home_id.lower() == 'all':
        destroyed = []
        for hid in list(self.homes.keys()):
          home = self.homes.pop(hid, None)
          if home:
            home.destroy_home()
            destroyed.append(hid)
        return {'status': 'destroyed_all', 'destroyed_homes': destroyed}

      home = self.homes.pop(home_id, None)
      if not home:
        raise ValueError(f'Home not found: {home_id}')
      res = home.destroy_home()
      return {'status': 'destroyed', 'home_id': home_id, 'result': res}

  def _tool_execute_device_cmd(self, args: Dict[str, Any]) -> Dict[str, Any]:
    home_id = args.get('home_id')
    device_id = args.get('device_id')
    cmd = args.get('cmd')
    stream = args.get('stream', False)

    home = self._get_home(home_id)
    if not home:
      raise ValueError(f'Home not found: {home_id}')
    if device_id not in home.devices:
      raise ValueError(f'Device not found in home: {device_id}')

    ret = home.execute_device_cmd(cmd, device_id, stream=stream)
    exit_code = getattr(ret, 'exit_code', 0)
    raw_output = getattr(ret, 'output', b'')
    if isinstance(raw_output, bytes):
      output_str = raw_output.decode('utf-8', errors='replace')
    else:
      output_str = str(raw_output)

    return {
        'home_id': home_id,
        'device_id': device_id,
        'cmd': cmd,
        'return_code': exit_code,
        'output': output_str,
    }

  def _tool_get_radio_state(self, args: Dict[str, Any]) -> Dict[str, Any]:
    home_id = args.get('home_id')
    android_device_id = args.get('android_device_id')

    bt_server = BlueToothCapability.get_or_start_virtual_server()
    wifi_server = WiFiCapability.get_or_start_virtual_server()

    # Bluetooth state
    bt_controllers = bt_server.list_controllers()
    bt_phy_frames = 0
    bt_loss = 0.0
    bt_latency = 0.0
    bt_default_rssi = -45
    if hasattr(bt_server, 'phy_hub') and bt_server.phy_hub is not None:
      bt_phy_frames = getattr(bt_server.phy_hub, 'total_frames_routed', 0)
      bt_loss = getattr(bt_server.phy_hub, '_packet_loss_rate', 0.0)
      bt_latency = getattr(bt_server.phy_hub, '_latency_ms', 0.0)
      bt_default_rssi = getattr(bt_server.phy_hub, '_default_rssi', -45)

    bt_relay_enabled = getattr(bt_server, 'relay_enabled', True)
    bt_effective_loss = 1.0 if not bt_relay_enabled else bt_loss
    bt_info = {
        'host': bt_server.host,
        'control_port': bt_server.control_port,
        'hci_port': bt_server.hci_port,
        'phy_port': bt_server.phy_port,
        'relay_enabled': bt_relay_enabled,
        'controllers': bt_controllers,
        'packet_loss_rate': bt_loss,
        'effective_packet_loss_rate': bt_effective_loss,
        'latency_ms': bt_latency,
        'default_rssi': bt_default_rssi,
        'total_phy_frames': bt_phy_frames,
    }

    # Wi-Fi state
    aps = [asdict(ap) for ap in wifi_server.list_aps()]
    stations = [asdict(st) for st in wifi_server.list_stations()]
    frame_counters = wifi_server.get_frame_counters()
    wifi_info = {
        'host': wifi_server.host,
        'control_port': wifi_server.control_port,
        'mgmt_port': wifi_server.mgmt_port,
        'data_port': wifi_server.data_port,
        'aps': aps,
        'stations': stations,
        'frame_counters': frame_counters,
    }

    # Android radio path check if requested
    android_radio_path = None
    if home_id and android_device_id:
      home = self._get_home(home_id)
      if home and android_device_id in home.devices:
        android_node = home.devices[android_device_id]
        android_radio_path = VirtualHomeTopology._android_radio_path(
            android_node, bt_server, hci_frames_before=0
        )

    # Multi-radio stochastic RF channel simulator state
    from cirque.connectivity.rf_channel_simulator import RfChannelSimulator

    rf_channel_info = RfChannelSimulator.get_shared().get_status()

    return {
        'bluetooth': bt_info,
        'wifi': wifi_info,
        'rf_channel': rf_channel_info,
        'android_radio_path': android_radio_path,
    }

  def _tool_summarize_pcaps(self, args: Dict[str, Any]) -> Dict[str, Any]:
    target_dir = args.get('pcap_dir') or self._pcap_dir
    if not os.path.exists(target_dir):
      return {
          'pcap_dir': target_dir,
          'pcap_count': 0,
          'files': [],
          'message': 'PCAP directory does not exist yet',
      }

    summaries = []
    pcap_paths = sorted(glob.glob(os.path.join(target_dir, '*.pcap')))
    for ppath in pcap_paths:
      try:
        sm = summarize_pcap(ppath)
        summaries.append(sm)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        summaries.append({
            'path': ppath,
            'file_size': os.path.getsize(ppath) if os.path.exists(ppath) else 0,
            'error': str(exc),
        })

    return {
        'pcap_dir': target_dir,
        'pcap_count': len(summaries),
        'files': summaries,
    }

  def _tool_inspect_thread_mesh(self, args: Dict[str, Any]) -> Dict[str, Any]:
    home_id = args.get('home_id')
    home = self._get_home(home_id)
    if not home:
      raise ValueError(f'Home not found: {home_id}')

    thread_nodes = {}
    commands = [
        ('state', 'ot-ctl state'),
        ('ipaddr', 'ot-ctl ipaddr'),
        ('panid', 'ot-ctl panid'),
        ('extpanid', 'ot-ctl extpanid'),
        ('channel', 'ot-ctl channel'),
        ('child_table', 'ot-ctl child table'),
        ('counters', 'ot-ctl counters ip'),
        ('ip6_routes', 'ip -6 route'),
    ]

    for dev_id, dev in home.devices.items():
      is_thread = getattr(dev, 'type', '') == 'ThreadBorderRouter' or any(
          getattr(c, 'name', '') == 'Thread'
          for c in getattr(dev, 'capabilities', [])
      )
      if not is_thread:
        continue

      node_data = {'type': getattr(dev, 'type', 'unknown')}
      for key, cmd in commands:
        try:
          ret = home.execute_device_cmd(cmd, dev_id)
          out = (
              ret.output.decode('utf-8', errors='replace').strip()
              if ret and ret.output
              else ''
          )
          node_data[key] = out
        except Exception as exc:  # pylint: disable=broad-exception-caught
          node_data[key] = f'Error: {exc}'
      thread_nodes[dev_id] = node_data

    return {
        'home_id': home_id,
        'thread_node_count': len(thread_nodes),
        'nodes': thread_nodes,
    }

  def _tool_inject_rf_fault(self, args: Dict[str, Any]) -> Dict[str, Any]:
    from cirque.connectivity.rf_channel_simulator import RfChannelSimulator

    rf_sim = RfChannelSimulator.get_shared()
    recipe = args.get('recipe')
    if recipe is not None and recipe != '' and recipe not in RF_FAULT_RECIPES:
      raise ValueError(f'Unknown RF fault recipe: {recipe}')

    bt_server = BlueToothCapability.get_or_start_virtual_server()
    wifi_server = WiFiCapability.get_or_start_virtual_server()
    actions = []
    applied_values: Dict[str, Any] = {}
    cleared_summary: Optional[Dict[str, Any]] = None

    if recipe == 'ble_brownout':
      bt_server.set_relay_enabled(False)
      actions.append('ble_brownout: set bt relay disabled')
    elif recipe == 'ble_restore':
      bt_server.set_relay_enabled(True)
      if hasattr(bt_server, 'phy_hub') and bt_server.phy_hub is not None:
        bt_server.phy_hub.set_packet_loss_rate(0.0)
        bt_server.phy_hub.set_latency_ms(0.0)
      actions.append('ble_restore: restored bt relay and 0% loss')
    elif recipe == 'wifi_deauth_roam':
      stations = wifi_server.list_stations()
      for st in stations:
        if not getattr(st, 'is_ap_bridge', False):
          wifi_server.disconnect_station(st.station_id, reason='deauth_roam')
          actions.append(f'wifi_deauth_roam: disconnected {st.station_id}')
    elif recipe == 'rf_cochannel_interference':
      rf_sim.apply_regime_preset('regime_c_cochannel_interference')
      actions.append(
          'rf_cochannel_interference: applied regime_c_cochannel_interference'
          ' RF preset'
      )
    elif recipe == 'clear_all_faults':
      rssi_cleared = 0
      isolated_cleared = 0
      bt_server.set_relay_enabled(True)
      if hasattr(bt_server, 'phy_hub') and bt_server.phy_hub is not None:
        rssi_cleared = len(getattr(bt_server.phy_hub, '_rssi_matrix', {}))
        isolated_cleared = len(
            getattr(bt_server.phy_hub, '_isolated_addrs', set())
        )
        bt_server.phy_hub.reset_medium()
      restored_stations: List[str] = []
      for st in wifi_server.list_stations():
        if (
            not getattr(st, 'is_ap_bridge', False)
            and getattr(st, 'state', '') != 'completed'
        ):
          wifi_server.reassociate_station(st.station_id)
          restored_stations.append(st.station_id)
      rf_sim.apply_regime_preset('ideal')
      cleared_summary = {
          'bt_relay_enabled': True,
          'bt_packet_loss_rate': 0.0,
          'bt_latency_ms': 0.0,
          'bt_default_rssi': -45,
          'rssi_matrix_cleared': rssi_cleared,
          'isolated_addresses_cleared': isolated_cleared,
          'wifi_stations_restored': restored_stations,
          'rf_channel_reset': True,
      }
      actions.append(
          'clear_all_faults: reset all BT, Wi-Fi & RF channel faults'
      )

    if 'rf_preset' in args and args['rf_preset']:
      preset_name = str(args['rf_preset'])
      rf_sim.apply_regime_preset(preset_name)
      applied_values['rf_preset'] = preset_name
      actions.append(f'set rf_preset={preset_name}')

    if 'rf_config' in args and isinstance(args['rf_config'], dict):
      rf_sim.update_config(args['rf_config'])
      applied_values['rf_config'] = args['rf_config']
      actions.append('updated rf_config')

    # Fine-grained parameters
    if 'bt_relay_enabled' in args:
      enabled = bool(args['bt_relay_enabled'])
      bt_server.set_relay_enabled(enabled)
      applied_values['bt_relay_enabled'] = enabled
      actions.append(f'set bt_relay_enabled={enabled}')

    if 'bt_packet_loss_rate' in args:
      rate = max(0.0, min(1.0, float(args['bt_packet_loss_rate'])))
      if hasattr(bt_server, 'phy_hub') and bt_server.phy_hub is not None:
        bt_server.phy_hub.set_packet_loss_rate(rate)
      applied_values['bt_packet_loss_rate'] = rate
      actions.append(f'set bt_packet_loss_rate={rate}')

    if 'bt_latency_ms' in args:
      lat = max(0.0, float(args['bt_latency_ms']))
      if hasattr(bt_server, 'phy_hub') and bt_server.phy_hub is not None:
        bt_server.phy_hub.set_latency_ms(lat)
      applied_values['bt_latency_ms'] = lat
      actions.append(f'set bt_latency_ms={lat}')

    if 'bt_rssi_dbm' in args:
      rssi = max(-127, min(20, int(args['bt_rssi_dbm'])))
      src = args.get('bt_src_bd_addr')
      dst = args.get('bt_dst_bd_addr')
      if hasattr(bt_server, 'phy_hub') and bt_server.phy_hub is not None:
        if src and dst:
          bt_server.phy_hub.set_rssi(src, dst, rssi)
          actions.append(f'set bt_rssi({src}->{dst})={rssi}dBm')
        else:
          bt_server.phy_hub.set_default_rssi(rssi)
          actions.append(f'set bt_default_rssi={rssi}dBm')
      applied_values['bt_rssi_dbm'] = rssi

    if 'wifi_drop_station' in args:
      sid = str(args['wifi_drop_station']).strip()
      if not sid or wifi_server.get_station(sid) is None:
        raise ValueError(f'Unknown Wi-Fi station: {sid}')
      wifi_server.disconnect_station(sid, reason='dropped')
      actions.append(f'wifi_drop_station={sid}')

    if 'wifi_deauth_station' in args:
      sid = str(args['wifi_deauth_station']).strip()
      if not sid or wifi_server.get_station(sid) is None:
        raise ValueError(f'Unknown Wi-Fi station: {sid}')
      wifi_server.disconnect_station(sid, reason='deauthenticated')
      actions.append(f'wifi_deauth_station={sid}')

    if 'wifi_reassociate_station' in args:
      sid = str(args['wifi_reassociate_station']).strip()
      st = wifi_server.get_station(sid) if sid else None
      if st is None:
        raise ValueError(f'Unknown Wi-Fi station: {sid}')
      if getattr(st, 'state', '') == 'completed':
        raise ValueError(
            f"Wi-Fi station '{sid}' is already associated (COMPLETED)"
        )
      wifi_server.reassociate_station(sid)
      actions.append(f'wifi_reassociate_station={sid}')

    resp: Dict[str, Any] = {
        'status': 'applied',
        'actions': actions,
        'applied_values': applied_values,
    }
    resp.update(applied_values)
    if cleared_summary is not None:
      resp['cleared'] = cleared_summary
    return resp

  def _tool_android_commission(self, args: Dict[str, Any]) -> Dict[str, Any]:
    home_id = args.get('home_id')
    device_id = args.get('device_id')
    network_type = args.get('network_type', 'wifi').lower()
    trigger = args.get('trigger', 'auto')
    ssid = args.get('ssid', DEFAULT_HOME_SSID)
    psk = args.get('psk', DEFAULT_HOME_PSK)
    setup_pin_code = int(args.get('setup_pin_code', 20202021))
    discriminator = int(args.get('discriminator', 3840))
    manual_code = str(args.get('manual_code', '34970112332'))
    timeout_sec = float(args.get('timeout_sec', 60.0))
    record_video = bool(args.get('record_video', False))

    home = self._get_home(home_id)
    if not home:
      raise ValueError(f'Home not found: {home_id}')
    node = home.devices.get(device_id)
    if not node:
      raise ValueError(f'Device not found in home: {device_id}')

    video_info = None
    if record_video and hasattr(node, 'start_screen_recording'):
      video_info = node.start_screen_recording(
          f'commission_{network_type}_{int(timeout_sec)}s.mp4'
      )

    try:
      if network_type == 'thread':
        if not hasattr(node, 'commission_thread_via_chiptool_ui'):
          raise TypeError(
              f'Node {device_id} does not support Thread UI commissioning.'
          )

        # Helper injection for joiner/dataset
        has_tbr = any(
            getattr(d, 'type', '') == 'ThreadBorderRouter'
            for d in home.devices.values()
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
        for did, dev_node in home.devices.items():
          if (
              did != device_id
              and getattr(dev_node, 'type', '') != 'ThreadBorderRouter'
              and any(
                  getattr(c, 'name', '') == 'Thread'
                  for c in getattr(dev_node, 'capabilities', [])
              )
          ):
            if getattr(dev_node, 'container', None) is not None:
              dev_node.container.exec_run(helper_cmd, detach=True)
            else:
              home.execute_device_cmd(helper_cmd, did)

        channel = args.get('channel')
        pan_id = args.get('pan_id')
        xpan_id = args.get('xpan_id')
        master_key = args.get('master_key')
        dataset_tlvs_hex = args.get('dataset_tlvs_hex')

        result = node.commission_thread_via_chiptool_ui(
            channel=int(channel) if channel is not None else None,
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
          raise TypeError(
              f'Node {device_id} does not support Wi-Fi UI commissioning.'
          )
        result = node.commission_via_chiptool_ui(
            ssid=ssid,
            psk=psk,
            setup_pin_code=setup_pin_code,
            discriminator=discriminator,
            manual_code=manual_code,
            timeout_sec=timeout_sec,
            trigger=trigger,
        )
      return {
          'status': 'success',
          'commission_result': result,
          'video': video_info,
      }
    finally:
      if record_video and hasattr(node, 'stop_screen_recording'):
        node.stop_screen_recording()

  def _tool_android_onoff_action(self, args: Dict[str, Any]) -> Dict[str, Any]:
    home_id = args.get('home_id')
    device_id = args.get('device_id')
    action = args.get('action', 'toggle')
    node_id = int(args.get('node_id', 1))
    endpoint = int(args.get('endpoint', 1))
    timeout_sec = float(args.get('timeout_sec', 15.0))
    record_video = bool(args.get('record_video', False))

    home = self._get_home(home_id)
    if not home:
      raise ValueError(f'Home not found: {home_id}')
    node = home.devices.get(device_id)
    if not node:
      raise ValueError(f'Device not found in home: {device_id}')

    if record_video and hasattr(node, 'start_screen_recording'):
      node.start_screen_recording(f'onoff_{action}_{int(timeout_sec)}s.mp4')

    try:
      if action == 'toggle':
        if not hasattr(node, 'toggle_onoff_via_chiptool_ui'):
          raise TypeError(
              f'Node {device_id} does not support toggle_onoff_via_chiptool_ui.'
          )
        res = node.toggle_onoff_via_chiptool_ui(
            node_id=node_id, endpoint=endpoint, timeout_sec=timeout_sec
        )
      elif action == 'read':
        if not hasattr(node, 'read_onoff_via_chiptool_ui'):
          raise TypeError(
              f'Node {device_id} does not support read_onoff_via_chiptool_ui.'
          )
        res = node.read_onoff_via_chiptool_ui(
            node_id=node_id, endpoint=endpoint, timeout_sec=timeout_sec
        )
      elif action == 'toggle_and_read':
        toggle_res = node.toggle_onoff_via_chiptool_ui(
            node_id=node_id, endpoint=endpoint, timeout_sec=timeout_sec
        )
        read_res = node.read_onoff_via_chiptool_ui(
            node_id=node_id, endpoint=endpoint, timeout_sec=timeout_sec
        )
        res = {'toggle': toggle_res, 'read': read_res}
      else:
        raise ValueError(f'Unknown action: {action}')
      return {'status': 'success', 'action': action, 'result': res}
    finally:
      if record_video and hasattr(node, 'stop_screen_recording'):
        node.stop_screen_recording()

  def _tool_android_ui_and_video(self, args: Dict[str, Any]) -> Dict[str, Any]:
    home_id = args.get('home_id')
    device_id = args.get('device_id')
    action = args.get('action')

    home = self._get_home(home_id)
    if not home:
      raise ValueError(f'Home not found: {home_id}')
    node = home.devices.get(device_id)
    if not node:
      raise ValueError(f'Device not found in home: {device_id}')

    if action == 'dump_ui':
      xml_str = node.dump_ui_hierarchy()
      return {'action': action, 'xml_length': len(xml_str), 'xml': xml_str}

    if action == 'find_element':
      coords = node.find_ui_element(
          resource_id=args.get('resource_id'),
          text=args.get('text'),
          content_desc=args.get('content_desc'),
          fallback_coords=tuple(args['fallback_coords'])
          if args.get('fallback_coords')
          else None,
          timeout_sec=float(args.get('timeout_sec', 10.0)),
      )
      return {'action': action, 'center': coords}

    if action == 'tap':
      coords = node.tap_ui_element(
          resource_id=args.get('resource_id'),
          text=args.get('text'),
          content_desc=args.get('content_desc'),
          fallback_coords=tuple(args['fallback_coords'])
          if args.get('fallback_coords')
          else None,
          timeout_sec=float(args.get('timeout_sec', 10.0)),
      )
      return {'action': action, 'tapped_coords': coords}

    if action == 'input_text':
      text_to_input = args.get('text_to_input', '')
      coords = node.input_text_ui_element(
          text_to_input,
          resource_id=args.get('resource_id'),
          text=args.get('text'),
          content_desc=args.get('content_desc'),
          fallback_coords=tuple(args['fallback_coords'])
          if args.get('fallback_coords')
          else None,
          timeout_sec=float(args.get('timeout_sec', 10.0)),
      )
      return {
          'action': action,
          'injected_text': text_to_input,
          'coords': coords,
      }

    if action == 'dismiss_dialogs':
      node.dismiss_system_dialogs()
      return {'action': action, 'status': 'dismissed'}

    if action == 'start_recording':
      name = args.get('recording_name', 'screen_recording.mp4')
      bit_rate = int(args.get('bit_rate', 4000000))
      res = node.start_screen_recording(name=name, bit_rate=bit_rate)
      return {'action': action, 'recording': res}

    if action == 'stop_recording':
      res = node.stop_screen_recording()
      return {'action': action, 'recording': res}

    if action == 'list_recordings':
      recs = node.list_screen_recordings()
      return {'action': action, 'recordings': recs}

    raise ValueError(f'Unknown action: {action}')

  def _tool_diagnose_commissioning_health(
      self, args: Dict[str, Any]
  ) -> Dict[str, Any]:
    home_id = args.get('home_id')
    android_device_id = args.get('android_device_id')
    home = self._get_home(home_id)
    if not home:
      raise ValueError(f'Home not found: {home_id}')

    oracles: Dict[str, bool] = {}
    root_causes: List[str] = []
    remediation_steps: List[str] = []

    # 1. Virtual Bluetooth Server check
    bt_server = BlueToothCapability.get_or_start_virtual_server()
    oracles['bt_server_running'] = getattr(bt_server, '_running', False)
    bt_relay_enabled = getattr(bt_server, 'relay_enabled', True)
    oracles['bt_relay_enabled'] = bt_relay_enabled
    bt_loss = 0.0
    if hasattr(bt_server, 'phy_hub') and bt_server.phy_hub is not None:
      bt_loss = getattr(bt_server.phy_hub, '_packet_loss_rate', 0.0)
    effective_bt_loss = 1.0 if not bt_relay_enabled else bt_loss
    oracles['bt_effective_packet_loss_rate'] = effective_bt_loss
    oracles['bt_packet_loss_healthy'] = effective_bt_loss == 0.0
    if not bt_relay_enabled:
      root_causes.append(
          'Virtual Bluetooth packet relay is disabled (RF brownout).'
      )
      remediation_steps.append(
          'Invoke cirque_inject_rf_fault with recipe="ble_restore".'
      )
    elif bt_loss > 0.0:
      root_causes.append(
          f'Virtual Bluetooth packet loss fault active ({bt_loss * 100:.0f}%).'
      )
      remediation_steps.append(
          'Invoke cirque_inject_rf_fault with bt_packet_loss_rate=0.0.'
      )

    controllers = bt_server.list_controllers()
    oracles['bt_controllers_bound'] = len(controllers) >= 2
    if len(controllers) < 2:
      root_causes.append(f'Fewer than 2 BT controllers bound: {controllers}')
      remediation_steps.append(
          'Ensure both Matter peripheral and controller are attached to Virtual'
          ' Bluetooth.'
      )

    # 2. Virtual Wi-Fi Server check
    wifi_server = WiFiCapability.get_or_start_virtual_server()
    oracles['wifi_server_running'] = getattr(wifi_server, '_running', False)
    aps = wifi_server.list_aps()
    oracles['wifi_ap_registered'] = len(aps) > 0
    if not oracles['wifi_ap_registered']:
      root_causes.append(
          'No Wi-Fi Access Point registered in Virtual Wi-Fi server.'
      )
      remediation_steps.append('Ensure wifi_ap node is created and running.')

    frame_counters = wifi_server.get_frame_counters()
    oracles['wifi_frames_flowing'] = (
        frame_counters.get('total_packets_with_handshake', 0) > 0
    )

    # 3. Android radio path & logs
    android_node = None
    if android_device_id and android_device_id in home.devices:
      android_node = home.devices[android_device_id]
    else:
      for dev in home.devices.values():
        if 'android' in getattr(dev, 'type', '').lower():
          android_node = dev
          break

    if android_node is not None:
      radio_path = VirtualHomeTopology._android_radio_path(
          android_node, bt_server, hci_frames_before=0
      )
      oracles['android_bt_bound'] = radio_path.get('bt_controller_bound', False)
      oracles['android_hci_flowing'] = (
          radio_path.get('android_hci_frames', 0) > 0
      )
      if not oracles['android_bt_bound']:
        root_causes.append(
            'Android pty_bridge is not bound to Virtual Bluetooth server.'
        )
        remediation_steps.append('Restart pty_bridge inside Android container.')

      # Check logcat markers
      if hasattr(android_node, '_chiptool_logcat_contains'):
        pase_ok = android_node._chiptool_logcat_contains(
            'Secure session established'
        ) or android_node._chiptool_logcat_contains('PASE established')
        case_ok = android_node._chiptool_logcat_contains(
            'CASE session established'
        ) or android_node._chiptool_logcat_contains('CASE established')
        oracles['pase_established'] = pase_ok
        oracles['case_established'] = case_ok

    # 4. Thread mesh check (if Thread present)
    has_thread = any(
        getattr(d, 'type', '') == 'ThreadBorderRouter'
        or any(
            getattr(c, 'name', '') == 'Thread'
            for c in getattr(d, 'capabilities', [])
        )
        for d in home.devices.values()
    )
    if has_thread:
      mesh_info = self._tool_inspect_thread_mesh({'home_id': home_id})
      leader_found = any(
          'leader' in n.get('state', '').lower()
          for n in mesh_info.get('nodes', {}).values()
      )
      oracles['thread_leader_elected'] = leader_found
      if not leader_found:
        root_causes.append('No Thread node has assumed the Leader role.')
        remediation_steps.append(
            'Run ot-ctl dataset init or form_thread_border_router_network.'
        )

    is_healthy = len(root_causes) == 0
    result_diag = {
        'home_id': home_id,
        'healthy': is_healthy,
        'oracles': oracles,
        'root_causes': root_causes,
        'remediation_steps': remediation_steps,
    }

    # 5. Evaluate dynamically registered extension health oracles
    extension_findings: Dict[str, Any] = {}
    with self._lock:
      oracles_to_run = list(self._extension_health_oracles.items())

    for oracle_name, (oracle_fn, ext_name) in oracles_to_run:
      try:
        findings = oracle_fn(home, android_device_id)
        extension_findings[oracle_name] = {
            'extension': ext_name,
            'result': findings,
        }
        if isinstance(findings, dict):
          if findings.get('healthy') is False:
            result_diag['healthy'] = False
          if 'root_causes' in findings and isinstance(
              findings['root_causes'], list
          ):
            result_diag['root_causes'].extend(findings['root_causes'])
          if 'remediation_steps' in findings and isinstance(
              findings['remediation_steps'], list
          ):
            result_diag['remediation_steps'].extend(
                findings['remediation_steps']
            )
          if 'oracles' in findings and isinstance(findings['oracles'], dict):
            result_diag['oracles'].update(findings['oracles'])
      except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.exception(
            'Extension health oracle %s failed: %s', oracle_name, exc
        )
        extension_findings[oracle_name] = {
            'extension': ext_name,
            'error': str(exc),
        }

    if extension_findings:
      result_diag['extension_findings'] = extension_findings

    return result_diag

  def _tool_diagnose_home_health(self, args: Dict[str, Any]) -> Dict[str, Any]:
    return self._tool_diagnose_commissioning_health(args)

  def _tool_register_mcp_extension(
      self, args: Dict[str, Any]
  ) -> Dict[str, Any]:
    module_or_path = args.get('module_or_path')
    if not module_or_path:
      raise ValueError('Parameter "module_or_path" is required.')
    ext_name = self.register_extension(module_or_path)
    return {
        'status': 'registered',
        'extension_name': ext_name,
        'extensions': self.list_extensions(),
    }

  def _tool_list_mcp_extensions(self, args: Dict[str, Any]) -> Dict[str, Any]:
    return self.list_extensions()

  def _tool_generate_flow_visualization(
      self, args: Dict[str, Any]
  ) -> Dict[str, Any]:
    """Generates cross-layer HTML visualizer and JSON trace from pcaps."""
    pcap_dir = args.get('pcap_dir') or self._pcap_dir
    title = args.get('title', 'Cirque Cross-Layer Flow Studio')

    os.makedirs(pcap_dir, exist_ok=True)
    output_html = args.get('output_html') or os.path.join(
        pcap_dir, 'cirque_flow_visualization.html'
    )
    output_json = args.get('output_json') or os.path.join(
        pcap_dir, 'cirque_flow_trace.json'
    )

    # Collect in-memory recorded events and loaded plugins
    with self._lock:
      recorded_events = list(self._recorded_flow_events)
      dissectors = dict(self._flow_dissectors)
      layers = dict(self._flow_layers)
      loaded_plugins = list(self._loaded_extensions.values())

    # Collect PCAP and container log events
    pcap_events = dissect_pcap_directory(pcap_dir, plugins=loaded_plugins)

    # Merge and sort
    merged = merge_and_sort_flow_events(
        pcap_events=pcap_events,
        recorded_events=recorded_events,
        dissectors=dissectors,
    )

    # Generate HTML
    generate_flow_html(merged, output_html, title=title, layers=layers)

    # Save JSON trace
    with open(output_json, 'w', encoding='utf-8') as f:
      json.dump([ev.to_dict() for ev in merged], f, indent=2)

    layer_counts: Dict[str, int] = {}
    stage_summary: Dict[str, int] = {}
    for ev in merged:
      layer_counts[ev.layer] = layer_counts.get(ev.layer, 0) + 1
      stage_summary[ev.stage] = stage_summary.get(ev.stage, 0) + 1

    summary_result = {
        'status': 'success',
        'html_path': output_html,
        'json_path': output_json,
        'total_events': len(merged),
        'layer_counts': layer_counts,
        'stage_summary': stage_summary,
        'pcap_dir': pcap_dir,
    }

    with self._lock:
      self._last_flow_visualization = summary_result

    return summary_result

  # ---------------------------------------------------------------------------
  # MCP Resources & Templates
  # ---------------------------------------------------------------------------

  def _handle_resources_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
    resources = [
        {
            'uri': 'cirque://homes',
            'name': 'Active Virtual Homes',
            'description': (
                'Real-time JSON registry of all active Cirque virtual homes.'
            ),
            'mimeType': 'application/json',
        },
        {
            'uri': 'cirque://flow/visualization',
            'name': 'Latest Cross-Layer Flow Visualization',
            'description': (
                'Summary metadata and HTML file path of latest cross-layer'
                ' flow visualizer.'
            ),
            'mimeType': 'application/json',
        },
    ]
    for hid in self.homes:
      resources.extend([
          {
              'uri': f'cirque://homes/{hid}/topology',
              'name': f'Topology ({hid})',
              'description': (
                  'Full device network topology and IP mappings for home'
                  f' {hid}.'
              ),
              'mimeType': 'application/json',
          },
          {
              'uri': f'cirque://homes/{hid}/radio',
              'name': f'Radio State ({hid})',
              'description': (
                  f'Bluetooth and Wi-Fi RF server states for home {hid}.'
              ),
              'mimeType': 'application/json',
          },
          {
              'uri': f'cirque://homes/{hid}/pcaps',
              'name': f'PCAPs ({hid})',
              'description': (
                  f'PCAP packet capture files and summaries for home {hid}.'
              ),
              'mimeType': 'application/json',
          },
          {
              'uri': f'cirque://homes/{hid}/health',
              'name': f'Health ({hid})',
              'description': (
                  f'Automated diagnostic health report for home {hid}.'
              ),
              'mimeType': 'application/json',
          },
      ])
    # Append dynamic extension resources
    with self._lock:
      for schema_dict, _, _ in self._extension_resources.values():
        resources.append(schema_dict)

    return {'resources': resources}

  def _handle_resource_templates_list(
      self, params: Dict[str, Any]
  ) -> Dict[str, Any]:
    templates = [
        {
            'uriTemplate': 'cirque://homes/{home_id}/topology',
            'name': 'Home Topology',
            'description': 'Device descriptions, IPs, and capabilities.',
            'mimeType': 'application/json',
        },
        {
            'uriTemplate': 'cirque://homes/{home_id}/radio',
            'name': 'Radio State',
            'description': 'Virtual BT and Virtual Wi-Fi server states.',
            'mimeType': 'application/json',
        },
        {
            'uriTemplate': 'cirque://homes/{home_id}/pcaps',
            'name': 'PCAP Summaries',
            'description': 'PCAP captures for the virtual home.',
            'mimeType': 'application/json',
        },
        {
            'uriTemplate': 'cirque://homes/{home_id}/health',
            'name': 'Commissioning Health',
            'description': 'Cross-Layer diagnostic health analysis.',
            'mimeType': 'application/json',
        },
        {
            'uriTemplate': 'cirque://homes/{home_id}/devices/{device_id}/logs',
            'name': 'Device Logs',
            'description': 'Raw device or Android logcat logs.',
            'mimeType': 'text/plain',
        },
        {
            'uriTemplate': (
                'cirque://homes/{home_id}/devices/{device_id}/videos'
            ),
            'name': 'Device Videos',
            'description': 'List of recorded MP4 screen captures.',
            'mimeType': 'application/json',
        },
    ]

    # Append dynamic extension templates
    with self._lock:
      for schema_dict, _, _, _ in self._extension_resource_templates.values():
        templates.append(schema_dict)

    return {'resourceTemplates': templates}

  def _handle_resources_read(
      self, req_id: Any, params: Dict[str, Any]
  ) -> Dict[str, Any]:
    uri = params.get('uri', '')
    if not uri.startswith('cirque://'):
      return {
          'jsonrpc': '2.0',
          'id': req_id,
          'error': {
              'code': -32602,
              'message': f'Invalid resource URI scheme: {uri}',
          },
      }

    try:
      # Check extension exact resources first
      with self._lock:
        if uri in self._extension_resources:
          res_schema, reader_fn, _ = self._extension_resources[uri]
          content_data = reader_fn(uri) if reader_fn else res_schema
          mime_type = res_schema.get('mimeType', 'application/json')
          text_out = (
              content_data
              if isinstance(content_data, str)
              else json.dumps(content_data, indent=2, default=str)
          )
          return {
              'jsonrpc': '2.0',
              'id': req_id,
              'result': {
                  'contents': [
                      {'uri': uri, 'mimeType': mime_type, 'text': text_out}
                  ]
              },
          }

      # Check extension resource templates
      with self._lock:
        for templ_name, (
            templ_schema,
            pat,
            reader_fn,
            _,
        ) in self._extension_resource_templates.items():
          m = pat.match(uri)
          if m:
            content_data = reader_fn(uri, m)
            mime_type = templ_schema.get('mimeType', 'application/json')
            text_out = (
                content_data
                if isinstance(content_data, str)
                else json.dumps(content_data, indent=2, default=str)
            )
            return {
                'jsonrpc': '2.0',
                'id': req_id,
                'result': {
                    'contents': [
                        {'uri': uri, 'mimeType': mime_type, 'text': text_out}
                    ]
                },
            }

      # cirque://homes
      if uri == 'cirque://homes':
        data = self._tool_list_homes({})
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'contents': [{
                    'uri': uri,
                    'mimeType': 'application/json',
                    'text': json.dumps(data, indent=2),
                }]
            },
        }

      # cirque://flow/visualization
      if uri == 'cirque://flow/visualization':
        with self._lock:
          last_vis = self._last_flow_visualization
        if not last_vis:
          last_vis = self._tool_generate_flow_visualization({})
        vis_json = json.dumps(last_vis, indent=2)
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'contents': [{
                    'uri': uri,
                    'mimeType': 'application/json',
                    'text': vis_json,
                }]
            },
        }

      # cirque://homes/{home_id}/topology
      m_top = re.match(r'^cirque://homes/([^/]+)/topology$', uri)
      if m_top:
        hid = m_top.group(1)
        data = self._tool_get_home_topology({'home_id': hid})
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'contents': [{
                    'uri': uri,
                    'mimeType': 'application/json',
                    'text': json.dumps(data, indent=2),
                }]
            },
        }

      # cirque://homes/{home_id}/radio
      m_rad = re.match(r'^cirque://homes/([^/]+)/radio$', uri)
      if m_rad:
        hid = m_rad.group(1)
        data = self._tool_get_radio_state({'home_id': hid})
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'contents': [{
                    'uri': uri,
                    'mimeType': 'application/json',
                    'text': json.dumps(data, indent=2),
                }]
            },
        }

      # cirque://homes/{home_id}/pcaps
      m_pcap = re.match(r'^cirque://homes/([^/]+)/pcaps$', uri)
      if m_pcap:
        data = self._tool_summarize_pcaps({})
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'contents': [{
                    'uri': uri,
                    'mimeType': 'application/json',
                    'text': json.dumps(data, indent=2),
                }]
            },
        }

      # cirque://homes/{home_id}/health
      m_hlt = re.match(r'^cirque://homes/([^/]+)/health$', uri)
      if m_hlt:
        hid = m_hlt.group(1)
        data = self._tool_diagnose_home_health({'home_id': hid})
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'contents': [{
                    'uri': uri,
                    'mimeType': 'application/json',
                    'text': json.dumps(data, indent=2),
                }]
            },
        }

      # cirque://homes/{home_id}/devices/{device_id}/logs
      m_log = re.match(r'^cirque://homes/([^/]+)/devices/([^/]+)/logs$', uri)
      if m_log:
        hid, did = m_log.group(1), m_log.group(2)
        home = self._get_home(hid)
        if not home or did not in home.devices:
          raise ValueError(f'Home or device not found: {hid}/{did}')
        logs = home.get_device_log(did, tail='all')
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'contents': [
                    {'uri': uri, 'mimeType': 'text/plain', 'text': logs}
                ]
            },
        }

      # cirque://homes/{home_id}/devices/{device_id}/videos
      m_vid = re.match(r'^cirque://homes/([^/]+)/devices/([^/]+)/videos$', uri)
      if m_vid:
        hid, did = m_vid.group(1), m_vid.group(2)
        home = self._get_home(hid)
        if not home or did not in home.devices:
          raise ValueError(f'Home or device not found: {hid}/{did}')
        node = home.devices[did]
        recs = (
            node.list_screen_recordings()
            if hasattr(node, 'list_screen_recordings')
            else []
        )
        return {
            'jsonrpc': '2.0',
            'id': req_id,
            'result': {
                'contents': [{
                    'uri': uri,
                    'mimeType': 'application/json',
                    'text': json.dumps(recs, indent=2),
                }]
            },
        }

      return {
          'jsonrpc': '2.0',
          'id': req_id,
          'error': {'code': -32602, 'message': f'Resource not found: {uri}'},
      }
    except Exception as exc:  # pylint: disable=broad-exception-caught
      return {
          'jsonrpc': '2.0',
          'id': req_id,
          'error': {
              'code': -32603,
              'message': f'Failed reading resource {uri}: {exc}',
          },
      }

  # ---------------------------------------------------------------------------
  # MCP Prompts
  # ---------------------------------------------------------------------------

  def _handle_prompts_list(self, params: Dict[str, Any]) -> Dict[str, Any]:
    prompts = [
        {
            'name': 'debug_commissioning_failure',
            'description': (
                'Guides autonomous debugging and triage of failed Matter'
                ' BLE/Wi-Fi/Thread commissioning.'
            ),
            'arguments': [
                {
                    'name': 'home_id',
                    'description': 'Target home ID.',
                    'required': True,
                },
                {
                    'name': 'network_type',
                    'description': 'wifi or thread.',
                    'required': False,
                },
            ],
        },
        {
            'name': 'rf_chaos_resilience_drill',
            'description': (
                'Executes an automated RF brownout or packet loss injection'
                ' drill to test reconnection resilience.'
            ),
            'arguments': [
                {
                    'name': 'home_id',
                    'description': 'Target home ID.',
                    'required': True,
                },
                {
                    'name': 'chaos_type',
                    'description': 'ble_brownout or wifi_deauth.',
                    'required': False,
                },
            ],
        },
        {
            'name': 'thread_border_router_triage',
            'description': (
                'Inspects OpenThread border router routing tables, OMR'
                ' prefixes, and child tables.'
            ),
            'arguments': [
                {
                    'name': 'home_id',
                    'description': 'Target home ID.',
                    'required': True,
                },
            ],
        },
        {
            'name': 'android_matter_certification',
            'description': (
                'Runs end-to-end Matter certification test sequence on Android'
                ' emulator with video capture evidence.'
            ),
            'arguments': [
                {
                    'name': 'home_id',
                    'description': 'Target home ID.',
                    'required': True,
                },
                {
                    'name': 'device_id',
                    'description': 'Android emulator node device ID.',
                    'required': True,
                },
            ],
        },
    ]
    # Append dynamic extension prompts
    with self._lock:
      for schema_dict, _, _ in self._extension_prompts.values():
        prompts.append(schema_dict)

    return {'prompts': prompts}

  def _handle_prompts_get(
      self, req_id: Any, params: Dict[str, Any]
  ) -> Dict[str, Any]:
    name = params.get('name')
    arguments = params.get('arguments') or {}

    # Check extension prompts first
    with self._lock:
      if name in self._extension_prompts:
        p_schema, renderer_fn, ext_name = self._extension_prompts[name]
        try:
          content_text = renderer_fn(arguments)
          return {
              'jsonrpc': '2.0',
              'id': req_id,
              'result': {
                  'description': p_schema.get(
                      'description', f'MCP prompt from extension {ext_name}'
                  ),
                  'messages': [{
                      'role': 'user',
                      'content': {'type': 'text', 'text': content_text},
                  }],
              },
          }
        except Exception as exc:  # pylint: disable=broad-exception-caught
          return {
              'jsonrpc': '2.0',
              'id': req_id,
              'error': {
                  'code': -32603,
                  'message': f'Failed rendering prompt {name}: {exc}',
              },
          }

    prompt_templates = {
        'debug_commissioning_failure': (
            'You are an expert IoT Systems and Matter protocol triage'
            ' copilot.\nAnalyze virtual home "{home_id}" (network type:'
            ' {network_type}).\n\nSteps to follow:\n1. Call'
            ' `cirque_diagnose_home_health` to evaluate all oracles.\n2. Call'
            ' `cirque_get_radio_state` to inspect controller bindings and'
            ' packet counters.\n3. Read'
            ' `cirque://homes/{home_id}/devices/{device_id}/logs` for session'
            ' errors.\n4. Call `cirque_summarize_pcaps` to verify Link Layer'
            ' frames in Wireshark PCAPs.\n5. Formulate root cause analysis and'
            ' propose concrete remediation steps.'
        ),
        'rf_chaos_resilience_drill': (
            'You are an autonomous IoT Chaos Monkey and Reliability'
            ' Engineer.\nExecute an RF degradation drill on home "{home_id}"'
            ' (chaos: {chaos_type}).\n\nSteps to follow:\n1. Measure baseline'
            ' state with `cirque_get_radio_state`.\n2. Inject RF fault via'
            ' `cirque_inject_rf_fault` (e.g. 50% packet loss or'
            ' ble_brownout).\n3. Exercise traffic during active fault and'
            ' observe timeout or retransmit behavior.\n4. Clear faults with'
            ' recipe="clear_all_faults" and verify self-healing recovery.'
        ),
        'thread_border_router_triage': (
            'You are an OpenThread network protocol engineer.\nTriage the'
            ' Thread mesh topology for virtual home "{home_id}".\n\nSteps to'
            ' follow:\n1. Call `cirque_inspect_thread_mesh` to gather ot-ctl'
            ' state, ipaddr, and routes.\n2. Confirm Leader election and verify'
            ' /64 OMR prefix propagation.\n3. Check IPv6 routing between Wi-Fi'
            ' and Thread subnets.'
        ),
        'android_matter_certification': (
            'You are a Matter Automated Certification Engineer.\nValidate'
            ' commissioning on Android emulator "{device_id}" in home'
            ' "{home_id}".\n\nSteps to follow:\n1. Start video evidence'
            ' recording with `cirque_android_ui_and_video`'
            ' action="start_recording".\n2. Execute commissioning sequence.\n3.'
            ' Stop recording and retrieve MP4 video artifact via resource'
            ' `cirque://homes/{home_id}/devices/{device_id}/videos`.'
        ),
    }

    if name not in prompt_templates:
      return {
          'jsonrpc': '2.0',
          'id': req_id,
          'error': {'code': -32602, 'message': f'Prompt not found: {name}'},
      }

    template = prompt_templates[name]
    content = template.format(
        home_id=arguments.get('home_id', '{home_id}'),
        network_type=arguments.get('network_type', 'wifi'),
        chaos_type=arguments.get('chaos_type', 'ble_brownout'),
        device_id=arguments.get('device_id', '{device_id}'),
    )

    return {
        'jsonrpc': '2.0',
        'id': req_id,
        'result': {
            'description': f'MCP prompt template for {name}',
            'messages': [{
                'role': 'user',
                'content': {'type': 'text', 'text': content},
            }],
        },
    }

  # ---------------------------------------------------------------------------
  # Stdio Stream Handling
  # ---------------------------------------------------------------------------

  def handle_stream(self, in_stream=sys.stdin, out_stream=sys.stdout) -> None:
    """Processes newline-delimited JSON-RPC 2.0 requests over stdio."""
    for line in in_stream:
      line = line.strip()
      if not line:
        continue
      try:
        req = json.loads(line)
      except json.JSONDecodeError as exc:
        err_resp = {
            'jsonrpc': '2.0',
            'id': None,
            'error': {'code': -32700, 'message': f'Parse error: {exc}'},
        }
        out_stream.write(json.dumps(err_resp) + '\n')
        out_stream.flush()
        continue

      resp = self.handle_message(req)
      if resp is not None:
        out_stream.write(json.dumps(resp) + '\n')
        out_stream.flush()


def main() -> None:
  import argparse

  parser = argparse.ArgumentParser(description='Cirque Virtual Home MCP Server')
  parser.add_argument(
      '--extension',
      action='append',
      default=[],
      help='Path or module name of Cirque MCP extension to load',
  )
  parser.add_argument(
      '--pcap-dir',
      default=None,
      help='Directory where PCAP capture files are stored',
  )
  args = parser.parse_args()

  logging.basicConfig(level=logging.INFO)
  server = CirqueMcpServer(pcap_dir=args.pcap_dir)
  for ext in args.extension:
    try:
      server.register_extension(ext)
    except Exception as exc:  # pylint: disable=broad-exception-caught
      logger.exception('Failed loading extension %s: %s', ext, exc)
  server.handle_stream()


if __name__ == '__main__':
  main()
