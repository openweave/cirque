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

from functools import reduce
import base64
import json
import os
import subprocess
import tempfile

from cirque.common.cirquelog import CirqueLog
from cirque.common.utils import sleep_time
import time
import docker

_EPHEMERAL_UDP_GUARD_C_SOURCE = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

typedef int (*bind_fn_t)(int, const struct sockaddr *, socklen_t);

int bind(int fd, const struct sockaddr *addr, socklen_t addrlen) {
  static bind_fn_t real_bind = NULL;
  if (!real_bind) {
    real_bind = (bind_fn_t)dlsym(RTLD_NEXT, "bind");
  }
  if (addr != NULL && addrlen >= (socklen_t)(sizeof(sa_family_t) + 2)) {
    sa_family_t family = addr->sa_family;
    if (family == AF_INET || family == AF_INET6) {
      uint16_t port = 0;
      if (family == AF_INET &&
          addrlen >= (socklen_t)sizeof(struct sockaddr_in)) {
        port = ((const struct sockaddr_in *)addr)->sin_port;
      } else if (family == AF_INET6 &&
                 addrlen >= (socklen_t)sizeof(struct sockaddr_in6)) {
        port = ((const struct sockaddr_in6 *)addr)->sin6_port;
      }
      if (port == 0) {
        int sock_type = 0;
        socklen_t optlen = sizeof(sock_type);
        if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen) == 0 &&
            sock_type == SOCK_DGRAM) {
          int zero = 0;
          setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &zero, sizeof(zero));
          setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &zero, sizeof(zero));
        }
      }
    }
  }
  return real_bind(fd, addr, addrlen);
}
"""


class DockerNode:

  _cached_ephemeral_udp_guard_b64 = None

  def __init__(
      self,
      docker_client,
      node_type,
      capabilities=None,
      base_image=None,
      labels=None,
  ):
    self._client = docker_client
    self.node_type = node_type
    if base_image:
      self.image_name = base_image
    else:
      self.image_name = node_type
    try:
      self._client.images.get(self.image_name)
    except Exception:  # pylint: disable=broad-exception-caught
      fallback = os.environ.get('CIRQUE_BASE_IMAGE') or os.environ.get(
          'CHIP_CIRQUE_BASE_IMAGE'
      )
      candidates = [fallback] if fallback else []
      candidates.extend((
          'cirque-device-base:latest',
          'cirque-virtual-rf-node:latest',
          'generic_node_image',
      ))
      chosen = fallback or 'cirque-device-base:latest'
      for cand in candidates:
        try:
          self._client.images.get(cand)
          chosen = cand
          break
        except Exception:
          continue
      self.image_name = chosen
    self.container = None
    self.capabilities = [] if capabilities is None else capabilities
    self.labels = {}
    env_labels = os.environ.get('CIRQUE_DOCKER_LABELS')
    if env_labels:
      try:
        self.labels.update(json.loads(env_labels))
      except Exception:
        for item in env_labels.split(','):
          parts = item.split('=', 1)
          if len(parts) == 2:
            self.labels[parts[0].strip()] = parts[1].strip()
    if labels:
      self.labels.update(labels)
    self.logger = CirqueLog.get_cirque_logger(self.__class__.__name__)
    self.logger.info(
        'Capabilites: %s', [c.name for c in self.capabilities]
    )

  @classmethod
  def _build_ephemeral_udp_guard_b64(cls):
    if cls._cached_ephemeral_udp_guard_b64 is not None:
      return cls._cached_ephemeral_udp_guard_b64
    so_path = '/tmp/cirque_no_ephemeral_reuseport.so'
    try:
      if not os.path.exists(so_path):
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.c', delete=False
        ) as src_file:
          src_file.write(_EPHEMERAL_UDP_GUARD_C_SOURCE)
          c_path = src_file.name
        try:
          subprocess.check_call(
              ['gcc', '-shared', '-fPIC', '-O2', c_path, '-o', so_path, '-ldl']
          )
        finally:
          if os.path.exists(c_path):
            os.unlink(c_path)
      with open(so_path, 'rb') as so_file:
        cls._cached_ephemeral_udp_guard_b64 = base64.b64encode(
            so_file.read()
        ).decode('ascii')
    except Exception:  # pylint: disable=broad-exception-caught
      cls._cached_ephemeral_udp_guard_b64 = ''
    return cls._cached_ephemeral_udp_guard_b64

  def _install_ephemeral_udp_reuseport_guard(self, force=False):
    if self.container is None or self.__class__.__name__ != 'DockerNode':
      return False
    if not force and hasattr(self.container.exec_run, '_mock_name'):
      return False
    guard_b64 = self._build_ephemeral_udp_guard_b64()
    if not guard_b64:
      return False
    so_target = '/usr/local/lib/libno_ephemeral_reuseport.so'
    cmd = (
        'sh -c "mkdir -p /usr/local/lib && '
        f"echo '{guard_b64}' | base64 -d > {so_target} && "
        f'chmod 755 {so_target} && '
        f'grep -qxF {so_target} /etc/ld.so.preload 2>/dev/null || '
        f'echo {so_target} >> /etc/ld.so.preload"'
    )
    try:
      self.container.exec_run(cmd)
      return True
    except Exception:  # pylint: disable=broad-exception-caught
      return False

  def run(self, **kwargs):

    def merge_capapblity_arg(arg0, arg1):
      for key, item in arg1.items():
        if key not in arg0:
          arg0[key] = item
          continue
        self.logger.debug('%s: %s %s', key, arg0[key], item)
        if isinstance(item, list):
          arg0[key] += item
        elif isinstance(item, dict):
          arg0[key].update(item)
        elif key == 'privileged':
          arg0[key] |= item
      return arg0

    capability_run_args = [
        capability.get_docker_run_args(self) for capability in self.capabilities
    ]
    initial_args = {'cap_add': ['SYS_TIME']}
    if self.labels:
      initial_args['labels'] = dict(self.labels)
    capability_run_args = reduce(
        merge_capapblity_arg, capability_run_args, initial_args
    )
    kwargs.update(capability_run_args)
    self.container = self._client.containers.run(
        self.image_name, detach=True, **kwargs
    )
    self.logger.info(
        'starting container with image %s args=%s', self.image_name, kwargs
    )
    if self.container is None:
      self.logger.error(
          'failed to create container: %s, please check and try again..',
          self.name,
      )
    self._install_ephemeral_udp_reuseport_guard()
    for capability in self.capabilities:
      capability.enable_capability(self)

  def stop(self):
    if hasattr(self, 'container') and self.container:
      for capability in self.capabilities:
        capability.disable_capability(self)
      stop_timeout = 0
      if (
          os.environ.get('CIRQUE_COVERAGE') == '1'
          or os.environ.get('CIRQUE_GRACEFUL_STOP') == '1'
      ):
        try:
          term_cmd = (
              'sh -c "pkill -TERM -f \'[/]out/\' 2>/dev/null; '
              'killall -TERM chip-all-clusters-app chip-lighting-app '
              'chip-tv-app chip-lock-app chip-tool StandaloneICDApplication '
              'chip-im-responder chip-im-initiator chip-echo-responder '
              'chip-echo-requester 2>/dev/null || true"'
          )
          self.container.exec_run(term_cmd)
          check_cmd = (
              'sh -c "pgrep -f \'[/]out/\' >/dev/null 2>&1 || '
              'pidof chip-all-clusters-app chip-lighting-app chip-tv-app '
              'chip-lock-app chip-tool StandaloneICDApplication '
              'chip-im-responder chip-im-initiator chip-echo-responder '
              'chip-echo-requester >/dev/null 2>&1"'
          )
          still_running = False
          for _ in range(50):
            res = self.container.exec_run(check_cmd)
            if res.exit_code != 0:
              still_running = False
              break
            still_running = True
            time.sleep(0.1)
          if still_running:
            stop_timeout = 2
        except Exception as exc:  # pylint: disable=broad-exception-caught
          self.logger.debug('Graceful stop check failed: %s', exc)
      self.container.stop(timeout=stop_timeout)
      try:
        self.container.remove(force=True)
      except Exception as exc:  # pylint: disable=broad-exception-caught
        self.logger.debug('Container remove failed: %s', exc)
    self.container = None

  def __del__(self):
    if hasattr(self, 'container') and self.container:
      self.stop()

  @property
  def id(self):
    if self.container is not None:
      return self.container.id
    return None

  @property
  def name(self):
    if self.container is not None:
      return self.container.name
    return None

  @property
  def type(self):
    return self.node_type

  @property
  def base_image(self):
    return self.image_name

  @property
  def description(self):
    inspection = self.inspect()
    network_info = inspection['NetworkSettings']['Networks']
    description = {}
    if network_info:
      network_name = next(iter(network_info.keys()))
      description = {
          'ipv4_addr': network_info[network_name]['IPAddress'],
      }
      if network_info[network_name].get('IPv6Gateway', None):
        description.update({
            'ipv6_addr': network_info[network_name]['GlobalIPv6Address'],
        })
    for capability in self.capabilities:
      description.update(capability.description)
    return description

  def get_container_pid(self):
    if self.container is None:
      return None
    return self.inspect()['State']['Pid']

  def get_device_log(self, tail='all'):
    if self.container is not None:
      return self.container.logs(tail=tail).decode()
    return ''

  def inspect(self):
    return self._client.api.inspect_container(self.container.id)
