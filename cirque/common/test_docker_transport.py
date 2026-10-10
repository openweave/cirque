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
"""Unit tests for cirque.common.docker_transport."""

import contextlib
import os
import shutil
import socket
import stat
import tempfile
import threading
import time
from typing import Callable
import unittest

from cirque.common import docker_transport

_LOOPBACK = '127.0.0.1'
# Upper bound on every blocking test-side socket call, so a regression fails
# the test instead of hanging it.
_CLIENT_TIMEOUT_S = 3.0


def _recv_until_eof(sock: socket.socket) -> bytes:
  """Reads from `sock` until the peer closes the connection."""
  chunks = []
  while True:
    chunk = sock.recv(4096)
    if not chunk:
      return b''.join(chunks)
    chunks.append(chunk)


def _recv_exactly(sock: socket.socket, num_bytes: int) -> bytes:
  """Reads exactly `num_bytes` from `sock`."""
  buf = bytearray()
  while len(buf) < num_bytes:
    chunk = sock.recv(num_bytes - len(buf))
    if not chunk:
      raise ConnectionError(f'EOF after {len(buf)} of {num_bytes} bytes')
    buf.extend(chunk)
  return bytes(buf)


def _thread_alive(name: str) -> bool:
  return any(thread.name == name for thread in threading.enumerate())


def _wait_for_threads_to_exit(name: str, timeout_s: float = 2.0) -> bool:
  """Returns whether every thread called `name` exits within `timeout_s`."""
  deadline = time.monotonic() + timeout_s
  while _thread_alive(name):
    if time.monotonic() >= deadline:
      return False
    time.sleep(0.02)
  return True


def _reply_once(conn: socket.socket) -> None:
  """Answers a single request with `b'reply:' + request`."""
  request = conn.recv(4096)
  conn.sendall(b'reply:' + request)


def _echo_until_eof(conn: socket.socket) -> None:
  while True:
    data = conn.recv(4096)
    if not data:
      return
    conn.sendall(data)


class _LoopbackTcpServer:
  """TCP server on 127.0.0.1 that runs `handler(conn)` for each client."""

  def __init__(self, handler: Callable[[socket.socket], None]) -> None:
    self._handler = handler
    self._listener = socket.create_server((_LOOPBACK, 0))
    self.port = self._listener.getsockname()[1]
    self._thread = threading.Thread(target=self._accept_loop, daemon=True)
    self._thread.start()

  def _accept_loop(self) -> None:
    while True:
      try:
        conn, _ = self._listener.accept()
      except OSError:
        return  # close() shut the listener down.
      threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

  def _serve(self, conn: socket.socket) -> None:
    # The proxy may drop the connection at any point; that ends the session.
    with conn, contextlib.suppress(OSError):
      conn.settimeout(_CLIENT_TIMEOUT_S)
      self._handler(conn)

  def close(self) -> None:
    # shutdown() wakes the blocked accept(); some platforms reject it.
    with contextlib.suppress(OSError):
      self._listener.shutdown(socket.SHUT_RDWR)
    self._listener.close()
    self._thread.join(timeout=2.0)


class TestDockerTransport(unittest.TestCase):
  """Tests the docker_transport helper functions."""

  def setUp(self):
    super().setUp()
    self.temp_dir = tempfile.mkdtemp(prefix='cirque_transport_test_')
    self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)

  def test_prepare_container_dbus_dir_creates_dir_and_clears_stale_files(self):
    """Verifies the directory is world-writable and stale files are gone."""
    dbus_dir = os.path.join(self.temp_dir, 'containers', 'node_alpha', 'dbus')
    self.assertEqual(
        docker_transport.prepare_container_dbus_dir(dbus_dir), dbus_dir
    )
    self.assertTrue(os.path.isdir(dbus_dir))
    self.assertEqual(stat.S_IMODE(os.stat(dbus_dir).st_mode), 0o777)

    pid_file = os.path.join(dbus_dir, 'pid')
    with open(pid_file, 'w', encoding='utf-8') as f:
      f.write('1234')
    # os.path.exists() is False for a dangling symlink; it must still go.
    bus_socket = os.path.join(dbus_dir, 'system_bus_socket')
    os.symlink(os.path.join(self.temp_dir, 'gone'), bus_socket)

    self.assertEqual(
        docker_transport.prepare_container_dbus_dir(dbus_dir), dbus_dir
    )
    self.assertFalse(os.path.lexists(pid_file))
    self.assertFalse(os.path.lexists(bus_socket))

  def test_prepare_container_dbus_dir_tolerates_undeletable_entries(self):
    """Verifies one entry that cannot be unlinked does not stop the rest."""
    dbus_dir = os.path.join(self.temp_dir, 'dbus')
    stale_pid_dir = os.path.join(dbus_dir, 'pid')  # unlink() fails on a dir.
    os.makedirs(stale_pid_dir)
    bus_socket = os.path.join(dbus_dir, 'system_bus_socket')
    with open(bus_socket, 'w', encoding='utf-8') as f:
      f.write('stale')

    self.assertEqual(
        docker_transport.prepare_container_dbus_dir(dbus_dir), dbus_dir
    )
    self.assertTrue(os.path.isdir(stale_pid_dir))
    self.assertFalse(os.path.lexists(bus_socket))

  def test_write_executable_script(self):
    """Verifies the script content, parent directory, and exec bits."""
    script_path = os.path.join(self.temp_dir, 'bin', 'test_script.sh')
    content = '#!/bin/sh\necho "hello cirque"\n'
    ret = docker_transport.write_executable_script(script_path, content)
    self.assertEqual(ret, script_path)
    self.assertTrue(os.path.exists(script_path))
    with open(script_path, 'r', encoding='utf-8') as f:
      self.assertEqual(f.read(), content)
    mode = os.stat(script_path).st_mode
    self.assertTrue(bool(mode & 0o111))

  def test_wait_for_socket_file(self):
    """Verifies the poll times out for a missing path and finds a new one."""
    fake_sock = os.path.join(self.temp_dir, 'test.sock')
    self.assertFalse(
        docker_transport.wait_for_socket_file(
            fake_sock, timeout_s=0.1, poll_interval_s=0.02
        )
    )
    with open(fake_sock, 'w', encoding='utf-8') as f:
      f.write('')
    self.assertTrue(
        docker_transport.wait_for_socket_file(
            fake_sock, timeout_s=0.2, poll_interval_s=0.02
        )
    )

  def test_bind_unix_listener(self):
    """Verifies the listener accepts clients and is world-writable."""
    sock_path = os.path.join(self.temp_dir, 'sock_dir', 'unix_test.sock')
    with docker_transport.bind_unix_listener(sock_path, backlog=4) as srv:
      self.assertEqual(stat.S_IMODE(os.stat(sock_path).st_mode), 0o666)
      with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(sock_path)
        conn, _ = srv.accept()
        with conn:
          client.sendall(b'ping')
          self.assertEqual(conn.recv(4), b'ping')

  def test_bind_unix_listener_replaces_dangling_symlink(self):
    """Verifies a dangling symlink at sock_path is unlinked before bind()."""
    sock_path = os.path.join(self.temp_dir, 'dangling.sock')
    os.symlink(os.path.join(self.temp_dir, 'missing_target'), sock_path)
    self.assertTrue(os.path.lexists(sock_path))
    self.assertFalse(os.path.exists(sock_path))
    with docker_transport.bind_unix_listener(sock_path, backlog=4) as srv:
      with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(sock_path)
        conn, _ = srv.accept()
        with conn:
          client.sendall(b'ok')
          self.assertEqual(conn.recv(2), b'ok')

  def test_bind_unix_listener_closes_socket_on_bind_failure(self):
    """Verifies bind() failure closes the socket without leaking an fd."""
    import gc

    too_long_path = os.path.join(self.temp_dir, 'x' * 120 + '.sock')
    fds_before = len(os.listdir('/proc/self/fd'))
    with self.assertRaises(OSError):
      docker_transport.bind_unix_listener(too_long_path)
    gc.collect()
    fds_after = len(os.listdir('/proc/self/fd'))
    self.assertEqual(fds_before, fds_after)

  def test_managers_clean_up_control_proxy_on_partial_init_failure(self):
    """Verifies Wi-Fi and BT managers stop _control_proxy if init fails."""
    from cirque.virtual_bt.docker_hci_bridge import DockerVirtualBtManager
    from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager
    from cirque.virtual_wifi.server import VirtualWiFiServer

    wifi_rt = os.path.join(self.temp_dir, 'wifi_rt')
    os.makedirs(os.path.join(wifi_rt, 'data.sock'))
    server = VirtualWiFiServer(host=_LOOPBACK)
    server.start()
    self.addCleanup(server.stop)
    with self.assertRaises(OSError):
      DockerVirtualWiFiManager(server, runtime_dir=wifi_rt)
    self.assertFalse(os.path.exists(os.path.join(wifi_rt, 'control.sock')))
    self.assertTrue(_wait_for_threads_to_exit('vwifi-unix-ctrl'))

    bt_rt = os.path.join(self.temp_dir, 'bt_rt')
    os.makedirs(os.path.join(bt_rt, 'bin', 'hciconfig'))
    with self.assertRaises(OSError):
      DockerVirtualBtManager(_LOOPBACK, 1, 2, 3, runtime_dir=bt_rt)
    self.assertFalse(os.path.exists(os.path.join(bt_rt, 'control.sock')))
    self.assertTrue(_wait_for_threads_to_exit('virtual-bt-unix-proxy'))

  def test_prepare_container_dbus_socket(self):
    """Verifies the UID, wpa_supplicant, and chmod commands are issued."""

    class FakeContainer:

      def __init__(self):
        self.commands = []

      def exec_run(self, cmd):
        self.commands.append(cmd)
        return (0, b'')

    fake_container = FakeContainer()
    sock_path = os.path.join(self.temp_dir, 'test_dbus.sock')
    with open(sock_path, 'w', encoding='utf-8') as f:
      f.write('')

    docker_transport.prepare_container_dbus_socket(
        fake_container, sock_path, stop_wpa=True, timeout_s=0.2
    )
    self.assertGreater(len(fake_container.commands), 1)
    self.assertTrue(
        any('killall -9 wpa_supplicant' in c for c in fake_container.commands)
    )
    self.assertTrue(
        any(
            'chmod 0777 /run/dbus/system_bus_socket' in c
            for c in fake_container.commands
        )
    )

    # Verify None container handles cleanly without error
    docker_transport.prepare_container_dbus_socket(None, sock_path)

  def test_prepare_container_dbus_socket_ignores_exec_failures(self):
    """Verifies a container that cannot run commands does not raise."""

    class BrokenContainer:

      def exec_run(self, cmd):
        raise RuntimeError(f'exec failed: {cmd}')

    docker_transport.prepare_container_dbus_socket(
        BrokenContainer(), os.path.join(self.temp_dir, 'none.sock')
    )


class TestUnixToTcpProxy(unittest.TestCase):
  """Tests UnixToTcpProxy over real Unix and loopback TCP sockets."""

  def setUp(self):
    super().setUp()
    self.temp_dir = tempfile.mkdtemp(prefix='cirque_proxy_test_')
    self.addCleanup(shutil.rmtree, self.temp_dir, ignore_errors=True)
    # Unique per test so thread checks never see another test's threads.
    self.proxy_name = f'proxy-{self._testMethodName}'

  def _start_tcp_server(
      self, handler: Callable[[socket.socket], None]
  ) -> _LoopbackTcpServer:
    server = _LoopbackTcpServer(handler)
    self.addCleanup(server.close)
    return server

  def _new_proxy(
      self, port: int, **kwargs: object
  ) -> docker_transport.UnixToTcpProxy:
    return docker_transport.UnixToTcpProxy(
        os.path.join(self.temp_dir, 'proxy.sock'),
        _LOOPBACK,
        port,
        name=self.proxy_name,
        **kwargs,
    )

  def _start_proxy(
      self, port: int, **kwargs: object
  ) -> docker_transport.UnixToTcpProxy:
    proxy = self._new_proxy(port, **kwargs)
    proxy.start()
    self.addCleanup(proxy.stop)
    return proxy

  def _connect(self, proxy: docker_transport.UnixToTcpProxy) -> socket.socket:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.addCleanup(client.close)
    client.settimeout(_CLIENT_TIMEOUT_S)
    client.connect(proxy.sock_path)
    return client

  def test_single_rpc_round_trip(self):
    """Verifies one request and one response are relayed, then EOF."""
    server = self._start_tcp_server(_reply_once)
    proxy = self._start_proxy(server.port)
    self.assertEqual(stat.S_IMODE(os.stat(proxy.sock_path).st_mode), 0o666)

    client = self._connect(proxy)
    client.sendall(b'{"cmd": "list_aps"}\n')
    self.assertEqual(_recv_until_eof(client), b'reply:{"cmd": "list_aps"}\n')

  def test_single_rpc_reassembles_multi_chunk_large_request_and_response(self):
    """Verifies single-RPC reassembles >64 KiB multi-chunk lines both ways."""
    payload_body = b'A' * (150 * 1024)
    request_line = b'{"req":"' + payload_body + b'"}\n'
    response_line = b'{"rsp":"' + payload_body + b'"}\n'

    def chunked_handler(conn: socket.socket) -> None:
      rx = bytearray()
      while b'\n' not in rx:
        chunk = conn.recv(65535)
        if not chunk:
          break
        rx.extend(chunk)
      if bytes(rx) == request_line:
        step = 50000
        for offset in range(0, len(response_line), step):
          conn.sendall(response_line[offset : offset + step])
          time.sleep(0.01)

    server = self._start_tcp_server(chunked_handler)
    proxy = self._start_proxy(server.port)
    client = self._connect(proxy)
    step = 50000
    for offset in range(0, len(request_line), step):
      client.sendall(request_line[offset : offset + step])
      time.sleep(0.01)
    received = _recv_until_eof(client)
    self.assertEqual(len(received), len(response_line))
    self.assertEqual(received, response_line)

  def test_start_twice_raises_runtime_error_and_restart_after_stop_works(self):
    """Verifies calling start() twice raises while first listener stays live."""
    server = self._start_tcp_server(_reply_once)
    proxy = self._start_proxy(server.port)
    with self.assertRaises(RuntimeError):
      proxy.start()

    client1 = self._connect(proxy)
    client1.sendall(b'first\n')
    self.assertEqual(_recv_until_eof(client1), b'reply:first\n')

    proxy.stop()
    proxy.start()
    client2 = self._connect(proxy)
    client2.sendall(b'second\n')
    self.assertEqual(_recv_until_eof(client2), b'reply:second\n')

  def test_bidirectional_stream_relays_messages_both_ways(self):
    """Verifies a persistent stream relays several messages each way."""
    server = self._start_tcp_server(_echo_until_eof)
    proxy = self._start_proxy(server.port, bidirectional=True)

    client = self._connect(proxy)
    for message in (b'frame-1', b'frame-2' * 1000, b'frame-3'):
      client.sendall(message)
      self.assertEqual(_recv_exactly(client, len(message)), message)

  def test_stop_removes_socket_and_joins_accept_thread(self):
    """Verifies stop() is idempotent and leaves nothing behind."""
    proxy = self._new_proxy(port=1)
    proxy.stop()  # Stopping a proxy that never started is a no-op.
    proxy.start()
    self.assertTrue(os.path.exists(proxy.sock_path))
    self.assertTrue(_thread_alive(self.proxy_name))

    proxy.stop()
    self.assertFalse(os.path.exists(proxy.sock_path))
    self.assertFalse(_thread_alive(self.proxy_name))
    proxy.stop()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
      with self.assertRaises(OSError):
        client.connect(proxy.sock_path)

  def test_silent_tcp_server_times_out_without_leaking_threads(self):
    """Verifies an endpoint that never answers ends after io_timeout_s."""
    silent = socket.create_server((_LOOPBACK, 0))  # Never calls accept().
    self.addCleanup(silent.close)
    proxy = self._start_proxy(silent.getsockname()[1], io_timeout_s=0.5)

    client = self._connect(proxy)
    started = time.monotonic()
    client.sendall(b'request\n')
    self.assertEqual(_recv_until_eof(client), b'')
    elapsed = time.monotonic() - started
    self.assertGreaterEqual(elapsed, 0.4)
    self.assertLess(elapsed, 2.5)
    self.assertTrue(_wait_for_threads_to_exit(f'{self.proxy_name}-client'))

  def test_unreachable_endpoint_closes_client(self):
    """Verifies a refused TCP connection closes the Unix client."""
    with socket.create_server((_LOOPBACK, 0)) as probe:
      closed_port = probe.getsockname()[1]
    proxy = self._start_proxy(closed_port)

    client = self._connect(proxy)
    client.sendall(b'request\n')
    self.assertEqual(_recv_until_eof(client), b'')

  def test_client_that_sends_nothing_gets_eof(self):
    """Verifies an empty request is closed without a TCP round trip."""
    server = self._start_tcp_server(_reply_once)
    proxy = self._start_proxy(server.port)

    client = self._connect(proxy)
    client.shutdown(socket.SHUT_WR)
    self.assertEqual(_recv_until_eof(client), b'')

  def test_stop_ends_open_bidirectional_stream(self):
    """Verifies stop() closes a live stream within the pump poll interval."""
    server = self._start_tcp_server(_echo_until_eof)
    proxy = self._start_proxy(server.port, bidirectional=True)
    client = self._connect(proxy)
    client.sendall(b'hello')
    self.assertEqual(_recv_exactly(client, 5), b'hello')

    started = time.monotonic()
    proxy.stop()
    self.assertEqual(_recv_until_eof(client), b'')
    self.assertLess(time.monotonic() - started, 2.5)

  def test_bind_tcp_listener_success_and_failure(self):
    """Verifies bind_tcp_listener binds cleanly and closes on failure."""
    listener = docker_transport.bind_tcp_listener(_LOOPBACK, 0, backlog=16)
    try:
      port = listener.getsockname()[1]
      self.assertGreater(port, 0)
      self.assertEqual(listener.getsockname()[0], _LOOPBACK)
    finally:
      listener.close()

    # Invalid port raises OSError or OverflowError and closes socket
    # without ResourceWarning.
    with self.assertRaises((OSError, OverflowError)):
      docker_transport.bind_tcp_listener(_LOOPBACK, -1)


  def test_chmod_failure_paths_tolerated(self):
    """Verifies chmod OSError is tolerated across docker_transport utilities."""
    from unittest import mock

    dbus_dir = os.path.join(self.temp_dir, 'chmod_dbus')
    script_path = os.path.join(self.temp_dir, 'chmod_script.sh')
    sock_path = os.path.join(self.temp_dir, 'chmod_sock.sock')

    with mock.patch('os.chmod', side_effect=OSError('Permission denied')):
      # 1. prepare_container_dbus_dir lines 63-64
      self.assertEqual(
          docker_transport.prepare_container_dbus_dir(dbus_dir), dbus_dir
      )

      # 2. write_executable_script lines 170-171
      self.assertEqual(
          docker_transport.write_executable_script(script_path, '#!/bin/sh\n'),
          script_path,
      )

      # 3. bind_unix_listener lines 204-205
      with docker_transport.bind_unix_listener(
          sock_path, chmod_mode=0o666
      ) as srv:
        self.assertIsNotNone(srv)



if __name__ == '__main__':
  unittest.main()

