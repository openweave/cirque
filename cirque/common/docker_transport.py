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
"""Shared Docker container transport, D-Bus, and Unix sockets."""

import contextlib
import logging
import os
import selectors
import socket
import threading
import time
from typing import Optional

logger = logging.getLogger(__name__)

# Containers run under arbitrary UIDs, so proxy sockets must be world-writable.
_UNIX_SOCKET_MODE = 0o666
# Single-RPC newline-framed read caps (256 KiB accommodates >500-AP scan JSON).
_RPC_REQUEST_MAX_BYTES = 262144
_RPC_RESPONSE_MAX_BYTES = 262144
_PUMP_CHUNK_BYTES = 65535
# Longest time an open bidirectional stream takes to notice stop().
_PUMP_POLL_INTERVAL_S = 1.0
_ACCEPT_THREAD_JOIN_TIMEOUT_S = 2.0


def _recv_line_or_eof(sock: socket.socket, max_bytes: int) -> bytes:
  """Reads from `sock` until a newline byte, EOF, or `max_bytes` is reached."""
  buf = bytearray()
  while len(buf) < max_bytes:
    chunk = sock.recv(min(_PUMP_CHUNK_BYTES, max_bytes - len(buf)))
    if not chunk:
      break
    buf.extend(chunk)
    if b'\n' in chunk:
      break
  return bytes(buf)


def prepare_container_dbus_dir(dbus_dir: str) -> str:
  """Creates a container's /run/dbus host directory and clears stale files.

  Removes the `pid` file and `system_bus_socket` left behind by a previous
  container so that a new dbus-daemon can start in the same directory.

  Args:
    dbus_dir: Host directory that is bind-mounted as /run/dbus.

  Returns:
    The prepared `dbus_dir` path.
  """
  os.makedirs(dbus_dir, exist_ok=True)
  try:
    os.chmod(dbus_dir, 0o777)
  except OSError:
    pass
  for stale_name in ('pid', 'system_bus_socket'):
    stale_path = os.path.join(dbus_dir, stale_name)
    if os.path.lexists(stale_path):
      try:
        os.unlink(stale_path)
      except OSError:
        pass
  return dbus_dir


def wait_for_socket_file(
    sock_path: str,
    timeout_s: float = 5.0,
    poll_interval_s: float = 0.05,
) -> bool:
  """Polls until a socket file appears on the host filesystem.

  Args:
    sock_path: Path to the expected socket file.
    timeout_s: Maximum seconds to wait.
    poll_interval_s: Interval between poll iterations in seconds.

  Returns:
    True if the socket file exists before the deadline, False otherwise.
  """
  deadline = time.time() + timeout_s
  while time.time() < deadline:
    if os.path.exists(sock_path):
      return True
    time.sleep(poll_interval_s)
  return os.path.exists(sock_path)


def bind_tcp_listener(
    host: str,
    port: int = 0,
    backlog: int = 32,
) -> socket.socket:
  """Creates, binds, and begins listening on an AF_INET TCP stream socket."""
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  try:
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, int(port)))
    sock.listen(backlog)
  except BaseException:
    sock.close()
    raise
  return sock


def prepare_container_dbus_socket(
    container: object,
    sock_path: str,
    stop_wpa: bool = False,
    timeout_s: float = 5.0,
) -> None:
  """Ensures host UID exists in container, waits for socket, and sets perms.

  Args:
    container: Docker container instance with an `exec_run` method.
    sock_path: Host path to the container D-Bus system bus socket.
    stop_wpa: Whether to kill existing wpa_supplicant processes in container.
    timeout_s: Maximum seconds to wait for the host socket file.
  """
  if container is None:
    return
  uid, gid = os.getuid(), os.getgid()
  try:
    exec_run = getattr(container, 'exec_run', None)
    if callable(exec_run):
      exec_run(
          f'sh -c "id -u {uid} >/dev/null 2>&1 || '
          f'echo hostuser:x:{uid}:{gid}:host:/tmp:/bin/sh >> /etc/passwd"'
      )
      if stop_wpa:
        exec_run('killall -9 wpa_supplicant >/dev/null 2>&1 || true')
    wait_for_socket_file(sock_path, timeout_s=timeout_s)
    if callable(exec_run):
      exec_run('chmod 0777 /run/dbus/system_bus_socket')
  except Exception as exc:  # pylint: disable=broad-exception-caught
    logger.debug(
        'Container D-Bus socket setup best-effort step failed: %s', exc
    )


def write_executable_script(
    script_path: str,
    content: str,
    mode: int = 0o755,
) -> str:
  """Writes a script file, ensures parent directories, and applies chmod mode.

  Args:
    script_path: Target path for the executable script.
    content: Script content string to write.
    mode: File permission mode flags (default 0o755).

  Returns:
    The path to the created script.
  """
  parent_dir = os.path.dirname(script_path)
  if parent_dir:
    os.makedirs(parent_dir, exist_ok=True)
  with open(script_path, 'w', encoding='utf-8') as script_file:
    script_file.write(content)
  try:
    os.chmod(script_path, mode)
  except OSError:
    pass
  return script_path


def bind_unix_listener(
    sock_path: str,
    backlog: int = 16,
    chmod_mode: Optional[int] = 0o666,
) -> socket.socket:
  """Creates, binds, and begins listening on an AF_UNIX stream socket.

  Args:
    sock_path: Filesystem path for the Unix domain socket.
    backlog: Maximum number of queued incoming connections.
    chmod_mode: Optional permission bits to apply after socket bind.

  Returns:
    An active listening socket.AF_UNIX socket instance.
  """
  parent_dir = os.path.dirname(sock_path)
  if parent_dir:
    os.makedirs(parent_dir, exist_ok=True)
  if os.path.lexists(sock_path):
    try:
      os.unlink(sock_path)
    except OSError:
      pass
  srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
  try:
    srv.bind(sock_path)
    if chmod_mode is not None:
      try:
        os.chmod(sock_path, chmod_mode)
      except OSError:
        pass
    srv.listen(backlog)
  except BaseException:
    srv.close()
    raise
  return srv


class UnixToTcpProxy:
  """Forwards clients of a Unix domain socket to a TCP endpoint.

  Containers reach the host-side virtual radio servers through Unix sockets
  bind-mounted into them; this class relays those sockets to the servers' TCP
  ports in one of two modes:

  * Single-RPC (default): each client gets one exchange. The proxy reads one
    request, opens a TCP connection, sends the request, reads one response,
    replies, and closes. This matches the `hciconfig` and `iwlist` shims,
    which write one JSON line and read one line back.
  * Bidirectional: each client is paired with its own TCP connection and bytes
    are pumped both ways until either side closes or `stop()` is called. The
    Wi-Fi `vwifi_l2_agent.py` data plane uses this mode.
  """

  def __init__(
      self,
      sock_path: str,
      host: str,
      port: int,
      *,
      bidirectional: bool = False,
      backlog: int = 16,
      connect_timeout_s: float = 5.0,
      io_timeout_s: float = 5.0,
      name: str = 'unix-tcp-proxy',
  ) -> None:
    """Initializes the proxy; `start()` begins accepting clients.

    Args:
      sock_path: Filesystem path of the listening Unix domain socket.
      host: Host of the TCP endpoint.
      port: Port of the TCP endpoint.
      bidirectional: Whether to pump a persistent stream instead of relaying one
        request and one response per client.
      backlog: Listen backlog of the Unix domain socket.
      connect_timeout_s: Timeout in seconds for each TCP connect.
      io_timeout_s: Timeout in seconds for each blocking read or write after
        connecting. Idle bidirectional streams stay open because they are only
        read after the selector reports data.
      name: Name of the accept thread; client threads append `-client`.
    """
    self.sock_path = sock_path
    self._host = host
    self._port = port
    self._bidirectional = bidirectional
    self._backlog = backlog
    self._connect_timeout_s = connect_timeout_s
    self._io_timeout_s = io_timeout_s
    self._name = name
    self._running = threading.Event()
    self._listener: Optional[socket.socket] = None
    self._accept_thread: Optional[threading.Thread] = None

  def start(self) -> None:
    """Binds `sock_path` with mode 0o666 and starts the accept thread."""
    if self._listener is not None:
      raise RuntimeError('UnixToTcpProxy is already running')
    self._listener = bind_unix_listener(
        self.sock_path, backlog=self._backlog, chmod_mode=_UNIX_SOCKET_MODE
    )
    self._running.set()
    self._accept_thread = threading.Thread(
        target=self._accept_loop,
        args=(self._listener,),
        name=self._name,
        daemon=True,
    )
    self._accept_thread.start()

  def stop(self) -> None:
    """Stops accepting, removes `sock_path`, and joins the accept thread.

    Idempotent: calling it again, or before `start()`, has no effect.
    """
    self._running.clear()
    listener, self._listener = self._listener, None
    if listener is None:
      return
    # close() alone does not wake a thread blocked in accept() on Linux;
    # shutdown() does. Some platforms reject it for listening sockets.
    with contextlib.suppress(OSError):
      listener.shutdown(socket.SHUT_RDWR)
    listener.close()
    # The socket file may already be gone, e.g. removed by hand.
    with contextlib.suppress(OSError):
      os.unlink(self.sock_path)
    if self._accept_thread is not None:
      self._accept_thread.join(timeout=_ACCEPT_THREAD_JOIN_TIMEOUT_S)
      self._accept_thread = None

  def _accept_loop(self, listener: socket.socket) -> None:
    while self._running.is_set():
      try:
        client_sock, _ = listener.accept()
      except OSError:
        return  # stop() shut the listener down.
      threading.Thread(
          target=self._serve_client,
          args=(client_sock,),
          name=f'{self._name}-client',
          daemon=True,
      ).start()

  def _serve_client(self, client_sock: socket.socket) -> None:
    # A peer that disconnects or times out, or an unreachable TCP endpoint,
    # only ends this client's session.
    with client_sock, contextlib.suppress(OSError):
      client_sock.settimeout(self._io_timeout_s)
      if self._bidirectional:
        self._pump_stream(client_sock)
      else:
        self._forward_single_rpc(client_sock)

  def _connect_tcp(self) -> socket.socket:
    tcp_sock = socket.create_connection(
        (self._host, self._port), timeout=self._connect_timeout_s
    )
    tcp_sock.settimeout(self._io_timeout_s)
    return tcp_sock

  def _forward_single_rpc(self, client_sock: socket.socket) -> None:
    request = _recv_line_or_eof(client_sock, _RPC_REQUEST_MAX_BYTES)
    if not request:
      return
    with self._connect_tcp() as tcp_sock:
      tcp_sock.sendall(request)
      response = _recv_line_or_eof(tcp_sock, _RPC_RESPONSE_MAX_BYTES)
    if response:
      client_sock.sendall(response)

  @staticmethod
  def _forward_ready_keys(selector: selectors.BaseSelector) -> bool:
    """Forwards ready socket chunks; returns False when a peer closes."""
    for key, _ in selector.select(timeout=_PUMP_POLL_INTERVAL_S):
      chunk = key.fileobj.recv(_PUMP_CHUNK_BYTES)
      if not chunk:
        return False
      key.data.sendall(chunk)
    return True

  def _pump_stream(self, client_sock: socket.socket) -> None:
    with (
        self._connect_tcp() as tcp_sock,
        selectors.DefaultSelector() as selector,
    ):
      selector.register(client_sock, selectors.EVENT_READ, tcp_sock)
      selector.register(tcp_sock, selectors.EVENT_READ, client_sock)
      while self._running.is_set():
        if not self._forward_ready_keys(selector):
          return
