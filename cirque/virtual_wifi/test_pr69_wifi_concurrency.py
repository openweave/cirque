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
"""Unit tests verifying cirque PR69 defect fixes for Virtual WiFi concurrency.

Verifies:
1. VirtualWiFiServer serializes peer_sock.sendall per socket (per-socket write lock)
   and invokes PcapWriter.write_frame outside self._lock.
2. VirtualRaServer._send_ra serializes sendall using a dedicated send lock.
"""

import socket
import struct
import threading
import time
import unittest

from cirque.virtual_wifi.docker_wifi_bridge import VirtualRaServer
from cirque.virtual_wifi.server import VirtualWiFiServer


class ChunkedSocket:
  """Socket wrapper whose sendall() emits one byte at a time and yields.

  This reproduces what the kernel does when a TCP send buffer is full:
  sendall() makes several partial send() calls and releases the GIL between
  them, so two unsynchronized writers interleave their bytes on the stream.
  """

  def __init__(self, sock: socket.socket):
    self._sock = sock

  def sendall(self, data: bytes) -> None:
    for i in range(len(data)):
      self._sock.send(data[i:i + 1])
      time.sleep(0)

  def close(self) -> None:
    self._sock.close()


def _read_frames(sock_rx: socket.socket, count: int):
  """Reads `count` 2-byte length-prefixed frames, returning their bodies."""
  sock_rx.settimeout(10.0)
  frames = []
  for _ in range(count):
    hdr = b''
    while len(hdr) < 2:
      chunk = sock_rx.recv(2 - len(hdr))
      if not chunk:
        return frames
      hdr += chunk
    flen = struct.unpack('!H', hdr)[0]
    body = b''
    while len(body) < flen:
      chunk = sock_rx.recv(flen - len(body))
      if not chunk:
        return frames
      body += chunk
    frames.append(body)
  return frames


def _run_with_reader(sock_rx: socket.socket, count: int, writers):
  """Runs writer threads while a reader drains the stream concurrently.

  One-byte sends consume far more socket buffer than their payload, so the
  stream must be drained while the writers run or they block forever.
  """
  result = {}
  reader = threading.Thread(
      target=lambda: result.setdefault('frames', _read_frames(sock_rx, count)))
  reader.start()
  for t in writers:
    t.start()
  for t in writers:
    t.join(timeout=60)
  reader.join(timeout=60)
  return result.get('frames', [])


class TestPartialSendInterleaving(unittest.TestCase):
  """Behavioral race tests: concurrent writers with partial sends."""

  def test_relay_frames_not_interleaved_under_partial_sends(self):
    server = VirtualWiFiServer(host='127.0.0.1')
    sock_tx, sock_rx = socket.socketpair()
    try:
      dst = server.register_station('sta_rx')
      dst.state = 'completed'
      server._data_clients['sta_rx'] = ChunkedSocket(sock_tx)
      num_threads, per_thread, payload_len = 4, 10, 32

      def worker(worker_id: int):
        src_id = f'sta_tx_{worker_id}'
        st = server.register_station(src_id)
        st.state = 'completed'
        frame = (bytes.fromhex('020000000199') + bytes.fromhex('020000000101')
                 + b'\x08\x00' + bytes([worker_id + 1]) * payload_len)
        for _ in range(per_thread):
          server._relay_l2_frame(src_id, frame)

      threads = [threading.Thread(target=worker, args=(i,))
                 for i in range(num_threads)]
      frames = _run_with_reader(sock_rx, num_threads * per_thread, threads)
      self.assertEqual(len(frames), num_threads * per_thread)
      for body in frames:
        payload = body[14:]
        self.assertEqual(len(payload), payload_len)
        self.assertEqual(len(set(payload)), 1,
                         'frame bytes from different writers interleaved')
    finally:
      server.stop()
      sock_tx.close()
      sock_rx.close()

  def test_send_ra_not_interleaved_under_partial_sends(self):
    ra_server = VirtualRaServer('127.0.0.1', 12345)
    sock_tx, sock_rx = socket.socketpair()
    try:
      ra_server._sock = ChunkedSocket(sock_tx)
      ra_server._running = True
      expected = ra_server.build_ra_packet()
      num_threads, per_thread = 4, 5

      def worker():
        for _ in range(per_thread):
          ra_server._send_ra()

      threads = [threading.Thread(target=worker) for _ in range(num_threads)]
      frames = _run_with_reader(sock_rx, num_threads * per_thread, threads)
      self.assertEqual(len(frames), num_threads * per_thread)
      for body in frames:
        self.assertEqual(body, expected, 'RA frames interleaved on the stream')
    finally:
      sock_tx.close()
      sock_rx.close()


class TestVirtualWiFiPcapAndSocketLock(unittest.TestCase):
  """Tests for defect 1: PcapWriter outside self._lock and per-socket write lock."""

  def setUp(self):
    super().setUp()
    self.server = VirtualWiFiServer(host='127.0.0.1')

  def tearDown(self):
    self.server.stop()
    super().tearDown()

  def test_pcap_write_frame_called_outside_server_lock(self):
    """Verifies PcapWriter.write_frame is invoked without holding self._lock."""
    lock_held_during_write = []

    class InspectingPcapWriter:
      def __init__(self, srv):
        self._srv = srv
        self.frames = []

      def write_frame(self, frame, ts=None):
        # In Python RLock, _is_owned() reveals if the current thread holds the lock.
        lock_held_during_write.append(self._srv._lock._is_owned())
        self.frames.append(frame)

      def close(self):
        pass

    writer = InspectingPcapWriter(self.server)
    self.server._pcap_medium_writer = writer

    # Set up station states so frame is delivered
    src_sta = self.server.register_station('sta_src')
    dst_sta = self.server.register_station('sta_dst')
    src_sta.state = 'completed'
    dst_sta.state = 'completed'

    sock1, sock2 = socket.socketpair()
    try:
      self.server._data_clients['sta_dst'] = sock1
      test_frame = (
          bytes.fromhex('020000000102')  # dst mac
          + bytes.fromhex('020000000101')  # src mac
          + b'\x08\x00'  # ethertype IPv4
          + b'A' * 40
      )
      self.server._relay_l2_frame('sta_src', test_frame)

      self.assertGreaterEqual(len(lock_held_during_write), 1)
      for was_held in lock_held_during_write:
        self.assertFalse(
            was_held,
            'PcapWriter.write_frame must be invoked outside self._lock!',
        )
    finally:
      sock1.close()
      sock2.close()

  def test_concurrent_send_data_frame_serialized_per_socket(self):
    """Verifies concurrent sends to the same peer socket are serialized."""
    dst_sta = self.server.register_station('sta_rx')
    dst_sta.state = 'completed'

    sock_tx, sock_rx = socket.socketpair()
    self.server._data_clients['sta_rx'] = sock_tx

    num_threads = 4
    frames_per_thread = 25
    payload_len = 100

    def worker(worker_id: int):
      src_id = f'sta_tx_{worker_id}'
      st = self.server.register_station(src_id)
      st.state = 'completed'
      for _ in range(frames_per_thread):
        frame = (
            bytes.fromhex('020000000199')
            + bytes.fromhex('020000000101')
            + b'\x08\x00'
            + bytes([worker_id]) * payload_len
        )
        self.server._relay_l2_frame(src_id, frame)

    threads = [
        threading.Thread(target=worker, args=(i,)) for i in range(num_threads)
    ]
    for t in threads:
      t.start()
    for t in threads:
      t.join()

    # Read all frames from sock_rx and verify framing integrity
    sock_rx.settimeout(2.0)
    total_expected = num_threads * frames_per_thread
    received_count = 0
    while received_count < total_expected:
      hdr = sock_rx.recv(2)
      if not hdr:
        break
      flen = struct.unpack('!H', hdr)[0]
      body = b''
      while len(body) < flen:
        chunk = sock_rx.recv(flen - len(body))
        if not chunk:
          break
        body += chunk
      self.assertEqual(len(body), flen)
      received_count += 1

    self.assertEqual(received_count, total_expected)
    sock_tx.close()
    sock_rx.close()


class TestVirtualRaServerSendLock(unittest.TestCase):
  """Tests for defect 2: VirtualRaServer._send_ra send lock serialization."""

  def test_virtual_ra_server_has_send_lock(self):
    ra_server = VirtualRaServer('127.0.0.1', 12345)
    self.assertTrue(hasattr(ra_server, '_send_lock'))
    self.assertIsInstance(ra_server._send_lock, type(threading.Lock()))

  def test_concurrent_send_ra_integrity(self):
    """Verifies concurrent _send_ra calls over a real socket produce uncorrupted framing."""
    ra_server = VirtualRaServer('127.0.0.1', 12345)
    sock_tx, sock_rx = socket.socketpair()
    ra_server._sock = sock_tx
    ra_server._running = True

    num_threads = 5
    calls_per_thread = 20

    def worker():
      for _ in range(calls_per_thread):
        ra_server._send_ra()

    threads = [threading.Thread(target=worker) for _ in range(num_threads)]
    for t in threads:
      t.start()
    for t in threads:
      t.join()

    sock_rx.settimeout(2.0)
    total_expected = num_threads * calls_per_thread
    received_count = 0
    while received_count < total_expected:
      hdr = sock_rx.recv(2)
      if not hdr:
        break
      flen = struct.unpack('!H', hdr)[0]
      body = b''
      while len(body) < flen:
        chunk = sock_rx.recv(flen - len(body))
        if not chunk:
          break
        body += chunk
      self.assertEqual(len(body), flen)
      # RA packet starts with dst_mac (6B) + src_mac (6B) + IPv6 Ethertype (0x86DD)
      self.assertEqual(body[12:14], b'\x86\xdd')
      received_count += 1

    self.assertEqual(received_count, total_expected)
    self.assertEqual(ra_server.advertised_count, total_expected)
    sock_tx.close()
    sock_rx.close()


if __name__ == '__main__':
  unittest.main()
