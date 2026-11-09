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
"""Flow-control tests for the SpinelHdlcRfProxy select() relay."""

import fcntl
import os
import select
import socket
import tempfile
import termios
import threading
import time
import unittest

import sys
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
)

from cirque.connectivity.rf_channel_simulator import RfChannelSimulator
from cirque.connectivity.threadsimpipe import (
    SpinelHdlcRfProxy,
    ThreadSimPipe,
    hdlc_decode_frame,
    hdlc_encode_frame,
)


def _recv_until(sock: socket.socket, needle: bytes, timeout: float) -> bool:
  deadline = time.time() + timeout
  buf = bytearray()
  while time.time() < deadline:
    r, _, _ = select.select([sock], [], [], 0.05)
    if r:
      data = sock.recv(65536)
      if not data:
        return False
      buf.extend(data)
      if needle in buf:
        return True
  return False


class SpinelProxyFlowControlTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.tmp = tempfile.TemporaryDirectory()
    sim = RfChannelSimulator(
        seed=3, thread_conf_path=os.path.join(self.tmp.name, 'rf.conf')
    )
    sim.apply_regime_preset('ideal')
    self.proxy = SpinelHdlcRfProxy(node_id=9, simulator=sim)
    # host side: test drives self.host, proxy owns host_end.
    self.host, host_end = socket.socketpair()
    self.rcp, rcp_end = socket.socketpair()
    for s in (self.host, host_end, self.rcp, rcp_end):
      s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
      s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
    self._proxy_socks = (host_end, rcp_end)
    self.proxy.start(host_end.fileno(), rcp_end.fileno())

  def tearDown(self):
    self.proxy.stop()
    for s in (self.host, self.rcp) + self._proxy_socks:
      s.close()
    self.tmp.cleanup()
    super().tearDown()

  def test_stalled_rcp_does_not_block_rcp_to_host_direction(self):
    """Regression: a blocking write toward one peer froze both directions."""
    host_frame = hdlc_encode_frame(bytes([0x81, 0x02, 0x01]) + b'\x00' * 32)

    def flood_host_to_rcp():
      # The RCP side never reads, so this eventually blocks; that is fine.
      try:
        while True:
          self.host.sendall(host_frame * 64)
      except OSError as exc:
        _ = exc

    threading.Thread(target=flood_host_to_rcp, daemon=True).start()
    # Let the host->RCP direction back up completely.
    time.sleep(0.5)

    rcp_body = bytes([0x80, 0x06, 0x02, 0x03, 0x04])
    rcp_frame = hdlc_encode_frame(rcp_body)
    self.rcp.sendall(rcp_frame)
    self.assertTrue(
        _recv_until(self.host, rcp_frame, timeout=3.0),
        'RCP->host frame not relayed while host->RCP was backed up',
    )

  def test_bytes_are_relayed_in_order_after_backlog_drains(self):
    frames = [
        hdlc_encode_frame(bytes([0x81, 0x02, i & 0xFF]) + bytes(40))
        for i in range(400)
    ]
    expected = b''.join(frames)

    def send_all():
      self.host.sendall(expected)

    sender = threading.Thread(target=send_all, daemon=True)
    sender.start()
    got = bytearray()
    deadline = time.time() + 10.0
    while len(got) < len(expected) and time.time() < deadline:
      r, _, _ = select.select([self.rcp], [], [], 0.05)
      if r:
        got.extend(self.rcp.recv(65536))
    sender.join(timeout=2.0)
    self.assertEqual(bytes(got), expected)




class ThreadSimPipeSinglePtyTest(unittest.TestCase):

  def _create_radio_script(self, script_body: str):
    self.temp_dir = tempfile.TemporaryDirectory()
    self.radio_script_path = os.path.join(self.temp_dir.name, 'radio_mock.py')
    repo_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '../..')
    )
    with open(self.radio_script_path, 'w') as f:
      f.write('#!/usr/bin/env python3\n')
      f.write('import os, sys, time, select, threading\n')
      f.write(f'sys.path.insert(0, {repo_root!r})\n')
      f.write('from cirque.connectivity.threadsimpipe \\\n')
      f.write('    import hdlc_encode_frame, hdlc_decode_frame\n')
      f.write(script_body)
    os.chmod(self.radio_script_path, 0o755)

  def test_pty_creation_and_termios(self):
    pipe = ThreadSimPipe(node_id=1, rcp=False)
    pipe.radio_command = 'true'
    pipe.open()
    try:
      self.assertIsNotNone(pipe.radio_fd)
      self.assertIsNotNone(pipe.pipe_path_for_user)
      attrs = termios.tcgetattr(pipe.radio_fd)
      self.assertEqual(attrs[3] & (termios.ECHO | termios.ICANON), 0)
    finally:
      pipe.close()

  def test_1500_frame_bidirectional_stress(self):

    script = '''
host_rx_count = 0
rcp_tx_count = 0

def sender():
  global rcp_tx_count
  while True:
    r, w, _ = select.select([], [1], [], 0.1)
    if 1 in w and rcp_tx_count < 1600:
      frame = bytes([128, 6, 0, 0, 0, 0, 0, 0])
      try:
        os.write(1, hdlc_encode_frame(frame))
        rcp_tx_count += 1
      except OSError as exc:
        _ = exc
    if rcp_tx_count >= 1600 and host_rx_count >= 1600:
      frame = (bytes([128, 6, 0, 0]) +
               host_rx_count.to_bytes(2, "little") +
               bytes([0, 0]))
      try:
        os.write(1, hdlc_encode_frame(frame))
      except OSError as exc:
        _ = exc
      time.sleep(2.0)
      break

threading.Thread(target=sender, daemon=True).start()
buf = bytearray()
while True:
  r, _, _ = select.select([0], [], [], 0.1)
  if r:
    try:
      chunk = os.read(0, 4096)
      if not chunk:
        break
      buf.extend(chunk)
      while b"~" in buf:
        part, buf = buf.split(b"~", 1)
        if not part: continue
        frame = hdlc_decode_frame(part)
        if frame:
          host_rx_count += 1
    except OSError as exc:
      _ = exc
  if host_rx_count >= 1600 and rcp_tx_count >= 1600:
    time.sleep(2.0)
    break
'''
    self._create_radio_script(script)

    pipe = ThreadSimPipe(node_id=1, rcp=True)
    pipe.radio_command = self.radio_script_path
    pipe.open()

    host_fd = os.open(pipe.pipe_path_for_user, os.O_RDWR | os.O_NONBLOCK)

    host_tx_count = 0
    rcp_rx_count = 0
    reported_host_rx_count = 0
    buf = bytearray()

    def host_sender():
      nonlocal host_tx_count
      while host_tx_count < 1600:
        r, w, _ = select.select([], [host_fd], [], 0.1)
        if host_fd not in w:
          continue
        frame = bytes([128, 6, 0, 0, 0, 0, 0, 0])
        try:
          os.write(host_fd, hdlc_encode_frame(frame))
          host_tx_count += 1
        except OSError as exc:
          _ = exc
          time.sleep(0.005)

    t1 = threading.Thread(target=host_sender, daemon=True)
    t1.start()

    while True:
      r, _, _ = select.select([host_fd], [], [], 0.1)
      if host_fd not in r:
        if reported_host_rx_count > 0:
          break
        continue
      try:
        chunk = os.read(host_fd, 4096)
        if not chunk:
          continue
        buf.extend(chunk)
        while b"~" in buf:
          part, buf = buf.split(b"~", 1)
          if not part:
            continue
          frame = hdlc_decode_frame(part)
          if not frame:
            continue
          if frame.startswith(b"\x80\x06\x00\x00") and len(frame) >= 6:
            val = int.from_bytes(frame[4:6], "little")
            if val > 0:
              reported_host_rx_count = val
              break
          rcp_rx_count += 1
      except OSError as exc:
        _ = exc
      if reported_host_rx_count > 0:
        break

    t1.join(timeout=5.0)
    os.close(host_fd)
    pipe.close()
    self.temp_dir.cleanup()

    self.assertGreaterEqual(host_tx_count, 1600)
    self.assertGreaterEqual(rcp_rx_count, 1600)
    self.assertGreaterEqual(reported_host_rx_count, 1600)

  def test_real_kernel_pty_eio_recovery(self):

    script = '''
while True:
  try:
    chunk = os.read(0, 4096)
    if not chunk: break
  except OSError as exc:
    _ = exc
    time.sleep(0.1)
'''
    self._create_radio_script(script)

    pipe = ThreadSimPipe(node_id=1, rcp=True)
    pipe.radio_command = self.radio_script_path
    pipe.open()

    host_fd = os.open(pipe.pipe_path_for_user, os.O_RDWR | os.O_NONBLOCK)
    os.write(host_fd, hdlc_encode_frame(bytes([128, 6, 0, 0, 0, 0, 0, 0])))

    os.close(host_fd)
    time.sleep(0.1)

    host_fd2 = os.open(pipe.pipe_path_for_user, os.O_RDWR | os.O_NONBLOCK)
    os.write(host_fd2, hdlc_encode_frame(bytes([128, 6, 0, 0, 0, 0, 0, 0])))
    os.close(host_fd2)

    pipe.close()
    self.temp_dir.cleanup()

  def test_slave_reopen_reset_and_pending_tids_cleared(self):

    script = '''
while True:
  try:
    chunk = os.read(0, 4096)
    if not chunk: break
  except OSError as exc:
    _ = exc
    time.sleep(0.1)
'''
    self._create_radio_script(script)

    pipe = ThreadSimPipe(node_id=1, rcp=True)
    pipe.radio_command = self.radio_script_path
    pipe.open()

    pipe._spinel_proxy._pending_no_ack_tids.add(3)

    host_fd = os.open(pipe.pipe_path_for_user, os.O_RDWR | os.O_NONBLOCK)
    try:
      fcntl.ioctl(host_fd, termios.TIOCEXCL)
    except OSError as exc:
      _ = exc

    os.write(host_fd, hdlc_encode_frame(bytes([129, 1, 0, 0, 0, 0, 0, 0])))
    time.sleep(0.1)

    self.assertEqual(len(pipe._spinel_proxy._pending_no_ack_tids), 0)

    os.close(host_fd)
    pipe.close()
    self.temp_dir.cleanup()


if __name__ == '__main__':
  unittest.main()
