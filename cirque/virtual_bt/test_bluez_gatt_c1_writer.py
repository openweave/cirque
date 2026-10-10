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
"""Tests that peripheral C1 writes never block the adapter poll thread."""

import os
import select
import threading
import time
import unittest

from cirque.virtual_bt.bluez_gatt_mixin import BluezGattPeripheralMixin


class _FakeAttServer:

  def __init__(self):
    self.cccd_states = {}


class _FakeBridge:

  def __init__(self):
    self.bd_addr = 'AA:BB:CC:DD:EE:02'
    self.connected_handles = {0x0040: 'AA:BB:CC:DD:EE:01'}
    self.att_server = _FakeAttServer()


class _FakeDockerManager:

  def __init__(self):
    self.adapter_bridges = {'hci0': _FakeBridge()}


class _SlowAcquireHarness(BluezGattPeripheralMixin):
  """AcquireWrite takes 0.5 s, like a slow D-Bus round trip."""

  def __init__(self):
    self.docker_manager = _FakeDockerManager()
    self._peripheral_c1_fds = {}
    self._peripheral_c2_fds = {}
    self._c1_written_controllers = set()
    self.read_fd = None

  def _acquire_peripheral_gatt_sockets(self, p_cid, peer_addr):
    time.sleep(0.5)
    r_fd, w_fd = os.pipe()
    self.read_fd = r_fd
    self._peripheral_c1_fds[p_cid] = w_fd

  def _acquire_peripheral_c2_notify(self, p_cid, peer_addr):
    pass


class PeripheralC1WriterTest(unittest.TestCase):

  def test_writes_are_queued_off_thread_and_delivered_in_order(self):
    h = _SlowAcquireHarness()
    try:
      start = time.monotonic()
      for chunk in (b'btp-1;', b'btp-2;', b'btp-3;'):
        h._on_peripheral_c1_write('hci0', chunk)
      # Regression: the first write used to block the caller (the bridge
      # poll thread) for the whole AcquireWrite round trip.
      self.assertLess(time.monotonic() - start, 0.2)

      got = b''
      deadline = time.monotonic() + 3.0
      while len(got) < 18 and time.monotonic() < deadline:
        if h.read_fd is None:
          time.sleep(0.01)
          continue
        r, _, _ = select.select([h.read_fd], [], [], 0.05)
        if r:
          got += os.read(h.read_fd, 64)
      self.assertEqual(got, b'btp-1;btp-2;btp-3;')
      self.assertIn('hci0', h._get_c1_written_set())
    finally:
      h._close_peripheral_fds('hci0')
      if h.read_fd is not None:
        os.close(h.read_fd)

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and any(
        t.name == 'BluezC1Writer-hci0' for t in threading.enumerate()
    ):
      time.sleep(0.01)
    self.assertFalse(
        any(t.name == 'BluezC1Writer-hci0' for t in threading.enumerate())
    )


if __name__ == '__main__':
  unittest.main()
