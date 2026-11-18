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
"""ATT request serialization tests for VirtualBluezAdapterBridge.

An ATT client may have only one request outstanding per bearer (Core Spec
Vol 3, Part F, 3.3.2), and after a transaction timeout no further requests
may be sent on that bearer (3.3.3).
"""

import collections
import struct
import threading
import time
import unittest

from cirque.virtual_bt.adapter_bridge import ATT_CID, VirtualBluezAdapterBridge
from cirque.virtual_bt.att_db import (
    ATT_OP_READ_REQ,
    ATT_OP_READ_RSP,
    ATT_OP_WRITE_REQ,
    ATT_OP_WRITE_RSP,
    CCCD_INDICATE,
)

_CONN_HANDLE = 0x0040
_PEER_ADDR = '02:00:00:00:00:02'
_RESPONSE_DELAY_S = 0.05


class InOrderResponderH4Client:
  """Fake H4 client whose peer answers each ATT request in arrival order."""

  # pylint: disable=too-many-instance-attributes

  def __init__(self, bridge, respond=True):
    self._cv = threading.Condition()
    self._adv_reports = []
    self._connections = {_CONN_HANDLE: {'peer_bd_addr': _PEER_ADDR}}
    self._acl_packets = []
    self.sent = []
    self.in_flight = 0
    self.max_in_flight = 0
    self._bridge = bridge
    self._queue = collections.deque()
    self._queue_cv = threading.Condition()
    if respond:
      threading.Thread(target=self._responder, daemon=True).start()

  def send_acl_l2cap(self, handle, cid, pdu):
    pdu = bytes(pdu)
    with self._queue_cv:
      self.sent.append((handle, cid, pdu))
      self.in_flight += 1
      self.max_in_flight = max(self.max_in_flight, self.in_flight)
      self._queue.append((handle, pdu))
      self._queue_cv.notify_all()

  def _responder(self):
    while True:
      with self._queue_cv:
        while not self._queue:
          self._queue_cv.wait()
        handle, pdu = self._queue.popleft()
      time.sleep(_RESPONSE_DELAY_S)
      if pdu[0] == ATT_OP_READ_REQ:
        rsp = struct.pack('<B', ATT_OP_READ_RSP) + pdu[1:3]
      else:
        rsp = struct.pack('<B', ATT_OP_WRITE_RSP)
      with self._queue_cv:
        self.in_flight -= 1
      self._bridge._process_acl_att_packets([(handle, ATT_CID, rsp)])


class SendAttRequestSerializationTest(unittest.TestCase):

  def _make_bridge(self, respond=True):
    bridge = VirtualBluezAdapterBridge(
        'ctrl0', '02:00:00:00:00:01', '127.0.0.1', 0
    )
    bridge.h4_client = InOrderResponderH4Client(bridge, respond=respond)
    bridge.connected_handles[_CONN_HANDLE] = _PEER_ADDR
    return bridge

  def test_concurrent_requests_on_one_bearer_are_serialized(self):
    """A C1 write racing the StartNotify CCCD write must not lose a reply."""
    bridge = self._make_bridge()
    read_req = struct.pack('<BH', ATT_OP_READ_REQ, 0x0003)
    cccd_req = struct.pack('<BHH', ATT_OP_WRITE_REQ, 0x0005, CCCD_INDICATE)
    results = {}
    start = threading.Barrier(2)

    def issue(name, pdu):
      start.wait()
      try:
        results[name] = bridge.send_att_request(_CONN_HANDLE, pdu, timeout=2.0)
      except Exception as exc:  # pylint: disable=broad-except
        results[name] = exc

    threads = [
        threading.Thread(target=issue, args=('read', read_req), daemon=True),
        threading.Thread(target=issue, args=('cccd', cccd_req), daemon=True),
    ]
    for t in threads:
      t.start()
    for t in threads:
      t.join(timeout=5.0)
      self.assertFalse(t.is_alive(), 'requester hung')

    self.assertEqual(results['read'], b'\x0b\x03\x00')
    self.assertEqual(results['cccd'], b'\x13')
    self.assertEqual(bridge.h4_client.max_in_flight, 1)
    self.assertEqual(len(bridge.h4_client.sent), 2)

  def test_late_response_is_not_matched_to_next_request(self):
    bridge = self._make_bridge(respond=False)
    write_req = struct.pack('<BHB', ATT_OP_WRITE_REQ, 0x0003, 0x01)
    with self.assertRaises(TimeoutError):
      bridge.send_att_request(_CONN_HANDLE, write_req, timeout=0.2)

    # The peer's reply to the timed-out request arrives late, after the next
    # request would have been sent. It must not be taken as that reply.
    def late_response():
      time.sleep(0.1)
      bridge._process_acl_att_packets(
          [(_CONN_HANDLE, ATT_CID, struct.pack('<B', ATT_OP_WRITE_RSP))]
      )

    late = threading.Thread(target=late_response, daemon=True)
    late.start()
    with self.assertRaises(TimeoutError):
      bridge.send_att_request(_CONN_HANDLE, write_req, timeout=0.5)
    late.join(timeout=1.0)
    self.assertEqual(len(bridge.h4_client.sent), 1)

    # A new connection on the same handle gets a usable bearer again.
    h4 = bridge.h4_client
    conn = h4._connections.pop(_CONN_HANDLE)
    bridge._sync_from_h4_client()
    h4._connections[_CONN_HANDLE] = conn
    bridge._sync_from_h4_client()
    threading.Thread(target=h4._responder, daemon=True).start()
    self.assertEqual(
        bridge.send_att_request(_CONN_HANDLE, write_req, timeout=2.0), b'\x13'
    )

  def test_disconnect_aborts_outstanding_request(self):
    bridge = self._make_bridge(respond=False)
    write_req = struct.pack('<BHB', ATT_OP_WRITE_REQ, 0x0003, 0x01)

    def drop_link():
      time.sleep(0.1)
      bridge.h4_client._connections.pop(_CONN_HANDLE)

    threading.Thread(target=drop_link, daemon=True).start()
    started = time.time()
    with self.assertRaises(ConnectionError):
      bridge.send_att_request(_CONN_HANDLE, write_req, timeout=3.0)
    self.assertLess(time.time() - started, 1.5)


if __name__ == '__main__':
  unittest.main()
