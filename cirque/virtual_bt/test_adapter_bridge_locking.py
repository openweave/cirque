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
"""Lock-ordering tests for VirtualBluezAdapterBridge.send_att_request."""

import struct
import threading
import unittest

from cirque.virtual_bt.adapter_bridge import ATT_CID, VirtualBluezAdapterBridge
from cirque.virtual_bt.att_db import ATT_OP_READ_REQ, ATT_OP_READ_RSP

_CONN_HANDLE = 0x0040


class FakeH4Client:
  """Minimal H4 client: records sent ACL PDUs, delivers nothing by itself."""

  def __init__(self):
    self._cv = threading.Condition()
    self._adv_reports = []
    self._connections = {_CONN_HANDLE: {'peer_bd_addr': '02:00:00:00:00:02'}}
    self._acl_packets = []
    self.sent = []

  def send_acl_l2cap(self, handle, cid, pdu):
    self.sent.append((handle, cid, bytes(pdu)))


class SendAttRequestLockOrderTest(unittest.TestCase):

  def setUp(self):
    super().setUp()
    self.bridge = VirtualBluezAdapterBridge(
        'ctrl0', '02:00:00:00:00:01', '127.0.0.1', 0
    )
    self.bridge.h4_client = FakeH4Client()
    self.bridge.connected_handles[_CONN_HANDLE] = '02:00:00:00:00:02'

  def test_response_delivered_while_poll_thread_holds_bridge_lock(self):
    """Regression for the _att_cv / _lock inversion.

    The poll thread holds bridge._lock and then takes bridge._att_cv to post
    an ATT response. The requester must never wait for bridge._lock while
    holding bridge._att_cv, or the two threads deadlock.
    """
    bridge = self.bridge
    rsp_pdu = struct.pack('<B', ATT_OP_READ_RSP) + b'\x2a'
    req_pdu = struct.pack('<BH', ATT_OP_READ_REQ, 0x0003)
    result = {}
    lock_held = threading.Event()

    def requester():
      try:
        result['rsp'] = bridge.send_att_request(
            _CONN_HANDLE, req_pdu, timeout=4.0
        )
      except Exception as exc:  # pylint: disable=broad-except
        result['error'] = exc

    def poll_thread():
      with bridge._lock:
        lock_held.set()
        # Give the requester several 50 ms wait/sync rounds, so it tries to
        # take bridge._lock while this thread owns it.
        threading.Event().wait(0.3)
        bridge._process_acl_att_packets([(_CONN_HANDLE, ATT_CID, rsp_pdu)])

    poller = threading.Thread(target=poll_thread, daemon=True)
    poller.start()
    self.assertTrue(lock_held.wait(2.0))
    req = threading.Thread(target=requester, daemon=True)
    req.start()

    poller.join(timeout=3.0)
    self.assertFalse(
        poller.is_alive(), 'poll thread deadlocked acquiring _att_cv'
    )
    req.join(timeout=3.0)
    self.assertFalse(req.is_alive(), 'requester deadlocked')
    self.assertNotIn('error', result)
    self.assertEqual(result['rsp'], rsp_pdu)
    self.assertEqual(bridge.h4_client.sent, [(_CONN_HANDLE, ATT_CID, req_pdu)])

  def test_stale_and_unexpected_responses_are_not_returned(self):
    bridge = self.bridge
    with bridge._att_cv:
      # A Read Response left over from an earlier request: cleared on send.
      bridge._pending_att_responses[_CONN_HANDLE] = b'\x0b\x00'
    req_pdu = struct.pack('<BH', ATT_OP_READ_REQ, 0x0003)

    def inject_wrong_opcode():
      threading.Event().wait(0.1)
      with bridge._att_cv:
        # Write Response (0x13) is not a valid reply to a Read Request.
        bridge._pending_att_responses[_CONN_HANDLE] = b'\x13'
        bridge._att_cv.notify_all()

    t = threading.Thread(target=inject_wrong_opcode, daemon=True)
    t.start()
    with self.assertRaises(TimeoutError):
      bridge.send_att_request(_CONN_HANDLE, req_pdu, timeout=0.5)
    t.join(timeout=1.0)
    self.assertNotIn(_CONN_HANDLE, bridge._pending_att_responses)


if __name__ == '__main__':
  unittest.main()
