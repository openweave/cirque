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
import copy
import pickle
import socket
import struct
import threading
import time
import unittest

from cirque.virtual_bt.adapter_bridge import ATT_CID, VirtualBluezAdapterBridge
from cirque.virtual_bt.att_db import (
    ATT_OP_EXCHANGE_MTU_REQ,
    ATT_OP_HANDLE_VALUE_CFM,
    ATT_OP_HANDLE_VALUE_IND,
    ATT_OP_HANDLE_VALUE_NTF,
    ATT_OP_PREPARE_WRITE_REQ,
    ATT_OP_READ_REQ,
    ATT_OP_READ_RSP,
    ATT_OP_WRITE_REQ,
    ATT_OP_WRITE_RSP,
    AttDatabase,
    CCCD_INDICATE,
    GATT_CLIENT_CHAR_CONFIG_UUID16,
)
from cirque.virtual_bt.client import AclPacket, H4TcpClient
from cirque.virtual_bt.hci_h4 import (
    build_acl_packet,
    build_disconnection_complete_event,
    build_le_connection_complete_event,
)

_CONN_HANDLE = 0x0040
_PEER_ADDR = '02:00:00:00:00:02'
_ALT_PEER_ADDR = '02:00:00:00:00:03'
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

  def clear_pending_requests(self):
    with self._queue_cv:
      self._queue.clear()
      self.in_flight = 0

  def send_acl_l2cap(self, handle, cid, pdu):
    pdu = bytes(pdu)
    with self._cv:
      cinfo = self._connections.get(handle)
      gen = cinfo.get('generation') if cinfo is not None else None
    with self._queue_cv:
      self.sent.append((handle, cid, pdu))
      self.in_flight += 1
      self.max_in_flight = max(self.max_in_flight, self.in_flight)
      self._queue.append((handle, pdu, gen))
      self._queue_cv.notify_all()

  def _responder(self):
    while True:
      with self._queue_cv:
        while not self._queue:
          self._queue_cv.wait()
        handle, pdu, gen = self._queue.popleft()
      time.sleep(_RESPONSE_DELAY_S)
      if pdu[0] == ATT_OP_READ_REQ:
        rsp = struct.pack('<B', ATT_OP_READ_RSP) + pdu[1:3]
      else:
        rsp = struct.pack('<B', ATT_OP_WRITE_RSP)
      with self._queue_cv:
        self.in_flight -= 1
      pkt = (
          AclPacket((handle, ATT_CID, rsp), gen)
          if gen is not None
          else (handle, ATT_CID, rsp)
      )
      self._bridge._process_acl_att_packets([pkt])


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
    h4.clear_pending_requests()
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

  def test_queued_request_on_dropped_handle_raises_before_sending(self):
    bridge = self._make_bridge(respond=False)
    req1 = struct.pack('<BH', ATT_OP_READ_REQ, 0x0003)
    req2 = struct.pack('<BHB', ATT_OP_WRITE_REQ, 0x0003, 0x01)
    first_sent = threading.Event()
    orig_send = bridge.h4_client.send_acl_l2cap

    def tracking_send(handle, cid, pdu):
      orig_send(handle, cid, pdu)
      first_sent.set()

    bridge.h4_client.send_acl_l2cap = tracking_send
    results = {}

    def issue(name, pdu):
      try:
        results[name] = bridge.send_att_request(_CONN_HANDLE, pdu, timeout=3.0)
      except Exception as exc:  # pylint: disable=broad-except
        results[name] = exc

    t1 = threading.Thread(target=issue, args=('r1', req1), daemon=True)
    t1.start()
    self.assertTrue(first_sent.wait(2.0))

    t2 = threading.Thread(target=issue, args=('r2', req2), daemon=True)
    t2.start()
    time.sleep(0.05)

    bridge.h4_client._connections.pop(_CONN_HANDLE)
    t1.join(timeout=3.0)
    t2.join(timeout=3.0)
    self.assertFalse(t1.is_alive())
    self.assertFalse(t2.is_alive())
    self.assertIsInstance(results['r1'], ConnectionError)
    self.assertIsInstance(results['r2'], ConnectionError)
    self.assertEqual(len(bridge.h4_client.sent), 1)

  def test_queued_request_on_reused_handle_raises_before_sending(self):
    bridge = self._make_bridge(respond=False)
    req1 = struct.pack('<BH', ATT_OP_READ_REQ, 0x0003)
    req2 = struct.pack('<BHB', ATT_OP_WRITE_REQ, 0x0003, 0x01)
    first_sent = threading.Event()
    orig_send = bridge.h4_client.send_acl_l2cap

    def tracking_send(handle, cid, pdu):
      orig_send(handle, cid, pdu)
      first_sent.set()

    bridge.h4_client.send_acl_l2cap = tracking_send
    results = {}

    def issue(name, pdu):
      try:
        results[name] = bridge.send_att_request(_CONN_HANDLE, pdu, timeout=3.0)
      except Exception as exc:  # pylint: disable=broad-except
        results[name] = exc

    t1 = threading.Thread(target=issue, args=('r1', req1), daemon=True)
    t1.start()
    self.assertTrue(first_sent.wait(2.0))

    t2 = threading.Thread(target=issue, args=('r2', req2), daemon=True)
    t2.start()
    time.sleep(0.05)

    # Drop Gen 1 and immediately reuse the same handle for Gen 2.
    bridge.connected_handles.pop(_CONN_HANDLE)
    bridge.connected_handles[_CONN_HANDLE] = _PEER_ADDR

    t1.join(timeout=3.0)
    t2.join(timeout=3.0)
    self.assertFalse(t1.is_alive())
    self.assertFalse(t2.is_alive())
    self.assertIsInstance(results['r1'], ConnectionError)
    self.assertIsInstance(results['r2'], ConnectionError)
    self.assertEqual(len(bridge.h4_client.sent), 1)

    # A fresh request issued on Gen 2 succeeds.
    bridge.h4_client.clear_pending_requests()
    bridge.h4_client.send_acl_l2cap = orig_send
    threading.Thread(target=bridge.h4_client._responder, daemon=True).start()
    self.assertEqual(
        bridge.send_att_request(_CONN_HANDLE, req2, timeout=2.0), b'\x13'
    )

  def test_timeout_on_gen1_does_not_poison_gen2_on_handle_reuse(self):
    bridge = self._make_bridge(respond=False)
    h4 = bridge.h4_client
    h4._connections[_CONN_HANDLE]['generation'] = 1
    bridge._sync_from_h4_client()
    read_req_gen1 = struct.pack('<BH', ATT_OP_READ_REQ, 0x0003)
    with self.assertRaises(TimeoutError):
      bridge.send_att_request(_CONN_HANDLE, read_req_gen1, timeout=0.15)

    # Same-generation follow-up is still rejected without sending ACL.
    with self.assertRaises(TimeoutError):
      bridge.send_att_request(_CONN_HANDLE, read_req_gen1, timeout=0.15)
    self.assertEqual(len(h4.sent), 1)

    # Reusing the handle on Gen 2 drops Gen 1's queued reply and returns
    # Gen 2's distinct read response.
    with h4._cv:
      h4._connections[_CONN_HANDLE] = {
          'peer_bd_addr': _PEER_ADDR, 'generation': 2
      }
    bridge.connected_handles.pop(_CONN_HANDLE)
    bridge.connected_handles[_CONN_HANDLE] = _PEER_ADDR
    threading.Thread(target=h4._responder, daemon=True).start()
    read_req_gen2 = struct.pack('<BH', ATT_OP_READ_REQ, 0x0007)
    self.assertEqual(
        bridge.send_att_request(_CONN_HANDLE, read_req_gen2, timeout=2.0),
        b'\x0b\x07\x00',
    )
    self.assertEqual(h4.in_flight, 0)

  def test_request_on_unregistered_handle_raises_connection_error(self):
    bridge = self._make_bridge(respond=False)
    write_req = struct.pack('<BHB', ATT_OP_WRITE_REQ, 0x0003, 0x01)
    with self.assertRaises(ConnectionError):
      bridge.send_att_request(0x0041, write_req, timeout=0.5)
    self.assertEqual(bridge.h4_client.sent, [])

  def test_removed_handle_drops_cached_gatt_discovery(self):
    bridge = self._make_bridge(respond=False)
    bridge.discovered_gatt[_CONN_HANDLE] = object()
    bridge.connected_handles.pop(_CONN_HANDLE)
    bridge.connected_handles[_CONN_HANDLE] = _PEER_ADDR
    self.assertNotIn(_CONN_HANDLE, bridge.discovered_gatt)

  def test_older_h4_generation_never_replaces_newer(self):
    bridge = self._make_bridge(respond=False)
    calls = []
    bridge.on_connection_callback = lambda h, a: calls.append((h, a))
    h4 = bridge.h4_client
    h4._connections[_CONN_HANDLE]['generation'] = 1
    bridge._sync_from_h4_client()
    h4._connections[_CONN_HANDLE]['generation'] = 2
    bridge._sync_from_h4_client()
    self.assertEqual(calls, [(_CONN_HANDLE, _PEER_ADDR)])
    gen = bridge._active_conn_generations[_CONN_HANDLE]
    with bridge._lock:
      self.assertFalse(
          bridge._set_connected_handle(_CONN_HANDLE, _PEER_ADDR, h4_gen=1)
      )
    self.assertEqual(bridge._active_conn_generations[_CONN_HANDLE], gen)
    self.assertEqual(bridge._h4_conn_generations[_CONN_HANDLE], 2)

  def test_older_h4_gen_rejected_on_addr_change_and_none_clears_gen(self):
    bridge = self._make_bridge(respond=False)
    with bridge._lock:
      self.assertTrue(
          bridge._set_connected_handle(_CONN_HANDLE, _ALT_PEER_ADDR, h4_gen=2)
      )
      gen2 = bridge._active_conn_generations[_CONN_HANDLE]
      self.assertFalse(
          bridge._set_connected_handle(_CONN_HANDLE, _PEER_ADDR, h4_gen=1)
      )
      self.assertEqual(bridge.connected_handles[_CONN_HANDLE], _ALT_PEER_ADDR)
      self.assertEqual(bridge._active_conn_generations[_CONN_HANDLE], gen2)

      # Replacing with h4_gen=None clears _h4_conn_generations and retires 2.
      self.assertTrue(
          bridge._set_connected_handle(_CONN_HANDLE, _PEER_ADDR, h4_gen=None)
      )
      self.assertNotIn(_CONN_HANDLE, bridge._h4_conn_generations)
      self.assertFalse(
          bridge._set_connected_handle(_CONN_HANDLE, _ALT_PEER_ADDR, h4_gen=2)
      )
    with bridge._att_cv:
      stale_pkt = AclPacket((_CONN_HANDLE, ATT_CID, b'\x13'), 2)
      self.assertFalse(bridge._acl_is_current(_CONN_HANDLE, stale_pkt))

  def test_removed_handle_not_resurrected_by_pre_disconnect_h4_snapshot(self):
    bridge = self._make_bridge(respond=False)
    h4 = bridge.h4_client
    h4._connections[_CONN_HANDLE]['generation'] = 1
    bridge._sync_from_h4_client()
    bridge.connected_handles.pop(_CONN_HANDLE)

    # H4 has not processed Disconnection_Complete yet; Gen 1 stays retired.
    bridge._sync_from_h4_client()
    self.assertNotIn(_CONN_HANDLE, bridge.connected_handles)

    # A fresh Gen 2 connection on the same handle is accepted.
    h4._connections[_CONN_HANDLE]['generation'] = 2
    bridge._sync_from_h4_client()
    self.assertEqual(bridge.connected_handles[_CONN_HANDLE], _PEER_ADDR)
    self.assertEqual(bridge._h4_conn_generations[_CONN_HANDLE], 2)

    # reset() clears the retired-generation watermark.
    h4.reset = lambda: None
    bridge.reset()
    self.assertEqual(bridge._retired_h4_conn_generations, {})

  def test_connect_to_peripheral_not_evicted_by_empty_poll_snapshot(self):
    bridge = VirtualBluezAdapterBridge(
        'ctrl0', '02:00:00:00:00:01', '127.0.0.1', 0
    )
    real_cv = threading.Condition()
    snapshot_taken = threading.Event()
    registered = threading.Event()

    class PausingPollCondition:

      paused = False

      def __enter__(self):
        return real_cv.__enter__()

      def __exit__(self, *exc):
        real_cv.__exit__(*exc)
        if threading.current_thread().name == 'Poller' and not self.paused:
          PausingPollCondition.paused = True
          snapshot_taken.set()
          registered.wait(1.0)
          time.sleep(0.02)
        return False

    class ConnectingH4Client:

      def __init__(self):
        self._cv = PausingPollCondition()
        self._adv_reports = []
        self._connections = {}
        self._conn_generation_seq = 0
        self._acl_packets = []
        self.sent = []

      def connect(self, peer_bd_addr, timeout=3.0):
        del timeout
        with real_cv:
          self._conn_generation_seq += 1
          self._connections[_CONN_HANDLE] = {
              'peer_bd_addr': peer_bd_addr,
              'generation': self._conn_generation_seq,
          }
        return _CONN_HANDLE

      def send_acl_l2cap(self, handle, cid, pdu):
        self.sent.append((handle, cid, bytes(pdu)))
        bridge._process_acl_att_packets(
            [AclPacket((handle, ATT_CID, b'\x13'), self._conn_generation_seq)]
        )

    h4 = ConnectingH4Client()
    bridge.h4_client = h4
    poller = threading.Thread(
        target=bridge._sync_from_h4_client, name='Poller', daemon=True
    )
    poller.start()
    self.assertTrue(snapshot_taken.wait(2.0))

    # 1. Direct _ConnectedHandlesDict write while poller holds empty snapshot
    #    with snapshot_seq=0: newer h4_gen=1 must not be treated as stale.
    h4.connect(_PEER_ADDR)
    bridge.connected_handles[_CONN_HANDLE] = _PEER_ADDR
    registered.set()
    poller.join(timeout=2.0)
    self.assertFalse(poller.is_alive())
    self.assertEqual(bridge.connected_handles[_CONN_HANDLE], _PEER_ADDR)

    # 2. connect_to_peripheral serializes under _sync_lock and keeps handle.
    bridge.connected_handles.pop(_CONN_HANDLE)
    PausingPollCondition.paused = False
    snapshot_taken.clear()
    registered.clear()
    with real_cv:
      h4._connections.clear()
    poller2 = threading.Thread(
        target=bridge._sync_from_h4_client, name='Poller', daemon=True
    )
    poller2.start()
    self.assertTrue(snapshot_taken.wait(2.0))

    connected_done = {}

    def do_connect():
      registered.set()
      connected_done['h'] = bridge.connect_to_peripheral(
          _PEER_ADDR, timeout=2.0, auto_discover=False
      )

    connector = threading.Thread(target=do_connect, daemon=True)
    connector.start()
    poller2.join(timeout=2.0)
    connector.join(timeout=2.0)
    self.assertFalse(poller2.is_alive())
    self.assertFalse(connector.is_alive())
    self.assertEqual(connected_done.get('h'), _CONN_HANDLE)
    write_req = struct.pack('<BHB', ATT_OP_WRITE_REQ, 0x0003, 0x01)
    self.assertEqual(
        bridge.send_att_request(_CONN_HANDLE, write_req, timeout=1.0), b'\x13'
    )

  def test_acl_packet_default_generation_and_copy_pickle(self):
    untagged = AclPacket((_CONN_HANDLE, ATT_CID, b'\x13'))
    self.assertIsNone(untagged.generation)
    self.assertEqual(untagged, (_CONN_HANDLE, ATT_CID, b'\x13'))

    tagged = AclPacket((_CONN_HANDLE, ATT_CID, b'\x0b\x22'), 7)
    for clone in (copy.deepcopy(tagged), pickle.loads(pickle.dumps(tagged))):
      self.assertIsInstance(clone, AclPacket)
      self.assertEqual(clone, (_CONN_HANDLE, ATT_CID, b'\x0b\x22'))
      self.assertEqual(clone.generation, 7)

  def test_stale_h4_snapshot_is_not_applied_after_newer_one(self):
    """Concurrent syncs must apply H4 snapshots in the order taken."""
    bridge = self._make_bridge(respond=False)
    h4 = bridge.h4_client
    h4._adv_reports = [{'bd_addr': _PEER_ADDR, 'adv_data': b'', 'rssi': -80}]
    h4._acl_packets = [(
        _CONN_HANDLE,
        ATT_CID,
        struct.pack('<BH', ATT_OP_HANDLE_VALUE_NTF, 0x0005) + b'first',
    )]

    snapshot_taken = threading.Event()
    b_started = threading.Event()
    real_cv = h4._cv

    class PausingCondition:
      """Pauses thread A right after its snapshot, outside the H4 lock."""

      paused = False

      def __enter__(self):
        return real_cv.__enter__()

      def __exit__(self, *exc):
        real_cv.__exit__(*exc)
        if threading.current_thread().name == 'A' and not self.paused:
          PausingCondition.paused = True
          snapshot_taken.set()
          b_started.wait(1.0)
          time.sleep(0.02)
        return False

    h4._cv = PausingCondition()

    def newer_sync():
      b_started.set()
      bridge._sync_from_h4_client()

    a = threading.Thread(
        target=bridge._sync_from_h4_client, name='A', daemon=True
    )
    a.start()
    self.assertTrue(snapshot_taken.wait(2.0))
    # H4 disconnects and receives a newer adv + second notification after A's
    # snapshot. Without _sync_lock, B applies first and A's stale snapshot
    # resurrects _CONN_HANDLE, reverts RSSI to -80, and reorders notifications.
    with real_cv:
      h4._connections.clear()
      h4._adv_reports = [{'bd_addr': _PEER_ADDR, 'adv_data': b'', 'rssi': -35}]
      h4._acl_packets.append((
          _CONN_HANDLE,
          ATT_CID,
          struct.pack('<BH', ATT_OP_HANDLE_VALUE_NTF, 0x0005) + b'second',
      ))
    b = threading.Thread(target=newer_sync, name='B', daemon=True)
    b.start()
    a.join(timeout=3.0)
    b.join(timeout=3.0)
    self.assertFalse(a.is_alive())
    self.assertFalse(b.is_alive())

    self.assertNotIn(_CONN_HANDLE, bridge.connected_handles)
    self.assertEqual(bridge.discovered_peripherals[_PEER_ADDR]['rssi'], -35)
    self.assertEqual(bridge.rx_indications, [b'first', b'second'])

  def test_request_not_sent_when_h4_reconnects_during_resync(self):
    bridge = self._make_bridge(respond=False)
    h4 = bridge.h4_client
    h4._connections[_CONN_HANDLE]['generation'] = 1
    bridge._sync_from_h4_client()
    # Gen 2 is in H4 but not yet applied, so the request resyncs first.
    h4._connections[_CONN_HANDLE] = {
        'peer_bd_addr': _PEER_ADDR, 'generation': 2
    }
    real_sync = bridge._sync_from_h4_client

    def sync_then_reconnect():
      real_sync()
      bridge._sync_from_h4_client = real_sync
      # Gen 3 lands in H4 right after the resync applied Gen 2.
      with h4._cv:
        h4._connections[_CONN_HANDLE] = {
            'peer_bd_addr': _PEER_ADDR, 'generation': 3
        }

    bridge._sync_from_h4_client = sync_then_reconnect
    write_req = struct.pack('<BHB', ATT_OP_WRITE_REQ, 0x0003, 0x01)
    with self.assertRaises(ConnectionError):
      bridge.send_att_request(_CONN_HANDLE, write_req, timeout=0.5)
    self.assertEqual(h4.sent, [])

  def _make_socket_bridge(self):
    """Returns (bridge, h4, peer_sock) with a real H4 client, Gen 1 synced."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    h4 = H4TcpClient('127.0.0.1', port, timeout=2.0)
    peer_sock, _ = srv.accept()
    srv.close()
    self.addCleanup(peer_sock.close)
    self.addCleanup(h4.close)
    bridge = VirtualBluezAdapterBridge(
        'ctrl0', '02:00:00:00:00:01', '127.0.0.1', port
    )
    bridge.h4_client = h4
    peer_sock.sendall(
        build_le_connection_complete_event(
            0x00, _CONN_HANDLE, 0, 0, _PEER_ADDR
        ).to_bytes()
    )
    self._wait_h4(h4, lambda: _CONN_HANDLE in h4._connections)
    bridge._sync_from_h4_client()
    return bridge, h4, peer_sock

  def _wait_h4(self, h4, predicate):
    deadline = time.time() + 2.0
    while time.time() < deadline:
      with h4._cv:
        if predicate():
          return
      time.sleep(0.01)
    self.fail('H4 state not reached')

  def test_notifications_just_before_disconnect_are_delivered(self):
    bridge, h4, peer_sock = self._make_socket_bridge()
    got = []
    bridge.on_indication_callback = got.append
    ntf = build_acl_packet(
        _CONN_HANDLE,
        ATT_CID,
        struct.pack('<BH', ATT_OP_HANDLE_VALUE_NTF, 0x0005) + b'ntf',
    ).to_bytes()
    ind = build_acl_packet(
        _CONN_HANDLE,
        ATT_CID,
        struct.pack('<BH', ATT_OP_HANDLE_VALUE_IND, 0x0005) + b'ind',
    ).to_bytes()
    disc = build_disconnection_complete_event(
        _CONN_HANDLE, 0x13, 0x00
    ).to_bytes()
    peer_sock.sendall(ntf + ind + disc)
    self._wait_h4(h4, lambda: _CONN_HANDLE not in h4._connections)

    bridge._sync_from_h4_client()

    self.assertEqual(got, [b'ntf', b'ind'])
    self.assertNotIn(_CONN_HANDLE, bridge.connected_handles)
    # The link is gone, so no Handle Value Confirmation is sent for it.
    peer_sock.settimeout(0.2)
    with self.assertRaises(socket.timeout):
      peer_sock.recv(1024)

  def test_fast_h4_reconnect_keeps_acl_and_does_not_poison_gen2(self):
    bridge, h4, peer_sock = self._make_socket_bridge()
    with h4._cv:
      gen1 = h4._connections[_CONN_HANDLE].get('generation')
    self.assertIsNotNone(gen1)
    # Time out on Gen 1; same-gen request must still be rejected.
    read_req = struct.pack('<BH', ATT_OP_READ_REQ, 0x0003)
    with self.assertRaises(TimeoutError):
      bridge.send_att_request(_CONN_HANDLE, read_req, timeout=0.15)
    with self.assertRaises(TimeoutError):
      bridge.send_att_request(_CONN_HANDLE, read_req, timeout=0.15)

    # Drain Gen 1 ACL request from peer_sock.
    peer_sock.settimeout(2.0)
    gen1_wire = peer_sock.recv(1024)
    self.assertGreater(len(gen1_wire), 0)

    # Fast H4 reconnect: stale Gen 1 READ_RSP (0x11) + disconnect + Gen 2.
    stale_acl = build_acl_packet(
        _CONN_HANDLE, ATT_CID, struct.pack('<BB', ATT_OP_READ_RSP, 0x11)
    ).to_bytes()
    disc = build_disconnection_complete_event(
        _CONN_HANDLE, 0x13, 0x00
    ).to_bytes()
    conn2 = build_le_connection_complete_event(
        0x00, _CONN_HANDLE, 0, 0, _PEER_ADDR
    ).to_bytes()
    peer_sock.sendall(stale_acl + disc + conn2)

    self._wait_h4(
        h4,
        lambda: h4._connections.get(_CONN_HANDLE, {}).get('generation')
        not in (None, gen1),
    )
    with h4._cv:
      gen2 = h4._connections[_CONN_HANDLE]['generation']
      acls_left = list(h4._acl_packets)
    self.assertGreater(gen2, gen1)
    # The stale ACL is kept, tagged with the generation it arrived on.
    self.assertEqual(len(acls_left), 1)
    self.assertEqual(acls_left[0][0], _CONN_HANDLE)
    self.assertEqual(acls_left[0].generation, gen1)

    # Pre-register Gen 2 (as connect_to_peripheral does) while stale_acl is
    # still queued in h4._acl_packets, so _acl_is_current must drop 0x11.
    with bridge._sync_lock:
      with bridge._lock:
        bridge._set_connected_handle(_CONN_HANDLE, _PEER_ADDR, h4_gen=gen2)

    def reply_gen2():
      data = peer_sock.recv(1024)
      if data:
        time.sleep(0.08)
        peer_sock.sendall(
            build_acl_packet(
                _CONN_HANDLE,
                ATT_CID,
                struct.pack('<BB', ATT_OP_READ_RSP, 0x22),
            ).to_bytes()
        )

    responder = threading.Thread(target=reply_gen2, daemon=True)
    responder.start()
    rsp = bridge.send_att_request(_CONN_HANDLE, read_req, timeout=2.0)
    responder.join(timeout=2.0)
    self.assertFalse(responder.is_alive())
    self.assertEqual(rsp, struct.pack('<BB', ATT_OP_READ_RSP, 0x22))

  def test_fast_reconnect_isolates_peripheral_state_and_delivers_gen1_write(
      self,
  ):
    bridge, h4, peer_sock = self._make_socket_bridge()
    with h4._cv:
      gen1 = h4._connections[_CONN_HANDLE]['generation']
    db = AttDatabase(start_handle=1)
    svc_h = db.add_primary_service(0xFFF6)
    _, write_val_h = db.add_characteristic(svc_h, 0x2A00, properties=0x08)
    _, _ = db.add_characteristic(svc_h, 0x2A01, properties=0x20)
    cccd_h = db.add_descriptor(
        svc_h, GATT_CLIENT_CHAR_CONFIG_UUID16, is_cccd=True
    )
    bridge.set_att_database(db)

    writes = []
    cccd_events = []
    cfms = []
    bridge.on_write_callback = writes.append
    bridge.on_cccd_callback = lambda h, v: cccd_events.append((h, v))
    bridge.on_indication_confirm_callback = lambda: cfms.append(True)

    # Burst on Gen 1 right before fast reconnect onto the same handle:
    # MTU 247, CCCD 0x0002, Prepare Write, Indication CFM, and final C1 write.
    mtu_pdu = struct.pack('<BH', ATT_OP_EXCHANGE_MTU_REQ, 247)
    cccd_pdu = struct.pack('<BHH', ATT_OP_WRITE_REQ, cccd_h, CCCD_INDICATE)
    prep_pdu = struct.pack('<BHH', ATT_OP_PREPARE_WRITE_REQ, write_val_h, 0) + (
        b'part'
    )
    cfm_pdu = struct.pack('<B', ATT_OP_HANDLE_VALUE_CFM)
    c1_pdu = struct.pack('<BH', ATT_OP_WRITE_REQ, write_val_h) + b'final-gen1'
    burst = b''.join(
        build_acl_packet(_CONN_HANDLE, ATT_CID, pdu).to_bytes()
        for pdu in (mtu_pdu, cccd_pdu, prep_pdu, cfm_pdu, c1_pdu)
    )
    disc = build_disconnection_complete_event(
        _CONN_HANDLE, 0x13, 0x00
    ).to_bytes()
    conn2 = build_le_connection_complete_event(
        0x00, _CONN_HANDLE, 0, 0, _PEER_ADDR
    ).to_bytes()
    peer_sock.sendall(burst + disc + conn2)
    self._wait_h4(
        h4,
        lambda: h4._connections.get(_CONN_HANDLE, {}).get('generation')
        not in (None, gen1),
    )

    bridge._sync_from_h4_client()

    self.assertEqual(writes, [b'final-gen1'])
    self.assertEqual(bridge.att_server.effective_mtu, 23)
    self.assertEqual(bridge.att_server.cccd_states, {})
    self.assertEqual(bridge.att_server._prepare_write_queue, [])
    self.assertEqual(cccd_events, [])
    self.assertEqual(bridge.att_confirmation_count, 0)
    self.assertEqual(cfms, [])
    peer_sock.settimeout(0.2)
    with self.assertRaises(socket.timeout):
      peer_sock.recv(1024)


if __name__ == '__main__':
  unittest.main()
