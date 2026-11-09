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
"""Unit tests for wpa_dbus_daemon scan filter edge cases."""

import tempfile
import unittest
from unittest import mock

from cirque.virtual_wifi.docker_wifi_bridge import DockerVirtualWiFiManager
from cirque.virtual_wifi.server import VirtualWiFiServer
from cirque.virtual_wifi.wpa_dbus_daemon import _WpaStationState, WpaSupplicantDbusService
from gi.repository import GLib


class TestWpaDbusDaemonEdges(unittest.TestCase):
  """Hermetic tests covering scan filter parsing in WpaSupplicantDbusService."""

  def setUp(self):
    super().setUp()
    self.temp_dir = tempfile.TemporaryDirectory()
    self.server = VirtualWiFiServer(host='127.0.0.1')
    self.server.register_ap(ssid='TargetSSID', psk='Passphrase123', ap_id='ap1')
    self.server.register_ap(ssid='OtherSSID', psk='Passphrase123', ap_id='ap2')
    self.docker_manager = DockerVirtualWiFiManager(
        server=self.server, runtime_dir=self.temp_dir.name
    )
    self.service = WpaSupplicantDbusService(docker_manager=self.docker_manager)

  def tearDown(self):
    self.service.stop()
    self.docker_manager.stop_all()
    self.temp_dir.cleanup()
    super().tearDown()

  def test_handle_scan_method_with_ssid_filter_list(self):
    """Verifies that Scan({SSIDs: [...]}) parses filter_ssids and filters."""
    mock_conn = mock.MagicMock()
    mock_invocation = mock.MagicMock()
    station_id = 'sta_scan_test'
    st = self.service._get_or_create_station_dict(station_id)

    # GLib.Variant for a{sv} containing 'SSIDs': ['TargetSSID']
    scan_args = GLib.Variant(
        '(a{sv})',
        ({'SSIDs': GLib.Variant('as', ['TargetSSID'])},)
    )

    with (
        mock.patch.object(self.service, '_export_obj'),
        mock.patch.object(
            self.service, '_emit_iface_props_changed'
        ) as mock_emit,
    ):

      self.service._handle_scan_method(
          conn=mock_conn,
          station_id=station_id,
          st=st,
          invocation=mock_invocation,
          params=scan_args,
      )
      self.assertTrue(st.scanning)
      mock_invocation.return_value.assert_called_once()
      mock_emit.assert_called_once()
      # Verify BSSs in station state only contain TargetSSID
      self.assertEqual(len(st.bss_paths), 1)
      bpath = st.bss_paths[0]
      self.assertEqual(st.bsss[bpath]['ssid'], 'TargetSSID')

  def test_handle_scan_method_with_malformed_args_logs_debug(self):
    """Verifies that invalid params trigger the exception handler gracefully."""
    mock_conn = mock.MagicMock()
    mock_invocation = mock.MagicMock()
    station_id = 'sta_scan_test2'
    st = self.service._get_or_create_station_dict(station_id)

    # Broken params where unpack() raises an exception
    broken_params = mock.MagicMock()
    broken_params.unpack.side_effect = ValueError('Corrupted variant')

    with mock.patch.object(self.service, '_export_obj'):
      with mock.patch.object(self.service, '_emit_iface_props_changed'):
        self.service._handle_scan_method(
            conn=mock_conn,
            station_id=station_id,
            st=st,
            invocation=mock_invocation,
            params=broken_params,
        )
        self.assertTrue(st.scanning)
        mock_invocation.return_value.assert_called_once()
        # On filter parse error, all APs are returned (TargetSSID, OtherSSID)
        self.assertEqual(len(st.bss_paths), 2)




if __name__ == '__main__':
  unittest.main()
