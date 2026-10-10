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
"""Unit tests for DockerNode graceful termination and coverage mode."""

import os
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from cirque.nodes.dockernode import DockerNode


class TestDockerNode(unittest.TestCase):
  """Unit tests for DockerNode lifecycle and termination."""

  def setUp(self):
    self.mock_client = MagicMock()
    self.mock_container = MagicMock()
    self.mock_container.exec_run.return_value = SimpleNamespace(
        exit_code=0, output=b'ok\n'
    )
    self.mock_client.containers.run.return_value = self.mock_container

  def test_stop_default_timeout(self):
    with patch.dict(os.environ, {}, clear=True):
      node = DockerNode(self.mock_client, 'default_node')
      node.container = self.mock_container
      node.stop()
      self.mock_container.stop.assert_called_once_with(timeout=0)

  def test_stop_coverage_mode_timeout_and_term(self):
    with patch.dict(os.environ, {'CIRQUE_COVERAGE': '1'}):
      node = DockerNode(self.mock_client, 'default_node')
      node.container = self.mock_container
      # Make exec_run return 1 after 1 check to simulate process exit
      self.mock_container.exec_run.side_effect = [
          SimpleNamespace(exit_code=0, output=b''),  # term_cmd
          SimpleNamespace(exit_code=1, output=b''),  # check_cmd -> exited
      ]
      node.stop()
      self.assertEqual(self.mock_container.exec_run.call_count, 2)
      term_arg = self.mock_container.exec_run.call_args_list[0][0][0]
      check_arg = self.mock_container.exec_run.call_args_list[1][0][0]
      self.assertIn("'[/]out/'", term_arg)
      self.assertIn("'[/]out/'", check_arg)
      self.mock_container.stop.assert_called_once_with(timeout=0)

  def test_stop_coverage_mode_fallback_timeout_when_process_lingers(self):
    with (
        patch.dict(os.environ, {'CIRQUE_COVERAGE': '1'}),
        patch('cirque.nodes.dockernode.time.sleep'),
    ):
      node = DockerNode(self.mock_client, 'default_node')
      node.container = self.mock_container
      self.mock_container.exec_run.return_value = SimpleNamespace(
          exit_code=0, output=b''
      )
      node.stop()
      self.mock_container.stop.assert_called_once_with(timeout=2)

  def test_stop_graceful_stop_env(self):
    with patch.dict(os.environ, {'CIRQUE_GRACEFUL_STOP': '1'}):
      node = DockerNode(self.mock_client, 'default_node')
      node.container = self.mock_container
      self.mock_container.exec_run.side_effect = [
          SimpleNamespace(exit_code=0, output=b''),
          SimpleNamespace(exit_code=1, output=b''),
      ]
      node.stop()
      self.mock_container.stop.assert_called_once_with(timeout=0)


if __name__ == '__main__':
  unittest.main()
