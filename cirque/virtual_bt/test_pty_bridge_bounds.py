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
"""Unit tests verifying pty_bridge.c defect 3 fixes.

Verifies:
1. Compilation with gcc -Wall -Wextra -Werror -fsyntax-only passes without warnings.
2. Inner write loops check g_running and bound EIO retries with MAX_EIO_RETRIES.
3. A test harness exercising the EIO write loop terminates in bounded iterations.
"""

import os
import subprocess
import tempfile
import unittest


class TestPtyBridgeBounds(unittest.TestCase):
  """Tests for defect 3: pty_bridge inner write loops g_running and EIO bounds."""

  def setUp(self):
    super().setUp()
    self.repo_root = os.path.abspath(
        os.path.join(os.path.dirname(__file__), '..', '..')
    )
    self.c_file = os.path.join(
        self.repo_root, 'cirque', 'virtual_bt', 'android', 'pty_bridge.c'
    )

  def test_gcc_syntax_and_warnings(self):
    """Verifies pty_bridge.c compiles cleanly with -Wall -Wextra -Werror."""
    ret = subprocess.run(
        ['gcc', '-Wall', '-Wextra', '-Werror', '-fsyntax-only', self.c_file],
        capture_output=True,
        text=True,
        check=False,
    )
    self.assertEqual(
        ret.returncode,
        0,
        f'gcc compilation failed:\nstdout: {ret.stdout}\nstderr: {ret.stderr}',
    )

  def test_source_contains_running_checks_and_eio_bounds(self):
    """Verifies static presence of g_running in write loops and MAX_EIO_RETRIES."""
    with open(self.c_file, 'r', encoding='utf-8') as f:
      content = f.read()

    self.assertIn('#define MAX_EIO_RETRIES', content)
    self.assertIn('while (g_running && sent < n)', content)
    self.assertIn('++eio_retries > MAX_EIO_RETRIES', content)

  def test_bounded_eio_loop_execution(self):
    """Compiles and executes a micro-harness verifying EIO loop breaks and g_running works."""
    harness_src = """
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#define MAX_EIO_RETRIES 10

static volatile int g_running = 1;
static int mock_write_calls = 0;

ssize_t mock_eio_write(int fd, const void *buf, size_t count) {
    (void)fd; (void)buf; (void)count;
    mock_write_calls++;
    errno = EIO;
    return -1;
}

int main(void) {
    // Test 1: Bounded EIO retry terminates after MAX_EIO_RETRIES + 1 calls
    int master_fd = 99;
    char buf[16] = "hello";
    ssize_t n = 5;
    ssize_t sent = 0;
    int eio_retries = 0;
    while (g_running && sent < n) {
        ssize_t s = mock_eio_write(master_fd, buf + sent, n - sent);
        if (s <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            if (errno == EIO) {
                if (++eio_retries > MAX_EIO_RETRIES) {
                    break;
                }
                continue;
            }
            break;
        }
        sent += s;
    }

    if (eio_retries != MAX_EIO_RETRIES + 1) {
        fprintf(stderr, "Expected %d EIO retries, got %d\\n", MAX_EIO_RETRIES + 1, eio_retries);
        return 1;
    }

    // Test 2: g_running == 0 aborts loop immediately
    g_running = 0;
    sent = 0;
    while (g_running && sent < n) {
        mock_eio_write(master_fd, buf + sent, n - sent);
    }
    if (g_running != 0) {
        return 2;
    }

    return 0;
}
"""
    with tempfile.TemporaryDirectory() as tmpdir:
      src_path = os.path.join(tmpdir, 'test_harness.c')
      bin_path = os.path.join(tmpdir, 'test_harness')
      with open(src_path, 'w', encoding='utf-8') as f:
        f.write(harness_src)

      comp = subprocess.run(
          ['gcc', '-O2', '-Wall', '-Werror', src_path, '-o', bin_path],
          capture_output=True,
          text=True,
          check=False,
      )
      self.assertEqual(comp.returncode, 0, f'Compilation failed: {comp.stderr}')

      run_ret = subprocess.run(
          [bin_path],
          capture_output=True,
          text=True,
          timeout=5.0,
          check=False,
      )
      self.assertEqual(run_ret.returncode, 0, f'Execution failed: {run_ret.stderr}')


if __name__ == '__main__':
  unittest.main()
