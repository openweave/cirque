# Copyright 2021 Google LLC
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

import os
import glob
import subprocess
from threading import Lock

from cirque.capabilities.basecapability import BaseCapability


class TrafficControlCapability(BaseCapability):

  def __init__(self, latencyMs=0, loss=0):
    self.latencyMs = latencyMs
    self.loss = loss

  @property
  def name(self):
    return "TrafficControl"

  @property
  def description(self):
    return {
        "latency": self.latencyMs,
        "latencyMs": self.latencyMs,
        "loss": self.loss,
    }

  def get_docker_run_args(self, dockernode):
    return {"cap_add": ["NET_ADMIN"]}

  def enable_capability(self, docker_node):
    command = []
    if self.latencyMs > 0:
      command += ["delay", "{}ms".format(self.latencyMs)]
    if self.loss > 0:
      command += ["loss", "{}%".format(self.loss)]
    if command:
      res = docker_node.container.exec_run(
          " ".join(
              ["tc", "qdisc", "replace", "dev", "eth0", "root", "netem"]
              + command
          )
      )
      exit_code = (
          res.exit_code
          if hasattr(res, "exit_code")
          else (res[0] if isinstance(res, tuple) and len(res) > 0 else 0)
      )
      output = getattr(
          res,
          "output",
          res[1] if isinstance(res, tuple) and len(res) > 1 else b"",
      )
      if isinstance(exit_code, int) and exit_code != 0:
        raise RuntimeError(
            "Failed to configure tc netem (exit={}): {}".format(
                exit_code, output
            )
        )

  def disable_capability(self, docker_node):
    container = getattr(docker_node, "container", None)
    if container is not None:
      container.exec_run("tc qdisc del dev eth0 root")

