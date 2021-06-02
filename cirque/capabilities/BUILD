# Copyright 2020 Google LLC
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



load("@rules_python//python:defs.bzl", "py_library")
load("@cirque_deps//:requirements.bzl", "requirement")
load("//utils/pystyletest:pystyletest.bzl", "py_style_test")

py_library(
    name="capabilities",
    srcs = [
        "basecapability.py",
        "dockernetworkcapability.py",
        "interactivecapability.py",
        "lanaccesscapability.py",
        "mountcapability.py",
        "trafficcontrolcapability.py",
        "threadcapability.py",
        "weavecapability.py",
        "wificapability.py",
        "xvnccapability.py",
    ],
    deps = [
        "//cirque/common",
        "//cirque/connectivity",
        requirement("pyroute2"),
    ],
    visibility = ["//visibility:public"],
)

py_style_test(
    name="lint",
    srcs = [
        "basecapability.py",
        "dockernetworkcapability.py",
        "interactivecapability.py",
        "lanaccesscapability.py",
        "mountcapability.py",
        "networkcontrolcapability.py",
        "threadcapability.py",
        "weavecapability.py",
        "wificapability.py",
        "xvnccapability.py",
        "test/test_wifi_capability.py",
        "test/test_mount_capability.py",
        "test/test_networkcontrol_capability.py",
    ],
    deps = [
        "//cirque/connectivity",
        "//cirque/capabilities",
        "//cirque/nodes",
        requirement("pyroute2"),
    ],
)

py_test(
    name="wifi_unit_test",
    main="test/test_wifi_capability.py",
    srcs=["test/test_wifi_capability.py"],
    deps = [
        "//cirque/common",
        "//cirque/nodes",
        "//cirque/capabilities",
    ],
)

py_test(
    name="mount_unit_test",
	  main="test/test_mount_capability.py",
    srcs=["test/test_mount_capability.py"],
    deps = [
        "//cirque/capabilities",
    ],
)


py_test(
    name="tc_unit_test",
	  main="test/test_networkcontrol_capability.py",
    srcs=["test/test_networkcontrol_capability.py"],
    deps = [
        "//cirque/capabilities",
    ],
)
