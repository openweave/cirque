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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(
    name = "rules_python",
    branch = "master",
    remote = "https://github.com/bazelbuild/rules_python.git",
)

load("@rules_python//python:repositories.bzl", "py_repositories")
py_repositories()
# Only needed if using the packaging rules.
load("@rules_python//python:pip.bzl", "pip_repositories")
pip_repositories()

http_archive(
    name = "com_github_grpc_grpc",
    strip_prefix = "grpc-1.26.0",
    url = "https://github.com/grpc/grpc/archive/v1.26.0.tar.gz",
    sha256 = "2fcb7f1ab160d6fd3aaade64520be3e5446fc4c6fa7ba6581afdc4e26094bd81",
)

load("@com_github_grpc_grpc//bazel:grpc_deps.bzl", "grpc_deps")
grpc_deps()
load("@com_github_grpc_grpc//bazel:grpc_extra_deps.bzl", "grpc_extra_deps")
grpc_extra_deps()

load("@rules_python//python:pip.bzl", "pip3_import")
pip3_import(
    name = "cirque_deps",
    requirements = "//:requirements.txt",
)

load("@cirque_deps//:requirements.bzl", "pip_install")
pip_install()

