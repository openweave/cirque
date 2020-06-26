#!/bin/bash
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

#   Description: Integration tests for cirque core
#   Usage: sudo ./run_integration_tests.sh

SRC_DIR="$(cd "$(dirname "$0")" && pwd -P)"
OPENTHREAD_DIR="${SRC_DIR}"/openthread

function flask_clean() {
  flask_pid=`ps aux | grep "[f]lask" | awk '{print $2}' | sort -k2 -rn`
  if [ ! -z "${flask_pid}" ]; then
    for pid in "${flask_pid}"; do
      kill -9 $pid >/dev/null 2>&1
    done
  fi
}

function socat_clean() {
  socat_pid=`ps aux | grep "[s]ocat" | awk '{print $2}'`
  if [ ! -z "${socat_pid}" ]; then
    for pid in "${socat_pid}"; do
      kill -9 $pid >/dev/null 2>&1
    done
  fi
}

function virtual_thread_clean() {
  vthread_pid=`ps aux | grep "[o]t-ncp-ftd" | awk '{print $2}'`
  if [ ! -z "${vthread_pid}" ]; then
    for pid in "${vthread_pid}"; do
      kill -9 $pid >/dev/null 2>&1
    done
  fi
}

function run_cirque_grpc_clean() {
  grpc_pid=`ps aux | grep "[c]irque.grpc.service" | awk '{print $2}'`
  if [ ! -z "${grpc_pid}" ]; then
    for pid in "${grpc_pid}"; do
      kill -9 $pid >/dev/null 2>&1
    done
  fi
}

function create_virtual_environment() {
  echo "creating python virtual environment for tests..."
  python3 -m venv venv-test
  source venv-test/bin/activate
  pip install --upgrade pip
  pip install --upgrade setuptools
  pip install wheel
}

function install_cirque_to_venv() {
  echo "installing cirque into virtual environment..."
  pip install .
}

function run_flask_service() {
  pip install -r requirements.txt
  FLASK_APP='cirque/restservice/service.py' \
    PATH="${PATH}":"${OPENTHREAD_DIR}"/output/x86_64-unknown-linux-gnu/bin/ \
    python -m flask run
}

function run_flask_virtual_home_test() {
  echo "running flask virtual home test.."
  run_flask_service >/dev/null 2>&1 &
  sleep 10
  python examples/test_flask_virtual_home.py
}

function run_flask_clean() {
  echo "done flask test, clean up.."
  flask_clean
  socat_clean
  virtual_thread_clean
}

function run_grpc_service() {
  current_dirname=${SRC_DIR##*/}
  pushd .
  cd ..
  PATH="${PATH}":"${OPENTHREAD_DIR}"/output/x86_64-unknown-linux-gnu/bin/ \
    ${current_dirname}/venv-test/bin/python3 -m cirque.grpc.service
}

function run_grpc_virtual_home_test() {
  run_grpc_service >/dev/null 2>&1 &
  sleep 10
  source venv-test/bin/activate
  python3 examples/test_grpc_virtual_home.py
}

function main() {
  if [ ! -d "${OPENTHREAD_DIR}" ]; then
    ./dependency_modules.sh
  fi
  create_virtual_environment
  install_cirque_to_venv
  run_flask_virtual_home_test
  run_flask_clean
  deactivate
  sleep 5
  run_grpc_virtual_home_test
  run_cirque_grpc_clean
  deactivate
}

main

exit 0  
