# Copyright 2023 Google LLC
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

import queue
import threading
import time

from cirque.common.cirquelog import CirqueLog

class Task:
    def __init__(self, fn):
        self.fn = fn
        self.result = None
        self.completed = None
        self.exception = None
        self.cv = threading.Condition()

    def run(self):
        try:
            self.result = self.fn()
        except Exception as ex:
            self.exception = ex

        with self.cv:
            self.completed = True
            self.cv.notify_all()

    def wait(self):
        with self.cv:
            while not self.completed:
                self.cv.wait()
        if self.exception:
            raise self.exception
        return self.result

class _TaskRunner:
    def __init__(self):
        self.logger = CirqueLog.get_cirque_logger(self.__class__.__name__)
        self.queue_cv = threading.Condition()
        self.queue = queue.Queue()

    def post_task(self, fn) -> Task:
        task = Task(fn)
        with self.queue_cv:
            self.queue.put(task)
            self.queue_cv.notify()
            self.logger.info("Task sent to runner thread.")
        return task

    def start(self):
        self.running = True
        self.logger.info("Starting task runner.")
        self.th = threading.Thread(target=lambda:self._run())
        self.th.start()
        self.logger.info("Task runner started.")


    def stop(self):
        self.logger.info("Stopping runner thread.")
        with self.queue_cv:
            self.running = False
            self.queue_cv.notify()
        self.th.join()

    def _run(self):
        self.logger.info("Task runner running.")
        with self.queue_cv:
            while self.running:
                try:
                    task = self.queue.get_nowait()
                    self.logger.info("Handled task.")
                    taskStart = time.time()
                    task.run()
                    self.logger.info(f"Task handling duration: {time.time() - taskStart}s")
                except queue.Empty:
                    self.logger.info(f"No task")
                    pass
                self.queue_cv.wait()
        self.logger.info("Task runner stopped.")

TaskRunner = _TaskRunner()
