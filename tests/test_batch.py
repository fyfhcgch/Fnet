"""Regression tests for the batch queue, pause/resume and merged reports."""
from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from fnet.app import build
from fnet.config import Config

DATA = Path(__file__).resolve().parent / "data"
PCAP = str(DATA / "http_ntlm.pcap")


class BatchQueueTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.patches = [
            mock.patch("fnet.jobs.CACHE_DIR", root / "cache"),
            mock.patch("fnet.paths.CACHE_DIR", root / "cache"),
        ]
        for patch in self.patches:
            patch.start()
        self.runtime = build(Config(root / "config.ini"))
        self.manager = self.runtime.jobs
        self.gate = threading.Event()
        self.lock = threading.Lock()
        self.active = 0
        self.peak = 0
        self.started: list[str] = []
        self.patch = None

    def tearDown(self):
        self.gate.set()
        if self.patch is not None:
            self.patch.stop()
        for patch in reversed(self.patches):
            patch.stop()
        for job in self.manager.list():
            job.cancel_event.set()
            if job.thread:
                job.thread.join(timeout=5)
        self.tmp.cleanup()

    def _slow_handler(self):
        def handler(ctx, name):
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
                self.started.append(name)
            self.gate.wait(20)
            with self.lock:
                self.active -= 1
        return handler

    def _wait_for(self, predicate, timeout=10):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return False

    def _wait_terminal(self, jobs, timeout=20):
        def done():
            return all(job.status in ("done", "error", "cancelled")
                       for job in jobs)
        self.assertTrue(self._wait_for(done, timeout),
                        [job.status for job in jobs])

    def test_concurrency_limit_is_respected(self):
        self.patch = mock.patch("fnet.jobs.call_feature",
                                side_effect=self._slow_handler())
        self.patch.start()
        jobs = self.manager.submit_batch([PCAP] * 4, ["checkBox_10"],
                                         concurrency=2)
        self.assertTrue(self._wait_for(
            lambda: self.peak == 2 and
            sum(1 for job in jobs if job.status == "running") == 2))
        self.assertEqual(self.peak, 2)
        self.assertEqual(sum(1 for job in jobs if job.status == "queued"), 2)
        self.gate.set()
        self._wait_terminal(jobs)
        self.assertLessEqual(self.peak, 2)
        self.assertEqual(sum(1 for job in jobs if job.status == "done"), 4)

    def test_pause_resume_and_queued_cancel(self):
        self.patch = mock.patch("fnet.jobs.call_feature",
                                side_effect=self._slow_handler())
        self.patch.start()
        jobs = self.manager.submit_batch([PCAP] * 3, ["checkBox_10"],
                                         concurrency=1)
        self.assertTrue(self._wait_for(
            lambda: jobs[0].status == "running"))
        summary = self.manager.pause_batch()
        self.assertTrue(summary["paused"])
        self.assertEqual(summary["queued"], 2)
        self.assertTrue(self.manager.cancel(jobs[2].id))
        self.assertEqual(jobs[2].status, "cancelled")
        self.gate.set()
        self.assertTrue(self._wait_for(
            lambda: jobs[0].status == "done"))
        # The paused queue must not start the remaining job on its own.
        time.sleep(0.2)
        self.assertEqual(jobs[1].status, "queued")
        summary = self.manager.resume_batch()
        self.assertFalse(summary["paused"])
        self._wait_terminal(jobs)
        self.assertEqual(jobs[1].status, "done")

    def test_reorder_queued_jobs(self):
        self.patch = mock.patch("fnet.jobs.call_feature",
                                side_effect=self._slow_handler())
        self.patch.start()
        jobs = self.manager.submit_batch([PCAP] * 4, ["checkBox_10"],
                                         concurrency=1)
        self.assertTrue(self._wait_for(lambda: jobs[0].status == "running"))
        self.manager.pause_batch()
        self.gate.set()
        self.assertTrue(self._wait_for(lambda: jobs[0].status == "done"))
        order = [jobs[3].id, jobs[1].id, jobs[2].id]
        summary = self.manager.reorder_batch(order)
        self.assertEqual(summary["pending"], order)
        self.manager.cancel(jobs[3].id)
        self.manager.cancel(jobs[1].id)
        self.manager.cancel(jobs[2].id)
        self._wait_terminal(jobs)

    def test_merged_report_contains_every_capture(self):
        self.patch = mock.patch("fnet.jobs.call_feature", return_value=None)
        self.patch.start()
        jobs = self.manager.submit_batch([PCAP, PCAP], ["checkBox_10"],
                                         concurrency=2)
        self._wait_terminal(jobs)
        report = self.manager.merged_report([job.id for job in jobs], "md")
        self.assertIsNotNone(report)
        self.assertTrue(report["filename"].endswith(".md"))
        self.assertEqual(report["count"], 2)
        self.assertIn("批量分析汇总", report["content"])
        self.assertIn("批量任务：http_ntlm.pcap", report["content"])
        html = self.manager.merged_report([job.id for job in jobs], "html")
        self.assertIn("<!doctype html>", html["content"])
        self.assertIn("http_ntlm.pcap", html["content"])

    def test_batch_snapshot_starts_empty(self):
        summary = self.manager.batch_summary()
        self.assertEqual(summary["total"], 0)
        self.assertFalse(summary["paused"])
        self.assertEqual(summary["pending"], [])


if __name__ == "__main__":
    unittest.main()
