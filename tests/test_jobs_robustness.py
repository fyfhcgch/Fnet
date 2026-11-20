"""Robustness regressions for job persistence and input validation.

Covers cross-process ``--resume``, non-atomic artifact writes + unlocked
``job.json`` writes, and unparseable input being reported as success.
"""
from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from fnet import jobs_checkpoint
from fnet.app import build
from fnet.config import Config
from fnet.findings import make

DATA = Path(__file__).resolve().parent / "data"
PCAP = str(DATA / "http_ntlm.pcap")


class IsolatedCacheTest(unittest.TestCase):
    """Base class: patch BOTH cache bindings (see AGENTS.md)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cache = self.root / "cache"
        self.cache.mkdir(parents=True, exist_ok=True)
        for patch in (mock.patch("fnet.jobs.CACHE_DIR", self.cache),
                      mock.patch("fnet.paths.CACHE_DIR", self.cache)):
            patch.start()
            self.addCleanup(patch.stop)
        self.runtime = build(Config(self.root / "config.ini"))
        self.manager = self.runtime.jobs

    def wait_for(self, predicate, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return False

    def write_job_json(self, job_id: str, **fields) -> Path:
        output = self.cache / "jobs" / job_id
        output.mkdir(parents=True, exist_ok=True)
        data = {"id": job_id, "pcap": PCAP, "pcap_name": Path(PCAP).name,
                "features": ["checkBox_10"], "params": {},
                "created": "2026-01-01T00:00:00"}
        data.update(fields)
        (output / "job.json").write_text(json.dumps(data, ensure_ascii=False),
                                         encoding="utf-8")
        return output


class ResumeNormalisationTest(IsolatedCacheTest):
    """B4: a crashed job's ``job.json`` must come back as ``interrupted``."""

    def test_load_from_history_normalises_running(self):
        job_id = "a1b2c3d4e5f60718"
        self.write_job_json(job_id, status="running", progress=42,
                            completed=["checkBox_10"])
        job = jobs_checkpoint.load_from_history(job_id)
        self.assertIsNotNone(job)
        self.assertEqual(job.status, "interrupted")
        self.assertTrue(job.can_resume, "cross-process --resume must work")

    def test_load_from_history_normalises_queued(self):
        job_id = "0f1e2d3c4b5a6978"
        self.write_job_json(job_id, status="queued")
        job = jobs_checkpoint.load_from_history(job_id)
        self.assertIsNotNone(job)
        self.assertEqual(job.status, "interrupted")
        self.assertTrue(job.can_resume)

    def test_load_from_history_keeps_terminal_status(self):
        job_id = "1111222233334444"
        self.write_job_json(job_id, status="done", progress=100)
        job = jobs_checkpoint.load_from_history(job_id)
        self.assertEqual(job.status, "done")
        self.assertFalse(job.can_resume)

    def test_disk_entries_skip_active_jobs(self):
        active_id, dead_id = "aaaa000011112222", "bbbb000011112222"
        self.write_job_json(active_id, status="running")
        self.write_job_json(dead_id, status="running")
        entries = jobs_checkpoint.load_disk_entries({active_id})
        self.assertEqual(entries[active_id]["status"], "running")
        self.assertEqual(entries[dead_id]["status"], "interrupted")

    def test_manager_resume_recovers_crashed_job(self):
        job_id = "cccc000011112222"
        self.write_job_json(job_id, status="running", progress=50,
                            completed=["checkBox_10"],
                            feature_status={"checkBox_10": "done"})
        job = self.manager.resume(job_id)
        self.assertIsNotNone(job, "manager.resume must accept a crashed job")
        self.assertTrue(self.wait_for(
            lambda: job.status in ("done", "error", "cancelled")),
            job.status)
        if job.thread is not None:
            job.thread.join(timeout=10)


class AtomicWriteTest(IsolatedCacheTest):
    """B5: a crash mid-write must leave the previous file intact."""

    def test_history_write_survives_crash(self):
        job = self.manager.create(PCAP, ["checkBox_10"], {})
        path = job.output_dir / "job.json"
        self.assertTrue(path.is_file())
        before = path.read_text(encoding="utf-8")
        self.assertIn('"id"', before)

        job.progress = 66
        original = Path.write_text

        def exploding(self, data, *args, **kwargs):
            if self.name.startswith(".job.json."):
                original(self, str(data)[: max(1, len(str(data)) // 2)],
                         *args, **kwargs)
                raise OSError("模拟写入过程中崩溃")
            return original(self, data, *args, **kwargs)

        with mock.patch.object(Path, "write_text", exploding):
            jobs_checkpoint.write_history(job)

        self.assertEqual(path.read_text(encoding="utf-8"), before,
                         "a failed write must not truncate job.json")
        self.assertNotIn('"progress": 66', path.read_text(encoding="utf-8"))
        leftovers = [item.name for item in job.output_dir.iterdir()
                     if item.name.endswith(".tmp")]
        self.assertEqual(leftovers, [], "the temporary file must be cleaned up")

    def test_history_write_replaces_content_atomically(self):
        job = self.manager.create(PCAP, ["checkBox_10"], {})
        path = job.output_dir / "job.json"
        job.progress = 73
        with mock.patch.object(jobs_checkpoint.os, "replace",
                               wraps=jobs_checkpoint.os.replace) as replace:
            jobs_checkpoint.write_history(job)
        self.assertEqual(replace.call_count, 1)
        source, target = replace.call_args[0]
        # The temp file must live next to the destination, so ``os.replace``
        # stays on one filesystem and therefore atomic.
        self.assertEqual(Path(source).parent, path.parent)
        self.assertEqual(Path(target), path)
        stored = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(stored["progress"], 73)
        self.assertEqual(
            [item.name for item in job.output_dir.iterdir()
             if item.name.endswith(".tmp")], [])

    def test_annotation_write_is_atomic(self):
        job = self.manager.create(PCAP, ["checkBox_10"], {})
        job.findings = [make("flag", "flag{atomic}")]
        result = self.manager.set_annotation(job.id, 1, "starred", "重点")
        self.assertTrue(result["ok"])
        path = job.output_dir / "annotations.json"
        self.assertTrue(path.is_file())
        stored = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(stored["1"]["status"], "starred")

    def test_findings_json_write_is_atomic(self):
        job = self.manager.create(PCAP, ["checkBox_10"], {})
        job.findings = [make("flag", "flag{findings}")]
        self.manager._write_findings(job)
        for name in ("findings.json", "findings.csv"):
            self.assertTrue((job.output_dir / name).is_file(), name)
        stored = json.loads(
            (job.output_dir / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["count"], 1)

    def test_history_writes_are_serialised_per_job(self):
        job = self.manager.create(PCAP, ["checkBox_10"], {})
        calls = []
        real = jobs_checkpoint.write_history

        def slow(target):
            calls.append(("enter", threading.get_ident()))
            time.sleep(0.05)
            real(target)
            calls.append(("exit", threading.get_ident()))

        with mock.patch.object(jobs_checkpoint, "write_history", slow):
            threads = [threading.Thread(target=self.manager._write_history,
                                        args=(job,)) for _ in range(4)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=10)

        # Every enter must be immediately followed by its own exit: no two
        # writers may interleave inside write_history.
        for index in range(0, len(calls), 2):
            self.assertEqual(calls[index][0], "enter")
            self.assertEqual(calls[index + 1][0], "exit")
            self.assertEqual(calls[index][1], calls[index + 1][1])
        self.assertEqual(len(calls), 8)


class FindingsSerialisationTest(IsolatedCacheTest):
    """B5/A6: a non-serialisable finding must not wedge the worker."""

    def test_non_serialisable_finding_is_stringified(self):
        job = self.manager.create(PCAP, ["checkBox_10"], {})
        job.findings = [make("flag", "flag{serialisable}")]
        job.findings[0]["extra"] = {"blob": object()}
        self.manager._write_findings(job)
        stored = json.loads(
            (job.output_dir / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["count"], 1)
        self.assertIn("blob", stored["findings"][0]["extra"])

    def test_unexpected_worker_error_marks_job_error(self):
        job = self.manager.create(PCAP, ["checkBox_10"], {})

        def boom(_job):
            raise TypeError("不可序列化的结果")

        with mock.patch.object(self.manager, "_run_job", side_effect=boom):
            self.manager.start(job)
            job.thread.join(timeout=10)

        self.assertEqual(job.status, "error")
        self.assertIn("任务执行失败", job.error)
        self.assertIsNotNone(job.finished)
        # The failure must be persisted so a restart sees the terminal state.
        stored = json.loads(
            (job.output_dir / "job.json").read_text(encoding="utf-8"))
        self.assertEqual(stored["status"], "error")
        text = "\n".join(record.line for record in job.log.records_since(0))
        self.assertIn("任务执行失败", text)


def _minimal_pcap() -> bytes:
    """Global header + one ARP frame: a capture tshark reads without complaint."""
    import struct

    global_header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    frame = (bytes.fromhex("ffffffffffff0011223344550806") + b"\x00" * 28)
    record = struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame
    return global_header + record


class CorruptInputTest(IsolatedCacheTest):
    """A6: unparseable captures must fail loudly instead of "succeeding"."""

    def _garbage(self, name="corrupt.pcap") -> Path:
        path = self.root / name
        path.write_bytes(b"garbage")
        return path

    def test_garbage_pcap_is_rejected(self):
        path = self._garbage()
        with self.assertRaises(ValueError) as raised:
            self.manager.create(str(path), ["checkBox_10"], {})
        self.assertIn("无法解析抓包", str(raised.exception))

    def test_text_renamed_to_pcap_is_rejected(self):
        path = self.root / "notes.pcap"
        path.write_text("这不是抓包，只是一段文字。\n", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.manager.create(str(path), ["checkBox_10"], {})

    def test_truncated_capture_still_runs(self):
        path = self.root / "truncated.pcap"
        # Valid magic + a half-written record: tshark exits 3 but the file is
        # recognisably a capture, so it must still be analysable.
        path.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 8)
        job = self.manager.create(str(path), ["checkBox_10"], {})
        self.assertEqual(job.kind, "pcap")

    def test_damaged_capture_runs_with_input_warning(self):
        """Valid magic but unreadable frames: run, but warn loudly."""
        path = self.root / "damaged.pcapng"
        # pcapng magic + a bogus section header: tshark exits 3 with
        # "appears to be damaged or corrupt", yet this is a real capture.
        path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x1c\x00\x00\x00"
                         + b"\x4d\x3c\x2b\x1a" + b"\x01\x00\x00\x00"
                         + b"\xff" * 64)
        job = self.manager.create(str(path), ["checkBox_10"], {})
        self.assertEqual(job.kind, "pcap")
        self.assertTrue(job.input_warning, "损坏抓包必须给出输入警告")
        self.assertIn("损坏", job.input_warning)
        # The warning is surfaced in the API payload and the txt report.
        self.assertEqual(job.as_dict()["input_warning"], job.input_warning)
        self.manager._write_report(job, status="done")
        report = (job.output_dir / "report.txt").read_text(encoding="utf-8")
        self.assertIn("输入警告", report)

    def test_healthy_capture_has_no_warning(self):
        """A well-formed capture must not be flagged as damaged."""
        path = self.root / "tiny.pcap"
        path.write_bytes(_minimal_pcap())
        job = self.manager.create(str(path), ["checkBox_10"], {})
        self.assertEqual(job.input_warning, "")

    def test_log_input_is_exempt_from_capture_validation(self):
        path = self.root / "access.log"
        path.write_text("2024-12-02 14:18:11 request ok\n", encoding="utf-8")
        job = self.manager.create(str(path), ["checkBox_10"], {})
        self.assertEqual(job.kind, "log")

    def test_cli_exit_code_is_non_zero_for_corrupt_input(self):
        import contextlib
        import io

        from fnet.cli import run_headless

        path = self._garbage()
        args = mock.Mock(
            capture=str(path), cli=True, features="checkBox_10", all=False,
            param=[], json=True, rules="", shards=1, resume="", compare=None,
            wpa_psk="", mcp=False, pcap_over_ip=None, keytab="",
            kerberos_password="", kerberos_key="", config=None, host=None,
            port=None, no_browser=True, list_features=False,
            list_tools=False, doctor=False, version=False)
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), \
                contextlib.redirect_stdout(io.StringIO()):
            code = run_headless(args, self.runtime)
        self.assertEqual(code, 2)
        self.assertIn("无法解析抓包", stderr.getvalue())

    def test_webui_analyze_reports_corrupt_input(self):
        """``POST /api/analyze`` maps the ValueError to a 400 (not a 500)."""
        from fnet.webui.server import make_server

        server = make_server(self.runtime.app, "127.0.0.1", 0)
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.05},
            daemon=True)
        thread.start()
        try:
            path = self._garbage("bad.pcap")
            body = json.dumps({"pcap": str(path),
                               "features": ["checkBox_10"]}).encode()
            request = urllib.request.Request(
                f"http://127.0.0.1:{server.server_address[1]}/api/analyze",
                data=body, headers={
                    "Content-Type": "application/json",
                    "X-Fnet-Token": self.runtime.app.token})
            with self.assertRaises(urllib.error.HTTPError) as raised:
                urllib.request.urlopen(request, timeout=30)
            self.assertEqual(raised.exception.code, 400)
            try:
                payload = json.loads(raised.exception.read().decode("utf-8"))
            finally:
                raised.exception.close()
            self.assertFalse(payload["ok"])
            self.assertIn("无法解析抓包", payload["error"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
