"""Unit tests for fnet.logger (levels, history, listeners, JobLog)."""
from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from fnet.logger import LEVEL_TAGS, JobLog, LogRecord, Logger


class LogRecordTest(unittest.TestCase):
    def test_line_and_tag(self):
        record = LogRecord(1, "12:00:00", "good", "ok")
        self.assertEqual(record.tag, "[+]")
        self.assertEqual(record.line, "12:00:00 [+] ok")
        self.assertEqual(record.as_dict(), {
            "seq": 1, "time": "12:00:00", "level": "good",
            "tag": "[+]", "text": "ok"})

    def test_unknown_level_falls_back_to_info_tag(self):
        record = LogRecord(1, "12:00:00", "bogus", "text")
        self.assertEqual(record.tag, "[*]")

    def test_all_levels_have_tags(self):
        for level in ("debug", "info", "good", "warn", "error"):
            self.assertIn(level, LEVEL_TAGS)


class LoggerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-log-"))
        self.path = self.tmp / "fnet.log"
        self.logger = Logger(path=self.path)

    def test_log_writes_file_and_memory(self):
        self.logger.good("第一条")
        self.logger.warn("第二条")
        self.assertEqual(self.logger.last_seq, 2)
        content = self.path.read_text("utf-8")
        self.assertIn("[+] 第一条", content)
        self.assertIn("[!] 第二条", content)
        records = self.logger.records_since(0)
        self.assertEqual([r.text for r in records], ["第一条", "第二条"])

    def test_invalid_level_is_coerced_to_info(self):
        self.logger.log("文本", "bogus")
        self.assertEqual(self.logger.records_since(0)[0].level, "info")

    def test_records_since_cursor(self):
        for index in range(5):
            self.logger.info(f"line-{index}")
        records = self.logger.records_since(2)
        self.assertEqual([r.text for r in records],
                         ["line-2", "line-3", "line-4"])
        self.assertEqual(self.logger.records_since(99), [])

    def test_records_since_limit(self):
        for index in range(10):
            self.logger.info(f"line-{index}")
        self.assertEqual(len(self.logger.records_since(0, limit=3)), 3)

    def test_history_and_tail(self):
        for index in range(5):
            self.logger.info(f"line-{index}")
        history = self.logger.history()
        self.assertEqual(len(history), 5)
        self.assertTrue(history[0].endswith("line-0"))
        tail = self.logger.tail(2)
        self.assertEqual([r.text for r in tail], ["line-3", "line-4"])

    def test_subscriber_receives_records(self):
        received: list[LogRecord] = []
        self.logger.subscribe(received.append)
        self.logger.info("订阅消息")
        self.assertEqual([r.text for r in received], ["订阅消息"])
        self.logger.unsubscribe(received.append)
        self.logger.info("取消后")
        self.assertEqual([r.text for r in received], ["订阅消息"])

    def test_broken_subscriber_does_not_break_logging(self):
        def broken(record):
            raise RuntimeError("listener bug")
        self.logger.subscribe(broken)
        self.logger.info("不应崩溃")
        self.assertEqual(self.logger.records_since(0)[0].text, "不应崩溃")
        self.logger.unsubscribe(broken)

    def test_clear_removes_history_and_file(self):
        self.logger.info("临时")
        self.logger.clear()
        self.assertEqual(self.logger.records_since(0), [])
        self.assertFalse(self.path.exists())

    def test_echo_prints_to_stdout(self):
        echoed = Logger(path=self.tmp / "echo.log", echo=True)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            echoed.info("echo-text")
        self.assertIn("[*] echo-text", buffer.getvalue())

    def test_in_memory_history_respects_keep(self):
        tiny = Logger(path=self.tmp / "tiny.log", keep=3)
        for index in range(6):
            tiny.info(f"line-{index}")
        self.assertEqual([r.text for r in tiny.records_since(0)],
                         ["line-3", "line-4", "line-5"])


class JobLogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-log-"))
        self.sink = Logger(path=self.tmp / "sink.log")
        self.job = JobLog(self.sink, prefix="42")

    def test_forward_to_sink_with_prefix(self):
        self.job.good("任务开始")
        record = self.job.records_since(0)[0]
        self.assertEqual(record.text, "任务开始")
        self.assertEqual(record.tag, "[+]")
        forwarded = self.sink.records_since(0)[0]
        self.assertEqual(forwarded.text, "[job:42] 任务开始")

    def test_records_since_cursor(self):
        for index in range(4):
            self.job.info(f"step-{index}")
        self.assertEqual([r.text for r in self.job.records_since(2)],
                         ["step-2", "step-3"])

    def test_seed_restores_sequences(self):
        self.job.seed([
            {"seq": 3, "time": "10:00:00", "level": "info", "text": "恢复-1"},
            {"seq": 0, "time": "", "level": "good", "text": "恢复-2"},
        ])
        records = self.job.records_since(0)
        self.assertEqual([r.seq for r in records], [3, 4])
        self.assertEqual(self.job.last_seq, 4)
        # New records continue after the restored cursor.
        self.job.info("新增")
        self.assertEqual(self.job.records_since(4)[0].text, "新增")

    def test_seed_accepts_log_records(self):
        self.job.seed([LogRecord(7, "09:00:00", "warn", "对象形式")])
        record = self.job.records_since(0)[0]
        self.assertEqual(record.text, "对象形式")
        self.assertEqual(record.seq, 7)

    def test_invalid_level_coerced(self):
        self.job.log("文本", "bogus")
        self.assertEqual(self.job.records_since(0)[0].level, "info")


if __name__ == "__main__":
    unittest.main()
