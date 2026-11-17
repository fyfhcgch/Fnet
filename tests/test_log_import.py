"""Tests for the ``forensics.log_import`` feature (checkBox_54).

The handler is fed sample Suricata ``eve.json`` and Zeek ``conn.log`` text
directly through the ``log_text`` / ``log_path`` parameters, so no tshark or
pcap is needed.
"""
from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path

from fnet.config import Config
from fnet.features import forensics
from fnet.features.registry import FeatureContext
from fnet.logger import Logger
from fnet.utils import evidence

EVE_TEXT = "\n".join([
    '{"timestamp":"2026-01-01T10:00:00.000000+0000","event_type":"alert",'
    '"src_ip":"192.168.1.50","src_port":49213,"dest_ip":"10.0.0.8",'
    '"dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,'
    '"signature_id":2010000,"rev":1,"signature":"ET MALWARE Suspicious C2",'
    '"severity":1}}',
    '{"timestamp":"2026-01-01T10:00:01.000000+0000","event_type":"http",'
    '"src_ip":"192.168.1.50","src_port":49213,"dest_ip":"93.184.216.34",'
    '"dest_port":80,"proto":"TCP","http":{"http_method":"GET",'
    '"hostname":"example.com","url":"/"}}',
    '{"timestamp":"2026-01-01T10:00:02.000000+0000","event_type":"dns",'
    '"src_ip":"192.168.1.50","dest_ip":"8.8.8.8","proto":"UDP",'
    '"dns":{"rrname":"evil.example.net"}}',
    "not a json line",
    "",
]) + "\n"

ZEEK_TEXT = "\n".join([
    "#separator \\x09",
    "#set_separator\t,",
    "#empty_field\t(empty)",
    "#unset_field\t-",
    "#path\tconn",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\t"
    "service\tduration\tconn_state",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenumerated\tstring\t"
    "interval\tstring",
    "1700000000.000000\tCXWfTK3LR9u2S8B1a\t192.168.1.50\t49213\t10.0.0.8\t"
    "80\ttcp\thttp\t0.001\tSF",
    "1700000001.000000\tCXWfTK3LR9u2S8B1b\t192.168.1.51\t51000\t8.8.8.8\t53\t"
    "udp\tdns\t0.02\tSF",
]) + "\n"

GARBAGE_TEXT = "2026-01-01 INFO something happened\n2026-01-01 INFO other\n"

FINDING_IP = "192.168.1.50"


def finding(summary: str, detail: str = "", extra: dict | None = None) -> dict:
    return {"kind": "http", "summary": summary, "detail": detail,
            "frame": "3", "feature": "http.extract", "level": "info",
            "time": "12:00:00", "extra": extra or {}}


def make_ctx(tmp: str, params: dict, findings: list | None = None) -> \
        tuple[FeatureContext, Path]:
    logger = Logger(Path(tmp) / "test.log")
    out_dir = Path(tmp) / "out"
    ctx = FeatureContext(
        config=Config(Path(tmp) / "config.ini"), logger=logger,
        tshark=None, pcap="", params=params, output_dir=out_dir,
        findings=list(findings or []))
    return ctx, out_dir


def log_text(ctx: FeatureContext) -> str:
    return "\n".join(record.line for record in ctx.logger.records_since(0))


class LogImportHandlerTest(unittest.TestCase):
    """Run the handler in-process against pasted log text."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ctx, self.out_dir = make_ctx(self.tmp.name, {}, [
            finding(f"HTTP 请求来自 {FINDING_IP}", "GET /"),
        ])

    def tearDown(self):
        self.tmp.cleanup()

    def run_handler(self, params: dict):
        self.ctx.params = params
        forensics.log_import(self.ctx)

    def test_eve_json_normalized_and_correlated(self):
        self.run_handler({"log_text": EVE_TEXT})
        text = log_text(self.ctx)
        self.assertIn("日志格式识别为 suricata", text)
        self.assertIn("共归一化 3 条事件", text)
        # 三条事件的 src 都是 FINDING_IP，全部命中
        self.assertIn("与流量发现相关的事件（3 条）", text)
        self.assertIn("ET MALWARE Suspicious C2", text)
        rules = [item for item in self.ctx.findings
                 if item["kind"] == "rule" and "日志证据" in item["summary"]]
        self.assertEqual(len(rules), 3)
        self.assertIn(FINDING_IP, rules[0]["detail"])
        sigs = [item for item in self.ctx.findings
                if item["kind"] == "rule" and "告警签名" in item["summary"]]
        self.assertEqual(len(sigs), 1)
        csv_path = self.out_dir / "log_import_events.csv"
        self.assertTrue(csv_path.is_file())
        rows = csv_path.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(rows), 4)  # header + 3 events
        self.assertIn("是", rows[1])

    def test_zeek_tsv_normalized(self):
        self.run_handler({"log_text": ZEEK_TEXT})
        text = log_text(self.ctx)
        self.assertIn("日志格式识别为 zeek", text)
        self.assertIn("共归一化 2 条事件", text)
        # 与 FINDING_IP 的发现相关
        self.assertIn("与流量发现相关的事件（1 条）", text)
        # ts 被格式化为 UTC 可读时间
        self.assertIn("2023-11-14 22:13:20", text)
        rules = [item for item in self.ctx.findings
                 if item["kind"] == "rule" and "日志证据" in item["summary"]]
        self.assertEqual(len(rules), 1)

    def test_bad_format_reports_clear_error(self):
        self.run_handler({"log_text": GARBAGE_TEXT})
        text = log_text(self.ctx)
        self.assertIn("无法识别日志格式", text)
        self.assertIn("eve.json", text)
        self.assertIn("#fields", text)

    def test_missing_source_reports_error(self):
        self.run_handler({})
        self.assertIn("未提供日志", log_text(self.ctx))

    def test_log_path_is_read(self):
        path = Path(self.tmp.name) / "eve.json"
        path.write_text(EVE_TEXT, encoding="utf-8")
        self.run_handler({"log_path": str(path)})
        self.assertIn("共归一化 3 条事件", log_text(self.ctx))

    def test_missing_path_reports_error(self):
        self.run_handler({"log_path": str(
            Path(self.tmp.name) / "nope.json")})
        self.assertIn("日志文件不存在", log_text(self.ctx))

    def test_no_findings_still_normalizes(self):
        self.ctx.findings = []
        self.run_handler({"log_text": EVE_TEXT})
        text = log_text(self.ctx)
        self.assertIn("共归一化 3 条事件", text)
        self.assertIn("没有流量发现", text)


class LogImportUnitTests(unittest.TestCase):
    """归一化/关联由 evidence 提供，这里锁定格式探测与历史列名映射。"""

    def test_detect_format(self):
        self.assertEqual(evidence.detect_format(EVE_TEXT), "suricata")
        self.assertEqual(evidence.detect_format(ZEEK_TEXT), "zeek")
        self.assertIsNone(evidence.detect_format(GARBAGE_TEXT))
        self.assertIsNone(evidence.detect_format(""))

    def test_map_suricata_event_columns(self):
        events = evidence.parse_events(EVE_TEXT)
        self.assertEqual(len(events), 3)
        alert = forensics.map_event(events[0])
        self.assertEqual(alert["format"], "suricata")
        self.assertEqual(alert["event_type"], "alert")
        self.assertEqual(alert["severity"], "high")
        self.assertEqual(alert["signature"], "ET MALWARE Suspicious C2")
        self.assertEqual(alert["src"], "192.168.1.50")
        self.assertEqual(alert["sport"], "49213")
        self.assertEqual(alert["dst"], "10.0.0.8")
        self.assertEqual(alert["dport"], "80")
        dns = forensics.map_event(events[2])
        self.assertIn("evil.example.net", dns["summary"])
        self.assertEqual(dns["severity"], "info")
        self.assertEqual(dns["dport"], "")

    def test_map_zeek_event_columns(self):
        events = evidence.parse_events(ZEEK_TEXT)
        self.assertEqual(len(events), 2)
        row = forensics.map_event(events[0])
        self.assertEqual(row["format"], "zeek")
        self.assertEqual(row["src"], "192.168.1.50")
        self.assertEqual(row["sport"], "49213")
        self.assertEqual(row["dport"], "80")
        self.assertEqual(row["proto"], "tcp")
        self.assertEqual(row["event_type"], "conn")
        self.assertEqual(row["time"], "2023-11-14 22:13:20")
        self.assertEqual(row["severity"], "info")

    def test_invalid_octets_are_not_indicators(self):
        self.assertNotIn("999.1.2.3",
                         evidence.extract_ips("版本 999.1.2.3 更新"))


def parity_finding() -> dict:
    """Capture-side finding aligned with ``EVE_TEXT`` (2026-01-01 10:00Z)."""
    return {"kind": "http", "summary": "HTTP 请求来自 192.168.1.50",
            "detail": "GET / 目标 93.184.216.34:80", "frame": "3",
            "feature": "http.extract", "level": "info",
            "time": "10:00:01", "capture": "2026-01-01 10:00:01"}


class LogImportEvidenceParityTest(unittest.TestCase):
    """Handler 输出必须与直接调用 evidence.correlate 的结果一致。

    回归目标：handler 只做字段映射，解析/关联不允许再出现第二套实现。
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.findings = [parity_finding()]
        self.ctx, self.out_dir = make_ctx(
            self.tmp.name, {"log_text": EVE_TEXT}, self.findings)

    def tearDown(self):
        self.tmp.cleanup()

    def run_handler(self, params: dict):
        self.ctx.params = params
        forensics.log_import(self.ctx)

    def expected_related(self, **kwargs) -> list[int]:
        pairs = evidence.correlate(
            evidence.parse_events(EVE_TEXT), self.findings,
            window=kwargs.get("window", evidence.DEFAULT_WINDOW),
            min_score=kwargs.get("min_score",
                                 forensics.DEFAULT_LOG_MIN_SCORE))
        return sorted({pair["event_index"] for pair in pairs})

    def csv_rows(self) -> list[list[str]]:
        text = (self.out_dir / "log_import_events.csv").read_text(
            encoding="utf-8")
        return list(csv.reader(text.splitlines()))

    def test_related_events_match_correlate(self):
        expected = self.expected_related()
        self.assertEqual(expected, [0, 1, 2])
        self.run_handler({"log_text": EVE_TEXT})
        self.assertIn(f"与流量发现相关的事件（{len(expected)} 条）",
                      log_text(self.ctx))
        rows = self.csv_rows()
        marked = [index for index, row in enumerate(rows[1:])
                  if row[-1] == "是"]
        self.assertEqual(marked, expected)

    def test_time_window_rejects_far_events(self):
        self.findings[0]["capture"] = "2026-01-01 18:00:00"
        expected = self.expected_related()
        self.assertEqual(expected, [])
        self.run_handler({"log_text": EVE_TEXT})
        self.assertIn("没有 IP/端口交集", log_text(self.ctx))
        rows = self.csv_rows()
        self.assertEqual(rows[1][-1], "")

    def test_window_param_widens_correlation(self):
        self.findings[0]["capture"] = "2026-01-01 18:00:00"
        expected = self.expected_related(window=36000)
        self.assertEqual(expected, [0, 1, 2])
        self.run_handler({"log_text": EVE_TEXT, "log_window": "36000"})
        self.assertIn(f"与流量发现相关的事件（{len(expected)} 条）",
                      log_text(self.ctx))

    def test_csv_cells_follow_evidence_events(self):
        self.run_handler({"log_text": EVE_TEXT})
        rows = self.csv_rows()
        self.assertEqual(rows[0], ["序号", "时间", "格式", "事件类型", "源IP",
                                   "源端口", "目的IP", "目的端口", "协议",
                                   "严重级别", "摘要", "与流量发现相关"])
        events = evidence.parse_events(EVE_TEXT)
        self.assertEqual(len(rows) - 1, len(events))
        for position, (row, event) in enumerate(zip(rows[1:], events)):
            self.assertEqual(row[0], str(position + 1))
            self.assertEqual(row[2], event["source"].split(":", 1)[0])
            self.assertEqual(row[3], event["type"])
            self.assertEqual(row[4], event["src_ip"])
            self.assertEqual(row[5], "" if event["src_port"] is None
                             else str(event["src_port"]))
            self.assertEqual(row[6], event["dst_ip"])
            self.assertEqual(row[7], "" if event["dst_port"] is None
                             else str(event["dst_port"]))
            self.assertEqual(row[8], event["proto"])
            self.assertEqual(row[10], event["summary"])


if __name__ == "__main__":
    unittest.main()
