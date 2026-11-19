"""Log-file ingestion and the new log feature category."""
from __future__ import annotations

import ast
import csv as csv_mod
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fnet.config import Config
from fnet.features import logs, text_scan
from fnet.features.registry import (
    FEATURES, FeatureContext, default_features_for,
)
from fnet.jobs import JobManager
from fnet.logger import Logger
from fnet.utils import logfile


CEPH_LINES = [
    "2024-12-02T14:00:01 ceph: Client operation, ClientID: client1, "
    "Operation: Read, Key: key_aaaa, Client IP: 192.168.1.10 ",
    "2024-12-02T14:00:02 ceph: Client operation, ClientID: client1, "
    "Operation: Read, Key: Invalid key, Client IP: 192.168.1.10 ",
    "2024-12-02T14:00:03 ceph: Client operation, ClientID: client2, "
    "Operation: Read, Key: Invalid key, Client IP: 192.168.1.11 ",
    "2024-12-02T14:00:04 ceph: Client operation, ClientID: client2, "
    "Operation: Delete, Key: key_bbbb, Client IP: 192.168.1.11 ",
]

SYSLOG_TEXT = (
    "Dec  2 14:18:11 web01 sshd[1234]: Failed password for invalid user root "
    "from 10.0.0.5 port 5555 ssh2\n"
    "Dec  2 14:18:12 web01 sshd[1234]: Accepted password for alice from "
    "10.0.0.6 port 2222 ssh2\n"
)

APACHE_TEXT = (
    '10.0.0.5 - - [02/Dec/2024:14:18:11 +0800] "GET /index.php?id=1 '
    'HTTP/1.1" 200 512 "-" "curl/8.0"\n'
    '10.0.0.5 - - [02/Dec/2024:14:18:12 +0800] "POST /login HTTP/1.1" '
    '500 0 "-" "curl/8.0"\n'
)


def make_ctx(tmp: str, path: str, params: dict | None = None) -> FeatureContext:
    logger = Logger(Path(tmp) / "test.log")
    return FeatureContext(
        config=Config(Path(tmp) / "config.ini"), logger=logger,
        tshark=None, pcap=path, params=dict(params or {}),
        output_dir=Path(tmp) / "out", findings=[], input_kind="log")


def log_text(ctx: FeatureContext) -> str:
    return "\n".join(record.line for record in ctx.logger.records_since(0))


class ClassifyInputTest(unittest.TestCase):
    def test_suffix_and_magic(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "ceph.log"
            log_path.write_text("hello\n", encoding="utf-8")
            self.assertEqual(logfile.classify_input(log_path), "log")

            pcap = Path(tmp) / "x.pcapng"
            pcap.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 8)
            self.assertEqual(logfile.classify_input(pcap), "pcap")

            unknown = Path(tmp) / "capture.bin"
            unknown.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 8)
            self.assertEqual(logfile.classify_input(unknown), "pcap")

            binary = Path(tmp) / "blob.bin"
            binary.write_bytes(b"\x00\x01\x02\x03")
            self.assertIsNone(logfile.classify_input(binary))


class LogParsingTest(unittest.TestCase):
    def test_ceph_fields_and_severity(self):
        parsed = logfile.parse_text("\n".join(CEPH_LINES), "ceph.log")
        self.assertEqual(parsed.format, "ceph")
        self.assertEqual(len(parsed.records), 4)
        invalid = parsed.records[1]
        self.assertEqual(invalid.fields["client_id"], "client1")
        self.assertEqual(invalid.fields["key"], "Invalid key")
        self.assertEqual(invalid.fields["client_ip"], "192.168.1.10")
        self.assertEqual(invalid.level, "warn")
        self.assertEqual(invalid.ips, ("192.168.1.10",))
        self.assertEqual(parsed.timespan()[0], "2024-12-02 14:00:01")
        self.assertIn("client_id", parsed.fields)

    def test_sshd_extracts_authentication(self):
        parsed = logfile.parse_text(SYSLOG_TEXT, "auth.log")
        self.assertEqual(parsed.format, "sshd")
        failed, accepted = parsed.records
        self.assertEqual(failed.fields["user"], "root")
        self.assertEqual(failed.fields["ip"], "10.0.0.5")
        self.assertEqual(failed.fields["auth_result"], "failed")
        self.assertEqual(failed.level, "warn")
        self.assertEqual(accepted.fields["auth_result"], "accepted")
        self.assertEqual(accepted.level, "good")

    def test_apache_combined(self):
        parsed = logfile.parse_text(APACHE_TEXT, "access.log")
        self.assertEqual(parsed.format, "apache")
        first, second = parsed.records
        self.assertEqual(first.fields["method"], "GET")
        self.assertEqual(first.fields["path"], "/index.php?id=1")
        self.assertEqual(first.fields["status"], "200")
        self.assertEqual(second.level, "error")
        self.assertEqual(parsed.records[0].time, "2024-12-02 14:18:11")

    def test_json_lines(self):
        text = ('{"timestamp": "2024-12-02T14:18:11Z", "level": "error", '
                '"service": "api", "message": "boom", '
                '"client": {"ip": "1.2.3.4"}}\n')
        parsed = logfile.parse_text(text, "app.jsonl")
        self.assertEqual(parsed.format, "jsonl")
        record = parsed.records[0]
        self.assertEqual(record.level, "error")
        self.assertEqual(record.source, "api")
        self.assertEqual(record.message, "boom")
        self.assertEqual(record.fields["client.ip"], "1.2.3.4")
        self.assertIn("1.2.3.4", record.ips)

    def test_csv_header(self):
        text = ("time,user,action,ip\n"
                "2024-12-02 14:18:11,alice,login,1.2.3.4\n")
        parsed = logfile.parse_text(text, "events.csv")
        self.assertEqual(parsed.format, "csv")
        self.assertEqual(parsed.records[0].fields["user"], "alice")
        self.assertEqual(parsed.records[0].time, "2024-12-02 14:18:11")

    def test_plain_generic_timestamp(self):
        parsed = logfile.parse_text(
            "2024-12-02 14:18:11 something happened from 1.2.3.4\n",
            "misc.log")
        self.assertEqual(parsed.format, "plain")
        self.assertEqual(parsed.records[0].time, "2024-12-02 14:18:11")
        self.assertEqual(parsed.records[0].ips, ("1.2.3.4",))

    def test_limit_truncates(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "many.log"
            path.write_text("\n".join(CEPH_LINES * 5), encoding="utf-8")
            parsed = logfile.parse_path(path, limit=3)
            self.assertTrue(parsed.truncated)
            self.assertEqual(len(parsed.records), 3)


class LogFeatureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ceph.log"
        self.path.write_text("\n".join(CEPH_LINES * 10), encoding="utf-8")
        self.ctx = make_ctx(self.tmp.name, str(self.path))

    def tearDown(self):
        self.tmp.cleanup()

    def test_summary(self):
        logs.summary(self.ctx)
        text = log_text(self.ctx)
        self.assertIn("日志格式: Ceph 审计日志", text)
        self.assertIn("解析记录 40 条", text)
        self.assertTrue((Path(self.tmp.name) / "out" / "log_fields.csv").is_file())
        kinds = {item["kind"] for item in self.ctx.findings}
        self.assertEqual(kinds, {"log"})
        by_summary = {item["summary"]: item for item in self.ctx.findings}
        # 概览主 finding 携带 top_sources / levels，可下钻（extra 值为字符串）。
        overview = next(item for key, item in by_summary.items()
                        if key.startswith("日志概览"))
        self.assertIn("top_sources", overview["extra"])
        self.assertIn("levels", overview["extra"])
        # 级别分布与来源分布各一条 finding，detail 为紧凑多行文本。
        levels_f = by_summary["日志级别分布"]
        sources_f = by_summary["日志来源分布"]
        self.assertEqual(levels_f["level"], "info")
        self.assertEqual(sources_f["level"], "info")
        self.assertIn("info", levels_f["extra"]["levels"])
        self.assertIn("info 20", levels_f["detail"])
        self.assertIn("ceph", sources_f["detail"])
        self.assertEqual(len(levels_f["detail"].split("\n")), 2)
        # 新增：字段覆盖率 finding，detail 每行「字段 非空数/唯一数」。
        fields_f = by_summary["日志字段覆盖率"]
        self.assertEqual(fields_f["kind"], "log")
        self.assertEqual(fields_f["level"], "info")
        self.assertIn("client_id", fields_f["extra"]["fields"])
        self.assertIn("client_id 40/2", fields_f["detail"])
        self.assertEqual(len(fields_f["detail"].split("\n")), 7)

    def test_entities(self):
        logs.entities(self.ctx)
        text = log_text(self.ctx)
        self.assertIn("实体统计 · client_id", text)
        self.assertIn("client1", text)
        self.assertTrue((Path(self.tmp.name) / "out" / "log_entities.csv").is_file())
        self.assertTrue(self.ctx.findings)
        # 每个维度最多前若干维、每维 Top 3 实体都有独立画像 finding。
        profiles = [item for item in self.ctx.findings
                    if item["summary"].startswith("实体画像")]
        self.assertGreaterEqual(len(profiles), 6)
        client1 = next(item for item in profiles
                       if item["extra"]["value"] == "client1")
        self.assertEqual(client1["extra"]["dimension"], "client_id")
        self.assertEqual(int(client1["extra"]["count"]), 20)
        self.assertEqual(int(client1["extra"]["fail"]), 10)
        self.assertGreater(int(client1["extra"]["line"]), 0)
        for keyword in ("占比", "失败 10 次", "第 ", "行"):
            self.assertIn(keyword, client1["detail"])

    def test_entity_stats_public_matches_handler(self):
        """entity_stats 公开函数与 entities handler 的日志表/CSV 口径一致。"""
        log = logfile.parse_path(self.path)
        stats = {entry["value"]: entry
                 for entry in logs.entity_stats(log, "client_id")}
        self.assertEqual(set(stats), {"client1", "client2"})
        # 默认失败规则：Invalid key 行计失败，其余计成功。
        for value in ("client1", "client2"):
            entry = stats[value]
            self.assertEqual(entry["count"], 20)
            self.assertEqual(entry["fail"], 10)
            self.assertEqual(entry["success"], 10)
            self.assertAlmostEqual(entry["fail_rate"], 0.5, places=4)
            self.assertAlmostEqual(entry["success_rate"], 0.5, places=4)
            self.assertAlmostEqual(entry["share"], 0.5, places=4)
            # client1 只出现在 :01/:02，client2 只出现在 :03/:04。
            span = ("2024-12-02 14:00:01", "2024-12-02 14:00:02") \
                if value == "client1" \
                else ("2024-12-02 14:00:03", "2024-12-02 14:00:04")
            self.assertEqual(entry["first"], span[0])
            self.assertEqual(entry["last"], span[1])
            self.assertTrue(entry["line"] > 0)
            self.assertIn("Invalid key", entry["sample"])  # 代表行取失败行
        # limit 截断排序后的列表。
        limited = logs.entity_stats(log, "client_id", limit=1)
        self.assertEqual(len(limited), 1)
        # 与 handler 的 CSV 产出逐行对账（次数/失败/成功列）。
        logs.entities(self.ctx)
        with (Path(self.tmp.name) / "out" / "log_entities.csv").open(
                encoding="utf-8", newline="") as handle:
            rows = list(csv_mod.reader(handle))
        header, body = rows[0], rows[1:]
        self.assertEqual(header[1:5],
                         ["值", "次数", "占比", "失败次数"])
        for row in body:
            if row[0] != "client_id":
                continue
            entry = stats[row[1]]
            self.assertEqual(int(row[2]), entry["count"])
            self.assertEqual(int(row[4]), entry["fail"])
            self.assertEqual(int(row[8]), entry["success"])
            self.assertEqual(row[6], entry["first"])
            self.assertEqual(row[7], entry["last"])

    def test_anomalies(self):
        logs.anomalies(self.ctx)
        text = log_text(self.ctx)
        self.assertIn("失败/异常关键字命中", text)
        self.assertIn("失败最多的实体", text)
        self.assertTrue((Path(self.tmp.name) / "out" / "log_anomalies.csv").is_file())
        # 认证类失败逐条样本，均匀取样，最多 10 条。
        samples = [item for item in self.ctx.findings
                   if item["summary"].startswith("认证失败样本")]
        self.assertEqual(len(samples), 10)
        for item in samples:
            self.assertEqual(item["kind"], "log")
            self.assertEqual(item["level"], "warn")
            self.assertIn("line", item["extra"])
            self.assertIn("time", item["extra"])
            self.assertIn("第 ", item["detail"])
        self.assertIn("client1 @ 192.168.1.10",
                      " ".join(item["summary"] for item in samples))
        # 失败实体画像 detail 带占比与原始行片段。
        suspect = next(item for item in self.ctx.findings
                       if item["summary"].startswith("实体 client1"))
        self.assertIn("占比", suspect["detail"])
        self.assertIn("第 ", suspect["detail"])
        self.assertIn("line", suspect["extra"])

    def test_anomalies_fail_samples_fallback(self):
        path = Path(self.tmp.name) / "app.log"
        path.write_text(
            "2024-12-02 14:18:11 worker disk error on /dev/sda\n",
            encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(path))
        logs.anomalies(ctx)
        samples = [item for item in ctx.findings
                   if item["summary"].startswith("失败样本")]
        self.assertEqual(len(samples), 1)
        self.assertEqual(samples[0]["level"], "warn")
        self.assertEqual(samples[0]["extra"]["line"], "1")
        self.assertEqual(samples[0]["extra"]["time"], "2024-12-02 14:18:11")

    def test_iocs_flags_and_credentials(self):
        flag_path = Path(self.tmp.name) / "app.log"
        flag_path.write_text(
            "2024-12-02 14:18:11 login failed from 8.8.8.8 "
            "password=S3cret flag{log_flag}\n",
            encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(flag_path))
        logs.iocs(ctx)
        text = log_text(ctx)
        self.assertIn("发现 Flag: flag{log_flag}", text)
        kinds = {item["kind"] for item in ctx.findings}
        self.assertIn("flag", kinds)
        self.assertIn("credential", kinds)
        # 凭据 finding 的 detail 补充出现次数。
        cred = next(item for item in ctx.findings
                    if item["kind"] == "credential")
        self.assertIn("出现 1 次", cred["detail"])
        self.assertEqual(cred["extra"]["count"], "1")
        # 新增：IOC 统计 finding，与"IOC 类型统计"表同源（唯一值/总次数）。
        stats_f = next(item for item in ctx.findings
                       if item["summary"] == "日志IOC统计")
        self.assertEqual(stats_f["kind"], "log")
        self.assertEqual(stats_f["level"], "info")
        self.assertIn("Flag 1/1", stats_f["detail"])
        self.assertIn("凭据 1/1", stats_f["detail"])
        self.assertIn("Flag", stats_f["extra"]["counts"])

    def test_total_findings_budget(self):
        """四类日志功能跑满时，findings 总数受软上限约束。"""
        lines = []
        for index in range(30):
            lines.append(f"2024-12-02 14:18:{index % 60:02d} auth failed "
                         f"password=PW{index} flag{{{index}}}")
            lines.append(f"2024-12-02 14:19:{index % 60:02d} hash "
                         f"{'a' * 32}{index:012d} ok")
        path = Path(self.tmp.name) / "busy.log"
        path.write_text("\n".join(lines), encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(path))
        for handler in (logs.summary, logs.entities, logs.anomalies, logs.iocs):
            handler(ctx)
        self.assertLessEqual(len(ctx.findings), logs._MAX_FINDINGS_TOTAL)

    def test_keyword_scan_uses_log_path(self):
        flag_path = Path(self.tmp.name) / "app.log"
        flag_path.write_text(
            "2024-12-02 14:18:11 request ok flag{scan_me}\n",
            encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(flag_path),
                       params={"keywords": r"flag\{.+?\}", "auto_regex": False})
        text_scan.keyword_scan(ctx)
        text = log_text(ctx)
        self.assertIn("日志关键字扫描", text)
        self.assertIn("发现 flag", text)
        self.assertIn("flag{scan_me}", text)
        self.assertIn("flag", {item["kind"] for item in ctx.findings})

    def test_capture_input_is_skipped(self):
        ctx = make_ctx(self.tmp.name, str(Path(self.tmp.name) / "x.pcap"))
        Path(ctx.pcap).write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 8)
        ctx.input_kind = "pcap"
        logs.summary(ctx)
        self.assertIn("当前输入不是日志文件", log_text(ctx))
        self.assertEqual(ctx.findings, [])


class LogSubnetTest(unittest.TestCase):
    """网段聚合 + 通用成功/失败口径（logs.entities）."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _log(self, name: str, lines: list[str]) -> Path:
        path = Path(self.tmp.name) / name
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _csv_rows(self) -> tuple[list[str], list[list[str]]]:
        with (Path(self.tmp.name) / "out" / "log_entities.csv").open(
                encoding="utf-8", newline="") as handle:
            rows = list(csv_mod.reader(handle))
        return rows[0], rows[1:]

    SUBNET_LINES = [
        "2024-12-02T14:00:01 ceph: Client operation, ClientID: client1, "
        "Operation: Read, Key: key_aaaa, Client IP: 10.1.1.5 ",
        "2024-12-02T14:00:02 ceph: Client operation, ClientID: client1, "
        "Operation: Read, Key: key_bbbb, Client IP: 10.1.1.6 ",
        "2024-12-02T14:00:03 ceph: Client operation, ClientID: client2, "
        "Operation: Read, Key: Invalid key, Client IP: 10.1.1.7 ",
        "2024-12-02T14:00:04 ceph: Client operation, ClientID: client2, "
        "Operation: Delete, Key: Invalid key, Client IP: 10.2.2.8 ",
    ]

    def test_subnet_grouping_and_success_regex(self):
        """/24 归组 + 自定义成功口径（Key: key_ 表示成功），唯一第一名。"""
        path = self._log("subnet.log", self.SUBNET_LINES)
        ctx = make_ctx(self.tmp.name, str(path),
                       params={"log_success_regex": r"Key: key_"})
        logs.entities(ctx)
        text = log_text(ctx)
        self.assertIn("实体统计 · 网段", text)
        self.assertIn("10.1.1.0/24", text)
        self.assertIn("10.2.2.0/24", text)
        self.assertIn("成功口径", text)
        header, rows = self._csv_rows()
        self.assertEqual(header[-2:], ["成功次数", "成功率"])
        by_value = {row[1]: row for row in rows if row[0] == "网段"}
        self.assertEqual(
            by_value["10.1.1.0/24"][header.index("成功次数")], "2")
        self.assertEqual(
            by_value["10.1.1.0/24"][header.index("失败次数")], "1")
        self.assertEqual(
            by_value["10.2.2.0/24"][header.index("成功次数")], "0")
        # 唯一第一名网段进入汇总 finding。
        finding = next(item for item in ctx.findings
                       if item["summary"] == "网段成功统计")
        self.assertEqual(finding["level"], "info")
        self.assertIn("10.1.1.0/24 成功 2 / 共 3", finding["detail"])
        top = ast.literal_eval(finding["extra"]["top"])
        self.assertEqual(top[0], {"subnet": "10.1.1.0/24",
                                  "success": 2, "total": 3})
        self.assertEqual(len(top), 2)

    def test_subnet_prefix_16(self):
        """log_subnet_prefix=16 时按 /16 归组；无 success regex 时非失败即成功。"""
        path = self._log("subnet16.log", self.SUBNET_LINES)
        ctx = make_ctx(self.tmp.name, str(path),
                       params={"log_subnet_prefix": "16"})
        logs.entities(ctx)
        text = log_text(ctx)
        self.assertIn("10.1.0.0/16", text)
        self.assertIn("10.2.0.0/16", text)
        self.assertIn("未提供 log_success_regex", text)
        header, rows = self._csv_rows()
        by_value = {row[1]: row for row in rows if row[0] == "网段"}
        self.assertEqual(
            by_value["10.1.0.0/16"][header.index("成功次数")], "2")
        self.assertEqual(
            by_value["10.2.0.0/16"][header.index("失败次数")], "1")

    def test_subnet_prefix_invalid_fallback(self):
        """非数字/越界前缀告警并回退 /24。"""
        path = self._log("subnet_bad.log", self.SUBNET_LINES)
        for bad in ("abc", "40"):
            ctx = make_ctx(self.tmp.name, str(path),
                           params={"log_subnet_prefix": bad})
            logs.entities(ctx)
            text = log_text(ctx)
            self.assertIn("log_subnet_prefix", text)
            self.assertIn("回退 /24", text)
            header, rows = self._csv_rows()
            by_value = {row[1]: row for row in rows if row[0] == "网段"}
            self.assertIn("10.1.1.0/24", by_value)
            self.assertNotIn("10.1.0.0/16", by_value)

    def test_ipv6_log_no_v4_subnet(self):
        """IPv6 日志按 /64 归组，不产生 v4 网段也不崩溃。"""
        lines = [
            "2024-12-02 14:18:11 conn ok from 2001:db8::1",
            "2024-12-02 14:18:12 conn ok from 2001:db8::2",
            "2024-12-02 14:18:13 conn failed from 2001:db9::1",
        ]
        path = self._log("v6.log", lines)
        ctx = make_ctx(self.tmp.name, str(path))
        logs.entities(ctx)
        header, rows = self._csv_rows()
        subnet_values = [row[1] for row in rows if row[0] == "网段"]
        self.assertIn("2001:db8::/64", subnet_values)
        self.assertIn("2001:db9::/64", subnet_values)
        self.assertTrue(all(":" in value for value in subnet_values))
        by_value = {row[1]: row for row in rows if row[0] == "网段"}
        self.assertEqual(
            by_value["2001:db8::/64"][header.index("成功次数")], "2")

    def test_success_regex_invalid_fallback(self):
        """非法 success 正则告警并回退为“非失败即成功”口径。"""
        path = self._log("subnet_re.log", self.SUBNET_LINES)
        ctx = make_ctx(self.tmp.name, str(path),
                       params={"log_success_regex": "("})
        logs.entities(ctx)
        text = log_text(ctx)
        self.assertIn("log_success_regex 无效", text)
        self.assertIn("未命中失败关键字", text)
        header, rows = self._csv_rows()
        by_value = {row[1]: row for row in rows if row[0] == "网段"}
        # 回退口径下 10.2.2.0/24 只有一条 Invalid key 记录，不计成功。
        self.assertEqual(
            by_value["10.2.2.0/24"][header.index("成功次数")], "0")


class LogDefaultsTest(unittest.TestCase):
    def test_log_defaults_are_log_features(self):
        expected = [feature.checkbox for feature in FEATURES
                    if feature.category == "log"]
        self.assertEqual(default_features_for("log"), expected)
        self.assertEqual(len(expected), 4)

    def test_pcap_defaults_unchanged(self):
        self.assertEqual(default_features_for("pcap"),
                         ["checkBox_10", "checkBox_30"])


class LogJobTest(unittest.TestCase):
    """The job pipeline records a log input and labels its report correctly."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cache = Path(self.tmp.name) / "cache"
        cache.mkdir()
        for patch in (mock.patch("fnet.jobs.CACHE_DIR", cache),
                      mock.patch("fnet.paths.CACHE_DIR", cache)):
            patch.start()
            self.addCleanup(patch.stop)
        self.manager = JobManager(
            Config(Path(self.tmp.name) / "config.ini"), None)

    def test_create_marks_kind_and_report_label(self):
        path = Path(self.tmp.name) / "ceph.log"
        path.write_text("\n".join(CEPH_LINES), encoding="utf-8")
        job = self.manager.create(str(path), default_features_for("log"), {})
        self.assertEqual(job.kind, "log")
        self.assertEqual([feature.category for feature in job.features],
                         ["log", "log", "log", "log"])
        job.log.info("日志概览")
        self.manager._write_report(job, "done")
        report = (job.output_dir / "report.txt").read_text(encoding="utf-8")
        self.assertIn("日志文件:", report)
        self.assertNotIn("流量包:", report)

    def _job_dir_with_artifacts(self) -> Path:
        out = Path(self.tmp.name) / "jobdir"
        (out / "frames").mkdir(parents=True)
        for name in ("job.json", "findings.json", "findings.csv",
                     "annotations.json", "log_fields.csv", "log_entities.csv",
                     "log_anomalies.csv", "log_iocs.csv",
                     "report.txt", "report.md", "report.html",
                     "ntlm_hashes.txt"):
            (out / name).write_text("x", encoding="utf-8")
        (out / "frames" / "clip.pcapng").write_bytes(b"clip")
        return out

    def test_artifacts_hide_analysis_files(self):
        """产出列表只列交付物：分析结果与报告文件不出现，磁盘文件保留。"""
        out = self._job_dir_with_artifacts()
        names = [item["name"] for item in JobManager.artifacts_in(out)]
        self.assertEqual(names, ["frames/clip.pcapng", "ntlm_hashes.txt"])
        # 磁盘文件不删除：/api/download?path= 精确下载仍可用。
        self.assertTrue((out / "findings.csv").is_file())
        self.assertTrue((out / "log_entities.csv").is_file())

    def test_zip_skips_analysis_files(self):
        """打包 ZIP 跳过分析结果文件，报告与交付物保留。"""
        out = self._job_dir_with_artifacts()
        archive = self.manager.zip_artifacts(
            SimpleNamespace(id="abc12345", output_dir=out))
        packed = set(zipfile.ZipFile(archive).namelist())
        self.assertIn("ntlm_hashes.txt", packed)
        self.assertIn("report.txt", packed)
        self.assertNotIn("findings.json", packed)
        self.assertNotIn("findings.csv", packed)
        self.assertNotIn("log_entities.csv", packed)
        self.assertNotIn("job.json", packed)
        self.assertNotIn("fnet-abc12345.zip", packed)


if __name__ == "__main__":
    unittest.main()
