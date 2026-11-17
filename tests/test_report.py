"""Unit tests for the Markdown/HTML report renderers."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from fnet.report import (
    DEFAULT_SECTIONS, normalise_sections, parse_report_text, render_html,
    render_markdown, select_findings, write_reports,
)


def sample_meta() -> dict:
    return {
        "id": "0123456789abcdef",
        "pcap": "/tmp/example.pcap",
        "pcap_name": "example.pcap",
        "features": ["checkBox_10", "http.extract"],
        "feature_titles": ["关键字检测", "HTTP数据提取"],
        "params": {"keywords": "flag{", "post_only": True},
        "status": "done",
        "created": "2026-01-01T10:00:00",
        "started": "2026-01-01T10:00:01",
        "finished": "2026-01-01T10:00:09",
    }


LOGS = [
    {"seq": 1, "time": "10:00:01", "tag": "[*]", "level": "info",
     "text": "开始分析: /tmp/example.pcap"},
    {"seq": 2, "time": "10:00:02", "tag": "[*]", "level": "info",
     "text": "命中 flag{report_test}，账号 admin:P@ssw0rd"},
    {"seq": 3, "time": "10:00:03", "tag": "[+]", "level": "good",
     "text": "关键字检测 完成"},
    {"seq": 4, "time": "10:00:04", "tag": "[!]", "level": "warn",
     "text": "疑似 ARP 欺骗"},
]


class SectionTest(unittest.TestCase):
    def test_normalise_accepts_strings_and_lists(self):
        self.assertEqual(normalise_sections(None), list(DEFAULT_SECTIONS))
        self.assertEqual(normalise_sections("log,summary"),
                         ["summary", "log"])
        self.assertEqual(normalise_sections(["artifacts", "unknown"]),
                         ["artifacts"])
        self.assertEqual(normalise_sections(["unknown"]), list(DEFAULT_SECTIONS))

    def test_findings_drop_noise_and_keep_warnings(self):
        findings = select_findings(LOGS)
        texts = [item["text"] for item in findings]
        self.assertTrue(any("flag{report_test}" in text for text in texts))
        self.assertIn("疑似 ARP 欺骗", texts)
        self.assertNotIn("关键字检测 完成", texts)
        self.assertNotIn("开始分析: /tmp/example.pcap", texts)


class MarkdownTest(unittest.TestCase):
    def test_all_default_sections_and_findings(self):
        text = render_markdown(sample_meta(), LOGS,
                              [{"name": "report.txt", "size": 2048}])
        for heading in ("## 概要", "## 功能清单", "## 关键发现",
                        "## 完整日志", "## 产出文件"):
            self.assertIn(heading, text)
        self.assertIn("flag{report_test}", text)
        self.assertIn("`http.extract`", text)
        self.assertIn("`report.txt`", text)
        self.assertIn("2.0 KB", text)
        self.assertNotIn("## 分析参数", text)

    def test_section_selection_and_escaping(self):
        text = render_markdown(sample_meta(), LOGS, [], sections=["summary"])
        self.assertIn("## 概要", text)
        self.assertNotIn("## 完整日志", text)
        self.assertNotIn("flag{report_test}", text)
        meta = sample_meta()
        meta["pcap"] = "a|b\nc"
        text = render_markdown(meta, LOGS, [], sections=["summary"])
        self.assertIn(r"a\|b c", text)


class HtmlTest(unittest.TestCase):
    def test_escapes_payloads_and_marks_flags(self):
        meta = sample_meta()
        meta["pcap"] = "<script>alert(1)</script>.pcap"
        logs = [{"seq": 1, "time": "10:00:00", "tag": "[*]", "level": "info",
                 "text": "<img src=x onerror=alert(1)> flag{xss_safe}"}]
        page = render_html(meta, logs, [{"name": "<b>out</b>", "size": 10}])
        self.assertIn("<!doctype html>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", page)
        self.assertIn("&lt;b&gt;out&lt;/b&gt;", page)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("<mark>flag{xss_safe}</mark>", page)
        self.assertIn("@media print", page)

    def test_sections_control_toc_and_body(self):
        page = render_html(sample_meta(), LOGS, [],
                           sections=["summary", "findings"])
        self.assertIn('href="#section-summary"', page)
        self.assertIn('href="#section-findings"', page)
        self.assertNotIn('id="section-log"', page)
        self.assertIn("疑似 ARP 欺骗", page)


class StructuredFindingsTest(unittest.TestCase):
    FINDINGS = [
        {"kind": "hash", "level": "good", "frame": "16",
         "feature": "NTLM HASH提取",
         "summary": "WORKGROUP\\Administrator NetNTLMv1",
         "detail": "Administrator::WORKGROUP:1122"},
        {"kind": "flag", "level": "good", "frame": "20",
         "feature": "关键字检测", "summary": "flag{report_table}",
         "detail": "<script>alert(1)</script>"},
    ]

    def test_markdown_table_replaces_highlight_list(self):
        text = render_markdown(sample_meta(), LOGS, [],
                               findings=self.FINDINGS)
        self.assertIn("| 类别 | 级别 | 帧 | 功能 | 摘要 | 详情 |", text)
        self.assertIn("哈希", text)
        self.assertIn("flag{report_table}", text)
        self.assertIn(r"<script>alert(1)</script>", text)

    def test_html_table_escapes_and_marks_flags(self):
        page = render_html(sample_meta(), LOGS, [], findings=self.FINDINGS)
        self.assertIn("<table>", page)
        self.assertIn("<mark>flag{report_table}</mark>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<script>alert(1)</script>", page)

    def test_findings_without_rows_falls_back_to_log_highlights(self):
        page = render_html(sample_meta(), LOGS, [], sections=["findings"])
        self.assertIn('<ul class="findings">', page)
        self.assertIn("疑似 ARP 欺骗", page)


class ParseTest(unittest.TestCase):
    def test_legacy_report_roundtrip(self):
        text = "\n".join([
            "Fnet 分析报告",
            "=" * 60,
            "流量包: /tmp/x.pcap",
            "=" * 60,
            "",
            "10:00:01 [*] 第一行",
            "10:00:02 [!] 警告",
            "续行内容",
        ])
        records = parse_report_text(text)
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["level"], "warn")
        self.assertIn("续行内容", records[1]["text"])

    def test_write_reports_creates_both_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            job = SimpleNamespace(
                id="0123456789abcdef", pcap="/tmp/example.pcap",
                features=[SimpleNamespace(checkbox="checkBox_10",
                                          title="关键字检测")],
                params={}, status="done", created="now", started="now",
                finished="now", output_dir=Path(tmp),
            )
            written = write_reports(job, LOGS, [])
            self.assertEqual(set(written), {"md", "html"})
            self.assertTrue((Path(tmp) / "report.md").is_file())
            self.assertTrue((Path(tmp) / "report.html").is_file())


if __name__ == "__main__":
    unittest.main()
