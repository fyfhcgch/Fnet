"""Unit tests for the Markdown/HTML report renderers."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fnet.config import Config
from fnet.jobs import JobManager
from fnet.report import (
    DEFAULT_SECTIONS, annotation_lines, normalise_sections, parse_report_text,
    render_html, render_markdown, select_findings, write_reports,
)

DATA = Path(__file__).resolve().parent / "data"


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

    def test_findings_drop_noise_and_failures(self):
        findings = select_findings(LOGS)
        texts = [item["text"] for item in findings]
        self.assertTrue(any("flag{report_test}" in text for text in texts))
        self.assertNotIn("疑似 ARP 欺骗", texts)
        self.assertNotIn("关键字检测 完成", texts)
        self.assertNotIn("开始分析: /tmp/example.pcap", texts)


class ReportFilterTest(unittest.TestCase):
    """Exported reports advertise results only: no failure or noise rows."""

    FINDINGS = [
        {"kind": "hash", "level": "good", "frame": "16", "time": "10:00:02",
         "feature": "NTLM HASH提取", "summary": "Administrator NetNTLMv2",
         "detail": "Administrator::LAB:1122"},
        {"kind": "file", "level": "info", "frame": "18", "time": "10:00:03",
         "feature": "HTTP数据提取", "summary": "导出 admin.aspx",
         "detail": "2048 字节"},
        {"kind": "protocol", "level": "warn", "frame": "20", "time": "10:00:04",
         "feature": "SMB流量分析", "summary": "SMB3 加密流量", "detail": ""},
        {"kind": "protocol", "level": "error", "frame": "21", "time": "10:00:05",
         "feature": "TCP流分析", "summary": "tshark 执行失败", "detail": ""},
        {"kind": "protocol", "level": "debug", "frame": "22", "time": "10:00:06",
         "feature": "DNS流量分析", "summary": "调试细节", "detail": ""},
        {"kind": "protocol", "level": "good", "frame": "23", "time": "10:00:07",
         "feature": "ICMP流量分析", "summary": "-", "detail": ""},
    ]

    def test_finding_rows_keep_only_results(self):
        from fnet.report import finding_rows
        rows = finding_rows(self.FINDINGS)
        self.assertEqual([row[4] for row in rows],
                         ["Administrator NetNTLMv2", "导出 admin.aspx"])

    def test_timeline_keeps_only_results(self):
        from fnet.report import timeline_rows
        rows = timeline_rows(self.FINDINGS)
        self.assertEqual([row[4] for row in rows],
                         ["Administrator NetNTLMv2", "导出 admin.aspx"])

    def test_rendered_reports_hide_failures(self):
        text = render_markdown(sample_meta(), LOGS, [], findings=self.FINDINGS)
        page = render_html(sample_meta(), LOGS, [], findings=self.FINDINGS)
        for content in (text, page):
            self.assertIn("Administrator NetNTLMv2", content)
            self.assertIn("导出 admin.aspx", content)
            self.assertNotIn("SMB3 加密流量", content)
            self.assertNotIn("tshark 执行失败", content)
            self.assertNotIn("调试细节", content)


class MarkdownTest(unittest.TestCase):
    def test_all_default_sections_and_findings(self):
        text = render_markdown(sample_meta(), LOGS,
                              [{"name": "ntlm_hashes.txt", "size": 2048}])
        for heading in ("## 概要", "## 功能清单", "## 关键发现",
                        "## 完整日志", "## 产出文件"):
            self.assertIn(heading, text)
        self.assertIn("flag{report_test}", text)
        self.assertIn("`http.extract`", text)
        self.assertIn("`ntlm_hashes.txt`", text)
        self.assertIn("2.0 KB", text)
        self.assertNotIn("## 分析参数", text)

    def test_artifacts_skip_report_files(self):
        text = render_markdown(
            sample_meta(), LOGS,
            [{"name": "report.txt", "size": 10},
             {"name": "report.md", "size": 11},
             {"name": "report.html", "size": 12},
             {"name": "hashes.txt", "size": 20}],
            sections=["artifacts"])
        self.assertIn("`hashes.txt`", text)
        self.assertNotIn("report.txt", text)
        self.assertNotIn("report.md", text)
        self.assertNotIn("report.html", text)

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
        self.assertIn("flag{report_test}", page)
        self.assertNotIn("疑似 ARP 欺骗", page)


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

    def test_findings_without_rows_falls_back_to_success_highlights(self):
        page = render_html(sample_meta(), LOGS, [], sections=["findings"])
        self.assertIn('<ul class="findings">', page)
        self.assertIn("flag{report_test}", page)
        self.assertNotIn("疑似 ARP 欺骗", page)


class IocsAttackTimelineTest(unittest.TestCase):
    FINDINGS = [
        {"kind": "dns", "level": "warn", "frame": "8",
         "feature": "DNS流量分析", "time": "10:00:03",
         "summary": "长标签查询 ev1l.example.com (10.0.0.5)",
         "detail": "隧道时间线见 https://tracker.example.invalid/q?a=1"},
        {"kind": "credential", "level": "good", "frame": "16",
         "feature": "NTLM HASH提取", "time": "10:00:02",
         "summary": "Administrator 凭据",
         "detail": "MD5 5d41402abc4b2a76b9719d911017c592 出现于 POST"},
        {"kind": "webshell", "level": "warn", "frame": "20",
         "feature": "Webshell 解密", "time": "10:00:01",
         "summary": "哥斯拉内存马 <script>alert(1)</script>",
         "detail": "命令执行：whoami"},
        {"kind": "flag", "level": "good", "frame": "24",
         "feature": "关键字检测", "time": "10:00:04",
         "summary": "flag{timeline}", "detail": "流量包尾部命中"},
    ]

    def test_iocs_extracted_and_deduplicated(self):
        from fnet.report import ioc_rows
        rows = ioc_rows(self.FINDINGS)
        values = {value for _, value, _, _ in rows}
        self.assertIn("ev1l.example.com", values)
        self.assertIn("https://tracker.example.invalid/q?a=1", values)
        self.assertIn("10.0.0.5", values)
        self.assertIn("5d41402abc4b2a76b9719d911017c592", values)
        # URL host must not be duplicated as a bare domain row.
        domains = [value for kind, value, _, _ in rows if kind == "域名"]
        self.assertNotIn("tracker.example.invalid", domains)

    def test_iocs_carry_first_seen_feature_and_count(self):
        from fnet.report import ioc_rows
        rows = ioc_rows(self.FINDINGS)
        first = {value: (kind, feature) for kind, value, _, feature in rows}
        kind, feature = first["ev1l.example.com"]
        self.assertEqual(kind, "域名")
        self.assertEqual(feature, "DNS流量分析")
        counts = {value: count for _, value, count, _ in rows}
        self.assertGreaterEqual(counts.get("10.0.0.5", 0), 1)

    def test_attack_mapping_and_note(self):
        from fnet.report import attack_rows, render_markdown
        rows = attack_rows(self.FINDINGS)
        techniques = {technique for _, technique, _, _, _ in rows}
        self.assertEqual(techniques, {"T1071.004", "T1505.003", "T1555"})
        text = render_markdown({}, [], [], sections=["attack"],
                               findings=self.FINDINGS)
        self.assertIn("提示性映射", text)
        self.assertIn("`T1505.003`", text)

    def test_timeline_is_sorted_by_time(self):
        from fnet.report import timeline_rows
        rows = timeline_rows(self.FINDINGS)
        times = [row[0] for row in rows]
        self.assertEqual(times, sorted(times))
        self.assertEqual([row[4] for row in rows],
                         ["Administrator 凭据", "flag{timeline}"])
        self.assertNotIn("哥斯拉内存马", [row[4] for row in rows])
        self.assertNotIn("长标签查询 ev1l.example.com (10.0.0.5)",
                         [row[4] for row in rows])

    def test_html_sections_render_and_escape(self):
        findings = self.FINDINGS + [{
            "kind": "flag", "level": "good", "frame": "28",
            "feature": "关键字检测", "time": "10:00:05",
            "summary": "flag{<script>alert(1)</script>}", "detail": ""}]
        page = render_html({}, [], [], findings=findings)
        self.assertIn('id="section-iocs"', page)
        self.assertIn('id="section-attack"', page)
        self.assertIn('id="section-timeline"', page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("@page{margin:14mm}", page)

    def test_new_sections_in_defaults(self):
        self.assertIn("timeline", DEFAULT_SECTIONS)
        self.assertIn("iocs", DEFAULT_SECTIONS)
        self.assertIn("attack", DEFAULT_SECTIONS)


class AnnotationRenderTest(unittest.TestCase):
    FINDINGS = [
        {"kind": "credential", "level": "good", "frame": "4",
         "feature": "NTLM HASH提取", "summary": "Administrator::WORKGROUP",
         "detail": "NTLMv1",
         "annotation": {"status": "false_positive", "note": "误报 <b>x</b>",
                        "updated": "2026-01-01T00:00:00"}},
        {"kind": "flag", "level": "good", "frame": "9",
         "feature": "关键字检测", "summary": "flag{annotated}", "detail": "",
         "annotation": {"status": "confirmed", "note": "已人工核对 | 保留"}},
    ]

    def test_markdown_annotation_column(self):
        text = render_markdown(sample_meta(), LOGS, [], findings=self.FINDINGS)
        self.assertIn("| 类别 | 级别 | 帧 | 功能 | 摘要 | 详情 | 标注 |", text)
        self.assertIn("误报 · 误报 <b>x</b>", text)
        self.assertIn(r"已人工核对 \| 保留", text)

    def test_markdown_without_annotations_is_unchanged(self):
        findings = [dict(item) for item in self.FINDINGS]
        for item in findings:
            item.pop("annotation")
        text = render_markdown(sample_meta(), LOGS, [], findings=findings)
        self.assertIn("| 类别 | 级别 | 帧 | 功能 | 摘要 | 详情 |", text)
        self.assertNotIn("| 标注 |", text)

    def test_html_annotation_is_escaped_and_marked(self):
        page = render_html(sample_meta(), LOGS, [], findings=self.FINDINGS)
        self.assertIn("<th>标注</th>", page)
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", page)
        self.assertNotIn("<b>x</b>", page)
        self.assertIn("ann-false", page)
        self.assertIn("误报", page)

    def test_plain_text_lines(self):
        lines = annotation_lines(self.FINDINGS)
        self.assertEqual(len(lines), 2)
        self.assertIn("误报", lines[0])
        self.assertIn("已人工核对", lines[1])
        self.assertTrue(lines[0].startswith("  #1 [凭据]"))


class AnnotationReportTest(unittest.TestCase):
    """report.txt / report.md / report.html tell the same annotation story."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cache = Path(self.tmp.name) / "cache"
        cache.mkdir()
        patches = (mock.patch("fnet.jobs.CACHE_DIR", cache),
                   mock.patch("fnet.paths.CACHE_DIR", cache))
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.manager = JobManager(Config(Path(self.tmp.name) / "config.ini"),
                                  None)

    def _job(self):
        from fnet.findings import make

        job = self.manager.create(str(DATA / "http_ntlm.pcap"),
                                  ["checkBox_10"], {})
        job.findings = [
            make("credential", "Administrator::WORKGROUP", frame="4",
                 detail="NTLMv1", feature="NTLM HASH提取"),
            make("flag", "flag{annotation_report}", frame="9",
                 feature="关键字检测"),
        ]
        return job

    def test_three_formats_render_annotation(self):
        job = self._job()
        self.manager.set_annotation(job.id, 1, "false_positive",
                                    "误报 <script>alert(1)</script>")
        self.manager.set_annotation(job.id, 2, "confirmed", "已人工核对")
        job.log.info("关键字检测 命中 flag{annotation_report}")
        # Worker order: findings.json/csv first, then the three report files.
        self.manager._write_findings(job)
        self.manager._write_report(job, "done")

        output = job.output_dir
        text = (output / "report.txt").read_text(encoding="utf-8")
        markdown = (output / "report.md").read_text(encoding="utf-8")
        page = (output / "report.html").read_text(encoding="utf-8")

        self.assertIn("人工标注:", text)
        self.assertIn("误报 <script>alert(1)</script>", text)
        self.assertIn("已人工核对", text)
        self.assertIn("| 标注 |", markdown)
        self.assertIn("误报 · 误报 <script>alert(1)</script>", markdown)
        self.assertIn("<th>标注</th>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("ann-false", page)

        # The txt annotation block sits before the timestamped log lines so
        # parse_report_text() still recovers the historical log unchanged.
        records = parse_report_text(text)
        self.assertTrue(records)
        self.assertFalse(any("人工标注" in record["text"] or "误报" in record["text"]
                             for record in records))
        self.assertTrue(any("命中 flag{annotation_report}" in record["text"]
                            for record in records))

        # /api/report (report_source -> export_report) carries them too.
        exported = self.manager.export_report(job.id, "html")["content"]
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", exported)
        self.assertIn("ann-false", exported)

        # Same for a job recovered from disk after a restart (no live job).
        with self.manager._lock:
            self.manager._jobs.pop(job.id, None)
        restored = self.manager.export_report(job.id, "md")["content"]
        self.assertIn("| 标注 |", restored)
        self.assertIn("已人工核对", restored)

    def test_report_without_annotations_unchanged(self):
        job = self._job()
        job.log.info("关键字检测 命中 flag{annotation_report}")
        self.manager._write_report(job, "done")
        text = (job.output_dir / "report.txt").read_text(encoding="utf-8")
        markdown = (job.output_dir / "report.md").read_text(encoding="utf-8")
        page = (job.output_dir / "report.html").read_text(encoding="utf-8")
        self.assertNotIn("人工标注", text)
        self.assertNotIn("| 标注 |", markdown)
        self.assertNotIn("<th>标注</th>", page)

    def test_set_annotation_refreshes_existing_reports(self):
        """Annotations are usually written after the run: reports must follow."""
        job = self._job()
        job.status = "done"
        job.log.info("关键字检测 命中 flag{annotation_report}")
        self.manager.set_annotation(job.id, 1, "confirmed", "事后补的标注")
        text = (job.output_dir / "report.txt").read_text(encoding="utf-8")
        markdown = (job.output_dir / "report.md").read_text(encoding="utf-8")
        self.assertEqual(text.count("人工标注:"), 1)
        self.assertIn("事后补的标注", text)
        self.assertIn("事后补的标注", markdown)
        # Clearing it removes the block again without duplicating the log.
        self.manager.set_annotation(job.id, 1, "", "")
        text = (job.output_dir / "report.txt").read_text(encoding="utf-8")
        self.assertNotIn("人工标注", text)
        self.assertEqual(text.count("命中 flag{annotation_report}"), 1)


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
