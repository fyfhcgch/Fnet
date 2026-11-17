"""Unit tests for the structured findings model."""
from __future__ import annotations

import unittest
from unittest import mock

from fnet import findings
from fnet.features.registry import FeatureContext


class StubLogger:
    def __init__(self) -> None:
        self.records = []

    def log(self, text: str, level: str = "info") -> None:
        self.records.append((level, text))


def context() -> tuple[FeatureContext, StubLogger]:
    logger = StubLogger()
    ctx = FeatureContext(config=None, logger=logger, tshark=None, pcap="x.pcap")
    return ctx, logger


class MakeTest(unittest.TestCase):
    def test_defaults_and_clipping(self):
        item = findings.make("HASH", "s" * 1000, frame=12, level="GOOD",
                             detail="d" * (findings.MAX_DETAIL + 50))
        self.assertEqual(item["kind"], "hash")
        self.assertEqual(item["level"], "good")
        self.assertEqual(item["frame"], "12")
        self.assertTrue(item["summary"].endswith("…"))
        self.assertLessEqual(len(item["summary"]), findings.MAX_SUMMARY + 1)
        self.assertLessEqual(len(item["detail"]), findings.MAX_DETAIL + 1)
        self.assertRegex(item["time"], r"^\d{2}:\d{2}:\d{2}$")

    def test_unknown_kind_and_level_fall_back(self):
        item = findings.make("nonsense", "hello", level="fatal")
        self.assertEqual(item["kind"], "other")
        self.assertEqual(item["level"], "info")

    def test_extra_values_are_stringified(self):
        item = findings.make("file", "a.bin", extra={"size": 12, "ok": True})
        self.assertEqual(item["extra"], {"size": "12", "ok": "True"})


class NormaliseTest(unittest.TestCase):
    def test_legacy_text_record(self):
        item = findings.normalise(
            {"text": "NetNTLMv1", "level": "good"}, feature="NTLM", checkbox="checkBox_39")
        self.assertEqual(item["summary"], "NetNTLMv1")
        self.assertEqual(item["feature"], "NTLM")
        self.assertEqual(item["checkbox"], "checkBox_39")

    def test_rejects_empty_and_non_dict(self):
        self.assertIsNone(findings.normalise(None))
        self.assertIsNone(findings.normalise("text"))
        self.assertIsNone(findings.normalise({"detail": "no summary"}))

    def test_unknown_kind(self):
        item = findings.normalise({"kind": "weird", "summary": "x"})
        self.assertEqual(item["kind"], "other")


class FilterTest(unittest.TestCase):
    ITEMS = [
        findings.make("flag", "flag{demo}", detail="frame 12"),
        findings.make("hash", "Administrator NetNTLMv1", level="good"),
        findings.make("dns", "long.example.com", level="warn"),
    ]

    def test_kind_and_level(self):
        self.assertEqual(len(findings.filter_items(self.ITEMS, kind="hash")), 1)
        self.assertEqual(len(findings.filter_items(self.ITEMS, level="warn")), 1)

    def test_query_is_case_insensitive_and_covers_detail(self):
        self.assertEqual(len(findings.filter_items(self.ITEMS, query="administrator")), 1)
        self.assertEqual(len(findings.filter_items(self.ITEMS, query="frame 12")), 1)
        self.assertEqual(len(findings.filter_items(self.ITEMS, query="missing")), 0)

    def test_kind_counts(self):
        counts = findings.kind_counts(self.ITEMS)
        self.assertEqual(counts["flag"], 1)
        self.assertEqual(sum(counts.values()), 3)


class CsvTest(unittest.TestCase):
    def test_header_and_rows(self):
        text = findings.to_csv([findings.make(
            "credential", "admin:p@ss", frame=7, feature="HTTP",
            detail="POST /login")])
        lines = text.strip().splitlines()
        self.assertEqual(lines[0], "类别,级别,帧,功能,摘要,详情")
        self.assertIn("凭据,info,7,HTTP,admin:p@ss,POST /login", lines[1])

    def test_quotes_commas(self):
        text = findings.to_csv([findings.make("file", "a,b", detail="x,y")])
        self.assertIn('"a,b"', text)


class ContextTest(unittest.TestCase):
    def test_add_finding_records_and_caps(self):
        ctx, logger = context()
        with mock.patch.object(findings, "MAX_FINDINGS", 2):
            ctx.add_finding("flag", "flag{one}")
            ctx.add_finding("flag", "flag{two}")
            self.assertIsNone(ctx.add_finding("flag", "flag{three}"))
        self.assertEqual([item["summary"] for item in ctx.findings],
                         ["flag{one}", "flag{two}"])
        self.assertTrue(any(level == "warn" for level, _ in logger.records))

    def test_findings_are_per_context(self):
        first, _ = context()
        second, _ = context()
        first.add_finding("hash", "a")
        self.assertEqual(len(second.findings), 0)


if __name__ == "__main__":
    unittest.main()
