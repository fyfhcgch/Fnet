"""Unit tests for the WebUI service helpers (no tshark needed)."""
from __future__ import annotations

import tempfile
import json
import unittest
from pathlib import Path
from unittest import mock

from fnet import services


class FakeToolbox:
    def __init__(self, wireshark: str | None) -> None:
        self.wireshark = wireshark

    def path(self, key: str) -> str | None:
        return self.wireshark if key == "wireshark" else None


class ServicesTest(unittest.TestCase):
    def test_clamp_frame(self):
        self.assertEqual(services.clamp_frame("12"), 12)
        self.assertEqual(services.clamp_frame(1), 1)
        self.assertIsNone(services.clamp_frame("0"))
        self.assertIsNone(services.clamp_frame("-3"))
        self.assertIsNone(services.clamp_frame("abc"))
        self.assertIsNone(services.clamp_frame(""))
        self.assertIsNone(services.clamp_frame("1000000001"))

    def test_clamp_context(self):
        self.assertEqual(services.clamp_context("3"), 3)
        self.assertEqual(services.clamp_context("abc"), 2)
        self.assertEqual(services.clamp_context("-1"), 0)
        self.assertEqual(services.clamp_context("999"), 20)
        self.assertEqual(services.clamp_context("4", default=1, maximum=5), 4)

    def test_frame_range_stops_at_one(self):
        self.assertEqual(services.frame_range(2, 2), (1, 4))
        self.assertEqual(services.frame_range(10, 3), (7, 13))

    def test_open_wireshark_uses_argument_array(self):
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "sample.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
            with mock.patch.object(services.subprocess, "Popen") as popen:
                result = services.open_wireshark(
                    str(pcap), "7", FakeToolbox("/usr/bin/wireshark"))
        self.assertTrue(result["ok"])
        args, kwargs = popen.call_args
        self.assertEqual(args[0][:2], ["/usr/bin/wireshark", "-r"])
        self.assertIn("frame.number == 7", args[0])
        self.assertFalse(kwargs.get("shell", False))

    def test_open_wireshark_requires_tool_and_capture(self):
        result = services.open_wireshark(
            "/nonexistent/sample.pcap", 7, FakeToolbox("/usr/bin/wireshark"))
        self.assertFalse(result["ok"])
        with tempfile.TemporaryDirectory() as tmp:
            pcap = Path(tmp) / "sample.pcap"
            pcap.write_bytes(b"\xd4\xc3\xb2\xa1")
            result = services.open_wireshark(str(pcap), 7, FakeToolbox(None))
        self.assertFalse(result["ok"])
        self.assertIn("Wireshark", result["text"])

    def test_bucket_timeline_aggregates_samples(self):
        points, low, high = services.bucket_timeline(
            [("0.0", "100"), ("1.0", "200"), ("2.0", "300")], buckets=3)
        self.assertEqual((low, high), (0.0, 2.0))
        self.assertEqual(len(points), 3)
        self.assertEqual(sum(point["frames"] for point in points), 3)
        self.assertEqual(sum(point["bytes"] for point in points), 600)
        self.assertEqual(points[0]["time"], 0.0)
        self.assertAlmostEqual(points[2]["time"], 4 / 3)

    def test_bucket_timeline_skips_invalid_rows(self):
        points, low, high = services.bucket_timeline(
            [("abc", "1"), ("", ""), ("3.0", "bad")], buckets=4)
        self.assertEqual(len(points), 4)
        self.assertEqual((low, high), (3.0, 3.0))
        self.assertEqual(sum(point["frames"] for point in points), 1)
        self.assertEqual(points[0]["frames"], 1)
        self.assertEqual(points[0]["bytes"], 0)

    def test_bucket_timeline_empty_and_clamped(self):
        self.assertEqual(services.bucket_timeline([], 10), ([], 0.0, 0.0))
        points, _low, _high = services.bucket_timeline([("1", "1")], buckets=0)
        self.assertEqual(len(points), 1)
        points, _low, _high = services.bucket_timeline([("1", "1")], buckets=999)
        self.assertEqual(len(points), 240)


class LogStatsTest(unittest.TestCase):
    """Stats subs for text-log inputs (the 统计图表 page on log jobs)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name: str, text: str) -> str:
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        return str(path)

    def test_timeline_shape_matches_capture_side(self):
        path = self._write("events.log", "\n".join(
            f"2026-01-01 10:00:{index:02d} info client_ip=10.0.0.{index % 3}"
            for index in range(10)) + "\n")
        result = services.log_timeline(path, 10)
        self.assertTrue(result["ok"])
        self.assertEqual(result["kind"], "log")
        self.assertLessEqual(len(result["points"]), 11)
        for point in result["points"]:
            self.assertEqual(set(point), {"time", "frames", "bytes"})
            self.assertEqual(point["bytes"], 0)
        self.assertEqual(sum(point["frames"] for point in result["points"]), 10)
        self.assertEqual(result["total_frames"], 10)
        self.assertEqual(result["total_bytes"], 0)
        self.assertEqual(result["start"], min(p["time"] for p in result["points"]))
        self.assertEqual(result["buckets"], len(result["points"]))
        self.assertIn("条日志", result["text"])

    def test_timeline_without_timestamps_is_a_clean_empty(self):
        path = self._write("plain.log", "hello\nworld\nagain\n")
        result = services.log_timeline(path)
        self.assertFalse(result["ok"])
        self.assertEqual(result["kind"], "log")
        self.assertIn("时间戳", result["text"])
        self.assertEqual(result.get("points", []), [])

    def test_timeline_single_timestamp_is_empty(self):
        path = self._write("one.log", "2026-01-01 10:00:00 only one\nplain\n")
        result = services.log_timeline(path)
        self.assertFalse(result["ok"])
        self.assertEqual(result["kind"], "log")

    def test_hierarchy_maps_levels_in_chinese_shape(self):
        text = "\n".join([
            "2026-01-01 10:00:00 error db down",
            "2026-01-01 10:00:01 warn slow query",
            "2026-01-01 10:00:02 warn retry",
            "2026-01-01 10:00:03 info started",
            "2026-01-01 10:00:04 debug detail",
        ])
        result = services.log_level_hierarchy(self._write("levels.log", text))
        self.assertTrue(result["ok"])
        self.assertEqual(result["kind"], "log")
        levels = {item["label"]: item["frames"] for item in result["items"]}
        self.assertEqual(levels, {"error": 1, "warn": 2, "info": 1,
                                  "debug": 1})
        for item in result["items"]:
            self.assertEqual(set(item), {"label", "frames", "bytes"})
        self.assertIn("级别", result["text"])

    def test_top_entities_prefers_user_over_ip(self):
        text = "\n".join([
            "2026-01-01 10:00:00 failed user=bob ip=10.0.0.1",
            "2026-01-01 10:00:01 failed user=bob ip=10.0.0.2",
            "2026-01-01 10:00:02 failed user=alice ip=10.0.0.3",
        ])
        result = services.log_top_entities(self._write("users.log", text))
        self.assertTrue(result["ok"])
        self.assertEqual(result["kind"], "log")
        self.assertEqual([item["label"] for item in result["items"]],
                         ["bob", "alice"])
        self.assertEqual(result["items"][0]["frames"], 2)

    def test_top_entities_without_any_is_a_clean_empty(self):
        path = self._write("noent.log", "2026-01-01 10:00:00 nothing here\n")
        result = services.log_top_entities(path)
        self.assertFalse(result["ok"])
        self.assertEqual(result["kind"], "log")
        self.assertIn("实体", result["text"])

    def test_entity_stats_dimension_whitelist(self):
        path = self._write("dims.log", "\n".join([
            "2026-01-01 10:00:00 client_id=alice Key: key_a ok",
            "2026-01-01 10:00:01 client_id=bob Invalid key",
        ]) + "\n")
        result = services.log_entity_stats(path, "client_id")
        self.assertTrue(result["ok"])
        self.assertEqual(result["kind"], "log")
        self.assertEqual(result["dimension"], "client_id")
        self.assertIn("client_id", result["dimensions"])
        self.assertEqual(result["total"], len(result["items"]))
        self.assertFalse(result["truncated"])
        item = result["items"][0]
        for key in ("value", "count", "share", "fail", "fail_rate",
                    "success", "success_rate", "first", "last", "line",
                    "sample"):
            self.assertIn(key, item)
        bad = services.log_entity_stats(path, "not_a_field")
        self.assertFalse(bad["ok"])
        self.assertEqual(bad["kind"], "log")
        self.assertIn("可用维度", bad["text"])
        self.assertIn("client_id", bad["dimensions"])
        self.assertEqual(bad["items"], [])

    def test_entity_stats_limit_and_truncated(self):
        lines = [f"2026-01-01 10:{index // 60:02d}:{index % 60:02d} "
                 f"client_id=u{index}" for index in range(80)]
        path = self._write("many.log", "\n".join(lines) + "\n")
        result = services.log_entity_stats(path, "client_id")
        self.assertTrue(result["ok"])
        self.assertLessEqual(len(result["items"]), 50)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["total"], 80)
        small = services.log_entity_stats(path, "client_id", limit=5)
        self.assertEqual(len(small["items"]), 5)
        self.assertTrue(small["truncated"])
        self.assertEqual(small["items"][0]["value"], "u0")

    def test_entity_stats_subnet_prefix_fallback(self):
        path = self._write("sub.log", "\n".join([
            "2026-01-01 10:00:00 client_ip=10.1.1.5 ok",
            "2026-01-01 10:00:01 client_ip=10.1.9.5 ok",
        ]) + "\n")
        good = services.log_entity_stats(path, "网段", subnet_prefix=16)
        self.assertTrue(good["ok"])
        self.assertEqual(good["subnet_prefix"], 16)
        self.assertIn("10.1.0.0/16",
                      {item["value"] for item in good["items"]})
        bad = services.log_entity_stats(path, "网段", subnet_prefix=40)
        self.assertTrue(bad["ok"])  # 越界优雅回退，不报错
        self.assertEqual(bad["subnet_prefix"], 24)
        self.assertIn("subnet_prefix 超出范围", bad["text"])
        self.assertIn("10.1.1.0/24",
                      {item["value"] for item in bad["items"]})
        junk = services.log_entity_stats(path, "网段", subnet_prefix="abc")
        self.assertTrue(junk["ok"])
        self.assertIn("subnet_prefix", junk["text"])
        self.assertIn("10.1.9.0/24",
                      {item["value"] for item in junk["items"]})

    def test_entity_stats_regex_fallback(self):
        path = self._write("re.log", "\n".join([
            "2026-01-01 10:00:00 client_id=alice Key: key_a ok",
            "2026-01-01 10:00:01 client_id=alice Invalid key",
        ]) + "\n")
        ok = services.log_entity_stats(path, "client_id",
                                       success_regex=r"Key: key_")
        self.assertTrue(ok["ok"])
        entry = next(item for item in ok["items"]
                     if item["value"] == "alice")
        self.assertEqual((entry["success"], entry["fail"]), (1, 1))
        broken = services.log_entity_stats(path, "client_id",
                                           success_regex="(")
        self.assertTrue(broken["ok"])
        self.assertIn("success_regex 无效", broken["text"])
        entry = next(item for item in broken["items"]
                     if item["value"] == "alice")
        # 回退口径：未命中失败关键字即成功。
        self.assertEqual((entry["success"], entry["fail"]), (1, 1))
        broken_fail = services.log_entity_stats(path, "client_id",
                                                fail_regex="([")
        self.assertTrue(broken_fail["ok"])
        self.assertIn("fail_regex 无效", broken_fail["text"])
        entry = next(item for item in broken_fail["items"]
                     if item["value"] == "alice")
        # 默认失败规则仍然命中 Invalid key。
        self.assertEqual(entry["fail"], 1)

    def test_entity_stats_parse_failure_and_empty_dimension(self):
        missing = services.log_entity_stats(str(self.dir / "missing.log"),
                                            "client_id")
        self.assertFalse(missing["ok"])
        self.assertEqual(missing["kind"], "log")
        self.assertTrue(missing["text"])
        self.assertEqual(missing["items"], [])
        empty = self._write("empty.log", "")
        result = services.log_entity_stats(empty, "client_id")
        self.assertFalse(result["ok"])
        self.assertIn("解析", result["text"])
        # 维度在白名单内但没有任何值时，也给出明确原因而不是抛异常。
        path = self._write("dims2.log",
                           "2026-01-01 10:00:00 client_id=alice ok\n")
        from fnet.features import logs as log_features

        with mock.patch.object(log_features, "entity_stats",
                               return_value=[]):
            blank = services.log_entity_stats(path, "client_id")
        self.assertFalse(blank["ok"])
        self.assertIn("没有统计到任何值", blank["text"])
        self.assertEqual(blank["items"], [])

    def test_topology_with_client_and_peer(self):
        rows = []
        for index in range(6):
            rows.append(json.dumps({
                "time": f"2026-01-02T00:00:{index:02d}",
                "level": "info",
                "client_ip": f"10.1.1.{index % 2}",
                "server": f"srv-{index % 3}",
                "message": f"probe {index}",
            }))
        result = services.log_topology(self._write("pairs.jsonl",
                                                   "\n".join(rows) + "\n"))
        self.assertTrue(result["ok"])
        self.assertEqual(result["kind"], "log")
        self.assertEqual(len(result["nodes"]), 5)
        self.assertGreater(len(result["edges"]), 0)
        node = result["nodes"][0]
        for key in ("id", "label", "ip", "port", "frames", "bytes", "peers",
                    "protocols"):
            self.assertIn(key, node)
        edge = result["edges"][0]
        for key in ("source", "target", "frames", "bytes", "protocol",
                    "first_frame", "last_frame"):
            self.assertIn(key, edge)
        self.assertEqual(result["total_bytes"], 0)
        self.assertGreater(result["max_frames"], 0)

    def test_topology_with_ip_but_no_peer_falls_back(self):
        text = "\n".join(
            f"2026-01-01 10:00:{index:02d} scan from 10.0.0.{index}"
            for index in range(3))
        result = services.log_topology(self._write("iponly.log", text))
        self.assertFalse(result["ok"])
        self.assertEqual(result["kind"], "log")
        self.assertIn("对端标识", result["text"])
        self.assertEqual(result.get("nodes", []), [])

    def test_parse_failure_never_raises(self):
        result = services.log_timeline(str(self.dir / "missing.log"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["kind"], "log")
        self.assertTrue(result["text"])

    def test_record_cap_is_inherited_from_parse_path(self):
        lines = [f"2026-01-03 00:00:{index % 60:02d} "
                 f"client_id=u{index % 5} server=srv{index % 5}"
                 for index in range(500)]
        path = self._write("cap.log", "\n".join(lines) + "\n")
        from fnet.utils import logfile

        capped = logfile.parse_path(path, limit=100)
        self.assertEqual(len(capped.records), 100)
        points = services.log_timeline_points(capped, 30)
        self.assertEqual(sum(point["frames"] for point in points), 100)
        items = services.log_entity_items(capped)
        # The display list is capped at 20 rows, but every capped record
        # feeds the underlying count.
        self.assertLessEqual(len(items), 20)
        self.assertEqual(sum(item["frames"] for item in items), 100)
        base = services.log_topology_base(capped)
        self.assertEqual(base["total_frames"], 100)

    def test_drilldowns_return_record_lists(self):
        rows = [json.dumps({"time": f"2026-01-02T00:00:{index:02d}",
                            "level": "warn" if index % 2 else "error",
                            "client_ip": "10.1.1.1", "server": "srv",
                            "message": f"m{index}"})
                for index in range(10)]
        path = self._write("drill.jsonl", "\n".join(rows) + "\n")
        from fnet.utils import logfile

        log = logfile.parse_path(path)
        low = min(r.epoch for r in log.records if r.epoch is not None)
        bucket = services.log_timeline_packets(path, low, low + 5, 5)
        self.assertTrue(bucket["ok"])
        self.assertEqual(bucket["kind"], "log")
        self.assertLessEqual(len(bucket["packets"]), 5)
        packet = bucket["packets"][0]
        for key in ("frame", "time", "src", "dst", "protocol", "info",
                    "length"):
            self.assertIn(key, packet)
        by_level = services.log_protocol_detail(path, "warn", 100)
        self.assertTrue(by_level["ok"])
        self.assertEqual(by_level["kind"], "log")
        self.assertTrue(all(p["protocol"] == "warn"
                            for p in by_level["packets"]))
        self.assertFalse(services.log_protocol_detail(path, "bad name!")["ok"])


if __name__ == "__main__":
    unittest.main()
