"""Unit tests for fnet.config (defaults, typed accessors, persistence)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fnet.config import DEFAULT_REGMATCH, DEFAULTS, Config


class ConfigDefaultsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-config-"))

    def test_missing_file_is_seeded_from_default_config(self):
        path = self.tmp / "config.ini"
        config = Config(path)
        self.assertTrue(path.is_file())
        self.assertEqual(config.get("port"), DEFAULTS["config"]["port"])
        self.assertEqual(config.get_int("thread_count"),
                         int(DEFAULTS["config"]["thread_count"]))

    def test_regmatch_builtin_keywords(self):
        config = Config(self.tmp / "config.ini")
        patterns = config.regmatch()
        self.assertGreater(len(patterns), 10)
        self.assertIn(DEFAULT_REGMATCH.split(";")[0], patterns)


class ConfigAccessorsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-config-"))
        self.config = Config(self.tmp / "config.ini")

    def test_get_with_section_and_fallback(self):
        self.assertEqual(self.config.get("rules_file", "paths"), "")
        self.assertEqual(self.config.get("missing_key", "config", "fallback"),
                         "fallback")
        self.assertEqual(self.config.get("missing_key", "paths", "fallback"),
                         "fallback")

    def test_get_int_float_bool(self):
        self.config.set("thread_count", "80")
        self.assertEqual(self.config.get_int("thread_count"), 80)
        self.config.set("sql_time_threshold", "2.5")
        self.assertEqual(self.config.get_float("sql_time_threshold"), 2.5)
        self.assertEqual(self.config.get_float("missing", fallback=1.5), 1.5)
        self.config.set("open_browser", "0")
        self.assertFalse(self.config.get_bool("open_browser"))
        self.config.set("open_browser", "true")
        self.assertTrue(self.config.get_bool("open_browser"))

    def test_invalid_numeric_values_fall_back(self):
        self.config.set("thread_count", "not-a-number")
        self.assertEqual(self.config.get_int("thread_count"), 0)
        self.assertEqual(self.config.get_int("thread_count", fallback=7), 7)
        self.config.set("sql_time_threshold", "not-a-float")
        self.assertEqual(self.config.get_float("sql_time_threshold"), 0.0)
        self.assertEqual(self.config.get_float("sql_time_threshold",
                                               fallback=1.5), 1.5)

    def test_as_dict(self):
        values = self.config.as_dict("config")
        self.assertIn("port", values)
        self.assertEqual(self.config.as_dict("no-such-section"), {})


class ConfigPersistenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-config-"))
        self.path = self.tmp / "config.ini"

    def test_set_save_reload_roundtrip(self):
        config = Config(self.path)
        config.set("sql_success", "TRUE")
        config.set("execute_cmd", '{"nmap": ["nmap", "-sV"]}', "plugins")
        config.set("tls_keylog", "/tmp/key.log", "paths")
        config.save()
        reloaded = Config(self.path)
        self.assertEqual(reloaded.get("sql_success"), "TRUE")
        self.assertEqual(reloaded.get("execute_cmd", "plugins"),
                         '{"nmap": ["nmap", "-S"]}'.replace("-S", "-sV"))
        self.assertEqual(reloaded.get("tls_keylog", "paths"), "/tmp/key.log")

    def test_set_many(self):
        config = Config(self.path)
        config.set_many({"font": "Fira Code", "font_size": "14"})
        self.assertEqual(config.get("font"), "Fira Code")
        self.assertEqual(config.get("font_size"), "14")

    def test_unknown_section_is_created(self):
        config = Config(self.path)
        config.set("anything", "1", "brand-new-section")
        self.assertEqual(config.get("anything", "brand-new-section"), "1")

    def test_existing_user_file_is_not_overwritten(self):
        self.path.write_text("[config]\nport = 9999\n", encoding="utf-8")
        config = Config(self.path)
        self.assertEqual(config.get("port"), "9999")


class RecentFilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-config-"))
        self.config = Config(self.tmp / "config.ini")

    def test_add_and_deduplicate(self):
        self.config.add_recent("a.pcap")
        self.config.add_recent("b.pcap")
        self.config.add_recent("a.pcap")
        self.assertEqual(self.config.recent_files(), ["a.pcap", "b.pcap"])

    def test_recent_files_capped_at_twelve(self):
        for index in range(15):
            self.config.add_recent(f"f{index}.pcap")
        files = self.config.recent_files()
        self.assertEqual(len(files), 12)
        self.assertEqual(files[0], "f14.pcap")

    def test_empty_recent(self):
        self.assertEqual(self.config.recent_files(), [])


if __name__ == "__main__":
    unittest.main()
