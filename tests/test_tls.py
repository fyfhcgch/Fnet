"""Unit tests for TLS key discovery helpers (no tshark needed)."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fnet.features import tls


class TlsKeyTest(unittest.TestCase):
    def test_key_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keylog = root / "keys.log"
            keylog.write_text("CLIENT_RANDOM aa bb\n", encoding="utf-8")
            private = root / "server.pem"
            private.write_text(
                "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n"
                "-----END RSA PRIVATE KEY-----\n", encoding="utf-8")
            other = root / "notes.txt"
            other.write_text("hello\n", encoding="utf-8")
            self.assertEqual(tls.key_kind(keylog), "keylog")
            self.assertEqual(tls.key_kind(private), "key")
            self.assertEqual(tls.key_kind(other), "")
            self.assertEqual(tls.key_kind(root / "missing.log"), "")

    def test_discover_keys(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            keys = root / "keys"
            keys.mkdir()
            (keys / "a.log").write_text("CLIENT_RANDOM aa bb\n", encoding="utf-8")
            (keys / "b.pem").write_text(
                "-----BEGIN PRIVATE KEY-----\nMIIB\n", encoding="utf-8")
            (keys / "ignore.txt").write_text("nothing\n", encoding="utf-8")
            with mock.patch.object(tls, "CACHE_DIR", root):
                found = tls.discover_keys()
        self.assertEqual([path.name for path in found["keylog"]], ["a.log"])
        self.assertEqual([path.name for path in found["key"]], ["b.pem"])

    def test_discover_keys_without_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(tls, "CACHE_DIR", Path(tmp)):
                self.assertEqual(tls.discover_keys(),
                                 {"keylog": [], "key": []})

    def test_merge_keylogs_deduplicates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = root / "a.log"
            second = root / "b.log"
            first.write_text(
                "# comment\nCLIENT_RANDOM aa bb\nSERVER_HANDSHAKE_TRAFFIC_SECRET c d\n",
                encoding="utf-8")
            second.write_text(
                "CLIENT_RANDOM aa bb\nCLIENT_RANDOM ee ff\n", encoding="utf-8")
            merged, count = tls.merge_keylogs([first, second],
                                              root / "merged.log")
            self.assertEqual(count, 3)
            self.assertTrue(merged.is_file())
            text = merged.read_text(encoding="utf-8")
            self.assertEqual(text.count("CLIENT_RANDOM aa bb"), 1)
            self.assertIn("CLIENT_RANDOM ee ff", text)
            self.assertNotIn("# comment", text)

    def test_merge_keylogs_without_readable_lines(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            empty = root / "empty.log"
            empty.write_text("# only comments\n\n", encoding="utf-8")
            self.assertEqual(tls.merge_keylogs([empty], root / "out.log"),
                             (None, 0))


if __name__ == "__main__":
    unittest.main()
