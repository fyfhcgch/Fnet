"""Lifecycle tests for :class:`fnet.live.LiveCapture`.

Real packet capture needs root and a live interface, so these tests drive a
small stub executable in place of ``tshark``: it writes a pcap header to the
``-w`` target, then blocks until SIGINT.  That covers argument building,
running-state reporting, the "one capture at a time" guard and SIGINT based
shutdown without touching the network.
"""
from __future__ import annotations

import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from fnet.live import LiveCapture, parse_interfaces
from fnet.tools.runner import IS_WINDOWS

# 24 byte little-endian pcap header, enough for ``capinfos``/``tshark``.
PCAP_HEADER = bytes.fromhex("d4c3b2a1020004000000000000000000ffff000001000000")

STUB = f'''#!{sys.executable}
import signal
import sys
import time
from pathlib import Path

args = sys.argv[1:]
target = args[args.index("-w") + 1]
Path(target).write_bytes({PCAP_HEADER!r})

def _stop(*_):
    sys.exit(0)

signal.signal(signal.SIGINT, _stop)
print("stub tshark started", flush=True)
while True:
    time.sleep(0.1)
'''


class _Toolbox:
    """Minimal stand-in for ``ToolBox`` returning a fixed tshark path."""

    def __init__(self, path: str | None) -> None:
        self._path = path or ""

    def path(self, name: str) -> str:  # noqa: ARG002 - only tshark is used
        return self._path


@unittest.skipIf(IS_WINDOWS, "stub 使用 POSIX 信号")
class LiveCaptureTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.cache = root / "cache"
        self.cache.mkdir()
        self.stub = root / "stub-tshark"
        self.stub.write_text(STUB, encoding="utf-8")
        self.stub.chmod(self.stub.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
        self.patch = mock.patch("fnet.live.CACHE_DIR", self.cache)
        self.patch.start()
        self.capture = LiveCapture(_Toolbox(str(self.stub)), mock.Mock())

    def tearDown(self):
        try:
            self.capture.shutdown()
        finally:
            self.patch.stop()
            self.tmp.cleanup()

    def test_start_requires_interface(self):
        with self.assertRaises(ValueError):
            self.capture.start("")

    def test_start_rejects_control_characters(self):
        with self.assertRaises(ValueError):
            self.capture.start("eth0\n--help")
        with self.assertRaises(ValueError):
            self.capture.start("eth0", "tcp\nhost 1.2.3.4")

    def test_start_without_tshark(self):
        capture = LiveCapture(_Toolbox(None), mock.Mock())
        with self.assertRaises(ValueError):
            capture.start("eth0")

    def test_status_before_start(self):
        status = self.capture.status()
        self.assertFalse(status["running"])
        self.assertEqual(status["path"], "")
        self.assertEqual(status["size"], 0)
        self.assertEqual(status["pid"], 0)

    def test_start_and_stop(self):
        status = self.capture.start("eth0", "tcp port 80", "demo")
        self.assertTrue(status["running"])
        self.assertEqual(status["interface"], "eth0")
        self.assertEqual(status["filter"], "tcp port 80")
        self.assertGreater(status["pid"], 0)
        path = Path(status["path"])
        self.assertTrue(path.is_file())
        self.assertTrue(path.name.startswith("live-"))
        self.assertIn("demo", path.name)
        self.assertEqual(path.parent, self.cache / "live")
        # Give tshark a moment to flush the header to disk.
        deadline = time.time() + 5
        while time.time() < deadline and self.capture.status()["size"] == 0:
            time.sleep(0.05)
        self.assertEqual(self.capture.status()["size"], len(PCAP_HEADER))

        with self.assertRaises(ValueError):
            self.capture.start("eth0")

        stopped = self.capture.stop()
        self.assertFalse(stopped["running"])
        self.assertEqual(stopped["interface"], "eth0")
        self.assertEqual(stopped["filter"], "tcp port 80")
        self.assertEqual(stopped["pid"], 0)
        self.assertEqual(Path(stopped["path"]), path)
        self.assertEqual(stopped["size"], len(PCAP_HEADER))
        self.assertIn("stub tshark started", stopped["output"])
        # A second stop is a no-op and keeps reporting the saved file.
        again = self.capture.stop()
        self.assertFalse(again["running"])
        self.assertEqual(again["path"], stopped["path"])

    def test_shutdown_stops_running_capture(self):
        self.capture.start("mon0")
        self.assertTrue(self.capture.status()["running"])
        self.capture.shutdown()
        self.assertFalse(self.capture.status()["running"])

    def test_interfaces_without_tshark(self):
        self.assertEqual(LiveCapture(_Toolbox(None), mock.Mock()).interfaces(), [])

    def test_interfaces_parses_tshark_output(self):
        capture = LiveCapture(_Toolbox("/bin/echo"), mock.Mock())
        with mock.patch("fnet.live.run",
                        return_value=(0, "1. eth0\n2. wlan0 (Wi-Fi)\n")):
            items = capture.interfaces()
        self.assertEqual([item["name"] for item in items], ["eth0", "wlan0"])
        self.assertEqual(items[1]["description"], "Wi-Fi")

    def test_interfaces_survives_failure(self):
        capture = LiveCapture(_Toolbox("/bin/echo"), mock.Mock())
        with mock.patch("fnet.live.run", return_value=(1, "boom")):
            self.assertEqual(capture.interfaces(), [])


class ParseInterfacesExtraTest(unittest.TestCase):
    def test_description_with_spaces_and_hyphen(self):
        items = parse_interfaces("4. en0 (Apple Wi-Fi - primary)\n")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["index"], 4)
        self.assertEqual(items[0]["name"], "en0")
        self.assertEqual(items[0]["description"], "Apple Wi-Fi - primary")

    def test_lines_without_index_are_ignored(self):
        self.assertEqual(parse_interfaces("Capturing on 'eth0'\n"), [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
