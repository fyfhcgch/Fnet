"""Unit tests for fnet.utils.system (platform helpers, mocked subprocesses)."""
from __future__ import annotations

import sys
import unittest
from unittest import mock

from fnet.utils import system

# system.py only exports IS_WINDOWS / IS_MACOS.
IS_LINUX = not system.IS_WINDOWS and not system.IS_MACOS


class PlatformFlagsTest(unittest.TestCase):
    def test_flags_match_sys_platform(self):
        self.assertEqual(system.IS_WINDOWS, sys.platform.startswith("win"))
        self.assertEqual(system.IS_MACOS, sys.platform == "darwin")


class OpenPathTest(unittest.TestCase):
    @unittest.skipUnless(IS_LINUX, "Linux 分支行为")
    def test_linux_uses_xdg_open(self):
        opener = "/usr/bin/xdg-open"
        with mock.patch.object(system.shutil, "which", return_value=opener), \
                mock.patch.object(system.subprocess, "Popen") as popen:
            self.assertTrue(system.open_path("/tmp/demo"))
        popen.assert_called_once()
        # which() only checks availability; the bare command name is spawned.
        self.assertEqual(popen.call_args[0][0], ["xdg-open", "/tmp/demo"])

    @unittest.skipUnless(IS_LINUX, "Linux 分支行为")
    def test_linux_falls_back_to_gio(self):
        with mock.patch.object(system.shutil, "which", return_value=None), \
                mock.patch.object(system.subprocess, "Popen") as popen:
            self.assertTrue(system.open_path("/tmp/demo"))
        self.assertEqual(popen.call_args[0][0], ["gio", "open", "/tmp/demo"])

    @unittest.skipUnless(IS_LINUX, "Linux 分支行为")
    def test_spawn_failure_returns_false(self):
        with mock.patch.object(system.shutil, "which", return_value="/usr/bin/xdg-open"), \
                mock.patch.object(system.subprocess, "Popen",
                                  side_effect=OSError("no fork")):
            self.assertFalse(system.open_path("/tmp/demo"))

    @unittest.skipIf(IS_LINUX, "仅验证 Windows/macOS 分支")
    def test_non_linux_branches(self):
        if system.IS_WINDOWS:
            with mock.patch.object(system.os, "startfile",
                                   create=True) as startfile:
                self.assertTrue(system.open_path("C:\\tmp"))
            startfile.assert_called_once_with("C:\\tmp")
        else:
            with mock.patch.object(system.subprocess, "Popen") as popen:
                self.assertTrue(system.open_path("/tmp/demo"))
            self.assertEqual(popen.call_args[0][0], ["open", "/tmp/demo"])


class RevealTest(unittest.TestCase):
    @unittest.skipUnless(IS_LINUX, "Linux 分支行为")
    def test_linux_reveals_parent_directory(self):
        opener = "/usr/bin/xdg-open"
        with mock.patch.object(system.shutil, "which", return_value=opener), \
                mock.patch.object(system.subprocess, "Popen") as popen:
            self.assertTrue(system.reveal("/tmp/demo/sub/file.txt"))
        self.assertEqual(popen.call_args[0][0], ["xdg-open", "/tmp/demo/sub"])

    @unittest.skipIf(IS_LINUX, "仅验证 Windows/macOS 分支")
    def test_native_reveal(self):
        if system.IS_WINDOWS:
            with mock.patch.object(system.subprocess, "Popen") as popen:
                self.assertTrue(system.reveal("C:\\tmp\\a.txt"))
            self.assertEqual(popen.call_args[0][0],
                             ["explorer", "/select,", "C:\\tmp\\a.txt"])
        else:
            with mock.patch.object(system.subprocess, "Popen") as popen:
                self.assertTrue(system.reveal("/tmp/a.txt"))
            self.assertEqual(popen.call_args[0][0], ["open", "-R", "/tmp/a.txt"])


class OpenUrlTest(unittest.TestCase):
    def test_open_url_returns_browser_result(self):
        with mock.patch("webbrowser.open", return_value=True) as opened:
            self.assertTrue(system.open_url("https://example.org"))
        opened.assert_called_once_with("https://example.org")

    def test_open_url_failure_returns_false(self):
        with mock.patch("webbrowser.open", side_effect=RuntimeError("boom")):
            self.assertFalse(system.open_url("https://example.org"))


class DefaultMonoFontTest(unittest.TestCase):
    def test_returns_a_family_name(self):
        self.assertIsInstance(system.default_mono_font(), str)
        self.assertTrue(system.default_mono_font())

    @unittest.skipUnless(IS_LINUX, "fc-match 分支")
    def test_linux_without_fc_match_uses_monospace(self):
        with mock.patch.object(system.shutil, "which", return_value=None):
            self.assertEqual(system.default_mono_font(), "monospace")

    @unittest.skipUnless(IS_LINUX, "fc-match 分支")
    def test_linux_prefers_installed_family(self):
        fake_result = mock.Mock(returncode=0, stdout="DejaVu Sans Mono,Foo")
        with mock.patch.object(system.shutil, "which", return_value="/usr/bin/fc-match"), \
                mock.patch.object(system.subprocess, "run",
                                  return_value=fake_result) as run:
            self.assertEqual(system.default_mono_font(), "DejaVu Sans Mono")
        run.assert_called_once()
        argv = run.call_args[0][0]
        self.assertEqual(argv, ["/usr/bin/fc-match", "-f", "%{family}"])

    @unittest.skipUnless(IS_LINUX, "fc-match 分支")
    def test_fc_match_failure_falls_back_to_monospace(self):
        with mock.patch.object(system.shutil, "which", return_value="/usr/bin/fc-match"), \
                mock.patch.object(system.subprocess, "run",
                                  side_effect=OSError("timeout")):
            self.assertEqual(system.default_mono_font(), "monospace")


if __name__ == "__main__":
    unittest.main()
