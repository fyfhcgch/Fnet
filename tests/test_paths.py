"""Unit tests for fnet.paths (XDG layout, FNET_HOME relocation, wordlists)."""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fnet import paths

ROOT = Path(__file__).resolve().parents[1]


class PathConstantsTest(unittest.TestCase):
    def test_package_and_project_root(self):
        self.assertEqual(paths.PACKAGE_DIR.name, "fnet")
        self.assertEqual(paths.PROJECT_ROOT, ROOT)

    def test_platform_flags_are_mutually_exclusive(self):
        flags = [paths.IS_WINDOWS, paths.IS_MACOS, paths.IS_LINUX]
        self.assertEqual(sum(1 for flag in flags if flag), 1)

    def test_default_config_and_wordlist_exist(self):
        self.assertTrue(paths.DEFAULT_CONFIG.is_file())
        self.assertTrue(paths.DEFAULT_WORDLIST.is_file())

    def test_resource_joins_inside_assets(self):
        path = paths.resource("wordlists", "top1000.txt")
        self.assertTrue(path.is_file())
        self.assertEqual(path.parent, paths.WORDLIST_DIR)

    def test_ensure_dirs(self):
        paths.ensure_dirs()
        for directory in (paths.USER_DIR, paths.LOG_DIR, paths.CACHE_DIR):
            self.assertTrue(directory.is_dir())

    def test_user_config_lives_in_user_dir(self):
        self.assertEqual(paths.USER_CONFIG.parent, paths.USER_DIR)


class WordlistTest(unittest.TestCase):
    def test_default_when_empty(self):
        self.assertEqual(paths.wordlist(None), paths.DEFAULT_WORDLIST)
        self.assertEqual(paths.wordlist(""), paths.DEFAULT_WORDLIST)

    def test_absolute_path(self):
        self.assertEqual(paths.wordlist(str(paths.DEFAULT_WORDLIST)),
                         paths.DEFAULT_WORDLIST)

    def test_absolute_missing_path_returns_none(self):
        self.assertIsNone(paths.wordlist("/no/such/wordlist.txt"))

    def test_bare_file_name_resolves_into_wordlist_dir(self):
        self.assertEqual(paths.wordlist("top25000.txt"),
                         paths.WORDLIST_DIR / "top25000.txt")

    def test_asset_relative_path(self):
        # "assets/..." resolves inside the shipped asset tree (the assets
        # actually live in ``fnet/assets``).
        self.assertEqual(paths.wordlist("assets/wordlists/top1000.txt"),
                         paths.ASSETS_DIR / "wordlists" / "top1000.txt")

    def test_windows_style_separator_is_normalised(self):
        self.assertEqual(paths.wordlist("assets\\wordlists\\top1000.txt"),
                         paths.ASSETS_DIR / "wordlists" / "top1000.txt")

    def test_unknown_name_returns_none(self):
        self.assertIsNone(paths.wordlist("no/such/file.txt"))


class EnvironmentRelocationTest(unittest.TestCase):
    """``FNET_HOME``/XDG variables are read at import time, so verify them in
    a child interpreter (argument-array subprocess, no shell)."""

    CODE = (
        "from fnet import paths;"
        "print(paths.USER_DIR);"
        "print(paths.LOG_DIR);"
        "print(paths.CACHE_DIR);"
        "print(paths.USER_CONFIG)"
    )

    def run_fnet_paths(self, env: dict[str, str]) -> list[str]:
        result = subprocess.run(
            [sys.executable, "-c", self.CODE],
            capture_output=True, text=True, timeout=60, cwd=str(ROOT),
            env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip().splitlines()

    def base_env(self) -> dict[str, str]:
        env = dict(os.environ)
        env.pop("FNET_HOME", None)
        return env

    def test_fnet_home_relocates_everything(self):
        home = Path(tempfile.mkdtemp(prefix="fnet-home-"))
        env = self.base_env()
        env["FNET_HOME"] = str(home)
        user, log, cache, config = self.run_fnet_paths(env)
        self.assertEqual(Path(user), home)
        self.assertEqual(Path(log), home / "logs")
        self.assertEqual(Path(cache), home / "cache")
        self.assertEqual(Path(config), home / "config.ini")

    def test_xdg_dirs_are_honoured_without_fnet_home(self):
        state = Path(tempfile.mkdtemp(prefix="fnet-state-"))
        cache = Path(tempfile.mkdtemp(prefix="fnet-cache-"))
        env = self.base_env()
        env["XDG_STATE_HOME"] = str(state)
        env["XDG_CACHE_HOME"] = str(cache)
        user, log, cache_out, config = self.run_fnet_paths(env)
        self.assertEqual(Path(user), Path.home() / ".config" / "fnet")
        self.assertEqual(Path(log), state / "fnet" / "logs")
        self.assertEqual(Path(cache_out), cache / "fnet")
        self.assertEqual(Path(config),
                         Path.home() / ".config" / "fnet" / "config.ini")

    def test_fnet_assets_overrides_asset_tree(self):
        assets = Path(tempfile.mkdtemp(prefix="fnet-assets-"))
        env = self.base_env()
        env["FNET_ASSETS"] = str(assets)
        result = subprocess.run(
            [sys.executable, "-c",
             "from fnet import paths; print(paths.ASSETS_DIR)"],
            capture_output=True, text=True, timeout=60, cwd=str(ROOT),
            env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(Path(result.stdout.strip()), assets)


if __name__ == "__main__":
    unittest.main()
