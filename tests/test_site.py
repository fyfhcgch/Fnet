"""Consistency checks for the GitHub Pages site sources.

The site is a plain Jekyll project (``_config.yml`` + ``index.md`` +
``manual/``) built by GitHub Pages from ``master``.  These tests keep the
version shown on the site in sync with the package and guard the deployment
source, so a stale ``_config.yml`` cannot silently publish an old version.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

from fnet import __version__
from fnet.features.registry import CATEGORIES, FEATURES

ROOT = Path(__file__).resolve().parents[1]
SITE_CONFIG = ROOT / "_config.yml"
SITE_INDEX = ROOT / "index.md"
SITE_FOOTER = ROOT / "_includes" / "footer.html"


def _site_version() -> str:
    text = SITE_CONFIG.read_text(encoding="utf-8")
    match = re.search(r"^version:\s*([0-9][^\s#]*)", text, re.MULTILINE)
    return match.group(1) if match else ""


class SiteVersionTest(unittest.TestCase):
    def test_config_version_matches_package(self):
        self.assertEqual(_site_version(), __version__)

    def test_footer_renders_site_version(self):
        footer = SITE_FOOTER.read_text(encoding="utf-8")
        self.assertIn("site.version", footer)

    def test_index_shows_the_version(self):
        index = SITE_INDEX.read_text(encoding="utf-8")
        self.assertIn("site.version", index)

    def test_index_reports_current_feature_counts(self):
        index = SITE_INDEX.read_text(encoding="utf-8")
        self.assertIn(f"{len(FEATURES)} 项功能", index)
        self.assertIn(f"{len(CATEGORIES)} 类", index)

    def test_pages_source_excludes_developer_files(self):
        config = SITE_CONFIG.read_text(encoding="utf-8")
        for name in ("README.md", "TODO.md", "tests", "fnet"):
            self.assertRegex(config, rf"(?ms)^exclude:.*^\s*-\s*{re.escape(name)}\s*$")

    def test_page_layout_override_applies_homepage_hero(self):
        # _layouts/page.html overrides minima so every manual page gets the
        # same hero UI (title, lead, version badge) as the homepage.
        layout = (ROOT / "_layouts" / "page.html").read_text(encoding="utf-8")
        self.assertIn("layout: default", layout)
        self.assertIn("docs-hero", layout)
        self.assertIn("site.version", layout)
        self.assertIn("page.description", layout)
        self.assertIn("site.version", layout)
        scss = (ROOT / "assets" / "main.scss").read_text(encoding="utf-8")
        self.assertIn(".docs-hero", scss)
        self.assertIn(".badge.version-badge", scss)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
