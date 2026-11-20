"""测试共用的隔离工具。

存在的理由（见 ``AGENTS.md`` 的 Testing gotchas 一节）：
``fnet.jobs.CACHE_DIR`` 与 ``fnet.paths.CACHE_DIR`` 是两个**独立的**名字，
任务产物走前者、tshark 的 TSV 缓存走后者。只 patch 其中一个会让测试把
文件写进开发者真实的 ``~/.cache/fnet/``，既污染本机也让测试之间互相影响。
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest import mock


def patch_cache_dirs(root: str | Path) -> list[mock._patch]:
    """返回**同时**指向 ``root`` 的两个 CACHE_DIR patch（未启动）。

    调用方负责 ``start()`` / ``stop()``，这样 unittest 的 ``setUpClass`` /
    ``tearDownClass`` 仍能保持原有结构::

        cls.patches = patch_cache_dirs(Path(cls.tmp.name))
        for patch in cls.patches:
            patch.start()
    """
    target = Path(root)
    return [
        mock.patch("fnet.jobs.CACHE_DIR", target),
        mock.patch("fnet.paths.CACHE_DIR", target),
    ]


class IsolatedCache:
    """``with IsolatedCache() as cache:`` —— 临时目录 + 两个 CACHE_DIR。

    ``cache.path`` 是临时根目录，``cache.patches`` 已启动的 patch 列表。
    """

    def __init__(self, prefix: str = "fnet-test-"):
        self.prefix = prefix
        self.tmp: tempfile.TemporaryDirectory | None = None
        self.patches: list[mock._patch] = []

    @property
    def path(self) -> Path:
        if self.tmp is None:  # pragma: no cover - 只在误用时触发
            raise RuntimeError("IsolatedCache 尚未进入 with 块")
        return Path(self.tmp.name)

    def __enter__(self) -> "IsolatedCache":
        self.tmp = tempfile.TemporaryDirectory(prefix=self.prefix)
        self.patches = patch_cache_dirs(self.path)
        for patch in self.patches:
            patch.start()
        return self

    def __exit__(self, *exc_info) -> None:
        for patch in reversed(self.patches):
            patch.stop()
        self.patches = []
        if self.tmp is not None:
            self.tmp.cleanup()
            self.tmp = None
