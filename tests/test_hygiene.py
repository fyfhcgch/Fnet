"""仓库级不变量：版本同步、stdlib-only 承诺、全模块可导入。

这些断言不依赖 tshark，也不会启动任何外部进程，因此可以放进默认测试集。
"""
from __future__ import annotations

import ast
import importlib
import pkgutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "fnet"

#: 允许出现在 ``fnet/`` 里的第三方模块名。它们只能在函数体内按需导入，
#: 并且必须带回退（见 AGENTS.md「可选加速层」）。
OPTIONAL_DEPENDENCIES = frozenset({
    "numba", "cupy", "numpy",
    "cryptography",
    "scapy",
    "pyrdp",
})


def _stdlib_names() -> set[str]:
    names = set(sys.stdlib_module_names)
    names.update({"__future__", "fnet", "tests", "scripts"})
    return names


def _top_level_imports(path: Path) -> list[tuple[int, str]]:
    """返回文件顶层的 ``import``/``from ... import`` 目标（不含函数体内）。"""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[int, str]] = []
    for node in tree.body:  # 只遍历模块顶层
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((node.lineno, alias.name.split(".")[0]))
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # 相对导入属于本包
                continue
            if node.module:
                found.append((node.lineno, node.module.split(".")[0]))
    return found


class VersionSyncTest(unittest.TestCase):
    """``pyproject.toml`` 与 ``fnet/__init__.py`` 的版本必须一致。"""

    def test_pyproject_matches_package_version(self):
        try:
            import tomllib
        except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
            self.skipTest("tomllib 需要 Python 3.11+")
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        declared = data["project"]["version"]
        from fnet import __version__

        self.assertEqual(declared, __version__)

    def test_site_config_matches_package_version(self):
        from fnet import __version__

        config = (ROOT / "_config.yml").read_text(encoding="utf-8")
        for line in config.splitlines():
            if line.startswith("version:"):
                self.assertEqual(line.split(":", 1)[1].strip().strip("\"'"),
                                 __version__)
                return
        self.skipTest("_config.yml 未声明 version")


class DocsCountTest(unittest.TestCase):
    """文档里的"分类 → 功能数"必须与 ``FEATURES`` 一致。

    这类数字最容易漂：加一个功能只改 `FEATURES`，`manual/features.md` 的
    「## 协议流量（17）」和首页卡片的「17 项」就会一起说谎。README 与
    `docs/FEATURES.md` 的总数由 `test_site`/`test_registry` 覆盖，这里补
    分类级别的两处。
    """

    def test_manual_features_headings_match_registry(self):
        import re

        from fnet.features.registry import CATEGORIES, FEATURES

        counts: dict[str, int] = {}
        for feature in FEATURES:
            counts[feature.category] = counts.get(feature.category, 0) + 1
        names = {item["name"]: item["key"] for item in CATEGORIES}
        text = (ROOT / "manual" / "features.md").read_text(encoding="utf-8")
        headings = re.findall(r"^## (.+?)（(\d+)）$", text, re.MULTILINE)
        self.assertTrue(headings, "manual/features.md 缺少分类标题")
        checked = 0
        for name, declared in headings:
            key = names.get(name)
            if key is None:
                continue  # 例如「高级功能（命令行调用）」等非分类标题
            self.assertEqual(int(declared), counts[key],
                             f"「{name}」的标题数字与 FEATURES 不一致")
            checked += 1
        self.assertEqual(checked, len(CATEGORIES),
                         "每个分类都应有「## 名称（N）」标题")


class StdlibOnlyTest(unittest.TestCase):
    """核心包不得在模块顶层导入第三方库。"""

    def test_no_top_level_third_party_imports(self):
        allowed = _stdlib_names()
        offenders: list[str] = []
        for path in sorted(PACKAGE.rglob("*.py")):
            for lineno, name in _top_level_imports(path):
                if name in allowed or name in OPTIONAL_DEPENDENCIES:
                    continue
                offenders.append(f"{path.relative_to(ROOT)}:{lineno} -> {name}")
        self.assertEqual(offenders, [], "顶层第三方导入: " + "; ".join(offenders))

    def test_optional_dependencies_are_lazy(self):
        """可选依赖只能在函数体内导入（顶层出现即视为硬依赖）。"""
        offenders: list[str] = []
        for path in sorted(PACKAGE.rglob("*.py")):
            for lineno, name in _top_level_imports(path):
                if name in OPTIONAL_DEPENDENCIES:
                    offenders.append(f"{path.relative_to(ROOT)}:{lineno} -> {name}")
        self.assertEqual(offenders, [],
                         "可选依赖被顶层导入: " + "; ".join(offenders))


class ImportSmokeTest(unittest.TestCase):
    """每个子模块都必须能导入（抓循环导入与改名遗漏）。"""

    def test_all_modules_import(self):
        failures: list[str] = []
        for info in pkgutil.walk_packages(fnet_path := [str(PACKAGE)], "fnet."):
            try:
                importlib.import_module(info.name)
            except Exception as exc:  # noqa: BLE001 - 报告全部失败项
                failures.append(f"{info.name}: {type(exc).__name__}: {exc}")
        self.assertEqual(failures, [], "导入失败: " + "; ".join(failures))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
