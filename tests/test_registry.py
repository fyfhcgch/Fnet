"""Feature catalogue invariants."""
from __future__ import annotations

import unittest

from fnet.features.registry import (
    BY_CHECKBOX, BY_HANDLER, CATEGORIES, FEATURES, resolve,
)


class RegistryTest(unittest.TestCase):
    def test_feature_count_and_defaults(self):
        self.assertEqual(len(FEATURES), 56)
        self.assertEqual(sum(1 for f in FEATURES if f.default), 2)

    def test_checkbox_and_handler_unique(self):
        self.assertEqual(len({f.checkbox for f in FEATURES}), len(FEATURES))
        self.assertEqual(len({f.handler for f in FEATURES}), len(FEATURES))
        self.assertEqual(len(BY_CHECKBOX), len(FEATURES))
        self.assertEqual(len(BY_HANDLER), len(FEATURES))

    def test_categories_exist_and_are_used(self):
        keys = [c["key"] for c in CATEGORIES]
        self.assertEqual(len(keys), len(set(keys)))
        for feature in FEATURES:
            self.assertIn(feature.category, keys)
        used = {f.category for f in FEATURES}
        self.assertEqual(used, set(keys))

    def test_every_handler_resolves(self):
        for feature in FEATURES:
            with self.subTest(feature=feature.checkbox):
                self.assertTrue(callable(resolve(feature.handler)))

    def test_unknown_handler_raises(self):
        with self.assertRaises(AttributeError):
            resolve("no_such_module.func")
        with self.assertRaises(AttributeError):
            resolve("text_scan.no_such_function")

    def test_needs_only_names_real_external_tools(self):
        """``needs`` 只用于 ``--list-features`` 打印"需要: …"。

        历史上 ``cs.analyze`` 声明了 ``("cryptography",)``，但全仓库从未
        导入过该包（Cobalt Strike 的 RSA/AES 都是纯标准库实现），于是
        ``--list-features`` 对用户谎报依赖。这里的门禁要求每一项都必须是
        :class:`~fnet.tools.runner.ToolBox` 里真实存在的外部工具。
        """
        from fnet.tools.runner import ToolBox

        known = set(ToolBox.TOOL_NAMES)
        for feature in FEATURES:
            for need in feature.needs:
                with self.subTest(feature=feature.checkbox, need=need):
                    self.assertIn(need, known)

    def test_needs_reference_known_tools_or_modules(self):
        known_tools = {"tshark", "wireshark", "java", "aircrack", "hashcat",
                       "john", "foremost", "binwalk", "pcapfix",
                       "etl2pcapng", "pyrdp_player"}
        known_modules = {"cryptography", "scapy"}
        for feature in FEATURES:
            for need in feature.needs:
                self.assertIn(need, known_tools | known_modules,
                              f"{feature.checkbox} 需要未知依赖 {need}")


if __name__ == "__main__":
    unittest.main()
