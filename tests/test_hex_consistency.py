"""十六进制解析语义必须全仓库一致。

历史上 ``pcap.hex_to_bytes`` / ``wifi._hex_bytes`` 会把 ``"0x41"`` 解析成
``b"\\x04"``（剥离 ``x`` 后长度变奇数，再截断最后一个半字节），而
``codec.from_hex`` / ``tunnel._hex_bytes`` 返回 ``b"A"``。同一份 tshark 输出
在不同模块得到不同字节，是真实存在的隐蔽错误来源。
"""
from __future__ import annotations

import unittest

from fnet.utils import codec, pcap, tunnel, wifi

#: 各模块对外暴露的十六进制解析入口（新增实现时应加入此表）。
IMPLEMENTATIONS = {
    "pcap.hex_to_bytes": pcap.hex_to_bytes,
    "wifi._hex_bytes": wifi._hex_bytes,
    "tunnel._hex_bytes": tunnel._hex_bytes,
}

CASES = [
    ("41", b"A"),
    ("0x41", b"A"),
    ("0X41", b"A"),
    ("4:1", b"A"),
    ("41 ", b"A"),
    ("0x1301,0xc02f", b"\x13\x01\xc0/"),
    ("", b""),
    ("0x", b""),
    ("zz", b""),
    ("414", b""),  # 奇数长度：宁可失败也不静默丢半字节
]


class HexConsistencyTest(unittest.TestCase):
    def test_all_implementations_agree(self):
        for name, func in IMPLEMENTATIONS.items():
            for value, expected in CASES:
                with self.subTest(impl=name, value=value):
                    self.assertEqual(func(value), expected,
                                     f"{name}({value!r}) 与统一语义不符")

    def test_codec_from_hex_agrees_on_0x_prefix(self):
        self.assertEqual(codec.from_hex("0x41"), b"A")

    def test_odd_length_is_rejected_not_truncated(self):
        for name, func in IMPLEMENTATIONS.items():
            with self.subTest(impl=name):
                self.assertEqual(func("0x414"), b"")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
