"""Handler-level tests for features without a dedicated test file yet.

Covers: ``rdp`` / ``sql`` / ``winrm`` / ``cs`` / ``usb`` / ``misc`` / ``ics``
/ ``text_scan`` / ``ntlm`` / ``arp`` / ``flows.icmp``.

The handlers are invoked through :class:`FeatureContext` with a fake tshark
(canned rows keyed by display filter), following the pattern of
``tests/test_protocol_streams.py``.  No real capture is parsed, so these
tests run without ``tshark``.

``fnet/features/ssh.py`` and ``fnet/features/tls.py`` are intentionally not
covered here (they already have ``tests/test_ssh_feature.py`` and
``tests/test_tls.py``).
"""
from __future__ import annotations

import base64
import os
import random
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fnet.config import Config
from fnet.features import arp, cs, ics, misc, ntlm, rdp, sql, text_scan, usb, winrm
from fnet.features.registry import FeatureContext
from fnet.logger import Logger
from fnet.utils import codec, crypto

# A throwaway 1024-bit RSA private key used only by the CS tests.
TEST_RSA_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQCj6ZJZmb22vCs2uTUR3nzhz7W6Wsq42UgEfZAVPl6zS2M+M74m
24bQIBNB/EUhRX0od/KvOgxoYuGP5BJNLn2nILzM/3+gmxbJQk/5Nt8BZuR7yPm1
UnKUpxmXvLe3FA/4uoxLVBjaUj0XAEaq4YKyR8xImp3Alja9oOOGQYKJfQIDAQAB
AoGAAs+qtuawHkYz54hdpKTQN388eqm7+FehqJIOuo6LST/tv89bX4c8VK14JxWQ
ifWLI/qKqv6v38pyW+lpdvFpLkGTiYAnPlFzNtx7qFJLWUCMpQYIE4U0yFu93bdE
2EWzAcl3jE3cqHpsh10lthVFW/zd3wXR0aS9JwOgVJsiR3ECQQDZU8JUIG4WSphC
8KtrIbOhELuf6IO7BP/B/qeeSfpWYApWxzCllPIP1voueQ3UR57WMzkmlFRrz3GU
5ypEL9XvAkEAwRSGo+oFuGCeY+xUo7qsixbPCddx+5KT3U9yI0/HGAsmxAkHOphT
+GA9PCYoq+CY28PncDNzyElKDCKR3MejUwJARnr5fNr/mM8cTilLDnVhkgyhLJz1
i8N1Rm7V4WnQfA6ti7MRvcFuN2DaxhOQPpXzlzgJgs98CXK/PTEy7eYtlQJATjd3
d62VFaUmZQpXG2DDBzF9O9poVWaCuhO2BDIMUGQsFxwlLoqI8cRi6hv3O/GnWtfY
yO4/CDMQaSwT9OF2+wJBALB9bdj30FiXy3a3IA7V/NTV0mrxtnlJE+9JDUFnTfU4
+dTIawFjC4wV7oEwCcCtUEhD76DIQFDJXfgnpWNmng0=
-----END RSA PRIVATE KEY-----
"""


class FakeTshark:
    """Return canned rows based on the display filter the handler uses."""

    def __init__(self, routes: dict[str, list] | None = None,
                 rows: list | None = None):
        self.routes = routes or {}
        self.rows = rows or []
        self.path = ""
        self.calls: list[tuple[str, list]] = []

    def fields(self, pcap, fields, display_filter="", extra=None, cancel=None):
        self.calls.append((display_filter, list(fields)))
        for key, value in self.routes.items():
            if key in display_filter:
                return value
        return self.rows


def make_ctx(tmp: Path, fake=None, params: dict | None = None) -> FeatureContext:
    return FeatureContext(
        config=Config(tmp / "config.ini"),
        logger=Logger(tmp / "fnet.log"),
        tshark=fake,
        pcap=str(tmp / "x.pcap"),
        params=params or {},
        output_dir=tmp / "out",
    )


class CtxTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-handler-"))

    def lines(self, ctx: FeatureContext) -> str:
        return "\n".join(r.line for r in ctx.logger.records_since(0, limit=100000))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# NTLMSSP message builders (shared by the ntlm and winrm tests)
# ---------------------------------------------------------------------------
NTLM_SIG = b"NTLMSSP\x00"


def ntlm_type2(challenge: bytes, flags: int = 0x8201) -> bytes:
    return (NTLM_SIG + struct.pack("<I", 2) + b"\x00" * 8
            + struct.pack("<I", flags) + challenge + b"\x00" * 8)


def ntlm_type3(*, lm=b"", nt=b"", domain="", user="", workstation="",
               session_key=b"", flags: int = 0x8201) -> bytes:
    parts = [lm, nt, domain.encode("utf-16le"), user.encode("utf-16le"),
             workstation.encode("utf-16le"), session_key]
    header = NTLM_SIG + struct.pack("<I", 3)
    offset = 64
    for part in parts:
        header += struct.pack("<HHI", len(part), len(part), offset)
        offset += len(part)
    header += struct.pack("<I", flags)
    return header + b"".join(parts)


def b64_field(message: bytes) -> str:
    return "NTLM " + base64.b64encode(message).decode()


class NtlmTest(CtxTestCase):
    def test_parse_type2(self):
        challenge = bytes(range(8))
        msg = ntlm_type2(challenge, flags=0x8205)
        parsed = ntlm.parse_type2(msg)
        self.assertEqual(parsed["challenge"], challenge)
        self.assertEqual(parsed["flags"], 0x8205)

    def test_parse_type3_fields(self):
        msg = ntlm_type3(lm=b"\x01" * 24, nt=b"\x02" * 16 + b"\xaa" * 24,
                         domain="CORP", user="vuser", workstation="PC01",
                         session_key=b"\x03" * 16, flags=0x8215)
        parsed = ntlm.parse_type3(msg)
        self.assertEqual(parsed["domain"], "CORP")
        self.assertEqual(parsed["user"], "vuser")
        self.assertEqual(parsed["workstation"], "PC01")
        self.assertEqual(parsed["nt"], b"\x02" * 16 + b"\xaa" * 24)
        self.assertEqual(parsed["lm"], b"\x01" * 24)
        self.assertEqual(parsed["session_key"], b"\x03" * 16)
        self.assertEqual(parsed["flags"], 0x8215)

    def test_parse_type3_too_short(self):
        self.assertEqual(ntlm.parse_type3(b"NTLMSSP\x00short"), {})

    def test_extract_messages_from_base64_with_trailing_http(self):
        msg = ntlm_type3(domain="CORP", user="vuser")
        raw = "WWW-Authenticate: " + b64_field(msg) + " HTTP/1.1 200 OK"
        messages = ntlm._extract_messages(raw)
        self.assertEqual(len(messages), 1)
        self.assertEqual(int.from_bytes(messages[0][8:12], "little"), 3)
        self.assertTrue(messages[0].startswith(NTLM_SIG))
        # Trailing protocol bytes must be trimmed for Type 3 messages.
        self.assertNotIn(b"HTTP/1.1", messages[0])

    def test_extract_messages_empty(self):
        self.assertEqual(ntlm._extract_messages(""), [])
        self.assertEqual(ntlm._extract_messages("Basic dXNlcjpwYXNz"), [])

    def test_extract_handler_emits_hashcat_line(self):
        challenge = bytes.fromhex("1122334455667788")
        proof = bytes(range(16))
        blob = b"\xcc" * 24
        fake = FakeTshark(routes={"ntlmssp": [
            ["1", "0"] + [""] * 11 + [b64_field(ntlm_type2(challenge)), ""],
            ["2", "0"] + [""] * 11
            + [b64_field(ntlm_type3(nt=proof + blob, domain="CORP",
                                    user="vuser")), ""],
        ]})
        ctx = make_ctx(self.tmp, fake)
        ntlm.extract(ctx)
        text = self.lines(ctx)
        expected = (f"vuser::CORP:{challenge.hex()}:{proof.hex()}:{blob.hex()}")
        self.assertIn("NTLM CHALLENGE: 1122334455667788", text)
        self.assertIn("NetNTLMv2 (hashcat -m 5600):", text)
        self.assertIn(expected, text)
        self.assertIn("共识别 1 个账号，1 条哈希", text)
        saved = (self.tmp / "out" / "ntlm_hashes.txt").read_text("utf-8")
        self.assertIn(expected, saved)

    def test_extract_accepts_hex_negotiateflags(self):
        # tshark renders ntlmssp.negotiateflags as 0x...; the structured
        # fallback path used to int() it as base 10 and crash the feature.
        proof = "00112233445566778899aabbccddeeff"
        row = ["1", "0", "", "", "vuser", "CORP", "PC01",
               "1122334455667788", proof, "", proof + "cc" * 24, "",
               "0x62088235", "", ""]
        fake = FakeTshark(routes={"ntlmssp": [row]})
        ctx = make_ctx(self.tmp, fake)
        ntlm.extract(ctx)
        text = self.lines(ctx)
        self.assertIn("vuser::CORP:", text)
        self.assertIn("协商标志: 0x62088235", text)

    def test_extract_smb_structured_challenge(self):
        # SMB2/LDAP/RDP: modern tshark has no ``ntlmssp.ntlmauthenticate``
        # column, so the server challenge arrives on its own frame and the
        # response fields on the AUTHENTICATE frame.
        challenge = "4078a5505a450ffd"
        proof = "7830894e632367cc9b516b255f12f8f0"
        blob = "01" * 24
        rows = [
            ["10", "0", "", "", "", "", "", challenge, "", "", "", "",
             "0x62088235", "", ""],
            ["12", "0", "", "", "winuser", "LAB", "PC-WIN11", "",
             proof, "", proof + blob, "", "0x62088235", "", ""],
        ]
        fake = FakeTshark(routes={"ntlmssp": rows})
        ctx = make_ctx(self.tmp, fake)
        ntlm.extract(ctx)
        text = self.lines(ctx)
        self.assertIn(f"NTLM CHALLENGE: {challenge}", text)
        self.assertIn(f"winuser::LAB:{challenge}:{proof}:{blob}", text)
        self.assertIn("NetNTLMv2 (hashcat -m 5600):", text)
        saved = (self.tmp / "out" / "ntlm_hashes.txt").read_text("utf-8")
        self.assertIn(f"winuser::LAB:{challenge}:{proof}:{blob}", saved)

    def test_extract_without_tshark_reports_error(self):
        ctx = make_ctx(self.tmp, None)
        ntlm.extract(ctx)
        text = self.lines(ctx)
        self.assertIn("该功能需要 tshark", text)
        self.assertIn("没有发现 NTLMSSP 认证流量", text)


class ArpTest(CtxTestCase):
    ROWS = [
        ["1", "1", "aa:aa:aa:aa:aa:01", "10.0.0.1", "ff:ff:ff:ff:ff:ff",
         "10.0.0.1"],
        ["2", "1", "aa:aa:aa:aa:aa:01", "10.0.0.1", "00:11:22:33:44:55",
         "10.0.0.2"],
        ["3", "2", "aa:aa:aa:aa:aa:02", "10.0.0.1", "00:11:22:33:44:55",
         "10.0.0.2"],
    ]

    def test_spoofing_gratuitous_and_opcode_stats(self):
        ctx = make_ctx(self.tmp, FakeTshark(routes={"arp": self.ROWS}))
        arp.analyze(ctx)
        text = self.lines(ctx)
        self.assertIn("===== ARP 报文 (3 条) =====", text)
        self.assertIn("操作码统计: 1=2, 2=1", text)
        self.assertIn("疑似 ARP 欺骗", text)
        self.assertIn("10.0.0.1: aa:aa:aa:aa:aa:01, aa:aa:aa:aa:aa:02", text)
        self.assertIn("===== 免费 ARP 1 条 =====", text)

    def test_no_conflict(self):
        rows = [["1", "1", "aa:aa:aa:aa:aa:01", "10.0.0.1",
                 "ff:ff:ff:ff:ff:ff", "10.0.0.2"]]
        ctx = make_ctx(self.tmp, FakeTshark(routes={"arp": rows}))
        arp.analyze(ctx)
        self.assertIn("未发现明显的 ARP 冲突", self.lines(ctx))

    def test_no_arp_traffic(self):
        ctx = make_ctx(self.tmp, FakeTshark())
        arp.analyze(ctx)
        self.assertIn("没有发现 ARP 流量", self.lines(ctx))

    def test_without_tshark(self):
        ctx = make_ctx(self.tmp, None)
        arp.analyze(ctx)
        self.assertIn("该功能需要 tshark", self.lines(ctx))


class IcsTest(CtxTestCase):
    def test_modbus_write_and_exception(self):
        rows = [
            ["1", "10.0.0.1", "10.0.0.2", "6", "100", "1", ""],
            ["2", "10.0.0.2", "10.0.0.1", "131", "0", "1", "1"],
        ]
        ctx = make_ctx(self.tmp, FakeTshark(routes={"modbus": rows}))
        ics.modbus(ctx)
        text = self.lines(ctx)
        self.assertIn("===== Modbus (2 条) =====", text)
        self.assertIn("功能码统计: 6=1, 131=1", text)
        self.assertIn("包含写操作: 功能码 6 (写单寄存器)", text)
        self.assertIn("发现 1 个 Modbus 异常响应", text)

    def test_mqtt_topics_and_messages(self):
        rows = [
            ["1", "10.0.0.1", "10.0.0.2", "3", "sensors/temp", "666c6167", ""],
            ["2", "10.0.0.2", "10.0.0.1", "3", "sensors/temp", "hello", ""],
            ["3", "10.0.0.1", "10.0.0.2", "8", "", "", ""],
        ]
        ctx = make_ctx(self.tmp, FakeTshark(routes={"mqtt": rows}))
        ics.mqtt(ctx)
        text = self.lines(ctx)
        self.assertIn("sensors/temp (2)", text)
        self.assertIn("[sensors/temp] 666c6167", text)

    def test_without_tshark(self):
        ctx = make_ctx(self.tmp, None)
        ics.modbus(ctx)
        self.assertIn("该功能需要 tshark", self.lines(ctx))


class UsbTest(CtxTestCase):
    @staticmethod
    def report(*keys, modifier=0):
        return [modifier] + [0] + list(keys) + [0] * (8 - 2 - len(keys))

    def test_keyboard_reconstruction(self):
        reports = [
            self.report(0x09), self.report(),      # f
            self.report(0x0F), self.report(),      # l
            self.report(0x04), self.report(),      # a
            self.report(0x0A), self.report(),      # g
            self.report(0x1E, modifier=0x02),      # shift+1 -> !
            self.report(),
            self.report(0x99),                     # unknown keycode
        ]
        rows = [[str(i + 1), bytes(r).hex(), ""]
                for i, r in enumerate(reports)]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.keyboard(ctx)
        text = self.lines(ctx)
        self.assertIn("USB 键盘报告 11 条", text)
        self.assertIn("===== 键盘还原结果 =====", text)
        self.assertIn("flag!", text)
        self.assertIn("未知键码 0x99", text)
        saved = (self.tmp / "out" / "usb_keyboard.txt").read_text("utf-8")
        self.assertEqual(saved, "flag!")

    def test_mouse_trajectory_and_buttons(self):
        rows = [
            ["1", bytes([0, 10, 20, 0]).hex(), ""],
            ["2", bytes([1, 251, 253, 0]).hex()],   # dx=-5 dy=-3, left btn
            ["3", bytes([0, 0, 5, 0]).hex()],
        ]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.mouse(ctx)
        text = self.lines(ctx)
        self.assertIn("USB 鼠标报告 3 条", text)
        self.assertIn("轨迹点 3 个，左键 1 次", text)
        self.assertIn("坐标范围 x=5..10 y=17..22", text)
        csv = (self.tmp / "out" / "usb_mouse.csv").read_text("utf-8")
        self.assertIn("x,y,buttons", csv)
        self.assertIn("10,20,0", csv)
        self.assertIn("5,22,0", csv)

    def test_without_tshark(self):
        ctx = make_ctx(self.tmp, None)
        usb.keyboard(ctx)
        usb.mouse(ctx)
        text = self.lines(ctx)
        self.assertEqual(text.count("未找到 USB HID 数据"), 2)


class MiscTest(CtxTestCase):
    def test_ev3_strings(self):
        rows = [["1", b"flag{ev3_str}".hex(), "", "", ""]]
        ctx = make_ctx(self.tmp, FakeTshark(routes={"bthci_acl": rows}))
        misc.ev3(ctx)
        text = self.lines(ctx)
        self.assertIn("===== EV3 / 蓝牙数据 (1 条) =====", text)
        self.assertIn("flag{ev3_str}", text)
        saved = (self.tmp / "out" / "ev3_strings.txt").read_text("utf-8")
        self.assertIn("flag{ev3_str}", saved)

    def test_ev3_without_strings(self):
        rows = [["1", b"\x01\x02\x03\x04".hex(), "", "", ""]]
        ctx = make_ctx(self.tmp, FakeTshark(routes={"bthci_acl": rows}))
        misc.ev3(ctx)
        self.assertIn("未发现可打印字符串", self.lines(ctx))

    def test_scsi_data_extraction(self):
        rows = [["1", "0", b"\x2a\x00\x00\x00".hex(), "123", "4", "0",
                 b"scsi_flag_data".hex()]]
        ctx = make_ctx(self.tmp, FakeTshark(routes={"scsi": rows}))
        misc.scsi(ctx)
        text = self.lines(ctx)
        self.assertIn("===== SCSI 命令 (1 条) =====", text)
        self.assertIn("提取 SCSI 数据 14 字节", text)
        saved = (self.tmp / "out" / "scsi_1.bin").read_bytes()
        self.assertEqual(saved, b"scsi_flag_data")

    def test_scsi_without_traffic(self):
        ctx = make_ctx(self.tmp, FakeTshark())
        misc.scsi(ctx)
        self.assertIn("没有发现 SCSI 流量", self.lines(ctx))

    def test_ipid_covert_channel_and_constant_id(self):
        rows = (
            [["1", "10.0.0.1", "10.0.0.2", "102", "20", "6"],
             ["2", "10.0.0.1", "10.0.0.2", "108", "20", "6"],
             ["3", "10.0.0.1", "10.0.0.2", "97", "20", "6"],
             ["4", "10.0.0.1", "10.0.0.2", "103", "20", "6"]]
            + [["5", "10.0.0.3", "10.0.0.4", "1234", "20", "6"],
               ["6", "10.0.0.3", "10.0.0.4", "1234", "20", "6"]]
        )
        ctx = make_ctx(self.tmp, FakeTshark(routes={"ip": rows}))
        misc.ipid(ctx)
        text = self.lines(ctx)
        self.assertIn("共 2 个 IP 流", text)
        self.assertIn("IP ID 恒定：可能存在 IP ID 隐蔽信道或空闲扫描", text)
        self.assertIn("低字节呈现可打印特征，提取为文本:", text)
        saved = (self.tmp / "out" / "ipid_10.0.0.1_10.0.0.2.txt")
        self.assertEqual(saved.read_text("utf-8"), "flag")


class TextScanTest(CtxTestCase):
    def test_compile_word_boundary_for_short_literals(self):
        rx = text_scan._compile("flag")
        self.assertIsNotNone(rx.search("flag{abc}"))
        self.assertIsNone(rx.search("flagged"))
        self.assertIsNone(rx.search("content_flag_x"))

    def test_compile_regex_passthrough_and_fallback(self):
        self.assertIsNotNone(text_scan._compile(r"fl[a-z]g").search("flag"))
        escaped = text_scan._compile("bad regex [")
        self.assertIsNotNone(escaped.search("a bad regex [ b"))

    def test_extra_keywords(self):
        self.assertEqual(text_scan._extra_keywords({"keywords": "a;b\nc"}),
                         ["a", "b", "c"])
        self.assertEqual(text_scan._extra_keywords({"regex": ["x", " ", ""]}),
                         ["x"])

    def test_decoded_views(self):
        views = dict(text_scan._decoded_views(b"ZmxhZ3tiNjR9"))
        self.assertIn(views["base64"], ("flag{b64}", "flag{b64}\n"))
        views = dict(text_scan._decoded_views(b"flag%7Burl%7D"))
        self.assertEqual(views["url"], "flag{url}")

    def test_keyword_scan_finds_flag(self):
        payload = b"GET /x HTTP/1.1\r\n x flag{kw_scan} y"
        rows = [["1", "TCP", "Info", payload.hex()]]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows),
                       params={"keywords": "flag"})
        text_scan.keyword_scan(ctx)
        text = self.lines(ctx)
        self.assertIn("关键字检测：", text)
        self.assertIn("发现 flag: flag{kw_scan}", text)
        self.assertIn("关键字检测完成", text)

    def test_keyword_scan_max_hits_stops(self):
        payload = b"a flag{one} b flag{two}"
        rows = [["1", "TCP", "Info", payload.hex()]]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows),
                       params={"keywords": "flag", "max_hits": 1})
        text_scan.keyword_scan(ctx)
        self.assertIn("命中数量达到上限，停止扫描", self.lines(ctx))


class SqlTest(CtxTestCase):
    @staticmethod
    def req(frame, uri, response_in):
        return [str(frame), "0", "GET", uri, uri, str(response_in), ""]

    @staticmethod
    def resp(frame, body):
        return [str(frame), "0", "200", body.hex(), "0.01"]

    def test_detect_success_strategies(self):
        contains = [
            {"response": self.resp_dict(1, b"result: TRUE")},
            {"response": self.resp_dict(2, b"result: FALSE")},
        ]
        flags, strategy = sql._detect_success(contains, "TRUE", "contains", 1.0)
        self.assertEqual(flags, [True, False])
        self.assertIn("响应体包含", strategy)
        flags, strategy = sql._detect_success(contains, "TRUE", "not_contains", 1.0)
        self.assertEqual(flags, [False, True])
        self.assertIn("不包含", strategy)

    @staticmethod
    def resp_dict(frame, body, delta="0.01"):
        return {"frame.number": str(frame), "http.response.code": "200",
                "http.file_data": body.hex(),
                "frame.time_delta_displayed": delta}

    def test_detect_success_time_based(self):
        pairs = [{"response": self.resp_dict(1, b"ok", "0.2")},
                 {"response": self.resp_dict(2, b"ok", "5.5")}]
        flags, strategy = sql._detect_success(pairs, "", "contains", 1.0)
        self.assertEqual(flags, [False, True])
        self.assertIn("时间盲注", strategy)

    def test_detect_success_two_templates(self):
        pairs = [{"response": self.resp_dict(i, b"no result")}
                 for i in (1, 2, 3)]
        pairs.append({"response": self.resp_dict(4, b"Welcome admin")})
        flags, strategy = sql._detect_success(pairs, "", "contains", 1.0)
        self.assertEqual(flags, [False, False, False, True])
        self.assertIn("少数派视为真", strategy)

    def test_blind_reconstruction(self):
        rows_req = [
            self.req(1, "http://h/?p1c102", 2),
            self.req(2, "http://h/?p2c108", 3),
            self.req(3, "http://h/?p3c97", 4),
            self.req(4, "http://h/?p4c103", 5),
            self.req(5, "http://h/?p5c120", 6),
        ]
        rows_resp = [
            self.resp(2, b"TRUE"), self.resp(3, b"TRUE"),
            self.resp(4, b"TRUE"), self.resp(5, b"TRUE"),
            self.resp(6, b"FALSE"),
        ]
        fake = FakeTshark(routes={"http.response": rows_resp,
                                  "http.request": rows_req})
        ctx = make_ctx(self.tmp, fake,
                       params={"sql_regex": r"p(\d+)c(\d+)",
                               "sql_success": "TRUE"})
        sql.blind(ctx)
        text = self.lines(ctx)
        self.assertIn("请求 5 条，成功 4 条", text)
        self.assertIn("===== 盲注还原结果 =====", text)
        self.assertIn("还原字符串: flag", text)
        saved = (self.tmp / "out" / "sql_blind_blind.txt").read_text("utf-8")
        self.assertEqual(saved, "flag")

    def test_binary_reconstruction(self):
        probes = [("1", ">96", True), ("1", ">112", False),
                  ("1", ">104", False), ("1", ">100", True),
                  ("1", ">102", False), ("1", ">101", True)]
        rows_req = [self.req(i + 1, f"http://h/?i{index}{op}", i + 2)
                    for i, (index, op, _) in enumerate(probes)]
        rows_resp = [self.resp(i + 2, b"TRUE" if success else b"FALSE")
                     for i, (_, _, success) in enumerate(probes)]
        fake = FakeTshark(routes={"http.response": rows_resp,
                                  "http.request": rows_req})
        ctx = make_ctx(self.tmp, fake,
                       params={"sql_regex": r"i(\d+)>(\d+)",
                               "sql_success": "TRUE"})
        sql.binary(ctx)
        text = self.lines(ctx)
        self.assertIn("===== 二分盲注推断 =====", text)
        self.assertIn("位置 1: 区间 [102,102] -> 'f'", text)
        self.assertIn("推断字符串: f", text)

    def test_log_analysis_from_text(self):
        log = ("1 102 true\n2 108 true\n3 97 true\n4 103 true\n"
               "5 120 false\n")
        ctx = make_ctx(self.tmp, None, params={"sql_log_text": log})
        sql.log_analysis(ctx)
        text = self.lines(ctx)
        self.assertIn("日志还原字符串: flag", text)
        saved = (self.tmp / "out" / "sql_log_result.txt").read_text("utf-8")
        self.assertEqual(saved, "flag")

    def test_log_analysis_from_file(self):
        path = self.tmp / "blind.log"
        path.write_text("1 102 success\n2 108 success\n3 97 success\n"
                        "4 103 success\n", encoding="utf-8")
        ctx = make_ctx(self.tmp, None, params={"sql_log": str(path)})
        sql.log_analysis(ctx)
        self.assertIn("日志还原字符串: flag", self.lines(ctx))

    def test_log_analysis_invalid_regex(self):
        ctx = make_ctx(self.tmp, None,
                       params={"sql_log_text": "1 102 true",
                               "sql_regex": "("})
        sql.log_analysis(ctx)
        self.assertIn("正则无效", self.lines(ctx))

    def test_no_requests(self):
        ctx = make_ctx(self.tmp, FakeTshark())
        sql.blind(ctx)
        self.assertIn("没有发现 HTTP 请求", self.lines(ctx))


class WinrmTest(CtxTestCase):
    PASSWORD = "S3cret"
    USER = "admin"
    DOMAIN = "CORP"
    NT_RESPONSE = bytes(range(16)) + b"\x11" * 16

    def _session_base(self) -> bytes:
        import hashlib
        import hmac
        nthash = crypto.nt_hash(self.PASSWORD)
        identity = (self.USER.upper() + self.DOMAIN).encode("utf-16le")
        response_key = hmac.new(nthash, identity, "md5").digest()
        return hmac.new(self.NT_RESPONSE[:16], response_key, "md5").digest()

    def test_derive_session_key_from_password(self):
        session_base, source = winrm._derive_session_key(
            self.PASSWORD, "", self.USER, self.DOMAIN, b"",
            self.NT_RESPONSE)
        self.assertEqual(source, "password")
        self.assertEqual(session_base, self._session_base())

    def test_derive_session_key_from_hash(self):
        session_base, source = winrm._derive_session_key(
            "", crypto.nt_hash(self.PASSWORD).hex(), self.USER, self.DOMAIN,
            b"", self.NT_RESPONSE)
        self.assertEqual(source, "NTLM HASH")
        self.assertEqual(session_base, self._session_base())

    def test_derive_session_key_rejects_bad_input(self):
        self.assertEqual(winrm._derive_session_key(
            "", "abcd", "u", "d", b"", self.NT_RESPONSE)[1],
            "NTLM HASH 必须是 32 位十六进制（16 字节）")
        self.assertEqual(winrm._derive_session_key(
            "", "zzzz", "u", "d", b"", self.NT_RESPONSE)[1],
            "NTLM HASH 必须是 32 位十六进制（16 字节）")
        self.assertEqual(winrm._derive_session_key(
            "", "", "u", "d", b"", self.NT_RESPONSE)[1],
            "需要 NTLM HASH 或 password")
        self.assertEqual(winrm._derive_session_key(
            "pw", "", "u", "d", b"", b"\x01" * 8)[1],
            "NTResponse 太短")
        # 奇数长度的十六进制串：清洗后 fromhex 抛 ValueError，
        # “格式无效”分支因此可达（回归保护）。
        self.assertEqual(winrm._derive_session_key(
            "", "abc", "u", "d", b"", self.NT_RESPONSE)[1],
            "NTLM HASH 格式无效")

    def test_try_unseal_recovers_rc4_xml(self):
        key = b"K" * 16
        plain = b"<?xml version=\"1.0\"?><s:Envelope><a>ok</a></s:Envelope>"
        cipher = crypto.rc4(key, plain)
        self.assertIsNone(winrm._try_unseal(cipher, [("wrong", b"W" * 16)]))
        variant, result = winrm._try_unseal(cipher, [("RC4(exported)", key)])
        self.assertIn("RC4(exported)", variant)
        self.assertEqual(result, plain)

    def test_decrypt_end_to_end(self):
        session_base = self._session_base()
        plain = (b"<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/"
                 b"soap-envelope\"><m>flag{winrm_ok}</m></s:Envelope>")
        cipher = crypto.rc4(session_base, plain)
        body = ("<EncryptedData><CipherValue>"
                + base64.b64encode(cipher).decode()
                + "</CipherValue></EncryptedData>")
        rows = [
            ["1", "0", "POST", "/wsman", b64_field(ntlm_type2(b"\x22" * 8)),
             "", "", ""],
            ["2", "0", "POST", "/wsman",
             b64_field(ntlm_type3(nt=self.NT_RESPONSE, domain=self.DOMAIN,
                                  user=self.USER, workstation="PC01")),
             "", "", ""],
            ["3", "0", "POST", "/wsman", "", "", "multipart/encrypted",
             body.encode().hex()],
        ]
        ctx = make_ctx(self.tmp, FakeTshark(routes={"http": rows}),
                       params={"winrm_ntlm": crypto.nt_hash(self.PASSWORD).hex()})
        winrm.decrypt(ctx)
        text = self.lines(ctx)
        self.assertIn(f"WinRM 账号: {self.DOMAIN}\\{self.USER} (帧 2)", text)
        self.assertIn("使用 NTLM HASH 派生 NTLM SessionBaseKey: "
                      + session_base.hex(), text)
        self.assertIn("WinRM 解密成功", text)
        self.assertIn("flag{winrm_ok}", text)
        saved = (self.tmp / "out" / "winrm_3.xml").read_bytes()
        self.assertIn(b"flag{winrm_ok}", saved)

    def test_decrypt_without_auth_info(self):
        ctx = make_ctx(self.tmp, FakeTshark(routes={"http": [["1", "0"] * 4]}))
        winrm.decrypt(ctx)
        text = self.lines(ctx)
        self.assertIn("未发现 WinRM NTLM 认证信息", text)


class CsTest(CtxTestCase):
    def test_candidate_blobs_base64_and_hex(self):
        blob = bytes(range(64))
        text = "url?s=" + base64.b64encode(blob).decode() + " hex="
        text += "deadbeef" * 16
        blobs = cs._candidate_blobs(text)
        self.assertIn(blob, blobs)
        self.assertIn(bytes.fromhex("deadbeef" * 16), blobs)

    def test_decode_metadata(self):
        aes_key = bytes(range(16))
        hmac_key = bytes(range(16, 32))
        plain = (b"\x00\x00\xbe\xef" + struct.pack("<I", 4242)
                 + struct.pack("<H", 8443) + bytes([0, 1]) + b"\x00" * 12
                 + aes_key + hmac_key + b"DESKTOP-R3F")
        info = cs._decode_metadata(plain)
        self.assertEqual(info["magic"], "0000beef")
        self.assertEqual(info["pid"], 4242)
        self.assertEqual(info["port"], 8443)
        self.assertEqual(info["aes_key"], aes_key)
        self.assertEqual(info["hmac_key"], hmac_key)
        self.assertIn("DESKTOP-R3F", info["strings"])

    def _metadata_plain(self) -> bytes:
        return (b"\x00\x00\xbe\xef" + struct.pack("<I", 4242)
                + struct.pack("<H", 8443) + bytes([0, 1]) + b"\x00" * 12
                + bytes(range(16)) + bytes(range(16, 32)) + b"DESKTOP-R3F")

    @staticmethod
    def _rsa_encrypt(key, message: bytes) -> bytes:
        size = (key.n.bit_length() + 7) // 8
        pad_len = size - len(message) - 3
        padding = bytes([0, 2]) + bytes((i % 254) + 1 for i in range(pad_len))
        padded = padding + b"\x00" + message
        value = int.from_bytes(padded, "big")
        return pow(value, key.e, key.n).to_bytes(size, "big")

    def test_metadata_from_blob_raw_and_length_prefixed(self):
        key = crypto.load_rsa_private_key(TEST_RSA_PEM.encode())
        self.assertIsNotNone(key)
        cipher = self._rsa_encrypt(key, self._metadata_plain())
        plain = cs._metadata_from_blob(cipher, key)
        self.assertIsNotNone(plain)
        self.assertTrue(plain.startswith(b"\x00\x00\xbe\xef"))
        prefixed = struct.pack("<I", len(cipher)) + cipher
        plain = cs._metadata_from_blob(prefixed, key)
        self.assertTrue(plain.startswith(b"\x00\x00\xbe\xef"))
        self.assertIsNone(cs._metadata_from_blob(cipher, None))

    def test_try_decrypt_output_cbc(self):
        key = bytes(range(16))
        iv = b"IV" * 8
        message = b"<output>flag{cs_out}</output>"
        encrypted = crypto.aes_cbc_encrypt(message, key, iv)
        blob = iv + encrypted
        result = cs._try_decrypt_output(blob, key)
        self.assertIsNotNone(result)
        self.assertIn("CBC(IV=前16字节)", result[0])
        self.assertEqual(result[1], message)

    def test_try_decrypt_output_rejects_ciphertext_like_garbage(self):
        from fnet.utils.pcap import printable_ratio

        key = bytes(range(16))
        iv = b"I" * 16
        # 伪随机字节：含一个 '<' 但可读率低于 0.6，旧逻辑会误判为解密成功。
        garbage = bytes((i * 37 + 11) % 256 for i in range(64))
        self.assertLess(printable_ratio(garbage), 0.6)
        self.assertIn(b"<", garbage)
        blob = iv + crypto.aes_cbc_encrypt(garbage, key, iv)
        self.assertIsNone(cs._try_decrypt_output(blob, key))
        # 全非打印字节同理（长度达标但没有任何可读结构）。
        self.assertIsNone(cs._try_decrypt_output(b"\x01" * 40, key))

    def test_load_key_missing_and_valid(self):
        ctx = make_ctx(self.tmp, FakeTshark(),
                       params={"cobaltstrike_keys": str(self.tmp / "no.pem")})
        self.assertIsNone(cs._load_key(ctx))
        self.assertIn("CS 密钥文件不存在", self.lines(ctx))

        key_path = self.tmp / "beacon_keys"
        key_path.write_text(TEST_RSA_PEM, encoding="utf-8")
        ctx = make_ctx(self.tmp, FakeTshark(),
                       params={"cobaltstrike_keys": str(key_path)})
        key = cs._load_key(ctx)
        self.assertIsNotNone(key)
        self.assertIn("已加载 RSA 私钥 (1024 bit)", self.lines(ctx))

    def test_analyze_without_key_saves_candidates(self):
        blob = base64.b64encode(bytes(range(64))).decode()
        rows = [["1", "0", "GET", f"http://evil/?s={blob}", f"/?s={blob}",
                 "", "", ""]]
        ctx = make_ctx(self.tmp, FakeTshark(routes={"http.request": rows}))
        cs.analyze(ctx)
        text = self.lines(ctx)
        self.assertIn("未配置 .cobaltstrike.beacon_keys", text)
        self.assertTrue(list((self.tmp / "out").glob("cs_metadata_1_1.bin")))
        self.assertTrue((self.tmp / "out" / "cs_README.txt").is_file())


class RdpTest(CtxTestCase):
    def _key_file(self, content: str) -> Path:
        path = self.tmp / "key.txt"
        path.write_text(content, encoding="utf-8")
        return path

    def test_find_executable_hint_and_missing(self):
        hint = self.tmp / "bin"
        hint.write_text("", encoding="utf-8")
        self.assertEqual(rdp.find_executable("tshark", str(hint)), str(hint))
        self.assertIsNone(rdp.find_executable("fnet-no-such-tool-xyz"))

    def test_decryption_uses_keylog_format(self):
        key = self._key_file("CLIENT_RANDOM abc123 server")
        out = self.tmp / "out.pcap"
        with mock.patch("fnet.features.rdp.run", return_value=(0, "")) as m:
            result = rdp.run_tshark_decryption(
                "tshark-bin", self.tmp / "in.pcap", key, None, 3389,
                out, log=lambda text, level="info": None)
        self.assertFalse(result)  # mocked run leaves the output file empty
        cmd = m.call_args[0][0]
        self.assertIsInstance(cmd, list)
        self.assertEqual(cmd[0], "tshark-bin")
        self.assertIn("-r", cmd)
        self.assertIn("tcp.port==3389,tls", cmd)
        self.assertIn(f"tls.keylog_file:{key}", cmd)

    def test_decryption_uses_private_key_format(self):
        key = self._key_file("-----BEGIN PRIVATE KEY-----\nabc\n")
        out = self.tmp / "out.pcap"
        with mock.patch("fnet.features.rdp.run", return_value=(0, "")) as m:
            rdp.run_tshark_decryption(
                "tshark-bin", self.tmp / "in.pcap", key, "10.0.0.1", 3389,
                out, log=lambda text, level="info": None)
        cmd = m.call_args[0][0]
        self.assertIn(f"tls.keys_list:10.0.0.1,3389,tpkt,{key}", cmd)

    def test_decryption_failure_and_unreadable_key(self):
        key = self._key_file("CLIENT_RANDOM abc")
        logs: list[str] = []
        with mock.patch("fnet.features.rdp.run", return_value=(1, "boom")):
            result = rdp.run_tshark_decryption(
                "tshark-bin", self.tmp / "in.pcap", key, None, 3389,
                self.tmp / "out.pcap", log=lambda text, level="info":
                logs.append(text))
        self.assertFalse(result)
        self.assertIn("tshark 执行失败", "\n".join(logs))
        logs.clear()
        self.assertFalse(rdp.run_tshark_decryption(
            "tshark-bin", self.tmp / "in.pcap", self.tmp, None, 3389,
            self.tmp / "out.pcap", log=lambda text, level="info":
            logs.append(text)))
        self.assertIn("无法读取密钥文件", "\n".join(logs))

    def test_handler_requires_key(self):
        ctx = make_ctx(self.tmp, FakeTshark())
        rdp.handler(ctx)
        self.assertIn("请在设置中指定 RDP 私钥或 Key log 文件", self.lines(ctx))

    def test_handler_falls_back_to_resolved_tshark(self):
        capture = self.tmp / "in.pcap"
        capture.write_bytes(b"")
        key = self._key_file("CLIENT_RANDOM abc")
        fake = FakeTshark()
        fake.path = str(self.tmp / "resolved-tshark")
        ctx = make_ctx(self.tmp, fake, params={"rdp_private_key": str(key)})
        ctx.pcap = str(capture)
        with mock.patch("fnet.features.rdp.replay_rdp_session",
                        return_value=None) as m:
            rdp.handler(ctx)
        # 无任务参数、[config] tshark 留空时，回落到 JobManager 解析的路径。
        self.assertEqual(m.call_args.kwargs["tshark_path"],
                         str(self.tmp / "resolved-tshark"))

    def test_handler_reports_missing_key_file(self):
        dummy_tshark = self.tmp / "tshark-dummy"
        dummy_tshark.write_text("", encoding="utf-8")
        capture = self.tmp / "in.pcap"
        capture.write_bytes(b"")  # pcap must exist so the key check is reached
        ctx = make_ctx(self.tmp, FakeTshark(), params={
            "rdp_private_key": str(self.tmp / "no-key.pem"),
            "tshark_path": str(dummy_tshark),
        })
        ctx.pcap = str(capture)
        rdp.handler(ctx)
        self.assertIn("密钥文件不存在", self.lines(ctx))

    def test_replay_reports_missing_pcap(self):
        dummy_tshark = self.tmp / "tshark-dummy"
        dummy_tshark.write_text("", encoding="utf-8")
        key = self._key_file("CLIENT_RANDOM abc")
        logs: list[str] = []
        result = rdp.replay_rdp_session(
            str(self.tmp / "no.pcap"), str(key),
            tshark_path=str(dummy_tshark), output_root=self.tmp / "rdp",
            log=lambda text, level="info": logs.append(text))
        self.assertIsNone(result)
        self.assertIn("输入 PCAP 不存在", "\n".join(logs))


class FlowsIcmpTest(CtxTestCase):
    """flows.icmp 隧道重组：罐装 tshark 行、载荷分层分析与告警收敛。"""

    class FieldRoutedTshark:
        """按字段路由罐装行：icmp handler 用不同字段列表查询三次。"""

        def __init__(self, routes: dict[str, list]):
            self.routes = routes
            self.path = ""
            self.calls: list[tuple[str, list]] = []

        def fields(self, pcap, fields, display_filter="", extra=None,
                   cancel=None):
            self.calls.append((display_filter, list(fields)))
            for key, value in self.routes.items():
                if key in fields:
                    return value
            return []

    @staticmethod
    def _tunnel_rows(src: str, dst: str, blob: bytes, per: int = 90) -> list:
        parts = [blob[i:i + per] for i in range(0, len(blob), per)]
        return [[str(number), src, dst, "8", "0", part.hex(), f"17{number}.0"]
                for number, part in enumerate(parts, 1)]

    def _run_icmp(self, tunnel_rows: list):
        from fnet.features import flows

        fake = self.FieldRoutedTshark({
            "frame.time_epoch": tunnel_rows,
            "data.data": [[row[0], row[5], "8"] for row in tunnel_rows],
            "data.len": [[row[0], str(len(row[5]) // 2)]
                         for row in tunnel_rows],
        })
        ctx = make_ctx(self.tmp, fake)
        flows.icmp(ctx)
        return ctx

    def test_encrypted_echo_id_tunnel(self):
        """不可解密文：载荷分析 finding 给出命令示例，告警收敛为一条。"""
        rng = random.Random(42)
        cipher = bytes(rng.randrange(256) for _ in range(1024))
        blob = base64.b64encode(cipher)
        ctx = self._run_icmp(self._tunnel_rows(
            "192.168.3.73", "54.199.175.227", blob))
        log = self.lines(ctx)
        self.assertIn("ICMP 隧道分块重组", log)
        self.assertIn("疑似隐蔽外传", log)
        self.assertIn("54.199.175.227", log)
        self.assertIn("公网地址", log)
        kinds = {finding["kind"] for finding in ctx.findings}
        self.assertIn("protocol", kinds)
        sessions = [f for f in ctx.findings
                    if f["summary"] == "ICMP 隧道 192.168.3.73>54.199.175.227"]
        self.assertEqual(len(sessions), 1)
        session = sessions[0]
        self.assertEqual(session["level"], "warn")
        self.assertIn("包数", session["detail"])
        self.assertIn("加密 是", session["detail"])
        self.assertIn("帧范围", session["detail"])
        self.assertIn("首帧时间戳", session["detail"])
        self.assertIn("高熵密文", session["detail"])
        self.assertEqual(session["extra"]["encrypted"], "True")
        # 每个方向一条载荷分层分析 finding：失败路径带命令示例与参数指引
        bin_name = "icmp_tunnel_192.168.3.73_54.199.175.227.bin"
        analyses = [f for f in ctx.findings
                    if f["summary"] == f"ICMP 隧道载荷分析 {bin_name}"]
        self.assertEqual(len(analyses), 1)
        detail = analyses[0]["detail"]
        self.assertIn("自动解密失败", detail)
        self.assertIn("openssl enc -d", detail)
        self.assertIn("-nosalt", detail)
        self.assertIn("openssl_file", detail)
        self.assertIn("-a -A", detail)
        self.assertEqual(analyses[0]["extra"]["decrypted"], "False")
        # 加密外传告警收敛为一条，公网 IOC 信息并入 detail
        alerts = [f for f in ctx.findings
                  if f["summary"] == "ICMP 隧道载荷为加密数据（疑似隐蔽外传）"]
        self.assertEqual(len(alerts), 1)
        self.assertIn("54.199.175.227", alerts[0]["detail"])
        self.assertIn("公网地址", alerts[0]["detail"])
        self.assertIn("载荷分析", alerts[0]["detail"])
        # 独立的「外传目标 X」IOC finding 不再出现
        self.assertFalse(any("外传目标" in f["summary"] for f in ctx.findings))
        # 告警收敛：session + 载荷分析 + 汇总告警 = 3 条且互不重复
        self.assertEqual(len(ctx.findings), 3,
                         [f["summary"] for f in ctx.findings])
        # 解码落盘：密文完整保存为 icmp_tunnel_*.bin
        bins = list((self.tmp / "out").glob("icmp_tunnel_*.bin"))
        self.assertTrue(bins)
        self.assertEqual(bins[0].stat().st_size, 1024)

    def test_encrypted_tunnel_auto_decrypt_success(self):
        """常见配方命中：解密成功 finding + 明文落盘 + flag 单独 emit。"""
        from fnet.utils.crypto import aes_cbc_encrypt
        from fnet.utils.openssl_enc import derive_key_iv

        plaintext = b"flag{icmp-auto-decrypt}\n" * 40
        key, iv = derive_key_iv("icmp", b"", key_len=16, iv_len=16, digest="md5")
        cipher = aes_cbc_encrypt(plaintext, key, iv)
        blob = base64.b64encode(cipher)
        ctx = self._run_icmp(self._tunnel_rows(
            "192.168.3.73", "54.199.175.227", blob))
        bin_name = "icmp_tunnel_192.168.3.73_54.199.175.227.bin"
        analyses = [f for f in ctx.findings
                    if f["summary"] == f"ICMP 隧道载荷分析 {bin_name}"]
        self.assertEqual(len(analyses), 1)
        finding = analyses[0]
        self.assertEqual(finding["level"], "good")
        self.assertIn("解密成功", finding["detail"])
        self.assertIn("aes-128-cbc", finding["detail"])
        self.assertIn("md5", finding["detail"])
        self.assertIn("flag{icmp-auto-decrypt}", finding["detail"])
        out_name = "icmp_tunnel_192.168.3.73_54.199.175.227_decoded.txt"
        self.assertIn(out_name, finding["detail"])
        self.assertEqual(finding["extra"]["decrypted"], "True")
        # 明文落盘为真交付物
        decoded = self.tmp / "out" / out_name
        self.assertEqual(decoded.read_bytes(), plaintext)
        # flag 以 kind=flag 单独 emit
        self.assertTrue(any(f["kind"] == "flag" and
                            f["summary"] == "flag{icmp-auto-decrypt}"
                            for f in ctx.findings))
        # 收敛后：session + 载荷分析 + 汇总告警 + flag = 4 条
        self.assertEqual(len(ctx.findings), 4,
                         [f["summary"] for f in ctx.findings])
        # 汇总告警注明已解密成功
        alerts = [f for f in ctx.findings
                  if f["summary"] == "ICMP 隧道载荷为加密数据（疑似隐蔽外传）"]
        self.assertEqual(len(alerts), 1)
        self.assertIn("已自动解密成功", alerts[0]["detail"])

    def test_plain_session_finding(self):
        parts = [b"flag{icmp_plain", b"_session}"]
        blob = b"".join(parts)
        tunnel_rows = [[str(number), "10.0.0.5", "10.0.0.6", "8",
                        str(number), part.hex(), f"17{number}.0"]
                       for number, part in enumerate(parts, 1)]
        ctx = self._run_icmp(tunnel_rows)
        session = [f for f in ctx.findings
                   if f["summary"] == "ICMP 隧道 10.0.0.5>10.0.0.6"]
        self.assertEqual(len(session), 1)
        self.assertEqual(session[0]["level"], "info")
        self.assertIn("加密 否", session[0]["detail"])
        self.assertIn("首帧时间戳", session[0]["detail"])
        self.assertIn("载荷未见加密特征", session[0]["detail"])
        self.assertTrue(any(f["kind"] == "flag" and
                            f["summary"] == "flag{icmp_plain_session}"
                            for f in ctx.findings))


    def test_length_channel_finds_embedded_flag(self):
        """长度隐写：每个请求包长度就是 ASCII 码（fetus_pcap 考点）。"""
        shadow = ("ubuntu:$6$LhHRomTE$M7C4n84UcFLAG{length_channel}::")
        encoded = base64.b64encode(shadow.encode()).decode()
        rows = [[str(number), "192.168.3.73", "54.199.175.227", "8", "0",
                 (b"A" * ord(char)).hex(), f"17{number}.0"]
                for number, char in enumerate(encoded, 1)]
        ctx = self._run_icmp(rows)
        log = self.lines(ctx)
        self.assertIn("ICMP 载荷长度隐写", log)
        finding = [f for f in ctx.findings
                   if f["summary"].startswith("ICMP 载荷长度隐写")]
        self.assertEqual(len(finding), 1)
        self.assertEqual(finding[0]["level"], "good")
        self.assertIn("ubuntu", finding[0]["detail"])
        self.assertIn("FLAG{length_channel}", finding[0]["detail"])
        self.assertEqual(finding[0]["extra"]["encoding"], "length-ascii")
        self.assertTrue(any(f["kind"] == "flag" and
                            f["summary"] == "FLAG{length_channel}"
                            for f in ctx.findings))
        # finding 的「帧」列要能直接跳到长度序列的第一帧。
        self.assertEqual(finding[0]["frame"], "1")
        outputs = list((self.tmp / "out").glob("*_length.txt"))
        self.assertTrue(outputs)
        self.assertIn("ubuntu", outputs[0].read_text("utf-8"))

    def test_length_channel_hint_marks_ciphertext_as_decoy(self):
        """同方向已由长度隐写解出 flag 时，载荷分析要提示密文是干扰项。"""
        import base64 as b64
        import random

        shadow = "ubuntu:$6$LhHRomTE$M7C4n84UcFLAG{decoy_hint}::"
        encoded = b64.b64encode(shadow.encode()).decode()
        rng = random.Random(7)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        # fetus 同款：载荷本身是可打印的 base64 文本（拼起来解码后是随机
        # 字节 → 判为密文），而每包长度恰好是消息字符的 ASCII 码。
        rows = []
        for number, char in enumerate(encoded, 1):
            body = "".join(rng.choice(alphabet) for _ in range(ord(char)))
            rows.append([str(number), "192.168.3.73", "54.199.175.227", "8",
                         str(number), body.encode().hex(), f"17{number}.0"])
        ctx = self._run_icmp(rows)
        analyses = [f for f in ctx.findings
                    if f["summary"].startswith("ICMP 隧道载荷分析")]
        self.assertTrue(analyses)
        self.assertIn("干扰项", analyses[0]["detail"])
        alert = [f for f in ctx.findings
                 if f["summary"].startswith("ICMP 隧道载荷为加密数据")]
        self.assertEqual(len(alert), 1)
        self.assertIn("长度隐写", alert[0]["detail"])


if __name__ == "__main__":
    unittest.main()
