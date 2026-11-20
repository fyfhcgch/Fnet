"""Modbus 寄存器隐蔽通道（ASCII 隐写）检测测试。

* 纯函数 :func:`fnet.features.ics.modbus_register_stego` 的单测
  （大端/小端段、低字节流、短段不触发、双字节序去重）；
* handler 层罐装行测试（不依赖 tshark，验证 finding 形状）；
* 用 ``tests/pcap_build.py``（纯 stdlib，struct 打包 Ethernet/IP/TCP/MBAP）
  构造最小 Modbus/TCP 抓包并跑完整 ``ics.modbus`` 任务的集成测试。
"""
from __future__ import annotations

import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

from fnet.app import build
from fnet.config import Config
from fnet.features import ics
from fnet.tools.runner import find_tool
from tests.support import patch_cache_dirs

sys.path.insert(0, str(Path(__file__).resolve().parent))
import pcap_build  # noqa: E402  (tests/pcap_build.py，纯 stdlib pcap 构造辅助)

TSHARK = find_tool("tshark", "")


def _regs_big(text: str) -> list[int]:
    """文本按大端 2 字节一组切成寄存器值（奇数长度末尾补 NUL）。"""
    if len(text) % 2:
        text += "\x00"
    return [int.from_bytes(text[i:i + 2].encode(), "big")
            for i in range(0, len(text), 2)]


def _regs_little(text: str) -> list[int]:
    """文本按小端 2 字节一组切成寄存器值。"""
    return [int.from_bytes(text[i:i + 2].encode(), "little")
            for i in range(0, len(text), 2)]


class StegoFunctionTest(unittest.TestCase):
    """modbus_register_stego 纯函数单测。"""

    def test_big_endian_flag_segment(self):
        text = "flag{modbus_stego}"
        entries = [(100 + i, 1 + i, v)
                   for i, v in enumerate(_regs_big(text))]
        segments = ics.modbus_register_stego(entries)
        self.assertEqual(len(segments), 1, segments)
        seg = segments[0]
        self.assertEqual(seg["encoding"], "big")
        self.assertEqual(seg["text"], text)
        self.assertEqual(seg["count"], 9)
        self.assertEqual(str(seg["frame"]), "100")
        self.assertEqual(str(seg["frame_end"]), "108")
        self.assertEqual((seg["ref"], seg["ref_end"]), (1, 9))
        self.assertGreaterEqual(seg["ratio"], 0.8)

    def test_little_endian_wins_by_flag_shape_and_dedup(self):
        # 两种字节序对全可打印文本必然都能拼出可打印段：同一只下标段去重后
        # 只保留一个，且解码出 flag{...} 形态的小端候选应胜出。
        text = "flag{modbus_stego}"
        entries = [(200 + i, 5 + i, v)
                   for i, v in enumerate(_regs_little(text))]
        segments = ics.modbus_register_stego(entries)
        self.assertEqual(len(segments), 1, segments)
        self.assertEqual(segments[0]["encoding"], "little")
        self.assertEqual(segments[0]["text"], text)

    def test_dedup_prefers_big_when_no_flag_shape(self):
        # 无 flag 形态且可打印率打平时，大端候选优先。
        entries = [(300 + i, 1 + i, v)
                   for i, v in enumerate(_regs_little("abcdefgh"))]
        segments = ics.modbus_register_stego(entries)
        self.assertEqual(len(segments), 1, segments)
        self.assertEqual(segments[0]["encoding"], "big")

    def test_low8_ascii_stream(self):
        # 高字节为不可打印的 0x01，仅低 8 位携带 ASCII，须走低字节流检测。
        payload = b"secret1"
        entries = [(400 + i, 10 + i, 0x0100 | b)
                   for i, b in enumerate(payload)]
        segments = ics.modbus_register_stego(entries)
        self.assertEqual(len(segments), 1, segments)
        self.assertEqual(segments[0]["encoding"], "low8")
        self.assertEqual(segments[0]["text"], "secret1")
        self.assertEqual((segments[0]["ref"], segments[0]["ref_end"]),
                         (10, 16))

    def test_short_segments_do_not_trigger(self):
        # 2 个 16 位值 / 5 个低字节可打印值都低于门槛，中间再用噪声值隔开，
        # 不应报任何段。
        noise = (9, 99, 0x0102)
        big2 = [(1, 1 + i, v) for i, v in enumerate(_regs_big("ab"))]
        low5 = [(2, 1 + i, 0x0100 | b) for i, b in enumerate(b"hello")]
        self.assertEqual(ics.modbus_register_stego(big2), [])
        self.assertEqual(ics.modbus_register_stego(low5), [])
        self.assertEqual(ics.modbus_register_stego(big2 + [noise] + low5), [])

    def test_noise_registers_do_not_trigger(self):
        entries = [(1, 1, 0x0102), (2, 2, 0x0304), (3, 3, 0xFFFF),
                   (4, 4, 0x7F7F), (5, 5, 0x0001)]
        self.assertEqual(ics.modbus_register_stego(entries), [])

    def test_segment_limit(self):
        # 10 个互不相邻的 4 值大端段（中间隔噪声值），只报前 5 段。
        entries = []
        frame = 1
        for _ in range(10):
            for value in _regs_big("secret12"):
                entries.append((frame, 1, value))
                frame += 1
            entries.append((frame, 1, 0x0102))  # 噪声值切断段
            frame += 1
        segments = ics.modbus_register_stego(entries)
        self.assertEqual(len(segments), ics.MODBUS_MAX_STEGO_SEGMENTS)


class StegoHandlerCannedTest(unittest.TestCase):
    """handler 层罐装行测试：不依赖 tshark，验证 finding 形状。

    行布局与 ``ics.MODBUS_EXT_FIELDS`` 一致:
    frame, unit, func, ref, regval, exception, sport, dport, stream。
    """

    def setUp(self):
        import shutil
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-modbus-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def _run(self, rows):
        from tests.test_handlers_extra import FakeTshark
        from fnet.features.registry import FeatureContext
        from fnet.logger import Logger
        ctx = FeatureContext(
            config=Config(self.tmp / "config.ini"),
            logger=Logger(self.tmp / "fnet.log"),
            tshark=FakeTshark(routes={"modbus": rows}),
            pcap=str(self.tmp / "x.pcap"),
            output_dir=self.tmp / "out",
        )
        ics.modbus(ctx)
        log = "\n".join(r.line for r in ctx.logger.records_since(0, limit=100000))
        return ctx, log

    def test_write_stego_findings(self):
        text = "flag{modbus_stego}"
        regs = _regs_big(text)
        rows = []
        for i, value in enumerate(regs):
            frame = 10 + i
            rows.append([str(frame), "1", "6", str(1 + i), str(value), "",
                         "50000", "502", "0"])
            rows.append([str(frame), "1", "6", str(1 + i), str(value), "",
                         "502", "50000", "0"])
        ctx, log = self._run(rows)
        kinds = [f["kind"] for f in ctx.findings]
        self.assertIn("flag", kinds)
        flags = [f for f in ctx.findings if f["kind"] == "flag"]
        self.assertTrue(any(text in f["summary"] for f in flags),
                        ctx.findings)
        stego = [f for f in ctx.findings
                 if f["summary"] == "疑似 Modbus 寄存器隐写"]
        self.assertEqual(len(stego), 1, ctx.findings)
        self.assertEqual(stego[0]["kind"], "protocol")
        self.assertEqual(stego[0]["level"], "good")
        self.assertIn("大端", stego[0]["detail"])
        self.assertIn(text, stego[0]["detail"])
        self.assertIn("疑似 Modbus 寄存器隐写", log)
        # 概览 finding 也应存在（请求 9 / 响应 9）。
        overview = [f for f in ctx.findings
                    if f["summary"].startswith("Modbus 流量概览")]
        self.assertEqual(len(overview), 1, ctx.findings)
        self.assertIn("请求 9 / 响应 9", overview[0]["summary"])

    def test_exception_code_finding(self):
        # 功能码 72 不是标准读写码，应单独报异常功能码 finding。
        rows = [["1", "1", "72", "5", "1234", "", "50000", "502", "0"]]
        ctx, _ = self._run(rows)
        anomalies = [f for f in ctx.findings
                     if f["summary"] == "Modbus 异常功能码"]
        self.assertEqual(len(anomalies), 1, ctx.findings)
        self.assertEqual(anomalies[0]["level"], "warn")


# --------------------------------------------------------------------------
# 集成测试：纯 stdlib 构造的最小 Modbus/TCP 抓包（需要 tshark）
# --------------------------------------------------------------------------
FLAG_TEXT = "flag{modbus_test}"


def _mbap(trans_id: int, unit: int, pdu: bytes) -> bytes:
    return struct.pack(">HHHB", trans_id, 0, len(pdu) + 1, unit) + pdu


def _fc6(trans_id: int, unit: int, ref: int, value: int) -> bytes:
    return _mbap(trans_id, unit, struct.pack(">BHH", 6, ref, value))


def _fc4_request(trans_id: int, unit: int, ref: int, count: int) -> bytes:
    return _mbap(trans_id, unit, struct.pack(">BHH", 4, ref, count))


def _fc4_response(trans_id: int, unit: int, values: list[int]) -> bytes:
    pdu = (struct.pack(">BB", 4, 2 * len(values))
           + b"".join(struct.pack(">H", v) for v in values))
    return _mbap(trans_id, unit, pdu)


def _write_modbus_stego_pcap(path: Path) -> None:
    """最小 Modbus/TCP 夹具：

    * FC6 连续写寄存器 1..N，大端携带 ``flag{modbus_test}``（含响应回显）；
    * 一个 FC4 读输入寄存器（值为不可打印噪声）；
    * 一条普通单值写（寄存器 100 = 1234，不构成隐写段）。
    """
    client: list[bytes] = []
    server: list[bytes] = []
    trans_id = 1
    for ref, value in enumerate(_regs_big(FLAG_TEXT + "\x00"), start=1):
        client.append(_fc6(trans_id, 1, ref, value))
        server.append(_fc6(trans_id, 1, ref, value))  # 写响应回显
        trans_id += 1
    client.append(_fc4_request(trans_id, 1, 0, 4))
    server.append(_fc4_response(trans_id, 1, [0x0102, 0x0304, 0x0506, 0x0708]))
    trans_id += 1
    client.append(_fc6(trans_id, 1, 100, 1234))
    server.append(_fc6(trans_id, 1, 100, 1234))
    pcap_build.write_pcap(
        path, pcap_build.tcp_session("10.0.0.1", 50100, "10.0.0.2", 502,
                                     client, server))


@unittest.skipUnless(TSHARK, "需要 tshark")
class ModbusStegoIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="fnet-modbus-it-")
        cls.pcap = Path(cls.tmp.name) / "modbus_stego.pcap"
        _write_modbus_stego_pcap(cls.pcap)
        cls.patches = patch_cache_dirs(cls.tmp.name)
        for patch in cls.patches:
            patch.start()
        cls.runtime = build(Config(Path(cls.tmp.name) / "config.ini"))

    @classmethod
    def tearDownClass(cls):
        for patch in reversed(cls.patches):
            patch.stop()
        cls.tmp.cleanup()

    def test_modbus_stego_end_to_end(self):
        job = self.runtime.jobs.submit(str(self.pcap), ["ics.modbus"], {})
        deadline = time.time() + 120
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                self.fail(f"任务超时: {job.id}")
            time.sleep(0.05)
        self.assertEqual(job.status, "done", job.error)
        log = "\n".join(r.line for r in job.log.records_since(0, limit=100000))
        findings = job.findings
        kinds = {f["kind"] for f in findings}

        # 概览 / 写统计 / 隐写 finding 均出现。
        self.assertIn("Modbus 流量概览", log)
        overview = [f for f in findings
                    if f["summary"].startswith("Modbus 流量概览")]
        self.assertEqual(len(overview), 1, findings)
        self.assertEqual(overview[0]["kind"], "protocol")
        self.assertIn("Write Single Register(6)", overview[0]["detail"])

        write_stats = [f for f in findings
                       if f["summary"].startswith("Modbus 写操作统计")]
        self.assertEqual(len(write_stats), 1, findings)
        self.assertIn("寄存器 1", write_stats[0]["detail"])

        stego = [f for f in findings
                 if f["summary"] == "疑似 Modbus 寄存器隐写"]
        self.assertEqual(len(stego), 1, findings)
        self.assertEqual(stego[0]["level"], "good")
        self.assertIn("大端", stego[0]["detail"])
        self.assertIn(FLAG_TEXT, stego[0]["detail"])
        self.assertIn("疑似 Modbus 寄存器隐写", log)

        # flag finding 命中 flag{modbus_test}。
        self.assertIn("flag", kinds)
        flags = [f for f in findings if f["kind"] == "flag"]
        self.assertTrue(
            any(FLAG_TEXT in f["summary"] for f in flags), findings)

        # 逐条写操作 finding：9 个隐写写（17 字符 + NUL 填充共 9 个寄存器）
        # + 1 个普通写。
        per_write = [f for f in findings
                     if f["summary"].startswith("Modbus 写操作: 帧")]
        self.assertEqual(len(per_write), 10, findings)


if __name__ == "__main__":
    unittest.main()
