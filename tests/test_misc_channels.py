"""``misc`` 隐蔽信道/外设提取的单元测试（无需 tshark）。

覆盖：
* IPID 三条通道（低字节 / 高字节 / 16 位全值）的形态判定与解码；
* USBMS（Bulk-Only Transport）CBW/CSW 边界定位与数据阶段重组。

断言针对纯函数（``ipid_profile`` / ``ipid_channels`` /
``ipid_decode_candidates`` / ``usbms_transfers`` / ``usbms_payload`` /
``assemble_usbms``），另有少量 handler 级用例用罐装 tshark 行验证
``misc.ipid`` / ``misc.scsi`` 的日志、结构化结果与工件命名。
"""
from __future__ import annotations

import base64
import string
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fnet.config import Config
from fnet.features import misc
from fnet.features.registry import FeatureContext
from fnet.logger import Logger

#: 羊城杯 2020 TCP_IP 真题里 ip.id 低字节的实际取值（64 字符字母表通道）。
YANGCHENG_LOW = (
    "@iH<,{*;oUp/im\"QPl`yR*ie}NK;.D!Xu)b:J[Rj+6KKM7P"
    "@iH<,{*;oUp/im\"QPl`yR"
)
B64 = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"


class FakeTshark:
    """按显示过滤器返回罐装行（与 tests/test_handlers_extra.py 同构）。"""

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


class BaseCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-misc-"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ctx(self, fake=None, params: dict | None = None) -> FeatureContext:
        return FeatureContext(
            config=Config(self.tmp / "config.ini"),
            logger=Logger(self.tmp / "fnet.log"),
            tshark=fake,
            pcap=str(self.tmp / "x.pcap"),
            params=params or {},
            output_dir=self.tmp / "out",
        )

    @staticmethod
    def lines(ctx: FeatureContext) -> str:
        return "\n".join(r.line for r in ctx.logger.records_since(0, limit=100000))


# ---------------------------------------------------------------------------
# IPID 通道
# ---------------------------------------------------------------------------
class IpidChannelTest(BaseCase):
    def test_constant_sequence_is_not_a_channel(self):
        ids = [0x04D2] * 20
        profile = misc.ipid_profile(ids)
        self.assertTrue(profile["constant"])
        self.assertEqual(misc.ipid_channels(ids), [])

    def test_sequential_sequence_is_normal_behaviour(self):
        ids = list(range(1000, 1020))
        profile = misc.ipid_profile(ids)
        self.assertTrue(profile["sequential"])
        self.assertFalse(profile["constant"])
        self.assertEqual(misc.ipid_channels(ids), [])

    def test_sequential_wraparound_is_still_normal(self):
        # 16 位回绕（65535 -> 0）也必须算顺序递增，否则会被误判成信道。
        ids = list(range(65528, 65536)) + list(range(0, 8))
        profile = misc.ipid_profile(ids)
        self.assertTrue(profile["sequential"])
        self.assertEqual(misc.ipid_channels(ids), [])

    def test_low_byte_base64_channel(self):
        message = "flag{ipid_low}"
        encoded = base64.b64encode(message.encode()).decode().rstrip("=")
        # 低字节 = base64 索引 + 0x20，保证可打印且取值集合很小。
        ids = [B64.index(char) + 0x20 for char in encoded]
        profile = misc.ipid_profile(ids)
        self.assertFalse(profile["constant"])
        self.assertFalse(profile["sequential"])
        channels = misc.ipid_channels(ids)
        names = [item["channel"] for item in channels]
        self.assertIn("low", names)
        # 高字节恒为 0，因此 16 位通道没有额外信息，不应重复上报。
        self.assertNotIn("full", names)
        low = next(item for item in channels if item["channel"] == "low")
        self.assertEqual(low["data"], bytes(ids))
        self.assertIn(message, misc.ipid_decode_candidates(low["data"]))

    def test_16bit_channel(self):
        message = "flag{ipid16ok}"          # 14 字符 = 7 个 16 位样本
        pairs = [message[index:index + 2]
                 for index in range(0, len(message), 2)]
        ids = [(ord(pair[0]) << 8) | ord(pair[1]) for pair in pairs]
        channels = {item["channel"]: item for item in misc.ipid_channels(ids)}
        self.assertIn("full", channels)
        self.assertEqual(channels["full"]["data"], message.encode())
        self.assertIn(message, misc.ipid_decode_candidates(
            channels["full"]["data"]))

    def test_random_ids_are_not_flagged(self):
        ids = [0x1000 + index * 0x137 for index in range(20)]
        self.assertEqual(misc.ipid_channels(ids), [])

    def test_short_sequence_needs_minimum_samples(self):
        encoded = base64.b64encode(b"flag").decode().rstrip("=")
        ids = [B64.index(char) + 0x20 for char in encoded]
        self.assertEqual(misc.ipid_channels(ids, min_samples=8), [])

    def test_channel_bytes_rendering(self):
        ids = [0x4142, 0x4344]
        self.assertEqual(misc.ipid_channel_bytes(ids, "low"), b"BD")
        self.assertEqual(misc.ipid_channel_bytes(ids, "high"), b"AC")
        self.assertEqual(misc.ipid_channel_bytes(ids, "full"), b"ABCD")

    # -- handler 级 ----------------------------------------------------
    def test_handler_flags_capture_wide_low_byte_channel(self):
        # 每个源 IP 只发 1 个包：单流样本不足，必须靠全捕获序列发现通道。
        rows = [[str(index + 1), f"10.0.1.{index + 1}", "8.8.8.8",
                 str(ord(char)), "60", "6"]
                for index, char in enumerate(YANGCHENG_LOW)]
        ctx = self.ctx(FakeTshark(routes={"ip": rows}))
        misc.ipid(ctx)
        text = self.lines(ctx)
        self.assertIn(f"共 {len(YANGCHENG_LOW)} 个 IP 流", text)
        self.assertIn("全捕获 IPID 隐蔽信道（低字节）", text)
        self.assertIn("取值集合小且非单调", text)
        channels = [item for item in ctx.findings
                    if item["kind"] == "protocol"
                    and item["summary"].startswith("IPID 隐蔽信道")]
        self.assertTrue(channels, [item["summary"] for item in ctx.findings])
        self.assertEqual(channels[0]["level"], "warn")
        self.assertEqual(channels[0]["extra"]["channel"], "low")
        self.assertEqual(channels[0]["extra"]["candidate"], YANGCHENG_LOW)
        saved = self.tmp / "out" / "ipid_all_all.txt"
        self.assertEqual(saved.read_text("utf-8"), YANGCHENG_LOW)

    def test_handler_keeps_sequential_debug_path(self):
        rows = [[str(index + 1), "10.0.0.1", "10.0.0.2", str(1000 + index),
                 "60", "6"] for index in range(10)]
        ctx = self.ctx(FakeTshark(routes={"ip": rows}))
        misc.ipid(ctx)
        text = self.lines(ctx)
        self.assertIn("IP ID 顺序递增（正常行为）", text)
        self.assertFalse([item for item in ctx.findings
                          if item["kind"] == "protocol"])

    def test_handler_without_ip_traffic(self):
        ctx = self.ctx(FakeTshark())
        misc.ipid(ctx)
        self.assertIn("没有发现 IP 流量", self.lines(ctx))


# ---------------------------------------------------------------------------
# USBMS / SCSI 数据阶段重组
# ---------------------------------------------------------------------------
CBW = str(misc.CBW_SIGNATURE)
CSW = str(misc.CSW_SIGNATURE)


def usbms_row(frame, data_len, direction, cbw="", csw="", expected="",
              flags=""):
    return [str(frame), str(data_len), str(direction), cbw, csw,
            str(expected), str(flags)]


class UsbmsReassemblyTest(BaseCase):
    ROWS = [
        usbms_row(1, 31, 0, cbw=CBW, expected=8, flags="0x80"),  # CBW IN
        usbms_row(2, 8, 1),                                      # data
        usbms_row(3, 13, 1, csw=CSW),                            # CSW
        usbms_row(4, 31, 0, cbw=CBW, expected=6, flags="0x00"),  # CBW OUT
        usbms_row(5, 6, 0),                                      # data
        usbms_row(6, 13, 1, csw=CSW),                            # CSW
    ]

    def test_transfer_grouping(self):
        transfers = misc.usbms_transfers(self.ROWS)
        self.assertEqual(len(transfers), 2)
        first, second = transfers
        self.assertEqual(first["cbw"], "1")
        self.assertEqual(first["csw"], "3")
        self.assertEqual(first["frames"], ["2"])
        self.assertTrue(first["in"])
        self.assertEqual(first["expected"], 8)
        self.assertEqual(second["cbw"], "4")
        self.assertFalse(second["in"])
        self.assertEqual(second["frames"], ["5"])

    def test_unpaired_bulk_frames_are_ignored(self):
        rows = [usbms_row(1, 4, 1), usbms_row(2, 4, 1)] + self.ROWS
        transfers = misc.usbms_transfers(rows)
        self.assertEqual([item["cbw"] for item in transfers], ["1", "4"])

    def test_assemble_concatenates_and_trims(self):
        transfers = misc.usbms_transfers(self.ROWS)
        assembled = misc.assemble_usbms(
            transfers, {"2": b"flag{usb", "5": b"SCSI!!"})
        self.assertEqual(assembled[0]["data"], b"flag{usb")
        self.assertEqual(assembled[1]["data"], b"SCSI!!")
        # 数据多于 CBW 声明的长度时按声明值截断。
        trimmed = misc.assemble_usbms(
            [{"cbw": "9", "frames": ["10"], "expected": 4, "in": True}],
            {"10": b"0123456789"})
        self.assertEqual(trimmed[0]["data"], b"0123")

    def test_multi_frame_data_phase(self):
        rows = [
            usbms_row(1, 31, 0, cbw=CBW, expected=10, flags="0x80"),
            usbms_row(2, 6, 1),
            usbms_row(3, 4, 1),
            usbms_row(4, 13, 1, csw=CSW),
        ]
        transfers = misc.usbms_transfers(rows)
        self.assertEqual(transfers[0]["frames"], ["2", "3"])
        assembled = misc.assemble_usbms(
            transfers, {"2": b"flag{", "3": b"abc}"})
        self.assertEqual(assembled[0]["data"], b"flag{abc}")

    def test_payload_strips_usbpcap_header(self):
        body = b"VendorCoProductCode  2.00"
        raw = (b"\x1b\x00\x60\x4a" + body).hex()
        payload = misc.usbms_payload(raw, data_len=len(body), header_len=4)
        self.assertEqual(payload, body)

    def test_payload_falls_back_to_tail_for_usbmon(self):
        raw = (b"\x00" * 8 + b"EXFAT   ").hex()
        self.assertEqual(misc.usbms_payload(raw, data_len=8),
                         b"EXFAT   ")

    def test_printable_stats_and_fragments(self):
        low, high = misc.printable_stats(b"abc\xff\x00")
        self.assertAlmostEqual(low, 0.6, places=2)
        self.assertAlmostEqual(high, 0.6, places=2)
        # GBK 汉字（0xA1–0xFE）算作“高位可打印”，控制字节不算。
        _, gbk = misc.printable_stats("中文".encode("gbk"))
        self.assertEqual(gbk, 1.0)
        self.assertEqual(misc.text_fragments(b"\x00flag{usbms}\x00"),
                         ["flag{usbms}"])

    def test_zip_listing_reports_entries_and_encryption(self):
        import io
        import zipfile

        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("out.txt", "flag{zip}")
        blob = b"\x00" * 16 + buffer.getvalue()
        self.assertIn("out.txt 9 字节", misc.zip_listing(blob))
        self.assertEqual(misc.zip_listing(b"no zip here"), [])
        # 只有 PK\x03\x04 头、没有中央目录的残缺数据不能抛异常。
        self.assertTrue(misc.zip_listing(b"PK\x03\x04garbage"))

    def test_looks_interesting(self):
        self.assertTrue(misc.looks_interesting(b"VendorCoProductCode  2.00"))
        self.assertFalse(misc.looks_interesting(bytes(range(64))))
        self.assertTrue(misc.looks_interesting(b"\x00" * 4 + b"PK\x03\x04"))

    # -- handler 级 ----------------------------------------------------
    def _bulk_rows(self):
        return [
            ["1", "31", "0", CBW, "", "8", "0x80"],
            ["2", "8", "1", "", "", "", ""],
            ["3", "13", "1", "", CSW, "", ""],
        ]

    def test_handler_writes_artifacts(self):
        fake = FakeTshark(routes={"usb.transfer_type": self._bulk_rows()})
        ctx = self.ctx(fake)
        with mock.patch.object(misc, "_usbms_payload_map",
                               return_value={"2": b"flag{usbms}"}):
            misc.scsi(ctx)
        text = self.lines(ctx)
        self.assertIn("USBMS 传输 1 个（CBW 定位），重组数据 8 字节", text)
        self.assertEqual((self.tmp / "out" / "scsi_usbms_in.bin").read_bytes(),
                         b"flag{usb")
        self.assertTrue((self.tmp / "out" / "scsi_1.bin").is_file())
        findings = [item for item in ctx.findings if item["kind"] == "file"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["frame"], "1")
        self.assertIn("8 字节", findings[0]["summary"])

    def test_handler_diagnoses_missing_data_phase(self):
        fake = FakeTshark(routes={"usb.transfer_type": self._bulk_rows()})
        ctx = self.ctx(fake)
        with mock.patch.object(misc, "_usbms_payload_map", return_value={}):
            misc.scsi(ctx)
        text = self.lines(ctx)
        self.assertIn("已发现 USBMS 命令（CBW/CSW），但未重组出数据阶段", text)
        findings = [item for item in ctx.findings
                    if item["kind"] == "protocol"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["level"], "warn")

    def test_handler_without_any_scsi_traffic(self):
        ctx = self.ctx(FakeTshark())
        misc.scsi(ctx)
        self.assertIn("没有发现 SCSI 流量", self.lines(ctx))


if __name__ == "__main__":
    unittest.main()
