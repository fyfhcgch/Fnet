"""USB HID parsing tests: boot vs non-boot reports and findings.

The handlers are driven through :class:`FeatureContext` with a fake tshark, so
no real capture (and no ``tshark`` binary) is required.

Measured reference: ``9.4.1 鼠标流量分析`` ships a Logitech G402 that declares
``bInterfaceProtocol=0x02`` (boot mouse) yet sends 8-byte non-boot reports
``[buttons, pad, x_lo, x_hi, y_lo, y_hi, wheel, pad]``.  Reading dx/dy at
offset 1/2 (boot) degenerates to ``x=0`` for all 3459 points; reading them at
2/4 reproduces the staircase trajectory.
"""
from __future__ import annotations

import csv
import struct
import tempfile
import unittest
from pathlib import Path

from fnet.config import Config
from fnet.features import usb
from fnet.features.registry import FeatureContext
from fnet.logger import Logger


class FakeTshark:
    """Return canned rows; remembers which fields were requested."""

    def __init__(self, rows=None):
        self.rows = rows or []
        self.path = ""
        self.calls: list[tuple[str, list[str]]] = []

    def fields(self, pcap, fields, display_filter="", extra=None, cancel=None):
        self.calls.append((display_filter, list(fields)))
        return self.rows


def make_ctx(tmp: Path, fake=None) -> FeatureContext:
    return FeatureContext(
        config=Config(tmp / "config.ini"),
        logger=Logger(tmp / "fnet.log"),
        tshark=fake,
        pcap=str(tmp / "x.pcap"),
        output_dir=tmp / "out",
    )


def boot_mouse(buttons: int, dx: int, dy: int, wheel: int = 0) -> bytes:
    """Classic 4-byte boot mouse report ``[buttons, dx, dy, wheel]``."""
    return bytes([buttons, dx & 0xFF, dy & 0xFF, wheel & 0xFF])


def hid_mouse(buttons: int, dx: int, dy: int, wheel: int = 0) -> bytes:
    """8-byte non-boot report: X int16@2, Y int16@4, little endian."""
    return (bytes([buttons, 0])
            + struct.pack("<h", dx) + struct.pack("<h", dy)
            + bytes([wheel & 0xFF, 0]))


def keyboard_report(*keys: int, modifier: int = 0) -> bytes:
    return bytes([modifier, 0] + list(keys) + [0] * (6 - len(keys)))


class CtxTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="fnet-usb-"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def lines(self, ctx: FeatureContext) -> str:
        return "\n".join(r.line for r in ctx.logger.records_since(0, limit=100000))

    def mouse_points(self, ctx: FeatureContext) -> list[dict]:
        path = self.tmp / "out" / "usb_mouse.csv"
        with path.open(encoding="utf-8", newline="") as handle:
            return list(csv.DictReader(handle))


class ReportFetchTest(CtxTestCase):
    def test_requests_interface_hint_fields(self):
        fake = FakeTshark(rows=[["1", "00000000", "", "", ""]])
        ctx = make_ctx(self.tmp, fake)
        usb.mouse(ctx)
        _filter, fields = fake.calls[0]
        self.assertEqual(fields, ["frame.number", "usb.capdata", "usbhid.data",
                                  "usb.bInterfaceProtocol", "usb.transfer_type"])

    def test_short_rows_are_padded_positionally(self):
        """Older tshark builds omit the hint columns entirely."""
        fake = FakeTshark(rows=[["7", "01000a14", ""]])
        ctx = make_ctx(self.tmp, fake)
        reports = usb._reports(ctx)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0].frame, "7")
        self.assertEqual(reports[0].protocol, "")
        self.assertEqual(reports[0].transfer, "")

    def test_hex_payload_preferred_over_empty_capdata(self):
        fake = FakeTshark(rows=[["1", "", "0000010000000000", "", ""]])
        ctx = make_ctx(self.tmp, fake)
        reports = usb._reports(ctx)
        self.assertEqual(reports[0].data, bytes.fromhex("0000010000000000"))


class MouseLayoutTest(CtxTestCase):
    def test_boot_mouse_four_byte_report(self):
        """4-byte boot report keeps ``[buttons, dx, dy, wheel]`` semantics."""
        rows = [
            ["1", boot_mouse(0, 10, 20).hex(), "", "", ""],
            ["2", boot_mouse(1, 0xFB, 0xFD).hex(), "", "", ""],   # dx=-5 dy=-3
            ["3", boot_mouse(0, 0, 5).hex(), "", "", ""],
        ]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.mouse(ctx)
        points = self.mouse_points(ctx)
        self.assertEqual([(int(p["x"]), int(p["y"])) for p in points],
                         [(10, 20), (5, 17), (5, 22)])
        self.assertEqual([int(p["buttons"]) for p in points], [0, 1, 0])
        text = self.lines(ctx)
        self.assertIn("轨迹点 3 个，左键 1 次", text)
        self.assertIn("坐标范围 x=5..10 y=17..22", text)

    def test_non_boot_eight_byte_report_uses_int16_offsets(self):
        """8-byte HID report: dx int16@2, dy int16@4 -> non-zero x span."""
        rows = []
        x = y = 0
        # A staircase: 30 steps right, 30 steps down, 30 steps left.
        for step in [(3, 0)] * 30 + [(0, 2)] * 30 + [(-3, 0)] * 30:
            x += step[0]
            y += step[1]
            rows.append([str(len(rows) + 1), hid_mouse(0, *step).hex(), "", "", ""])
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.mouse(ctx)
        points = self.mouse_points(ctx)
        self.assertEqual(len(points), 90)
        xs = [int(p["x"]) for p in points]
        ys = [int(p["y"]) for p in points]
        self.assertEqual((min(xs), max(xs)), (0, 90))
        self.assertEqual((min(ys), max(ys)), (0, 60))
        # The old boot layout read dx from byte 1 (always 0 here) -> degenerate.
        self.assertGreater(max(xs) - min(xs), 0)
        self.assertIn("x=0..90 y=0..60", self.lines(ctx))
        self.assertIn("非 boot HID 报告", self.lines(ctx))

    def test_non_boot_negative_int16_deltas(self):
        """Sign-extended int16 deltas must not be read as large positives."""
        rows = [
            ["1", hid_mouse(0, -1, -1).hex(), "", "", ""],
            ["2", hid_mouse(0, -256, 255).hex(), "", "", ""],
        ]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.mouse(ctx)
        points = self.mouse_points(ctx)
        self.assertEqual([(int(p["x"]), int(p["y"])) for p in points],
                         [(-1, -1), (-257, 254)])

    def test_five_byte_report_uses_truncated_dy(self):
        """A 5-byte report is a truncated HID report: dy is int8@4."""
        report = bytes([0, 0]) + struct.pack("<h", 7) + bytes([0xFE])
        self.assertEqual(usb.mouse_layout(usb.Report("1", report)), "hid")
        self.assertEqual(usb.mouse_delta(usb.Report("1", report)), (0, 7, -2))

    def test_declared_boot_protocol_does_not_override_report_length(self):
        """The G402 declares boot mouse but sends 8-byte reports (measured)."""
        report = usb.Report("1", hid_mouse(0, 5, 0), protocol="0x02")
        self.assertEqual(usb.mouse_layout(report), "hid")
        self.assertEqual(usb.mouse_delta(report), (0, 5, 0))

    def test_non_boot_dy_is_not_read_from_dx_high_byte(self):
        """``00000000ffff0000`` is dy=-1, not the bogus -256 from dy@3."""
        report = bytes.fromhex("00000000ffff0000")
        self.assertEqual(usb.mouse_delta(usb.Report("1", report)), (0, 0, -1))

    def test_short_report_is_boot_regardless_of_protocol_hint(self):
        # Length wins: a 4-byte report is boot even with a non-boot hint.
        self.assertEqual(usb.mouse_layout(
            usb.Report("1", boot_mouse(0, 1, 2), protocol="0x00")), "boot")

    def test_too_short_reports_are_ignored(self):
        rows = [
            ["1", "01", "", "", ""],
            ["2", "0100", "", "", ""],
            ["3", boot_mouse(0, 4, 4).hex(), "", "", ""],
        ]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.mouse(ctx)
        points = self.mouse_points(ctx)
        self.assertEqual([(int(p["x"]), int(p["y"])) for p in points], [(4, 4)])

    def test_boot_keyboard_reports_are_not_mouse_movement(self):
        rows = [
            ["1", boot_mouse(0, 1, 1).hex(), "", "0x01", "0x01"],
            ["2", boot_mouse(0, 2, 2).hex(), "", "0x01", "0x01"],
        ]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.mouse(ctx)
        self.assertEqual(self.mouse_points(ctx), [])


class MouseFindingTest(CtxTestCase):
    def test_non_trivial_trajectory_produces_finding(self):
        rows = [[str(i + 1), boot_mouse(0, 4, 2).hex(), "", "", ""]
                for i in range(40)]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.mouse(ctx)
        self.assertEqual(len(ctx.findings), 1)
        item = ctx.findings[0]
        self.assertEqual(item["kind"], "other")
        self.assertIn("USB 鼠标轨迹 40 点", item["summary"])
        self.assertEqual(item["frame"], "1")
        self.assertIn("usb_mouse.csv", item["detail"])
        # Log line and finding stay in sync (AGENTS.md).
        self.assertIn(item["summary"], self.lines(ctx))

    def test_degenerate_trajectory_produces_no_finding(self):
        rows = [[str(i + 1), boot_mouse(0, 0, 0).hex(), "", "", ""]
                for i in range(40)]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.mouse(ctx)
        self.assertEqual(ctx.findings, [])

    def test_tiny_trajectory_produces_no_finding(self):
        rows = [["1", boot_mouse(0, 5, 5).hex(), "", "", ""]]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.mouse(ctx)
        self.assertEqual(ctx.findings, [])


class KeyboardTest(CtxTestCase):
    def test_boot_keyboard_decode(self):
        reports = [
            keyboard_report(0x09), keyboard_report(),      # f
            keyboard_report(0x0F), keyboard_report(),      # l
            keyboard_report(0x04), keyboard_report(),      # a
            keyboard_report(0x0A), keyboard_report(),      # g
            keyboard_report(0x1E, modifier=0x02),          # shift+1 -> !
        ]
        rows = [[str(i + 1), r.hex(), "", "", ""]
                for i, r in enumerate(reports)]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.keyboard(ctx)
        saved = (self.tmp / "out" / "usb_keyboard.txt").read_text("utf-8")
        self.assertEqual(saved, "flag!")
        self.assertIn("USB 键盘报告 9 条", self.lines(ctx))

    def test_keyboard_decode_produces_finding(self):
        rows = [[str(i + 1), r.hex(), "", "", ""]
                for i, r in enumerate(key_reports("flag"))]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.keyboard(ctx)
        kinds = [item["kind"] for item in ctx.findings]
        self.assertIn("other", kinds)
        text_finding = next(f for f in ctx.findings if f["kind"] == "other")
        self.assertIn("USB 键盘还原文本", text_finding["summary"])
        self.assertEqual(text_finding["detail"], "flag")
        self.assertIn(text_finding["summary"], self.lines(ctx))

    def test_decoded_flag_becomes_flag_finding(self):
        rows = [[str(i + 1), r.hex(), "", "", ""]
                for i, r in enumerate(key_reports("flag{usb}"))]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.keyboard(ctx)
        flags = [f for f in ctx.findings if f["kind"] == "flag"]
        self.assertEqual([f["summary"] for f in flags], ["flag{usb}"])

    def test_flag_split_by_editor_escape_sequences(self):
        """``thekey``: ``ctf`` + ESC ``vbUA`` + ``{...}`` must still decode."""
        rows = [[str(i + 1), r.hex(), "", "", ""]
                for i, r in enumerate(
                    key_reports("ctf\x1bvbUA{my_favorite_editor_is_vim}"))]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.keyboard(ctx)
        flags = [f["summary"] for f in ctx.findings if f["kind"] == "flag"]
        self.assertEqual(flags, ["ctf{my_favorite_editor_is_vim}"])

    def test_plain_word_before_brace_is_not_a_flag(self):
        rows = [[str(i + 1), r.hex(), "", "", ""]
                for i, r in enumerate(key_reports("notaflag{x}"))]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.keyboard(ctx)
        self.assertEqual([f for f in ctx.findings if f["kind"] == "flag"], [])

    def test_mouse_interface_reports_are_skipped(self):
        rows = [["1", keyboard_report(0x04).hex(), "", "0x02", "0x01"]]
        ctx = make_ctx(self.tmp, FakeTshark(rows=rows))
        usb.keyboard(ctx)
        saved = (self.tmp / "out" / "usb_keyboard.txt").read_text("utf-8")
        self.assertEqual(saved, "")

    def test_without_tshark(self):
        ctx = make_ctx(self.tmp, None)
        usb.keyboard(ctx)
        usb.mouse(ctx)
        self.assertEqual(self.lines(ctx).count("未找到 USB HID 数据"), 2)


#: Reverse of ``usb.HID_KEYMAP`` for the characters the tests type.
_CHAR_TO_CODE = {value: key for key, value in usb.HID_KEYMAP.items()
                 if value and value.isprintable()}


def usb_char(char: str) -> int:
    """HID usage id for a printable ASCII character (shifted ones included)."""
    if char in _CHAR_TO_CODE:
        return _CHAR_TO_CODE[char]
    if char.isupper() and char.lower() in _CHAR_TO_CODE:
        return _CHAR_TO_CODE[char.lower()]
    for base, shifted in usb.SHIFT_MAP.items():
        if shifted == char and base in _CHAR_TO_CODE:
            return _CHAR_TO_CODE[base]
    raise AssertionError(f"no HID usage id for {char!r}")


def usb_modifier(char: str) -> int:
    """Left-shift modifier bit for characters that need one."""
    if char.isupper() or char in usb.SHIFT_MAP.values():
        return 0x02
    return 0


def key_reports(text: str) -> list[bytes]:
    """One press + one release report per character (with modifiers)."""
    reports: list[bytes] = []
    for char in text:
        code = 0x29 if char == "\x1b" else usb_char(char)
        reports.append(keyboard_report(code, modifier=usb_modifier(char)))
        reports.append(keyboard_report())
    return reports


if __name__ == "__main__":
    unittest.main()
