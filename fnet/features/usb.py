"""USB HID keyboard and mouse reconstruction."""
from __future__ import annotations

import csv
import io
import re
import struct
from dataclasses import dataclass

from fnet.features.registry import FeatureContext
from fnet.utils import codec
from fnet.utils.pcap import hex_to_bytes

# USB HID Usage ID -> character (US layout).  Index 0x00-0x67.
HID_KEYMAP = {
    0x04: "a", 0x05: "b", 0x06: "c", 0x07: "d", 0x08: "e", 0x09: "f",
    0x0A: "g", 0x0B: "h", 0x0C: "i", 0x0D: "j", 0x0E: "k", 0x0F: "l",
    0x10: "m", 0x11: "n", 0x12: "o", 0x13: "p", 0x14: "q", 0x15: "r",
    0x16: "s", 0x17: "t", 0x18: "u", 0x19: "v", 0x1A: "w", 0x1B: "x",
    0x1C: "y", 0x1D: "z",
    0x1E: "1", 0x1F: "2", 0x20: "3", 0x21: "4", 0x22: "5", 0x23: "6",
    0x24: "7", 0x25: "8", 0x26: "9", 0x27: "0",
    0x28: "\n", 0x29: "\x1b", 0x2A: "\b", 0x2B: "\t", 0x2C: " ",
    0x2D: "-", 0x2E: "=", 0x2F: "[", 0x30: "]", 0x31: "\\", 0x32: "#",
    0x33: ";", 0x34: "'", 0x35: "`", 0x36: ",", 0x37: ".", 0x38: "/",
    0x39: "\x00",  # caps lock
    0x3A: "\x00", 0x3B: "\x00", 0x3C: "\x00", 0x3D: "\x00", 0x3E: "\x00",
    0x3F: "\x00", 0x40: "\x00", 0x41: "\x00", 0x42: "\x00", 0x43: "\x00",
    0x44: "\x00", 0x45: "\x00", 0x46: "\x00", 0x47: "\x00", 0x48: "\x00",
    0x49: "\x00", 0x4A: "\x00", 0x4B: "\x00", 0x4C: "\x00", 0x4D: "\x00",
    0x4E: "\x00", 0x4F: "\x00",
    0x50: "\x00", 0x51: "\x00", 0x52: "\x00", 0x53: "\x00", 0x54: "\x00",
    0x55: "\x00", 0x56: "\x00", 0x57: "\x00", 0x58: "\x00", 0x59: "\x00",
    0x5A: "\x00", 0x5B: "\x00", 0x5C: "\x00", 0x5D: "\x00", 0x5E: "\x00",
    0x5F: "\x00",
    0x60: "\x00", 0x61: "\x00", 0x62: "\x00", 0x63: "\x00", 0x64: "\x00",
}
SHIFT_MAP = {
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^", "7": "&",
    "8": "*", "9": "(", "0": ")", "-": "_", "=": "+", "[": "{", "]": "}",
    "\\": "|", ";": ":", "'": '"', "`": "~", ",": "<", ".": ">", "/": "?",
}

KEYPAD_MAP = {
    0x53: "0", 0x54: "/", 0x55: "*", 0x56: "-", 0x57: "+", 0x58: "\n",
    0x59: "1", 0x5A: "2", 0x5B: "3", 0x5C: "4", 0x5D: "5", 0x5E: "6",
    0x5F: "7", 0x60: "8", 0x61: "9", 0x62: "0", 0x63: ".",
}

#: ``usb.bInterfaceProtocol`` values for the HID boot subclasses.
BOOT_KEYBOARD_PROTOCOL = 1
BOOT_MOUSE_PROTOCOL = 2
#: A boot mouse report is 3 bytes (no wheel) or 4 bytes (with wheel).
MOUSE_BOOT_REPORT_LEN = 4

#: A mouse trajectory is only worth a structured finding when it actually
#: moves: the degenerate ``x=0`` tracks produced by mis-parsed reports have a
#: span of 0 and must stay out of the findings table.
MOUSE_FINDING_MIN_POINTS = 20
MOUSE_FINDING_MIN_SPAN = 20

#: Control characters interleaved into a keystroke stream (vim/terminal
#: escapes); stripped before looking for flags.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
_BRACE_RE = re.compile(r"\{([^{}\r\n]{1,200})\}")
#: How far before ``{`` an editor command may sit between prefix and brace.
_PREFIX_WINDOW = 12
#: Longest first so ``dasctf{`` wins over the shorter ``ctf{``.
_FLAG_PREFIXES = tuple(sorted(set(codec.FLAG_PREFIXES), key=len, reverse=True))


@dataclass(frozen=True)
class Report:
    """One ``usb.capdata``/``usbhid.data`` payload plus its interface hints.

    ``protocol`` and ``transfer`` come from ``usb.bInterfaceProtocol`` and
    ``usb.transfer_type``.  Both are frequently empty on *data* rows (tshark
    only fills them for descriptor/setup frames), so every consumer must treat
    them as hints and never as the sole decision input.
    """

    frame: str
    data: bytes
    protocol: str = ""
    transfer: str = ""

    def protocol_value(self) -> int | None:
        """First ``usb.bInterfaceProtocol`` value, or ``None`` when unknown."""
        return _first_int(self.protocol)


def _first_int(value: str) -> int | None:
    """Parse a tshark numeric field (``2``/``0x02``/``0x02,0x00``)."""
    text = str(value or "").strip()
    if not text:
        return None
    head = text.split(",", 1)[0].strip()
    try:
        return int(head, 0)
    except ValueError:
        return None


def _reports(ctx: FeatureContext) -> list[Report]:
    """Fetch every HID payload with the interface hints that tshark offers.

    ``usb.bInterfaceProtocol``/``usb.transfer_type`` are requested so reports
    can be bucketed per interface; on tshark builds that do not expose them on
    data rows the columns come back empty and callers fall back to deciding by
    report length (see :func:`mouse_layout`).
    """
    if ctx.tshark is None:
        return []
    fields = ["frame.number", "usb.capdata", "usbhid.data",
              "usb.bInterfaceProtocol", "usb.transfer_type"]
    rows = ctx.tshark.fields(
        ctx.pcap, fields,
        "usb.capdata or usbhid.data", cancel=ctx.cancel,
    )
    out: list[Report] = []
    for row in rows:
        row = list(row) + [""] * (len(fields) - len(row))
        frame = str(row[0] or "")
        raw = hex_to_bytes(row[1] or row[2])
        if raw:
            out.append(Report(frame, raw, str(row[3] or ""), str(row[4] or "")))
    return out


def mouse_layout(report: Report) -> str:
    """Return ``"boot"``, ``"hid"`` or ``"short"`` for one mouse report.

    报告长度是最可靠的判据：boot 鼠标报告固定 3 字节（无滚轮）或 4 字节
    （有滚轮），``>=5`` 字节一律按非 boot HID 报告解析。

    为什么不因为 ``usb.bInterfaceProtocol`` 是 2 就走 boot：实测
    ``9.4.1 鼠标流量分析`` 的 Logitech G402 在接口描述符里声明 boot mouse
    （``bInterfaceProtocol=0x02``），实际却发送 8 字节非 boot 报告，而且
    tshark 在这些数据行上根本不填该字段（3459 行全为空，只有描述符帧带值）。
    只按协议分桶会退化成 x 恒为 0 的轨迹 —— 这正是本次要修的缺陷。
    """
    size = len(report.data)
    if size < 3:
        return "short"
    if size <= MOUSE_BOOT_REPORT_LEN:
        return "boot"
    return "hid"


def mouse_delta(report: Report) -> tuple[int, int, int] | None:
    """``(buttons, dx, dy)`` for one report, or ``None`` when it is too short.

    boot 布局：``[buttons, dx, dy, wheel]``，dx/dy 为有符号 int8。

    非 boot 布局：``[buttons, pad, dx_lo, dx_hi, dy_lo, dy_hi, wheel, pad]``。
    也就是把报告看成 ``[buttons]`` 之后的 int16 字段序列时，**第 2 个字段是
    dx（字节 offset 2）**、**第 3 个字段是 dy（字节 offset 4）** —— 即
    "dx/dy 在字段 2/3" 对应的字节偏移是 2 和 4。

    为什么 dy 不在字节 offset 3：该包 3459/3459 条报告都满足 byte3/byte5
    分别是 byte2/byte4 的符号扩展，且只有 dy@4 给出物理上合理的位移
    （|dx|<=6、|dy|<=2）。若把 dy 放在字节 offset 3（与 dx 的高字节重叠），
    最常见的 ``00000000ffff0000`` 会读出 -256 而不是 -1，整条轨迹失真。

    5 字节报告放不下 int16@4，按同一布局截断成 int8@4 解析。
    """
    data = report.data
    layout = mouse_layout(report)
    if layout == "short":
        return None
    if layout == "boot":
        # 4-byte boot mouse report: [buttons, dx, dy, wheel]
        return data[0], _signed8(data[1]), _signed8(data[2])
    dx = struct.unpack_from("<h", data, 2)[0]
    if len(data) >= 6:
        dy = struct.unpack_from("<h", data, 4)[0]
    else:  # 5 字节：同一布局被截断，只剩 dy 的低字节
        dy = _signed8(data[4])
    return data[0], dx, dy


def _signed8(value: int) -> int:
    return value - 256 if value > 127 else value


def keyboard(ctx: FeatureContext) -> None:
    reports = _reports(ctx)
    if not reports:
        ctx.report("未找到 USB HID 数据", "warn")
        return
    ctx.report(f"USB 键盘报告 {len(reports)} 条", "info")
    text: list[str] = []
    last_keys: set[int] = set()
    first_frame = ""
    for index, report in enumerate(reports):
        if index % 200 == 0:
            ctx.set_progress(int(index / max(len(reports), 1) * 100))
            ctx.check_cancel()
        # 明确的鼠标接口（boot mouse）不是按键流，跳过以免还原出乱码。
        if report.protocol_value() == BOOT_MOUSE_PROTOCOL:
            continue
        data = report.data
        if len(data) < 8:
            continue
        modifier = data[0]
        keys = [k for k in data[2:8] if k]
        if not keys:
            last_keys.clear()
            continue
        shift = bool(modifier & 0x22)
        for key in keys:
            if key in last_keys:
                continue
            char = KEYPAD_MAP.get(key) or HID_KEYMAP.get(key, "")
            if not char:
                ctx.report(f"帧 {report.frame} 未知键码 0x{key:02x}", "warn")
                continue
            if shift:
                char = SHIFT_MAP.get(char, char.upper() if char.isalpha() else char)
            if not first_frame:
                first_frame = report.frame
            text.append(char)
        last_keys = set(keys)

    result = "".join(text)
    ctx.report("===== 键盘还原结果 =====", "good")
    ctx.report(result, "good")
    ctx.write_output("usb_keyboard.txt", result)

    if sum(1 for ch in result if ch.isprintable() or ch in "\n\t") < 3:
        return
    summary = f"USB 键盘还原文本 {len(result)} 字符"
    ctx.report(f"键盘还原结果已记录为结构化发现: {summary}", "good")
    ctx.add_finding("other", summary, frame=first_frame, level="good",
                    detail=result,
                    extra={"output": "usb_keyboard.txt", "chars": len(result)})
    for flag in _flags_from_text(result):
        ctx.report(f"  发现 flag: {flag}", "good")
        ctx.add_finding("flag", flag, frame=first_frame, level="good",
                        detail="USB HID 键盘按键还原")


def _flags_from_text(text: str) -> list[str]:
    """Flag candidates in a decoded keystroke stream.

    按键流里常混入 vim/终端转义序列：``thekey`` 的 ``ctf`` 与 ``{...}``
    之间夹着 ``ESC vbUA``（vim 可视块命令），直接套正则只能得到
    ``vbUA{...}``。这里先去掉控制字符，再在 ``{`` 前的小窗口里回找已知前缀；
    要求前缀前是边界、或前缀与 ``{`` 之间确实夹了编辑器命令噪声，避免把
    ``notaflag{...}`` 这类普通单词误判成 flag。
    """
    clean = _CONTROL_RE.sub("", str(text or ""))
    found: list[str] = []
    for match in _BRACE_RE.finditer(clean):
        head = clean[:match.start()]
        lowered = head.lower()
        for prefix in _FLAG_PREFIXES:
            index = lowered.rfind(prefix)
            if index < 0:
                continue
            gap = head[index + len(prefix):]
            before = head[:index]
            if len(gap) > _PREFIX_WINDOW:
                continue
            if gap and not all(ch.isalnum() or ch == "_" for ch in gap):
                continue
            boundary = not before or not (before[-1].isalnum() or before[-1] == "_")
            if not gap and not boundary:
                continue
            value = head[index:index + len(prefix)] + "{" + match.group(1) + "}"
            if value not in found:
                found.append(value)
            break
    return found


def mouse(ctx: FeatureContext) -> None:
    reports = _reports(ctx)
    if not reports:
        ctx.report("未找到 USB HID 数据", "warn")
        return
    ctx.report(f"USB 鼠标报告 {len(reports)} 条", "info")
    x = y = 0
    points: list[tuple[int, int, int]] = []
    button_count = 0
    hid_count = 0
    first_frame = ""
    for index, report in enumerate(reports):
        if index % 200 == 0:
            ctx.set_progress(int(index / max(len(reports), 1) * 100))
            ctx.check_cancel()
        # 明确的键盘接口（boot keyboard）不是鼠标移动，跳过。
        if report.protocol_value() == BOOT_KEYBOARD_PROTOCOL:
            continue
        parsed = mouse_delta(report)
        if parsed is None:
            continue
        if mouse_layout(report) == "hid":
            hid_count += 1
        buttons, dx, dy = parsed
        x += dx
        y += dy
        if buttons & 0x01:
            button_count += 1
        if not first_frame:
            first_frame = report.frame
        points.append((x, y, buttons))

    if hid_count:
        ctx.report(f"其中 {hid_count} 条为非 boot HID 报告"
                   "（dx int16@2 / dy int16@4，小端）", "info")
    ctx.report(f"轨迹点 {len(points)} 个，左键 {button_count} 次", "info")

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["x", "y", "buttons"])
    writer.writerows(points)
    ctx.write_output("usb_mouse.csv", buffer.getvalue())

    if not points:
        return
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    ctx.report(f"坐标范围 x={min(xs)}..{max(xs)} y={min(ys)}..{max(ys)}", "info")
    span = (max(xs) - min(xs)) + (max(ys) - min(ys))
    if len(points) < MOUSE_FINDING_MIN_POINTS or span < MOUSE_FINDING_MIN_SPAN:
        return
    summary = (f"USB 鼠标轨迹 {len(points)} 点，左键 {button_count} 次"
               f"（x {min(xs)}..{max(xs)}，y {min(ys)}..{max(ys)}）")
    ctx.report(f"轨迹已记录为结构化发现: {summary}", "good")
    ctx.add_finding("other", summary, frame=first_frame, level="info",
                    detail=(f"坐标跨度 {span}；轨迹点 {len(points)} 个；"
                            f"左键 {button_count} 次；"
                            f"非 boot HID 报告 {hid_count} 条；"
                            "轨迹已保存: usb_mouse.csv"),
                    extra={"output": "usb_mouse.csv", "points": len(points),
                           "buttons": button_count, "span": span,
                           "hid_reports": hid_count})
