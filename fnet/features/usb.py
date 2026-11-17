"""USB HID keyboard and mouse reconstruction."""
from __future__ import annotations

import csv

from fnet.features.registry import FeatureContext
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


def _reports(ctx: FeatureContext) -> list[tuple[str, bytes]]:
    if ctx.tshark is None:
        return []
    rows = ctx.tshark.fields(
        ctx.pcap, ["frame.number", "usb.capdata", "usbhid.data"],
        "usb.capdata or usbhid.data", cancel=ctx.cancel,
    )
    out = []
    for row in rows:
        row += [""] * (3 - len(row))
        frame = row[0]
        raw = hex_to_bytes(row[1] or row[2])
        if raw:
            out.append((frame, raw))
    return out


def keyboard(ctx: FeatureContext) -> None:
    reports = _reports(ctx)
    if not reports:
        ctx.report("未找到 USB HID 数据", "warn")
        return
    ctx.report(f"USB 键盘报告 {len(reports)} 条", "info")
    text: list[str] = []
    last_keys: set[int] = set()
    for index, (frame, data) in enumerate(reports):
        if index % 200 == 0:
            ctx.set_progress(int(index / max(len(reports), 1) * 100))
            ctx.check_cancel()
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
                ctx.report(f"帧 {frame} 未知键码 0x{key:02x}", "warn")
                continue
            if shift:
                char = SHIFT_MAP.get(char, char.upper() if char.isalpha() else char)
            text.append(char)
        last_keys = set(keys)

    result = "".join(text)
    ctx.report("===== 键盘还原结果 =====", "good")
    ctx.report(result, "good")
    ctx.write_output("usb_keyboard.txt", result)


def mouse(ctx: FeatureContext) -> None:
    reports = _reports(ctx)
    if not reports:
        ctx.report("未找到 USB HID 数据", "warn")
        return
    ctx.report(f"USB 鼠标报告 {len(reports)} 条", "info")
    x = y = 0
    points: list[tuple[int, int, int]] = []
    button_count = 0
    for index, (_frame, data) in enumerate(reports):
        if index % 200 == 0:
            ctx.set_progress(int(index / max(len(reports), 1) * 100))
            ctx.check_cancel()
        if len(data) < 3:
            continue
        # 4-byte boot mouse report: [buttons, dx, dy, wheel]
        buttons, dx, dy = data[0], data[1], data[2]
        if dx > 127:
            dx -= 256
        if dy > 127:
            dy -= 256
        x += dx
        y += dy
        if buttons & 0x01:
            button_count += 1
        points.append((x, y, buttons))

    ctx.report(f"轨迹点 {len(points)} 个，左键 {button_count} 次", "info")
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["x", "y", "buttons"])
    writer.writerows(points)
    ctx.write_output("usb_mouse.csv", buffer.getvalue())
    if points:
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        ctx.report(f"坐标范围 x={min(xs)}..{max(xs)} y={min(ys)}..{max(ys)}", "info")
