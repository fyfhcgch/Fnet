"""Miscellaneous CTF helpers: EV3, USBMS/SCSI, IP ID covert channel."""
from __future__ import annotations

import base64
import json
import re
from collections import Counter, defaultdict

from fnet.features.common import clean_cell, table, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.tools.runner import run
from fnet.utils.codec import decode_chain, find_flags
from fnet.utils.pcap import (file_magic_bytes, hex_to_bytes, payload_text,
                             printable_ratio)

#: tshark columns used to rebuild USB Mass Storage transfers.  The data phase
#: of a Bulk-Only-Transport transfer never shows up in ``scsi.data``: tshark
#: keeps it as the raw URB payload, so the CBW/CSW boundaries plus the bulk
#: frame numbers are what identify the bytes that belong to each transfer.
USBMS_FIELDS = ["frame.number", "usb.data_len",
                "usb.endpoint_address.direction",
                "usbms.dCBWSignature", "usbms.dCSWSignature",
                "usbms.dCBWDataTransferLength", "usbms.dCBWFlags"]

CBW_SIGNATURE = 0x43425355
CSW_SIGNATURE = 0x53425355

#: Signatures worth naming when they show up inside a recovered data stream.
EMBEDDED_SIGNATURES = (
    ("ZIP", b"PK\x03\x04"),
    ("RAR", b"Rar!\x1a\x07"),
    ("PDF", b"%PDF"),
    ("PNG", b"\x89PNG\r\n\x1a\n"),
    ("EXFAT", b"EXFAT"),
    ("FAT", b"FAT"),
    ("ELF", b"\x7fELF"),
    ("PE/MZ", b"MZ"),
    ("GZIP", b"\x1f\x8b"),
)

#: IP ID channels evaluated for every flow: low byte, high byte, full 16 bit.
IPID_CHANNELS = ("low", "high", "full")
IPID_CHANNEL_NAMES = {"low": "低字节", "high": "高字节", "full": "16 位全值"}
BASE64_ALPHABET = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   "abcdefghijklmnopqrstuvwxyz0123456789+/")


def ev3(ctx: FeatureContext) -> None:
    fields = ["frame.number", "bthci_acl.data", "btatt.value",
              "btl2cap.payload", "data.data"]
    rows = tshark_rows(ctx, fields, "bthci_acl or btatt or btl2cap",
                       limit=50_000)
    if not rows:
        ctx.report("没有发现蓝牙/EV3 数据", "warn")
        return
    ctx.report(f"===== EV3 / 蓝牙数据 ({len(rows)} 条) =====", "good")
    texts: list[str] = []
    for index, row in enumerate(rows):
        if index % 200 == 0:
            ctx.check_cancel()
        row += [""] * (len(fields) - len(row))
        for raw in row[1:]:
            data = hex_to_bytes(raw)
            if not data:
                continue
            for match in re.finditer(rb"[\x20-\x7e]{3,}", data):
                text = match.group().decode("latin-1")
                if text not in texts:
                    texts.append(text)
    if texts:
        ctx.report("可打印字符串:", "good")
        for text in texts[:200]:
            ctx.report("  " + clean_cell(text, 240), "info")
        ctx.write_output("ev3_strings.txt", "\n".join(texts))
    else:
        ctx.report("未发现可打印字符串，已输出原始载荷摘要", "warn")
        table(ctx, "EV3 原始载荷", fields, rows, limit=100)


# ---------------------------------------------------------------------------
# USB Mass Storage (USBMS / SCSI) data-phase reassembly
# ---------------------------------------------------------------------------
def _hex_int(value) -> int:
    text = str(value if value is not None else "").strip()
    if not text:
        return 0
    try:
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return 0


def usbms_transfers(rows) -> list[dict]:
    """Group ``USBMS_FIELDS`` rows into CBW → data phase → CSW transfers.

    Each returned dict has ``cbw``/``csw`` frame numbers, the expected data
    length from the CBW, the transfer direction and the frame numbers that
    carried the data phase.  Frames outside a CBW/CSW pair are ignored, which
    keeps unrelated bulk traffic out of the reassembly.
    """
    transfers: list[dict] = []
    current: dict | None = None
    for row in rows or []:
        values = list(row or []) + [""] * (len(USBMS_FIELDS) - len(row or []))
        frame = str(values[0] or "").strip()
        if not frame:
            continue
        direction = str(values[2] or "").strip().lower()
        cbw = _hex_int(values[3])
        csw = _hex_int(values[4])
        if cbw == CBW_SIGNATURE:
            if current is not None:
                transfers.append(current)
            flags = _hex_int(values[6])
            if flags:
                in_transfer = bool(flags & 0x80)
            else:
                in_transfer = direction in ("1", "0x01", "in")
            current = {"cbw": frame, "csw": "", "in": in_transfer,
                       "expected": max(0, _hex_int(values[5])),
                       "frames": []}
            continue
        if csw == CSW_SIGNATURE:
            if current is not None:
                current["csw"] = frame
                transfers.append(current)
                current = None
            continue
        if current is not None:
            current["frames"].append(frame)
    if current is not None:
        transfers.append(current)
    return transfers


def usbms_payload(raw_hex: str, data_len: int = 0, header_len: int = 0) -> bytes:
    """Strip the URB/USBPcap header from a raw frame and return its payload."""
    raw = hex_to_bytes(raw_hex)
    if not raw:
        return b""
    length = max(0, int(data_len or 0))
    header = max(0, int(header_len or 0))
    if length and header and header + length <= len(raw):
        return raw[header:header + length]
    if length and length <= len(raw):
        # usbmon (Linux) puts the payload at the end of the frame.
        return raw[-length:]
    if header and header < len(raw):
        return raw[header:]
    return raw


def assemble_usbms(transfers, payloads: dict[str, bytes]) -> list[dict]:
    """Concatenate the data-phase frames of every transfer.

    ``payloads`` maps a frame number to its already extracted payload bytes.
    Data is trimmed to the CBW's ``dCBWDataTransferLength`` so a short read
    does not pull the next transfer's bytes into this one.
    """
    assembled: list[dict] = []
    for transfer in transfers or []:
        chunks = [payloads.get(str(frame), b"")
                  for frame in transfer.get("frames", [])]
        data = b"".join(chunk for chunk in chunks if chunk)
        expected = max(0, int(transfer.get("expected") or 0))
        if expected and len(data) > expected:
            data = data[:expected]
        item = dict(transfer)
        item["data"] = data
        item["missing"] = sum(1 for chunk in chunks if not chunk)
        assembled.append(item)
    return assembled


def _usbms_payload_map(ctx: FeatureContext, frames) -> dict[str, bytes]:
    """Return ``{frame: payload}`` for the bulk frames of the data phases.

    tshark exposes no field for the raw URB payload, so the frames are dumped
    once with ``-T ek -x`` and only the requested frame numbers are kept.  The
    display filter is bounded to the frame range of the USBMS transfers, so a
    capture with unrelated bulk traffic is not fully materialised.
    """
    numbers = sorted(int(frame) for frame in frames
                     if str(frame).strip().isdigit())
    if not numbers or ctx.tshark is None:
        return {}
    path = getattr(ctx.tshark, "path", "")
    if not path:
        return {}
    display = (f"usb.transfer_type == 0x03 && frame.number >= {numbers[0]}"
               f" && frame.number <= {numbers[-1]}")
    code, out = run([path, "-r", str(ctx.pcap), "-Y", display,
                     "-T", "ek", "-x"],
                    timeout=max(30, int(getattr(ctx.tshark, "timeout", 600))),
                    cancel=ctx.cancel, echo=False)
    if code != 0 and not out.strip():
        ctx.report(f"读取 USB 原始载荷失败（tshark 退出码 {code}）", "warn")
        return {}
    wanted = {str(number) for number in numbers}
    payloads: dict[str, bytes] = {}
    for line in out.splitlines():
        if '"layers"' not in line:
            continue
        try:
            packet = json.loads(line)
        except ValueError:
            continue
        layers = packet.get("layers") or {}
        frame = str((layers.get("frame") or {}).get("frame_frame_number") or "")
        if frame not in wanted:
            continue
        usb = layers.get("usb") or {}
        data_len = _hex_int(usb.get("usb_usb_data_len"))
        header_len = _hex_int(usb.get("usb_usb_usbpcap_header_len"))
        payload = usbms_payload(layers.get("frame_raw") or "",
                                data_len, header_len)
        if payload:
            payloads[frame] = payload
    return payloads


def printable_stats(data: bytes) -> tuple[float, float]:
    """Return ``(ASCII printable ratio, high-byte printable ratio)``.

    The second value also counts ``0xA1``–``0xFE``, the lead/trail byte range
    of GBK/Big5 text, so Chinese Windows U-disk images do not look like pure
    noise.  Control bytes stay excluded from both.
    """
    if not data:
        return 0.0, 0.0
    high = sum(1 for byte in data
               if 0x20 <= byte <= 0x7E or 0xA1 <= byte <= 0xFE)
    return printable_ratio(data), high / len(data)


def text_fragments(data: bytes, minimum: int = 8,
                   limit: int = 40) -> list[str]:
    """Printable ASCII runs of at least ``minimum`` bytes, de-duplicated."""
    fragments: list[str] = []
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % max(1, minimum), data):
        text = match.group().decode("latin-1").strip()
        if text and text not in fragments:
            fragments.append(text)
            if len(fragments) >= limit:
                break
    return fragments


def _report_scsi_blob(ctx: FeatureContext, name: str, data: bytes) -> None:
    low, high = printable_stats(data)
    ctx.report(f"{name}: {len(data)} 字节，可打印比例 {low:.0%}，"
               f"高位可打印比例 {high:.0%}", "info")
    magic = file_magic_bytes(data[:16])
    if magic not in ("binary", "text", "unknown"):
        ctx.report(f"{name} 文件类型: {magic}", "good")
    for label, signature in EMBEDDED_SIGNATURES:
        offset = data.find(signature)
        if offset >= 0:
            ctx.report(f"{name} 内嵌 {label} 签名 @ 偏移 {offset}", "good")
    for line in zip_listing(data):
        ctx.report(f"{name} 内嵌 ZIP: {line}", "good")
    for text in text_fragments(data)[:20]:
        ctx.report(f"[{name}] {clean_cell(text, 240)}", "info")


def zip_listing(data: bytes, limit: int = 30) -> list[str]:
    """List the entries of an embedded ZIP archive (``PK\\x03\\x04``).

    Encrypted entries are reported as such instead of failing: a password
    protected archive is itself a useful hint for a CTF disk image.
    """
    import io
    import zipfile

    start = data.find(b"PK\x03\x04")
    if start < 0:
        return []
    end = data.find(b"PK\x05\x06", start)
    blob = data[start:end + 22] if end >= 0 else data[start:]
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
    except (OSError, ValueError, zipfile.BadZipFile):
        return [f"偏移 {start} 处有 ZIP 头但无法解析（数据不完整）"]
    lines: list[str] = []
    for info in archive.infolist()[:limit]:
        state = "（加密）" if info.flag_bits & 0x1 else ""
        lines.append(f"{info.filename} {info.file_size} 字节{state}")
    if len(archive.infolist()) > limit:
        lines.append(f"…共 {len(archive.infolist())} 个条目")
    return lines


def _extract_scsi_field_rows(ctx: FeatureContext, rows) -> int:
    """Legacy path: payload exposed by ``scsi.data`` (iSCSI and dissected
    USBMS reads)."""
    total = 0
    for row in rows:
        ctx.check_cancel()
        row += [""] * (7 - len(row))
        raw = row[6]
        if not raw:
            continue
        data = hex_to_bytes(raw)
        if not data:
            continue
        total += len(data)
        ctx.write_output(f"scsi_{row[0]}.bin", data)
        if printable_ratio(data) > 0.8:
            text = payload_text(data)
            for line in text.splitlines()[:20]:
                if line.strip():
                    ctx.report(f"[{row[0]}] {clean_cell(line, 240)}", "info")
    return total


def looks_interesting(data: bytes) -> bool:
    """True when a data phase is worth its own ``scsi_<cbw>.bin`` artifact."""
    if not data:
        return False
    low, high = printable_stats(data)
    if low >= 0.8 or high >= 0.95:
        return True
    if file_magic_bytes(data[:16]) not in ("binary", "unknown"):
        return True
    if any(signature in data for _label, signature in EMBEDDED_SIGNATURES):
        return True
    # A run of printable bytes only counts as text when it contains real
    # words, so padding/ID tables of punctuation do not produce junk artifacts.
    return bool(re.search(rb"[A-Za-z]{4,}", data))


def _extract_usbms(ctx: FeatureContext, transfers) -> int:
    """Rebuild the data phase of every USBMS transfer and save the bytes."""
    frames = {frame for transfer in transfers for frame in transfer["frames"]}
    payloads = _usbms_payload_map(ctx, frames) if frames else {}
    assembled = assemble_usbms(transfers, payloads)
    in_stream = bytearray()
    out_stream = bytearray()
    total = 0
    saved = 0
    missing = 0
    for item in assembled:
        ctx.check_cancel()
        data = item["data"]
        missing += item["missing"]
        if not data:
            continue
        total += len(data)
        target = in_stream if item["in"] else out_stream
        target.extend(data)
        # Per-transfer artifacts for readable/file-like payloads (SCSI INQUIRY
        # responses, directory entries); the combined streams below always
        # keep every byte.
        if saved < 50 and looks_interesting(data):
            ctx.write_output(f"scsi_{item['cbw']}.bin", data)
            saved += 1
    if total:
        ctx.report(f"USBMS 传输 {len(assembled)} 个（CBW 定位），"
                   f"重组数据 {total} 字节", "good")
        for name, blob in (("scsi_usbms_in.bin", bytes(in_stream)),
                           ("scsi_usbms_out.bin", bytes(out_stream))):
            if not blob:
                continue
            ctx.write_output(name, blob)
            _report_scsi_blob(ctx, name, blob)
        if missing:
            ctx.report(f"有 {missing} 个数据帧未取到原始载荷（抓包截断？）", "warn")
        detail = (f"CBW 定位 {len(assembled)} 个传输，重组 {total} 字节；"
                  f"IN {len(in_stream)} 字节 / OUT {len(out_stream)} 字节")
        ctx.add_finding("file", f"USBMS/SCSI 数据提取 {total} 字节",
                        frame=assembled[0]["cbw"] if assembled else "",
                        detail=detail, level="good",
                        extra={"transfers": len(assembled),
                               "bytes": total,
                               "in_bytes": len(in_stream),
                               "out_bytes": len(out_stream),
                               "artifacts": "scsi_usbms_in.bin, scsi_usbms_out.bin"})
    return total


def scsi(ctx: FeatureContext) -> None:
    fields = ["frame.number", "scsi.lun", "scsi.cdb", "scsi.sbc_lba",
              "scsi.sbc.num_blocks", "scsi.sbc.ctrl", "scsi.data"]
    rows = tshark_rows(ctx, fields, "scsi", limit=50_000)
    bulk_rows = tshark_rows(ctx, USBMS_FIELDS, "usb.transfer_type == 0x03",
                            limit=200_000)
    transfers = usbms_transfers(bulk_rows)
    if rows:
        table(ctx, "SCSI 命令", fields[:-1], [r[:-1] for r in rows], limit=300)
    total = 0
    if rows:
        total += _extract_scsi_field_rows(ctx, rows)
    if transfers:
        total += _extract_usbms(ctx, transfers)
    if not rows and not transfers:
        ctx.report("没有发现 SCSI 流量（需要 USB Mass Storage / iSCSI 抓包）",
                   "warn")
        return
    if transfers and not total:
        ctx.report("已发现 USBMS 命令（CBW/CSW），但未重组出数据阶段："
                   "可能只抓到了命令阶段，或数据帧被截断", "warn")
        ctx.add_finding(
            "protocol", "USBMS 已发现但未提取到数据", level="warn",
            frame=transfers[0]["cbw"],
            detail=f"识别到 {len(transfers)} 个 CBW/CSW 传输，但数据阶段为空；"
                   f"请确认抓包包含 bulk IN/OUT 数据帧",
            extra={"transfers": len(transfers)})
        return
    ctx.report(f"提取 SCSI 数据 {total} 字节", "good")


# ---------------------------------------------------------------------------
# IP ID covert channel
# ---------------------------------------------------------------------------
def ipid_channel_bytes(ids, channel: str) -> bytes:
    """Render one IP ID channel as a byte string."""
    values = [int(value) & 0xFFFF for value in ids]
    if channel == "low":
        return bytes(value & 0xFF for value in values)
    if channel == "high":
        return bytes((value >> 8) & 0xFF for value in values)
    return bytes(byte for value in values
                 for byte in (value >> 8, value & 0xFF))


def ipid_profile(ids) -> dict:
    """Classify an IP ID sequence: constant / sequential / other."""
    values = [int(value) & 0xFFFF for value in ids]
    unique = len(set(values))
    deltas = [(b - a) % 0x10000 for a, b in zip(values, values[1:])]
    counts = Counter(deltas)
    delta, count = counts.most_common(1)[0] if counts else (0, 0)
    steps = max(len(values) - 1, 1)
    return {
        "samples": len(values),
        "unique": unique,
        "delta": delta,
        "delta_count": count,
        "sequential": delta == 1 and count >= max(1, int(steps * 0.8)),
        "constant": unique <= 1,
    }


def ipid_counter_like(data: bytes, threshold: float = 0.75,
                      max_step: int = 32, min_samples: int = 4) -> bool:
    """True when a channel just counts up (a normal IP ID allocator).

    Two shapes are treated as counters, not channels:

    * symbols that mostly move forward by a tiny step (1..32) — a router
      allocating IDs in order, possibly skipping some;
    * long runs of one repeated value — a *stepped* counter, i.e. the low byte
      counting while the high byte only changes occasionally (the classic
      "high byte increments every 256 packets" pattern that made every busy
      capture look like a channel).

    A covert channel writes symbols, so neither shape fits.
    """
    if len(data) < max(3, min_samples):
        return False
    deltas = [(b - a) % 256 for a, b in zip(data, data[1:])]
    # 0 counts as well: a stepped counter repeats the same byte for a while.
    small = sum(1 for delta in deltas if delta <= max_step)
    if small / len(deltas) >= threshold:
        return True
    run = best = 1
    for previous, current in zip(data, data[1:]):
        run = run + 1 if previous == current else 1
        best = max(best, run)
    return best >= max(8, int(len(data) * 0.2))


def ipid_channels(ids, *, min_samples: int = 6, max_unique: int = 64,
                  min_printable: float = 0.8,
                  channels: tuple[str, ...] = IPID_CHANNELS) -> list[dict]:
    """Return the channels that look like a covert channel.

    A channel qualifies when it carries enough samples, has a small value set
    (so it is an alphabet rather than random IDs), is *not* a sequential
    counter, and its bytes are mostly printable.  Sequential streams (normal
    routers, including 16-bit wraparound) and constant streams are excluded.

    Short byte channels must also re-use their symbols: an alphabet channel
    repeats characters, while a handful of unrelated IDs merely happens to be
    printable.  The 16-bit channel is different — one ASCII pair per ID means
    a short text can be entirely distinct — so it is judged by the counter
    shape of its two bytes instead.
    """
    values = [int(value) & 0xFFFF for value in ids]
    profile = ipid_profile(values)
    if (profile["constant"] or profile["sequential"]
            or profile["samples"] < min_samples):
        return []
    low = ipid_channel_bytes(values, "low")
    high = ipid_channel_bytes(values, "high")
    high_constant = len(set(high)) <= 1
    # One counting byte plus one constant byte is a counter, not a 16-bit
    # channel: that is exactly how a stepped IP ID allocator looks.
    full_is_counter = ipid_counter_like(low) or ipid_counter_like(high)
    found: list[dict] = []
    for channel in channels:
        # With a constant high byte the 16-bit channel is just the low byte.
        if channel == "full" and high_constant:
            continue
        data = ipid_channel_bytes(values, channel)
        symbols = values if channel == "full" else list(data)
        unique = len(set(symbols))
        if unique <= 1 or unique > max_unique:
            continue
        if channel == "full":
            if full_is_counter:
                continue
        elif unique > len(symbols) - 2 and len(symbols) < 24:
            continue
        if printable_ratio(data) < min_printable:
            continue
        # A byte channel that only climbs (with occasional skips) is an
        # ordinary counter, not an alphabet channel.
        if channel != "full" and ipid_counter_like(data):
            continue
        found.append({"channel": channel, "data": data, "unique": unique,
                      "samples": profile["samples"], "profile": profile})
    return found


def _b64_bytes(text: str) -> bytes:
    try:
        return base64.b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        return b""


def _readable_text(text: str) -> bool:
    if not text or not text.strip():
        return False
    return printable_ratio(text.encode("utf-8", "replace")) >= 0.85


def _alphabet_candidates(data: bytes) -> list[bytes]:
    """Map the channel's byte values onto the base64 alphabet.

    CTF IP ID channels usually carry 6-bit symbols: either the raw value, the
    value minus an ASCII offset, or an index into the alphabet the author used
    (recovered here from the observed value set).
    """
    candidates: list[bytes] = []
    unique = sorted(set(data))
    if 2 <= len(unique) <= 64:
        index = {value: position for position, value in enumerate(unique)}
        text = "".join(BASE64_ALPHABET[index[byte]] for byte in data)
        candidates.append(_b64_bytes(text))
    for offset in (0, 0x20):
        text = "".join(BASE64_ALPHABET[(byte - offset) % 64] for byte in data)
        candidates.append(_b64_bytes(text))
    return [item for item in candidates if item]


def ipid_decode_candidates(data: bytes, limit: int = 8) -> list[str]:
    """Surface readable decodes (base64/hex/url/custom alphabet) of a channel."""
    text = data.decode("latin-1")
    found: list[str] = []

    def add(value: str) -> None:
        if not value or value in found or not _readable_text(value):
            return
        found.append(value)

    # The channel bytes may already be readable text (16-bit channel carrying
    # two ASCII characters per ID), so it is the first candidate.
    add(text)
    for candidate in decode_chain(text):
        add(candidate)
    for raw in _alphabet_candidates(data):
        decoded = raw.decode("latin-1")
        add(decoded)
        for candidate in decode_chain(decoded):
            add(candidate)
    return found[:limit]


def _report_ipid_channel(ctx: FeatureContext, channel: dict, src: str,
                         dst: str, frame="", scope: str = "") -> None:
    data = channel["data"]
    text = data.decode("latin-1")
    label = IPID_CHANNEL_NAMES.get(channel["channel"], channel["channel"])
    prefix = f"{scope} " if scope else ""
    ctx.report(f"{prefix}IPID 隐蔽信道（{label}）：{channel['samples']} 个样本、"
               f"{channel['unique']} 种取值，取值集合小且非单调", "warn")
    ctx.report("  候选文本: " + clean_cell(text, 240), "warn")
    decoded = ipid_decode_candidates(data)
    for item in decoded[:5]:
        ctx.report("  解码候选: " + clean_cell(item, 240), "warn")
    ctx.write_output(f"ipid_{src}_{dst}.txt", text)
    if decoded:
        ctx.write_output(f"ipid_{src}_{dst}_decoded.txt", "\n".join(decoded))
    detail = (f"通道 {label}，样本 {channel['samples']}，"
              f"取值 {channel['unique']} 种，非单调序列\n候选文本: {text[:200]}")
    if decoded:
        detail += "\n解码候选: " + " | ".join(item[:120] for item in decoded[:5])
    ctx.add_finding("protocol", f"IPID 隐蔽信道 {src}>{dst}（{label}）",
                    frame=frame, detail=detail, level="warn",
                    extra={"channel": channel["channel"],
                           "samples": channel["samples"],
                           "unique": channel["unique"],
                           "candidate": text[:400]})
    flags: list[str] = []
    for item in decoded:
        for value in find_flags(item):
            if value not in flags:
                flags.append(value)
    for value in flags:
        ctx.add_finding("flag", value, frame=frame, level="good",
                        detail=f"来自 IPID {label}通道解码候选")


def ipid(ctx: FeatureContext) -> None:
    fields = ["frame.number", "ip.src", "ip.dst", "ip.id", "ip.len",
              "ip.proto"]
    rows = tshark_rows(ctx, fields, "ip", limit=200_000)
    if not rows:
        ctx.report("没有发现 IP 流量", "warn")
        return
    flows: dict[tuple[str, str], list[tuple[int, int, int]]] = defaultdict(list)
    sequence: list[tuple[int, int]] = []
    for row in rows:
        row += [""] * (6 - len(row))
        try:
            frame = int(row[0])
            ipid = int(row[3], 0)
        except ValueError:
            continue
        flows[(row[1], row[2])].append((frame, ipid, int(row[4] or 0)))
        sequence.append((frame, ipid))

    ctx.report(f"共 {len(flows)} 个 IP 流", "info")
    for (src, dst), packets in sorted(flows.items(), key=lambda kv: -len(kv[1]))[:10]:
        ctx.check_cancel()
        packets.sort()
        ids = [p[1] for p in packets]
        deltas = [b - a for a, b in zip(ids, ids[1:])]
        delta_counts = Counter(deltas)
        ctx.report(f"===== {src} -> {dst} ({len(packets)} 包) =====", "good")
        ctx.report(f"IP ID 范围 {min(ids)}..{max(ids)}，最常见的差值: "
                   + ", ".join(f"{d}({c})" for d, c in delta_counts.most_common(5)),
                   "info")
        if ids and all(value == ids[0] for value in ids):
            ctx.report("IP ID 恒定：可能存在 IP ID 隐蔽信道或空闲扫描", "warn")
        elif deltas and delta_counts.most_common(1)[0][0] == 1:
            ctx.report("IP ID 顺序递增（正常行为）", "debug")
        elif len(delta_counts) > 10:
            ctx.report("IP ID 变化异常，可能存在隐蔽信道", "warn")
        # Low byte as an ASCII covert channel.
        low_bytes = bytes(value & 0xFF for value in ids[:2000])
        printable = sum(32 <= b < 127 for b in low_bytes) / max(len(low_bytes), 1)
        if printable > 0.8:
            text = payload_text(low_bytes)
            ctx.report("低字节呈现可打印特征，提取为文本:", "warn")
            for line in text.splitlines()[:30]:
                if line.strip():
                    ctx.report("  " + clean_cell(line, 240), "warn")
            ctx.write_output(f"ipid_{src}_{dst}.txt", text)
        # Low byte / high byte / 16-bit channels of this flow.
        for channel in ipid_channels(ids):
            _report_ipid_channel(ctx, channel, src, dst,
                                 frame=packets[0][0])

    # A channel can be spread over many short flows (one packet per source),
    # so the capture-wide sequence in frame order is evaluated as well.  The
    # printable requirement is stricter here: mixing normal hosts would
    # otherwise turn every busy capture into a "channel".
    if len(flows) > 1:
        ctx.check_cancel()
        ordered = [value for _frame, value in sorted(sequence)]
        for channel in ipid_channels(ordered, min_printable=0.85,
                                     channels=("low", "full")):
            _report_ipid_channel(ctx, channel, "all", "all",
                                 frame=min(frame for frame, _ in sequence),
                                 scope="全捕获")
