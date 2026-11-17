"""Shared helpers for the feature handlers."""
from __future__ import annotations

import re
from typing import Iterable

from fnet.features.registry import FeatureContext
from fnet.utils.pcap import hex_to_bytes, payload_text, printable_ratio

MAX_LOG_LINES = 1200


def tshark_rows(ctx: FeatureContext, fields: list[str], display_filter: str = "",
                limit: int = 5000, extra: list[str] | None = None) -> list[list[str]]:
    if ctx.tshark is None:
        ctx.report("该功能需要 tshark，请先安装 Wireshark/tshark", "error")
        return []
    ctx.check_cancel()
    rows = ctx.tshark.fields(ctx.pcap, fields, display_filter,
                             extra=extra, cancel=ctx.cancel)
    ctx.check_cancel()
    return rows[:limit]


def table(ctx: FeatureContext, title: str, fields: list[str],
          rows: Iterable[list[str]], limit: int = 200,
          cell_limit: int = 160) -> None:
    rows = list(rows)
    if not rows:
        ctx.report(f"{title}: 没有匹配的流量", "warn")
        return
    ctx.report(f"===== {title} ({len(rows)} 条) =====", "good")
    ctx.report(" | ".join(fields), "debug")
    for index, row in enumerate(rows[:limit]):
        row = list(row) + [""] * (len(fields) - len(row))
        cells = []
        for value in row[:len(fields)]:
            value = clean_cell(value, cell_limit)
            cells.append(value)
        ctx.report(" | ".join(cells), "info")
        if index and index % 100 == 0:
            ctx.check_cancel()
    if len(rows) > limit:
        ctx.report(f"仅显示前 {limit} 条（共 {len(rows)} 条）", "warn")


def clean_cell(value: str, limit: int = 160) -> str:
    text = (value or "").replace("\x00", "").replace("\r", " ").replace("\n", " ")
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def payload_lines(ctx: FeatureContext, title: str, display_filter: str,
                  payload_fields: list[str], max_lines: int = MAX_LOG_LINES,
                  min_printable: float = 0.55) -> None:
    rows = tshark_rows(ctx, ["frame.number"] + payload_fields, display_filter)
    if not rows:
        ctx.report(f"{title}: 没有匹配的流量", "warn")
        return
    ctx.report(f"===== {title} ({len(rows)} 条) =====", "good")
    count = 0
    for row in rows:
        row += [""] * (len(payload_fields) + 1 - len(row))
        frame = row[0]
        for raw in row[1:]:
            data = hex_to_bytes(raw)
            if not data or printable_ratio(data) < min_printable:
                continue
            text = payload_text(data).replace("\r", "")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                ctx.report(f"[{frame}] {line}", "info")
                count += 1
                if count >= max_lines:
                    ctx.report("输出行数达到上限，停止显示", "warn")
                    return
        ctx.check_cancel()


def decode_blob(raw: str) -> str:
    data = hex_to_bytes(raw)
    if not data:
        return ""
    return payload_text(data)


def csv_rows(ctx: FeatureContext, fields: list[str],
             display_filter: str = "") -> list[dict[str, str]]:
    return [dict(zip(fields, row + [""] * (len(fields) - len(row))))
            for row in tshark_rows(ctx, fields, display_filter)]


def normalize_hex(value: str) -> str:
    return re.sub(r"(?i)[^0-9a-f]", "", value or "")
