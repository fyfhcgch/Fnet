#!/usr/bin/env python3
"""Reproducible performance benchmark for Fnet.

The script generates synthetic Ethernet captures (10 MB / 100 MB / 1 GB by
default) with the standard library only, then runs each selected feature in an
isolated worker process and records:

* wall clock time for the whole feature handler;
* peak RSS of the worker (``resource.getrusage(RUSAGE_SELF).ru_maxrss``);
* peak RSS of the external tools it spawned (``RUSAGE_CHILDREN``);
* the number of structured findings produced.

Results are written to ``docs/PERFORMANCE.md`` (Markdown) and to a JSON file
next to it, so the numbers can be compared across releases.

Examples::

    python3 scripts/bench.py --sizes 10 --features default
    python3 scripts/bench.py --sizes 10,100,1000 --features all --keep
    python3 scripts/bench.py --sizes 100 --features checkBox_10,http.extract

Notes
-----
* Keep ``tshark_cache`` disabled (the default here): a warm cache would hide
  the real parsing cost.
* The 1 GB tier is intentionally opt-in by size; it needs about 1.1 GB of free
  disk plus space for the task output.
* A worker process is started per feature so the peak RSS is attributable and
  one crashing handler cannot invalidate the rest of the run.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import platform
import random
import resource
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
DEFAULT_OUT = ROOT / "docs" / "PERFORMANCE.md"


# ---------------------------------------------------------------------------
# Synthetic capture writer (stdlib only)
# ---------------------------------------------------------------------------
def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _ipv4(src: bytes, dst: bytes, payload: bytes, proto: int,
          ident: int) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident,
                         0x4000, 64, proto, 0, src, dst)
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return header + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns_query(name: str, ident: int) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode("ascii")
                      for part in name.split(".") if part)
    question = labels + b"\x00" + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", ident & 0xFFFF, 0x0100, 1, 0, 0, 0) + question


def _ethernet(payload: bytes, index: int) -> bytes:
    src = bytes([0x02, 0x00, 0x00, 0x00, (index >> 8) & 0xFF, index & 0xFF])
    dst = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
    return dst + src + struct.pack("!H", 0x0800) + payload


def write_capture(path: Path, size_bytes: int, packet_size: int = 1200,
                  seed: int = 1337) -> int:
    """Write a pcap with roughly ``size_bytes`` bytes; return the exact size."""
    rng = random.Random(seed)
    # A deterministic "random" body keeps the file compressible enough to move
    # around while still exercising binary payload scanning.
    body = bytes(rng.randrange(256) for _ in range(packet_size))
    marker = b"\nGET /bench?q=flag%7Bbench%7D HTTP/1.1\r\nHost: bench.local\r\n\r\n"
    dns_names = ["ZmxhZ3tiZW5jaF9kbnN9.example.com", "bench.local",
                 "notice.local"]

    written = 0
    index = 0
    started = time.time()
    with path.open("wb") as fh:
        # pcap global header (little endian, microsecond timestamps).
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        written += 24
        while written < size_bytes:
            index += 1
            kind = index % 10
            if kind < 2:
                payload = _udp(53000 + index % 100, 53,
                               _dns_query(dns_names[index % len(dns_names)],
                                          index))
                proto = 17
            elif kind < 8:
                payload = _udp(40000 + index % 100, 40001, body)
                proto = 17
            else:
                payload = _udp(40002, 80, body[:packet_size // 2] + marker)
                proto = 17
            ip = _ipv4(bytes([10, 0, (index >> 8) & 0xFF, index & 0xFF]),
                       bytes([10, 0, 0, 1]), payload, proto, index & 0xFFFF)
            frame = _ethernet(ip, index)
            stamp = int(started) + index // 1000
            usec = (index % 1000) * 1000
            fh.write(struct.pack("<IIII", stamp, usec, len(frame), len(frame)))
            fh.write(frame)
            written += 16 + len(frame)
    return written


# ---------------------------------------------------------------------------
# Worker: run one feature on one capture in a fresh process
# ---------------------------------------------------------------------------
def _rss_mb(value: int) -> float:
    # Linux reports KiB, macOS bytes.
    if sys.platform == "darwin":
        return value / (1024 * 1024)
    return value / 1024


def run_worker(pcap: str, feature: str, cache_root: str) -> int:
    os.environ["FNET_HOME"] = cache_root
    from unittest import mock

    from fnet.app import build
    from fnet.config import Config

    cache = Path(cache_root) / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    with mock.patch("fnet.jobs.CACHE_DIR", cache), \
            mock.patch("fnet.paths.CACHE_DIR", cache):
        config = Config(Path(cache_root) / "config.ini")
        config.set("tshark_cache", "0")
        runtime = build(config)
        started = time.perf_counter()
        job = runtime.jobs.submit(pcap, [feature], {})
        deadline = time.time() + 6 * 3600
        while job.status not in ("done", "error", "cancelled"):
            if time.time() > deadline:
                runtime.jobs.cancel(job.id)
                break
            time.sleep(0.1)
        elapsed = time.perf_counter() - started
        usage = resource.getrusage(resource.RUSAGE_SELF)
        children = resource.getrusage(resource.RUSAGE_CHILDREN)
        payload = {
            "feature": feature,
            "status": job.status,
            "error": job.error or "",
            "seconds": round(elapsed, 3),
            "rss_mb": round(_rss_mb(usage.ru_maxrss), 1),
            "children_rss_mb": round(_rss_mb(children.ru_maxrss), 1),
            "findings": len(job.findings),
        }
    print("BENCH_RESULT " + json.dumps(payload), flush=True)
    return 0 if job.status == "done" else 1


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
def _environment() -> dict[str, str]:
    from fnet import __version__
    from fnet.tools.runner import find_tool, tool_version

    tshark = find_tool("tshark", "")
    return {
        "fnet": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cpu_count": str(os.cpu_count() or 1),
        "tshark": tool_version(tshark) if tshark else "not found",
        "generated": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def _feature_selection(spec: str) -> list[str]:
    from fnet.features.registry import FEATURES

    token = (spec or "default").strip().lower()
    if token == "all":
        return [feature.checkbox for feature in FEATURES]
    if token in ("default", "defaults", ""):
        return [feature.checkbox for feature in FEATURES if feature.default]
    selected = []
    for item in spec.split(","):
        item = item.strip()
        if item and item not in selected:
            selected.append(item)
    return selected


def _size_label(size_bytes: int) -> str:
    value = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def _fmt_seconds(value) -> str:
    try:
        value = float(value)
    except (TypeError, ValueError):
        return "—"
    if value < 1:
        return f"{value * 1000:.0f} ms"
    if value < 60:
        return f"{value:.2f} s"
    return f"{value / 60:.1f} min"


def render_markdown(env: dict[str, str], results: list[dict],
                    sizes: list[tuple[int, int]], command: str) -> str:
    lines = [
        "# 性能基准",
        "",
        "本文件由 `scripts/bench.py` 生成，请勿手工编辑。每次发布前重新运行：",
        "",
        "```bash",
        command,
        "```",
        "",
        "## 运行环境",
        "",
        "| 项目 | 值 |",
        "| --- | --- |",
    ]
    for key in ("fnet", "python", "platform", "cpu_count", "tshark", "generated"):
        lines.append(f"| {key} | {env.get(key, '')} |")
    lines += [
        "",
        "## 方法",
        "",
        "- 抓包由脚本用标准库直接写出 pcap（1200 字节 UDP 包，含 DNS、明文与二进制载荷），"
        "不依赖 scapy。",
        "- 每个功能在独立子进程中运行，只提交该功能，`tshark_cache=0`，"
        "因此耗时包含 tshark 解析成本。",
        "- 峰值 RSS 取 `resource.getrusage(RUSAGE_SELF).ru_maxrss`；"
        "`RUSAGE_CHILDREN` 单独列出，表示 tshark 等外部工具的最大 RSS。",
        "- 计时包含任务创建、报告与结构化结果落盘，单位为秒。"
        "同一台机器上重复运行会有 ±10% 波动。",
        "",
        "## 结果",
        "",
    ]
    if not results:
        lines.append("（没有结果）")
        return "\n".join(lines) + "\n"
    by_size: dict[int, list[dict]] = {}
    for item in results:
        by_size.setdefault(item["size"], []).append(item)
    for size_bytes, actual in sizes:
        items = by_size.get(size_bytes, [])
        lines += [
            f"### {_size_label(size_bytes)}（实际 {actual:,} 字节）",
            "",
            "| 功能 | 状态 | 耗时 | 峰值 RSS | tshark 峰值 RSS | 结构化结果 |",
            "| --- | --- | ---: | ---: | ---: | ---: |",
        ]
        for item in items:
            status = item.get("status") or "error"
            lines.append(
                f"| `{item['feature']}` | {status} | "
                f"{_fmt_seconds(item.get('seconds'))} | "
                f"{item.get('rss_mb', 0):.1f} MB | "
                f"{item.get('children_rss_mb', 0):.1f} MB | "
                f"{item.get('findings', 0)} |")
        total = sum(float(item.get("seconds") or 0) for item in items)
        lines.append(f"| **合计** | | **{_fmt_seconds(total)}** | | | |")
        lines.append("")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fnet performance benchmark")
    parser.add_argument("--sizes", default="10,100,1000",
                        help="逗号分隔的 MB 档位（默认 10,100,1000）")
    parser.add_argument("--features", default="default",
                        help="default、all 或逗号分隔的 checkbox/handler")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help="Markdown 输出路径")
    parser.add_argument("--keep", action="store_true", help="保留生成的抓包")
    parser.add_argument("--repeat", type=int, default=1,
                        help="每个功能重复次数，取最小耗时（默认 1）")
    parser.add_argument("--worker", nargs=3, metavar=("PCAP", "FEATURE", "HOME"),
                        help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.worker:
        return run_worker(*args.worker)

    sizes: list[int] = []
    for token in str(args.sizes).split(","):
        token = token.strip()
        if not token:
            continue
        try:
            value = int(float(token))
        except ValueError:
            parser.error(f"无法解析档位: {token}")
        if value > 0:
            sizes.append(value)
    if not sizes:
        parser.error("至少需要一个档位")
    features = _feature_selection(args.features)
    if not features:
        parser.error("没有选择任何功能")

    workdir = Path(tempfile.mkdtemp(prefix="fnet-bench-"))
    os.environ.setdefault("FNET_HOME", str(workdir / "home"))
    env = _environment()
    command = "python3 scripts/bench.py --sizes " + args.sizes \
        + " --features " + args.features
    results: list[dict] = []
    actual_sizes: list[tuple[int, int]] = []
    try:
        for mb in sizes:
            target = mb * 1024 * 1024
            capture = workdir / f"bench-{mb}mb.pcap"
            print(f"[bench] 生成 {mb} MB 抓包: {capture}", flush=True)
            actual = write_capture(capture, target)
            actual_sizes.append((target, actual))
            print(f"[bench] 实际 {actual:,} 字节，功能 {len(features)} 个",
                  flush=True)
            for feature in features:
                best = None
                for attempt in range(max(1, args.repeat)):
                    proc = subprocess.run(
                        [sys.executable, str(Path(__file__).resolve()),
                         "--worker", str(capture), feature,
                         str(workdir / "home")],
                        capture_output=True, text=True)
                    payload = None
                    for line in proc.stdout.splitlines():
                        if line.startswith("BENCH_RESULT "):
                            payload = json.loads(line[len("BENCH_RESULT "):])
                    if payload is None:
                        payload = {
                            "feature": feature, "status": "error",
                            "seconds": 0, "rss_mb": 0, "children_rss_mb": 0,
                            "findings": 0,
                            "error": (proc.stderr or proc.stdout)[-400:],
                        }
                    if best is None or payload.get("seconds", 0) < best.get("seconds", 0):
                        best = payload
                    print(f"[bench] {mb:>4} MB {feature:<28s} "
                          f"{best.get('status'):<9s} "
                          f"{_fmt_seconds(best.get('seconds')):>8s} "
                          f"RSS {best.get('rss_mb', 0):.0f} MB", flush=True)
                item = dict(best)
                item["size"] = mb
                item["size_bytes"] = actual
                results.append(item)
            if not args.keep:
                capture.unlink(missing_ok=True)
                shutil.rmtree(workdir / "home", ignore_errors=True)
    finally:
        if not args.keep:
            shutil.rmtree(workdir, ignore_errors=True)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown(env, results, actual_sizes, command),
                   encoding="utf-8")
    out.with_suffix(".json").write_text(
        json.dumps({"environment": env, "command": command,
                    "results": results}, ensure_ascii=False, indent=2),
        encoding="utf-8")
    print(f"[bench] 结果已写入 {out} 与 {out.with_suffix('.json')}", flush=True)
    failures = [item for item in results if item.get("status") != "done"]
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
