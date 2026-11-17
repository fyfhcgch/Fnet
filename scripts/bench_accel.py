#!/usr/bin/env python3
"""加速层跑分：对比现状纯 Python 基线与 accel 各后端在两个热点的吞吐。

生成合成数据、只测计算内核本身（不跑 tshark），输出 Markdown 表格，可直接
粘贴进 docs/PERFORMANCE.md 的加速章节。加速栈缺失时自动跳过对应行，纯
Python 回退分支在本机必然可跑。

用法::

    python3 scripts/bench_accel.py                 # 默认规模
    python3 scripts/bench_accel.py --scan-mb 16 --gcm-kb 512 --rounds 3

接入的热点（见 fnet/utils/accel.py）：

a) ``printable_ratio``：关键字/flag 扫描（text_scan / flag_deep）解码视图
   的逐字节可打印统计——现状基线是纯 Python ``sum()`` 循环；
b) AES-GCM GHASH（GF(2^128) 乘法链）：QUIC Initial 解密的计算核心——现状
   基线是 ``crypto._ghash`` 的 128 步/块逐位乘法。
"""
from __future__ import annotations

import argparse
import multiprocessing
import os
import platform
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fnet.utils import accel                        # noqa: E402
from fnet.utils import crypto                       # noqa: E402


def _baseline_printable_ratio(data: bytes) -> float:
    """现状基线：照抄 fnet/utils/pcap.printable_ratio 委托前的实现。"""
    if not data:
        return 0.0
    good = sum(32 <= b < 127 or b in (9, 10, 13) for b in data)
    return good / len(data)


def _best(fn, *args, rounds: int) -> float:
    """取 rounds 次的最短耗时（秒），降低调度噪声。"""
    times = []
    for _ in range(rounds):
        start = time.perf_counter()
        fn(*args)
        times.append(time.perf_counter() - start)
    return min(times)


def _throughput(size: int, seconds: float) -> str:
    if seconds <= 0:
        return "-"
    return f"{size / seconds / 1024 / 1024:,.1f}"


def bench_printable_ratio(total_bytes: int, chunk: int, rounds: int) -> list[dict]:
    """热点 a)：对 total_bytes 的合成载荷按 chunk 分块统计可打印占比。"""
    rng = random.Random(2026)
    # 混合载荷：70% 可打印文本 + 30% 二进制，贴近真实抓包解码视图。
    text = bytes(rng.choice(b"abcdefghijklmnopqrstuvwxyz0123456789 {}\t\n")
                 for _ in range(chunk))
    data = bytearray()
    while len(data) < total_bytes:
        data += text if rng.random() < 0.7 else rng.randbytes(chunk)
    payload = bytes(data[:total_bytes])

    chunks = [payload[i:i + chunk] for i in range(0, len(payload), chunk)]

    def run(fn):
        for piece in chunks:
            fn(piece)

    def verified(fn):
        """先逐块对照现状基线确认结果一致，再返回原函数用于计时。"""
        for piece in chunks:
            got = fn(piece)
            expect = _baseline_printable_ratio(piece)
            assert got == expect, f"结果不一致：{got} != {expect}"
        return fn

    rows = []
    rows.append({"name": "现状基线（纯 Python sum 循环）",
                 "seconds": _best(run, _baseline_printable_ratio,
                                  rounds=rounds), "ok": True})

    rows.append({"name": "accel CPU（translate 快速路径）",
                 "seconds": _best(run, verified(accel._printable_ratio_fast),
                                  rounds=rounds), "ok": True})
    try:
        import numba                                   # noqa: F401
        rows.append({"name": "accel CPU-JIT（numba njit）",
                     "seconds": _best(run, verified(accel._printable_ratio_jit),
                                      rounds=rounds), "ok": True})
    except ImportError:
        rows.append({"name": "accel CPU-JIT（numba njit）",
                     "seconds": None, "ok": False})
    if accel.detect().backend == "cuda":
        try:
            rows.append({"name": "accel CUDA（cupy/numba.cuda）",
                         "seconds": _best(run, verified(accel._printable_ratio_cuda),
                                          rounds=rounds), "ok": True})
        except Exception as exc:                       # noqa: BLE001
            rows.append({"name": "accel CUDA（cupy/numba.cuda）",
                         "seconds": None, "ok": False,
                         "note": str(exc)})
    else:
        rows.append({"name": "accel CUDA（cupy/numba.cuda）",
                     "seconds": None, "ok": False, "note": "无可用 GPU"})
    return rows


def bench_gcm(size: int, rounds: int) -> list[dict]:
    """热点 b)：AES-GCM 解密（GHASH 主导）在 size 字节密文上的吞吐。"""
    rng = random.Random(9001)
    key = rng.randbytes(16)
    iv = rng.randbytes(12)
    aad = rng.randbytes(16)
    msg = rng.randbytes(size)
    enc = crypto.aes_gcm_encrypt(msg, key, iv, aad)
    accel.reset()

    rows = []
    # 现状基线：crypto.aes_gcm_decrypt 直调（加速关闭时 accel 即此路径）。
    rows.append({"name": "现状基线（crypto.aes_gcm_decrypt）",
                 "seconds": _best(crypto.aes_gcm_decrypt, enc, key, iv, aad,
                                  rounds=rounds), "ok": True})
    # 仅 GHASH：乘法链本身（加速能吃到的部分）。
    h = int.from_bytes(crypto.aes_encrypt_block(b"\x00" * 16, key), "big")
    rows.append({"name": "  ├ 仅 GHASH（现状逐位乘法）",
                 "seconds": _best(crypto._ghash, h, aad, msg,
                                  rounds=rounds), "ok": True})
    rows.append({"name": "  ├ 仅 GHASH（CPU 表驱动）",
                 "seconds": _best(accel._ghash_table, h, aad, msg,
                                  rounds=rounds), "ok": True})
    try:
        import numba                                   # noqa: F401
        rows.append({"name": "  ├ 仅 GHASH（CPU-JIT njit）",
                     "seconds": _best(accel._ghash_jit, h, aad, msg,
                                      rounds=rounds), "ok": True})
    except ImportError:
        rows.append({"name": "  ├ 仅 GHASH（CPU-JIT njit）",
                     "seconds": None, "ok": False})
    if accel.detect().backend == "cuda":
        try:
            got = accel._ghash_cuda(h, aad, msg)
            assert got == crypto._ghash(h, aad, msg), "GPU GHASH 结果不一致"
            rows.append({"name": "  ├ 仅 GHASH（CUDA 并行）",
                         "seconds": _best(accel._ghash_cuda, h, aad, msg,
                                          rounds=rounds), "ok": True})
        except Exception as exc:                       # noqa: BLE001
            rows.append({"name": "  ├ 仅 GHASH（CUDA 并行）",
                         "seconds": None, "ok": False, "note": str(exc)})
    else:
        rows.append({"name": "  ├ 仅 GHASH（CUDA 并行）",
                     "seconds": None, "ok": False, "note": "无可用 GPU"})
    # 完整解密：accel 自动分派（应不低于基线）。
    rows.append({"name": "accel 完整解密（自动后端）",
                 "seconds": _best(accel.aes_gcm_decrypt, enc, key, iv, aad,
                                  rounds=rounds), "ok": True})
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scan-mb", type=float, default=16.0,
                        help="关键字扫描热点测的总数据量（MiB，默认 16）")
    parser.add_argument("--scan-chunk", type=int, default=64 * 1024,
                        help="关键字扫描的分块大小（字节，默认 64KiB）")
    parser.add_argument("--gcm-kb", type=int, default=1024,
                        help="GCM 热点测的密文大小（KiB，默认 1024）")
    parser.add_argument("--rounds", type=int, default=3,
                        help="每项计时轮数（取最短，默认 3）")
    args = parser.parse_args()

    status = accel.detect(refresh=True)
    print("## 加速层基准（scripts/bench_accel.py）\n")
    print("| 项目 | 值 |")
    print("| --- | --- |")
    import fnet
    print(f"| fnet | {getattr(fnet, '__version__', '?')} |")
    print(f"| python | {platform.python_version()} |")
    print(f"| platform | {platform.platform()} |")
    print(f"| cpu_count | {multiprocessing.cpu_count()} |")
    print(f"| 后端 | {status.backend}（{status.provider or '纯 Python'}，"
          f"{status.device}） |")
    print(f"| 探测 | {status.detail} |")
    print("")

    scan_bytes = int(args.scan_mb * 1024 * 1024)
    print(f"### 热点 a）：printable_ratio（关键字扫描编码变换，"
          f"{args.scan_mb:g} MiB，{args.scan_chunk // 1024} KiB 分块）\n")
    print("| 实现 | 耗时 | 吞吐 |")
    print("| --- | ---: | ---: |")
    rows = bench_printable_ratio(scan_bytes, args.scan_chunk, args.rounds)
    base = rows[0]["seconds"]
    for row in rows:
        if row["seconds"] is None:
            note = f"（{row.get('note', '不可用')}）"
            print(f"| {row['name']} | - | - {note} |")
            continue
        speedup = f"{base / row['seconds']:.2f}x" if row is not rows[0] else "-"
        print(f"| {row['name']} | {row['seconds'] * 1000:,.0f} ms "
              f"| {_throughput(scan_bytes, row['seconds'])} MiB/s（{speedup}） |")
    print("")

    size = args.gcm_kb * 1024
    print(f"### 热点 b）：AES-GCM 解密 / GHASH（{args.gcm_kb} KiB 密文）\n")
    print("| 实现 | 耗时 | 吞吐 |")
    print("| --- | ---: | ---: |")
    rows = bench_gcm(size, args.rounds)
    base = rows[0]["seconds"]
    for row in rows:
        if row["seconds"] is None:
            note = f"（{row.get('note', '不可用')}）"
            print(f"| {row['name']} | - | - {note} |")
            continue
        speedup = f"{base / row['seconds']:.2f}x" if row is not rows[0] else "-"
        print(f"| {row['name']} | {row['seconds'] * 1000:,.0f} ms "
              f"| {_throughput(size, row['seconds'])} MiB/s（{speedup}） |")
    print("")
    print("> 说明：GPU 分支仅作参考——单 kernel 内 H^1..H^n 幂预计算是串行"
          "瓶颈，收益取决于密文规模与 PCIe 带宽；keystream（AES-CTR）仍在 "
          "CPU，完整解密的加速比低于仅 GHASH 行。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
