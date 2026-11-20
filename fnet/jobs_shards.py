"""Frame-range sharding helpers for stateless (``shardable``) features.

Split out of :mod:`fnet.jobs` so the JobManager facade stays readable; the
behavior is unchanged and the module deliberately holds no job-lifecycle
state — everything works on plain values and the :class:`~fnet.jobs.Job`
instance passed in.
"""
from __future__ import annotations

from pathlib import Path


def split_ranges(total: int, shards: int) -> list[tuple[int, int]]:
    """Split ``1..total`` into ``shards`` contiguous 1-based frame ranges."""
    total = max(0, int(total))
    shards = max(1, int(shards))
    if total <= 0:
        return []
    shards = min(shards, total)
    size, extra = divmod(total, shards)
    ranges: list[tuple[int, int]] = []
    start = 1
    for index in range(shards):
        length = size + (1 if index < extra else 0)
        if length <= 0:
            continue
        ranges.append((start, start + length - 1))
        start += length
    return ranges


def frame_count(pcap: str, tshark) -> int:
    """Total frame count using capinfos when available, tshark otherwise."""
    from fnet.tools.runner import count_frames

    return count_frames(pcap, tshark.path if tshark is not None else "")


def clip_shard(job, tshark, start: int, end: int,
               shard_index: int, cancel=None) -> Path | None:
    """Write frames ``start..end`` to a temporary pcapng for one shard.

    走 :func:`fnet.tools.runner.run` 而不是裸 ``subprocess.run``，这样切片
    与其它 tshark 调用共享超时/重试语义，并且能被用户的"取消"打断。
    """
    if tshark is None:
        return None
    from fnet.tools.runner import run

    target = job.output_dir / "shards" / f"shard-{shard_index}-{start}-{end}.pcapng"
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    code, _out = run(
        [tshark.path, "-r", job.pcap, "-Y",
         f"frame >= {start} && frame <= {end}", "-w", str(target)],
        timeout=getattr(tshark, "timeout", 3600), cancel=cancel, echo=False)
    if code != 0 or not target.is_file():
        return None
    return target
