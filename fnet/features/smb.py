"""SMB2/SMB3 protocol analysis: shares, sessions, files and SMB3 transforms.

The handler reassembles every SMB-looking TCP stream and uses
:mod:`fnet.utils.smb` to walk the NetBIOS framing and SMB2 headers:

* ``TREE_CONNECT`` shares (including per-share encryption flags) and named
  pipe accesses;
* ``SESSION_SETUP`` NTLM identities (user/domain/workstation) even on
  non-standard ports;
* negotiated dialects, DFS referrals and SMB3 encryption/compression
  transforms (reported as warnings — the payload cannot be parsed);
* ``CREATE``/``READ``/``WRITE`` reassembly: file contents are rebuilt from
  the byte ranges and written to the job output directory.

Requests and responses of one TCP stream are processed in frame order so
file names learned from ``CREATE`` requests are visible when the matching
``READ``/``WRITE``/``CREATE`` responses arrive in the opposite direction.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from fnet.features.common import clean_cell, protocol_streams
from fnet.features.registry import FeatureContext
from fnet.utils import smb as smb_util
from fnet.utils.smb import DIALECTS, SHAREFLAG_ENCRYPT_DATA

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
MAX_EXPORT_BYTES = 16 * 1024 * 1024


def _safe_name(value: str, fallback: str = "file") -> str:
    text = SAFE_NAME.sub("_", (value or "").replace("\\", "/").split("/")[-1])
    text = text.strip("._")
    return (text or fallback)[:80]


def _frame_number(frame: str) -> int:
    try:
        return int(frame)
    except (TypeError, ValueError):
        return 10 ** 9


def _group_streams(streams):
    """Group the two reassembled directions of every TCP stream together."""
    groups: dict[str, list] = {}
    for stream in streams:
        groups.setdefault(stream.stream, []).append(stream)
    return list(groups.values())


def analyze(ctx: FeatureContext) -> None:
    streams = protocol_streams(ctx, "smb2")
    if not streams:
        ctx.report("没有发现 SMB 流量", "warn")
        return

    shares: dict[int, str] = {}
    share_types: dict[int, str] = {}
    encrypted_shares: set[str] = set()
    users: list[str] = []
    dialects: list[str] = []
    files: dict[tuple, dict] = {}
    pipes: list[str] = []
    dfs_paths: list[str] = []
    warned_encrypt = warned_compress = False

    def _file_entry(key: tuple) -> dict:
        return files.setdefault(
            key, {"name": "", "share": "", "write": {}, "read": {},
                  "frame": "", "pipe": False})

    for index, group in enumerate(_group_streams(streams)):
        ctx.check_cancel()
        ctx.set_progress(int(index / len(_group_streams(streams)) * 90))
        for stream in group:
            if stream.gaps:
                ctx.report(f"SMB 流 {stream.stream} 存在 {stream.gaps} 处序列"
                           "空洞，文件还原可能不完整", "warn")
        combined = []
        for stream in group:
            for message in smb_util.parse_messages(stream.data):
                frame = stream.frame_at(message.offset)
                combined.append((_frame_number(frame), frame,
                                 stream.direction, message))
        combined.sort(key=lambda item: item[0])
        create_names: dict[int, str] = {}
        pending_shares: dict[int, str] = {}
        read_ranges: dict[int, tuple] = {}

        for _sort, frame, direction, message in combined:
            ctx.check_cancel()

            if message.encrypted:
                if not warned_encrypt:
                    warned_encrypt = True
                    ctx.report(f"帧 {frame} 检测到 SMB3 加密流量 "
                               f"(transform, {message.original_size} 字节)，"
                               "载荷无法解析", "warn")
                    ctx.add_finding("protocol", "SMB3 加密流量",
                                    frame=frame, level="warn",
                                    extra={"protocol": "smb2"})
                continue
            if message.compressed:
                if not warned_compress:
                    warned_compress = True
                    ctx.report(f"帧 {frame} 检测到 SMB3 压缩流量 "
                               f"({message.original_size} 字节)", "warn")
                    ctx.add_finding("protocol", "SMB3 压缩流量",
                                    frame=frame, level="warn",
                                    extra={"protocol": "smb2"})
                continue

            command = message.command_name
            if command == "NEGOTIATE":
                if message.is_response and message.dialect:
                    name = DIALECTS.get(message.dialect,
                                        f"0x{message.dialect:#06x}")
                    if name not in dialects:
                        dialects.append(name)
                for dialect in message.dialects:
                    name = DIALECTS.get(dialect, f"0x{dialect:#06x}")
                    if name not in dialects:
                        dialects.append(name)
            elif command == "SESSION_SETUP":
                if message.user or message.domain:
                    account = (f"{message.domain}\\{message.user}"
                               if message.domain else message.user)
                    if account not in users:
                        users.append(account)
                        ctx.report(f"帧 {frame} SMB 会话认证 [{direction}] "
                                   f"账号={account} "
                                   f"包={message.auth_package or '?'}",
                                   "good")
                        ctx.add_finding(
                            "credential", f"SMB 账号 {account}", frame=frame,
                            level="good",
                            detail=f"user={message.user} "
                                   f"domain={message.domain} "
                                   f"workstation={message.workstation}",
                            extra={"protocol": "smb2", "account": account})
            elif command == "TREE_CONNECT":
                if not message.is_response and message.share:
                    pending_shares[message.message_id] = message.share
                    if message.tree_id not in shares:
                        shares[message.tree_id] = message.share
                    ctx.report(f"帧 {frame} 连接共享 {message.share} "
                               f"[{direction}]", "info")
                    ctx.add_finding("protocol",
                                    f"SMB 共享 {message.share}",
                                    frame=frame,
                                    extra={"protocol": "smb2",
                                           "share": message.share})
                elif message.is_response:
                    share = pending_shares.get(message.message_id) or \
                        shares.get(message.tree_id, "")
                    if message.share_type == "pipe":
                        share_types[message.tree_id] = "pipe"
                    if share and message.tree_id not in shares:
                        shares[message.tree_id] = share
                    if message.share_flags & SHAREFLAG_ENCRYPT_DATA and share:
                        encrypted_shares.add(share)
                        ctx.report(f"共享 {share} 要求加密 (SHARE FLAG "
                                   "ENCRYPT_DATA)", "warn")
            elif command == "CREATE":
                if not message.is_response and message.file_name:
                    create_names[message.message_id] = message.file_name
                    share = shares.get(message.tree_id, "")
                    pipe = smb_util.is_pipe(message, shares) or \
                        share_types.get(message.tree_id) == "pipe"
                    if pipe:
                        pipe_name = smb_util.normalize_pipe(message.file_name)
                        label = f"{share}\\{message.file_name}" if share \
                            else message.file_name
                        if label not in pipes:
                            pipes.append(label)
                        ctx.report(f"帧 {frame} 打开命名管道 {label}",
                                   "info")
                        ctx.add_finding("protocol",
                                        f"SMB 命名管道 {pipe_name}",
                                        frame=frame,
                                        extra={"protocol": "smb2",
                                               "pipe": pipe_name})
                    else:
                        entry = _file_entry(smb_util.file_id_key(message))
                        entry["name"] = message.file_name
                        entry["share"] = share
                        entry["pipe"] = False
                        if not entry["frame"]:
                            entry["frame"] = frame
                        ctx.report(f"帧 {frame} 打开文件 "
                                   f"{share or ''}\\{message.file_name}",
                                   "info")
                elif message.is_response and message.file_id:
                    name = create_names.get(message.message_id, "")
                    if name:
                        entry = _file_entry(smb_util.file_id_key(message))
                        entry["name"] = name
                        entry["share"] = shares.get(message.tree_id, "")
                        if not entry["frame"]:
                            entry["frame"] = frame
            elif command == "READ":
                if not message.is_response:
                    read_ranges[message.message_id] = (
                        smb_util.file_id_key(message), message.file_offset)
                elif message.read_data:
                    lookup = read_ranges.get(message.message_id)
                    if lookup:
                        key, offset = lookup
                        entry = _file_entry(key)
                        store = entry["read"]
                        existing = store.get(offset)
                        if not existing or len(existing) < len(
                                message.read_data):
                            store[offset] = message.read_data
            elif command == "WRITE":
                if not message.is_response and message.write_data:
                    entry = _file_entry(smb_util.file_id_key(message))
                    entry.setdefault("write", {})[message.file_offset] = \
                        message.write_data
                    if not entry["frame"]:
                        entry["frame"] = frame
                    share = entry.get("share") or shares.get(
                        message.tree_id, "")
                    ctx.report(f"帧 {frame} 写入文件 "
                               f"{share or ''}\\{entry['name'] or '?'} "
                               f"偏移 {message.file_offset} "
                               f"{len(message.write_data)} 字节", "info")
            elif command == "IOCTL" and message.dfs_paths:
                for path in message.dfs_paths:
                    if path not in dfs_paths:
                        dfs_paths.append(path)
                        ctx.report(f"帧 {frame} DFS 引用 {path}", "info")
                        ctx.add_finding("protocol", f"SMB DFS 引用 {path}",
                                        frame=frame,
                                        extra={"protocol": "smb2",
                                               "path": path})

    if dialects:
        ctx.report("SMB 方言: " + ", ".join(dialects), "info")
    for share in sorted(encrypted_shares):
        ctx.add_finding("protocol", f"SMB 共享要求加密 {share}", level="warn",
                        extra={"protocol": "smb2", "share": share})

    exported: list[str] = []
    number = 0
    for key, entry in files.items():
        ctx.check_cancel()
        write_data = b"".join(data for _offset, data
                              in sorted(entry["write"].items()))
        read_data = b"".join(data for _offset, data
                             in sorted(entry["read"].items()))
        data = write_data or read_data
        if not data or entry["pipe"]:
            continue
        number += 1
        if len(data) > MAX_EXPORT_BYTES:
            ctx.report(f"文件 {entry['name']} 超过导出上限，仅保留前 "
                       f"{MAX_EXPORT_BYTES} 字节", "warn")
            data = data[:MAX_EXPORT_BYTES]
        name = _safe_name(entry["name"])
        path = ctx.write_output(f"smb_file_{number}_{name}.bin", data)
        exported.append(f"{entry['share'] or ''}\\{entry['name'] or '?'}\t"
                        f"{len(data)} 字节\tmd5={hashlib.md5(data).hexdigest()}"
                        f"\tframe={entry['frame']}\t{Path(path).name}")
        ctx.report(f"SMB 文件 {entry['share'] or ''}\\{entry['name']} "
                   f"已还原 {len(data)} 字节", "good")
        ctx.add_finding("file",
                        f"SMB 文件 {entry['share'] or ''}"
                        f"\\{entry['name'] or '?'}",
                        frame=entry["frame"], level="info",
                        detail=f"size={len(data)} "
                               f"md5={hashlib.md5(data).hexdigest()}",
                        extra={"protocol": "smb2",
                               "path": f"{entry['share'] or ''}"
                                       f"\\{entry['name'] or '?'}",
                               "size": len(data)})
    if pipes:
        ctx.write_output("smb_pipes.txt", "\n".join(pipes) + "\n")
    if exported:
        ctx.write_output("smb_shared_files.txt", "\n".join(exported) + "\n")
        ctx.report(f"共还原 {len(exported)} 个文件内容", "good")
    elif not files:
        ctx.report("没有发现可还原的 SMB 文件传输", "warn")
    ctx.set_progress(100)
