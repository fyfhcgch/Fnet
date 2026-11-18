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


def _ntlmv2_hash_line(blob: bytes, challenge: bytes) -> str:
    """hashcat -m 5600 line for a captured NTLMv2 AUTHENTICATE message."""
    if len(challenge) != 8:
        return ""
    auth = smb_util.ntlm_type3(blob)
    nt = auth.get("nt") or b""
    if len(nt) <= 24:
        return ""
    return (f"{auth.get('user', '')}::{auth.get('domain', '')}:"
            f"{challenge.hex()}:{nt[:16].hex()}:{nt[16:].hex()}")


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
    encrypted_streams: dict[str, dict] = {}
    compressed_streams: dict[str, dict] = {}
    stream_meta: dict[str, dict] = {}
    challenges: dict[str, bytes] = {}
    #: Per-stream NTLM identity, so the SMB3 加密流量 finding can hand the
    #: account (and its NetNTLMv2 hash) to the SMB3 解密 dialog as a hint.
    identities: dict[str, dict] = {}

    def _file_entry(key: tuple) -> dict:
        return files.setdefault(
            key, {"name": "", "share": "", "write": {}, "read": {},
                  "frame": "", "pipe": False, "stream": ""})

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
        endpoints = {stream.direction: f"{stream.src}:{stream.sport}"
                     for stream in group}
        stream_id = group[0].stream
        meta = stream_meta.setdefault(
            group[0].stream, {"stream": group[0].stream, "client": "",
                              "server": "", "dialects": [],
                              "security_mode": 0, "capabilities": 0})
        for _sort, _frame, direction, message in combined:
            if message.command == 0 and not message.is_response \
                    and not meta["client"]:
                meta["client"] = endpoints.get(direction, direction)
            elif message.command == 0 and message.is_response:
                if not meta["server"]:
                    meta["server"] = endpoints.get(direction, direction)
                meta["security_mode"] = meta["security_mode"] or \
                    message.security_mode
                meta["capabilities"] = meta["capabilities"] or \
                    message.capabilities

        for _sort, frame, direction, message in combined:
            ctx.check_cancel()

            if message.encrypted:
                info = encrypted_streams.setdefault(stream_id, {
                    "stream": stream_id, "client": meta["client"],
                    "server": meta["server"], "count": 0, "bytes": 0,
                    "first_frame": frame,
                    "session_id": f"{message.session_id:#x}",
                    "nonce": message.nonce[:12].hex(),
                    "flags": set()})
                info["count"] += 1
                info["bytes"] += len(message.raw)
                info["flags"].add(message.transform_flags)
                continue
            if message.compressed:
                info = compressed_streams.setdefault(stream_id, {
                    "stream": stream_id, "client": meta["client"],
                    "server": meta["server"], "count": 0, "bytes": 0,
                    "first_frame": frame,
                    "algorithm": message.compression or "?",
                    "original_size": message.original_size})
                info["count"] += 1
                info["bytes"] += len(message.raw)
                continue

            command = message.command_name
            if command == "NEGOTIATE":
                if message.is_response and message.dialect:
                    name = DIALECTS.get(message.dialect,
                                        f"0x{message.dialect:#06x}")
                    if name not in dialects:
                        dialects.append(name)
                    if name not in meta["dialects"]:
                        meta["dialects"].append(name)
                for dialect in message.dialects:
                    name = DIALECTS.get(dialect, f"0x{dialect:#06x}")
                    if name not in dialects:
                        dialects.append(name)
                    if name not in meta["dialects"]:
                        meta["dialects"].append(name)
            elif command == "SESSION_SETUP":
                if message.is_response and \
                        message.security_blob.startswith(smb_util.NTLMSSP):
                    challenge = message.security_blob[24:32]
                    if len(challenge) == 8:
                        challenges[stream_id] = challenge
                if message.user or message.domain:
                    account = (f"{message.domain}\\{message.user}"
                               if message.domain else message.user)
                    hash_line = _ntlmv2_hash_line(
                        message.security_blob,
                        challenges.get(stream_id, b""))
                    identity = identities.setdefault(
                        stream_id, {"stream": stream_id, "account": "",
                                    "user": "", "domain": "", "frame": "",
                                    "auth": "", "hash": ""})
                    identity.update({"account": account,
                                     "user": message.user,
                                     "domain": message.domain,
                                     "frame": frame,
                                     "auth": message.auth_package
                                             or identity["auth"],
                                     "hash": hash_line or identity["hash"]})
                    if account not in users:
                        users.append(account)
                        ctx.report(f"帧 {frame} SMB 会话认证 [{direction}] "
                                   f"账号={account} "
                                   f"包={message.auth_package or '?'}",
                                   "good")
                        extra = {
                            "protocol": "smb2", "account": account,
                            "user": message.user, "domain": message.domain,
                            "workstation": message.workstation,
                            "auth": message.auth_package,
                            "stream": stream_id,
                            "server": meta["server"],
                        }
                        if hash_line:
                            extra["hash"] = hash_line
                            extra["mode"] = "5600"
                        ctx.add_finding(
                            "credential", f"SMB 账号 {account}", frame=frame,
                            level="good",
                            detail=f"user={message.user} "
                                   f"domain={message.domain} "
                                   f"workstation={message.workstation} "
                                   f"stream={stream_id}",
                            extra=extra)
                        if hash_line:
                            ctx.add_finding(
                                "hash", f"SMB NetNTLMv2 {account}",
                                frame=frame, level="good", detail=hash_line,
                                extra={"protocol": "smb2",
                                       "account": account,
                                       "user": message.user,
                                       "domain": message.domain,
                                       "stream": stream_id,
                                       "hash": hash_line, "mode": "5600"})
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
                                           "share": message.share,
                                           "stream": stream_id,
                                           "server": meta["server"],
                                           "client": meta["client"],
                                           "dialect": ", ".join(
                                               meta["dialects"])})
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
                        ctx.add_finding(
                            "protocol", f"SMB 共享要求加密 {share}",
                            frame=frame, level="warn",
                            extra={"protocol": "smb2", "share": share,
                                   "stream": stream_id,
                                   "server": meta["server"],
                                   "encrypted": True,
                                   "share_flags":
                                       f"0x{message.share_flags:08x}"})
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
                                               "pipe": pipe_name,
                                               "share": share,
                                               "stream": stream_id,
                                               "server": meta["server"]})
                    else:
                        entry = _file_entry(smb_util.file_id_key(message))
                        entry["name"] = message.file_name
                        entry["share"] = share
                        entry["pipe"] = False
                        entry["stream"] = stream_id
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
                        entry["stream"] = stream_id
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
                                               "path": path,
                                               "stream": stream_id,
                                               "server": meta["server"]})

    if dialects:
        ctx.report("SMB 方言: " + ", ".join(dialects), "info")

    for info in encrypted_streams.values():
        dialect = ", ".join(stream_meta.get(info["stream"], {})
                            .get("dialects", []))
        identity = identities.get(info["stream"]) or {}
        account = identity.get("account") or ""
        ctx.report(f"帧 {info['first_frame']} 检测到 SMB3 加密流量 "
                   f"(transform, {info['count']} 条, {info['bytes']} 字节)，"
                   "载荷无法解析；可在结果详情中提供 NT 哈希/密码解密"
                   + (f"（已识别账号 {account}，可自动填入）" if account else ""),
                   "warn")
        extra = {"protocol": "smb2", "smb": "encrypted",
                 "stream": info["stream"],
                 "client": info["client"], "server": info["server"],
                 "dialect": dialect,
                 "session_id": info["session_id"],
                 "transforms": info["count"],
                 "encrypted_bytes": info["bytes"],
                 "nonce": info["nonce"],
                 "first_frame": info["first_frame"]}
        if account:
            extra.update({"account": account,
                          "user": identity.get("user", ""),
                          "domain": identity.get("domain", ""),
                          "auth": identity.get("auth", "")})
            if identity.get("hash"):
                extra["hash"] = identity["hash"]
                extra["mode"] = "5600"
        detail = (f"stream={info['stream']} 加密消息={info['count']} "
                  f"字节={info['bytes']} session={info['session_id']}")
        if account:
            detail += f" 账号={account}"
        ctx.add_finding(
            "protocol", "SMB3 加密流量", frame=info["first_frame"],
            level="warn", detail=detail, extra=extra)

    for info in compressed_streams.values():
        ctx.report(f"帧 {info['first_frame']} 检测到 SMB3 压缩流量 "
                   f"({info['algorithm']}, {info['original_size']} 字节)",
                   "warn")
        ctx.add_finding(
            "protocol", "SMB3 压缩流量", frame=info["first_frame"],
            level="warn",
            detail=f"stream={info['stream']} 算法={info['algorithm']} "
                   f"原始大小={info['original_size']}",
            extra={"protocol": "smb2", "smb": "compressed",
                   "stream": info["stream"],
                   "server": info["server"],
                   "algorithm": info["algorithm"],
                   "original_size": info["original_size"],
                   "transforms": info["count"]})

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
                               f"md5={hashlib.md5(data).hexdigest()} "
                               f"stream={entry.get('stream', '')}",
                        extra={"protocol": "smb2",
                               "path": f"{entry['share'] or ''}"
                                       f"\\{entry['name'] or '?'}",
                               "share": entry["share"],
                               "name": entry["name"],
                               "size": len(data),
                               "md5": hashlib.md5(data).hexdigest(),
                               "stream": entry.get("stream", ""),
                               "artifact": Path(path).name})
    if pipes:
        ctx.write_output("smb_pipes.txt", "\n".join(pipes) + "\n")
    if exported:
        ctx.write_output("smb_shared_files.txt", "\n".join(exported) + "\n")
        ctx.report(f"共还原 {len(exported)} 个文件内容", "good")
    elif not files:
        ctx.report("没有发现可还原的 SMB 文件传输", "warn")
    ctx.set_progress(100)
