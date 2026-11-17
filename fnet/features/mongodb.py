"""MongoDB wire protocol analysis: commands, SCRAM auth and GridFS files.

The handler reassembles every MongoDB-looking TCP stream (default ports
27017-27019 plus payload detection for moved ports) and uses
:mod:`fnet.utils.mongodb` to decode the wire format and BSON:

* OP_MSG/OP_QUERY/OP_REPLY commands and the collection/namespace they target;
* SCRAM-SHA-1/256 ``saslStart``/``saslContinue`` exchanges with usernames;
* sensitive fields (user/password/token keys) inside BSON documents;
* GridFS ``fs.files``/``fs.chunks`` reassembly — files are written to the
  job output directory with their MD5 for verification.
"""
from __future__ import annotations

import re
from pathlib import Path

from fnet.features.common import clean_cell, protocol_streams
from fnet.features.registry import FeatureContext
from fnet.utils import mongodb as mongo_util

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")
MAX_LISTED_COMMANDS = 400


def _safe_name(value: str, fallback: str = "gridfs.bin") -> str:
    text = SAFE_NAME.sub("_", (value or "").replace("\\", "/").split("/")[-1])
    text = text.strip("._")
    return (text or fallback)[:80]


def analyze(ctx: FeatureContext) -> None:
    streams = protocol_streams(ctx, "mongodb")
    if not streams:
        ctx.report("没有发现 MongoDB 流量", "warn")
        return

    command_lines: list[str] = []
    listed_users: list[str] = []
    exported: list[str] = []
    truncated = 0

    for index, stream in enumerate(streams):
        ctx.check_cancel()
        ctx.set_progress(int(index / len(streams) * 90))
        if stream.gaps:
            ctx.report(f"MongoDB 流 {stream.stream} 存在 {stream.gaps} 处"
                       "序列空洞，解析结果可能不完整", "warn")
        messages = mongo_util.parse_stream(stream.data, stream.frame_at)
        direction = stream.direction
        for message in messages:
            ctx.check_cancel()
            frame = message.frame
            if message.truncated:
                truncated += 1
                continue
            command = mongo_util.command_of(message)
            namespace = mongo_util.namespace(message)
            if command or namespace:
                line = (f"帧 {frame} MongoDB {message.name} "
                        f"{command or '-'} {namespace}".rstrip())
                ctx.report(line, "info")
                command_lines.append(line)
            documents = mongo_util.documents(message)
            for document in documents:
                for token in mongo_util.sensitive_tokens(document):
                    ctx.report(f"  帧敏感字段: {clean_cell(token, 200)}",
                               "good")
                    ctx.add_finding(
                        "credential", f"MongoDB 字段 {clean_cell(token, 80)}",
                        frame=frame, level="good", detail=token,
                        extra={"protocol": "mongodb"})
        for event in mongo_util.scram_exchanges(messages):
            ctx.check_cancel()
            kind = event.get("kind")
            user = event.get("user") or ""
            mechanism = event.get("mechanism") or ""
            if kind == "mechanisms":
                ctx.report(f"帧 {event.get('frame')} MongoDB 支持的 SASL "
                           f"机制: {event.get('mechanism')}", "debug")
            elif kind == "scram" and user:
                if user not in listed_users:
                    listed_users.append(user)
                    ctx.report(f"帧 {event.get('frame')} MongoDB SCRAM "
                               f"认证 [{direction}] 用户={user} "
                               f"机制={mechanism}", "good")
                    ctx.add_finding(
                        "credential", f"MongoDB SCRAM 用户 {user}", frame=event.get("frame"),
                        level="good",
                        detail=f"user={user} mechanism={mechanism} "
                               f"nonce={event.get('client_nonce')}",
                        extra={"protocol": "mongodb", "account": user,
                               "mechanism": mechanism})
            elif kind == "scram-error":
                ctx.report(f"帧 {event.get('frame')} MongoDB SCRAM 失败: "
                           f"{event.get('error')}", "warn")
            elif kind == "scram-verified":
                ctx.report(f"帧 {event.get('frame')} MongoDB SCRAM 认证成功",
                           "good")
        for grid in mongo_util.gridfs_files(messages):
            ctx.check_cancel()
            if not grid.get("data"):
                continue
            name = _safe_name(grid.get("filename"))
            path = ctx.write_output(f"gridfs_{name}", grid["data"])
            expected = grid.get("length") or grid.get("actual_length") or 0
            status = "完整" if grid.get("complete") else "不完整"
            md5_note = ""
            if grid.get("md5") and grid["md5"] != grid["actual_md5"]:
                md5_note = "（与 fs.files 中记录的 MD5 不一致！）"
            ctx.report(f"GridFS 文件 {grid.get('filename') or name} 已还原: "
                       f"{grid['actual_length']} 字节 ({status}, "
                       f"{grid.get('chunks')} 个分块{md5_note})", "good")
            ctx.add_finding(
                "file", f"GridFS 文件 {grid.get('filename') or name}",
                frame=grid.get("frame"), level="warn" if md5_note else "info",
                detail=f"size={grid['actual_length']} expected={expected} "
                       f"md5={grid['actual_md5']} chunks={grid.get('chunks')} "
                       f"complete={grid.get('complete')}",
                extra={"protocol": "mongodb", "path": Path(path).name,
                       "size": grid["actual_length"]})
            exported.append(f"{grid.get('filename') or name}\t"
                            f"{grid['actual_length']} 字节\t"
                            f"md5={grid['actual_md5']}")
        if truncated:
            ctx.report(f"MongoDB 流 {stream.stream} 有 {truncated} 条消息"
                       "解析失败（截断或损坏）", "warn")

    if command_lines:
        ctx.write_output("mongodb_commands.txt", "\n".join(command_lines) + "\n")
        ctx.report(f"MongoDB 命令 {len(command_lines)} 条，已写入 "
                   "mongodb_commands.txt", "info")
    else:
        ctx.report("没有解析出 MongoDB 命令", "warn")
    if exported:
        ctx.report(f"共还原 {len(exported)} 个 GridFS 文件", "good")
    ctx.set_progress(100)
