"""Redis protocol analysis: commands, AUTH credentials and key/value views.

Wireshark has no Redis dissector and Redis often runs on non-standard ports,
so the handler relies on pure RESP reassembly: every TCP stream whose payload
looks like RESP (or touches ports 6379/6380) is handed to
:mod:`fnet.utils.redis`:

* every command with its arguments (limited listing) and command statistics;
* ``AUTH`` / ``HELLO AUTH`` / ``CONFIG SET requirepass`` credentials;
* ACL changes, cluster ``MOVED``/``ASK`` redirects, Pub/Sub and
  ``EVAL``/``EVALSHA`` scripts;
* sensitive key reads (password/flag/token-like keys) and written values.
"""
from __future__ import annotations

from fnet.features.common import clean_cell, protocol_streams
from fnet.features.registry import FeatureContext
from fnet.utils import redis as redis_util

MAX_LISTED_COMMANDS = 400


def analyze(ctx: FeatureContext) -> None:
    streams = protocol_streams(ctx, "redis")
    if not streams:
        ctx.report("没有发现 Redis 流量", "warn")
        return

    command_lines: list[str] = []
    for index, stream in enumerate(streams):
        ctx.check_cancel()
        ctx.set_progress(int(index / len(streams) * 90))
        if stream.gaps:
            ctx.report(f"Redis 流 {stream.stream} 存在 {stream.gaps} 处序列"
                       "空洞，解析结果可能不完整", "warn")
        messages = redis_util.parse_messages(stream.data, stream.frame_at)
        commands = redis_util.commands(messages)
        direction = stream.direction

        counts = redis_util.command_counts(messages)
        if counts:
            summary = ", ".join(
                f"{name}={count}" for name, count
                in sorted(counts.items(), key=lambda pair: -pair[1])[:15])
            ctx.report(f"Redis 流 {stream.stream} 命令统计: {summary}", "info")

        for item in commands[:MAX_LISTED_COMMANDS]:
            ctx.check_cancel()
            args = " ".join(item.args[:20])
            ctx.report(f"帧 {item.frame} Redis [{direction}] "
                       f"{clean_cell(args, 240)}", "info")
            command_lines.append(f"{item.frame}\t{args}")

        for event in redis_util.auth_events(messages):
            ctx.check_cancel()
            account = event.get("account") or "-"
            secret = event.get("secret") or ""
            ctx.report(f"帧 {event.get('frame')} Redis 认证 "
                       f"[{event.get('detail')}] 用户={account} "
                       f"密码={secret}", "good")
            ctx.add_finding("credential",
                            f"Redis 认证 {account}:{secret}",
                            frame=event.get("frame"), level="good",
                            detail=f"account={account} secret={secret} "
                                   f"({event.get('detail')})",
                            extra={"protocol": "redis", "account": account,
                                   "password": secret})

        for change in redis_util.acl_changes(messages):
            ctx.check_cancel()
            rules = " ".join(change.get("rules") or [])
            ctx.report(f"帧 {change.get('frame')} Redis ACL {change['action']} "
                       f"{change.get('user') or '-'} {clean_cell(rules, 160)}",
                       "info")
            if change["action"] in ("SETUSER", "DELUSER"):
                ctx.add_finding("protocol",
                                f"Redis ACL {change['action']} "
                                f"{change.get('user') or '-'}",
                                frame=change.get("frame"),
                                detail=clean_cell(
                                    change.get("command", ""), 300),
                                extra={"protocol": "redis"})

        for redirect in redis_util.cluster_redirects(messages):
            ctx.report(f"帧 {redirect.get('frame')} Redis 集群重定向 "
                       f"{redirect.get('kind')} slot={redirect.get('slot')} "
                       f"-> {redirect.get('target')}", "warn")
            ctx.add_finding("protocol",
                            f"Redis {redirect.get('kind')} 重定向 -> "
                            f"{redirect.get('target')}",
                            frame=redirect.get("frame"), level="warn",
                            extra={"protocol": "redis"})

        for script in redis_util.eval_scripts(messages):
            ctx.check_cancel()
            ctx.report(f"帧 {script.get('frame')} Redis {script.get('command')} "
                       f"脚本 [{script.get('encoding') or '明文'}]: "
                       f"{clean_cell(script.get('script') or '', 300)}",
                       "info")
            ctx.add_finding("protocol",
                            f"Redis {script.get('command')} 脚本",
                            frame=script.get("frame"),
                            detail=clean_cell(script.get("script") or "", 600),
                            extra={"protocol": "redis"})

        for read in redis_util.sensitive_reads(messages):
            ctx.report(f"帧 {read.get('frame')} Redis 敏感键读取 "
                       f"{read['command']} {read['key']}", "warn")
            ctx.add_finding("protocol",
                            f"Redis 敏感键读取 {read['key']}",
                            frame=read.get("frame"), level="warn",
                            detail=f"{read['command']} {read['key']}",
                            extra={"protocol": "redis", "key": read["key"]})

        for frame, text in redis_util.value_flags(messages):
            ctx.report(f"帧 {frame} Redis 写入值: {clean_cell(text, 240)}",
                       "good")
            ctx.add_finding("protocol", "Redis 写入值", frame=frame,
                            detail=clean_cell(text, 600),
                            extra={"protocol": "redis"})

        for event in redis_util.pubsub_events(messages):
            ctx.report(f"帧 {event.get('frame')} Redis Pub/Sub "
                       f"{event.get('kind')} {event.get('channel') or ''}"
                       f"{clean_cell(event.get('message') or '', 160)}",
                       "debug")

    if command_lines:
        ctx.write_output("redis_session.txt", "\n".join(command_lines) + "\n")
        ctx.report(f"Redis 命令 {len(command_lines)} 条，已写入 "
                   "redis_session.txt", "info")
    else:
        ctx.report("没有解析出 Redis 命令", "warn")
    ctx.set_progress(100)
