"""PostgreSQL protocol analysis: queries, results, credentials and COPY.

The handler reassembles every PostgreSQL-looking TCP stream (default ports
5432/5433 plus payload detection for moved ports) and uses
:mod:`fnet.utils.postgres` to parse the frontend/backend message framing:

* startup parameters (``user`` / ``database``) and SSL negotiation attempts;
* simple ``Query`` and extended ``Parse``/``Bind``/``Execute`` statements with
  bound parameter values;
* cleartext and MD5 password messages as credential findings;
* result summaries (columns, row counts, first rows) and command tags;
* ``COPY`` data reassembly written to the job output directory.
"""
from __future__ import annotations

from fnet.features.common import clean_cell, protocol_streams
from fnet.features.registry import FeatureContext
from fnet.utils import postgres as pg_util

MAX_LISTED_QUERIES = 300
MAX_LISTED_ROWS = 20


def analyze(ctx: FeatureContext) -> None:
    streams = protocol_streams(ctx, "postgres")
    if not streams:
        ctx.report("没有发现 PostgreSQL 流量", "warn")
        return

    query_lines: list[str] = []
    passwords: list[str] = []
    copy_files: list[str] = []
    for index, stream in enumerate(streams):
        ctx.check_cancel()
        ctx.set_progress(int(index / len(streams) * 90))
        if stream.gaps:
            ctx.report(f"PostgreSQL 流 {stream.stream} 存在 {stream.gaps} 处"
                       "序列空洞，解析结果可能不完整", "warn")
        messages = pg_util.parse_stream(stream.data, stream.frame_at)
        direction = stream.direction

        for info in pg_util.startup_info(messages):
            ctx.check_cancel()
            params = info.get("params") or {}
            user = params.get("user", "")
            database = params.get("database", "")
            kind = info.get("kind", "")
            if kind and kind != "StartupMessage":
                ctx.report(f"PostgreSQL {kind} 请求 [{direction}]", "info")
            if user or database:
                ctx.report(f"PostgreSQL 连接 [{direction}] 用户={user or '-'} "
                           f"数据库={database or '-'}", "good")
                ctx.add_finding("credential",
                                f"PostgreSQL 用户 {user or '-'}",
                                level="good",
                                detail=f"user={user} database={database} "
                                       f"stream={stream.stream}",
                                extra={"protocol": "postgres",
                                       "account": user, "database": database})

        for event in pg_util.auth_events(messages):
            ctx.check_cancel()
            frame = event.get("frame", "")
            if event.get("request"):
                ctx.report(f"帧 {frame} PostgreSQL 认证方式: "
                           f"{event['request']}", "info")
            if event.get("password"):
                password = event["password"]
                if password not in passwords:
                    passwords.append(password)
                ctx.report(f"帧 {frame} PostgreSQL 明文口令: {password}",
                           "good")
                ctx.add_finding("credential",
                                f"PostgreSQL 口令 {password}",
                                frame=frame, level="good",
                                detail=f"password={password}",
                                extra={"protocol": "postgres",
                                       "password": password})

        queries = pg_util.queries(messages)
        for query in queries[:MAX_LISTED_QUERIES]:
            ctx.check_cancel()
            frame = query.get("frame", "")
            sql = clean_cell(query.get("query") or
                             query.get("statement") or "(扩展协议)", 400)
            params = [str(value) for value in query.get("params") or []]
            line = f"帧 {frame} PostgreSQL 查询 [{direction}]: {sql}"
            if params:
                line += f" 参数={','.join(params[:20])}"
            ctx.report(line, "info")
            query_lines.append(line)

        # Result summaries: track columns from RowDescription, count rows.
        columns: list[str] = []
        rows: list[list[str]] = []
        total_rows = 0
        for message in messages:
            ctx.check_cancel()
            if message.direction != "backend":
                continue
            if message.type == "T":
                columns = [column.get("name", "")
                           for column in message.fields.get("columns", [])]
                rows = []
            elif message.type == "D":
                total_rows += 1
                if len(rows) < MAX_LISTED_ROWS:
                    rows.append(message.fields.get("values", []))
            elif message.type == "C":
                tag = clean_cell(message.fields.get("tag", ""), 120)
                ctx.report(f"帧 {message.frame} PostgreSQL 完成: {tag} "
                           f"({total_rows} 行)", "info")
                if columns:
                    ctx.report("  列: " + ", ".join(columns), "debug")
                for values in rows:
                    ctx.report("  " + clean_cell(" | ".join(values), 200),
                               "info")
                total_rows = 0
            elif message.type == "E":
                severity = message.fields.get("S", "")
                text = message.fields.get("M", "")
                ctx.report(f"帧 {message.frame} PostgreSQL 错误 "
                           f"{severity}: {clean_cell(text, 200)}", "warn")

        for number, copy in enumerate(pg_util.copy_data(messages), start=1):
            ctx.check_cancel()
            data = copy.get("data") or b""
            if not data:
                continue
            label = "pg_copy_in" if copy.get("direction") == "in" \
                else "pg_copy_out"
            path = ctx.write_output(f"{label}_{number}.bin", data)
            ctx.report(f"PostgreSQL COPY 数据 {len(data)} 字节已还原 "
                       f"({copy.get('direction')})", "good")
            ctx.add_finding("file", f"PostgreSQL COPY 数据 ({len(data)} 字节)",
                            frame=copy.get("frame"), level="info",
                            detail=f"direction={copy.get('direction')} "
                                   f"size={len(data)}",
                            extra={"protocol": "postgres",
                                   "path": path.name})
            copy_files.append(f"{label}_{number}.bin\t{len(data)} 字节")

    if query_lines:
        ctx.write_output("pg_queries.txt", "\n".join(query_lines) + "\n")
        ctx.report(f"PostgreSQL 查询 {len(query_lines)} 条，已写入 "
                   "pg_queries.txt", "info")
    else:
        ctx.report("没有解析出 PostgreSQL 查询", "warn")
    if passwords:
        ctx.report(f"提取到 {len(passwords)} 个 PostgreSQL 明文口令", "good")
    ctx.set_progress(100)
