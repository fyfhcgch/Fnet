"""LDAP protocol analysis: binds, searches, entries and StartTLS.

The handler reassembles every LDAP-looking TCP stream (default ports 389/636/
3268/3269 plus any stream whose payload looks like a BER ``LDAPMessage``) and
hands the bytes to :mod:`fnet.utils.ldap`:

* simple binds surface DN + cleartext password; SASL binds name the mechanism;
* search requests expose base/scope/filter/attributes;
* every ``SearchResultEntry`` is dumped with its attributes (AD accounts,
  LAPS passwords, service principals...);
* ``StartTLS`` extended requests produce a warning that the following traffic
  is TLS encrypted.
"""
from __future__ import annotations

from fnet.features.common import clean_cell, protocol_streams
from fnet.features.registry import FeatureContext
from fnet.utils import ldap as ldap_util

MAX_LISTED_ENTRIES = 60


def analyze(ctx: FeatureContext) -> None:
    streams = protocol_streams(ctx, "ldap")
    if not streams:
        ctx.report("没有发现 LDAP 流量", "warn")
        return

    queries: list[str] = []
    entries: list[str] = []
    binds = sasl = starttls = 0
    sensitive = 0
    listed = 0

    for index, stream in enumerate(streams):
        ctx.check_cancel()
        ctx.set_progress(int(index / len(streams) * 90))
        if stream.gaps:
            ctx.report(f"LDAP 流 {stream.stream} 存在 {stream.gaps} 处序列空洞，"
                       "解析结果可能不完整", "warn")
        if stream.truncated:
            ctx.report(f"LDAP 流 {stream.stream} 超出重组上限，已截断", "warn")
        for message in ldap_util.parse_messages(stream.data):
            ctx.check_cancel()
            frame = stream.frame_at(message.offset)
            direction = stream.direction
            if message.op == "BindRequest":
                if message.sasl_mechanism:
                    sasl += 1
                    ctx.report(f"帧 {frame} LDAP SASL 绑定 [{direction}] "
                               f"DN={message.bind_dn or '-'} "
                               f"机制={message.sasl_mechanism}", "info")
                    ctx.add_finding(
                        "protocol", f"LDAP SASL 绑定 {message.bind_dn or '-'}"
                        f" ({message.sasl_mechanism})", frame=frame,
                        extra={"protocol": "ldap",
                               "mechanism": message.sasl_mechanism})
                elif message.bind_dn or message.password:
                    binds += 1
                    ctx.report(f"帧 {frame} LDAP 简单绑定 [{direction}] "
                               f"DN={message.bind_dn}", "good")
                    if message.password:
                        ctx.report(f"  绑定密码: {message.password}", "good")
                    ctx.add_finding(
                        "credential",
                        f"LDAP 绑定 {message.bind_dn}:{message.password or '-'}",
                        frame=frame, level="good",
                        detail=f"DN={message.bind_dn} "
                               f"password={message.password}",
                        extra={"protocol": "ldap",
                               "account": message.bind_dn,
                               "password": message.password})
            elif message.op == "BindResponse":
                if message.result_code not in (0, -1):
                    ctx.report(f"帧 {frame} LDAP 绑定失败 "
                               f"{message.result_name} "
                               f"{clean_cell(message.diagnostic, 160)}",
                               "warn")
            elif message.op == "SearchRequest":
                line = (f"帧 {frame} LDAP 查询 [{direction}] "
                        f"base={message.base or '-'} scope={message.scope} "
                        f"filter={message.filter_text or '-'}")
                if message.attributes:
                    line += f" attrs={','.join(message.attributes[:20])}"
                ctx.report(line, "info")
                queries.append(line)
            elif message.op == "SearchResultEntry":
                values = ldap_util.entry_lines(message, limit=30)
                head = f"帧 {frame} LDAP 条目 [{direction}] " \
                       f"DN={message.object_name}"
                ctx.report(head, "info")
                for value in values[:8]:
                    ctx.report("  " + clean_cell(value, 200), "info")
                text = head + "\n" + "\n".join(values)
                entries.append(text)
                if listed < MAX_LISTED_ENTRIES:
                    listed += 1
                    ctx.add_finding(
                        "protocol",
                        f"LDAP 条目 {message.object_name} "
                        f"({len(values)} 个属性)",
                        frame=frame, detail=clean_cell(text, 2000),
                        extra={"protocol": "ldap",
                               "dn": message.object_name})
                pairs = message.sensitive_values()
                if pairs:
                    sensitive += 1
                    detail = "; ".join(f"{name}={value}"
                                       for name, value in pairs[:10])
                    ctx.report(f"  敏感属性: {clean_cell(detail, 300)}",
                               "good")
                    ctx.add_finding(
                        "credential",
                        f"LDAP 敏感属性 {message.object_name}",
                        frame=frame, level="good", detail=detail,
                        extra={"protocol": "ldap",
                               "dn": message.object_name})
            elif message.op == "ExtendedRequest" and message.is_starttls:
                starttls += 1
                ctx.report(f"帧 {frame} 检测到 LDAP StartTLS 请求，"
                           "后续流量为 TLS 加密，明文解析到此为止", "warn")
                ctx.add_finding("protocol", "LDAP StartTLS 加密升级",
                                frame=frame, level="warn",
                                extra={"protocol": "ldap"})
            elif message.op == "UnbindRequest":
                ctx.report(f"帧 {frame} LDAP Unbind [{direction}]", "debug")

    ctx.report(f"LDAP 消息统计: 绑定={binds} SASL={sasl} "
               f"查询={len(queries)} 条目={len(entries)} "
               f"StartTLS={starttls}", "info")
    if sensitive:
        ctx.report(f"发现 {sensitive} 个含敏感属性的条目（userPassword/LAPS 等）",
                   "good")
    if queries:
        ctx.write_output("ldap_searches.txt", "\n".join(queries) + "\n")
    if entries:
        ctx.write_output("ldap_entries.txt", "\n\n".join(entries) + "\n")
    if starttls:
        ctx.report("该抓包包含 StartTLS：如需解析 TLS 之后的 LDAP，"
                   "请配合 TLS 流量解密功能", "info")
    ctx.set_progress(100)
