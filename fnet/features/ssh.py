"""SSH session analysis: version exchange, KEXINIT, userauth and brute force.

Everything an SSH capture can reveal lives before the first ``NEWKEYS``:
the version banners, the algorithm negotiation and — when passwords are used
against legacy or CTF servers — the cleartext ``userauth`` layer.  The
handler reassembles SSH-looking TCP streams (port 22 plus any stream whose
payload starts with ``SSH-``) and uses :mod:`fnet.utils.ssh` to:

* report client/server software versions;
* list the negotiated key exchange / host key / cipher / MAC algorithms;
* extract ``USERAUTH_REQUEST`` usernames, methods and cleartext passwords;
* count ``USERAUTH_FAILURE`` events per user and emit a brute-force timeline
  (threshold configurable via the ``ssh_brute_threshold`` parameter).
"""
from __future__ import annotations

from fnet.features.common import clean_cell, protocol_streams
from fnet.features.registry import FeatureContext
from fnet.utils import ssh as ssh_util

DEFAULT_BRUTE_THRESHOLD = 5


def _looks_like_ssh(data: bytes) -> bool:
    return ssh_util.looks_like_ssh(data)


def analyze(ctx: FeatureContext) -> None:
    streams = protocol_streams(ctx, matcher=_looks_like_ssh)
    if not streams:
        ctx.report("没有发现 SSH 流量", "warn")
        return

    threshold_raw = str(ctx.params.get("ssh_brute_threshold") or "").strip()
    try:
        threshold = int(threshold_raw) if threshold_raw else \
            DEFAULT_BRUTE_THRESHOLD
    except ValueError:
        threshold = DEFAULT_BRUTE_THRESHOLD

    timeline: list[str] = []
    passwords: list[str] = []
    reported_brute: set[str] = set()

    # Group directions of one TCP stream so failures observed by the server
    # can borrow the username from the client's USERAUTH_REQUEST messages.
    groups: dict[str, list] = {}
    for stream in streams:
        groups.setdefault(stream.stream, []).append(stream)

    for index, group in enumerate(groups.values()):
        ctx.check_cancel()
        ctx.set_progress(int(index / len(groups) * 90))
        usernames: list[str] = []
        parsed = []
        for stream in group:
            if stream.gaps:
                ctx.report(f"SSH 流 {stream.stream} 存在 {stream.gaps} 处序列空洞",
                           "warn")
            messages = ssh_util.parse_stream(stream.data, stream.frame_at)
            events = ssh_util.auth_events(messages)
            failures = ssh_util.failure_counts(events)
            for event in events:
                if event.get("kind") == "request" and event.get("user"):
                    usernames.append(event["user"])
            parsed.append((stream, messages, events, failures))
        # Failures carry no username; attribute them to the stream's users.
        borrowed = usernames[0] if len(set(usernames)) == 1 else ""
        for stream, messages, events, failures in parsed:
            direction = stream.direction
            for event in events:
                if event.get("kind") in ("failure", "success") \
                        and not event.get("user"):
                    event["user"] = borrowed
            failures = ssh_util.failure_counts(events)

            for message in messages:
                ctx.check_cancel()
                frame = message.frame
                if message.kind == "banner":
                    fields = message.fields
                    ctx.report(f"帧 {frame} SSH 版本交换 [{direction}] "
                               f"{fields.get('software') or ''} "
                               f"({fields.get('protocol')})", "info")
                    ctx.add_finding(
                        "protocol", f"SSH 版本 {fields.get('protocol')} "
                        f"{fields.get('software')}".strip(), frame=frame,
                        detail=fields.get("banner", ""),
                        extra={"protocol": "ssh",
                               "software": fields.get("software")})
                elif message.type_name == "KEXINIT":
                    fields = message.fields
                    kex = ",".join(fields.get("kex_algorithms", [])[:6])
                    host_key = ",".join(
                        fields.get("server_host_key_algorithms", [])[:6])
                    cipher = ",".join(
                        fields.get("encryption_algorithms_client_to_server",
                                   [])[:6])
                    mac = ",".join(
                        fields.get("mac_algorithms_client_to_server", [])[:6])
                    compression = ",".join(
                        fields.get("compression_algorithms_client_to_server",
                                   [])[:6])
                    ctx.report(f"帧 {frame} SSH 算法协商 [{direction}]:",
                               "info")
                    for label, value in (("KEX", kex), ("主机密钥", host_key),
                                         ("加密", cipher), ("MAC", mac),
                                         ("压缩", compression)):
                        if value:
                            ctx.report(f"  {label}: {clean_cell(value, 200)}",
                                       "debug")
                elif message.kind == "encrypted":
                    ctx.report(f"帧 {frame} SSH 会话从此帧开始加密 "
                               f"(剩余 {message.fields.get('remaining', 0)} 字节"
                               "无法解析)", "info")

            for event in events:
                ctx.check_cancel()
                frame = event.get("frame", "")
                user = event.get("user") or "-"
                kind = event.get("kind")
                if kind == "request":
                    method = event.get("method", "")
                    if method == "password" and event.get("password"):
                        password = event["password"]
                        if password not in passwords:
                            passwords.append(password)
                        ctx.report(f"帧 {frame} SSH 口令认证 [{direction}] "
                                   f"用户={user} 密码={password}", "good")
                        ctx.add_finding(
                            "credential", f"SSH 口令 {user}:{password}",
                            frame=frame, level="good",
                            detail=f"user={user} password={password}",
                            extra={"protocol": "ssh", "account": user,
                                   "password": password})
                    elif method == "publickey":
                        ctx.report(f"帧 {frame} SSH 公钥认证 [{direction}] "
                                   f"用户={user} "
                                   f"算法={event.get('algorithm', '?')}",
                                   "info")
                    elif method:
                        ctx.report(f"帧 {frame} SSH 认证 [{direction}] "
                                   f"用户={user} 方法={method}", "info")
                    timeline.append(
                        f"{frame or '-'}\trequest\t{user}\t{method}")
                elif kind == "failure":
                    ctx.report(f"帧 {frame} SSH 认证失败 [{direction}] "
                               f"用户={user}", "warn")
                    timeline.append(f"{frame or '-'}\tfailure\t{user}\t")
                    if user in reported_brute:
                        continue
                    count = failures.get(event.get("user") or "", 0)
                    if count >= threshold:
                        reported_brute.add(user)
                        ctx.report(f"SSH 用户 {user or '(未知)'} 认证失败 "
                                   f"{count} 次，疑似爆破", "warn")
                        ctx.add_finding(
                            "protocol",
                            f"疑似 SSH 爆破 用户 {user or '(未知)'} "
                            f"失败 {count} 次",
                            frame=frame, level="warn",
                            detail=f"user={user} failures={count} "
                                   f"threshold={threshold}",
                            extra={"protocol": "ssh", "account": user,
                                   "failures": count})
                elif kind == "success":
                    ctx.report(f"帧 {frame} SSH 认证成功 [{direction}] "
                               f"用户={user}", "good")
                    ctx.add_finding("protocol", f"SSH 认证成功 {user}",
                                    frame=frame, level="good",
                                    extra={"protocol": "ssh",
                                           "account": user})
                    timeline.append(f"{frame or '-'}\tsuccess\t{user}\t")

    if timeline:
        ctx.write_output("ssh_auth_timeline.txt", "\n".join(timeline) + "\n")
        ctx.report(f"SSH 认证时间线 {len(timeline)} 条事件，已写入 "
                   "ssh_auth_timeline.txt", "info")
    if passwords:
        ctx.report(f"提取到 {len(passwords)} 个 SSH 明文口令", "good")
    if not timeline:
        ctx.report("没有解析出 SSH 认证事件（会话可能在 banner 后立即加密）",
                   "warn")
    ctx.set_progress(100)
