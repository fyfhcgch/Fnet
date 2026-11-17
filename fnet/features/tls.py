"""TLS/QUIC decryption with an NSS key log and/or an RSA private key.

Two key sources are supported:

* ``tls_keylog`` – ``SSLKEYLOGFILE`` style secrets (TLS 1.2/1.3);
* ``tls_private_key`` – PEM RSA key used for ``tls.keys_list`` on captures
  without forward secrecy.  Encrypted PEM keys are decrypted with
  ``openssl`` when ``tls_key_passphrase`` is configured; the passphrase only
  travels through an environment variable.

Both can be uploaded from the WebUI ("设置 → 上传 TLS keylog / 私钥…"); the
server stores them under ``<cache>/keys`` and remembers the path.  When no key
is configured the handler looks in that directory and tells the user which
candidate files are available if decryption still fails.

After decryption the handler also inspects the recovered plaintext: TLS 1.3
``KeyUpdate`` messages, certificate chains, HTTP/2 and WebSocket traffic,
credentials and exported files are summarised next to the HTTP requests.
"""
from __future__ import annotations

import base64
import hashlib
import re
import urllib.parse
from pathlib import Path

from fnet.features.common import clean_cell, table, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.logger import logger
from fnet.paths import CACHE_DIR
from fnet.tools.runner import run
from fnet.utils import codec, tlsdeep
from fnet.utils.pcap import file_magic, hex_to_bytes, payload_text

KEYLOG_MARKERS = ("CLIENT_RANDOM", "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                  "SERVER_HANDSHAKE_TRAFFIC_SECRET", "EXPORTER_SECRET",
                  "EARLY_EXPORTER_SECRET", "RESUMPTION_MASTER_SECRET")
SECRET_NAME_RE = re.compile(
    r"(pass(word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"auth|session|jwt|ticket|cookie|csrf)", re.IGNORECASE)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
FLAG_LIKE_RE = re.compile(r"(?:flag|ctf|key)\{[^}\r\n]{1,200}\}", re.IGNORECASE)
QUIC_FIELDS = [
    "frame.number", "frame.time_relative", "ip.src", "udp.srcport",
    "ip.dst", "udp.dstport", "quic.version", "quic.dcid", "quic.scid",
    "quic.long.packet_type", "quic.long.packet_type_v2",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions_alpn_str", "quic.connection.number",
    "frame.len",
]


def key_kind(path: Path) -> str:
    """Return ``keylog``/``key`` for a file, or ``""`` when unrecognised."""
    try:
        head = path.read_text(encoding="utf-8", errors="ignore")[:4000]
    except OSError:
        return ""
    if any(marker in head for marker in KEYLOG_MARKERS):
        return "keylog"
    if "PRIVATE KEY" in head:
        return "key"
    return ""


def discover_keys() -> dict[str, list[Path]]:
    """Find keylog/private-key files uploaded through the WebUI."""
    found: dict[str, list[Path]] = {"keylog": [], "key": []}
    root = CACHE_DIR / "keys"
    if not root.is_dir():
        return found
    for path in sorted(root.iterdir()):
        if not path.is_file():
            continue
        kind = key_kind(path)
        if kind:
            found[kind].append(path)
    return found


def merge_keylogs(paths: list[Path],
                  destination: Path | None = None) -> tuple[Path | None, int]:
    """Merge several NSS keylog files into one de-duplicated file.

    tshark accepts only one ``tls.keylog_file`` per run, but a capture often
    needs secrets collected from several browsers/hosts.  The merged file keeps
    the input line order and drops duplicate ``CLIENT_RANDOM``/traffic secret
    lines.  Returns ``(path, unique_line_count)``; ``(None, 0)`` when no
    readable keylog had usable lines.
    """
    lines: list[str] = []
    seen: set[str] = set()
    for path in paths or []:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped in seen:
                continue
            seen.add(stripped)
            lines.append(stripped)
    if not lines:
        return None, 0
    target = Path(destination) if destination else (
        CACHE_DIR / "keys" / "merged.keylog")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except OSError:
        return None, 0
    return target, len(lines)


def server_endpoints(ctx: FeatureContext) -> list[tuple[str, str]]:
    """Unique ``(server ip, port)`` pairs from TLS Client Hello frames."""
    rows = tshark_rows(
        ctx, ["ip.src", "ip.dst", "tcp.srcport", "tcp.dstport",
              "tls.handshake.type"],
        "tls.handshake.type == 1", limit=20_000)
    endpoints: list[tuple[str, str]] = []
    for row in rows:
        row += [""] * (5 - len(row))
        ip, port = row[1], row[3]
        if ip and port and (ip, port) not in endpoints:
            endpoints.append((ip, port))
    return endpoints


def _keylog_options(paths: list[Path]) -> list[str]:
    if not paths:
        return []
    if len(paths) == 1:
        return ["-o", f"tls.keylog_file:{paths[0]}"]
    # tshark accepts one keylog file; merge every configured/uploaded file.
    merged, count = merge_keylogs(paths)
    if merged is not None:
        logger.info(f"已合并 {len(paths)} 个 keylog（{count} 条唯一密钥）: {merged}")
        return ["-o", f"tls.keylog_file:{merged}"]
    latest = max(paths, key=lambda item: item.stat().st_mtime)
    return ["-o", f"tls.keylog_file:{latest}"]


def _passphrase(ctx: FeatureContext) -> str:
    return str(ctx.params.get("tls_key_passphrase")
               or ctx.config.get("tls_key_passphrase", "paths") or "").strip()


def _resolve_keys(ctx: FeatureContext) -> tuple[list[Path], list[Path]]:
    keylog = str(ctx.params.get("tls_keylog")
                 or ctx.config.get("tls_keylog", "paths") or "").strip()
    private = str(ctx.params.get("tls_private_key")
                  or ctx.config.get("tls_private_key", "paths") or "").strip()
    configured_log = [Path(keylog).expanduser()] if keylog and Path(
        keylog).expanduser().is_file() else []
    configured_key = [Path(private).expanduser()] if private and Path(
        private).expanduser().is_file() else []
    discovered = discover_keys()
    # Combine explicitly configured files with the WebUI upload directory so
    # several keylogs from different browsers/hosts can be merged.
    keylogs = list(dict.fromkeys(configured_log + discovered["keylog"]))
    keys = list(dict.fromkeys(configured_key + discovered["key"]))
    if discovered["keylog"] and not configured_log:
        ctx.report("自动使用已上传的 keylog: "
                   + ", ".join(str(p) for p in discovered["keylog"]), "info")
    elif len(keylogs) > 1:
        ctx.report(f"将合并 {len(keylogs)} 个 keylog 文件", "info")
    if discovered["key"] and not configured_key:
        ctx.report("自动使用已上传的私钥: "
                   + ", ".join(str(p) for p in keys), "info")
    if keylog and not keylogs:
        ctx.report(f"keylog 文件不存在: {keylog}", "warn")
    if private and not keys:
        ctx.report(f"私钥文件不存在: {private}", "warn")
    return keylogs, keys


def _prepare_private_keys(ctx: FeatureContext,
                          paths: list[Path]) -> tuple[list[Path], str]:
    """Decrypt encrypted PEM keys and return ``(usable_paths, passphrase)``."""
    passphrase = _passphrase(ctx)
    prepared: list[Path] = []
    for path in paths:
        if not tlsdeep.encrypt_marker(path):
            prepared.append(path)
            continue
        digest = hashlib.sha256(
            (path.read_bytes() + passphrase.encode("utf-8"))).hexdigest()[:12]
        base = Path(ctx.output_dir or CACHE_DIR) / "keys"
        destination = base / f"{path.stem}-{digest}.pem"
        decrypted, message = tlsdeep.decrypt_private_key(
            path, passphrase, destination)
        ctx.report(message, "good" if decrypted else "warn")
        if decrypted is not None:
            prepared.append(decrypted)
    return prepared, passphrase


# ---------------------------------------------------------------------------
# Handshake, certificates and TLS 1.3 KeyUpdate
# ---------------------------------------------------------------------------
def _report_handshake(ctx: FeatureContext) -> None:
    handshake = ["frame.number", "tls.handshake.type",
                 "tls.handshake.extensions_server_name", "tls.record.version",
                 "tls.handshake.ciphersuite"]
    rows = tshark_rows(ctx, handshake, "tls.handshake", limit=20_000)
    if not rows:
        return
    table(ctx, "TLS 握手", handshake, rows, limit=150)
    sni = sorted({r[2] for r in rows if len(r) > 2 and r[2]})
    if sni:
        ctx.report("SNI: " + ", ".join(sni[:100]), "info")


def _load_certificates(ctx: FeatureContext) -> dict[tuple[str, str], dict]:
    """Certificate chain per ``server ip:port`` from ``Certificate`` frames."""
    fields = ["frame.number", "ip.src", "tcp.srcport",
              "tls.handshake.certificate"]
    rows = tshark_rows(ctx, fields, "tls.handshake.type == 11", limit=4000)
    chains: dict[tuple[str, str], dict] = {}
    for raw in rows:
        row = list(raw) + [""] * (4 - len(raw))
        endpoint = (row[1], row[2])
        if not endpoint[0] or endpoint in chains:
            continue
        certs = []
        for value in row[3].split(","):
            der = hex_to_bytes(value)
            if not der:
                continue
            info = tlsdeep.certificate_info(der)
            if info["subject"] or info["issuer"]:
                certs.append(info)
        if not certs:
            continue
        chains[endpoint] = {
            "frame": row[0], "chain": certs, "leaf": certs[0],
            "spki": certs[0].get("spki") or b"",
        }
    return chains


def _report_certificates(ctx: FeatureContext,
                         chains: dict[tuple[str, str], dict]) -> None:
    if not chains:
        return
    fields = ["服务端", "主体 CN", "SAN", "颁发者", "有效期", "序列号", "链", "帧"]
    rows = []
    for (ip, port), item in list(chains.items())[:100]:
        leaf = item["leaf"]
        rows.append([
            f"{ip}:{port}", leaf.get("subject", ""),
            ", ".join(leaf.get("san") or [])[:240],
            leaf.get("issuer", ""),
            f"{leaf.get('not_before', '')} ~ {leaf.get('not_after', '')}",
            leaf.get("serial", "")[:32], str(len(item["chain"])), item["frame"],
        ])
        ctx.add_finding(
            "protocol", f"TLS 证书 {leaf.get('subject') or ip}",
            frame=item["frame"],
            detail=(f"{ip}:{port} · 颁发者 {leaf.get('issuer') or '-'} · "
                    f"SAN {', '.join(leaf.get('san') or []) or '-'} · "
                    f"有效期 {leaf.get('not_before')}~{leaf.get('not_after')}"),
            level="info")
    table(ctx, "TLS 证书链", fields, rows, cell_limit=240)
    self_signed = sum(1 for item in chains.values()
                      if item["leaf"].get("subject")
                      and item["leaf"].get("subject") == item["leaf"].get("issuer"))
    if self_signed:
        ctx.report(f"其中 {self_signed} 个端点使用自签名证书", "warn")


def _report_key_updates(ctx: FeatureContext) -> int:
    fields = ["frame.number", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"]
    rows = tshark_rows(ctx, fields, "tls.handshake.type == 24", limit=4000)
    updates = tlsdeep.key_update_rows(rows)
    if not updates:
        return 0
    total = sum(item["count"] for item in updates)
    ctx.report(f"检测到 TLS 1.3 KeyUpdate {total} 次（{len(updates)} 个方向）", "warn")
    for item in updates[:100]:
        frames = ",".join(item["frames"][:10])
        ctx.report(f"  {item['endpoint']} ×{item['count']} 帧 {frames}", "info")
        ctx.add_finding(
            "protocol", f"TLS 1.3 KeyUpdate ×{item['count']}",
            frame=item["frames"][0] if item["frames"] else "",
            detail=(f"{item['endpoint']} · 帧 {frames} · Wireshark 会用 keylog "
                    "中的 traffic secret 自动派生更新后的密钥；缺少 secret 的"
                    "连接在 KeyUpdate 之后无法解密"),
            level="warn")
    ctx.report("可尝试：重新抓取包含完整握手与 keylog 的会话；keylog 需要包含 "
               "CLIENT_TRAFFIC_SECRET_0/SERVER_TRAFFIC_SECRET_0", "info")
    return total


def _report_keylog_coverage(ctx: FeatureContext, keylogs: list[Path]) -> None:
    if not keylogs:
        return
    entries = tlsdeep.keylog_entries(keylogs)
    if not entries["lines"]:
        return
    labels = ", ".join(f"{name}×{count}" for name, count in
                       sorted(entries["labels"].items()))
    ctx.report(f"keylog 共 {entries['lines']} 条唯一密钥（{labels}）", "info")
    rows = tshark_rows(ctx, ["tls.handshake.random"], "tls.handshake.type == 1",
                       limit=20_000)
    randoms = [row[0] for row in rows if row and row[0]]
    coverage = tlsdeep.keylog_coverage(entries, randoms)
    if coverage["total"]:
        ctx.report(
            f"keylog 覆盖 {coverage['covered']}/{coverage['total']} 个 Client Hello"
            f"（{coverage['percent']:.0f}%）", "good" if coverage["missing"] else "info")
        if coverage["missing"]:
            ctx.report("未覆盖的 Client Hello（这些连接无法解密）: "
                       + ", ".join(item[:16] for item in coverage["missing"][:10]),
                       "warn")


# ---------------------------------------------------------------------------
# Key selection
# ---------------------------------------------------------------------------
def _private_key_options(ctx: FeatureContext, paths: list[Path],
                         passphrase: str,
                         chains: dict[tuple[str, str], dict]) -> list[str]:
    options: list[str] = []
    endpoints = server_endpoints(ctx)
    if not endpoints:
        ctx.report("找到私钥，但抓包里没有 TLS Client Hello，无法确定服务端地址", "warn")
        return options
    supported = ctx.tshark is None or tlsdeep.rsa_keylist_supported(ctx.tshark.path)
    if not chains:
        ctx.report("未从抓包中提取到证书链（TLS 1.3 需先用 keylog 解密），"
                   "私钥将尝试所有服务端端点", "info")
    for path in paths:
        spki = tlsdeep.spki_from_private_key(path, passphrase)
        fingerprint = tlsdeep.key_fingerprint(spki)
        matched = [(ip, port) for (ip, port), item in chains.items()
                   if spki and item.get("spki") == spki]
        if matched:
            subjects = {chains[endpoint]["leaf"].get("subject", "")
                        for endpoint in matched}
            ctx.report(f"私钥 {path.name} 与证书匹配"
                       f"（{fingerprint or '未知指纹'}，CN={', '.join(filter(None, subjects)) or '-'}）",
                       "good")
            targets = matched
        elif chains:
            ctx.report(f"私钥 {path.name} 与抓包证书不匹配，已跳过；"
                       "请上传正确私钥或提供 tls_key_passphrase", "warn")
            continue
        else:
            targets = endpoints
        for ip, port in targets:
            options += ["-o", f"tls.keys_list:{ip},{port},http,{path}"]
    if options and not supported:
        ctx.report("当前 tshark 已移除 tls.keys_list（RSA 私钥解密）偏好，"
                   "上述私钥无法用于解密；请使用 NSS keylog（推荐），或改用仍支持"
                   "该偏好的 tshark 版本。", "warn")
        return []
    if options:
        shown = ", ".join(f"{ip}:{port}" for ip, port in endpoints[:20])
        ctx.report(f"使用私钥解密端点: {shown}", "info")
    return options


# ---------------------------------------------------------------------------
# Decrypted plaintext helpers
# ---------------------------------------------------------------------------
def _secret_pairs(text: str) -> list[tuple[str, str]]:
    """Credential-looking ``name=value`` pairs from a query/form/JSON blob."""
    pairs: list[tuple[str, str]] = []
    for part in re.split(r"[&;\r\n]+", text or ""):
        name, sep, value = part.partition("=")
        if not sep:
            continue
        name = urllib.parse.unquote_plus(name.strip())[:80]
        value = urllib.parse.unquote_plus(value.strip())[:300]
        if name and value and SECRET_NAME_RE.search(name):
            pairs.append((name, value))
    for match in re.finditer(
            r'["\']([A-Za-z0-9_.-]{2,40})["\']\s*:\s*"([^"]{1,300})"', text or ""):
        name, value = match.groups()
        if SECRET_NAME_RE.search(name):
            pairs.append((name, value))
    return list(dict.fromkeys(pairs))


def _report_credentials(ctx: FeatureContext, *, frame: str, method: str,
                        uri: str, host: str, auth: str, cookie: str,
                        set_cookie: str, body: str) -> int:
    found = 0
    if auth:
        scheme, _, value = auth.partition(" ")
        scheme = scheme.strip().lower()
        if scheme == "basic" and value:
            try:
                decoded = base64.b64decode(value).decode("utf-8", "replace")
                account, _, secret = decoded.partition(":")
                ctx.report(f"帧 {frame} Basic 认证: {decoded}", "good")
                ctx.add_finding("credential", f"TLS Basic 认证 {account}",
                                frame=frame, level="good",
                                detail=f"{method} {uri}\n密码: {secret}",
                                extra={"protocol": "tls-http", "account": account,
                                       "secret": secret, "host": host,
                                       "uri": uri})
                found += 1
            except Exception:  # noqa: BLE001
                ctx.report(f"帧 {frame} Basic 认证（无法解码）", "warn")
        elif scheme == "bearer" and value:
            ctx.report(f"帧 {frame} Bearer Token: {clean_cell(value, 120)}", "good")
            ctx.add_finding("credential", "TLS Bearer Token", frame=frame,
                            level="good", detail=f"{method} {uri}\n{value}",
                            extra={"protocol": "tls-http", "secret": value,
                                   "host": host, "uri": uri})
            found += 1
        elif scheme == "digest":
            for name, secret in re.findall(
                    r"(username|response|nonce)=\"([^\"]+)\"", value):
                ctx.add_finding("credential", f"TLS Digest {name}", frame=frame,
                                detail=f"{method} {uri}\n{secret}",
                                extra={"protocol": "tls-http", "secret": secret})
                found += 1

    sources = [("URI", urllib.parse.urlparse(uri).query),
               ("表单", body)]
    for label, text in sources:
        for name, secret in _secret_pairs(text)[:20]:
            ctx.report(f"帧 {frame} {label}凭据 {name}={secret}", "warn")
            ctx.add_finding("credential", f"TLS {label}凭据 {name}", frame=frame,
                            level="warn", detail=f"{method} {uri}\n{name}={secret}",
                            extra={"protocol": "tls-http", "account": name,
                                   "secret": secret, "host": host, "uri": uri})
            found += 1
    for value in JWT_RE.findall(" ".join([auth, cookie, set_cookie, body]))[:10]:
        ctx.add_finding("credential", "TLS JWT", frame=frame, level="good",
                        detail=f"{method} {uri}\n{value}",
                        extra={"protocol": "tls-http", "secret": value,
                               "host": host, "uri": uri})
        found += 1
    return found


def _write_csv(ctx: FeatureContext, name: str, header: list[str],
               rows: list[list[str]]) -> None:
    if not rows:
        return
    lines = ["\t".join(header)]
    lines += ["\t".join(str(cell).replace("\t", " ").replace("\n", " ")
                        for cell in row) for row in rows]
    ctx.write_output(name, "\n".join(lines) + "\n")


def _analyze_http2(ctx: FeatureContext, options: list[str]) -> int:
    fields = ["frame.number", "http2.headers.method", "http2.headers.authority",
              "http2.headers.path", "http2.headers.status", "http2.headers.cookie",
              "http2.headers.authorization", "http2.headers.content_type",
              "http2.data.data"]
    if ctx.tshark is None:
        return 0
    rows = ctx.tshark.fields(ctx.pcap, fields, "http2", extra=options,
                             cancel=ctx.cancel)
    if not rows:
        return 0
    secrets = 0
    grpc = 0
    csv_rows: list[list[str]] = []
    for raw in rows[:2000]:
        row = list(raw) + [""] * (len(fields) - len(raw))
        frame, method, authority, path, status, cookie, auth, ctype, data = row
        if not any(row[:8]):
            continue
        proto = "gRPC" if "grpc" in (ctype or "").lower() else "HTTP/2"
        if proto == "gRPC":
            grpc += 1
        uri = f"https://{authority}{path}" if authority else path
        body = ""
        for chunk in (data or "").split(","):
            raw_bytes = hex_to_bytes(chunk)
            if raw_bytes:
                body += payload_text(raw_bytes)
        if auth or cookie or body:
            secrets += _report_credentials(
                ctx, frame=frame, method=method or "DATA", uri=uri,
                host=authority, auth=auth, cookie=cookie, set_cookie="",
                body=body)
        for flag in FLAG_LIKE_RE.findall(" ".join([path, body])):
            ctx.report(f"发现 flag: {flag}", "good")
            ctx.add_finding("flag", flag, frame=frame,
                            detail=f"TLS 解密后的 {proto} 正文", level="good")
        ctx.report(f"帧 {frame} [{proto}] {status or '-'} {method or 'DATA'} {uri}",
                   "info")
        csv_rows.append([frame, proto, status, method, authority, path,
                         ctype, cookie, auth, clean_cell(body, 300)])
    if grpc:
        ctx.report(f"其中 {grpc} 个 gRPC 请求（content-type: application/grpc）",
                   "info")
    ctx.report(f"解密后 HTTP/2 记录 {len(rows)} 条", "good")
    _write_csv(ctx, "tls_http2.csv",
               ["帧", "协议", "状态", "方法", "主机", "路径", "类型",
                "Cookie", "认证", "正文"], csv_rows)
    return secrets


def _analyze_websocket(ctx: FeatureContext, options: list[str]) -> int:
    fields = ["frame.number", "tcp.stream", "websocket.opcode",
              "websocket.payload"]
    if ctx.tshark is None:
        return 0
    rows = ctx.tshark.fields(ctx.pcap, fields, "websocket", extra=options,
                             cancel=ctx.cancel)
    if not rows:
        return 0
    count = 0
    lines: list[str] = []
    for raw in rows[:5000]:
        row = list(raw) + [""] * (len(fields) - len(raw))
        frame, stream, opcode, payload = row
        data = hex_to_bytes(payload)
        text = payload_text(data)
        if not text:
            continue
        count += 1
        lines.append(f"[{frame}] stream={stream} opcode={opcode} {clean_cell(text, 300)}")
        for flag in FLAG_LIKE_RE.findall(text):
            ctx.report(f"发现 flag: {flag}", "good")
            ctx.add_finding("flag", flag, frame=frame,
                            detail="TLS 解密后的 WebSocket 载荷", level="good")
        ctx.add_finding("protocol", f"TLS WebSocket 帧（opcode {opcode or '?'}）",
                        frame=frame, detail=clean_cell(text, 500), level="info")
        for name, secret in _secret_pairs(text)[:10]:
            ctx.add_finding("credential", f"TLS WebSocket 凭据 {name}",
                            frame=frame, detail=f"{name}={secret}",
                            extra={"protocol": "tls-websocket", "secret": secret})
    if count:
        ctx.report(f"解密后 WebSocket 载荷 {count} 条", "good")
        ctx.write_output("tls_websocket.txt", "\n".join(lines) + "\n")
    return count


def _export_objects(ctx: FeatureContext, options: list[str],
                    outdir: Path) -> list[Path]:
    if ctx.tshark is None:
        return []
    run([ctx.tshark.path, "-r", ctx.pcap, *options,
         "--export-objects", f"http,{outdir}"],
        timeout=1800, cancel=ctx.cancel, echo=False)
    return [p for p in outdir.rglob("*") if p.is_file()]


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------
def decrypt(ctx: FeatureContext) -> None:
    _report_handshake(ctx)
    chains = _load_certificates(ctx)
    _report_certificates(ctx, chains)
    _report_key_updates(ctx)
    # QUIC/HTTP3 runs even without a keylog: Initial packets reveal SNI/ALPN.
    quic(ctx, quiet=True)

    keylogs, keys = _resolve_keys(ctx)
    if not keylogs and not keys:
        discovered = discover_keys()
        ctx.report("未配置 TLS keylog 或私钥。", "warn")
        if discovered["keylog"] or discovered["key"]:
            ctx.report("已发现可用的密钥文件（可在设置中使用）:", "info")
            for kind, paths in discovered.items():
                for path in paths:
                    ctx.report(f"  [{kind}] {path}", "info")
        ctx.report("获取 keylog：设置环境变量 SSLKEYLOGFILE 后让浏览器/客户端访问目标，"
                   "或在“设置 → 上传 TLS keylog / 私钥…”里上传文件。", "info")
        return

    options: list[str] = []
    if keylogs:
        options += _keylog_options(keylogs)
        head = ""
        try:
            latest = max(keylogs, key=lambda item: item.stat().st_mtime)
            head = latest.read_text(encoding="utf-8", errors="ignore")[:4000]
        except OSError:
            pass
        if head and not any(marker in head for marker in KEYLOG_MARKERS):
            ctx.report("警告：keylog 文件看起来不是 NSS keylog 格式", "warn")
        ctx.report("使用 keylog 解密 TLS…", "info")
        _report_keylog_coverage(ctx, keylogs)
    if keys:
        prepared, passphrase = _prepare_private_keys(ctx, keys)
        if prepared:
            key_options = _private_key_options(ctx, prepared, passphrase, chains)
            options += key_options
            ctx.report("使用 RSA 私钥补充分支解密…", "info")

    if ctx.tshark is None:
        ctx.report("该功能需要 tshark", "error")
        return

    fields = ["frame.number", "http.request.method", "http.request.full_uri",
              "http.host", "http.request.uri", "http.response.code",
              "http.content_type", "http.content_encoding", "http.file_data",
              "http.cookie", "http.set_cookie", "http.authorization",
              "http.user_agent"]
    cmd = [ctx.tshark.path, "-r", ctx.pcap, *options, "-T", "fields"]
    for field in fields:
        cmd += ["-e", field]
    cmd += ["-Y", "http", "-E", "separator=\t", "-E", "occurrence=a",
            "-E", "quote=d"]
    code, out = run(cmd, timeout=1800, cancel=ctx.cancel, echo=False)
    if code != 0:
        ctx.report(f"tshark 解密失败: {out[-1500:]}", "error")
        return
    decrypted = 0
    secrets = 0
    csv_rows: list[list[str]] = []
    for line in out.splitlines():
        if not line.strip():
            continue
        values = [v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v
                  for v in line.split("\t")]
        values += [""] * (len(fields) - len(values))
        (frame, method, uri, host, path, rcode, ctype, cencoding, body,
         cookie, set_cookie, auth, agent) = values[:13]
        if not any(values[:8]):
            continue
        decrypted += 1
        ctx.report(f"帧 {frame} [{rcode}] {method} https://{host}{uri or path}", "good")
        ctx.add_finding("http", f"TLS 解密 {method} https://{host}{uri or path}",
                        frame=frame,
                        detail=f"状态 {rcode} · {ctype} · UA {clean_cell(agent, 120)}",
                        level="info")
        if cookie:
            ctx.report(f"  Cookie: {clean_cell(cookie, 240)}", "info")
        if set_cookie:
            ctx.report(f"  Set-Cookie: {clean_cell(set_cookie, 240)}", "info")
        text = ""
        if body:
            data = hex_to_bytes(body)
            text = payload_text(data)
            for body_line in text.splitlines()[:30]:
                if body_line.strip():
                    ctx.report("  " + clean_cell(body_line, 260), "info")
            for flag in codec.find_flags(text) + FLAG_LIKE_RE.findall(text):
                ctx.report(f"发现 flag: {flag}", "good")
                ctx.add_finding("flag", flag, frame=frame,
                                detail="TLS 解密后的 HTTP 正文", level="good")
        secrets += _report_credentials(
            ctx, frame=frame, method=method, uri=f"https://{host}{uri or path}",
            host=host, auth=auth, cookie=cookie, set_cookie=set_cookie,
            body=text)
        csv_rows.append([frame, method, host, uri or path, rcode, ctype,
                         clean_cell(cookie, 200), clean_cell(auth, 200),
                         clean_cell(agent, 120),
                         "gzip" if "gzip" in cencoding.lower() else ""])

    if not decrypted:
        ctx.report("密钥未能解密出 HTTP 明文（可能密钥不匹配或流量非 HTTP）", "warn")
        available = discover_keys()
        candidates = available["keylog"] + available["key"]
        if candidates:
            ctx.report("本机可用的密钥文件（可在设置中切换后重试）:", "info")
            for item in candidates:
                ctx.report(f"  [{key_kind(item) or '未知'}] {item}", "info")
        ctx.report("可尝试：确认抓包时 SSLKEYLOGFILE 已设置、使用完整 keylog、"
                   "或改用与服务器证书匹配的 RSA 私钥（仅限非前向保密套件）。",
                   "info")
    else:
        ctx.report(f"共解密 {decrypted} 个 HTTP 报文", "good")
        if secrets:
            ctx.report(f"从解密明文提取 {secrets} 个凭据/令牌", "good")
        _write_csv(ctx, "tls_decrypted_http.csv",
                   ["帧", "方法", "主机", "URI", "状态", "类型", "Cookie",
                    "认证", "User-Agent", "编码"], csv_rows)

    # Continue analysis on the decrypted protocols beyond plain HTTP.
    h2 = _analyze_http2(ctx, options)
    ws = _analyze_websocket(ctx, options)
    if h2 or ws:
        ctx.report(f"解密后协议分析: HTTP/2 {h2} 条凭据 · WebSocket {ws} 帧", "info")

    # Export objects through the decrypted TLS session.
    outdir = Path(ctx.output_dir or ".") / "tls_http_objects"
    outdir.mkdir(parents=True, exist_ok=True)
    files = _export_objects(ctx, options, outdir)
    if files:
        ctx.report(f"导出 {len(files)} 个 TLS 内的 HTTP 对象到 {outdir}", "good")
    manifest: list[list[str]] = []
    for flagfile in files:
        try:
            data = flagfile.read_bytes()
        except OSError:
            continue
        text = data.decode("utf-8", "ignore")
        digest = hashlib.md5(data).hexdigest()
        manifest.append([flagfile.relative_to(outdir).as_posix(), str(len(data)),
                         file_magic(flagfile), digest])
        ctx.add_finding("file", flagfile.relative_to(outdir).as_posix(),
                        detail=f"{len(data)} 字节 · {file_magic(flagfile)} · "
                               f"md5={digest}", level="good")
        for flag in codec.find_flags(text):
            ctx.report(f"发现 flag: {flag}", "good")
            ctx.add_finding("flag", flag, frame="",
                            detail=f"TLS 导出文件 {flagfile.name}", level="good")
    _write_csv(ctx, "tls_http_objects.csv",
               ["文件", "大小", "类型", "MD5"], manifest)
    ctx.set_progress(100)


def quic(ctx: FeatureContext, quiet: bool = False) -> None:
    """Identify QUIC/HTTP3 flows and summarise their TLS/HTTP3 metadata.

    ``tls.decrypt`` calls this with ``quiet=True`` so captures without QUIC do
    not produce a warning; the handler can still be selected directly as
    ``tls.quic`` from the CLI or the special-features menu.
    """
    rows = tshark_rows(ctx, QUIC_FIELDS, "quic", limit=100_000)
    if not rows:
        if not quiet:
            ctx.report("未发现 QUIC/HTTP3 流量", "warn")
        return
    failed = tshark_rows(ctx, ["frame.number", "quic.decryption_failed"],
                         "quic.decryption_failed", limit=2000)
    connections = tlsdeep.quic_connections(rows)
    if failed:
        ctx.report(f"{len(failed)} 个 QUIC 包解密失败（握手密钥不完整或使用了 "
                   "不支持的版本）", "warn")

    versions: dict[str, int] = {}
    for item in connections:
        item["version_names"] = [tlsdeep.quic_version_name(value)
                                 for value in item["versions"]]
        for name in item["version_names"] or ["未知版本"]:
            versions[name] = versions.get(name, 0) + 1
    ctx.report(f"发现 {len(connections)} 个 QUIC 连接，"
               + ", ".join(f"{name}×{count}" for name, count in versions.items()),
               "good")

    table_fields = ["客户端", "服务端", "版本", "SNI", "ALPN", "帧", "包类型"]
    table_rows = []
    for item in connections[:100]:
        table_rows.append([
            item["client"], item["server"],
            ", ".join(item["version_names"]) or "-",
            ", ".join(item["sni"]) or "-", ", ".join(item["alpn"]) or "-",
            str(item["frames"]),
            ", ".join(f"{name}×{count}" for name, count in
                      item["packet_types"].items()),
        ])
        if item["sni"]:
            ctx.add_finding("protocol", f"QUIC 连接 {item['sni'][0]}",
                            frame=item["frames_list"][0] if item["frames_list"] else "",
                            detail=(f"{item['client']} → {item['server']} · "
                                    f"{', '.join(item['version_names'])} · "
                                    f"ALPN {', '.join(item['alpn']) or '-'} · "
                                    f"{item['frames']} 帧"),
                            level="info")
    table(ctx, "QUIC 连接", table_fields, table_rows, cell_limit=200)
    csv_rows = [[item["client"], item["server"],
                 " ".join(item["version_names"]), " ".join(item["sni"]),
                 " ".join(item["alpn"]), str(item["frames"]),
                 str(item["bytes"]),
                 " ".join(f"{name}={count}"
                          for name, count in item["packet_types"].items())]
                for item in connections]
    _write_csv(ctx, "quic_connections.csv",
               ["客户端", "服务端", "版本", "SNI", "ALPN", "帧", "字节", "包类型"],
               csv_rows)

    keylogs, _keys = _resolve_keys(ctx)
    if not keylogs:
        ctx.report("已识别 QUIC；配置 TLS keylog 后可进一步解密 HTTP/3 头与正文。"
                   "Wireshark 会先用版本内置 salt 解密 Initial，因此 SNI/ALPN 通常"
                   "无需密钥即可看到。", "info")
        ctx.set_progress(100)
        return

    options = _keylog_options(keylogs)
    fields = ["frame.number", "http3.headers.method", "http3.headers.scheme",
              "http3.headers.authority", "http3.headers.path",
              "http3.headers.status", "http3.headers.cookie",
              "http3.headers.authorization", "http3.headers.content_type",
              "http3.body.reassembled.data"]
    if ctx.tshark is None:
        return
    h3_rows = ctx.tshark.fields(ctx.pcap, fields, "http3", extra=options,
                                cancel=ctx.cancel)
    if not h3_rows:
        ctx.report("keylog 未能解密 HTTP/3 头；请确认 keylog 包含该连接的 TLS 1.3 "
                   "traffic secret，并保持抓包包含完整握手。", "warn")
        ctx.set_progress(100)
        return
    h3_csv: list[list[str]] = []
    for raw in h3_rows[:2000]:
        row = list(raw) + [""] * (len(fields) - len(raw))
        (frame, method, scheme, authority, path, status, cookie, auth,
         ctype, body_hex) = row
        uri = f"{scheme or 'https'}://{authority}{path}"
        body = payload_text(hex_to_bytes(body_hex))
        ctx.report(f"帧 {frame} [{status or '-'}] {method or 'DATA'} {uri}", "good")
        ctx.add_finding("http", f"QUIC/HTTP3 {method} {uri}", frame=frame,
                        detail=f"状态 {status} · {ctype}", level="info")
        _report_credentials(ctx, frame=frame, method=method, uri=uri,
                            host=authority, auth=auth, cookie=cookie,
                            set_cookie="", body=body)
        for flag in codec.find_flags(body):
            ctx.add_finding("flag", flag, frame=frame,
                            detail="QUIC/HTTP3 解密正文", level="good")
        h3_csv.append([frame, method, authority, path, status, ctype,
                       clean_cell(cookie, 200), clean_cell(auth, 200),
                       clean_cell(body, 300)])
    _write_csv(ctx, "http3_requests.csv",
               ["帧", "方法", "主机", "路径", "状态", "类型", "Cookie", "认证",
                "正文"], h3_csv)
    ctx.report(f"解密出 {len(h3_rows)} 条 HTTP/3 记录", "good")
    ctx.set_progress(100)
