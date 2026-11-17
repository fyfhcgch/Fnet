"""HTTP extraction, login correlation and file export."""
from __future__ import annotations

import base64
import hashlib
import re
from collections import Counter
from pathlib import Path

from fnet.features.common import clean_cell, tshark_rows
from fnet.features.registry import FeatureContext
from fnet.utils.pcap import file_magic, hex_to_bytes, payload_text, printable_ratio

FIELDS = [
    "frame.number",
    "tcp.stream",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.request.full_uri",
    "http.user_agent",
    "http.cookie",
    "http.authorization",
    "http.response.code",
    "http.content_type",
    "http.referer",
    "http.response_in",
    "http.request_in",
    "http.file_data",
    "urlencoded-form.key",
    "urlencoded-form.value",
]

LOGIN_HINTS = re.compile(
    r"(user(name)?|account|login|pass(word)?|pwd|email|token|session|admin)",
    re.IGNORECASE,
)
SUCCESS_HINTS = re.compile(
    r"(success|登录成功|welcome|dashboard|logout|退出|token|set-cookie|index)",
    re.IGNORECASE,
)


def _pair(rows: list[list[str]]) -> tuple[list[dict], dict[str, dict], dict[str, dict]]:
    """Split tshark HTTP rows into requests/responses.

    ``http.response_in`` is only populated by tshark in two-pass mode, so the
    responses are also indexed by the ``http.request_in`` they answer.  That
    keeps a single pass fast while still pairing request/response reliably.
    """
    requests: list[dict] = []
    responses: dict[str, dict] = {}
    by_request: dict[str, dict] = {}
    for raw in rows:
        row = raw + [""] * (len(FIELDS) - len(raw))
        item = dict(zip(FIELDS, row))
        if item["http.response.code"]:
            responses[item["frame.number"]] = item
            parent = item.get("http.request_in")
            if parent:
                by_request[parent] = item
        elif item["http.request.method"] or item["http.request.uri"]:
            requests.append(item)
    return requests, responses, by_request


def _response_for(request: dict, responses: dict[str, dict],
                  by_request: dict[str, dict]) -> dict | None:
    target = request.get("http.response_in")
    if target and target in responses:
        return responses[target]
    return by_request.get(request["frame.number"])


def _form_credentials(form: str) -> tuple[str, str]:
    """Pull a likely username/password pair out of an urlencoded form."""
    account = secret = ""
    for part in (form or "").split("&"):
        key, _, value = part.partition("=")
        key = key.strip().lower()
        if not key or not value:
            continue
        if not account and key in ("user", "username", "login", "account",
                                   "email", "uname"):
            account = value
        elif not secret and key in ("pass", "password", "pwd", "passwd"):
            secret = value
    return account, secret


def extract(ctx: FeatureContext) -> None:
    rows = tshark_rows(ctx, FIELDS, "http", limit=100_000)
    if not rows:
        ctx.report("未发现 HTTP 流量", "warn")
        return

    requests, responses, by_request = _pair(rows)
    methods = Counter()
    hosts = Counter()
    codes = Counter()
    uris: list[str] = []
    logins: list[dict] = []
    basic_auth: list[str] = []
    cookies: Counter = Counter()
    successes: list[dict] = []

    for index, req in enumerate(requests):
        if index % 200 == 0:
            ctx.set_progress(int(index / max(len(requests), 1) * 85))
            ctx.check_cancel()
        resp = _response_for(req, responses, by_request)
        method = req["http.request.method"].upper()
        uri = req["http.request.full_uri"] or req["http.request.uri"]
        if method:
            methods[method] += 1
        if req["http.host"]:
            hosts[req["http.host"]] += 1
        if resp and resp["http.response.code"]:
            codes[resp["http.response.code"]] += 1
        if uri:
            uris.append(uri)
        if req["http.cookie"]:
            for part in req["http.cookie"].split(";"):
                name = part.split("=", 1)[0].strip()
                if name:
                    cookies[name] += 1
        auth = req["http.authorization"]
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth.split(None, 1)[1]).decode("utf-8", "replace")
                basic_auth.append(f"帧 {req['frame.number']} {decoded}")
                account, _, secret = decoded.partition(":")
                ctx.add_finding("credential", f"Basic 认证 {decoded}",
                                frame=req["frame.number"], level="good",
                                detail=f"{method} {uri}", extra={
                                    "protocol": "http",
                                    "account": account,
                                    "secret": secret,
                                    "host": req["http.host"],
                                })
            except Exception:  # noqa: BLE001
                basic_auth.append(f"帧 {req['frame.number']} {auth}")
                ctx.add_finding("credential", "Basic 认证（未能解码）",
                                frame=req["frame.number"], level="warn",
                                detail=auth)

        body = ""
        if resp and resp["http.file_data"]:
            body = payload_text(hex_to_bytes(resp["http.file_data"]))
        form = ""
        if req["http.file_data"]:
            raw_req = payload_text(hex_to_bytes(req["http.file_data"]))
            if printable_ratio(hex_to_bytes(req["http.file_data"])) > 0.6:
                form = raw_req.strip().replace("\r", "").split("\n")[0][:400]
        if not form and req["urlencoded-form.key"]:
            keys = [part for part in req["urlencoded-form.key"].split(",") if part]
            values = [part for part in req["urlencoded-form.value"].split(",") if part]
            form = "&".join(f"{key}={value}" for key, value in zip(keys, values))[:400]
        hint_text = " ".join([uri or "", form, body[:2000]])
        if method in ("POST", "PUT") and LOGIN_HINTS.search(hint_text):
            success = bool(resp and resp["http.response.code"][:1] in ("2", "3")
                           and (not body or SUCCESS_HINTS.search(body)))
            logins.append({"frame": req["frame.number"], "uri": uri,
                           "form": form, "code": resp["http.response.code"] if resp else "",
                           "stream": req["tcp.stream"], "success": success,
                           "body": body[:600]})
            form_user, form_secret = _form_credentials(form)
            ctx.add_finding(
                "credential" if success else "http",
                f"{method} {uri}",
                frame=req["frame.number"],
                level="good" if success else "warn",
                detail=f"表单: {form}\n状态: {resp['http.response.code'] if resp else '-'}"
                       + (f"\n响应: {body[:400]}" if body else ""),
                extra={"protocol": "http", "account": form_user,
                       "secret": form_secret, "host": req["http.host"],
                       "success": "1" if success else "0"})
            if success:
                successes.append(logins[-1])

    ctx.report(f"HTTP 请求 {len(requests)} 条，响应 {len(responses)} 条", "good")
    ctx.report("方法: " + ", ".join(f"{k}={v}" for k, v in methods.most_common()), "info")
    ctx.report("状态码: " + ", ".join(f"{k}={v}" for k, v in codes.most_common()), "info")
    for host, count in hosts.most_common(30):
        ctx.report(f"Host {host} ({count})", "info")
    for uri in dict.fromkeys(uris):
        ctx.report(f"URI {clean_cell(uri, 300)}", "info")
    if basic_auth:
        ctx.report("===== Basic 认证 =====", "good")
        for line in basic_auth[:100]:
            ctx.report(line, "good")
    if cookies:
        ctx.report("Cookie 名称: " + ", ".join(f"{k}({v})" for k, v in cookies.most_common(30)),
                   "info")

    if logins:
        ctx.report("===== 疑似登录请求 =====", "warn")
        for item in logins[:100]:
            level = "good" if item["success"] else "warn"
            ctx.report(
                f"帧 {item['frame']} [{item['code']}] {item['uri']} {item['form']}",
                level)
            if item["success"] and item["body"]:
                snippet = clean_cell(item["body"], 300)
                ctx.report(f"    响应: {snippet}", "good")
    if successes:
        ctx.report(f"识别到 {len(successes)} 个可能登录成功的账号密码：", "good")
        for item in successes:
            ctx.report(f"  {item['uri']}  {item['form']}", "good")
    ctx.set_progress(100)


def export_files(ctx: FeatureContext) -> None:
    if ctx.tshark is None:
        ctx.report("该功能需要 tshark", "error")
        return
    outdir = Path(ctx.output_dir or ".") / "http_objects"
    ctx.report(f"导出 HTTP 对象到 {outdir}", "info")
    code, out = ctx.tshark.export_objects(ctx.pcap, "http", outdir,
                                          cancel=ctx.cancel)
    if code != 0 and not outdir.exists():
        ctx.report("导出 HTTP 对象失败: " + out.strip(), "error")
        return
    files = [p for p in outdir.rglob("*") if p.is_file()]
    if not files:
        ctx.report("没有可导出的 HTTP 对象", "warn")
        return
    ctx.report(f"导出 {len(files)} 个文件", "good")
    total = 0
    for index, path in enumerate(files):
        if index % 50 == 0:
            ctx.set_progress(int(index / len(files) * 100))
            ctx.check_cancel()
        data = path.read_bytes()
        total += len(data)
        digest = hashlib.md5(data).hexdigest()
        ctx.report(
            f"{path.relative_to(outdir)}  {len(data)} 字节  {file_magic(path)}  md5={digest}",
            "info")
        ctx.add_finding("file", path.relative_to(outdir).as_posix(),
                        detail=f"{len(data)} 字节 · {file_magic(path)} · md5={digest}")
    ctx.report(f"合计 {total} 字节，{len(files)} 个文件", "good")
    ctx.set_progress(100)
