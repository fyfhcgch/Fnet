"""SMB3 解密对话框的“自动填入”建议。

WebUI 的 **SMB3 解密** 对话框需要六个参数：明文密码 / NT 哈希 / 会话密钥 /
账号 / 域 / TCP 流。这些信息其实大多已经躺在同一个任务的结构化结果里，只是
分散在不同功能写下的 findings 中：

* :mod:`fnet.features.smb` 的 ``SMB 账号 …`` / ``SMB NetNTLMv2 …`` 结果给出
  账号、域、流和 NetNTLMv2 抓哈希；``SMB3 加密流量`` 结果给出流和会话 ID，
  较新的版本还会把账号一起带进来（用于把账号和流绑定）；
* :mod:`fnet.features.ntlm` 的 ``NTLM HASH提取``（``extra.protocol == "ntlm"``）
  也带 NetNTLMv2 抓哈希，但**没有** ``stream`` / ``user`` 键：从 ``account``
  的最后一个反斜杠后取用户名，再按账号身份与上面的结果合并；
* :mod:`fnet.features.ntlm_verify` / :mod:`fnet.features.smb_intel` 的
  ``NTLM 密码验证命中`` 给出已验证的明文密码（可能只有 ``account`` 标签，
  没有 ``user`` / ``domain`` / ``stream``）；
* 上次成功解密落盘的 ``smb3_keys.txt``（见 :func:`fnet.smb3.read_keys_file`）
  带着会话密钥；
* 调用方还可以传入正在运行的 hashcat / 本地 NTLM 破解任务的结果。

历史任务里还会有 ``SMB 候选密码 流 N``（``extra.candidates`` 是一大串候选）
和 ``SMB 协商`` 这类纯信息结果：它们一律不作为填入来源，候选字符串绝不会被
当成明文密码。

本模块把这些来源拼成一份建议字典，**完全离线**：不启动 tshark、不调用
hashcat、不联网，也不修改任何文件。:func:`decrypt_hints` 保证永不抛异常，
脏数据（非字典、``None``、被 ``findings.make()`` 字符串化的 ``session`` 字段、
超长字段）只会退化成空建议或带中文说明的空建议。

注意 ``nt_hash``：对话框里的 NT 哈希只接受裸的 32 位十六进制 NT 哈希。
NetNTLMv2 抓哈希（``user::domain:challenge:client_blob:crack_blob``）包含
``:`` 且远长于 32 位，**绝不**填进 ``nt_hash``；它会原样出现在
``accounts[].hash`` 里，必须先 ``hashcat -m 5600`` 破解成明文密码，或用
NTLM 验证功能命中口令，才能作为密码填入对话框。

公开接口：:func:`decrypt_hints`（纯数据）与 :func:`hints_for_job`
（从任务目录读结果后再调用前者）。
"""
from __future__ import annotations

import re
from pathlib import Path

from fnet import smb3

#: 对话框里可以直接填的字段（顺序即备注行的顺序）。
FIELDS = ("password", "nt_hash", "session_key", "user", "domain", "stream")

#: ``accounts`` 里每条候选账号的字段。
ACCOUNT_FIELDS = ("user", "domain", "stream", "password", "nt_hash",
                  "hash", "mode", "source")

#: 上一次 SMB3 解密的会话密钥来源（供 sources 显示）。
KEY_SOURCE_LABEL = "上次 SMB3 解密（smb3_keys.txt）"

MAX_NOTES = 8

# 私有上限：一份建议的体量与单字段长度都必须可预测，避免脏 capture 把
# GET /api/smb/hints 撑爆。公开常量只有一个 MAX_NOTES，保持不变。
_MAX_ACCOUNTS = 64
_MAX_IDENTITY = 128
_MAX_HASH = 200
_MAX_SOURCE = 200
_MAX_PASSWORD = 200
_MAX_TEXT = 256
_MAX_NOTE = 400
_MAX_RECORDS = 20_000

_NT_HASH = re.compile(r"[0-9a-fA-F]{32}")
_SESSION_KEY = re.compile(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{64}")
_DIGITS = re.compile(r"\d+")
_TRUE_TEXT = frozenset({"1", "true", "yes", "on"})

NOTHING_NOTE = ("没有发现任何可用的 SMB3 解密线索：请先运行 NTLM 验证 / SMB "
                 "密码候选 破解 NetNTLMv2，或手动填写账号、密码与会话密钥")


# ---------------------------------------------------------------------------
# 小工具：所有取值都必须是“脏数据也不会炸”的
# ---------------------------------------------------------------------------
def _clip(text: str, limit: int) -> str:
    return text[:limit] if len(text) > limit else text


def _text(value, limit: int = _MAX_TEXT) -> str:
    """Best-effort clipped string; structured/odd values become ``""``."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return ""
    if isinstance(value, (bytes, bytearray)):
        try:
            value = bytes(value).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - 建议功能绝不升级成异常
            return ""
    if isinstance(value, (dict, list, tuple, set, frozenset)):
        # findings.make() 会把字典字符串化（例如 SMB3 解密成功的 session），
        # 这种值我们一律不猜内容；真正传进来的结构化值同样忽略。
        return ""
    try:
        text = str(value).strip()
    except Exception:  # noqa: BLE001
        return ""
    return _clip(text, limit)


def _truthy(value) -> bool:
    """``verified`` 可能是 bool / int / 被字符串化的 ``True``。"""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return _text(value, 16).lower() in _TRUE_TEXT


def _digits(value) -> str:
    """Only accept a plain TCP stream number."""
    text = _text(value, 40)
    return text if _DIGITS.fullmatch(text) else ""


def _hex(value, pattern: re.Pattern) -> str:
    text = _text(value, _MAX_HASH).replace(" ", "").replace(":", "")
    if not pattern.fullmatch(text):
        return ""
    return text.lower()


def _extra(record) -> dict:
    if not isinstance(record, dict):
        return {}
    found = record.get("extra")
    if not isinstance(found, dict):
        return {}
    return found


def _records(value) -> list[dict]:
    """Tolerate any iterable of dicts (findings, cracked, saved keys)."""
    try:
        items = []
        for index, item in enumerate(value or []):
            if index >= _MAX_RECORDS:
                break
            items.append(item)
    except Exception:  # noqa: BLE001 - 不可迭代 / 迭代中途出错都要降级
        return []
    return [item for item in items if isinstance(item, dict)]


def _frame_of(record, extra: dict) -> str:
    return _digits(record.get("frame")) or _digits(extra.get("first_frame"))


def _source(label: str, frame: str) -> str:
    """``SMB NTLM 认证（帧 12）`` 风格的来源说明。"""
    label = _text(label, 160)
    if frame:
        label = f"{label}（帧 {frame}）"
    return _clip(label, _MAX_SOURCE)


def _account_label(user: str, domain: str) -> str:
    user = _text(user, _MAX_IDENTITY)
    domain = _text(domain, _MAX_IDENTITY)
    if domain and user:
        return f"{domain}\\{user}"
    return user or domain or ""


def _noisy(record, extra: dict) -> bool:
    """旧任务里的候选密码/协商信息行不是解密线索。"""
    if "candidates" in extra:
        return True
    if _text(extra.get("smb"), 32).lower() in (
            "negotiate", "candidate", "candidates", "compressed"):
        return True
    summary = _text(record.get("summary"), 200)
    if "SMB 协商" in summary:
        return True
    if "候选" in summary and ("密码" in summary or "口令" in summary):
        return True
    return False


# ---------------------------------------------------------------------------
# 账号表
# ---------------------------------------------------------------------------
def _refresh_key(item: dict) -> None:
    item["_key"] = (item["user"].upper(), item["domain"].upper(),
                    item["stream"])


def _new_account(user: str, domain: str, stream: str) -> dict:
    item = {name: "" for name in ACCOUNT_FIELDS}
    item["user"] = _text(user, _MAX_IDENTITY)
    item["domain"] = _text(domain, _MAX_IDENTITY)
    item["stream"] = _digits(stream)
    item["_password_source"] = ""
    item["_nt_source"] = ""
    item["_hash_rank"] = 0
    _refresh_key(item)
    return item


def _fill_identity(item: dict, user: str, domain: str, stream: str) -> None:
    """合并同一账号从不同来源带来的身份/流（只补空，不覆盖已有值）。"""
    before = (item["user"], item["domain"], item["stream"])
    if not item["user"]:
        item["user"] = _text(user, _MAX_IDENTITY)
    if not item["domain"]:
        item["domain"] = _text(domain, _MAX_IDENTITY)
    if not item["stream"]:
        item["stream"] = _digits(stream)
    if (item["user"], item["domain"], item["stream"]) != before:
        _refresh_key(item)


def _split_account(account: str, user: str, domain: str) -> tuple[str, str]:
    """``CORP\\alice`` / ``alice`` 补齐缺失的 user / domain。

    ``NTLM HASH提取`` 有 ``domain`` 却没有 ``user``，仍要从 ``account`` 的
    最后一个反斜杠后取用户名；反之亦然。
    """
    account = _text(account, _MAX_IDENTITY)
    user = _text(user, _MAX_IDENTITY)
    domain = _text(domain, _MAX_IDENTITY)
    if not user and account:
        if "\\" in account:
            head, _, tail = account.rpartition("\\")
            user = tail
            if not domain:
                domain = head
        elif "@" in account:
            head, _, tail = account.partition("@")
            user = head
            if not domain:
                domain = tail
        else:
            user = account
    return user, domain


def _account(accounts: list[dict], user: str, domain: str, stream: str,
             account: str = "", state: dict | None = None) -> dict:
    user = _text(user, _MAX_IDENTITY)
    domain = _text(domain, _MAX_IDENTITY)
    stream = _digits(stream)
    user, domain = _split_account(account, user, domain)

    # 主去重键严格按 (user.upper(), domain.upper(), stream)。
    key = (user.upper(), domain.upper(), stream)
    for item in accounts:
        if item["_key"] == key:
            _fill_identity(item, user, domain, stream)
            return item

    # NTLM HASH提取 / 验证命中往往没有 stream：与同身份、只是一侧缺流的
    # SMB 凭据合并，而不是另起一条孤立的账号（否则密码会挂到“空流”副本上）。
    if user or domain:
        for item in accounts:
            if (item["user"].upper(), item["domain"].upper()) != \
                    (user.upper(), domain.upper()):
                continue
            if not item["stream"] or not stream:
                _fill_identity(item, user, domain, stream)
                return item

    if len(accounts) >= _MAX_ACCOUNTS:
        # 返回不入表的临时对象：调用方照常写字段，但最终不会出现在结果里。
        if state is not None:
            state["capped"] = True
        return _new_account(user, domain, stream)
    item = _new_account(user, domain, stream)
    accounts.append(item)
    return item


def _match_account(accounts: list[dict], user: str, domain: str,
                   stream: str = "") -> dict | None:
    """忽略大小写地找账号；身份不全时也不跨流猜。"""
    user = _text(user, _MAX_IDENTITY).upper()
    domain = _text(domain, _MAX_IDENTITY).upper()
    stream = _digits(stream)
    if not (user or domain):
        return None
    pool = [item for item in accounts
            if item["stream"] == stream] if stream else accounts
    if stream and not pool:
        return None
    for item in pool:  # user+domain 同时命中最优先
        if user and domain and item["user"].upper() == user \
                and item["domain"].upper() == domain:
            return item
    for item in pool:  # 只给了 user（或只给了 domain）时放宽一个维度
        if user and not domain and item["user"].upper() == user:
            return item
        if domain and not user and item["domain"].upper() == domain:
            return item
    return None


def _attach_hash(item: dict, extra: dict, record, bare: list,
                 rank: int = 0) -> None:
    """记录 NetNTLMv2 抓哈希 / 裸 NT 哈希。

    ``rank`` 让同一账号的多条抓哈希有稳定的优先级：专门的 NTLM HASH提取
    结果胜过 SMB 凭据结果，后者胜过加密流量结果里附带的副本。
    """
    frame = _frame_of(record, extra)
    line = _text(extra.get("hash"), _MAX_HASH)
    if line and ":" in line and (
            not item["hash"] or rank > item.get("_hash_rank", 0)):
        # NetNTLMv2：只能破解，不能当 NT 哈希用
        item["hash"] = line
        item["mode"] = _text(extra.get("mode"), 32) or "5600"
        item["_hash_rank"] = rank
    # 只有原本就不带冒号的值才可能是裸 NT 哈希；冒号剥掉后恰好 32 位也不收。
    bare_line = line if ":" not in line else ""
    value = _hex(extra.get("nt_hash"), _NT_HASH) or _hex(bare_line, _NT_HASH)
    if not value:
        return
    if not item["nt_hash"]:
        item["nt_hash"] = value
        item["_nt_source"] = _source("SMB 账号发现", frame)
    if len(bare) < _MAX_ACCOUNTS:
        bare.append({"user": item["user"], "domain": item["domain"],
                     "value": value, "source": item["_nt_source"]})


def _same_identity(a: dict, b: dict) -> bool:
    if not a or not b:
        return False
    if a.get("user") or b.get("user"):
        if a.get("user", "").upper() != b.get("user", "").upper():
            return False
    if a.get("domain") or b.get("domain"):
        if a.get("domain", "").upper() != b.get("domain", "").upper():
            return False
    return bool(a.get("user") or a.get("domain")
                or b.get("user") or b.get("domain"))


def _stream_sort(value: str):
    return (int(value), value) if value.isdigit() else (10 ** 9, value)


def _final_accounts(accounts: list[dict]) -> list[dict]:
    """按 (数字流, user, domain) 稳定排序、去重并截断到 64 条。"""
    by_key: dict[tuple, dict] = {}
    ordered: list[dict] = []
    for item in sorted(accounts, key=lambda row: (
            _stream_sort(row["stream"]), row["user"], row["domain"])):
        key = item["_key"]
        keep = by_key.get(key)
        if keep is None:
            keep = item
            by_key[key] = keep
            ordered.append(keep)
        else:  # 同键的重复项：把对方的非空字段补进来
            for name in ACCOUNT_FIELDS:
                if not keep[name] and item[name]:
                    keep[name] = item[name]
        if len(ordered) >= _MAX_ACCOUNTS:
            break
    return ordered


# ---------------------------------------------------------------------------
# 主要逻辑
# ---------------------------------------------------------------------------
def _collect(records: list, stream: str, cracked, saved_keys) -> dict:
    accounts: list[dict] = []
    encrypted: list[str] = []          # SMB3 加密流量所在的 TCP 流
    encrypted_frame: dict[str, str] = {}
    hashes: list[dict] = []            # 全局限定的裸 NT 哈希
    passwords: list[dict] = []         # 明文密码候选
    extra_notes: list[str] = []
    state = {"capped": False}

    def get_account(user, domain, stream_id, account=""):
        return _account(accounts, user, domain, stream_id, account, state)

    # --- 账号 / 哈希（SMB2、NTLM HASH提取、带身份的 SMB3 加密流量）--------
    for record in records:
        extra = _extra(record)
        protocol = _text(extra.get("protocol"), 32).lower()
        if protocol not in ("smb2", "ntlm") or _noisy(record, extra):
            continue
        stream_id = _digits(extra.get("stream"))
        frame = _frame_of(record, extra)
        user = _text(extra.get("user"), _MAX_IDENTITY)
        domain = _text(extra.get("domain"), _MAX_IDENTITY)
        account = _text(extra.get("account"), _MAX_IDENTITY)
        smb = _text(extra.get("smb"), 32).lower()
        if smb == "encrypted":
            if stream_id and stream_id not in encrypted:
                encrypted.append(stream_id)
                encrypted_frame[stream_id] = frame
            # 新版加密流量结果自带身份：这是把账号绑到正确流上的关键线索。
            if not (user or domain or account):
                continue
            item = get_account(user, domain, stream_id, account)
            if not item["source"]:
                item["source"] = _source("SMB3 加密流量", frame)
            _attach_hash(item, extra, record, hashes, 1)
            continue
        if not (user or domain or account):
            continue
        item = get_account(user, domain, stream_id, account)
        if not item["source"]:
            kind = _text(record.get("kind"), 32).lower()
            if protocol == "ntlm":
                label = "NTLM HASH提取"
            elif kind == "hash":
                label = "SMB NetNTLMv2 哈希"
            else:
                label = "SMB NTLM 认证"
            item["source"] = _source(label, frame)
        _attach_hash(item, extra, record, hashes,
                     3 if protocol == "ntlm" else 2)

    # --- 明文密码：NTLM 验证命中 + SMB3 智能串联解密成功 + 破解结果 -------
    for record in records:
        extra = _extra(record)
        if _noisy(record, extra):
            continue
        password = _text(extra.get("password"), _MAX_PASSWORD)
        if not password:
            continue
        kind = _text(extra.get("kind"), 32).lower()
        if kind == "ntlm-password" or _truthy(extra.get("verified")):
            user, domain = _split_account(
                _text(extra.get("account"), _MAX_IDENTITY),
                _text(extra.get("user"), _MAX_IDENTITY),
                _text(extra.get("domain"), _MAX_IDENTITY))
            passwords.append({
                "user": user, "domain": domain,
                "stream": _digits(extra.get("stream")),
                "password": password, "source": "NTLM 破解命中"})
        elif _text(extra.get("protocol"), 32).lower() == "smb3":
            # session 字段是被字符串化的字典，只取 password，不去解析它。
            passwords.append({"user": "", "domain": "", "stream": "",
                              "password": password,
                              "source": "SMB3 智能串联解密成功"})

    for item in _records(cracked):
        password = _text(item.get("password"), _MAX_PASSWORD)
        if not password:
            continue
        source = _text(item.get("source"), _MAX_SOURCE) or "破解任务结果"
        user, domain = _split_account(
            _text(item.get("account"), _MAX_IDENTITY),
            _text(item.get("user"), _MAX_IDENTITY),
            _text(item.get("domain"), _MAX_IDENTITY))
        stream = _digits(item.get("stream"))
        passwords.append({"user": user, "domain": domain, "stream": stream,
                          "password": password, "source": source})
        value = _hex(item.get("nt_hash"), _NT_HASH) or _hex(
            item.get("hash"), _NT_HASH)
        if value:
            hashes.append({"user": user, "domain": domain, "stream": stream,
                           "value": value, "source": source})

    # 把密码挂到账号上：先按身份（含流）精确匹配；身份全无时只有唯一候选
    # 账号才认领，多个候选宁可忽略并记备注，绝不把 A 的密码塞给 B。
    for item in passwords:
        target = _match_account(accounts, item["user"], item["domain"],
                                item["stream"])
        if target is None and len(accounts) == 1 and (
                not item["stream"] or item["stream"] == accounts[0]["stream"]):
            # 唯一候选账号：沿用旧行为，即使标签对不上也让它认领这条密码。
            target = accounts[0]
        if target is None and item["stream"]:
            scoped = [row for row in accounts
                      if row["stream"] == item["stream"]]
            if len(scoped) == 1:
                target = scoped[0]
            elif len(scoped) > 1:
                extra_notes.append(
                    f"TCP 流 {item['stream']} 上有多个账号，{item['source']} "
                    "无法确定归属，已忽略以免串号")
                continue
        if target is None:
            if item["user"] or item["domain"] or item["stream"]:
                # 身份明确但还没见过：新建候选，不误挂给别的账号。
                target = get_account(item["user"], item["domain"],
                                     item["stream"])
                if not target["source"]:
                    target["source"] = item["source"]
            elif not accounts:
                target = get_account("", "", "")
                target["source"] = item["source"]
            else:
                extra_notes.append(
                    f"{item['source']} 没有账号/流信息，现有 "
                    f"{len(accounts)} 个候选账号，已忽略以免串号")
                continue
        if target is not None and not target["password"]:
            target["password"] = item["password"]
            target["_password_source"] = item["source"]

    for item in hashes:  # 裸 NT 哈希同样挂到账号上
        target = _match_account(accounts, item["user"], item["domain"],
                                item.get("stream", ""))
        if target is None and len(accounts) == 1:
            target = accounts[0]
        if target is not None and not target["nt_hash"]:
            target["nt_hash"] = item["value"]
            target["_nt_source"] = item["source"] or "SMB 账号发现"

    if state["capped"]:
        extra_notes.append(
            f"候选账号超过 {_MAX_ACCOUNTS} 条，仅保留前 {_MAX_ACCOUNTS} 条")
    return _select(_final_accounts(accounts), encrypted, encrypted_frame,
                   hashes, passwords, stream, saved_keys, extra_notes)


def _select(accounts, encrypted, encrypted_frame, hashes, passwords,
            stream, saved_keys, extra_notes) -> dict:
    result = _blank()
    requested = _digits(stream)

    # --- hints.stream ----------------------------------------------------
    ordered_streams = sorted(set(encrypted), key=_stream_sort)
    chosen_stream = requested
    stream_source = "用户指定的 TCP 流" if requested else ""
    if not chosen_stream:
        for item in ordered_streams:  # 先挑确实有账号的那条加密流
            if any(entry["stream"] == item for entry in accounts):
                chosen_stream = item
                break
        if not chosen_stream and ordered_streams:
            chosen_stream = ordered_streams[0]
        if chosen_stream:
            stream_source = _source("SMB3 加密流量",
                                    encrypted_frame.get(chosen_stream, ""))
        if len(ordered_streams) > 1:
            extra_notes.append(
                f"发现 {len(ordered_streams)} 条 SMB3 加密流"
                f"（{', '.join(ordered_streams)}），默认选择流 "
                f"{chosen_stream or ordered_streams[0]}；"
                "可用 stream 参数指定其它流")

    # --- hints.user / hints.domain ---------------------------------------
    account = None
    if chosen_stream:
        account = next((item for item in accounts
                        if item["stream"] == chosen_stream), None)
    if account is None and not requested:
        for item in ordered_streams:  # 加密流上没有账号记录时，按流号顺序找
            account = next((entry for entry in accounts
                            if entry["stream"] == item), None)
            if account is not None:
                break
    if account is None and accounts:
        account = accounts[0]
    if account is not None and (account["user"] or account["domain"]):
        result["hints"]["user"] = account["user"]
        result["hints"]["domain"] = account["domain"]
        source = account["source"] or "SMB NTLM 认证"
        result["sources"]["user"] = source
        result["sources"]["domain"] = source

    if chosen_stream:
        result["hints"]["stream"] = chosen_stream
        result["sources"]["stream"] = stream_source or "SMB3 加密流量"

    # --- hints.password --------------------------------------------------
    password = ""
    password_source = ""
    if account and account["password"]:
        password = account["password"]
        password_source = account["_password_source"] or "SMB 凭据结果"
    else:
        for item in passwords:  # 退而求其次：身份相符的第一个密码
            if account and not _same_identity(item, account):
                continue
            if account and item["stream"] and account["stream"] \
                    and item["stream"] != account["stream"]:
                continue
            if item["password"]:
                password = item["password"]
                password_source = item["source"]
                break
    if password:
        result["hints"]["password"] = password
        result["sources"]["password"] = password_source

    # --- hints.nt_hash（只收裸 32 位十六进制 NT 哈希）--------------------
    nt_hash = ""
    nt_source = ""
    if account and account["nt_hash"]:
        nt_hash = account["nt_hash"]
        nt_source = account["_nt_source"] or "SMB 账号发现"
    else:
        for item in hashes:
            if account and not _same_identity(item, account):
                continue
            if item["value"]:
                nt_hash = item["value"]
                nt_source = item["source"] or "SMB 账号发现"
                break
    if nt_hash:
        result["hints"]["nt_hash"] = nt_hash
        result["sources"]["nt_hash"] = nt_source

    # --- hints.session_key（上次解密的 smb3_keys.txt）--------------------
    valid: list[tuple[dict, str]] = []
    for item in _records(saved_keys):
        value = _hex(item.get("session_key"), _SESSION_KEY)
        if value:
            valid.append((item, value))
    picked = None
    if valid:
        if chosen_stream:
            matching = [entry for entry in valid
                        if _digits(entry[0].get("stream")) == chosen_stream]
            if matching:
                picked = matching[0]
            elif len(valid) == 1:
                # 唯一可用的密钥仍可跨流填入（兼容旧任务）。
                picked = valid[0]
            else:
                extra_notes.append(
                    f"有 {len(valid)} 个会话密钥但都不属于 TCP 流 "
                    f"{chosen_stream}，已忽略以免用错密钥")
        elif len(valid) == 1:
            picked = valid[0]
        elif len({_digits(entry[0].get("stream")) for entry in valid}) == 1:
            picked = valid[0]
        else:
            extra_notes.append(
                f"发现 {len(valid)} 个会话密钥且无法确定对应 TCP 流，已忽略")
    if picked is not None:
        result["hints"]["session_key"] = picked[1]
        result["sources"]["session_key"] = KEY_SOURCE_LABEL

    result["accounts"] = [{name: item[name] for name in ACCOUNT_FIELDS}
                          for item in accounts]
    result["notes"] = _notes(result, extra_notes)
    return result


def _notes(result: dict, extra_notes=None) -> list[str]:
    hints = result["hints"]
    sources = result["sources"]
    notes: list[str] = []
    if hints["password"]:
        notes.append(f"明文密码 {hints['password']} 来自 {sources['password']}")
    if hints["nt_hash"]:
        notes.append(f"NT 哈希 {hints['nt_hash']} 来自 {sources['nt_hash']}")
    if hints["session_key"]:
        notes.append(f"会话密钥来自 {sources['session_key']}")
    if hints["user"] or hints["domain"]:
        label = _account_label(hints["user"], hints["domain"])
        notes.append(f"账号 {label} 来自 {sources['user']}")
    if hints["domain"]:
        notes.append(f"域 {hints['domain']} 来自 {sources['domain']}")
    if hints["stream"]:
        notes.append(f"TCP 流 {hints['stream']} 来自 {sources['stream']}")
    if not any(hints.values()):
        # 什么线索都没有：只留一条中文说明，告诉用户下一步做什么。
        notes.append(NOTHING_NOTE)
    elif not hints["password"] and any(item["hash"]
                                       for item in result["accounts"]):
        notes.append("只找到 NetNTLMv2 抓哈希，先用 NTLM 验证 / "
                     "hashcat -m 5600 破解成明文密码再来解密")
    for extra in extra_notes or []:
        text = _text(extra, _MAX_NOTE)
        if text and text not in notes:
            notes.append(text)
    return notes[:MAX_NOTES]


def _blank(notes=None) -> dict:
    return {
        "hints": {key: "" for key in FIELDS},
        "sources": {key: "" for key in FIELDS},
        "accounts": [],
        "notes": list(notes or []),
    }


# ---------------------------------------------------------------------------
# 公开接口
# ---------------------------------------------------------------------------
def decrypt_hints(findings=None, *, stream: str = "", cracked=None,
                  saved_keys=None) -> dict:
    """Return auto-fill suggestions for the SMB3 decrypt dialog.

    ``findings`` 是任务的结构化结果（``fnet.findings.make()`` 生成的字典列表，
    ``extra`` 里的值已经被清洗成字符串）；``cracked`` 是调用方手里的破解记录
    ``{"user","domain","password","stream","source"}``；``saved_keys`` 是
    :func:`fnet.smb3.read_keys_file` 读出来的上次解密会话密钥。

    返回永远是同一个形状，且所有值都是字符串（列表字段为空列表）::

        {"hints":   {"password", "nt_hash", "session_key",
                     "user", "domain", "stream"},
         "sources": 同上六个字段，说明每个值是从哪条结果来的,
         "accounts": [{"user", "domain", "stream", "password", "nt_hash",
                       "hash", "mode", "source"}, ...],
         "notes":   ["中文一行说明", ...]}

    ``nt_hash`` 只会是裸的 32 位十六进制 NT 哈希；NetNTLMv2 抓哈希留在
    ``accounts[].hash``，必须先破解成明文密码再填对话框。任何脏输入都不会
    让本函数抛异常，最坏情况是返回空建议加一条中文提示。
    """
    try:
        return _collect(_records(findings), stream, cracked, saved_keys)
    except Exception:  # noqa: BLE001 - 自动填入不能把页面搞崩
        return _blank(["生成自动填入建议时出错，请手动填写 SMB3 解密参数"])


def hints_for_job(jobs, job_id: str, stream: str = "",
                  cracked=None) -> dict:
    """Read a job's findings + smb3_keys.txt and build the same suggestion dict.

    ``jobs`` 是 :class:`fnet.jobs.JobManager`（或任何提供 ``findings_for`` /
    ``output_dir_for`` 的对象）。读盘失败、任务不存在、文件缺失都只会退化成
    空建议 + 一条中文说明。
    """
    findings: list = []
    saved: list = []
    try:
        found = jobs.findings_for(str(job_id or ""), limit=1_000_000)
        if isinstance(found, dict):
            findings = found.get("findings") or []
        else:
            findings = found or []
    except Exception:  # noqa: BLE001 - 任务不存在/磁盘错误都要继续给空建议
        findings = []
    try:
        output = jobs.output_dir_for(str(job_id or ""))
    except Exception:  # noqa: BLE001
        output = None
    if output:
        saved = smb3.read_keys_file(Path(str(output)) / smb3.KEYS_FILE_NAME)
    try:
        return decrypt_hints(findings, stream=stream, cracked=cracked,
                             saved_keys=saved)
    except Exception:  # noqa: BLE001 - 兜底：decrypt_hints 本身不会抛
        return _blank(["读取任务结果失败，请手动填写 SMB3 解密参数"])
