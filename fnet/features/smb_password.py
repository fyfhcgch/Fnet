"""SMB 候选密码生成器与一次性排查 handler。

独立小模块，避免与 :mod:`fnet.features.smb_intel` 耦合：它只负责
"从一个账号线索 + 用户参数 + 内置弱口令小字典 推导出一批候选密码"，
不关心 SMB3 解密本身。``smb_intel`` 会调用这里的纯函数做密码注入。

自动回退/健壮性：
    内部对 ``fnet.utils.ntlmcrack`` / ``fnet.utils.crypto`` 的导入全部用
    ``try/except`` 包裹（并行子代理可能在稍后才落地这些模块），缺失时
    静默降级——只做候选**生成**、不做密码**验证**，绝不抛异常。

候选来源（优先级从高到低）：
    1. ``params`` 的 ``path`` 字典文件（utf-8，一行一个）；
    2. ``params`` 的 ``base_words``（分号分隔的种子词）；
    3. 账号线索派生词（user / domain / workstation / 共享名 / 文件名 / 域名）；
    4. 内置常见弱口令小字典；
    5. ``bruteforce`` 开启时再用 :func:`fnet.utils.ntlmcrack.brute_force_ntlmv2`
       做≤6 位的字母+数字策略性枚举。

每种基础词都生成原样 / 小写 / 大写 / 首字母大写 四种形式，并追加常见
数字后缀（``123 / 1234 / 12345 / 123456 / 1 / 666 / 888``）与符号后缀
（``@ / ! / #``）。

常规的候选数量只落到日志和 ``smb_password_candidates.txt`` 里，不再作为
结构化发现写入；后续 handler 也应遵循此约定：日常排查进度归 ``report``，
分析结果只留值得关注的发现。
"""
from __future__ import annotations

import re
from typing import Iterator

from fnet.features.registry import FeatureContext
from fnet.utils import smb as smb_util


#: 内置常见弱口令小字典（CTF 场景最常见的一批）。
WEAK_PASSWORDS = [
    "admin", "password", "123456", "12345678", "123456789", "qwerty",
    "abc123", "password123", "admin123", "root", "toor", "letmein",
    "welcome", "monkey", "dragon", "master", "login", "passw0rd",
    "P@ssw0rd", "changeme", "guest", "test", "user", "iloveyou",
]

DIGIT_SUFFIXES = ("", "1", "12", "123", "1234", "12345", "123456",
                  "666", "888", "0000", "2024", "2025", "2026")
SYMBOL_SUFFIXES = ("", "@", "!", "#", "@1", "!1", "!!", "@@")

#: 从账号线索里提取的基础词：按可读性排序，域名优先，用户名其次。
_ACCOUNT_STEMS = ("domain", "user", "workstation", "share", "file", "server")


def _split_words(value, separators: str = ",; \t\n") -> list[str]:
    """把分号/逗号/空格分隔的参数拆成一列种子词。"""
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    if not isinstance(value, str):
        return []
    words = []
    for piece in re.split(f"[{re.escape(separators)}]+", value):
        piece = piece.strip().strip("\\/")
        if piece and piece not in words:
            words.append(piece)
    return words


#: 文件名/共享名派生基础词时要剥掉的常见扩展名。
_FILE_EXTS = (".txt", ".bin", ".dat", ".log", ".doc", ".docx", ".xls",
              ".xlsx", ".csv", ".zip", ".rar", ".tar", ".gz", ".pdf",
              ".png", ".jpg", ".jpeg", ".key", ".pem")

def _account_stems(account) -> list[str]:
    """从账号线索抽取候选基础词，保序去重。

    对共享名/文件名会取路径末段并剥掉常见扩展名，避免出现
    ``secret.txt`` 这种含点的基础词。
    """
    account = account or {}
    stems: list[str] = []
    for key in _ACCOUNT_STEMS:
        value = account.get(key)
        if isinstance(value, str) and value.strip():
            # 共享名/文件名可能是 ``\\server\share`` 或含路径，取最末段。
            piece = value.strip().replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            piece = piece.strip()
            lowered = piece.lower()
            for ext in _FILE_EXTS:
                if lowered.endswith(ext):
                    piece = piece[:len(piece) - len(ext)]
                    break
            piece = piece.strip(" .")
            if piece and piece.lower() not in (stem.lower() for stem in stems):
                stems.append(piece)
    return stems


def _variants(stem: str) -> list[str]:
    """对单个基础词做大小写/首字母大写变形。"""
    if not stem:
        return []
    out: list[str] = []
    for candidate in (stem, stem.lower(), stem.upper(),
                      stem[:1].upper() + stem[1:]):
        if candidate not in out:
            out.append(candidate)
    return out


def _order_stems(stems: list[str]) -> list[str]:
    """给基础词排序：短的、常见的优先，方便暴力前先试高命中词。"""
    def score(stem: str) -> tuple:
        lowered = stem.lower()
        return (0 if lowered in (w.lower() for w in WEAK_PASSWORDS) else 1,
                len(stem), 0 if lowered == stem else 1)
    ordered = sorted(set(stems), key=score)
    # 保持账号派生的相对优先级（域名/用户放前面）。
    seen: set[str] = set()
    return [s for s in ordered if not (s in seen or seen.add(s))]


def _build_candidates(account, params) -> list[str]:
    """纯候选生成核心，供给生成器与纯函数共用。"""
    params = params or {}

    # 1) 字典文件路径。
    path = str(params.get("path") or "").strip()
    if path:
        words = _load_wordlist(path)
        return _dedupe(words)

    # 2) 显式种子词。
    base_words = _split_words(params.get("base_words"))
    # 3) 账号派生词。
    base_words.extend(_account_stems(account))
    # 4) 弱口令。
    base_words.extend(WEAK_PASSWORDS)

    append_digits = bool(params.get("append_digits", True))

    candidates: list[str] = []
    for stem in _order_stems(base_words):
        for variant in _variants(stem):
            suffixes = DIGIT_SUFFIXES if append_digits else ("",)
            for digit in suffixes:
                for symbol in SYMBOL_SUFFIXES:
                    candidates.append(variant + digit + symbol)

    # 纯数字短口令兜底（字典里常见）。
    candidates.extend(["123456", "12345678", "88888888", "000000"])
    return _dedupe(candidates)


def _dedupe(words: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for word in words:
        if not word:
            continue
        if word in seen:
            continue
        seen.add(word)
        out.append(word)
    return out


def _load_wordlist(path: str) -> list[str]:
    """读取 utf-8 字典文件，一行一个密码。"""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return _dedupe([line.strip() for line in handle])
    except (OSError, UnicodeDecodeError, ValueError):
        return []


def password_candidates_for_account(account, params) -> list[str]:
    """纯函数：返回 ``account`` + ``params`` 可生成的候选密码列表。

    供测试与 :mod:`fnet.features.smb_intel` 直接调用；不做任何验证。
    ``params`` 支持 ``base_words`` / ``append_digits`` / ``path``。
    """
    return _build_candidates(account, params)


def _resolve_verifier():
    """仅当并行子代理已交付 ``fnet.utils.ntlmcrack`` 时返回验证函数。

    没有则返回 ``None``，调用方据此跳过密码验证而非崩溃。
    """
    try:
        from fnet.utils import ntlmcrack  # 延迟导入 + 异常兜底
        return ntlmcrack.verify_password
    except Exception:  # noqa: BLE001 - 自动回退：验证模块未就绪
        return None


def generate_password_candidates(ctx: FeatureContext, account) -> Iterator[str]:
    """按优先级生成候选密码的可验证生成器（供 ``smb_intel`` 消费）。

    每个候选被 yield 前，若账号带了 ``challenge`` / ``nt_response`` 且
    ``fnet.utils.ntlmcrack`` 可用，则先用 :func:`verify_password` 在校验命中
    时立即停止生成（return），从而把"第一个真密码"快速暴露给上层。

    若 ``params.bruteforce`` 为真，在基础候选耗尽后再尝试
    ``fnet.utils.ntlmcrack.brute_force_ntlmv2`` 做 ≤6 位字母+数字短枚举。
    """
    ctx = ctx or _NullContext()
    params = dict(ctx.params or {})
    account = account or {}
    candidates = _build_candidates(account, params)
    verify = _resolve_verifier()

    challenge = account.get("challenge")
    nt_response = account.get("nt_response")
    user = account.get("user")
    domain = account.get("domain")

    def _verify(candidate: str) -> bool:
        if verify is None or not challenge or not nt_response:
            return False
        try:
            return bool(verify(candidate, bytes(challenge), bytes(nt_response),
                               user=user, domain=domain))
        except Exception:  # noqa: BLE001 - 校验失败当作不命中
            return False

    for candidate in candidates:
        ctx.check_cancel()
        yield candidate
        if _verify(candidate):
            return  # 命中即停止，把优先权交还给上层流水线

    # 策略性暴力（可选、受控）：交给 ntlmcrack，仅当模块可用。
    if bool(params.get("bruteforce")) and challenge and nt_response:
        try:
            from fnet.utils import ntlmcrack
            found = ntlmcrack.brute_force_ntlmv2(
                challenge, nt_response, user, domain,
                max_attempts=min(int(params.get("bruteforce_max") or 500_000),
                                 5_000_000),
                cancel=lambda: not ctx.cancelled())
            if found:
                yield str(found)
        except Exception:  # noqa: BLE001 - 枚举失败不阻塞流水线
            ctx.report("NTLM 暴力枚举模块不可用，跳过", "warn")


class _NullContext:
    """无 ops 的最小上下文，仅让生成器在无 ctx 时也能工作。"""

    params: dict = {}

    def report(self, text, level="info") -> None:
        return None

    def check_cancel(self) -> None:
        return None

    def cancelled(self) -> bool:
        return False


def analyze(ctx: FeatureContext) -> None:
    """独立 handler：对捕获中每条 SMB 流做一次性密码候选排查。

    不落盘、不解密，只报告"基于账号与参数生成的可能候选密码"，供
    人工挑选后交给 :mod:`fnet.features.smb_intel` 解密。可单选此配置查看
    生成结果。
    """
    from fnet.features.common import protocol_streams

    streams = protocol_streams(ctx, "smb2")
    if not streams:
        ctx.report("没有发现 SMB 流量", "warn")
        return

    groups: dict[str, list] = {}
    for stream in streams:
        groups.setdefault(stream.stream, []).append(stream)

    all_candidates: list[str] = []
    seen_accounts = 0
    for stream_id, group in groups.items():
        ctx.check_cancel()
        account: dict = {"stream": stream_id}
        auth: dict = {}
        challenge: bytes = b""
        account["code"] = ""
        for stream in group:
            for message in smb_util.parse_messages(stream.data):
                if message.security_blob:
                    found = smb_util.find_ntlm_type3(message.security_blob)
                    if found:
                        auth = found
                        account["user"] = found.get("user", "")
                        account["domain"] = found.get("domain", "")
                        account["workstation"] = found.get("workstation", "")
                    elif message.security_blob.startswith(smb_util.NTLMSSP) \
                            and message.is_response \
                            and len(message.security_blob) >= 32:
                        # 服务端 CHALLENGE（TYPE2）在 SESSION_SETUP 响应里。
                        challenge = message.security_blob[24:32]
                account["code"] = account["code"] or message.command_name
        if challenge:
            account["challenge"] = challenge
            if "nt_response" not in account and auth:
                account["nt_response"] = auth.get("nt")
        if auth:
            seen_accounts += 1
        account_list = password_candidates_for_account(account, ctx.params)
        label = (f"{account.get('domain') or ''}"
                 f"\\{account.get('user') or '?'}") .lstrip("\\") or "?"
        ctx.report(f"流 {stream_id} 账号={label} 生成 "
                   f"{len(account_list)} 个候选密码", "info")
        for candidate in account_list:
            if candidate not in all_candidates:
                all_candidates.append(candidate)

    if all_candidates:
        ctx.write_output("smb_password_candidates.txt",
                         "\n".join(sorted(set(all_candidates))) + "\n")
    ctx.report(f"共识别 {seen_accounts} 个账号，生成 "
               f"{len(all_candidates)} 个候选密码", "good")
    if not seen_accounts and str(ctx.params.get("path") or "").strip():
        ctx.report("未识别到 NTLM 账号，仅按字典文件路径生成候选", "info")
    ctx.set_progress(100)