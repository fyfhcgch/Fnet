"""OpenSSL 加密文件检测与解密（含熵值分析与 ``openssl enc`` 兼容配方）。

CTF 场景：``openssl enc -aes-256-ctr -d -nosalt -in flag -out out.bin
-pass pass:haha``，以及较新的 ``openssl enc -aes-256-cbc -pbkdf2 -iter 10000
-a -saltlen 16 -in flag.enc -out out.bin -pass pass:...``。

处理器流程：
1. 收集落盘候选文件，跳过 Fnet 自己生成的 README/报告等明文工件；
2. 熵值排行，仅对带 ``Salted__`` / ``U2FsdGVkX1`` 标记或高熵低可打印率的文件
   记录“疑似加密文件”发现，避免把中等熵文本塞进分析结果；
3. 用 :mod:`fnet.utils.openssl_enc` 识别信封（含 Base64 变体）并给出可操作发现；
4. 有口令/原始密钥时按配方尝试解密，成功后落盘 ``decrypted.bin`` 与逐文件
   ``<stem>.decrypted``，并复用 :func:`fnet.utils.tunnel.find_flags` 扫 flag。

所有口令仅在日志中以“已脱敏”字样出现，绝不回显。
"""
from __future__ import annotations

from pathlib import Path

from fnet.features.registry import FeatureContext
from fnet.utils import openssl_enc
from fnet.utils.entropy import HIGH_ENTROPY, classify, entropy_ratio, shannon_entropy

#: 小于该体积的文件不单独按熵值判定。
MIN_ENTROPY_SIZE = 32
#: 配方尝试上限（与 openssl_enc.decrypt_envelope 的默认 max_recipes 对齐）。
MAX_RECIPES = 24
#: “低可打印率”的阈值，与 entropy.classify 的 0.60 保持一致。
PRINTABLE_LIMIT = 0.60
#: 兜底标记（核心常量缺失时使用；与 openssl_enc 的约定一致）。
_ENVELOPE_MAGIC = b"Salted__"
_BASE64_MAGIC = b"U2FsdGVkX1"


def _read_bytes(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except (OSError, ValueError, IsADirectoryError):
        return None


def _as_bytes(value) -> bytes:
    """把核心返回的 marker/salt 统一成 bytes，容忍 None / str / bytes。"""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8", "replace")
    return b""


def _normalise_hex(value) -> str:
    """把 ``-K/-iv`` 参数归一化成不带分隔符的十六进制字符串。"""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    text = str(value).strip().replace(" ", "").replace(":", "").replace("-", "")
    if text.lower().startswith("0x"):
        text = text[2:]
    return text.lower()


def _file_candidates(ctx: FeatureContext) -> tuple[list[tuple[str, bytes]], list[str]]:
    """收集待分析文件，并单独返回被跳过的生成/明文工件名。

    ``openssl_enc.looks_like_generated_text`` 负责识别 Fnet 自己写出的
    ``c2_README.txt`` / ``*_README.txt`` / ``findings.json`` / ``report*.md`` /
    ``job.json`` 等文件；这些文件绝不能混进“疑似加密文件”发现。
    """
    candidates: list[tuple[str, bytes]] = []
    skipped: list[str] = []
    out_dir = ctx.output_dir
    if out_dir is not None and out_dir.is_dir():
        for path in sorted(out_dir.iterdir()):
            if not path.is_file():
                continue
            data = _read_bytes(path)
            if not data:
                continue
            if openssl_enc.looks_like_generated_text(path.name, data):
                skipped.append(path.name)
                continue
            candidates.append((path.name, data))

    path_param = ctx.params.get("path") if ctx.params else None
    if path_param:
        p = Path(str(path_param))
        if p.is_file():
            data = _read_bytes(p)
            if data:
                if openssl_enc.looks_like_generated_text(p.name, data):
                    skipped.append(p.name)
                elif p.name not in {name for name, _ in candidates}:
                    candidates.append((p.name, data))
    return candidates, skipped


def _marker_present(data: bytes) -> bool:
    """文件头是否带 OpenSSL 信封标记（原始或 Base64 形式）。"""
    magic = _as_bytes(getattr(openssl_enc, "ENVELOPE_MAGIC", b"")) or _ENVELOPE_MAGIC
    b64 = _as_bytes(getattr(openssl_enc, "BASE64_MAGIC", b"")) or _BASE64_MAGIC
    head = data.lstrip()
    return head.startswith(magic) or head.startswith(b64)


def _env_value(env, key, default=b""):
    """兼容核心返回的 dataclass 与 ``asdict`` 字典两种信封表示。"""
    if isinstance(env, dict):
        return env.get(key, default)
    return getattr(env, key, default)


def _printable_ratio(data: bytes) -> float:
    """从核心 classify_payload 取可打印比例，兼容计数/比例两种表示。"""
    try:
        info = openssl_enc.classify_payload(data)
    except Exception:  # noqa: BLE001 - 探测失败不应影响熵值分析
        return 1.0
    value = info.get("printable_ratio", info.get("printable",
                                                  info.get("ratio", 1.0)))
    value = float(value)
    if value > 1.0:
        value = value / max(len(data), 1)
    return max(0.0, min(1.0, value))


def _entropy_report(ctx: FeatureContext, candidates: list[tuple[str, bytes]]) -> None:
    """熵值排行；只有带标记或高熵低可打印率的文件才产生发现。

    中等熵的 UTF-8 文本（例如截图里的 ``c2_README.txt``）只写日志，
    不再产出 ``文件/信息/疑似加密文件`` 噪声。
    """
    scored = []
    for name, data in candidates:
        if not data or len(data) <= MIN_ENTROPY_SIZE:
            continue
        cls = classify(data)
        marker = _marker_present(data)
        printable = _printable_ratio(data)
        high = cls["entropy"] >= HIGH_ENTROPY and printable < PRINTABLE_LIMIT
        scored.append((cls["entropy"], name, len(data), cls,
                       marker, high, printable))
    scored.sort(key=lambda item: item[0], reverse=True)
    if not scored:
        ctx.report("没有足够大的二进制文件可进行熵值分析", "info")
        return

    ctx.report("===== 疑似加密文件熵值排行（最高熵在前）=====", "good")
    for entropy, name, size, cls, marker, high, printable in scored:
        ctx.report(f"{name} (size={size}) 熵={entropy:.4f} "
                   f"ratio={cls['ratio']:.2f} printable={printable:.2f} "
                   f"-> {cls['hint']}", "warn" if marker else "info")
        if not (marker or high):
            continue
        ctx.add_finding(
            "file", f"疑似加密文件 {name}",
            detail=(f"熵 {entropy:.4f}（ratio {cls['ratio']:.2f}, "
                    f"printable {printable:.2f}） {cls['hint']}"),
            extra={"path": name, "size": size, "entropy": cls["entropy"],
                   "ratio": cls["ratio"], "marker": marker,
                   "printable": printable})
    ctx.report("若需解密，请提供 password（及可选 cipher/kdf 参数）", "info")


def _envelope_finding(ctx: FeatureContext, name: str, data: bytes,
                      env, encoding: str | None = None) -> None:
    """记录一个可操作的信封发现（编码、salt、长度、大小、标记）。"""
    salt_hex = _as_bytes(_env_value(env, "salt", b"")).hex()
    marker = _as_bytes(_env_value(env, "marker", "")).decode("utf-8", "replace")
    enc = encoding or _as_bytes(_env_value(env, "encoding", "")).decode(
        "utf-8", "replace") or "raw"
    salt_len = int(_env_value(env, "salt_len", 0) or 0)
    size = len(_as_bytes(_env_value(env, "ciphertext", b"")))
    level = "warn" if marker else "info"
    detail = (f"编码={enc}, salt={salt_hex or '无'}, salt 长度={salt_len}, "
              f"密文大小={size}, 标记={marker or '无'}")
    ctx.report(f"检测到 OpenSSL 信封 {name}: {detail}", level)
    ctx.add_finding("file", f"OpenSSL 密文信封 {name}", detail=detail,
                    level=level,
                    extra={"path": name, "encoding": enc, "salt": salt_hex,
                           "salt_len": salt_len, "size": size,
                           "marker": marker})


def _report_envelopes(ctx: FeatureContext,
                      candidates: list[tuple[str, bytes]]) -> None:
    """对每个候选（含 Base64 解码变体）先给出信封发现，再进入解密阶段。"""
    for name, data in candidates:
        ctx.check_cancel()
        try:
            env = openssl_enc.detect_envelope(data)
        except Exception:  # noqa: BLE001 - 单个文件失败不影响整体
            env = None
        if env is not None:
            _envelope_finding(ctx, name, data, env)
        try:
            decoded = openssl_enc.decode_base64_candidates(data)
        except Exception:  # noqa: BLE001
            decoded = []
        for plain, label in decoded:
            ctx.check_cancel()
            try:
                env2 = openssl_enc.detect_envelope(plain)
            except Exception:  # noqa: BLE001
                env2 = None
            if env2 is not None:
                _envelope_finding(ctx, name, plain, env2, encoding=label)


def _resolve_password(ctx: FeatureContext, params: dict) -> str:
    """口令优先取 ``password``，否则读 ``password_file`` 首个非空行。

    返回值只用于解密，任何日志都不回显。
    """
    pw = params.get("password")
    if pw is not None and str(pw):
        return str(pw)
    pf = params.get("password_file")
    if pf:
        try:
            text = Path(str(pf)).read_text(encoding="utf-8", errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line:
                    return line
        except (OSError, ValueError) as exc:
            ctx.report(f"读取 password_file 失败: {exc}", "warn")
    return ""


def _build_spec(params: dict) -> dict:
    """把用户参数映射为 ``openssl_enc`` 的 ``spec`` 字典。"""
    spec: dict = {}
    cipher = params.get("cipher")
    if cipher:
        name = str(cipher)
        spec["cipher"] = name
        try:
            parsed = openssl_enc.parse_cipher(name)
            for key in ("key_len", "iv_len", "mode"):
                if key in parsed:
                    spec[key] = parsed[key]
        except Exception:  # noqa: BLE001 - 交给核心按默认值处理
            pass
    kdf = params.get("kdf")
    if kdf:
        spec["kdf"] = str(kdf).lower()
    digest = params.get("digest") or params.get("md")
    if digest:
        spec["digest"] = str(digest).lower()
    iterations = params.get("iterations") if "iterations" in params else params.get("iter")
    if iterations is not None:
        try:
            spec["iterations"] = int(iterations)
        except (TypeError, ValueError):
            pass
    saltlen = params.get("saltlen")
    if saltlen is not None:
        try:
            spec["salt_len"] = int(saltlen)
        except (TypeError, ValueError):
            pass
    if "nosalt" in params:
        spec["nosalt"] = bool(params["nosalt"])
    for src in ("base64", "zlib", "nopad"):
        if src in params:
            spec[src] = bool(params[src])
    key_hex = params.get("key_hex") or params.get("key")
    if key_hex:
        spec["key_hex"] = _normalise_hex(key_hex)
    iv_hex = params.get("iv_hex") or params.get("iv")
    if iv_hex:
        spec["iv_hex"] = _normalise_hex(iv_hex)
    return spec


def _explicit_salt(params: dict) -> bytes:
    """解析 ``salt_hex`` / ``salt`` 显式盐值。

    OpenSSL 3.0+ 用 ``-S`` 指定的盐不再写入文件头，解密时必须再次提供；
    1.1.1 及更早版本仍会写入 ``Salted__`` 头。两种情况都由
    :func:`_with_explicit_salt` 归一化后交给核心。
    """
    hex_salt = params.get("salt_hex")
    if hex_salt:
        try:
            salt = bytes.fromhex(_normalise_hex(hex_salt))
            if salt:
                return salt
        except ValueError:
            pass
    plain = params.get("salt")
    if plain is not None and str(plain):
        return str(plain).encode("utf-8")
    return b""


def _with_explicit_salt(data: bytes, salt: bytes) -> bytes:
    """把显式盐值归一化成 ``Salted__ + salt + ciphertext`` 供核心识别。"""
    if not salt:
        return data
    magic = _as_bytes(getattr(openssl_enc, "ENVELOPE_MAGIC", b"")) or _ENVELOPE_MAGIC
    if data.startswith(magic):
        return magic + salt + data[len(magic) + len(salt):]
    return magic + salt + data


def _count_recipes(spec: dict) -> int:
    """报告本次最多会尝试多少种配方。"""
    try:
        recipes = openssl_enc.recipe_candidates(spec or None)
        return min(len(recipes), MAX_RECIPES) if recipes else 1
    except Exception:  # noqa: BLE001
        return 1 if spec else MAX_RECIPES


def _decrypt_target(ctx: FeatureContext, name: str, raw: bytes, password: str,
                    spec: dict, salt: bytes, max_recipes: int):
    """尝试原始字节、Base64 与外层 zlib 变体，返回首个成功结果。

    真实 ``openssl enc -z`` 会把整个信封包进 zlib；核心虽会先 inflate，
    但 ``zlib=true`` 的配方仍可能要求解密后再 inflate。这里额外构造一个
    “先 inflate、不再强制内层 zlib”的变体，覆盖两种位置。
    """
    variants: list[tuple[bytes, str, dict]] = [(raw, "raw", dict(spec))]
    try:
        for decoded, label in openssl_enc.decode_base64_candidates(raw):
            local = dict(spec)
            if label != "raw":
                local["base64"] = False  # 已在本处理器解码，避免核心重复处理
            variants.append((decoded, label, local))
    except Exception:  # noqa: BLE001
        pass
    if spec.get("zlib"):
        inflate = getattr(openssl_enc, "_safe_inflate", None)
        if callable(inflate):
            try:
                expanded = inflate(raw)
                if expanded and expanded != raw:
                    local = dict(spec)
                    local["zlib"] = False
                    variants.insert(0, (expanded, "zlib-outer", local))
            except Exception:  # noqa: BLE001
                pass

    for data, label, local_spec in variants:
        ctx.check_cancel()
        payload = _with_explicit_salt(data, salt) if salt else data
        try:
            result = openssl_enc.decrypt_envelope(
                payload, password, spec=local_spec or None,
                max_recipes=max_recipes)
        except Exception as exc:  # noqa: BLE001 - 单个配方失败不应中断
            ctx.report(f"{name} 解密异常: {exc}", "debug")
            continue
        if result and result.get("plaintext") is not None:
            return result
    return None


def _find_flags(ctx: FeatureContext, data: bytes) -> list[str]:
    """Run flag scanning with ``find_flags`` (imported lazily to avoid cycles)."""
    from fnet.utils.tunnel import find_flags
    return list(find_flags(data))


def _report_success(ctx: FeatureContext, name: str, result: dict) -> None:
    """落盘明文并写入可操作的成功发现与中文日志。"""
    plain = bytes(result.get("plaintext") or b"")
    recipe = result.get("recipe") or {}
    flags = list(result.get("flags") or [])
    if not flags:
        flags = _find_flags(ctx, plain)
    signatures = list(result.get("signatures") or [])
    env = result.get("envelope")
    salt_hex = _as_bytes(_env_value(env, "salt", b"")).hex() if env else ""
    encoding = _as_bytes(_env_value(env, "encoding", "")).decode(
        "utf-8", "replace") if env else ""

    ctx.report(
        f"解密成功: {name} ({len(plain)} bytes), "
        f"cipher={recipe.get('cipher', '?')} mode={recipe.get('mode', '?')} "
        f"kdf={recipe.get('kdf', '?')} digest={recipe.get('digest', '?')} "
        f"iter={recipe.get('iterations', '?')} salt={salt_hex or '无'} "
        f"encoding={encoding or 'raw'} flags={flags}", "good")
    # 保留 decrypted.bin 这个名字兼容既有测试；另存逐文件工件便于区分。
    ctx.write_output("decrypted.bin", plain)
    stem = Path(name).stem or "decrypted"
    ctx.write_output(f"{stem}.decrypted", plain)
    detail = (
        f"cipher={recipe.get('cipher', '?')} mode={recipe.get('mode', '?')} "
        f"kdf={recipe.get('kdf', '?')} digest={recipe.get('digest', '?')} "
        f"iterations={recipe.get('iterations', '?')} salt={salt_hex or '无'} "
        f"encoding={encoding or 'raw'} flags={flags} signatures={signatures} "
        f"口令已脱敏")
    ctx.add_finding("file", f"OpenSSL 解密成功 {name}", detail=detail,
                    extra={"path": name, "recipe": recipe, "salt": salt_hex,
                           "encoding": encoding, "flags": flags,
                           "signatures": signatures})


def detect_encrypted_files(ctx: FeatureContext) -> None:
    """检测疑似加密文件，并在有口令/密钥时尝试 OpenSSL 兼容解密。"""
    ctx.set_progress(5)
    params = ctx.params or {}
    ctx.check_cancel()

    candidates, skipped = _file_candidates(ctx)
    if skipped:
        ctx.report(f"已跳过 {len(skipped)} 个生成/明文工件（"
                   f"{', '.join(skipped[:5])}），不参与熵值与解密分析", "info")
    if not candidates:
        ctx.report("未找到可分析的二进制文件（请用 path 参数指定文件）", "warn")
        return

    ctx.set_progress(15)
    _entropy_report(ctx, candidates)
    ctx.check_cancel()
    ctx.set_progress(30)
    _report_envelopes(ctx, candidates)
    ctx.check_cancel()
    ctx.set_progress(45)

    spec = _build_spec(params)
    salt = _explicit_salt(params)
    password = _resolve_password(ctx, params)
    has_key = bool(spec.get("key_hex"))
    recipe_count = _count_recipes(spec)

    ctx.report(f"解密配置: kdf={spec.get('kdf', 'auto')} "
               f"cipher={spec.get('cipher', 'auto')} "
               f"digest={spec.get('digest', 'auto')} "
               f"base64={spec.get('base64', 'auto')} "
               f"zlib={spec.get('zlib', 'auto')} "
               f"候选配方={recipe_count}（口令已脱敏）", "info")

    if not password and not has_key:
        ctx.report("未提供 password/password_file 或原始 key，仅执行检测与熵值分析",
                   "info")
        ctx.report("已知口令可用 password/path 重试；支持 pbkdf2/iter/saltlen、"
                   "Base64、zlib、key/iv 等 openssl enc 参数", "info")
        ctx.set_progress(100)
        return

    target_path = params.get("path")
    wanted = Path(str(target_path)).name if target_path else ""
    targets = [item for item in candidates if item[0] == wanted] if wanted else candidates
    if not targets and wanted:
        ctx.report(f"未找到指定文件: {target_path}，将遍历所有候选文件尝试", "warn")
        targets = candidates

    success = False
    total = len(targets)
    for index, (name, raw) in enumerate(targets, start=1):
        ctx.check_cancel()
        ctx.report(f"[{index}/{total}] 尝试解密: {name}（最多 {recipe_count} 种配方）",
                   "info")
        result = _decrypt_target(ctx, name, raw, password, spec, salt, MAX_RECIPES)
        if result:
            _report_success(ctx, name, result)
            success = True
            break
        ctx.report(f"{name} 解密失败（口令或配方不匹配）", "debug")
        ctx.set_progress(45 + int(50 * index / total))

    if not success:
        ctx.report(f"未能成功解密（已尝试最多 {recipe_count} 种配方）。"
                   "口令可能不正确或 cipher/kdf/salt 参数不符；CTF 可改用 "
                   "generate_candidates/hashcat 生成口令字典", "warn")
    ctx.set_progress(100)


#: Handler alias, usable interchangeably with ``detect_encrypted_files``.
analyze = detect_encrypted_files
