"""SMB3 transform decryption (SMB 3.0 / 3.0.2 / 3.1.1).

Wireshark cannot decrypt SMB3 transforms on every build and never without the
session key, so Fnet derives the keys itself and decrypts ``\\xfdSMB`` payloads
with the AES-GCM/AES-CCM implementation that already ships with the project.

Key material comes from one of three places:

* the plaintext password (hashed to the NT hash with MD4);
* the NT hash (``hashcat -m 1000`` output);
* an already known session key (``smb2.seskey`` in other tools).

From the NT hash the NTLMv2 session base key is rebuilt from the captured
``NTLMSSP`` AUTHENTICATE message, the encrypted random session key is unwrapped
and MS-SMB2 3.2.5.3.1 derives the cipher keys.  SMB 3.1.1 binds them to the
preauth integrity hash; captures disagree on the exact message set that feeds
that hash, so every plausible prefix is tried and the first AEAD tag that
validates wins.  A wrong key is rejected by the 128-bit tag, so "decrypted"
always means authenticated.

The module is import-safe without tshark: :func:`decrypt_capture` takes an
object with a ``fields(pcap, fields, display_filter)`` method (see
:class:`fnet.tools.runner.TShark`), which keeps the unit tests offline.
"""
from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from pathlib import Path

from fnet.utils import smb as smb_util
from fnet.utils.crypto import aes_gcm_decrypt, md4, rc4
from fnet.utils.stream import STREAM_FIELDS, reassemble_rows
from fnet.utils.wifi import ccm_decrypt

#: Cap on the number of transforms decrypted per direction.
MAX_TRANSFORMS = 4000
#: Cap on exported file contents (same order of magnitude as the SMB feature).
MAX_EXPORT_BYTES = 16 * 1024 * 1024

CIPHERS = ("AES-GCM", "AES-CCM")
KDF_LABELS = ("SMBC2SCipherKey", "SMBS2CCipherKey")

#: Name of the artifact that remembers the keys of a successful decryption.
KEYS_FILE_NAME = "smb3_keys.txt"
#: Columns of ``smb3_keys.txt`` (tab separated, first line is a ``#`` header).
KEYS_COLUMNS = ("stream", "session_id", "cipher", "key_source", "session_key",
                "cipher_key", "user", "domain")

SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass
class DecryptedMessage:
    frame: str
    stream: str
    direction: str
    cipher: str
    message: smb_util.Smb2Message


@dataclass
class Smb3Session:
    """One SMB3 session as reconstructed from the capture."""

    stream: str
    client: str = ""
    server: str = ""
    user: str = ""
    domain: str = ""
    workstation: str = ""
    session_id: str = ""
    dialect: str = ""
    cipher: str = ""
    preauth: str = ""
    preauth_frames: list[str] = field(default_factory=list)
    session_key: str = ""
    #: Hex of the base session key (NTLMv2/SMB session key before the 3.1.1
    #: KDF) that ``session_key`` was derived from; what a user should paste
    #: back into the decryption dialog.
    nt_session_key: str = ""
    key_source: str = ""
    decrypted: int = 0

    def as_dict(self) -> dict:
        return {
            "stream": self.stream,
            "client": self.client,
            "server": self.server,
            "user": self.user,
            "domain": self.domain,
            "workstation": self.workstation,
            "session_id": self.session_id,
            "dialect": self.dialect,
            "cipher": self.cipher,
            "preauth": self.preauth,
            "preauth_frames": list(self.preauth_frames),
            "session_key": self.session_key,
            "nt_session_key": self.nt_session_key,
            "key_source": self.key_source,
            "decrypted": self.decrypted,
        }


# ---------------------------------------------------------------------------
# key material
# ---------------------------------------------------------------------------
def nt_hash_from_password(password: str) -> bytes:
    """``MD4(UTF-16LE(password))`` — the NT hash."""
    return md4(str(password or "").encode("utf-16le"))


def nt_hash_from_hex(text: str) -> bytes | None:
    """Accept a bare 32-digit NT hash (ignoring spaces/colons)."""
    cleaned = re.sub(r"[\s:-]", "", str(text or ""))
    if len(cleaned) != 32 or not re.fullmatch(r"[0-9a-fA-F]{32}", cleaned):
        return None
    return bytes.fromhex(cleaned)


def kdf(key: bytes, label: str, context: bytes, length: int = 16) -> bytes:
    """SP800-108 counter-mode KDF used by SMB 3.1.1.

    MS-SMB2 feeds ``i || Label || 0x00 || Context || L`` where ``Label`` is
    itself NUL-terminated (``"SMBC2SCipherKey\\0"``), hence the two zero bytes.
    The Microsoft SMB 3.1.1 test vector only validates with both.
    """
    data = ((1).to_bytes(4, "big") + label.encode("ascii") + b"\x00\x00"
            + bytes(context or b"") + (length * 8).to_bytes(4, "big"))
    return hmac.new(key, data, hashlib.sha256).digest()[:length]


def session_key_candidates(auth: dict, nt_hash: bytes) -> list[tuple[str, bytes]]:
    """Rebuild NTLMv2 session keys from a type 3 message and an NT hash."""
    user = str(auth.get("user") or "")
    domain = str(auth.get("domain") or "")
    nt_proof = bytes(auth.get("nt_proof") or b"")
    if not user and not domain:
        return []
    if not nt_proof:
        return []
    response_key = hmac.new(
        nt_hash, (user.upper() + domain).encode("utf-16le"),
        hashlib.md5).digest()
    session_base = hmac.new(response_key, nt_proof, hashlib.md5).digest()
    candidates: list[tuple[str, bytes]] = []
    encrypted = bytes(auth.get("session_key") or b"")
    if encrypted:
        exchange = hmac.new(session_base, b"session key exchange",
                            hashlib.md5).digest()
        candidates.append(("ntlmv2+key-exchange", rc4(exchange, encrypted)))
        candidates.append(("ntlmv2+no-exchange", rc4(session_base, encrypted)))
    candidates.append(("ntlmv2-base", session_base))
    return candidates


def preauth_candidates(messages) -> list[tuple[bytes, list[str]]]:
    """Preauth integrity hashes for every plausible message prefix.

    ``messages`` is the frame-ordered list of ``(sort, frame, direction,
    message)`` tuples produced by :func:`_stream_messages`.
    """
    start = None
    for index, item in enumerate(messages):
        message = item[3]
        if message.command == 0 and not message.is_response and message.raw:
            start = index
            break
    if start is None:
        return []
    digest = bytes(64)
    frames: list[str] = []
    out: list[tuple[bytes, list[str]]] = []
    for _sort, frame, _direction, message in messages[start:]:
        if message.command not in (0, 1) or not message.raw:
            continue
        raw = bytearray(message.raw)
        if len(raw) >= 64:
            raw[48:64] = b"\x00" * 16
        digest = hashlib.sha512(digest + bytes(raw)).digest()
        frames.append(str(frame))
        out.append((digest, list(frames)))
        if message.command == 1 and message.is_response \
                and message.success and message.raw:
            break
    out.reverse()  # most complete hash first
    return out


# ---------------------------------------------------------------------------
# transform decryption
# ---------------------------------------------------------------------------
def decrypt_transform(key: bytes, cipher: str,
                      message: smb_util.Smb2Message) -> tuple[bytes, bool]:
    """Decrypt one ``\\xfdSMB`` transform and validate its AEAD tag."""
    raw = bytes(message.raw or b"")
    if len(raw) < 52 or len(key) not in (16, 24, 32):
        return b"", False
    aad = raw[20:52]
    nonce = raw[20:36]
    data = raw[52:] + raw[4:20]  # ciphertext || signature(tag)
    try:
        if cipher == "AES-GCM":
            return aes_gcm_decrypt(data, key, nonce[:12], aad, tag_len=16)
        return ccm_decrypt(key, nonce[:11], aad, data, 16)
    except Exception:  # noqa: BLE001 - a bad key must never abort the run
        return b"", False


def cipher_keys(session_keys, preauth_list):
    """Yield ``(source, cipher, key, preauth, frames, base)`` combinations.

    ``key`` is the AEAD key that gets tried against the capture, ``base`` is
    the original session key it was derived from (the NTLMv2/SMB session key
    *before* the SMB 3.1.1 KDF).  For the ``*:direct`` candidates the two are
    the same bytes; callers report ``base`` as the value a user can paste back
    into the "会话密钥" field.
    """
    seen: set[bytes] = set()
    for source, session_key in session_keys:
        for preauth, frames in preauth_list:
            for label in KDF_LABELS:
                for size in (16, 32):
                    key = kdf(session_key, label, preauth, size)
                    if key in seen:
                        continue
                    seen.add(key)
                    for cipher in CIPHERS:
                        yield (f"{source}:{label}:{size * 8}", cipher, key,
                               preauth, frames, session_key)
        # SMB 3.0/3.0.2 (and mid-capture 3.1.1) use the session key directly.
        if len(session_key) in (16, 32):
            for cipher in CIPHERS:
                yield (f"{source}:direct", cipher, session_key,
                       bytes(64), [], session_key)


def _try_schemes(transform: smb_util.Smb2Message, schemes):
    """Return the first scheme whose tag validates on ``transform``."""
    for scheme in schemes:
        # scheme == (source, cipher, key, preauth, frames, base)
        plain, ok = decrypt_transform(scheme[2], scheme[1], transform)
        if ok:
            return scheme, plain
    return None, b""


# ---------------------------------------------------------------------------
# stream walking
# ---------------------------------------------------------------------------
def _frame_number(frame: str) -> int:
    try:
        return int(frame)
    except (TypeError, ValueError):
        return 10 ** 9


def _stream_messages(group):
    combined = []
    for stream in group:
        for message in smb_util.parse_messages(stream.data):
            frame = stream.frame_at(message.offset)
            combined.append((_frame_number(frame), frame, stream.direction,
                             message))
    combined.sort(key=lambda item: item[0])
    return combined


def _dialect(messages) -> int:
    responses = [message.dialect for _sort, _frame, _direction, message
                 in messages
                 if message.command == 0 and message.is_response
                 and message.dialect and message.dialect in smb_util.DIALECTS]
    if responses:
        return max(responses)
    for _sort, _frame, _direction, message in messages:
        if message.command == 0 and message.dialects:
            return max(message.dialects)
    return 0


def _find_type3(messages) -> dict:
    for _sort, _frame, _direction, message in messages:
        if message.security_blob:
            found = smb_util.find_ntlm_type3(message.security_blob)
            if found:
                return found
    return {}


def _safe_name(value: str, fallback: str = "file") -> str:
    text = SAFE_NAME.sub("_", (value or "").replace("\\", "/").split("/")[-1])
    text = text.strip("._")
    return (text or fallback)[:80]


class _Files:
    """Rebuild files from decrypted CREATE/READ/WRITE messages."""

    def __init__(self) -> None:
        self.shares: dict[int, str] = {}
        self.pending_shares: dict[int, str] = {}
        self.names: dict[int, str] = {}
        self.frames: dict[int, str] = {}
        self.entries: dict[tuple, dict] = {}
        self.read_ranges: dict[int, tuple] = {}

    def _entry(self, key: tuple) -> dict:
        return self.entries.setdefault(
            key, {"name": "", "share": "", "write": {}, "read": {},
                  "frame": "", "pipe": False})

    def feed(self, frame: str, message: smb_util.Smb2Message) -> None:
        command = message.command_name
        if command == "TREE_CONNECT":
            if not message.is_response and message.share:
                self.pending_shares[message.message_id] = message.share
                self.shares.setdefault(message.tree_id, message.share)
            elif message.is_response:
                share = self.pending_shares.get(message.message_id, "")
                if share:
                    self.shares[message.tree_id] = share
        elif command == "CREATE":
            if not message.is_response and message.file_name:
                self.names[message.message_id] = message.file_name
                self.frames[message.message_id] = frame
                entry = self._entry(smb_util.file_id_key(message))
                entry["name"] = message.file_name
                entry["share"] = self.shares.get(message.tree_id, "")
                entry["pipe"] = smb_util.is_pipe(message, self.shares)
                if not entry["frame"]:
                    entry["frame"] = frame
            elif message.is_response and message.file_id:
                name = self.names.get(message.message_id, "")
                if name:
                    # The response carries the file id used by READ/WRITE.
                    entry = self._entry(smb_util.file_id_key(message))
                    entry["name"] = name
                    entry["share"] = self.shares.get(message.tree_id, "")
                    entry["frame"] = self.frames.get(message.message_id, frame)
        elif command == "READ":
            if not message.is_response:
                self.read_ranges[message.message_id] = (
                    smb_util.file_id_key(message), message.file_offset)
            elif message.read_data:
                lookup = self.read_ranges.get(message.message_id)
                if lookup:
                    key, offset = lookup
                    store = self._entry(key)["read"]
                    if len(store.get(offset, b"")) < len(message.read_data):
                        store[offset] = message.read_data
        elif command == "WRITE" and not message.is_response \
                and message.write_data:
            entry = self._entry(smb_util.file_id_key(message))
            entry["write"][message.file_offset] = message.write_data
            if not entry["frame"]:
                entry["frame"] = frame

    def export(self) -> list[dict]:
        exported = []
        number = 0
        for entry in self.entries.values():
            write_data = b"".join(data for _offset, data
                                  in sorted(entry["write"].items()))
            read_data = b"".join(data for _offset, data
                                 in sorted(entry["read"].items()))
            data = write_data or read_data
            if not data or entry["pipe"]:
                continue
            number += 1
            if len(data) > MAX_EXPORT_BYTES:
                data = data[:MAX_EXPORT_BYTES]
            exported.append({
                "number": number,
                "name": entry["name"] or f"file{number}",
                "share": entry["share"],
                "path": f"{entry['share'] or ''}\\{entry['name'] or '?'}",
                "data": data,
                "size": len(data),
                "md5": hashlib.md5(data).hexdigest(),
                "frame": entry["frame"],
            })
        return exported


def _flags_in(data: bytes) -> list[str]:
    from fnet.utils.tunnel import find_flags

    return find_flags(data)


# ---------------------------------------------------------------------------
# key material persistence (smb3_keys.txt)
# ---------------------------------------------------------------------------
def _field(value) -> str:
    """One tab-safe, newline-free cell for ``smb3_keys.txt``."""
    text = str(value if value is not None else "")
    for character in ("\t", "\r", "\n", "\v", "\x00"):
        text = text.replace(character, " ")
    return text.strip()


def keys_file_text(keys: list[dict]) -> str:
    """Render the ``smb3_keys.txt`` body for ``keys``.

    The body is the commented header (``"# " + "\\t".join(KEYS_COLUMNS)``)
    followed by one tab separated line per session, sorted by TCP stream and
    then session id::

        # stream\\tsession_id\\tcipher\\tkey_source\\tsession_key
        3\\t0x4000\\tAES-GCM\\tntlmv2+key-exchange:SMBC2SCipherKey:16\\t<64hex>

    (``\\t`` above means a real tab character; each line carries all eight
    :data:`KEYS_COLUMNS` fields.)  ``session_key`` is the base session key
    (what the "会话密钥" field wants), ``cipher_key`` the AEAD key actually
    used for the transforms.  Non-dict entries are skipped so a partially
    built list cannot break the artifact.
    """
    rows = []
    for item in keys or []:
        if not isinstance(item, dict):
            continue
        rows.append({column: _field(item.get(column))
                     for column in KEYS_COLUMNS})
    rows.sort(key=lambda row: (len(row["stream"]), row["stream"],
                               row["session_id"]))
    lines = ["# " + "\t".join(KEYS_COLUMNS)]
    lines.extend("\t".join(row[column] for column in KEYS_COLUMNS)
                 for row in rows)
    return "\n".join(lines) + "\n"


def read_keys_file(path) -> list[dict]:
    """Read ``smb3_keys.txt`` back into a list of dicts; never raises.

    Returns ``[]`` when the file is missing, unreadable or not valid UTF-8,
    and skips blank, commented and unparsable lines.  Every returned record
    has exactly the :data:`KEYS_COLUMNS` fields as strings; columns missing at
    the end of a short line become ``""``.
    """
    try:
        text = Path(str(path)).read_text(encoding="utf-8")
    except (OSError, ValueError, TypeError):  # incl. UnicodeDecodeError
        return []
    rows: list[dict] = []
    for line in text.splitlines():
        parts = line.split("\t")
        head = parts[0].strip()
        if len(parts) < 2 or not head or head.startswith("#"):
            continue
        if not re.fullmatch(r"\d+", head):
            continue  # 手改过/别的内容的行：忽略而不是整个文件作废
        rows.append({column: (parts[index].strip() if index < len(parts)
                              else "")
                     for index, column in enumerate(KEYS_COLUMNS)})
    return rows


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------
def decrypt_capture(pcap: str | Path, tshark, *, password: str = "",
                    nt_hash: str = "", session_key: str = "",
                    user: str = "", domain: str = "", stream: str = "",
                    output_dir: str | Path | None = None,
                    cancel=None) -> dict:
    """Decrypt every SMB3 transform that matches the supplied credentials.

    Returns a JSON-friendly dict with ``ok``, ``text`` (human summary),
    ``log`` (progress lines), ``sessions``, ``keys``, ``files``, ``flags`` and
    ``decrypted`` (message count).  ``keys`` lists the key material of every
    decrypted session (see :func:`keys_file_text`) and is also written to
    ``smb3_keys.txt`` when ``output_dir`` is given, so the SMB3 解密对话框 can
    offer it as an 自动填入 suggestion later.
    """
    if tshark is None:
        return {"ok": False, "error": "未找到 tshark，无法读取流量包"}
    try:
        filter_text = "tcp.len > 0"
        if str(stream or "").strip():
            filter_text = f"tcp.stream == {int(str(stream).strip())} && tcp.len > 0"
    except (TypeError, ValueError):
        return {"ok": False, "error": "TCP 流编号必须是数字"}
    rows = tshark.fields(str(pcap), list(STREAM_FIELDS), filter_text,
                         cancel=cancel)
    streams = reassemble_rows(rows)
    if not streams:
        return {"ok": False, "error": "流量包中没有 TCP 载荷"}
    groups: dict[str, list] = {}
    for item in streams:
        groups.setdefault(item.stream, []).append(item)

    given_key = None
    if str(session_key or "").strip():
        cleaned = re.sub(r"[\s:-]", "", str(session_key))
        if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{64}", cleaned):
            given_key = bytes.fromhex(cleaned)
    given_nt = nt_hash_from_hex(nt_hash)
    if given_nt is None and str(password or ""):
        given_nt = nt_hash_from_password(password)

    log: list[str] = []
    sessions: list[Smb3Session] = []
    decrypted_messages: list[DecryptedMessage] = []
    files = _Files()
    flags: list[str] = []

    for stream_id in sorted(groups, key=lambda value: (len(value), value)):
        if cancel is not None and cancel.is_set():
            return {"ok": False, "error": "解密已取消"}
        messages = _stream_messages(groups[stream_id])
        if not messages:
            continue
        transforms = [item for item in messages if item[3].encrypted]
        if not transforms:
            continue
        client = server = ""
        endpoints = {item.direction: f"{item.src}:{item.sport}"
                     for item in groups[stream_id]}
        for item in messages:
            message = item[3]
            if message.command == 0 and not message.is_response:
                if not client:
                    client = endpoints.get(item[2], item[2])
            elif message.command == 0 and message.is_response and not server:
                server = endpoints.get(item[2], item[2])

        auth = _find_type3(messages)
        dialect = _dialect(messages)
        preauth_list = preauth_candidates(messages)
        if not preauth_list:
            preauth_list = [(bytes(64), [])]

        key_list: list[tuple[str, bytes]] = []
        if given_key is not None:
            key_list.append(("会话密钥", given_key))
        if given_nt is not None and auth:
            key_list.extend(session_key_candidates(auth, given_nt))
        if not key_list:
            log.append(f"流 {stream_id}: 有 {len(transforms)} 个 SMB3 加密消息，"
                       "但缺少 NT 哈希/密码/会话密钥")
            sessions.append(Smb3Session(
                stream=stream_id, client=client, server=server,
                user=str(auth.get("user") or user),
                domain=str(auth.get("domain") or domain),
                workstation=str(auth.get("workstation") or ""),
                dialect=smb_util.DIALECTS.get(dialect, f"0x{dialect:04x}"),
                preauth_frames=list(preauth_list[0][1])))
            continue

        schemes = list(cipher_keys(key_list, preauth_list))
        session = Smb3Session(
            stream=stream_id, client=client, server=server,
            user=str(auth.get("user") or user),
            domain=str(auth.get("domain") or domain),
            workstation=str(auth.get("workstation") or ""),
            dialect=smb_util.DIALECTS.get(dialect, f"0x{dialect:04x}"))
        by_direction: dict[str, list] = {}
        for item in transforms:
            by_direction.setdefault(item[2], []).append(item)

        working: dict[str, tuple] = {}
        for direction, items in by_direction.items():
            scheme, plain = _try_schemes(items[0][3], schemes)
            if scheme is None:
                log.append(f"流 {stream_id} [{direction}]: "
                           f"{len(items)} 个加密消息未能解密（密钥/哈希不匹配）")
                continue
            working[direction] = scheme
            source, cipher, key, preauth, frames, base = scheme
            session.cipher = cipher
            session.session_key = key.hex()
            session.nt_session_key = bytes(base or b"").hex()
            session.key_source = source
            session.preauth = preauth.hex()
            session.preauth_frames = list(frames)
            session.session_id = f"{items[0][3].session_id:#x}"
            log.append(f"流 {stream_id} [{direction}]: 解密成功 "
                       f"cipher={cipher} key={key.hex()} 来源={source}")
            for _sort, frame, _direction, message in items[:MAX_TRANSFORMS]:
                plain, ok = decrypt_transform(key, cipher, message)
                if not ok:
                    continue
                session.decrypted += 1
                flags.extend(_flags_in(plain))
                for parsed in smb_util.parse_packet(plain):
                    parsed.frame = str(frame)
                    decrypted_messages.append(DecryptedMessage(
                        frame=str(frame), stream=stream_id,
                        direction=direction, cipher=cipher,
                        message=parsed))
                    files.feed(str(frame), parsed)
                    if parsed.command == 1 and parsed.session_id:
                        session.session_id = f"{parsed.session_id:#x}"

        if session.cipher:
            sessions.append(session)

    #: One record per decrypted session: the key material a user needs to
    #: re-run the decryption (and what ``smb3_keys.txt`` persists).
    keys: list[dict] = []
    for session in sessions:
        if not session.cipher:
            continue
        keys.append({
            "stream": session.stream,
            "session_id": session.session_id,
            "cipher": session.cipher,
            "key_source": session.key_source,
            "session_key": session.nt_session_key,
            "cipher_key": session.session_key,
            "user": session.user,
            "domain": session.domain,
            "decrypted": session.decrypted,
        })
    keys.sort(key=lambda item: (len(str(item["stream"])), str(item["stream"]),
                                str(item["session_id"])))

    exported = files.export()
    written: list[dict] = []
    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        lines = []
        for message in decrypted_messages:
            item = message.message
            name = f" {item.file_name}" if item.file_name else ""
            lines.append(
                f"frame={message.frame}\tstream={message.stream}\t"
                f"{message.direction}\t{item.command_name}{name}\t"
                f"status={item.status_text()}")
        if lines:
            (out / "smb3_decrypted.txt").write_text(
                "\n".join(lines) + "\n", encoding="utf-8")
            written.append({"name": "smb3_decrypted.txt",
                            "size": (out / "smb3_decrypted.txt").stat().st_size})
        file_lines = []
        for entry in exported:
            name = (f"smb3_file_{entry['number']}_"
                    f"{_safe_name(entry['name'])}.bin")
            (out / name).write_bytes(entry["data"])
            written.append({"name": name, "size": entry["size"]})
            file_lines.append(f"{entry['path']}\t{entry['size']} 字节\t"
                              f"md5={entry['md5']}\tframe={entry['frame']}\t"
                              f"{name}")
        if file_lines:
            (out / "smb3_files.txt").write_text(
                "\n".join(file_lines) + "\n", encoding="utf-8")
            written.append({"name": "smb3_files.txt",
                            "size": (out / "smb3_files.txt").stat().st_size})
        if keys:
            key_path = out / KEYS_FILE_NAME
            key_path.write_text(keys_file_text(keys), encoding="utf-8")
            written.append({"name": KEYS_FILE_NAME,
                            "size": key_path.stat().st_size})

    total = len(decrypted_messages)
    text_lines = []
    if sessions:
        for session in sessions:
            label = (f"{session.domain}\\{session.user}"
                     if session.domain else session.user) or "?"
            text_lines.append(
                f"流 {session.stream}: {session.client} -> {session.server} "
                f"账号={label} 方言={session.dialect or '?'} "
                f"解密 {session.decrypted} 条")
            if session.cipher:
                text_lines.append(f"  cipher={session.cipher} "
                                  f"key={session.session_key}")
                if session.preauth:
                    text_lines.append(f"  preauth={session.preauth}")
                    if session.preauth_frames:
                        text_lines.append("  preauth 帧="
                                          + ", ".join(session.preauth_frames))
    else:
        text_lines.append("没有解密任何 SMB3 加密消息")
    if exported:
        text_lines.append("")
        for entry in exported:
            text_lines.append(f"文件 {entry['path']} {entry['size']} 字节 "
                              f"md5={entry['md5']}")
    if flags:
        text_lines.append("")
        text_lines.append("flag: " + ", ".join(sorted(set(flags))))
    text = "\n".join(text_lines)
    log.extend(text_lines)
    return {
        "ok": total > 0,
        "text": text,
        "log": log,
        "sessions": [session.as_dict() for session in sessions],
        "keys": keys,
        "files": written,
        "flags": sorted(set(flags)),
        "decrypted": total,
        "error": "" if total else "没有解密任何消息（密钥不匹配或流量未加密）",
    }
