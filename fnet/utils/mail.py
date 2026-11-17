"""SMTP, IMAP, POP3 and MIME helpers for mail traffic analysis.

Wireshark's SMTP/IMAP/POP3 dissectors are good at naming fields but they do
not hand back the complete message, and they assume the standard ports.  This
module works on reassembled ``tcp.payload`` bytes instead: it tokenises the
protocol transcripts, pulls out credentials and embedded MIME messages, and
exposes the parts (filenames, hashes, decoded bodies) an analyst needs.

Design rules:

* standard library only -- :mod:`email` does the MIME work;
* every parser accepts ``bytes`` or ``str`` and is defensive against truncated
  captures and garbage: a broken message is skipped, never raised;
* sizes are capped (:data:`MAX_MESSAGE`, :data:`MAX_ATTACHMENTS`,
  :data:`MAX_ATTACHMENT_BYTES`) so a hostile capture cannot exhaust memory;
* nothing is written to disk unless :func:`save_attachments` is called.
"""
from __future__ import annotations

import base64
import binascii
import email
import email.policy
import hashlib
import mimetypes
import re
import urllib.parse
from email.header import decode_header, make_header
from email.message import Message
from pathlib import Path
from typing import Any

#: Largest raw message / transcript chunk that is inspected.
MAX_MESSAGE = 8 * 1024 * 1024
#: Largest number of attachment parts returned per message.
MAX_ATTACHMENTS = 32
#: Largest decoded attachment body kept in memory (hashes cover all bytes).
MAX_ATTACHMENT_BYTES = 4 * 1024 * 1024

_POLICY = email.policy.default

_HEADER_FIELDS = ("From", "To", "Cc", "Subject", "Date", "Message-ID",
                  "Reply-To", "Return-Path")
_RECEIVED_KEYS = ("from", "by", "with", "id", "for", "date")

__all__ = [
    "MAX_MESSAGE", "MAX_ATTACHMENTS", "MAX_ATTACHMENT_BYTES",
    "parse_message", "attachment_entries", "save_attachments",
    "delivery_chain", "header_summary", "smtp_transcript",
    "imap_transcript", "pop3_transcript", "mail_summary",
]


# -- generic helpers ---------------------------------------------------
def _raw_bytes(data: bytes | bytearray | memoryview | str | None) -> bytes:
    """Coerce capture data to bytes without ever raising."""
    if data is None:
        return b""
    if isinstance(data, str):
        return data.encode("latin-1", "replace")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return bytes(data)
    try:
        return bytes(data)
    except Exception:
        return str(data).encode("latin-1", "replace")


def _collapse(value: str) -> str:
    return re.sub(r"\s+", " ", value or "").strip()


def _decode_bytes(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1", "replace")


def _b64_bytes(value: str) -> bytes:
    """Decode a base64 token, falling back to its literal bytes."""
    cleaned = re.sub(r"\s+", "", value or "")
    if not cleaned:
        return b""
    padded = cleaned + "=" * (-len(cleaned) % 4)
    for validate in (True, False):
        try:
            return base64.b64decode(padded, validate=validate)
        except (binascii.Error, ValueError):
            continue
    return value.encode("latin-1", "replace")


def _b64_text(value: str) -> str:
    text = _decode_bytes(_b64_bytes(value))
    if text and all(ch == "\t" or ord(ch) >= 32 for ch in text):
        return text
    return (value or "").strip()


def _plain_credentials(token: str) -> tuple[str, str]:
    """Split an AUTH PLAIN token (``authzid\\0authcid\\0passwd``)."""
    raw = _b64_bytes(token)
    parts = raw.split(b"\x00")
    if len(parts) >= 3:
        return _decode_bytes(parts[-2]), _decode_bytes(parts[-1])
    if len(parts) == 2:
        return _decode_bytes(parts[0]), _decode_bytes(parts[1])
    return _decode_bytes(raw), ""


def _decode_words(value: str) -> str:
    """Decode RFC 2047 encoded words, leaving malformed text untouched."""
    text = str(value or "")
    if "=?" not in text:
        return text
    try:
        return str(make_header(decode_header(text)))
    except Exception:
        return text


# -- MIME parsing ------------------------------------------------------
def parse_message(raw: bytes | bytearray | memoryview | str | None) -> Message:
    """Parse raw bytes into a :class:`email.message.Message`.

    ``email.policy.default`` is used so headers are decoded and RFC 2231
    parameters are available.  Malformed input returns an empty message rather
    than raising.
    """
    data = _raw_bytes(raw)[:MAX_MESSAGE]
    try:
        return email.message_from_bytes(data, policy=_POLICY)
    except Exception:
        pass
    try:
        text = data.decode("latin-1", "replace")
        return email.message_from_string(text, policy=_POLICY)
    except Exception:
        pass
    try:
        return email.message_from_bytes(b"", policy=_POLICY)
    except Exception:  # pragma: no cover - email always parses b""
        return Message()


def _filename_from_headers(part: Message) -> str:
    for header in ("Content-Disposition", "Content-Type"):
        try:
            raw = part.get(header)
        except Exception:
            continue
        if not raw:
            continue
        text = str(raw)
        match = re.search(
            r"(?i)(?:filename|name)\*\s*=\s*"
            r"(?:[^'\s;]*'[^']*')?([^;\r\n]+)", text)
        if match:
            return urllib.parse.unquote(match.group(1).strip().strip('"'))
    return ""


def _filename(part: Message) -> str:
    name = ""
    try:
        name = part.get_filename() or ""
    except Exception:
        name = ""
    if not name:
        name = _filename_from_headers(part)
    return _collapse(_decode_words(str(name)))


def _content_type(part: Message) -> str:
    try:
        value = part.get_content_type()
    except Exception:
        value = ""
    return _collapse(str(value or "")).lower() or "application/octet-stream"


def _disposition(part: Message) -> str:
    try:
        value = part.get_content_disposition()
    except Exception:
        value = ""
    return (value or "").strip().lower()


def _is_attachment(part: Message) -> bool:
    try:
        if part.is_multipart():
            return False
        maintype = part.get_content_maintype()
    except Exception:
        return False
    if maintype == "multipart":
        return False
    if _disposition(part) == "attachment":
        return True
    if _filename(part):
        return True
    return maintype not in ("text", "message")


def _part_payload(part: Message) -> bytes:
    payload: Any = None
    try:
        payload = part.get_payload(decode=True)
    except Exception:
        payload = None
    if payload is None:
        # message/rfc822 (or a broken part): serialise the nested message.
        inner = None
        try:
            inner = part.get_payload()
        except Exception:
            inner = None
        if isinstance(inner, list) and inner:
            try:
                payload = inner[0].as_bytes()
            except Exception:
                payload = b""
        else:
            payload = b""
    try:
        return bytes(payload or b"")
    except Exception:
        return b""


def _attachment_entry(part: Message) -> dict[str, Any]:
    full = _part_payload(part)
    return {
        "filename": _filename(part),
        "content_type": _content_type(part),
        "size": len(full),
        "md5": hashlib.md5(full).hexdigest(),
        "sha256": hashlib.sha256(full).hexdigest(),
        "data": full[:MAX_ATTACHMENT_BYTES],
        "inline": _disposition(part) == "inline",
    }


def attachment_entries(message: Message | None) -> list[dict[str, Any]]:
    """Return every attachment part of ``message`` as a dictionary.

    Keys: ``filename``, ``content_type``, ``size``, ``md5``, ``sha256``,
    ``data`` (capped at :data:`MAX_ATTACHMENT_BYTES`) and ``inline``.
    """
    entries: list[dict[str, Any]] = []
    if message is None:
        return entries
    try:
        parts = list(message.walk())
    except Exception:
        return entries
    for part in parts:
        if len(entries) >= MAX_ATTACHMENTS:
            break
        try:
            if not _is_attachment(part):
                continue
            entries.append(_attachment_entry(part))
        except Exception:
            continue
    return entries


def _safe_name(name: str, fallback: str) -> str:
    base = (name or "").replace("\\", "/").rsplit("/", 1)[-1]
    base = re.sub(r"[\x00-\x1f\x7f]", "", base).strip()
    base = re.sub(r"[^0-9A-Za-z._-]+", "_", base)
    base = base.strip("._")[:120]
    if not base:
        base = fallback
    return base[:120] or "attachment.bin"


def _unique_path(directory: Path, name: str) -> Path:
    candidate = directory / name
    stem = candidate.stem
    suffix = candidate.suffix
    counter = 1
    while candidate.exists() and counter < 10_000:
        candidate = directory / f"{stem}-{counter}{suffix}"
        counter += 1
    return candidate


def save_attachments(message: Message | None, outdir: str | Path,
                     prefix: str = "mail") -> list[str]:
    """Write every decoded attachment under ``outdir``; return the paths."""
    paths: list[str] = []
    directory = Path(outdir)
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError:
        return paths
    base = _safe_name(prefix, "mail")
    for index, entry in enumerate(attachment_entries(message), start=1):
        content_type = str(entry.get("content_type") or "").split(";")[0]
        try:
            suffix = mimetypes.guess_extension(content_type.strip()) or ""
        except Exception:
            suffix = ""
        fallback = f"{base}_{index}{suffix}"
        name = _safe_name(str(entry.get("filename") or ""), fallback)
        path = _unique_path(directory, name)
        try:
            path.write_bytes(entry.get("data") or b"")
        except OSError:
            continue
        paths.append(str(path))
    return paths


# -- headers -----------------------------------------------------------
def _header_text(value: Any) -> str:
    if value is None:
        return ""
    try:
        text = str(value)
    except Exception:
        try:
            text = value.decode("latin-1", "replace")
        except Exception:
            return ""
    text = _decode_words(text)
    cleaned = "".join(
        " " if ord(ch) < 32 and ch not in "\t" else ch for ch in text)
    return _collapse(cleaned)


def _header_values(message: Message | None, name: str) -> list[str]:
    if message is None:
        return []
    try:
        values = message.get_all(name) or []
    except Exception:
        return []
    result: list[str] = []
    for value in values:
        text = _header_text(value)
        if text:
            result.append(text)
    return result


def header_summary(message: Message | None) -> dict[str, str]:
    """Return the interesting headers with RFC 2047 words decoded."""
    summary = {name: "" for name in _HEADER_FIELDS}
    if message is None:
        return summary
    for name in _HEADER_FIELDS:
        try:
            values = _header_values(message, name)
        except Exception:
            continue
        if values:
            summary[name] = ", ".join(values)
    return summary


def _parse_received(value: str) -> dict[str, str]:
    entry = {key: "" for key in _RECEIVED_KEYS}
    text = _collapse(value)
    head, separator, date = text.rpartition(";")
    if not separator:
        head = text
        date = ""
    entry["date"] = _collapse(date)
    for match in re.finditer(
            r"\b(from|by|with|id|for)\s+([^;]*?)"
            r"(?=\s+(?:from|by|with|id|for)\s+|$)",
            head, re.IGNORECASE):
        key = match.group(1).lower()
        if key in entry and not entry[key]:
            entry[key] = match.group(2).strip()
    return entry


def delivery_chain(message: Message | None) -> list[dict[str, str]]:
    """Parse every ``Received`` header, most recent hop first."""
    chain: list[dict[str, str]] = []
    for value in _header_values(message, "Received"):
        try:
            chain.append(_parse_received(value))
        except Exception:
            continue
    return chain


# -- transcript helpers ------------------------------------------------
def _lines(raw: bytes) -> list[bytes]:
    return [line[:-1] if line.endswith(b"\r") else line
            for line in raw.split(b"\n")]


def _empty_summary(protocol: str) -> dict[str, Any]:
    return {
        "protocol": protocol,
        "commands": [],
        "credentials": [],
        "mail_from": [],
        "rcpt_to": [],
        "mailboxes": [],
        "uids": [],
        "messages": [],
    }


def _message_entry(raw: bytes, protocol: str, *, mailbox: str = "",
                   source: str = "", **extra: Any) -> dict[str, Any]:
    data = raw[:MAX_MESSAGE] if raw else b""
    message = parse_message(data)
    attachments: list[dict[str, Any]] = []
    try:
        attachments = [{key: value for key, value in item.items()
                        if key != "data"}
                       for item in attachment_entries(message)]
    except Exception:
        attachments = []
    entry: dict[str, Any] = {
        "protocol": protocol,
        "source": source,
        "mailbox": mailbox,
        "size": len(raw or b""),
        "summary": header_summary(message),
        "attachments": attachments,
        "message": message,
    }
    entry.update(extra)
    return entry


# -- SMTP --------------------------------------------------------------
_SMTP_REPLY = re.compile(r"^\d{3}(?:[ -]|$)")
_SMTP_COMMAND = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,15}$")
_SMTP_ADDRESS = re.compile(r"<([^<>]*)>")


def _smtp_address(argument: str) -> str:
    match = _SMTP_ADDRESS.search(argument or "")
    if match:
        return match.group(1).strip()
    tokens = (argument or "").split()
    if not tokens:
        return ""
    value = tokens[0]
    if ":" in value:
        value = value.split(":", 1)[1]
    return value.strip().strip("<>")


def _smtp_data(lines: list[bytes],
               index: int) -> tuple[list[bytes], int]:
    """Collect a DATA block until the ``.`` terminator, unstuffing dots."""
    body: list[bytes] = []
    while index < len(lines):
        line = lines[index]
        index += 1
        if line == b".":
            break
        if not body and _SMTP_REPLY.match(line.decode("latin-1", "replace")):
            # The ``354`` continuation reply sits between DATA and the body.
            continue
        if line.startswith(b"."):
            line = line[1:]
        body.append(line)
    return body, index


def _smtp_plain(result: dict[str, Any], token: str) -> None:
    username, password = _plain_credentials(token)
    if not username and not password:
        return
    result["credentials"].append({
        "protocol": "smtp", "mechanism": "PLAIN",
        "username": username, "password": password, "raw": token,
    })


def smtp_transcript(data: bytes | str | None) -> dict[str, Any]:
    """Parse an SMTP client/server transcript.

    Returns a dict with ``commands``, ``credentials``, ``mail_from``,
    ``rcpt_to`` and ``messages`` (each with a parsed ``message``).
    Server reply lines are skipped.
    """
    result = _empty_summary("smtp")
    try:
        raw = _raw_bytes(data)[:MAX_MESSAGE]
        lines = _lines(raw)
        index = 0
        sender = ""
        recipients: list[str] = []
        state = ""
        auth_user = ""
        while index < len(lines):
            line = lines[index]
            index += 1
            text = _collapse(line.decode("latin-1", "replace"))
            if not text:
                continue
            if state:
                if _SMTP_REPLY.match(text):
                    continue
                token = text
                if state == "plain":
                    _smtp_plain(result, token)
                    state = ""
                elif state == "login_user":
                    auth_user = _b64_text(token)
                    state = "login_password"
                else:
                    result["credentials"].append({
                        "protocol": "smtp", "mechanism": "LOGIN",
                        "username": auth_user,
                        "password": _b64_text(token), "raw": token,
                    })
                    auth_user = ""
                    state = ""
                continue
            if _SMTP_REPLY.match(text):
                continue
            command, _, argument = text.partition(" ")
            command = command.upper()
            argument = argument.strip()
            if not _SMTP_COMMAND.match(command):
                continue
            result["commands"].append(
                {"command": command, "argument": argument})
            if command == "AUTH":
                mechanism, _, initial = argument.partition(" ")
                mechanism = mechanism.upper()
                initial = initial.strip()
                if mechanism == "PLAIN":
                    if initial:
                        _smtp_plain(result, initial)
                    else:
                        state = "plain"
                elif mechanism == "LOGIN":
                    if initial:
                        auth_user = _b64_text(initial)
                        state = "login_password"
                    else:
                        state = "login_user"
                elif initial:
                    result["credentials"].append({
                        "protocol": "smtp", "mechanism": mechanism,
                        "username": "", "password": "", "raw": initial,
                    })
            elif command == "MAIL":
                sender = _smtp_address(argument)
                recipients = []
                if sender:
                    result["mail_from"].append(sender)
            elif command == "RCPT":
                recipient = _smtp_address(argument)
                if recipient:
                    result["rcpt_to"].append(recipient)
                    recipients.append(recipient)
            elif command == "RSET":
                sender = ""
                recipients = []
            elif command == "DATA":
                body, index = _smtp_data(lines, index)
                raw_message = b"\r\n".join(body)
                if body:
                    raw_message += b"\r\n"
                result["messages"].append(_message_entry(
                    raw_message, "smtp", source="DATA",
                    mail_from=sender, rcpt_to=list(recipients)))
                sender = ""
                recipients = []
    except Exception:
        return result
    return result


# -- IMAP --------------------------------------------------------------
_IMAP_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_IMAP_COMMAND = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,15}$")
_IMAP_LITERAL = re.compile(r"\{(\d+)\+?\}$")
_IMAP_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|(\S+)')
_HEADER_LINE = re.compile(rb"^[!-9;-~]+:[ \t]", re.MULTILINE)


def _looks_like_message(raw: bytes) -> bool:
    if not raw:
        return False
    head = raw[:8192]
    if head.startswith(b"From "):
        return True
    return bool(_HEADER_LINE.search(head))


def _read_line(raw: bytes, position: int) -> tuple[bytes, int]:
    end = raw.find(b"\n", position)
    if end < 0:
        return raw[position:], len(raw)
    return raw[position:end], end + 1


def _read_imap_line(raw: bytes,
                    position: int) -> tuple[str, list[bytes], int]:
    """Read one logical IMAP line, resolving ``{N}`` literals."""
    parts: list[str] = []
    literals: list[bytes] = []
    line, position = _read_line(raw, position)
    text = line.rstrip(b"\r").decode("latin-1", "replace")
    while True:
        match = _IMAP_LITERAL.search(text)
        if match is None or position >= len(raw):
            parts.append(text)
            break
        size = max(0, min(int(match.group(1)), MAX_MESSAGE))
        parts.append(text[:match.start()])
        literals.append(raw[position:position + size])
        position += size
        line, position = _read_line(raw, position)
        text = line.rstrip(b"\r").decode("latin-1", "replace")
    return "".join(parts), literals, position


def _imap_args(text: str) -> list[str]:
    tokens: list[str] = []
    for match in _IMAP_TOKEN.finditer(text or ""):
        quoted = match.group(1)
        if quoted is not None:
            tokens.append(re.sub(r"\\(.)", r"\1", quoted))
        else:
            tokens.append(match.group(2) or "")
    return tokens


def _add_mailbox(result: dict[str, Any], name: str) -> None:
    if name and name not in result["mailboxes"]:
        result["mailboxes"].append(name)


def _imap_record_plain(result: dict[str, Any], token: str,
                       mechanism: str = "PLAIN") -> None:
    username, password = _plain_credentials(token)
    if not username and not password:
        return
    result["credentials"].append({
        "protocol": "imap", "mechanism": mechanism,
        "username": username, "password": password, "raw": token,
    })


def imap_transcript(data: bytes | str | None) -> dict[str, Any]:
    """Parse an IMAP transcript, including ``{N}`` literals.

    Returns a dict with ``commands``, ``credentials``, ``mailboxes`` and
    ``messages`` extracted from ``FETCH``/``APPEND`` literals.
    """
    result = _empty_summary("imap")
    try:
        raw = _raw_bytes(data)[:MAX_MESSAGE]
        position = 0
        selected = ""
        while position < len(raw):
            text, literals, position = _read_imap_line(raw, position)
            text = text.strip()
            if not text:
                continue
            if text.startswith("*"):
                if literals and "FETCH" in text.upper():
                    for literal in literals:
                        if _looks_like_message(literal):
                            result["messages"].append(_message_entry(
                                literal, "imap", mailbox=selected,
                                source="FETCH"))
                continue
            if text.startswith("+"):
                continue
            parts = text.split(None, 2)
            if len(parts) < 2:
                continue
            tag = parts[0]
            command = parts[1].upper()
            arguments = parts[2] if len(parts) > 2 else ""
            if not _IMAP_TAG.match(tag) or not _IMAP_COMMAND.match(command):
                continue
            if command in ("OK", "NO", "BAD", "BYE", "PREAUTH"):
                continue
            result["commands"].append({
                "tag": tag, "command": command, "arguments": arguments,
                "literals": [len(item) for item in literals],
            })
            if command == "LOGIN":
                tokens = _imap_args(arguments)
                username = tokens[0] if tokens else ""
                password = tokens[1] if len(tokens) > 1 else ""
                if username or password:
                    result["credentials"].append({
                        "protocol": "imap", "mechanism": "LOGIN",
                        "username": username, "password": password,
                        "tag": tag,
                    })
            elif command == "AUTHENTICATE":
                tokens = _imap_args(arguments)
                mechanism = tokens[0].upper() if tokens else ""
                initial = tokens[1] if len(tokens) > 1 else ""
                if literals:
                    initial = literals[0].decode("latin-1", "replace")
                if mechanism == "PLAIN" and initial:
                    _imap_record_plain(result, initial)
                elif mechanism:
                    result["credentials"].append({
                        "protocol": "imap", "mechanism": mechanism,
                        "username": "", "password": "", "raw": initial,
                        "tag": tag,
                    })
            elif command in ("SELECT", "EXAMINE"):
                tokens = _imap_args(arguments)
                if tokens:
                    selected = tokens[0]
                    _add_mailbox(result, selected)
            elif command == "APPEND":
                tokens = _imap_args(arguments)
                mailbox = tokens[0] if tokens else selected
                _add_mailbox(result, mailbox)
                for literal in literals:
                    result["messages"].append(_message_entry(
                        literal, "imap", mailbox=mailbox, source="APPEND"))
            elif command in ("CREATE", "DELETE", "STATUS", "RENAME"):
                tokens = _imap_args(arguments)
                if tokens:
                    _add_mailbox(result, tokens[0])
            elif command == "FETCH":
                for literal in literals:
                    if _looks_like_message(literal):
                        result["messages"].append(_message_entry(
                            literal, "imap", mailbox=selected,
                            source="FETCH"))
    except Exception:
        return result
    return result


# -- POP3 --------------------------------------------------------------
_POP3_REPLY = re.compile(r"^(?:\+OK|-ERR)", re.IGNORECASE)
_POP3_COMMAND = re.compile(r"^[A-Z][A-Z0-9]{1,7}$")


def _pop3_body(lines: list[bytes],
               index: int) -> tuple[list[bytes], int]:
    """Collect a multi-line POP3 response terminated by a lone ``.``."""
    body: list[bytes] = []
    while index < len(lines):
        line = lines[index]
        index += 1
        if line == b".":
            break
        if line.startswith(b"."):
            line = line[1:]
        if not body and _POP3_REPLY.match(line.decode("latin-1", "replace")):
            continue
        body.append(line)
    return body, index


def pop3_transcript(data: bytes | str | None) -> dict[str, Any]:
    """Parse a POP3 transcript (``USER``/``PASS``/``APOP``/``RETR``/``TOP``).

    Returns a dict with ``commands``, ``credentials``, ``uids`` and
    ``messages``.  Server replies are skipped; ``RETR``/``TOP`` bodies are
    parsed as MIME messages.
    """
    result = _empty_summary("pop3")
    try:
        raw = _raw_bytes(data)[:MAX_MESSAGE]
        lines = _lines(raw)
        index = 0
        user = ""
        while index < len(lines):
            text = _collapse(lines[index].decode("latin-1", "replace"))
            index += 1
            if not text:
                continue
            if _POP3_REPLY.match(text) or text.startswith("+"):
                continue
            command, _, argument = text.partition(" ")
            command = command.upper()
            argument = argument.strip()
            if not _POP3_COMMAND.match(command):
                continue
            result["commands"].append(
                {"command": command, "argument": argument})
            if command == "USER":
                user = argument
            elif command == "PASS":
                result["credentials"].append({
                    "protocol": "pop3", "mechanism": "USER",
                    "username": user, "password": argument,
                })
            elif command == "APOP":
                account, _, digest = argument.partition(" ")
                if account or digest:
                    result["credentials"].append({
                        "protocol": "pop3", "mechanism": "APOP",
                        "username": account, "password": digest,
                        "digest": digest,
                    })
            elif command in ("RETR", "TOP"):
                body, index = _pop3_body(lines, index)
                if body:
                    raw_message = b"\r\n".join(body) + b"\r\n"
                    number = argument.split()[0] if argument.split() else ""
                    result["messages"].append(_message_entry(
                        raw_message, "pop3", source=command,
                        message_number=number))
            elif command == "UIDL":
                body, index = _pop3_body(lines, index)
                for line in body:
                    fields = line.decode("latin-1", "replace").split(None, 1)
                    if len(fields) == 2:
                        result["uids"].append({
                            "message": fields[0], "uid": fields[1].strip()})
                if argument and not body:
                    fields = argument.split(None, 1)
                    if len(fields) == 2:
                        result["uids"].append({
                            "message": fields[0], "uid": fields[1].strip()})
    except Exception:
        return result
    return result


# -- dispatcher --------------------------------------------------------
_HANDLERS = {
    "smtp": smtp_transcript,
    "esmtp": smtp_transcript,
    "submission": smtp_transcript,
    "imap": imap_transcript,
    "imap4": imap_transcript,
    "pop3": pop3_transcript,
    "pop": pop3_transcript,
}


def _sniff_protocol(raw: bytes) -> str:
    head = raw[:8192]
    upper = head.upper()
    if (b"EHLO " in upper or b"HELO " in upper
            or b"MAIL FROM:" in upper or b"AUTH PLAIN" in upper):
        return "smtp"
    if b"+OK" in upper and (b"USER " in upper or b"PASS " in upper
                            or b"RETR" in upper or b"APOP " in upper):
        return "pop3"
    if (re.search(rb"(?m)^\* OK", head)
            or re.search(rb"(?m)^\S+ (?:LOGIN|FETCH|APPEND|SELECT)\b",
                         upper)):
        return "imap"
    return ""


def mail_summary(protocol: str, data: bytes | str | None) -> dict[str, Any]:
    """Dispatch to the SMTP/IMAP/POP3 parser and never raise."""
    name = _collapse(str(protocol or "")).lower()
    handler = _HANDLERS.get(name)
    try:
        if handler is None:
            name = _sniff_protocol(_raw_bytes(data)[:8192])
            handler = _HANDLERS.get(name)
        if handler is None:
            return _empty_summary(name or "mail")
        return handler(data)
    except Exception:
        return _empty_summary(name or "mail")
