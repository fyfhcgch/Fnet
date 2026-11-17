"""Redis RESP2/RESP3 parsing over a reassembled TCP stream.

There is no Redis dissector in Wireshark, so Fnet parses the wire protocol
itself.  Compared to the early per-packet parser this module adds:

* RESP3 types (maps, sets, push messages, attributes, doubles, booleans …);
* cluster redirections (``MOVED``/``ASK``) and the target node;
* Pub/Sub subscribe/unsubscribe/publish/message frames;
* ``EVAL``/``EVALSHA`` scripts with ``numkeys``/keys/arguments, plus a small
  Base64/Hex unwrap for scripts that are stored encoded;
* ACL changes (``ACL SETUSER``/``DELUSER``) and ``CONFIG SET requirepass``;
* sensitive key reads and decoded flag values.

Everything is a pure function so it can be unit tested without tshark.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

#: Kept in sync with :data:`fnet.utils.protocol_detect.REDIS_COMMANDS`.
COMMANDS = frozenset({
    "AUTH", "HELLO", "SELECT", "GET", "SET", "SETEX", "PSETEX", "MSET",
    "MGET", "DEL", "EXISTS", "HGET", "HSET", "HGETALL", "LPUSH", "RPUSH",
    "LRANGE", "SADD", "SMEMBERS", "CONFIG", "INFO", "KEYS", "SCAN", "EVAL",
    "EVALSHA", "SCRIPT", "FLUSHALL", "FLUSHDB", "CLIENT", "ACL", "MONITOR",
    "SUBSCRIBE", "UNSUBSCRIBE", "PSUBSCRIBE", "PUNSUBSCRIBE", "PSUBSCRIBE",
    "PUBLISH", "PUBSUB", "PING", "COMMAND", "CLUSTER", "READONLY",
    "READWRITE", "ASKING", "MULTI", "EXEC", "DISCARD", "WATCH", "UNWATCH",
    "TTL", "EXPIRE", "TYPE", "DBSIZE", "SORT", "XADD", "XREAD", "XINFO",
})
PUBSUB_COMMANDS = frozenset({
    "SUBSCRIBE", "UNSUBSCRIBE", "PSUBSCRIBE", "PUNSUBSCRIBE", "PUBLISH",
    "PUBSUB", "SSUBSCRIBE", "SUNSUBSCRIBE",
})
SENSITIVE_RE = re.compile(r"(?i)(pass|pwd|token|secret|flag|key|credential)")
REDIRECT_RE = re.compile(r"^(MOVED|ASK)\s+(\d+)\s+(\S+)$", re.I)
MAX_VALUE_DEPTH = 32


class RespError(ValueError):
    """Raised when a RESP value cannot be framed."""


@dataclass
class RespValue:
    kind: str
    value: object
    start: int
    end: int

    @property
    def text(self) -> str:
        if isinstance(self.value, str):
            return self.value
        if isinstance(self.value, (int, float)):
            return str(self.value)
        return ""


@dataclass
class RedisMessage:
    """One parsed protocol element with its byte offset and frame."""

    kind: str                 # command | push | error | reply | inline | other
    name: str = ""
    args: list[str] = field(default_factory=list)
    value: object = None
    offset: int = 0
    frame: str = ""
    raw: bytes = b""

    @property
    def command(self) -> str:
        return (self.args[0].upper() if self.args else self.name.upper())


def _line(data: bytes, index: int) -> tuple[bytes, int]:
    end = data.find(b"\r\n", index)
    if end < 0:
        raise RespError("unterminated RESP line")
    return data[index:end], end + 2


def _bulk(data: bytes, index: int, marker: bytes) -> tuple[bytes, int]:
    head, cursor = _line(data, index)
    try:
        length = int(head)
    except ValueError as exc:
        raise RespError("bad RESP bulk length") from exc
    if length < 0:
        return b"", cursor
    end = cursor + length
    if end > len(data):
        raise RespError("truncated RESP bulk string")
    # Bulk strings are followed by CRLF, which belongs to the value.
    return data[cursor:end], end + 2 if data[end:end + 2] == b"\r\n" else end


def _parse_value(data: bytes, index: int, depth: int = 0) -> RespValue:
    if depth > MAX_VALUE_DEPTH:
        raise RespError("RESP nesting too deep")
    if index >= len(data):
        raise RespError("empty RESP value")
    marker = data[index:index + 1]
    start = index
    if marker in (b"*", b"~", b">"):
        head, cursor = _line(data, index + 1)
        try:
            count = int(head)
        except ValueError as exc:
            raise RespError("bad RESP aggregate length") from exc
        if count < 0:
            return RespValue("array", [], start, cursor)
        if count > 1_000_000:
            raise RespError("RESP aggregate too large")
        items = []
        for _ in range(count):
            item = _parse_value(data, cursor, depth + 1)
            items.append(item.value)
            cursor = item.end
        kind = {b"*": "array", b"~": "set", b">": "push"}[marker]
        return RespValue(kind, items, start, cursor)
    if marker == b"%":
        head, cursor = _line(data, index + 1)
        count = int(head or b"0")
        pairs = []
        for _ in range(max(0, count) * 2):
            item = _parse_value(data, cursor, depth + 1)
            pairs.append(item.value)
            cursor = item.end
        value = {str(pairs[i]): pairs[i + 1]
                 for i in range(0, len(pairs) - 1, 2)}
        return RespValue("map", value, start, cursor)
    if marker == b"|":
        # RESP3 attribute: a map prefixed to the following value.
        head, cursor = _line(data, index + 1)
        count = int(head or b"0")
        for _ in range(max(0, count) * 2):
            cursor = _parse_value(data, cursor, depth + 1).end
        return RespValue("attribute", {}, start, cursor)
    if marker in (b"+", b"-", b":", b",", b"(", b"#"):
        line, cursor = _line(data, index + 1)
        text = line.decode("utf-8", "replace")
        if marker == b"+":
            return RespValue("simple", text, start, cursor)
        if marker == b"-":
            return RespValue("error", text, start, cursor)
        if marker == b":":
            try:
                return RespValue("integer", int(text), start, cursor)
            except ValueError:
                return RespValue("integer", text, start, cursor)
        if marker == b",":
            try:
                return RespValue("double", float(text), start, cursor)
            except ValueError:
                return RespValue("double", text, start, cursor)
        if marker == b"(":
            return RespValue("bigint", text, start, cursor)
        return RespValue("boolean", text == "t", start, cursor)
    if marker == b"_":
        return RespValue("null", None, start, index + 2)
    if marker in (b"$", b"!"):
        payload, cursor = _bulk(data, index + 1, marker)
        text = payload.decode("utf-8", "replace")
        kind = "bulk" if marker == b"$" else "error"
        return RespValue(kind, text, start, cursor)
    if marker == b"=":
        payload, cursor = _bulk(data, index + 1, marker)
        text = payload[4:].decode("utf-8", "replace") if len(payload) >= 4 else ""
        return RespValue("verbatim", text, start, cursor)
    # Inline command: "PING\r\n" or "SET key value\r\n".
    line, cursor = _line(data, index)
    text = line.decode("utf-8", "replace").strip()
    return RespValue("inline", text, start, cursor)


def _strings(values) -> list[str]:
    result: list[str] = []
    for value in values if isinstance(values, (list, tuple)) else []:
        if isinstance(value, str):
            result.append(value)
        elif value is None:
            result.append("")
        elif isinstance(value, bool):
            result.append("1" if value else "0")
        else:
            result.append(str(value))
    return result


def parse_messages(data: bytes, frame_lookup=None) -> list[RedisMessage]:
    """Parse a reassembled Redis byte stream into commands and replies."""
    messages: list[RedisMessage] = []
    index = 0
    size = len(data or b"")
    while index < size:
        while index < size and data[index] in b"\r\n \t":
            index += 1
        if index >= size:
            break
        try:
            parsed = _parse_value(data, index)
        except (RespError, ValueError, IndexError):
            # Corrupt or truncated tail: stop; the next capture may hold the
            # rest of the frame and the caller reports the truncation.
            break
        frame = frame_lookup(index) if frame_lookup else ""
        raw = data[parsed.start:parsed.end]
        if parsed.kind in ("array", "set", "push"):
            args = _strings(parsed.value)
            if parsed.kind == "push":
                kind = "push"
            elif args and (args[0].upper() in COMMANDS
                           or re.fullmatch(r"[A-Za-z]{2,24}", args[0] or "")):
                kind = "command"
            else:
                kind = "reply"
            messages.append(RedisMessage(
                kind=kind, name=args[0] if args else "", args=args,
                value=parsed.value, offset=parsed.start, frame=frame,
                raw=raw))
        elif parsed.kind == "inline":
            text = str(parsed.value or "")
            if text:
                args = text.split()
                if args:
                    command = args[0].upper()
                    kind = ("command" if command in COMMANDS
                            or re.fullmatch(r"[A-Za-z]{2,24}", command)
                            else "inline")
                    messages.append(RedisMessage(
                        kind=kind, name=args[0], args=args,
                        value=text, offset=parsed.start, frame=frame,
                        raw=raw))
        elif parsed.kind == "error":
            messages.append(RedisMessage(
                kind="error", name=str(parsed.value), value=parsed.value,
                offset=parsed.start, frame=frame, raw=raw))
        elif parsed.kind in ("simple", "bulk", "verbatim", "integer",
                             "double", "boolean", "null", "map"):
            messages.append(RedisMessage(
                kind="reply", name=parsed.kind, value=parsed.value,
                offset=parsed.start, frame=frame, raw=raw))
        if parsed.end <= index:  # safety: never spin on a malformed value
            break
        index = parsed.end
    return messages


def commands(messages: list[RedisMessage]) -> list[RedisMessage]:
    return [item for item in messages if item.kind == "command"]


def command_counts(messages: list[RedisMessage]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in commands(messages):
        name = item.command
        counts[name] = counts.get(name, 0) + 1
    return counts


def auth_events(messages: list[RedisMessage]) -> list[dict]:
    """Extract AUTH/HELLO 3 credentials plus ``requirepass`` changes."""
    events: list[dict] = []
    for item in commands(messages):
        command = item.command
        args = item.args
        if command == "AUTH" and len(args) >= 2:
            if len(args) >= 3:
                events.append({"kind": "auth", "frame": item.frame,
                               "account": args[1], "secret": args[2],
                               "detail": "AUTH user password"})
            else:
                events.append({"kind": "auth", "frame": item.frame,
                               "account": "", "secret": args[1],
                               "detail": "AUTH password"})
        elif command == "HELLO":
            # HELLO 3 AUTH <user> <pass>
            if "AUTH" in (value.upper() for value in args):
                index = next(i for i, value in enumerate(args)
                             if value.upper() == "AUTH")
                if len(args) > index + 1:
                    if len(args) > index + 2:
                        events.append({"kind": "auth", "frame": item.frame,
                                       "account": args[index + 1],
                                       "secret": args[index + 2],
                                       "detail": "HELLO AUTH"})
                    else:
                        events.append({"kind": "auth", "frame": item.frame,
                                       "account": "",
                                       "secret": args[index + 1],
                                       "detail": "HELLO AUTH"})
        elif command == "CONFIG" and len(args) >= 4 and args[1].lower() == "set":
            if "requirepass" in args[2].lower():
                events.append({"kind": "requirepass", "frame": item.frame,
                               "account": "", "secret": args[3],
                               "detail": "CONFIG SET requirepass"})
    return events


def acl_changes(messages: list[RedisMessage]) -> list[dict]:
    """Extract ``ACL SETUSER``/``DELUSER``/``SETUSER`` rule changes."""
    changes: list[dict] = []
    for item in commands(messages):
        if item.command != "ACL" or len(item.args) < 2:
            continue
        action = item.args[1].upper()
        if action in ("SETUSER", "DELUSER", "GETUSER", "LIST", "WHOAMI",
                      "USERS", "CAT", "GENPASS", "LOG"):
            target = item.args[2] if len(item.args) > 2 else ""
            rules = item.args[3:] if action == "SETUSER" else []
            changes.append({"frame": item.frame, "action": action,
                            "user": target, "rules": rules,
                            "command": " ".join(item.args[:12])})
    return changes


def cluster_redirects(messages: list[RedisMessage]) -> list[dict]:
    """Parse ``-MOVED slot host:port`` and ``-ASK slot host:port`` replies."""
    redirects: list[dict] = []
    for item in messages:
        if item.kind != "error":
            continue
        match = REDIRECT_RE.match(str(item.value or "").strip())
        if not match:
            continue
        host, _, port = match.group(3).rpartition(":")
        redirects.append({"frame": item.frame, "kind": match.group(1).upper(),
                          "slot": int(match.group(2)), "host": host,
                          "port": port})
    return redirects


def pubsub_events(messages: list[RedisMessage]) -> list[dict]:
    """Extract subscribe/unsubscribe/publish and RESP3 push messages."""
    events: list[dict] = []
    for item in messages:
        args = item.args
        if item.kind == "push" and args:
            head = args[0].lower()
            if head in ("message", "pmessage", "smessage"):
                events.append({"frame": item.frame, "kind": head,
                               "channel": args[1] if len(args) > 1 else "",
                               "payload": args[2] if len(args) > 2 else ""})
            elif head in ("subscribe", "unsubscribe", "psubscribe",
                          "punsubscribe"):
                events.append({"frame": item.frame, "kind": head,
                               "channel": args[1] if len(args) > 1 else "",
                               "payload": args[2] if len(args) > 2 else ""})
            continue
        if item.kind == "command" and item.command in PUBSUB_COMMANDS:
            events.append({"frame": item.frame, "kind": item.command.lower(),
                           "channel": args[1] if len(args) > 1 else "",
                           "payload": args[2] if len(args) > 2 else ""})
    return events


def _decode_script(script: str) -> tuple[str, str]:
    """Unwrap Base64/Hex encoded Lua scripts; return ``(text, encoding)``."""
    stripped = (script or "").strip()
    if not stripped:
        return "", ""
    if re.fullmatch(r"[0-9a-fA-F]+", stripped) and len(stripped) % 2 == 0 \
            and len(stripped) >= 16:
        try:
            decoded = bytes.fromhex(stripped).decode("utf-8")
            if decoded.isprintable() or "\n" in decoded:
                return decoded, "hex"
        except (ValueError, UnicodeDecodeError):
            pass
    if re.fullmatch(r"[A-Za-z0-9+/=\s]+", stripped) and len(stripped) >= 16:
        try:
            decoded = base64.b64decode(
                re.sub(r"\s+", "", stripped) + "===").decode("utf-8")
            if decoded.isprintable() or "\n" in decoded:
                return decoded, "base64"
        except (binascii.Error, UnicodeDecodeError):
            pass
    return stripped, "plain"


def eval_scripts(messages: list[RedisMessage]) -> list[dict]:
    """Return ``EVAL``/``EVALSHA`` details with keys/args and script text."""
    scripts: list[dict] = []
    for item in commands(messages):
        if item.command not in ("EVAL", "EVALSHA"):
            continue
        args = item.args
        script = args[1] if len(args) > 1 else ""
        try:
            numkeys = int(args[2]) if len(args) > 2 else 0
        except ValueError:
            numkeys = 0
        numkeys = max(0, numkeys)
        keys = args[3:3 + numkeys]
        argv = args[3 + numkeys:]
        text, encoding = (_decode_script(script)
                          if item.command == "EVAL" else (script, "sha1"))
        scripts.append({"frame": item.frame, "command": item.command,
                        "script": text, "encoding": encoding,
                        "numkeys": numkeys, "keys": keys, "args": argv,
                        "raw": script})
    return scripts


def sensitive_reads(messages: list[RedisMessage]) -> list[dict]:
    """Flag GET/HGET/MGET/SCAN keys that look credential/flag related."""
    reads: list[dict] = []
    for item in commands(messages):
        if item.command not in ("GET", "HGET", "MGET", "HMGET", "SCAN",
                                "KEYS", "LRANGE"):
            continue
        for key in item.args[1:]:
            if SENSITIVE_RE.search(key or ""):
                reads.append({"frame": item.frame, "command": item.command,
                              "key": key})
                break
    return reads


def value_flags(messages: list[RedisMessage]) -> list[tuple[str, str]]:
    """Return ``(frame, text)`` for SET/HSET/LPUSH/publish values worth scanning."""
    found: list[tuple[str, str]] = []
    for item in commands(messages):
        if item.command not in ("SET", "SETEX", "PSETEX", "MSET", "HSET",
                                "HMSET", "LPUSH", "RPUSH", "PUBLISH"):
            continue
        if len(item.args) < 3:
            continue
        text = " ".join(item.args[2:]) if item.command == "MSET" \
            else item.args[-1]
        found.append((item.frame, text))
    return found
