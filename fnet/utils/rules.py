"""Custom detection rules for Fnet (regular expressions + a YARA subset).

Only the standard library is used.  Two file formats are accepted:

``*.json``
    ``{"rules": [{"name": "...", "pattern": "...", "level": "warn",
    "tags": ["credential"]}]}`` or a bare list of those objects.

Text files
    YARA-like syntax::

        rule credential_leak : credential
        {
            meta:
                description = "password in clear text"
                severity = "warn"
            strings:
                $a = "password=" nocase
                $b = /passwd\\s*[:=]/ nocase
            condition:
                any of them
        }

    or one regular expression per line (``#`` starts a comment).  A line may
    be written as ``name = regex`` / ``name: regex`` to name the rule.

    注意 ``name = regex`` 的拆分规则：在第一个 ``=`` / ``:`` 处切开，左侧是
    规则名、右侧是正则表达式。想匹配字面量 ``password=`` 时必须转义等号，
    写成 ``password\\=``（或 ``password[=]``）；直接写 ``password=\\w+`` 得到的
    是名为 ``password``、正则为 ``\\w+`` 的规则（几乎匹配一切），这是本语法
    最常见的误用。

Supported conditions: ``any of them``, ``all of them``, ``N of them`` and
simple ``$a and $b`` / ``$a or $b`` expressions.  This deliberately implements
the subset that is useful for traffic triage; full YARA modules are not
supported.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

MAX_RULES = 2000
MAX_MATCHES = 2000
MAX_RULE_FILE = 8 * 1024 * 1024
MAX_SNIPPET = 240

#: tshark fields used to recover payload text from a capture.
SCAN_FIELDS = [
    "frame.number", "frame.time_relative", "_ws.col.protocol",
    "data.data", "tcp.payload", "udp.payload",
    "dns.qry.name", "http.request.full_uri", "http.host",
]


@dataclass
class Rule:
    name: str
    patterns: list = field(default_factory=list)
    mode: str = "any"          # any|all|count|expr
    count: int = 1
    expression: str = ""
    description: str = ""
    tags: list = field(default_factory=list)
    level: str = "warn"

    def matches(self, text: str) -> tuple[bool, int]:
        """Return ``(matched, hit_count)`` for one text blob."""
        flags = [bool(pattern.search(text)) for pattern in self.patterns]
        hits = sum(1 for value in flags if value)
        if not self.patterns:
            return False, 0
        if self.mode == "all":
            return hits == len(self.patterns), hits
        if self.mode == "count":
            return hits >= max(1, self.count), hits
        if self.mode == "expr":
            return _eval_expression(self.expression, self.patterns, text), hits
        return hits > 0, hits


def _eval_expression(expression: str, patterns: list, text: str) -> bool:
    """Evaluate a small boolean expression over ``$a``/``$b`` identifiers."""
    names: dict[str, bool] = {}
    for index, pattern in enumerate(patterns, 1):
        names[f"$s{index}"] = bool(pattern.search(text))
        names[f"${chr(ord('a') + index - 1)}"] = names[f"$s{index}"]
    tokens = re.findall(r"\$[A-Za-z0-9_]+|and|or|not|\(|\)", expression.lower())
    if not tokens:
        return any(names.values())
    python = []
    for token in tokens:
        if token == "and":
            python.append("and")
        elif token == "or":
            python.append("or")
        elif token == "not":
            python.append("not")
        elif token in ("(", ")"):
            python.append(token)
        elif token in names:
            python.append("True" if names[token] else "False")
        else:
            python.append("False")
    try:
        return bool(eval(" ".join(python), {"__builtins__": {}}, {}))
    except Exception:  # noqa: BLE001 - malformed rule expressions never crash
        return any(names.values())


def _compile(pattern: str, flags: int = 0) -> re.Pattern | None:
    try:
        return re.compile(pattern, flags)
    except re.error:
        return None


def _string_to_pattern(value: str, modifiers: str = "") -> re.Pattern | None:
    flags = re.MULTILINE
    if "nocase" in modifiers.lower() or "i" in modifiers.split():
        flags |= re.IGNORECASE
    if "wide" in modifiers.lower():
        value = "\x00".join(value)
    if value.startswith("/") and value.endswith("/"):
        return _compile(value[1:-1], flags)
    return _compile(re.escape(value), flags)


def parse_yara(text: str) -> list[Rule]:
    """Parse the supported YARA-like subset."""
    rules: list[Rule] = []
    for match in re.finditer(
            r"(?ms)^\s*rule\s+([A-Za-z0-9_]+)\s*(?::\s*([\w\s,]+))?\{"
            r"(.*?)^\s*\}", text):
        if len(rules) >= MAX_RULES:
            break
        name = match.group(1)
        tags = [item for item in re.split(r"[\s,]+", (match.group(2) or ""))
                if item]
        body = match.group(3)
        rule = Rule(name=name, tags=tags)
        meta = re.search(r"(?ms)^\s*meta\s*:\s*(.*?)(?=^\s*(?:strings|condition)\s*:|\Z)",
                         body)
        if meta:
            for key, value in re.findall(
                    r"(\w+)\s*=\s*\"([^\"]*)\"", meta.group(1)):
                if key in ("description", "desc"):
                    rule.description = value
                elif key in ("severity", "level"):
                    rule.level = value.strip().lower()
        strings = re.search(
            r"(?ms)^\s*strings\s*:\s*(.*?)(?=^\s*condition\s*:|\Z)", body)
        if strings:
            for line in strings.group(1).splitlines():
                line = line.strip()
                if not line or not line.startswith("$"):
                    continue
                _, _, value = line.partition("=")
                value = value.strip()
                modifiers = ""
                if value.startswith("/"):
                    end = value.rfind("/")
                    if end > 0:
                        modifiers = value[end + 1:]
                        value = value[:end + 1]
                elif value.startswith('"'):
                    end = value.find('"', 1)
                    if end > 0:
                        modifiers = value[end + 1:]
                        value = value[:end + 1]
                value = value.strip()
                if value.startswith('"') and value.endswith('"'):
                    value = value[1:-1]
                pattern = _string_to_pattern(value, modifiers)
                if pattern is not None:
                    rule.patterns.append(pattern)
        condition = re.search(r"(?ms)^\s*condition\s*:\s*(.*)$", body)
        text_condition = (condition.group(1).strip() if condition else "")
        lowered = text_condition.lower()
        count_match = re.search(r"(\d+)\s+of\s+them", lowered)
        if count_match:
            rule.mode = "count"
            rule.count = int(count_match.group(1))
        elif "all of them" in lowered:
            rule.mode = "all"
        elif "any of them" in lowered:
            rule.mode = "any"
        elif text_condition and ("$" in text_condition):
            rule.mode = "expr"
            rule.expression = text_condition
        elif rule.patterns:
            rule.mode = "any"
        if rule.patterns:
            rules.append(rule)
    return rules


def parse_line_rules(text: str) -> list[Rule]:
    """One regular expression per line (``name = regex`` names a rule).

    A line is split at the first ``=`` / ``:``: everything before it becomes
    the rule name, everything after it is the regex.  To match a literal
    ``=`` escape it — write ``password\\=``; ``password=\\w+`` is parsed as
    rule ``password`` with regex ``\\w+``.
    """
    rules: list[Rule] = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if len(rules) >= MAX_RULES:
            break
        name = f"line_{number}"
        body = line
        match = re.match(r"([A-Za-z0-9_.\-]+)\s*[=:]\s*(.+)$", line)
        if match and not line.startswith(("(", "[", "\\")):
            name, body = match.group(1), match.group(2).strip()
        pattern = _compile(body, re.MULTILINE)
        if pattern is not None:
            rules.append(Rule(name=name, patterns=[pattern], mode="any"))
    return rules


def parse_json(text: str) -> list[Rule]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        # Public entry point: malformed input yields no rules instead of an
        # exception (parse_rules callers rely on the fallback behaviour).
        return []
    if isinstance(data, dict):
        data = data.get("rules") or []
    if not isinstance(data, list):
        return []
    rules: list[Rule] = []
    for item in data[:MAX_RULES]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("id") or "").strip()
        patterns = item.get("patterns") or item.get("pattern") or item.get("regex")
        if isinstance(patterns, str):
            patterns = [patterns]
        if not name or not isinstance(patterns, list):
            continue
        compiled = []
        for value in patterns:
            pattern = _compile(str(value), re.MULTILINE)
            if pattern is not None:
                compiled.append(pattern)
        if not compiled:
            continue
        mode = str(item.get("mode") or "any").lower()
        if mode not in ("any", "all", "count"):
            mode = "any"
        rules.append(Rule(
            name=name, patterns=compiled, mode=mode,
            count=int(item.get("count") or 1),
            description=str(item.get("description") or ""),
            tags=[str(tag) for tag in item.get("tags") or []],
            level=str(item.get("level") or "warn").lower()))
    return rules


def parse_rules(text: str, suffix: str = "") -> list[Rule]:
    """Detect the rule syntax and parse it into :class:`Rule` objects."""
    text = str(text or "")
    if suffix.lower() == ".json" or text.lstrip().startswith(("{", "[")):
        try:
            return parse_json(text)
        except (ValueError, TypeError):
            return []
    if re.search(r"(?m)^\s*rule\s+[A-Za-z0-9_]+\s*(?::|\{)", text):
        return parse_yara(text)
    return parse_line_rules(text)


def load_rules(path: str | Path) -> list[Rule]:
    """Load and compile a rule file, raising ``ValueError`` on bad input."""
    target = Path(path).expanduser()
    if not target.is_file():
        raise ValueError(f"规则文件不存在: {target}")
    if target.stat().st_size > MAX_RULE_FILE:
        raise ValueError("规则文件过大（上限 8 MiB）")
    text = target.read_text(encoding="utf-8", errors="replace")
    rules = parse_rules(text, target.suffix)
    if not rules:
        raise ValueError("规则文件中没有可用的规则")
    return rules


def snippet(text: str, pattern: re.Pattern | None = None) -> str:
    """Short printable excerpt around the first hit."""
    if pattern is not None:
        match = pattern.search(text)
        if match:
            start = max(0, match.start() - 40)
            return text[start:start + MAX_SNIPPET].replace("\n", " ")
    return text[:MAX_SNIPPET].replace("\n", " ")


def match_text(rules: list[Rule], text: str, frame="", time="",
               protocol="") -> list[dict]:
    """Match every rule against one payload and return finding dictionaries."""
    if not text:
        return []
    hits: list[dict] = []
    for rule in rules:
        matched, count = rule.matches(text)
        if not matched:
            continue
        excerpt = snippet(text, rule.patterns[0] if rule.patterns else None)
        label = rule.name
        if rule.description:
            label = f"{rule.name}（{rule.description}）"
        hits.append({
            "rule": rule.name,
            "tags": list(rule.tags),
            "level": rule.level if rule.level in
                     ("debug", "info", "good", "warn", "error") else "warn",
            "frame": str(frame or ""),
            "time": str(time or ""),
            "protocol": str(protocol or ""),
            "hits": count,
            "summary": f"自定义规则命中：{label}",
            "detail": (f"{protocol or '数据'} 帧 {frame or '-'} 命中 "
                       f"{count}/{len(rule.patterns)} 个表达式；片段：{excerpt}"),
        })
        if len(hits) >= MAX_MATCHES:
            break
    return hits


def _decode_payload(value: str) -> str:
    """Decode one tshark hex payload field, tolerating separators."""
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(value or ""))
    if len(raw) < 2 or len(raw) % 2:
        return ""
    try:
        data = bytes.fromhex(raw)
    except ValueError:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1", "replace")


def scan_pcap(rules: list[Rule], pcap: str, tshark,
              cancel=None, limit: int = MAX_MATCHES) -> list[dict]:
    """Scan packet payloads in a capture and return rule hits.

    ``cancel`` is an optional :class:`threading.Event`; when it is set the
    scan stops and returns what was found so far.
    """
    if tshark is None or not rules:
        return []
    rows = tshark.fields(pcap, SCAN_FIELDS, cancel=cancel)
    found: list[dict] = []
    for row in rows:
        if cancel is not None and cancel.is_set():
            break
        values = list(row) + [""] * (len(SCAN_FIELDS) - len(row))
        frame, time, protocol = values[0], values[1], values[2]
        chunks = []
        # 3..5 are hex payload fields, 6..8 are already decoded text.
        for index, field_value in enumerate(values[3:], 3):
            if not field_value:
                continue
            text = (_decode_payload(field_value) if index <= 5
                    else str(field_value))
            if text:
                chunks.append(text)
        if not chunks:
            continue
        payload = "\n".join(chunks)
        found.extend(match_text(rules, payload, frame=frame, time=time,
                                protocol=protocol))
        if len(found) >= limit:
            break
    return found[:limit]
