"""Minimal LDAP BER decoder for capture analysis.

Wireshark has a full LDAP dissector, but it only runs on the standard ports and
it flattens the result entries into a handful of repeated fields.  For CTF and
incident work we want the *structure*: who bound with which password, which
SASL mechanism was used, the exact search base/filter, and every attribute of
every returned entry (AD accounts, LAPS passwords, service principals...).

This module walks the BER (definite length) encoding itself.  It is read-only,
never executes anything and tolerates truncation: a broken/partial message is
skipped rather than aborting the whole stream.

References: RFC 4511 (LDAP), RFC 4515 (filters), RFC 2830 (StartTLS).
"""
from __future__ import annotations

from dataclasses import dataclass, field

STARTTLS_OID = "1.3.6.1.4.1.1466.20037"
MAX_MESSAGE = 16 * 1024 * 1024

#: LDAP protocol operation tags.
OP_NAMES = {
    0x42: "UnbindRequest",
    0x50: "AbandonRequest",
    0x60: "BindRequest",
    0x61: "BindResponse",
    0x63: "SearchRequest",
    0x64: "SearchResultEntry",
    0x65: "SearchResultDone",
    0x66: "ModifyRequest",
    0x67: "ModifyResponse",
    0x68: "AddRequest",
    0x69: "AddResponse",
    0x4A: "DeleteRequest",
    0x6B: "DeleteResponse",
    0x6C: "ModifyDNRequest",
    0x6D: "ModifyDNResponse",
    0x6E: "CompareRequest",
    0x6F: "CompareResponse",
    0x77: "ExtendedRequest",
    0x78: "ExtendedResponse",
    0x79: "IntermediateResponse",
}

SCOPE = {0: "base", 1: "one", 2: "sub"}

#: Result codes worth translating (RFC 4511 appendix A).
RESULT_CODES = {
    0: "success", 1: "operationsError", 2: "protocolError",
    3: "timeLimitExceeded", 4: "sizeLimitExceeded", 5: "compareFalse",
    6: "compareTrue", 7: "authMethodNotSupported", 8: "strongerAuthRequired",
    16: "noSuchAttribute", 17: "undefinedAttributeType",
    18: "inappropriateMatching", 19: "constraintViolation",
    20: "attributeOrValueExists", 21: "invalidAttributeSyntax",
    32: "noSuchObject", 33: "aliasProblem", 34: "invalidDNSyntax",
    48: "inappropriateAuthentication", 49: "invalidCredentials",
    50: "insufficientAccessRights", 51: "busy", 52: "unavailable",
    53: "unwillingToPerform", 54: "loopDetect", 64: "namingViolation",
    65: "objectClassViolation", 66: "notAllowedOnNonLeaf",
    67: "notAllowedOnRDN", 68: "entryAlreadyExists",
    69: "objectClassModsProhibited", 71: "affectsMultipleDSAs",
    80: "other", 122: "cancelled", 123: "noSuchOperation",
}

#: AD attributes that are useful in a forensic report.
AD_ATTRIBUTES = (
    "sAMAccountName", "userPrincipalName", "displayName", "description",
    "memberOf", "mail", "servicePrincipalName", "userAccountControl",
    "objectSid", "objectClass", "givenName", "sn", "telephoneNumber",
    "adminCount", "pwdLastSet", "lastLogonTimestamp", "ms-Mcs-AdmPwd",
    "unixUserPassword", "userPassword", "homeDirectory",
)

SENSITIVE_ATTRIBUTES = {
    "userpassword", "unicodepassword", "ms-mcs-admpwd", "ms-mcs-admpwdexpirationtime",
    "unixuserpassword", "userparameters", "supplementalcredentials",
}


class BerError(ValueError):
    """Raised when a TLV is truncated or uses an unsupported encoding."""


def read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    """Read one BER TLV, returning ``(tag, value, next_offset)``."""
    if offset >= len(data):
        raise BerError("truncated tag")
    tag = data[offset]
    offset += 1
    if tag & 0x1F == 0x1F:  # high-tag-number form is not used by LDAP
        raise BerError("unsupported high tag number")
    if offset >= len(data):
        raise BerError("truncated length")
    first = data[offset]
    offset += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise BerError("indefinite length is not valid in LDAP")
    else:
        count = first & 0x7F
        if count > 4 or offset + count > len(data):
            raise BerError("invalid length")
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    if length > MAX_MESSAGE or offset + length > len(data):
        raise BerError("truncated value")
    return tag, data[offset:offset + length], offset + length


def read_int(data: bytes, tag: int = 0x02) -> int:
    actual, value, _end = read_tlv(data)
    if actual != tag:
        raise BerError(f"expected tag {tag:#x}, got {actual:#x}")
    return int.from_bytes(value, "big", signed=True)


def read_str(data: bytes, tag: int = 0x04) -> str:
    actual, value, _end = read_tlv(data)
    if actual != tag:
        raise BerError(f"expected tag {tag:#x}, got {actual:#x}")
    return value.decode("utf-8", "replace")


def read_sequence(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    tag, value, end = read_tlv(data, offset)
    if tag != 0x30:
        raise BerError("expected SEQUENCE")
    return value, end


def _children(data: bytes) -> list[tuple[int, bytes]]:
    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        tag, value, offset = read_tlv(data, offset)
        items.append((tag, value))
    return items


@dataclass
class LdapMessage:
    message_id: int = 0
    op: str = ""
    offset: int = 0
    frame: str = ""

    # BindRequest / BindResponse
    version: int = 0
    bind_dn: str = ""
    password: str = ""
    sasl_mechanism: str = ""
    sasl_credentials: bytes = b""

    # LDAPResult
    result_code: int = -1
    diagnostic: str = ""
    matched_dn: str = ""
    referral: list[str] = field(default_factory=list)

    # SearchRequest
    base: str = ""
    scope: str = ""
    filter_text: str = ""
    attributes: list[str] = field(default_factory=list)

    # SearchResultEntry
    object_name: str = ""
    entry: dict[str, list[str]] = field(default_factory=dict)

    # ExtendedRequest / Response (StartTLS etc.)
    request_name: str = ""
    request_value: bytes = b""
    response_name: str = ""
    response_value: bytes = b""

    @property
    def result_name(self) -> str:
        if self.result_code < 0:
            return ""
        return RESULT_CODES.get(self.result_code, str(self.result_code))

    @property
    def is_starttls(self) -> bool:
        return self.request_name == STARTTLS_OID

    def sensitive_values(self) -> list[tuple[str, str]]:
        out = []
        for name, values in self.entry.items():
            if name.lower() in SENSITIVE_ATTRIBUTES:
                out.extend((name, value) for value in values)
        return out


def _parse_result(data: bytes, message: LdapMessage) -> None:
    offset = 0
    tag, value, offset = read_tlv(data, offset)
    if tag == 0x0A:
        message.result_code = int.from_bytes(value, "big", signed=True)
    tag, value, offset = read_tlv(data, offset)  # matchedDN
    if tag == 0x04:
        message.matched_dn = value.decode("utf-8", "replace")
    tag, value, offset = read_tlv(data, offset)  # diagnosticMessage
    if tag == 0x04:
        message.diagnostic = value.decode("utf-8", "replace")
    while offset < len(data):
        tag, value, offset = read_tlv(data, offset)
        if tag == 0xA3:  # referral [3] SEQUENCE OF LDAPURL
            for ref_tag, ref_value in _children(value):
                if ref_tag == 0x04:
                    message.referral.append(
                        ref_value.decode("utf-8", "replace"))


def _render_filter(data: bytes, depth: int = 0) -> str:
    """Render an LDAP search filter (RFC 4511 4.5.1.7) as text."""
    try:
        tag, value, _end = read_tlv(data)
    except BerError:
        return ""
    return _render_tlv(tag, value, depth)


def _render_tlv(tag: int, value: bytes, depth: int = 0) -> str:
    if depth > 16:
        return "…"
    if tag == 0xA0:  # and
        return "(&" + "".join(_render_tlv(item_tag, item_value, depth + 1)
                             for item_tag, item_value in _children(value)) + ")"
    if tag == 0xA1:  # or
        return "(|" + "".join(_render_tlv(item_tag, item_value, depth + 1)
                             for item_tag, item_value in _children(value)) + ")"
    if tag == 0xA2:  # not
        items = _children(value)
        return "(!" + (_render_tlv(items[0][0], items[0][1], depth + 1)
                       if items else "") + ")"
    if tag in (0xA3, 0xA5, 0xA6, 0xA8):  # equality/ge/le/approx
        items = _children(value)
        if len(items) >= 2:
            attr = items[0][1].decode("utf-8", "replace")
            assertion = items[1][1].decode("utf-8", "replace")
            operator = {0xA3: "=", 0xA5: ">=", 0xA6: "<=", 0xA8: "~="}[tag]
            return f"({attr}{operator}{assertion})"
        return ""
    if tag == 0xA4:  # substrings
        items = _children(value)
        if not items:
            return ""
        attr = items[0][1].decode("utf-8", "replace")
        pieces: list[str] = []
        first_tag = last_tag = 0
        for sub_tag, sub_value in (_children(items[1][1])
                                   if len(items) > 1 else []):
            kind = sub_tag & 0x1F
            if kind not in (0, 1, 2):
                continue
            first_tag = first_tag if pieces else kind
            last_tag = kind
            pieces.append(sub_value.decode("utf-8", "replace"))
        if not pieces:
            return f"({attr}=*)"
        part = "*".join(pieces)
        if first_tag != 0:
            part = "*" + part
        if last_tag != 2:
            part = part + "*"
        return f"({attr}={part})"
    if tag == 0x87:  # present
        return f"({value.decode('utf-8', 'replace')}=*)"
    if tag == 0xA9:  # extensibleMatch
        attr = ""
        matching_rule = ""
        match_value = ""
        for item_tag, item_value in _children(value):
            if item_tag == 0x81:
                matching_rule = item_value.decode("utf-8", "replace")
            elif item_tag == 0x82:
                attr = item_value.decode("utf-8", "replace")
            elif item_tag == 0x83:
                match_value = item_value.decode("utf-8", "replace")
        return f"({attr}{':' + matching_rule if matching_rule else ''}={match_value})"
    return ""


def _parse_bind(data: bytes, message: LdapMessage) -> None:
    offset = 0
    tag, value, offset = read_tlv(data, offset)
    if tag == 0x02:
        message.version = int.from_bytes(value, "big", signed=True)
    tag, value, offset = read_tlv(data, offset)
    if tag == 0x04:
        message.bind_dn = value.decode("utf-8", "replace")
    if offset >= len(data):
        return
    tag, value, _offset = read_tlv(data, offset)
    if tag == 0x80:  # simple
        message.password = value.decode("utf-8", "replace")
    elif tag == 0xA3:  # sasl SEQUENCE { mechanism, credentials }
        items = _children(value)
        if items and items[0][0] == 0x04:
            message.sasl_mechanism = items[0][1].decode("utf-8", "replace")
        if len(items) > 1:
            message.sasl_credentials = items[1][1]


def _parse_search(data: bytes, message: LdapMessage) -> None:
    offset = 0
    tag, value, offset = read_tlv(data, offset)
    if tag == 0x04:
        message.base = value.decode("utf-8", "replace")
    tag, value, offset = read_tlv(data, offset)
    if tag == 0x0A:
        message.scope = SCOPE.get(int.from_bytes(value, "big", signed=True), "")
    # derefAliases, sizeLimit, timeLimit, typesOnly
    for _ in range(4):
        if offset >= len(data):
            return
        _tag, _value, offset = read_tlv(data, offset)
    if offset >= len(data):
        return
    filter_tag, filter_value, offset = read_tlv(data, offset)
    message.filter_text = _render_filter(bytes([filter_tag]) +
                                         _encode_length(len(filter_value)) +
                                         filter_value)
    if offset < len(data):
        tag, value, _offset = read_tlv(data, offset)
        if tag == 0x30:
            for item_tag, item_value in _children(value):
                if item_tag == 0x04:
                    message.attributes.append(
                        item_value.decode("utf-8", "replace"))


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _parse_entry(data: bytes, message: LdapMessage) -> None:
    offset = 0
    tag, value, offset = read_tlv(data, offset)
    if tag == 0x04:
        message.object_name = value.decode("utf-8", "replace")
    if offset >= len(data):
        return
    tag, value, _offset = read_tlv(data, offset)
    if tag != 0x30:
        return
    for item_tag, item_value in _children(value):
        if item_tag != 0x30:
            continue
        parts = _children(item_value)
        if len(parts) < 2 or parts[0][0] != 0x04:
            continue
        name = parts[0][1].decode("utf-8", "replace")
        values: list[str] = []
        if parts[1][0] == 0x31:
            for value_tag, value_value in _children(parts[1][1]):
                if value_tag == 0x04:
                    values.append(value_value.decode("utf-8", "replace"))
        elif parts[1][0] == 0x04:
            values.append(parts[1][1].decode("utf-8", "replace"))
        message.entry.setdefault(name, []).extend(values)


def parse_message(data: bytes, offset: int = 0) -> tuple[LdapMessage, int]:
    """Parse one LDAPMessage at ``offset``; returns ``(message, end)``."""
    start = offset
    tag, value, end = read_tlv(data, offset)
    if tag != 0x30:
        raise BerError("LDAPMessage is not a SEQUENCE")
    message = LdapMessage(offset=start)
    inner = 0
    id_tag, id_value, inner = read_tlv(value, inner)
    if id_tag != 0x02:
        raise BerError("LDAPMessage without messageID")
    message.message_id = int.from_bytes(id_value, "big", signed=True)
    op_tag, op_value, inner = read_tlv(value, inner)
    message.op = OP_NAMES.get(op_tag, f"OP_{op_tag:#x}")
    try:
        if op_tag == 0x60:
            _parse_bind(op_value, message)
        elif op_tag == 0x61:
            _parse_result(op_value, message)
        elif op_tag == 0x63:
            _parse_search(op_value, message)
        elif op_tag == 0x64:
            _parse_entry(op_value, message)
        elif op_tag in (0x65, 0x67, 0x69, 0x6B, 0x6D, 0x6F):
            _parse_result(op_value, message)
        elif op_tag == 0x77:
            parts = _children(op_value)
            if parts and parts[0][0] == 0x80:
                message.request_name = parts[0][1].decode("utf-8", "replace")
            if len(parts) > 1 and parts[1][0] == 0x81:
                message.request_value = parts[1][1]
        elif op_tag == 0x78:
            _parse_result(op_value, message)
            parts = _children(op_value)
            for part_tag, part_value in parts:
                if part_tag == 0x8A:
                    message.response_name = part_value.decode("utf-8", "replace")
                elif part_tag == 0x8B:
                    message.response_value = part_value
    except (BerError, ValueError):
        # Keep the partially decoded message: messageID/op are still useful.
        pass
    return message, end


def parse_messages(data: bytes, *, max_messages: int = 20_000
                   ) -> list[LdapMessage]:
    """Parse every LDAPMessage in ``data``, skipping unparseable bytes."""
    messages: list[LdapMessage] = []
    offset = 0
    while offset < len(data) and len(messages) < max_messages:
        try:
            message, end = parse_message(data, offset)
        except BerError:
            offset += 1
            continue
        if end <= offset:
            break
        messages.append(message)
        offset = end
    return messages


def looks_like_ldap(data: bytes) -> bool:
    """True when the buffer starts with a plausible LDAPMessage."""
    if len(data) < 8 or data[0] != 0x30:
        return False
    try:
        _message, end = parse_message(data)
    except BerError:
        return False
    return end > 0


def entry_lines(message: LdapMessage, limit: int = 40) -> list[str]:
    """Readable ``name: value`` lines for one search result entry."""
    lines: list[str] = []
    for name, values in message.entry.items():
        for value in values[:limit]:
            lines.append(f"{name}: {value}")
    return lines


def is_sensitive(name: str) -> bool:
    return name.lower() in SENSITIVE_ATTRIBUTES