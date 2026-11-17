"""Unit tests for the LDAP BER decoder (no tshark)."""
from __future__ import annotations

import unittest

from fnet.utils import ldap


def tlv(tag: int, value: bytes) -> bytes:
    length = len(value)
    if length < 0x80:
        header = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + header + value


def integer(value: int) -> bytes:
    return tlv(0x02, value.to_bytes(max(1, (value.bit_length() + 7) // 8),
                                    "big", signed=True))


def octets(value: str) -> bytes:
    return tlv(0x04, value.encode())


def ldap_message(message_id: int, op: bytes) -> bytes:
    return tlv(0x30, integer(message_id) + op)


def bind_request(dn: str, password: str) -> bytes:
    body = integer(3) + octets(dn) + tlv(0x80, password.encode())
    return ldap_message(1, tlv(0x60, body))


def bind_response(code: int = 0, diagnostic: str = "") -> bytes:
    body = tlv(0x0A, bytes([code])) + octets("") + octets(diagnostic)
    return ldap_message(1, tlv(0x61, body))


def search_request(base: str, filter_bytes: bytes,
                   attributes=("sAMAccountName",)) -> bytes:
    body = (octets(base) + tlv(0x0A, b"\x02") + tlv(0x0A, b"\x00")
            + integer(100) + integer(30) + tlv(0x01, b"\x00")
            + filter_bytes
            + tlv(0x30, b"".join(octets(attr) for attr in attributes)))
    return ldap_message(2, tlv(0x63, body))


def search_entry(dn: str, attributes: dict[str, list[str]]) -> bytes:
    parts = bytearray()
    for name, values in attributes.items():
        parts += tlv(0x30, octets(name)
                     + tlv(0x31, b"".join(octets(value) for value in values)))
    return ldap_message(2, tlv(0x64, octets(dn) + tlv(0x30, bytes(parts))))


class LdapParseTest(unittest.TestCase):
    def test_simple_bind(self):
        messages = ldap.parse_messages(bind_request("cn=admin,dc=corp",
                                                    "s3cr3t"))
        self.assertEqual(len(messages), 1)
        message = messages[0]
        self.assertEqual(message.message_id, 1)
        self.assertEqual(message.op, "BindRequest")
        self.assertEqual(message.version, 3)
        self.assertEqual(message.bind_dn, "cn=admin,dc=corp")
        self.assertEqual(message.password, "s3cr3t")

    def test_sasl_bind(self):
        sasl = tlv(0xA3, octets("GSSAPI") + octets("token"))
        body = integer(3) + octets("") + sasl
        message = ldap.parse_messages(ldap_message(4, tlv(0x60, body)))[0]
        self.assertEqual(message.sasl_mechanism, "GSSAPI")
        self.assertEqual(message.sasl_credentials, b"token")

    def test_bind_result(self):
        message = ldap.parse_messages(
            bind_response(49, "80090308: LdapErr: DSID-0C0903A9"))[0]
        self.assertEqual(message.result_code, 49)
        self.assertEqual(message.result_name, "invalidCredentials")
        self.assertIn("DSID", message.diagnostic)

    def test_search_filter_rendering(self):
        equality = tlv(0xA3, octets("sAMAccountName") + octets("admin"))
        and_filter = tlv(0xA0, equality
                         + tlv(0x87, b"objectClass"))
        message = ldap.parse_messages(search_request(
            "dc=corp,dc=local", and_filter,
            ["sAMAccountName", "memberOf"]))[0]
        self.assertEqual(message.op, "SearchRequest")
        self.assertEqual(message.base, "dc=corp,dc=local")
        self.assertEqual(message.scope, "sub")
        self.assertEqual(message.filter_text,
                         "(&(sAMAccountName=admin)(objectClass=*))")
        self.assertEqual(message.attributes, ["sAMAccountName", "memberOf"])

    def test_substring_filter(self):
        substrings = tlv(0xA4, octets("cn")
                         + tlv(0x30, tlv(0x80, b"adm")
                               + tlv(0x81, b"in") + tlv(0x82, b"ist")))
        message = ldap.parse_messages(search_request("dc=corp", substrings))[0]
        self.assertEqual(message.filter_text, "(cn=adm*in*ist)")

    def test_search_entry_attributes_and_secrets(self):
        message = ldap.parse_messages(search_entry(
            "CN=Alice,OU=Users,DC=corp",
            {"sAMAccountName": ["alice"],
             "memberOf": ["CN=Domain Admins,DC=corp"],
             "ms-Mcs-AdmPwd": ["P@ssw0rd!"]}))[0]
        self.assertEqual(message.op, "SearchResultEntry")
        self.assertEqual(message.entry["sAMAccountName"], ["alice"])
        self.assertEqual(message.sensitive_values(),
                         [("ms-Mcs-AdmPwd", "P@ssw0rd!")])
        self.assertIn("sAMAccountName: alice", ldap.entry_lines(message))

    def test_starttls_request(self):
        body = tlv(0x80, ldap.STARTTLS_OID.encode())
        message = ldap.parse_messages(ldap_message(5, tlv(0x77, body)))[0]
        self.assertEqual(message.op, "ExtendedRequest")
        self.assertTrue(message.is_starttls)

    def test_skips_garbage_and_truncated_messages(self):
        data = b"\x16\x03\x01garbage" + bind_request("cn=a", "b")
        messages = ldap.parse_messages(data)
        self.assertEqual([item.op for item in messages], ["BindRequest"])
        self.assertTrue(ldap.looks_like_ldap(bind_request("cn=a", "b")))
        self.assertFalse(ldap.looks_like_ldap(b"\x16\x03\x01\x00\x05hello"))

    def test_truncated_result_is_skipped(self):
        good = bind_request("cn=a", "b")
        data = good + good[:6]
        messages = ldap.parse_messages(data)
        self.assertEqual(len(messages), 1)


if __name__ == "__main__":
    unittest.main()