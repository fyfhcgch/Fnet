"""Tests for the pure-Python MySQL protocol parser (no tshark, no network)."""
from __future__ import annotations

import hashlib
import struct
import unittest

from fnet.utils import mysql
from fnet.utils.stream import StreamData

SALT = b"12345678abcdefghijkl"

CAPABILITIES = (
    mysql.CLIENT_LONG_PASSWORD
    | mysql.CLIENT_PROTOCOL_41
    | mysql.CLIENT_SECURE_CONNECTION
    | mysql.CLIENT_PLUGIN_AUTH
    | mysql.CLIENT_CONNECT_WITH_DB
    | mysql.CLIENT_LOCAL_FILES
    | mysql.CLIENT_TRANSACTIONS
)


def frame(payload: bytes, sequence: int = 0) -> bytes:
    """Wrap one payload in the MySQL 3-byte length + sequence header."""
    return (len(payload).to_bytes(3, "little")
            + bytes([sequence & 0xFF]) + payload)


def lenenc_str(value: bytes) -> bytes:
    """Encode a short length-encoded string."""
    if len(value) >= 0xFB:
        raise ValueError("test helper only handles short strings")
    return bytes([len(value)]) + value


def handshake_payload(server_version: str = "8.0.36",
                      connection_id: int = 42,
                      plugin: str = "mysql_native_password",
                      salt: bytes = SALT,
                      capabilities: int = CAPABILITIES) -> bytes:
    """Build a Protocol::HandshakeV10 payload."""
    payload = b"\x0a" + server_version.encode() + b"\x00"
    payload += struct.pack("<I", connection_id)
    payload += salt[:8] + b"\x00"          # first salt part + filler
    payload += struct.pack("<H", capabilities & 0xFFFF)
    payload += bytes([33])                 # utf8_general_ci
    payload += struct.pack("<H", 2)        # SERVER_STATUS_AUTOCOMMIT
    payload += struct.pack("<H", capabilities >> 16)
    payload += bytes([21])                 # auth plugin data len: 20 + NUL
    payload += b"\x00" * 10                # reserved
    payload += salt[8:20] + b"\x00"        # second salt part (12 bytes)
    payload += plugin.encode() + b"\x00"
    return payload


def handshake_response_payload(username: str = "alice",
                               database: str = "app",
                               plugin: str = "caching_sha2_password",
                               auth_response: bytes = b"",
                               capabilities: int = CAPABILITIES) -> bytes:
    """Build a Protocol::HandshakeResponse41 payload."""
    payload = struct.pack("<I", capabilities)
    payload += struct.pack("<I", 16 * 1024 * 1024)
    payload += bytes([33]) + b"\x00" * 23
    payload += username.encode() + b"\x00"
    payload += bytes([len(auth_response)]) + auth_response
    payload += database.encode() + b"\x00"
    payload += plugin.encode() + b"\x00"
    return payload


def ok_payload(affected: int = 0, last_id: int = 0, status: int = 2,
               warnings: int = 0, info: bytes = b"") -> bytes:
    """Build an OK packet."""
    return (b"\x00" + bytes([affected]) + bytes([last_id])
            + struct.pack("<HH", status, warnings) + info)


def eof_payload(warnings: int = 0, status: int = 2) -> bytes:
    """Build a legacy EOF packet."""
    return b"\xfe" + struct.pack("<HH", warnings, status)


def err_payload(code: int = 1045, sqlstate: str = "28000",
                message: bytes = b"Access denied") -> bytes:
    """Build an ERR packet."""
    return (b"\xff" + struct.pack("<H", code) + b"#"
            + sqlstate.encode() + message)


def column_payload(name: str, column_type: int = 253,
                   flags: int = 0) -> bytes:
    """Build a ColumnDefinition41 packet."""
    payload = (lenenc_str(b"def") + lenenc_str(b"app")
               + lenenc_str(b"users") + lenenc_str(b"users")
               + lenenc_str(name.encode()) + lenenc_str(name.encode()))
    payload += b"\x0c" + struct.pack("<H", 33) + struct.pack("<I", 255)
    payload += bytes([column_type]) + struct.pack("<H", flags)
    payload += b"\x00" + b"\x00\x00"
    return payload


def text_row(*values) -> bytes:
    """Build a text-protocol row (``None`` becomes the 0xFB NULL marker)."""
    payload = b""
    for value in values:
        if value is None:
            payload += b"\xfb"
        else:
            payload += lenenc_str(str(value).encode())
    return payload


class PacketFramingTest(unittest.TestCase):
    def test_packet_roundtrip_and_offsets(self):
        wire = (frame(b"SELECT 1", 0) + frame(b"", 1)
                + frame(b"tail", 2))
        packets = list(mysql.iter_packets(wire))
        self.assertEqual([payload for _seq, payload, _offset in packets],
                         [b"SELECT 1", b"", b"tail"])
        self.assertEqual([sequence for sequence, _p, _o in packets], [0, 1, 2])
        self.assertEqual(packets[2][2], 16)

    def test_truncated_packet_is_ignored(self):
        wire = frame(b"abc", 0) + frame(b"de", 1)
        # A cut payload and a partial header both stop the iterator cleanly.
        self.assertEqual([payload for _s, payload, _o
                          in mysql.iter_packets(wire[:-1])], [b"abc"])
        self.assertEqual([payload for _s, payload, _o
                          in mysql.iter_packets(wire + b"\x05\x00")],
                         [b"abc", b"de"])
        self.assertEqual(list(mysql.iter_packets(b"")), [])


class HandshakeTest(unittest.TestCase):
    def test_handshake_v10_native_password(self):
        payload = handshake_payload()
        handshake = mysql.parse_handshake(payload)
        self.assertIsNotNone(handshake)
        self.assertEqual(handshake["protocol_version"], 10)
        self.assertEqual(handshake["server_version"], "8.0.36")
        self.assertEqual(handshake["connection_id"], 42)
        self.assertEqual(handshake["auth_plugin_data"], SALT)
        self.assertEqual(len(handshake["auth_plugin_data"]), 20)
        self.assertEqual(handshake["auth_plugin_name"],
                         "mysql_native_password")
        self.assertEqual(handshake["charset"], 33)
        self.assertEqual(handshake["status_flags"], 2)
        self.assertTrue(handshake["capabilities"]
                        & mysql.CLIENT_PROTOCOL_41)
        self.assertIn("CLIENT_PLUGIN_AUTH", handshake["capability_names"])

    def test_malformed_handshake_returns_none(self):
        self.assertIsNone(mysql.parse_handshake(b""))
        self.assertIsNone(mysql.parse_handshake(b"\x09short"))
        self.assertIsNone(mysql.parse_handshake(b"\x0a8.0"))

    def test_handshake_response_with_database_and_plugin(self):
        auth_response = mysql.caching_sha2_scramble("s3cr3t", SALT)
        payload = handshake_response_payload(auth_response=auth_response)
        response = mysql.parse_handshake_response(payload)
        self.assertIsNotNone(response)
        self.assertEqual(response["username"], "alice")
        self.assertEqual(response["database"], "app")
        self.assertEqual(response["auth_plugin_name"],
                         "caching_sha2_password")
        self.assertEqual(response["auth_response"], auth_response)
        self.assertEqual(response["max_packet"], 16 * 1024 * 1024)
        self.assertIsNone(mysql.parse_handshake_response(b"\x00" * 8))


class ScrambleTest(unittest.TestCase):
    def test_native_password_scramble_matches_formula(self):
        password = "s3cr3t"
        stage1 = hashlib.sha1(password.encode()).digest()
        stage2 = hashlib.sha1(stage1).digest()
        expected = bytes(
            left ^ right for left, right in
            zip(stage1, hashlib.sha1(SALT + stage2).digest()))
        scramble = mysql.native_password_scramble(password, SALT)
        self.assertEqual(scramble, expected)
        self.assertTrue(mysql.verify_native_password(
            password, SALT, expected))
        self.assertFalse(mysql.verify_native_password(
            "wrong", SALT, expected))

    def test_caching_sha2_scramble_matches_formula(self):
        password = "s3cr3t"
        stage1 = hashlib.sha256(password.encode()).digest()
        stage2 = hashlib.sha256(stage1).digest()
        expected = bytes(
            left ^ right for left, right in
            zip(stage1, hashlib.sha256(stage2 + SALT).digest()))
        scramble = mysql.caching_sha2_scramble(password, SALT)
        self.assertEqual(scramble, expected)
        self.assertTrue(mysql.verify_caching_sha2(
            password, SALT, expected))
        self.assertFalse(mysql.verify_caching_sha2(
            "wrong", SALT, expected))

    def test_empty_password_has_empty_auth_response(self):
        self.assertEqual(mysql.native_password_scramble("", SALT), b"")
        self.assertEqual(mysql.caching_sha2_scramble("", SALT), b"")


class PacketTypeTest(unittest.TestCase):
    def test_ok_err_and_eof(self):
        ok = mysql.parse_ok(ok_payload(affected=1, info=b"done"))
        self.assertEqual(ok["type"], "ok")
        self.assertEqual(ok["affected_rows"], 1)
        self.assertEqual(ok["status_flags"], 2)
        self.assertEqual(ok["info"], "done")

        err = mysql.parse_err(err_payload())
        self.assertEqual(err["type"], "err")
        self.assertEqual(err["code"], 1045)
        self.assertEqual(err["sqlstate"], "28000")
        self.assertEqual(err["message"], "Access denied")

        eof = mysql.parse_eof(eof_payload())
        self.assertEqual(eof["type"], "eof")
        self.assertEqual(eof["status_flags"], 2)

        self.assertIsNone(mysql.parse_ok(err_payload()))
        self.assertIsNone(mysql.parse_err(ok_payload()))
        self.assertIsNone(mysql.parse_eof(ok_payload()))


class ColumnAndRowTest(unittest.TestCase):
    def test_column_definition(self):
        column = mysql.parse_column_definition(column_payload("id", 3))
        self.assertEqual(column["catalog"], "def")
        self.assertEqual(column["schema"], "app")
        self.assertEqual(column["table"], "users")
        self.assertEqual(column["org_table"], "users")
        self.assertEqual(column["name"], "id")
        self.assertEqual(column["org_name"], "id")
        self.assertEqual(column["type"], 3)
        self.assertEqual(column["type_name"], "LONG")
        self.assertEqual(column["charset"], 33)
        self.assertEqual(column["flags"], 0)
        self.assertTrue(column["nullable"])

    def test_text_row_with_null(self):
        values = mysql.decode_text_row(text_row(1, "alice", None), 3)
        self.assertEqual(values, ["1", "alice", None])
        self.assertEqual(mysql.decode_text_row(b"", 2), [None, None])


class ResultSetTest(unittest.TestCase):
    def test_legacy_result_set(self):
        payloads = [
            b"\x02",
            column_payload("id", 3), column_payload("name"),
            eof_payload(),
            text_row(1, "alice"), text_row(2, "bob"),
            eof_payload(),
        ]
        result = mysql.ResultSet(payloads)
        self.assertEqual([column["name"] for column in result.columns],
                         ["id", "name"])
        self.assertEqual(result.rows, [["1", "alice"], ["2", "bob"]])
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.eof)
        self.assertIsNone(result.ok)
        self.assertEqual(result.consumed, len(payloads))

    def test_deprecate_eof_result_set(self):
        payloads = [
            b"\x01", column_payload("id", 3),
            text_row(7),
            b"\xfe\x00\x00" + struct.pack("<HH", 0, 2),
        ]
        result = mysql.ResultSet(payloads, deprecate_eof=True)
        self.assertEqual([column["name"] for column in result.columns],
                         ["id"])
        self.assertEqual(result.rows, [["7"]])
        self.assertIsNone(result.eof)
        self.assertIsNotNone(result.ok)
        self.assertEqual(result.consumed, len(payloads))

    def test_error_result_set(self):
        result = mysql.ResultSet([err_payload(1064, "42000", b"syntax")])
        self.assertIsNotNone(result.error)
        self.assertEqual(result.error["code"], 1064)
        self.assertEqual(result.error["sqlstate"], "42000")
        self.assertEqual(result.rows, [])
        self.assertIsNone(result.ok)
        self.assertEqual(result.consumed, 1)


class LocalInfileTest(unittest.TestCase):
    def test_request_and_chunks(self):
        self.assertEqual(
            mysql.parse_local_infile_request(b"\xfb/tmp/flag.csv"),
            "/tmp/flag.csv")
        self.assertIsNone(mysql.parse_local_infile_request(b"not-a-request"))
        framed = (frame(b"1,alice\n", 1) + frame(b"2,bob\n", 2)
                  + frame(b"", 3))
        self.assertEqual(mysql.load_data_chunks(framed),
                         b"1,alice\n2,bob\n")
        self.assertEqual(mysql.load_data_chunks([b"one\n", b"two\n"]),
                         b"one\ntwo\n")
        # Headers are stripped even when each blob is a separate packet.
        self.assertEqual(
            mysql.load_data_chunks([frame(b"one\n", 1), frame(b"", 2)]),
            b"one\n")


class SummariseStreamTest(unittest.TestCase):
    @staticmethod
    def _session_streams():
        """Build the client/server directions of one fake MySQL session."""
        server = (frame(handshake_payload(plugin="caching_sha2_password"), 0)
                  + frame(ok_payload(), 2)
                  + frame(b"\x02", 1)
                  + frame(column_payload("id", 3), 2)
                  + frame(column_payload("name"), 3)
                  + frame(eof_payload(), 4)
                  + frame(text_row(1, "alice"), 5)
                  + frame(text_row(2, "bob"), 6)
                  + frame(eof_payload(), 7)
                  + frame(b"\xfb/tmp/flag.csv", 1)
                  + frame(ok_payload(), 2))
        auth_response = mysql.caching_sha2_scramble("s3cr3t", SALT)
        client = (frame(handshake_response_payload(
                            auth_response=auth_response), 1)
                  + frame(b"\x03SELECT id, name FROM users", 0)
                  + frame(b"\x03LOAD DATA LOCAL INFILE '/tmp/flag.csv' "
                          b"INTO TABLE t", 0)
                  + frame(b"1,alice\n", 1)
                  + frame(b"2,bob\n", 2)
                  + frame(b"", 3))
        server_stream = StreamData(
            stream="0", src="10.0.0.9", sport="3306",
            dst="10.0.0.5", dport="40000", data=server)
        client_stream = StreamData(
            stream="0", src="10.0.0.5", sport="40000",
            dst="10.0.0.9", dport="3306", data=client)
        return client_stream, server_stream

    def test_session_summary(self):
        client, server = self._session_streams()
        summary = mysql.summarise_stream([client, server])
        self.assertEqual(summary["host"], "10.0.0.9")
        self.assertEqual(summary["port"], 3306)
        self.assertEqual(summary["client"], "10.0.0.5:40000")
        self.assertEqual(summary["server_version"], "8.0.36")
        self.assertIn("caching_sha2_password", summary["auth_plugin"])
        self.assertEqual(summary["users"], ["alice"])
        self.assertEqual(summary["databases"], ["app"])
        self.assertIn("SELECT id, name FROM users", summary["queries"])
        self.assertTrue(any("LOAD DATA LOCAL INFILE" in query
                            for query in summary["queries"]))
        self.assertEqual(len(summary["result_sets"]), 1)
        result = summary["result_sets"][0]
        self.assertEqual(result["columns"], ["id", "name"])
        self.assertEqual(result["rows"], [["1", "alice"], ["2", "bob"]])
        self.assertEqual(len(summary["local_infiles"]), 1)
        upload = summary["local_infiles"][0]
        self.assertEqual(upload["filename"], "/tmp/flag.csv")
        self.assertEqual(upload["data"], b"1,alice\n2,bob\n")
        self.assertEqual(upload["size"], len(b"1,alice\n2,bob\n"))
        self.assertEqual(summary["errors"], [])

    def test_load_file_result_carries_file_text(self):
        server = (frame(handshake_payload(), 0)
                  + frame(ok_payload(), 2)
                  + frame(b"\x01", 1)
                  + frame(column_payload("data"), 2)
                  + frame(eof_payload(), 3)
                  + frame(text_row("root:x:0:0"), 4)
                  + frame(eof_payload(), 5))
        client = (frame(handshake_response_payload(
                            auth_response=b"x" * 20), 1)
                  + frame(b"\x03SELECT LOAD_FILE('/etc/passwd')", 0))
        summary = mysql.summarise_stream([
            StreamData(stream="0", src="10.0.0.9", sport="3306",
                       dst="10.0.0.5", dport="40000", data=server),
            StreamData(stream="0", src="10.0.0.5", sport="40000",
                       dst="10.0.0.9", dport="3306", data=client),
        ])
        self.assertEqual(len(summary["load_file_results"]), 1)
        item = summary["load_file_results"][0]
        self.assertEqual(item["filename"], "/etc/passwd")
        self.assertEqual(item["data"], "root:x:0:0")
        self.assertTrue(item["found"])

    def test_no_handshake_returns_empty_summary(self):
        summary = mysql.summarise_stream([])
        self.assertEqual(summary["queries"], [])
        self.assertEqual(summary["users"], [])
        self.assertEqual(summary["errors"], [])


if __name__ == "__main__":
    unittest.main()

