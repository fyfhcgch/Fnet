"""Unit tests for the pure-Python MySQL protocol parser (no tshark)."""
from __future__ import annotations

import hashlib
import struct
import unittest

from fnet.utils import mysql

CAPS = (mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_PROTOCOL_41
        | mysql.CLIENT_SECURE_CONNECTION | mysql.CLIENT_PLUGIN_AUTH
        | mysql.CLIENT_CONNECT_WITH_DB | mysql.CLIENT_DEPRECATE_EOF)
PLUGIN = "caching_sha2_password"
SALT = bytes(range(1, 21))


# ---------------------------------------------------------------------------
# Packet builders (little helpers used by several tests)
# ---------------------------------------------------------------------------

def packet(payload: bytes, seq: int = 0) -> bytes:
    return len(payload).to_bytes(3, "little") + bytes([seq]) + payload


def lenenc(value: int) -> bytes:
    if value < 0xFB:
        return bytes([value])
    if value < 0x10000:
        return b"\xfc" + value.to_bytes(2, "little")
    return b"\xfe" + value.to_bytes(8, "little")


def lstr(value: str | bytes) -> bytes:
    data = value.encode() if isinstance(value, str) else value
    return lenenc(len(data)) + data


def handshake(server_version: str = "8.0.36", connection_id: int = 42,
              salt: bytes = SALT, plugin: str = PLUGIN,
              caps: int = CAPS, charset: int = 33, status: int = 2) -> bytes:
    part1, part2 = salt[:8], salt[8:]
    return (bytes([10]) + server_version.encode() + b"\x00"
            + connection_id.to_bytes(4, "little")
            + part1 + b"\x00"
            + (caps & 0xFFFF).to_bytes(2, "little")
            + bytes([charset]) + status.to_bytes(2, "little")
            + (caps >> 16).to_bytes(2, "little")
            + bytes([len(salt) + 1]) + b"\x00" * 10
            + part2 + b"\x00"
            + plugin.encode() + b"\x00")


def handshake_response(user: str = "root", password: str = "s3cret",
                       database: str = "ctf", plugin: str = PLUGIN,
                       caps: int = CAPS, salt: bytes = SALT) -> bytes:
    auth = mysql.caching_sha2_scramble(password, salt)
    body = (caps.to_bytes(4, "little")
            + (16 * 1024 * 1024).to_bytes(4, "little")
            + bytes([33]) + b"\x00" * 23
            + user.encode() + b"\x00"
            + bytes([len(auth)]) + auth)
    if caps & mysql.CLIENT_CONNECT_WITH_DB:
        body += database.encode() + b"\x00"
    if caps & mysql.CLIENT_PLUGIN_AUTH:
        body += plugin.encode() + b"\x00"
    return body


def ok_packet(affected: int = 0, insert_id: int = 0, status: int = 2,
              warnings: int = 0, info: bytes = b"") -> bytes:
    return (b"\x00" + lenenc(affected) + lenenc(insert_id)
            + status.to_bytes(2, "little") + warnings.to_bytes(2, "little")
            + info)


def err_packet(code: int = 1146, sql_state: str = "42S02",
               message: str = "Table 'ctf.users' doesn't exist") -> bytes:
    return (b"\xff" + code.to_bytes(2, "little") + b"#"
            + sql_state.encode() + message.encode())


def eof_packet(warnings: int = 0, status: int = 2) -> bytes:
    return b"\xfe" + warnings.to_bytes(2, "little") + status.to_bytes(2, "little")


def column_definition(name: str, type_code: int = 253, flags: int = 0,
                      schema: str = "ctf", table: str = "users") -> bytes:
    return (lstr("def") + lstr(schema) + lstr(table) + lstr(table)
            + lstr(name) + lstr(name) + b"\x0c"
            + (33).to_bytes(2, "little") + (255).to_bytes(4, "little")
            + bytes([type_code]) + flags.to_bytes(2, "little")
            + b"\x00" + b"\x00\x00")


def text_row(*values: str | None) -> bytes:
    return b"".join(b"\xfb" if v is None else lstr(str(v)) for v in values)


class FakeStream:
    """Minimal stand-in for fnet.utils.stream.StreamData."""

    def __init__(self, src: str, sport: str, dst: str, dport: str,
                 data: bytes):
        self.src = src
        self.sport = sport
        self.dst = dst
        self.dport = dport
        self.data = data


def frame(payloads: list[bytes]) -> bytes:
    return b"".join(packet(p, seq) for seq, p in enumerate(payloads))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class IterPacketsTest(unittest.TestCase):
    def test_framing(self):
        data = packet(b"hello", 3) + packet(b"world", 4)
        packets = list(mysql.iter_packets(data))
        self.assertEqual(packets, [(3, b"hello"), (4, b"world")])

    def test_empty_payload_packet(self):
        # Zero-length packets (e.g. the LOCAL INFILE end marker) are valid.
        self.assertEqual(list(mysql.iter_packets(packet(b"", 9))),
                         [(9, b"")])

    def test_stops_on_truncated_packet(self):
        data = packet(b"aaa", 1) + packet(b"bbbbbbb")[:5]
        self.assertEqual(list(mysql.iter_packets(data)), [(1, b"aaa")])

    def test_garbage_and_empty(self):
        self.assertEqual(list(mysql.iter_packets(b""), ), [])
        self.assertEqual(list(mysql.iter_packets(b"\x01\x02")), [])
        self.assertEqual(list(mysql.iter_packets(b"\xff\xff\xff\x07xxxxx")), [])


class HandshakeTest(unittest.TestCase):
    def test_parse_handshake(self):
        info = mysql.parse_handshake(handshake())
        self.assertIsNotNone(info)
        self.assertEqual(info["protocol"], 10)
        self.assertEqual(info["server_version"], "8.0.36")
        self.assertEqual(info["connection_id"], 42)
        self.assertEqual(info["salt"], SALT)
        self.assertEqual(len(info["salt"]), 20)
        self.assertEqual(info["capabilities"], CAPS)
        self.assertEqual(info["charset"], 33)
        self.assertEqual(info["status"], 2)
        self.assertEqual(info["auth_plugin"], PLUGIN)

    def test_parse_handshake_default_plugin(self):
        info = mysql.parse_handshake(handshake(plugin="", caps=0x00008200))
        self.assertEqual(info["auth_plugin"], "")
        self.assertEqual(info["salt"], SALT)

    def test_parse_handshake_rejects_malformed(self):
        self.assertIsNone(mysql.parse_handshake(b""))
        self.assertIsNone(mysql.parse_handshake(b"\x09"))
        self.assertIsNone(mysql.parse_handshake(b"\x0a5.7-log"))
        self.assertIsNone(mysql.parse_handshake(handshake()[:20]))


class HandshakeResponseTest(unittest.TestCase):
    def test_parse_response(self):
        response = mysql.parse_handshake_response(handshake_response())
        self.assertIsNotNone(response)
        self.assertEqual(response["capabilities"], CAPS)
        self.assertEqual(response["username"], "root")
        self.assertEqual(response["database"], "ctf")
        self.assertEqual(response["auth_plugin"], PLUGIN)
        self.assertEqual(response["auth_response"],
                         mysql.caching_sha2_scramble("s3cret", SALT))
        self.assertTrue(mysql.verify_caching_sha2(
            "s3cret", SALT, response["auth_response"]))

    def test_parse_response_no_database(self):
        caps = CAPS & ~mysql.CLIENT_CONNECT_WITH_DB
        payload = handshake_response(caps=caps)
        response = mysql.parse_handshake_response(payload)
        self.assertEqual(response["database"], "")
        self.assertEqual(response["username"], "root")

    def test_parse_response_rejects_malformed(self):
        self.assertIsNone(mysql.parse_handshake_response(b""))
        self.assertIsNone(mysql.parse_handshake_response(b"\x00" * 31))
        # Unterminated username after the fixed part.
        self.assertIsNone(mysql.parse_handshake_response(b"\x00" * 32 + b"root"))


class ScrambleTest(unittest.TestCase):
    @staticmethod
    def _native_expected(pw: str, salt: bytes) -> bytes:
        stage1 = hashlib.sha1(pw.encode()).digest()
        stage2 = hashlib.sha1(stage1).digest()
        stage3 = hashlib.sha1(salt + stage2).digest()
        return bytes(a ^ b for a, b in zip(stage1, stage3))

    @staticmethod
    def _sha2_expected(pw: str, salt: bytes) -> bytes:
        d1 = hashlib.sha256(pw.encode()).digest()
        d2 = hashlib.sha256(d1).digest()
        d3 = hashlib.sha256(d2 + salt).digest()
        return bytes(a ^ b for a, b in zip(d1, d3))

    def test_native_vector(self):
        salt = bytes(range(20))
        self.assertEqual(mysql.native_password_scramble("toor", salt),
                         self._native_expected("toor", salt))
        self.assertEqual(mysql.native_password_scramble("", b"nolib"),
                         self._native_expected("", b"nolib"))
        self.assertTrue(mysql.verify_native_password(
            "toor", salt, self._native_expected("toor", salt)))
        self.assertFalse(mysql.verify_native_password(
            "wrong", salt, self._native_expected("toor", salt)))

    def test_caching_sha2_vector(self):
        salt = bytes(range(1, 21))
        self.assertEqual(mysql.caching_sha2_scramble("p@ss", salt),
                         self._sha2_expected("p@ss", salt))
        self.assertTrue(mysql.verify_caching_sha2(
            "p@ss", salt, self._sha2_expected("p@ss", salt)))
        self.assertFalse(mysql.verify_caching_sha2(
            "p@ss", salt, self._native_expected("p@ss", salt)))

    def test_accepts_bytes_input(self):
        self.assertEqual(mysql.native_password_scramble(b"pw", SALT),
                         mysql.native_password_scramble("pw", SALT))


class ResponsePacketTest(unittest.TestCase):
    def test_parse_ok(self):
        info = mysql.parse_ok(ok_packet(affected=3, insert_id=7, info=b"Rows"))
        self.assertEqual(info["affected_rows"], 3)
        self.assertEqual(info["last_insert_id"], 7)
        self.assertEqual(info["status"], 2)
        self.assertEqual(info["warnings"], 0)
        self.assertEqual(info["info"], "Rows")

    def test_parse_ok_rejects_other_packets(self):
        self.assertIsNone(mysql.parse_ok(b""))
        self.assertIsNone(mysql.parse_ok(err_packet()))
        self.assertIsNone(mysql.parse_ok(eof_packet()))

    def test_parse_err(self):
        error = mysql.parse_err(err_packet())
        self.assertEqual(error["code"], 1146)
        self.assertEqual(error["sql_state"], "42S02")
        self.assertEqual(error["message"], "Table 'ctf.users' doesn't exist")

    def test_parse_err_without_sql_state(self):
        raw = b"\xff" + (1045).to_bytes(2, "little") + b"denied"
        error = mysql.parse_err(raw)
        self.assertEqual(error["code"], 1045)
        self.assertEqual(error["sql_state"], "")
        self.assertEqual(error["message"], "denied")

    def test_parse_eof(self):
        eof = mysql.parse_eof(eof_packet(warnings=1, status=0x0002))
        self.assertEqual(eof, {"warnings": 1, "status": 2})
        self.assertIsNone(mysql.parse_eof(b""))
        self.assertIsNone(mysql.parse_ok(eof_packet()))
        self.assertIsNone(mysql.parse_eof(b"\xfe" + b"\x00" * 6))


class ColumnAndRowTest(unittest.TestCase):
    def test_parse_column_definition(self):
        column = mysql.parse_column_definition(
            column_definition("name", type_code=253, flags=1))
        self.assertEqual(column["name"], "name")
        self.assertEqual(column["org_name"], "name")
        self.assertEqual(column["schema"], "ctf")
        self.assertEqual(column["table"], "users")
        self.assertEqual(column["catalog"], "def")
        self.assertEqual(column["charset"], 33)
        self.assertEqual(column["type"], 253)
        self.assertEqual(column["type_name"], "varstring")
        self.assertEqual(column["flags"], 1)
        self.assertEqual(column["decimals"], 0)

    def test_parse_column_definition_malformed(self):
        self.assertIsNone(mysql.parse_column_definition(b"\x02ab"))
        self.assertIsNone(mysql.parse_column_definition(b""))

    def test_decode_text_row(self):
        payload = lstr("alice") + b"\xfb" + lstr("42") + lenenc(0)
        self.assertEqual(mysql.decode_text_row(payload, 4),
                         ["alice", None, "42", ""])

    def test_decode_text_row_truncated(self):
        payload = lstr("ab") + b"\x10xy"
        self.assertEqual(mysql.decode_text_row(payload, 2), ["ab"])

    def test_decode_text_row_empty(self):
        self.assertEqual(mysql.decode_text_row(b"", 3), [])


class ResultSetTest(unittest.TestCase):
    def _columns(self, names: list[str]) -> list[bytes]:
        return [lenenc(len(names))] + [column_definition(n) for n in names]

    def test_success_classic_eof(self):
        packets = [lenenc(2), column_definition("id", type_code=3),
                   column_definition("name"), eof_packet(),
                   text_row("1", "alice"), text_row("2", "bob"), eof_packet()]
        result = mysql.ResultSet(packets)
        self.assertEqual(result.column_count, 2)
        self.assertEqual(result.column_names, ["id", "name"])
        self.assertEqual(result.rows, [["1", "alice"], ["2", "bob"]])
        self.assertIsNone(result.error)
        self.assertTrue(result.succeeded)
        self.assertEqual(result.consumed, 7)

    def test_success_deprecate_eof(self):
        packets = self._columns(["a", "b"]) + [text_row("", "hello"),
                                               ok_packet(affected=0)]
        result = mysql.ResultSet(packets)
        self.assertIsNone(result.error)
        self.assertEqual(result.rows, [["", "hello"]])
        self.assertIsNotNone(result.ok)
        self.assertEqual(result.ok["status"], 2)

    def test_error_packet(self):
        packets = [lenenc(2), column_definition("a"),
                   err_packet(code=1064, message="syntax error")]
        result = mysql.ResultSet(packets)
        self.assertEqual(result.rows, [])
        self.assertEqual(result.error["code"], 1064)
        self.assertFalse(result.succeeded)

    def test_empty_and_malformed(self):
        self.assertEqual(mysql.ResultSet([]).rows, [])
        self.assertEqual(mysql.ResultSet([err_packet()]).error["code"], 1146)
        # A lone OK packet (e.g. USE db response) parses fine.
        result = mysql.ResultSet([ok_packet()])
        self.assertIsNone(result.error)
        self.assertIsNotNone(result.ok)


class LocalInfileTest(unittest.TestCase):
    def test_parse_request(self):
        self.assertEqual(
            mysql.parse_local_infile_request(b"\xfb/etc/passwd"),
            "/etc/passwd")
        self.assertEqual(
            mysql.parse_local_infile_request(b"\xfbflag.txt\x00"), "flag.txt")
        self.assertIsNone(mysql.parse_local_infile_request(b"\x00"))
        self.assertIsNone(mysql.parse_local_infile_request(b""))

    def test_load_data_chunks_strips_headers(self):
        chunks = [packet(b"root:x:0:0\n", 1), packet(b"daemon:x:1:0\n", 2),
                  packet(b"", 3)]
        self.assertEqual(mysql.load_data_chunks(chunks),
                         b"root:x:0:0\ndaemon:x:1:0\n")

    def test_load_data_chunks_accepts_bare_payloads(self):
        self.assertEqual(mysql.load_data_chunks([b"abc", b"def"]), b"abcdef")

    def test_load_data_chunks_empty(self):
        self.assertEqual(mysql.load_data_chunks([]), b"")
        self.assertEqual(mysql.load_data_chunks([b"", b""]), b"")


class SummariseStreamTest(unittest.TestCase):
    FILE_DATA = b"root:x:0:0:root:/root:/bin/sh\ndaemon:x:1:1\n"

    def build_streams(self) -> list[FakeStream]:
        file_data = self.FILE_DATA
        server = frame([
            handshake(),                              # greeting
            ok_packet(),                              # auth OK
            lenenc(2),                                # column count
            column_definition("id", type_code=3),
            column_definition("name"),
            text_row("1", "alice"),
            text_row("2", None),
            eof_packet(),                             # classic EOF
            b"\xfb/etc/passwd",                       # LOCAL INFILE request
            ok_packet(affected=2),                    # upload OK
        ])
        client = frame([
            handshake_response(),                     # login
            b"\x03SELECT id, name FROM users",        # COM_QUERY
            b"\x03LOAD DATA LOCAL INFILE '/etc/passwd'"
            b" INTO TABLE dump",                      # COM_QUERY
            file_data,
            b"",                                      # end-of-upload marker
        ])
        return [FakeStream("10.0.0.2", "50000", "10.0.0.1", "3306", client),
                FakeStream("10.0.0.1", "3306", "10.0.0.2", "50000", server)]

    def test_summary(self):
        summary = mysql.summarise_stream(self.build_streams())
        self.assertEqual(summary["host"], "10.0.0.1")
        self.assertEqual(summary["port"], 3306)
        self.assertEqual(summary["server_version"], "8.0.36")
        self.assertEqual(summary["auth_plugin"], PLUGIN)
        self.assertEqual(summary["users"], ["root"])
        self.assertEqual(summary["databases"], ["ctf"])
        self.assertEqual(summary["queries"], [
            "SELECT id, name FROM users",
            "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE dump",
        ])
        self.assertEqual(len(summary["result_sets"]), 1)
        result = summary["result_sets"][0]
        self.assertEqual(result["columns"], ["id", "name"])
        self.assertEqual(result["rows"], [["1", "alice"], ["2", None]])
        self.assertIsNone(result["error"])

    def test_summary_local_infile(self):
        summary = mysql.summarise_stream(self.build_streams())
        self.assertEqual(len(summary["local_infiles"]), 1)
        entry = summary["local_infiles"][0]
        self.assertEqual(entry["filename"], "/etc/passwd")
        self.assertEqual(entry["size"], len(self.FILE_DATA))
        self.assertIn(b"root:x:0:0", entry["data"])

    def test_no_handshake(self):
        stream = FakeStream("1.2.3.4", "1", "5.6.7.8", "2", b"not-mysql")
        summary = mysql.summarise_stream([stream])
        self.assertEqual(summary["host"], "")
        self.assertEqual(summary["queries"], [])

    def test_malformed_never_raises(self):
        stream = FakeStream("10.0.0.1", "3306", "10.0.0.2", "1",
                            b"\x0a\x02\x05\x00\x00\x00\x01\x00garbage")
        summary = mysql.summarise_stream([stream])
        # No parsable handshake greeting -> empty summary, but no exception.
        self.assertEqual(summary["host"], "")
        self.assertEqual(summary["port"], 0)
        self.assertEqual(summary["result_sets"], [])
        # Empty input and a single stream object are accepted too.
        self.assertEqual(mysql.summarise_stream([])["users"], [])
        self.assertEqual(mysql.summarise_stream(stream)["users"], [])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
