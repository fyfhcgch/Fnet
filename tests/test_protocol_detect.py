"""Unit tests for port-independent protocol detection (no tshark needed)."""
from __future__ import annotations

import struct
import unittest

from fnet.utils import protocol_detect


def mongo_msg(opcode: int = 2013, flags: int = 0) -> bytes:
    body = struct.pack("<I", flags) + b"\x00"
    length = 16 + len(body)
    return struct.pack("<iiii", length, 1, 0, opcode) + body


class ProtocolDetectTest(unittest.TestCase):
    def test_redis_resp_and_inline(self):
        resp = b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n"
        self.assertTrue(protocol_detect.detect_redis(resp))
        self.assertTrue(protocol_detect.detect_redis(b"PING\r\n"))
        self.assertTrue(protocol_detect.detect_redis(b"GET foo\r\n"))
        self.assertFalse(protocol_detect.detect_redis(b"GET / HTTP/1.1\r\n"))

    def test_mongodb_header(self):
        self.assertTrue(protocol_detect.detect_mongodb(mongo_msg()))
        self.assertTrue(protocol_detect.detect_mongodb(mongo_msg(2004)))
        self.assertFalse(protocol_detect.detect_mongodb(b"\x00" * 16))
        self.assertFalse(protocol_detect.detect_mongodb(b"short"))

    def test_postgres_startup_and_frontend(self):
        startup = struct.pack(">I", 8) + struct.pack(">I", 196608)
        self.assertTrue(protocol_detect.detect_postgres(startup))
        ssl_request = struct.pack(">II", 8, 80877103)
        self.assertTrue(protocol_detect.detect_postgres(ssl_request))
        query = b"Q" + struct.pack(">I", 4 + len(b"select 1\x00")) + b"select 1\x00"
        self.assertTrue(protocol_detect.detect_postgres(query))
        self.assertFalse(protocol_detect.detect_postgres(b"HTTP/1.1 200 OK\r\n"))
        self.assertFalse(protocol_detect.detect_postgres(b"\x00" * 8))

    def test_ldap_bind(self):
        bind = b"\x30\x08\x02\x01\x01\x60\x03\x02\x01\x03"
        self.assertTrue(protocol_detect.detect_ldap(bind))
        search = b"\x30\x0b\x02\x01\x02\x63\x06\x04\x04a=b="
        self.assertTrue(protocol_detect.detect_ldap(search))
        self.assertFalse(protocol_detect.detect_ldap(b"\x30\x01\x00"))
        self.assertFalse(protocol_detect.detect_ldap(b"hello"))

    def test_smb2_and_netbios(self):
        self.assertTrue(protocol_detect.detect_smb2(b"\xfeSMB" + b"\x00" * 20))
        netbios = b"\x00\x00\x00\x20" + b"\xfeSMB" + b"\x00" * 20
        self.assertTrue(protocol_detect.detect_smb2(netbios))
        self.assertFalse(protocol_detect.detect_smb2(b"GET / HTTP/1.1"))

    def test_http2_preface_and_frame(self):
        self.assertTrue(protocol_detect.detect_http2(
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
        frame = b"\x00\x00\x04\x04\x00\x00\x00\x00\x01"
        self.assertTrue(protocol_detect.detect_http2(frame))
        self.assertFalse(protocol_detect.detect_http2(b"GET / HTTP/1.1\r\n"))

    def test_best_guess_order(self):
        self.assertEqual(protocol_detect.detect_protocol(
            b"*1\r\n$4\r\nPING\r\n"), "redis")
        self.assertEqual(protocol_detect.detect_protocol(mongo_msg()),
                         "mongodb")
        self.assertEqual(protocol_detect.detect_protocol(b"\x00" * 4), "")

    def test_helpers(self):
        self.assertTrue(protocol_detect.is_default_port("redis", 6379))
        self.assertFalse(protocol_detect.is_default_port("redis", 16379))
        self.assertEqual(protocol_detect.decode_as("mongodb"), "mongo")
        self.assertEqual(protocol_detect.decode_args("postgres", [15432]),
                         ["-d", "tcp.port==15432,pgsql"])
        self.assertEqual(protocol_detect.port_filter("redis", [6379, 16379]),
                         "tcp.port == 6379 || tcp.port == 16379")
        self.assertEqual(protocol_detect.decode_args("redis", [6379]), [])


if __name__ == "__main__":
    unittest.main()
