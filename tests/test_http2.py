"""Unit tests for the HTTP/2 framing + HPACK implementation (no tshark)."""
from __future__ import annotations

import unittest

from fnet.utils import http2
from fnet.utils.http2 import (
    HpackDecoder, PREFACE, encode_literal, grpc_messages, huffman_decode,
    parse_direction, parse_frames, protobuf_fields,
)


def frame(kind: int, flags: int, stream: int, payload: bytes) -> bytes:
    return (len(payload).to_bytes(3, "big") + bytes([kind, flags])
            + stream.to_bytes(4, "big") + payload)


class HpackTest(unittest.TestCase):
    def test_rfc7541_huffman_request(self):
        # RFC 7541 C.4.1: GET http://www.example.com/ with Huffman strings.
        block = bytes.fromhex("828684418cf1e3c2e5f23a6ba0ab90f4ff")
        self.assertEqual(HpackDecoder().decode(block), [
            (":method", "GET"), (":scheme", "http"), (":path", "/"),
            (":authority", "www.example.com"),
        ])

    def test_dynamic_table_and_literal(self):
        decoder = HpackDecoder()
        block = (encode_literal("x-token", "abc", indexing=True)
                 + encode_literal("x-token", "def", indexing=True)
                 + b"\xbe")  # index 62 = newest dynamic entry
        headers = decoder.decode(block)
        self.assertEqual(headers[-1], ("x-token", "def"))
        self.assertEqual(decoder.dynamic[0], ("x-token", "def"))

    def test_table_size_update_clears_entries(self):
        decoder = HpackDecoder()
        decoder.decode(encode_literal("a", "b", indexing=True))
        self.assertTrue(decoder.dynamic)
        # 0x20 = dynamic table size update, value 0.
        decoder.decode(b"\x20")
        self.assertEqual(decoder.dynamic, [])
        self.assertEqual(decoder.size_updates, [0])

    def test_never_indexed_literal(self):
        # 0x10 prefix with a literal name/value pair.
        block = b"\x10" + b"\x03abc" + b"\x03xyz"
        self.assertEqual(HpackDecoder().decode(block),
                         [("abc", "xyz")])

    def test_huffman_padding_error(self):
        with self.assertRaises(ValueError):
            huffman_decode(b"\x00")
        self.assertEqual(huffman_decode(b"\xf1\xe3\xc7"), "www")


class FrameTest(unittest.TestCase):
    def test_frames_and_data_reassembly(self):
        block = (encode_literal(":method", "POST")
                 + encode_literal(":path", "/login"))
        data = (PREFACE + frame(4, 0, 0, b"")
                + frame(1, 0x5, 1, block)
                + frame(0, 0x0, 1, b"user=")
                + frame(0, 0x1, 1, b"admin"))
        frames, truncated = parse_frames(data)
        self.assertFalse(truncated)
        self.assertEqual([item.name for item in frames],
                         ["SETTINGS", "HEADERS", "DATA", "DATA"])
        side = parse_direction(data, frame_at=lambda offset: str(offset))
        stream = side.streams[1]
        self.assertEqual(stream.headers,
                         [(":method", "POST"), (":path", "/login")])
        self.assertEqual(bytes(stream.body), b"user=admin")
        self.assertTrue(stream.ended)
        self.assertFalse(side.truncated)

    def test_continuation_and_trailers(self):
        block = (encode_literal(":method", "GET")
                 + encode_literal(":path", "/x")
                 + encode_literal("cookie", "a=b"))
        cut = 6
        data = (frame(1, 0x1, 3, block[:cut])
                + frame(9, 0x4, 3, block[cut:])
                + frame(0, 0x1, 3, b"body"))
        side = parse_direction(data)
        stream = side.streams[3]
        self.assertEqual(stream.header(":path"), "/x")
        self.assertEqual(stream.header("cookie"), "a=b")
        self.assertEqual(bytes(stream.body), b"body")
        self.assertTrue(stream.ended)

    def test_padding_priority_and_settings(self):
        headers = encode_literal(":path", "/p")
        payload = bytes([2]) + b"\x00\x00\x00\x03" + b"\x10" + headers + b"\x00\x00"
        settings = (1).to_bytes(2, "big") + (65535).to_bytes(4, "big")
        data = (frame(1, 0x8 | 0x20 | 0x4, 2, payload)
                + frame(4, 0, 0, settings))
        side = parse_direction(data)
        self.assertEqual(side.streams[2].headers, [(":path", "/p")])
        self.assertEqual(side.streams[2].padding, 2)
        self.assertEqual(side.priorities[2]["weight"], 17)
        self.assertEqual(side.settings[0]["entries"][0]["name"],
                         "HEADER_TABLE_SIZE")

    def test_goaway_reset_and_ping(self):
        data = (frame(6, 0, 0, b"12345678")
                + frame(3, 0, 1, (8).to_bytes(4, "big"))
                + frame(7, 0, 0, (1).to_bytes(4, "big")
                        + (11).to_bytes(4, "big") + b"calm"))
        side = parse_direction(data)
        self.assertEqual(side.pings, 1)
        self.assertEqual(side.resets[1], 8)
        self.assertEqual(side.goaway["name"], "ENHANCE_YOUR_CALM")
        self.assertEqual(side.goaway["debug"], "calm")

    def test_truncated_frame_is_reported(self):
        data = frame(0, 0, 1, b"abc")[:-1]
        frames, truncated = parse_frames(data)
        self.assertEqual(frames, [])
        self.assertTrue(truncated)

    def test_looks_like_http2(self):
        self.assertTrue(http2.looks_like_http2(PREFACE))
        self.assertTrue(http2.looks_like_http2(frame(4, 0, 0, b"")))
        self.assertFalse(http2.looks_like_http2(b"GET / HTTP/1.1\r\n\r\n"))


class GrpcTest(unittest.TestCase):
    def test_grpc_messages(self):
        payload = b"\x08\x96\x01\x12\x03abc"
        body = b"\x00" + len(payload).to_bytes(4, "big") + payload
        self.assertEqual(grpc_messages(body), [(False, payload)])
        fields = protobuf_fields(payload)
        self.assertIn("#1 varint=150", fields)
        self.assertIn("#2 string=abc", fields)

    def test_grpc_truncated_message_is_ignored(self):
        body = b"\x00" + (10).to_bytes(4, "big") + b"short"
        self.assertEqual(grpc_messages(body), [])

    def test_is_grpc(self):
        self.assertTrue(http2.is_grpc([("content-type", "application/grpc")]))
        self.assertFalse(http2.is_grpc([("content-type", "text/plain")]))


if __name__ == "__main__":
    unittest.main()