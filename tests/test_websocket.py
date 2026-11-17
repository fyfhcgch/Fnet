"""Unit tests for the raw WebSocket parser (no tshark needed)."""
from __future__ import annotations

import unittest
import zlib

from fnet.utils import websocket as ws


def frame(opcode: int, payload: bytes, *, fin: bool = True,
          rsv1: bool = False, mask: bytes | None = None) -> bytes:
    first = (0x80 if fin else 0) | (0x40 if rsv1 else 0) | opcode
    length = len(payload)
    if length < 126:
        head = bytes([first, (0x80 | length) if mask else length])
    elif length < 65536:
        head = bytes([first, (0x80 | 126) if mask else 126]) + length.to_bytes(2, "big")
    else:
        head = bytes([first, (0x80 | 127) if mask else 127]) + length.to_bytes(8, "big")
    if mask:
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        return head + mask + masked
    return head + payload


def deflate(payload: bytes) -> bytes:
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(payload) + compressor.flush()


class FrameParserTest(unittest.TestCase):
    def test_masked_text_frame(self):
        data = frame(ws.OP_TEXT, b"hello", mask=b"abcd")
        frames = ws.parse_frames(data)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].opcode, ws.OP_TEXT)
        self.assertTrue(frames[0].masked)
        self.assertEqual(frames[0].payload, b"hello")

    def test_unmasked_server_frame(self):
        frames = ws.parse_frames(frame(ws.OP_TEXT, b"world"))
        self.assertEqual(frames[0].payload, b"world")
        self.assertFalse(frames[0].masked)

    def test_incremental_parse(self):
        data = frame(ws.OP_TEXT, b"split", mask=b"1234")
        parser = ws.FrameParser()
        parser.handshake_done = True
        self.assertEqual(parser.feed(data[:3], "1"), [])
        frames = parser.feed(data[3:], "2")
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0].payload, b"split")
        self.assertEqual(frames[0].frame, "1")

    def test_multiple_frames_in_one_payload(self):
        data = frame(ws.OP_TEXT, b"one") + frame(ws.OP_TEXT, b"two")
        self.assertEqual([item.payload for item in ws.parse_frames(data)],
                         [b"one", b"two"])

    def test_handshake_is_skipped(self):
        handshake = (b"GET /chat HTTP/1.1\r\nHost: x\r\n"
                     b"Upgrade: websocket\r\n\r\n")
        data = handshake + frame(ws.OP_TEXT, b"after")
        parser = ws.FrameParser()
        frames = parser.feed(data, "1")
        self.assertEqual([item.payload for item in frames], [b"after"])
        self.assertTrue(parser.handshake_done)


class ReassembleTest(unittest.TestCase):
    def test_fragmented_message(self):
        frames = [
            ws.Frame(fin=False, opcode=ws.OP_TEXT, payload=b"Hello ", frame="1"),
            ws.Frame(fin=False, opcode=ws.OP_CONTINUATION, payload=b"frag", frame="2"),
            ws.Frame(fin=True, opcode=ws.OP_CONTINUATION, payload=b"mented", frame="3"),
        ]
        messages = ws.reassemble(frames)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].payload, b"Hello fragmented")
        self.assertEqual(messages[0].frames, ["1", "2", "3"])

    def test_control_frame_between_fragments(self):
        frames = [
            ws.Frame(fin=False, opcode=ws.OP_TEXT, payload=b"a", frame="1"),
            ws.Frame(fin=True, opcode=ws.OP_PING, payload=b"p", frame="2"),
            ws.Frame(fin=True, opcode=ws.OP_CONTINUATION, payload=b"b", frame="3"),
        ]
        messages = ws.reassemble(frames)
        names = [message.name for message in messages]
        self.assertEqual(names, ["ping", "text"])
        self.assertEqual(messages[1].payload, b"ab")

    def test_permessage_deflate(self):
        payload = b"flag{deflated}" * 10
        frames = [ws.Frame(fin=True, opcode=ws.OP_BINARY,
                           payload=deflate(payload), rsv1=True, frame="1")]
        messages = ws.reassemble(frames, inflate=True)
        self.assertEqual(messages[0].payload, payload)
        self.assertTrue(messages[0].compressed)

    def test_inflate_rejects_garbage(self):
        self.assertEqual(ws.inflate_message(b"not deflate"), b"")


class HelperTest(unittest.TestCase):
    def test_strip_handshake(self):
        data = b"GET / HTTP/1.1\r\nUpgrade: websocket\r\n\r\nbody"
        stripped, done = ws.strip_http_handshake(data)
        self.assertTrue(done)
        self.assertEqual(stripped, b"body")
        payload = b"\x81\x02hi"
        self.assertEqual(ws.strip_http_handshake(payload), (payload, False))

    def test_looks_like_frame(self):
        self.assertTrue(ws.looks_like_frame(b"\x81\x02hi"))
        self.assertFalse(ws.looks_like_frame(b""))


if __name__ == "__main__":
    unittest.main()
