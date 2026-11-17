"""Tests for the covert-channel reassembly helpers in fnet.utils.tunnel."""
from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from fnet.utils import tunnel
from fnet.utils.tunnel import Chunk


class DecodeChunkTest(unittest.TestCase):
    def test_base64_without_padding(self):
        label = base64.b64encode(b"flag{dns_tunnel}").decode().rstrip("=")
        self.assertIn(("base64", b"flag{dns_tunnel}"),
                      tunnel.decode_chunk(label))

    def test_urlsafe_base64(self):
        payload = b"\xfb\xffflag{dns_tunnel}"
        label = base64.urlsafe_b64encode(payload).decode().rstrip("=")
        self.assertTrue("-" in label or "_" in label, label)
        decoded = [data for _, data in tunnel.decode_chunk(label)]
        self.assertTrue(any(data.endswith(b"flag{dns_tunnel}") for data in decoded))

    def test_base32_lowercase(self):
        label = base64.b32encode(b"flag{dns_tunnel}").decode()
        label = label.lower().rstrip("=")
        self.assertIn(("base32", b"flag{dns_tunnel}"),
                      tunnel.decode_chunk(label))

    def test_hex(self):
        label = b"flag{dns_tunnel}".hex()
        self.assertIn(("hex", b"flag{dns_tunnel}"), tunnel.decode_chunk(label))

    def test_rejects_unreadable_decoding(self):
        self.assertEqual(tunnel.decode_chunk("0001"), [])
        self.assertEqual(tunnel.decode_chunk(""), [])


class ParseSequenceTest(unittest.TestCase):
    def test_forms(self):
        cases = {
            "0007": (7, None),
            "7": (7, None),
            "c007": (7, None),
            "seq7": (7, None),
            "7of20": (7, 20),
            "p7": (7, None),
            "a": (0, None),
            "z": (25, None),
            "C": (2, None),
            "seq03of09": (3, 9),
            "not-a-number": (None, None),
        }
        for label, expected in cases.items():
            with self.subTest(label=label):
                self.assertEqual(tunnel.parse_sequence(label), expected)


class ReassembleTest(unittest.TestCase):
    def test_out_of_order_with_duplicate_and_gap(self):
        chunks = [
            Chunk(index=4, total=4, data=b"}", time=4.0),
            Chunk(index=2, total=4, data=b"chunk", time=2.0),
            Chunk(index=1, total=4, data=b"flag{", time=1.0),
            Chunk(index=2, total=4, data=b"chunk", time=5.0),
        ]
        result = tunnel.reassemble(chunks)
        self.assertEqual(result["data"], b"flag{chunk}")
        self.assertEqual(result["missing"], [3])
        self.assertEqual(result["duplicates"], [2])
        self.assertFalse(result["complete"])
        self.assertEqual([c.index for c in result["ordered"]], [1, 2, 4])

    def test_complete_without_gap(self):
        chunks = [
            Chunk(index=3, total=4, data=b"ed_"),
            Chunk(index=1, total=4, data=b"flag{chunk"),
            Chunk(index=4, total=4, data=b"ok}"),
            Chunk(index=2, total=4, data=b"ed_"),
        ]
        result = tunnel.reassemble(chunks)
        self.assertEqual(result["data"], b"flag{chunked_ed_ok}")
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["duplicates"], [])
        self.assertTrue(result["complete"])

    def test_unindexed_keeps_encounter_order(self):
        chunks = [Chunk(data=b"ab"), Chunk(data=b"cd")]
        result = tunnel.reassemble(chunks)
        self.assertEqual(result["data"], b"abcd")
        self.assertTrue(result["complete"])


class GroupSessionsTest(unittest.TestCase):
    def test_dns_domains_are_separate(self):
        entries = [
            ("0001.abc", "0001.abc.evil.com"),
            ("0002.def", "0002.def.evil.com"),
            ("0001.ghi", "0001.ghi.other.com"),
        ]
        groups = tunnel.group_sessions(entries)
        self.assertEqual(set(groups), {"evil.com", "other.com"})
        self.assertEqual(len(groups["evil.com"]), 2)
        self.assertEqual(len(groups["other.com"]), 1)

    def test_icmp_groups_by_triple(self):
        entries = [
            ("10.0.0.1", "10.0.0.2", "7"),
            ("10.0.0.1", "10.0.0.2", "7"),
            ("10.0.0.1", "10.0.0.3", "7"),
        ]
        groups = tunnel.group_sessions(entries)
        self.assertEqual(set(groups), {"10.0.0.1|10.0.0.2|7",
                                       "10.0.0.1|10.0.0.3|7"})
        self.assertEqual(len(groups["10.0.0.1|10.0.0.2|7"]), 2)


class AnalyseDnsTest(unittest.TestCase):
    def test_chunked_flag_per_domain(self):
        parts = [b"flag{c", b"hunked_", b"dns}"]
        rows = []
        for number, part in enumerate(parts, 1):
            label = base64.b64encode(part).decode().rstrip("=")
            rows.append([str(number), f"{number:04d}.{label}.evil.com",
                         str(number)])
        hello = base64.b64encode(b"hello").decode().rstrip("=")
        rows.append(["9", f"0001.{hello}.other.com", "9"])

        result = tunnel.analyse_dns(rows)
        self.assertEqual(set(result["sessions"]), {"evil.com", "other.com"})
        evil = [entry for entry in result["decoded"]
                if entry["session"] == "evil.com"][0]
        self.assertIn("flag{chunked_dns}", evil["text"])
        self.assertEqual(evil["chunks"], 3)
        self.assertTrue(evil["complete"])
        combined = "".join(entry["text"] for entry in result["decoded"])
        self.assertIn("flag{chunked_dns}", combined)
        self.assertIn("flag{chunked_dns}", result["flags"])
        self.assertIn("long_labels", result)
        self.assertGreaterEqual(result["suspicious"], 1)


class AnalyseIcmpTest(unittest.TestCase):
    def test_payload_chunks_carry_flag(self):
        parts = [b"flag{icmp", b"_tunnel", b"}"]
        rows = [[str(number), "10.0.0.1", "10.0.0.2", "8", str(number),
                 part.hex()] for number, part in enumerate(parts, 1)]
        result = tunnel.analyse_icmp(rows)
        self.assertTrue(any("flag{icmp_tunnel}" in entry["text"]
                            for entry in result["decoded"]))
        self.assertIn("flag{icmp_tunnel}", result["flags"])
        self.assertIn("flag{icmp_tunnel}", result["text"])


class TimelineTest(unittest.TestCase):
    def test_bucket_totals(self):
        chunks = [Chunk(index=i, data=b"x" * (i + 1), frame=str(i),
                        time=float(i)) for i in range(5)]
        buckets = tunnel.timeline(chunks, buckets=4)
        self.assertEqual(len(buckets), 4)
        self.assertEqual(sum(bucket["frames"] for bucket in buckets), 5)
        self.assertEqual(sum(bucket["bytes"] for bucket in buckets), 15)

    def test_empty(self):
        self.assertEqual(tunnel.timeline([]), [])


class WriteDecodedTest(unittest.TestCase):
    def test_writes_file_with_hash(self):
        data = b"flag{written}"
        entries = [{"session": "evil.com", "data": data, "text": "x"}]
        with tempfile.TemporaryDirectory() as tmp:
            written = tunnel.write_decoded(entries, tmp)
            self.assertEqual(len(written), 1)
            record = written[0]
            self.assertEqual(record["name"], "tunnel_evil.com.bin")
            path = Path(record["path"])
            self.assertTrue(path.is_file())
            self.assertEqual(path.read_bytes(), data)
            self.assertEqual(record["size"], len(data))
            self.assertEqual(record["sha256"], hashlib.sha256(data).hexdigest())

    def test_bad_entries_do_not_raise(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(tunnel.write_decoded(
                [None, {"session": "empty", "data": b""}], tmp), [])


class FindFlagsTest(unittest.TestCase):
    def test_bytes_and_noise(self):
        self.assertEqual(tunnel.find_flags(b"\x00flag{abc}\x00"),
                         ["flag{abc}"])
        self.assertEqual(tunnel.find_flags("notaflag{show}"), [])


if __name__ == "__main__":
    unittest.main()
