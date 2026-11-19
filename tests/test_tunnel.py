"""Tests for the covert-channel reassembly helpers in fnet.utils.tunnel."""
from __future__ import annotations

import base64
import hashlib
import random
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


class EchoIdTunnelTest(unittest.TestCase):
    """seq 恒为 "0" 的 ICMP echo 隧道：分片不得被去重丢弃。"""

    @staticmethod
    def _cipher(length: int = 7968) -> bytes:
        rng = random.Random(20261119)
        return bytes(rng.randrange(256) for _ in range(length))

    def _rows(self, cipher: bytes, count: int = 124):
        blob = base64.b64encode(cipher).decode().rstrip("=")
        # 精确切成 count 片，每片长度落在 48..122（与真实样本一致）。
        base, remainder = divmod(len(blob), count)
        assert 48 <= base <= 122 and base + (1 if remainder else 0) <= 122
        parts: list[str] = []
        offset = 0
        for i in range(count):
            size = base + (1 if i < remainder else 0)
            parts.append(blob[offset:offset + size])
            offset += size
        assert offset == len(blob)
        return [[str(number), "192.168.3.73", "54.199.175.227", "8", "0",
                 part.encode("latin-1").hex()]
                for number, part in enumerate(parts, 1)], parts

    def test_reassemble_keeps_all_same_index_chunks(self):
        cipher = self._cipher(256)
        blob = base64.b64encode(cipher).decode().rstrip("=")
        chunks = [Chunk(index=0, data=part.encode("latin-1"), frame=str(i),
                        time=float(i))
                  for i, part in enumerate(
                      [blob[i:i + 60] for i in range(0, len(blob), 60)])]
        result = tunnel.reassemble(chunks)
        self.assertEqual(result["index_mode"], "echo_id")
        self.assertEqual(len(result["ordered"]), len(chunks))
        self.assertEqual(result["missing"], [])
        self.assertEqual(result["duplicates"], [])
        self.assertTrue(result["complete"])
        self.assertEqual(result["data"].decode("latin-1"), blob)

    def test_seq_zero_session_not_dropped_and_encrypted(self):
        cipher = self._cipher()
        rows, parts = self._rows(cipher)
        self.assertEqual(len(rows), 124)
        self.assertEqual(sum(len(part) for part in parts), 10624)
        result = tunnel.analyse_icmp(rows)
        self.assertEqual(len(result["decoded"]), 1)
        entry = result["decoded"][0]
        self.assertEqual(entry["session"], "192.168.3.73>54.199.175.227")
        self.assertEqual(entry["chunks"], 124)
        self.assertTrue(entry["complete"])
        self.assertEqual(entry["missing"], [])
        self.assertEqual(entry["duplicates"], [])
        self.assertEqual(entry["index_mode"], "echo_id")
        self.assertEqual(entry["payload_bytes"], 10624)
        self.assertEqual(entry["frame_range"], "1-124")
        # 整段 base64 二次解码成功，得到完整密文并判定为加密数据。
        self.assertEqual(entry["data"], cipher)
        self.assertTrue(entry["encrypted"])
        profile = entry["cipher"]
        self.assertEqual(profile["length"], 7968)
        self.assertTrue(profile["aligned_16"])
        self.assertGreaterEqual(profile["entropy"], 7.5)
        self.assertLess(profile["printable_ratio"], 0.5)
        self.assertEqual(entry["encodings"], ["raw"])
        self.assertEqual(entry["text"], "")

    def test_seq_zero_whole_base64_readable(self):
        plain = b"flag{second_pass_works} " * 40
        blob = base64.b64encode(plain).decode().rstrip("=")
        rows = [[str(number), "10.0.0.1", "10.0.0.2", "8", "0",
                 blob[i:i + 70].encode("latin-1").hex()]
                for number, i in enumerate(range(0, len(blob), 70), 1)]
        result = tunnel.analyse_icmp(rows)
        entry = result["decoded"][0]
        self.assertIn("flag{second_pass_works}", entry["text"])
        self.assertIn("flag{second_pass_works}", result["flags"])
        self.assertFalse(entry["encrypted"])

    def test_fragmented_tunnel_still_dedupes(self):
        # index 0..N 含重复与空洞：现有分片隧道行为不变。
        chunks = [
            Chunk(index=0, data=b"flag{"),
            Chunk(index=1, data=b"frag"),
            Chunk(index=1, data=b"frag"),
            Chunk(index=3, data=b"ment"),
        ]
        result = tunnel.reassemble(chunks)
        self.assertEqual(result["index_mode"], "fragmented")
        self.assertEqual(result["data"], b"flag{fragment")
        self.assertEqual(result["missing"], [2])
        self.assertEqual(result["duplicates"], [1])
        self.assertFalse(result["complete"])


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


class LengthChannelTest(unittest.TestCase):
    """ICMP 载荷长度隐写：长度即 ASCII（fetus_pcap.pcap 考点）。"""

    SHADOW = ("::\\nmongodb:!:17843:0:99999:7:::\\n"
              "ubuntu:$6$LhHRomTE$M7C4n84UcFLAG{xx2b8a_6mm64c_fsociety}::")

    def _lengths(self) -> list[int]:
        encoded = base64.b64encode(self.SHADOW.encode()).decode()
        return [ord(char) for char in encoded]

    def test_lengths_decode_to_shadow_and_embedded_flag(self):
        result = tunnel.length_channel(self._lengths())
        self.assertTrue(result["channel"])
        self.assertEqual(result["printable_ratio"], 1.0)
        self.assertIn("ubuntu", result["decoded_text"])
        self.assertEqual(result["flags"],
                         ["FLAG{xx2b8a_6mm64c_fsociety}"])
        self.assertEqual([item["encoding"] for item in result["decodings"]],
                         ["base64"])

    def test_reversed_lengths_are_detected(self):
        result = tunnel.length_channel(list(reversed(self._lengths())))
        self.assertTrue(result["channel"])
        self.assertEqual(result["order"], "reversed")
        self.assertIn("flag{xx2b8a_6mm64c_fsociety}",
                      "".join(result["flags"]).lower())

    def test_constant_ping_lengths_are_not_a_channel(self):
        self.assertFalse(tunnel.length_channel([56] * 40)["channel"])

    def test_short_sequence_is_not_a_channel(self):
        self.assertFalse(tunnel.length_channel([65, 66, 67])["channel"])

    def test_loose_flag_matches_embedded_token(self):
        self.assertEqual(tunnel.find_flags("...UcFLAG{abc}::"), [])
        self.assertEqual(tunnel.find_flags_loose("...UcFLAG{abc}::"),
                         ["FLAG{abc}"])


if __name__ == "__main__":
    unittest.main()
