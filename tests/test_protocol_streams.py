"""Tests for the deep protocol parsers and TCP stream reassembly."""
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from fnet.config import Config
from fnet.features import protocols
from fnet.features.registry import FeatureContext
from fnet.logger import Logger
from fnet.utils import mongodb
from fnet.utils import postgres
from fnet.utils import redis
from fnet.utils import stream


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def bson_document(values: dict) -> bytes:
    """Minimal BSON encoder used by the MongoDB tests."""
    body = bytearray()
    for key, value in values.items():
        name = key.encode() + b"\x00"
        if isinstance(value, bool):
            body += b"\x08" + name + bytes([1 if value else 0])
        elif isinstance(value, int):
            body += b"\x10" + name + struct.pack("<i", value)
        elif isinstance(value, str):
            raw = value.encode() + b"\x00"
            body += b"\x02" + name + struct.pack("<i", len(raw)) + raw
        elif isinstance(value, dict):
            body += b"\x03" + name + bson_document(value)
        elif isinstance(value, (list, tuple)):
            body += b"\x04" + name + bson_document(
                {str(index): item for index, item in enumerate(value)})
        elif isinstance(value, mongodb.BinaryValue):
            body += (b"\x05" + name + struct.pack("<i", len(value.data))
                     + bytes([value.subtype]) + value.data)
        elif isinstance(value, bytes):
            body += b"\x05" + name + struct.pack("<i", len(value)) + b"\x00" + value
        elif isinstance(value, mongodb.ObjectId):
            body += b"\x07" + name + bytes.fromhex(value.hex)
        elif value is None:
            body += b"\x0A" + name
        else:
            raise TypeError(f"unsupported test BSON value: {type(value)}")
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + bytes(body)


def mongo_message(opcode: int, body: bytes, request_id: int = 1) -> bytes:
    return (struct.pack("<iiii", 16 + len(body), request_id, 0, opcode)
            + body)


def mongo_msg(documents: list[dict], sequences: list[tuple[str, list[dict]]] = (),
              flags: int = 0) -> bytes:
    body = struct.pack("<I", flags)
    for document in documents:
        body += b"\x00" + bson_document(document)
    for identifier, docs in sequences:
        payload = b"".join(bson_document(doc) for doc in docs)
        section = identifier.encode() + b"\x00" + payload
        body += b"\x01" + struct.pack("<i", len(section) + 4) + section
    return mongo_message(2013, body)


def pg_message(kind: bytes, body: bytes) -> bytes:
    return kind + struct.pack(">i", len(body) + 4) + body


def pg_startup(params: dict, code: int = 196608) -> bytes:
    payload = struct.pack(">i", code)
    for key, value in params.items():
        payload += key.encode() + b"\x00" + str(value).encode() + b"\x00"
    payload += b"\x00"
    return struct.pack(">i", len(payload) + 4) + payload


class _FakeTshark:
    """Return canned rows based on the display filter the handler uses."""

    def __init__(self, stream_rows=None, detect_rows=None):
        self.stream_rows = stream_rows or []
        self.detect_rows = detect_rows or []
        self.calls = []

    def fields(self, pcap, fields, display_filter="", extra=None, cancel=None):
        self.calls.append((display_filter, list(fields), extra))
        if display_filter == "tcp.len > 0":
            return self.detect_rows
        if "tcp.port ==" in display_filter or "tcp.stream ==" in display_filter:
            return self.stream_rows
        return []


def make_ctx(tmp: Path, fake) -> FeatureContext:
    return FeatureContext(
        config=Config(tmp / "config.ini"),
        logger=Logger(tmp / "fnet.log"),
        tshark=fake,
        pcap=str(tmp / "x.pcap"),
        output_dir=tmp / "out",
    )


# ---------------------------------------------------------------------------
# stream reassembly
# ---------------------------------------------------------------------------
class StreamReassemblyTest(unittest.TestCase):
    def test_out_of_order_retransmit_and_gap(self):
        rows = [
            ["3", "0", "10.0.0.1", "1234", "10.0.0.2", "80", "1006",
             b"bb".hex()],
            ["1", "0", "10.0.0.1", "1234", "10.0.0.2", "80", "1000",
             b"aaaa".hex()],
            ["2", "0", "10.0.0.1", "1234", "10.0.0.2", "80", "1004",
             b"cc".hex()],
            ["4", "0", "10.0.0.1", "1234", "10.0.0.2", "80", "1006",
             b"bb".hex()],
        ]
        streams = stream.reassemble_rows(rows)
        self.assertEqual(len(streams), 1)
        item = streams[0]
        self.assertEqual(item.data, b"aaaaccbb")
        self.assertEqual(item.retransmits, 1)
        self.assertEqual(item.gaps, 0)
        self.assertEqual(item.frame_at(0), "1")
        self.assertEqual(item.frame_at(6), "3")

    def test_missing_sequence_falls_back_to_capture_order(self):
        rows = [
            ["1", "0", "a", "1", "b", "2", "", b"one".hex()],
            ["2", "0", "a", "1", "b", "2", "", b"two".hex()],
        ]
        item = stream.reassemble_rows(rows)[0]
        self.assertEqual(item.data, b"onetwo")
        self.assertEqual([span[2] for span in item.spans()], ["1", "2"])

    def test_directions_are_separate(self):
        rows = [
            ["1", "0", "a", "1", "b", "2", "0", b"hi".hex()],
            ["2", "0", "b", "2", "a", "1", "0", b"yo".hex()],
        ]
        items = stream.reassemble_rows(rows)
        self.assertEqual(len(items), 2)
        self.assertEqual({item.data for item in items}, {b"hi", b"yo"})

    def test_gap_is_counted(self):
        rows = [
            ["1", "0", "a", "1", "b", "2", "1000", b"aa".hex()],
            ["2", "0", "a", "1", "b", "2", "1006", b"bb".hex()],
        ]
        item = stream.reassemble_rows(rows)[0]
        self.assertEqual(item.gaps, 1)
        self.assertEqual(item.data, b"aabb")


# ---------------------------------------------------------------------------
# Redis
# ---------------------------------------------------------------------------
class RedisProtocolTest(unittest.TestCase):
    def test_resp2_command_and_auth(self):
        data = (b"*2\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n"
                b"*3\r\n$3\r\nSET\r\n$4\r\nflag\r\n$12\r\nflag{redis3}\r\n")
        messages = redis.parse_messages(data)
        self.assertEqual([item.args for item in messages],
                         [["AUTH", "admin"], ["SET", "flag", "flag{redis3}"]])
        events = redis.auth_events(messages)
        self.assertEqual(events[0]["secret"], "admin")

    def test_resp3_map_push_and_hello_auth(self):
        hello = (b"*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n"
                 b"$6\r\nsecret\r\n")
        messages = redis.parse_messages(hello)
        self.assertEqual(redis.auth_events(messages)[0]["account"], "admin")
        mapping = redis.parse_messages(b"%2\r\n$1\r\na\r\n$1\r\nb\r\n$1\r\nc\r\n:1\r\n")
        self.assertEqual(mapping[0].value, {"a": "b", "c": 1})
        push = redis.parse_messages(b">3\r\n$7\r\nmessage\r\n$4\r\nnews\r\n$2\r\nhi\r\n")
        self.assertEqual(push[0].kind, "push")
        self.assertEqual(redis.pubsub_events(push)[0]["payload"], "hi")

    def test_cluster_redirection(self):
        messages = redis.parse_messages(b"-MOVED 3999 10.0.0.9:6381\r\n")
        redirect = redis.cluster_redirects(messages)[0]
        self.assertEqual(redirect["kind"], "MOVED")
        self.assertEqual(redirect["slot"], 3999)
        self.assertEqual(redirect["port"], "6381")

    def test_eval_script_keys_and_args(self):
        script = b"return redis.call('get', KEYS[1])"
        data = (b"*5\r\n$4\r\nEVAL\r\n$%d\r\n" % len(script) + script
                + b"\r\n$1\r\n1\r\n$6\r\nsecret\r\n$5\r\nhello\r\n")
        item = redis.eval_scripts(redis.parse_messages(data))[0]
        self.assertEqual(item["numkeys"], 1)
        self.assertEqual(item["keys"], ["secret"])
        self.assertEqual(item["args"], ["hello"])

    def test_eval_base64_script_is_unwrapped(self):
        import base64
        script = base64.b64encode(b"return 'flag{lua}'")
        data = b"*4\r\n$4\r\nEVAL\r\n$%d\r\n" % len(script) + script + \
            b"\r\n$1\r\n0\r\n$0\r\n\r\n"
        item = redis.eval_scripts(redis.parse_messages(data))[0]
        self.assertEqual(item["encoding"], "base64")
        self.assertEqual(item["script"], "return 'flag{lua}'")

    def test_acl_and_requirepass(self):
        data = (b"*6\r\n$3\r\nACL\r\n$7\r\nSETUSER\r\n$5\r\nalice\r\n"
                b"$2\r\non\r\n$5\r\n>p@ss\r\n$6\r\n~flag*\r\n"
                b"*4\r\n$6\r\nCONFIG\r\n$3\r\nSET\r\n$11\r\nrequirepass\r\n"
                b"$6\r\nhunter\r\n")
        messages = redis.parse_messages(data)
        change = redis.acl_changes(messages)[0]
        self.assertEqual(change["user"], "alice")
        self.assertIn(">p@ss", change["rules"])
        self.assertEqual(redis.auth_events(messages)[0]["secret"], "hunter")

    def test_sensitive_reads(self):
        data = b"*2\r\n$3\r\nGET\r\n$8\r\npassword\r\n"
        reads = redis.sensitive_reads(redis.parse_messages(data))
        self.assertEqual(reads[0]["key"], "password")

    def test_truncated_tail_is_ignored(self):
        data = b"*1\r\n$4\r\nPING\r\n*2\r\n$3\r\nGET\r\n$5\r\nab"
        messages = redis.parse_messages(data)
        self.assertEqual(messages[0].args, ["PING"])
        self.assertEqual(len(messages), 1)


# ---------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------
class PostgresProtocolTest(unittest.TestCase):
    def test_startup_ssl_and_cancel(self):
        startup = pg_startup({"user": "alice", "database": "app",
                              "application_name": "psql"})
        messages = postgres.parse_stream(startup, direction="frontend")
        self.assertEqual(messages[0].name, "StartupMessage")
        self.assertEqual(messages[0].fields["params"]["user"], "alice")
        ssl = postgres.parse_stream(
            struct.pack(">ii", 8, postgres.SSL_REQUEST), direction="frontend")
        self.assertEqual(ssl[0].name, "SSLRequest")
        cancel = postgres.parse_stream(
            struct.pack(">iiii", 16, postgres.CANCEL_REQUEST, 42, 7),
            direction="frontend")
        self.assertEqual(cancel[0].fields["pid"], 42)

    def test_extended_query_binary_parameters(self):
        parse = pg_message(b"P", b"\x00SELECT * FROM users WHERE id=$1\x00"
                           + struct.pack(">h", 1) + struct.pack(">i", 23))
        bind = pg_message(b"B", b"\x00\x00"
                          + struct.pack(">h", 1) + struct.pack(">h", 1)
                          + struct.pack(">h", 1) + struct.pack(">i", 4)
                          + struct.pack(">i", 1337) + struct.pack(">h", 1)
                          + struct.pack(">h", 0))
        execute = pg_message(b"E", b"\x00" + struct.pack(">i", 0))
        messages = postgres.parse_stream(parse + bind + execute,
                                         direction="frontend")
        self.assertEqual([item.name for item in messages],
                         ["Parse", "Bind", "Execute"])
        query = postgres.queries(messages)[0]
        self.assertEqual(query["query"], "SELECT * FROM users WHERE id=$1")
        self.assertEqual(query["params"][0]["type"], "int4")
        self.assertEqual(query["params"][0]["value"], "1337")
        self.assertEqual(query["params"][0]["format"], "binary")

    def test_auth_and_cleartext_password(self):
        auth = pg_message(b"R", struct.pack(">i", 3))
        password = pg_message(b"p", b"hunter2\x00")
        md5 = pg_message(b"R", struct.pack(">i", 5) + b"salt")
        sasl = pg_message(b"R", struct.pack(">i", 10)
                          + b"SCRAM-SHA-256\x00\x00")
        events = postgres.auth_events(
            postgres.parse_stream(auth + md5 + sasl, direction="backend")
            + postgres.parse_stream(password, direction="frontend"))
        kinds = [event.get("request") or "password" for event in events]
        self.assertEqual(kinds, ["cleartext", "md5", "sasl", "password"])
        self.assertEqual(events[-1]["password"], "hunter2")

    def test_copy_data_and_rows(self):
        copy_in = pg_message(b"G", b"\x00\x00\x01")
        data = pg_message(b"d", b"1\tflag{copy}\n")
        done = pg_message(b"c", b"")
        copies = postgres.copy_data(
            postgres.parse_stream(copy_in + data + done, direction="backend"))
        self.assertEqual(copies[0]["direction"], "in")
        self.assertEqual(copies[0]["data"], b"1\tflag{copy}\n")
        description = pg_message(
            b"T", struct.pack(">h", 1) + b"id\x00"
            + struct.pack(">ihihih", 0, 0, 23, 4, -1, 0))
        row = pg_message(b"D", struct.pack(">h", 1) + struct.pack(">i", 2)
                         + b"42")
        messages = postgres.parse_stream(description + row, direction="backend")
        self.assertEqual(messages[0].fields["columns"][0]["name"], "id")
        self.assertEqual(messages[1].fields["values"], ["42"])

    def test_truncated_stream_is_tolerated(self):
        data = pg_message(b"Q", b"SELECT 1\x00")[:-3]
        self.assertEqual(postgres.parse_stream(data), [])


# ---------------------------------------------------------------------------
# MongoDB
# ---------------------------------------------------------------------------
class MongoProtocolTest(unittest.TestCase):
    def test_bson_types_round_trip(self):
        identifier = mongodb.ObjectId("00112233445566778899aabb")
        raw = bson_document({
            "name": "alice", "age": 30, "admin": True,
            "tags": ["a", "b"], "id": identifier,
            "blob": b"\x01\x02", "nested": {"x": 1}, "none": None,
        })
        document, end = mongodb.decode_document(raw)
        self.assertEqual(end, len(raw))
        self.assertEqual(document["name"], "alice")
        self.assertEqual(document["tags"], ["a", "b"])
        self.assertEqual(str(document["id"]), identifier.hex)
        self.assertEqual(document["blob"].data, b"\x01\x02")
        self.assertIsNone(document["none"])

    def test_op_msg_sections(self):
        wire = mongo_msg(
            [{"find": "users", "filter": {"user": "alice"}, "$db": "app"}],
            sequences=[("documents", [{"user": "bob", "password": "pw"}])])
        message = mongodb.parse_stream(wire)[0]
        self.assertEqual(message.name, "OP_MSG")
        documents = mongodb.documents(message)
        self.assertEqual(documents[0]["find"], "users")
        self.assertEqual(documents[1]["user"], "bob")
        self.assertIn("password=pw", mongodb.sensitive_tokens(documents[1]))

    def test_op_query_and_reply(self):
        query = mongo_message(2004, struct.pack("<I", 0)
                              + b"app.users\x00"
                              + struct.pack("<ii", 0, 10)
                              + bson_document({"find": "users"}))
        reply = mongo_message(1, struct.pack("<I", 0)
                              + struct.pack("<q", 0)
                              + struct.pack("<ii", 0, 1)
                              + bson_document({"ok": 1}))
        messages = mongodb.parse_stream(query + reply)
        self.assertEqual(messages[0].name, "OP_QUERY")
        self.assertEqual(mongodb.namespace(messages[0]), "app.users")
        self.assertEqual(messages[1].name, "OP_REPLY")
        self.assertEqual(mongodb.documents(messages[1])[0]["ok"], 1)

    def test_scram_exchange(self):
        start = mongo_msg([{"saslStart": 1, "mechanism": "SCRAM-SHA-256",
                            "payload": mongodb.BinaryValue(
                                0, b"n,,n=alice,r=abc123")}])
        server = mongo_msg([{"saslContinue": 1,
                             "payload": mongodb.BinaryValue(
                                 0, b"r=abc123def,s=c2FsdA==,i=15000")}])
        final = mongo_msg([{"saslContinue": 1,
                            "payload": mongodb.BinaryValue(
                                0, b"c=biws,r=abc123def,p=proof")}])
        events = mongodb.scram_exchanges(
            mongodb.parse_stream(start + server + final))
        self.assertEqual(events[0]["user"], "alice")
        self.assertEqual(events[1]["kind"], "scram-server")
        self.assertEqual(events[1]["iterations"], "15000")
        self.assertEqual(events[2]["kind"], "scram-final")
        self.assertEqual(events[2]["proof"], "proof")

    def test_gridfs_chunks_are_reassembled(self):
        identifier = mongodb.ObjectId("00112233445566778899aabb")
        body = b"flag{gridfs_data}"
        files = mongo_msg([{"find": "fs.files", "$db": "app"}], sequences=[
            ("documents", [{"_id": identifier, "filename": "flag.txt",
                            "length": len(body), "chunkSize": 8,
                            "contentType": "text/plain"}])])
        chunks = mongo_msg([{"insert": "fs.chunks", "$db": "app"}],
                           sequences=[("documents", [
                               {"_id": mongodb.ObjectId(
                                   "00112233445566778899aacc"),
                                "files_id": identifier, "n": 1,
                                "data": mongodb.BinaryValue(0, body[8:])},
                               {"_id": mongodb.ObjectId(
                                   "00112233445566778899aadd"),
                                "files_id": identifier, "n": 0,
                                "data": mongodb.BinaryValue(0, body[:8])},
                           ])])
        files_out = mongodb.gridfs_files(
            mongodb.parse_stream(files + chunks))
        self.assertEqual(len(files_out), 1)
        self.assertEqual(files_out[0]["filename"], "flag.txt")
        self.assertEqual(files_out[0]["data"], body)
        self.assertTrue(files_out[0]["complete"])


# ---------------------------------------------------------------------------
# handler integration (still no tshark binary)
# ---------------------------------------------------------------------------
class HandlerIntegrationTest(unittest.TestCase):
    def setUp(self):
        protocols.clear_detection_cache()

    def test_redis_command_split_across_packets(self):
        payload = (b"*3\r\n$4\r\nAUTH\r\n$5\r\nadmin\r\n$8\r\npassword\r\n"
                   b"*3\r\n$3\r\nSET\r\n$4\r\nflag\r\n"
                   b"$15\r\nflag{redis_pkt}\r\n")
        split = 12
        rows = [
            ["2", "0", "10.0.0.5", "40000", "10.0.0.9", "6379", "1012",
             payload[split:].hex()],
            ["1", "0", "10.0.0.5", "40000", "10.0.0.9", "6379", "1000",
             payload[:split].hex()],
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = make_ctx(root, _FakeTshark(stream_rows=rows,
                                             detect_rows=rows[:1]))
            protocols.redis(ctx)
            log = "\n".join(ctx.logger.history())
            self.assertIn("Redis AUTH admin:password", log)
            self.assertIn("flag{redis_pkt}", log)
            self.assertTrue((root / "out" / "redis_commands.txt").is_file())
            kinds = [item["kind"] for item in ctx.findings]
            self.assertIn("credential", kinds)
            self.assertIn("flag", kinds)

    def test_postgres_extended_query_handler(self):
        wire = (pg_startup({"user": "alice", "database": "app"})
                + pg_message(b"P", b"\x00SELECT 1 FROM t WHERE id=$1\x00"
                             + struct.pack(">h", 1) + struct.pack(">i", 23))
                + pg_message(b"B", b"\x00\x00" + struct.pack(">h", 1)
                             + struct.pack(">h", 1) + struct.pack(">h", 1)
                             + struct.pack(">i", 4) + struct.pack(">i", 7)
                             + struct.pack(">h", 0)))
        rows = [["1", "0", "10.0.0.5", "40000", "10.0.0.9", "5432", "1000",
                 wire.hex()]]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = make_ctx(root, _FakeTshark(stream_rows=rows))
            protocols.postgres(ctx)
            log = "\n".join(ctx.logger.history())
            self.assertIn("SELECT 1 FROM t WHERE id=$1", log)
            self.assertIn("$1=7(int4,binary)", log)
            self.assertIn("PostgreSQL 用户 alice", log)
            self.assertTrue((root / "out" / "postgres_queries.txt").is_file())

    def test_mongodb_handler_writes_gridfs_file(self):
        identifier = mongodb.ObjectId("00112233445566778899aabb")
        body = b"flag{mongo_gridfs}"
        files = mongo_msg([{"find": "fs.files", "$db": "app"}], sequences=[
            ("documents", [{"_id": identifier, "filename": "m.txt",
                            "length": len(body), "chunkSize": 16}])])
        chunks = mongo_msg([{"insert": "fs.chunks", "$db": "app"}],
                           sequences=[("documents", [
                               {"_id": mongodb.ObjectId(
                                   "00112233445566778899aacc"),
                                "files_id": identifier, "n": 0,
                                "data": mongodb.BinaryValue(0, body)}])])
        login = mongo_msg([{"find": "users", "$db": "app"}], sequences=[
            ("documents", [{"user": "alice", "password": "s3cr3t"}])])
        rows = [["1", "0", "10.0.0.5", "40000", "10.0.0.9", "27017", "1000",
                 (files + chunks + login).hex()]]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ctx = make_ctx(root, _FakeTshark(stream_rows=rows))
            protocols.mongodb(ctx)
            log = "\n".join(ctx.logger.history())
            self.assertIn("alice", log)
            self.assertIn("s3cr3t", log)
            self.assertIn("GridFS", log)
            self.assertTrue((root / "out" / "gridfs_m.txt").is_file())
            self.assertEqual((root / "out" / "gridfs_m.txt").read_bytes(), body)
            kinds = [item["kind"] for item in ctx.findings]
            self.assertIn("credential", kinds)
            self.assertIn("file", kinds)


if __name__ == "__main__":
    unittest.main()
