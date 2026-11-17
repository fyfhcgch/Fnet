"""Generate small synthetic captures used by the smoke tests.

Run with ``python scripts/make_samples.py``; the files are written to
``tests/data`` and are safe to regenerate at any time.

Only ``scapy`` is required (``pip install scapy``).  The captures intentionally
contain well known markers (``flag{...}``) so the tests can assert that the
analysers actually find something.
"""
from __future__ import annotations

import base64
import hashlib
import struct
import sys
import zlib
from pathlib import Path

from scapy.all import (  # type: ignore[import-not-found]
    ARP, DNS, DNSQR, Dot11, Dot11Beacon, Dot11Elt, Ether, ICMP, IP, LLC,
    RadioTap, Raw, SNAP, TCP, UDP, wrpcap,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fnet.utils.crypto import aes_encrypt_block, aes_gcm_encrypt  # noqa: E402

OUT = Path(__file__).resolve().parents[1] / "tests" / "data"


def tcp_stream(src: str, sport: int, dst: str, dport: int,
               client_payloads: list[bytes],
               server_payloads: list[bytes]) -> list:
    """Very small TCP session with correct sequence numbers."""
    packets = []
    cs, ss = 1000, 5000
    packets.append(Ether() / IP(src=src, dst=dst) /
                   TCP(sport=sport, dport=dport, flags="S", seq=cs))
    packets.append(Ether() / IP(src=dst, dst=src) /
                   TCP(sport=dport, dport=sport, flags="SA", seq=ss, ack=cs + 1))
    packets.append(Ether() / IP(src=src, dst=dst) /
                   TCP(sport=sport, dport=dport, flags="A", seq=cs + 1, ack=ss + 1))
    seq_c, seq_s = cs + 1, ss + 1
    for index in range(max(len(client_payloads), len(server_payloads))):
        if index < len(client_payloads):
            payload = client_payloads[index]
            packets.append(Ether() / IP(src=src, dst=dst) /
                           TCP(sport=sport, dport=dport, flags="PA", seq=seq_c,
                               ack=seq_s) / Raw(payload))
            seq_c += len(payload)
        if index < len(server_payloads):
            payload = server_payloads[index]
            packets.append(Ether() / IP(src=dst, dst=src) /
                           TCP(sport=dport, dport=sport, flags="PA", seq=seq_s,
                               ack=seq_c) / Raw(payload))
            seq_s += len(payload)
    packets.append(Ether() / IP(src=src, dst=dst) /
                   TCP(sport=sport, dport=dport, flags="FA", seq=seq_c, ack=seq_s))
    packets.append(Ether() / IP(src=dst, dst=src) /
                   TCP(sport=dport, dport=sport, flags="FA", seq=seq_s, ack=seq_c + 1))
    packets.append(Ether() / IP(src=src, dst=dst) /
                   TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1,
                       ack=seq_s + 1))
    return packets


def ntlmssp_type1() -> bytes:
    return (b"NTLMSSP\x00" + struct.pack("<I", 1)
            + struct.pack("<I", 0x00088207) + b"\x00" * 16)


def ntlmssp_type2(challenge: bytes = b"\x11\x22\x33\x44\x55\x66\x77\x88") -> bytes:
    target = "WORKGROUP".encode("utf-16le")
    header = b"NTLMSSP\x00" + struct.pack("<I", 2)
    payload_offset = 40
    fields = struct.pack("<HHI", len(target), len(target), payload_offset)
    return (header + fields + struct.pack("<I", 0x00008205) + challenge
            + b"\x00" * 8 + target)


def ntlmssp_type3(user: str = "Administrator", domain: str = "WORKGROUP",
                  workstation: str = "KALI") -> bytes:
    def utf16(value: str) -> bytes:
        return value.encode("utf-16le")

    lm = b"\x00" * 24
    # 24 byte NTLMv1 response (proof + 16 byte blob) so both formats parse.
    nt = bytes.fromhex("aabbccddeeff00112233445566778899") + b"\x00" * 8
    domain_b, user_b, ws_b = utf16(domain), utf16(user), utf16(workstation)
    session = b"\x00" * 16
    offset = 64
    parts = []
    descriptor = b""
    for value in (lm, nt, domain_b, user_b, ws_b, session):
        descriptor += struct.pack("<HHI", len(value), len(value), offset)
        offset += len(value)
        parts.append(value)
    return (b"NTLMSSP\x00" + struct.pack("<I", 3) + descriptor
            + struct.pack("<I", 0x00008205) + b"".join(parts))


def http_capture() -> list:
    packets = []
    # Basic auth + a flag in the response.
    request = (b"GET /admin/ HTTP/1.1\r\n"
               b"Host: ctf.local\r\n"
               b"Authorization: Basic " + base64.b64encode(b"admin:P@ssw0rd") + b"\r\n"
               b"Cookie: theme=ZGVhZGJlZWY=\r\n\r\n")
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                b"Set-Cookie: session=abc\r\n\r\n"
                b"<html>welcome admin flag{http_basic_auth}</html>")
    packets += tcp_stream("10.0.0.5", 40001, "10.0.0.80", 80,
                          [request], [response])
    # NTLM protected endpoint (three requests over one connection).
    type1 = base64.b64encode(ntlmssp_type1())
    type3 = base64.b64encode(ntlmssp_type3())
    challenge = base64.b64encode(ntlmssp_type2())
    r1 = (b"GET /ntlm HTTP/1.1\r\nHost: ctf.local\r\n"
          b"Connection: keep-alive\r\n\r\n")
    r2 = (b"GET /ntlm HTTP/1.1\r\nHost: ctf.local\r\nAuthorization: NTLM "
          + type1 + b"\r\nConnection: keep-alive\r\n\r\n")
    r3 = (b"GET /ntlm HTTP/1.1\r\nHost: ctf.local\r\nAuthorization: NTLM "
          + type3 + b"\r\nConnection: keep-alive\r\n\r\n")
    s1 = (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM\r\n"
          b"Content-Length: 0\r\nConnection: keep-alive\r\n\r\n")
    s2 = (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: NTLM "
          + challenge + b"\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n")
    s3 = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nok")
    packets += tcp_stream("10.0.0.5", 40002, "10.0.0.80", 80,
                          [r1, r2, r3], [s1, s2, s3])
    # A plain (base64 wrapped) webshell command and its response.
    payload = (b"@ini_set('display_errors','0');@set_time_limit(0);"
               b"$s='id';system($s);echo 'flag{webshell_plain}';")
    body = b"pass=" + base64.b64encode(payload)
    wreq = (b"POST /shell.php HTTP/1.1\r\nHost: ctf.local\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body)
    wresp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
             b"Content-Length: 33\r\n\r\n"
             b"uid=33(www-data)\nflag{webshell_plain}\n")
    packets += tcp_stream("10.0.0.5", 40006, "10.0.0.80", 80,
                          [wreq], [wresp])
    # Shiro rememberMe using AES-GCM and the well-known default key.
    shiro_key = base64.b64decode("kPH+bIxk5D2deZiIxcaaaA==")
    shiro_iv = b"0123456789abcdef"
    shiro_plain = b"flag{shiro_gcm_decrypted}"
    shiro_blob = shiro_iv + aes_gcm_encrypt(shiro_plain, shiro_key, shiro_iv)
    shiro_cookie = base64.b64encode(shiro_blob)
    sreq = (b"GET /shiro/ HTTP/1.1\r\nHost: ctf.local\r\nCookie: rememberMe="
            + shiro_cookie + b"\r\nConnection: keep-alive\r\n\r\n")
    sresp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
             b"Content-Length: 2\r\n\r\nok")
    packets += tcp_stream("10.0.0.5", 40007, "10.0.0.80", 80,
                          [sreq], [sresp])
    return packets


def ftp_smtp_telnet() -> list:
    packets = []
    packets += tcp_stream(
        "10.0.0.6", 40003, "10.0.0.21", 21,
        [b"USER alice\r\n", b"PASS s3cr3t\r\n", b"RETR flag.txt\r\n"],
        [b"331 need password\r\n", b"230 logged in\r\n",
         b"150 opening data\r\nflag{ftp_download}\r\n226 done\r\n"])
    packets += tcp_stream(
        "10.0.0.7", 40004, "10.0.0.25", 25,
        [b"EHLO test\r\n", b"MAIL FROM:<a@b.c>\r\n", b"RCPT TO:<d@e.f>\r\n",
         b"DATA\r\n"],
        [b"250 ok\r\n", b"250 ok\r\n", b"250 ok\r\n", b"354 send data\r\n"])
    # Telnet login and shell output.
    packets += tcp_stream(
        "10.0.0.8", 40005, "10.0.0.9", 23,
        [b"root\r\n", b"toor\r\n", b"cat /flag\r\n"],
        [b"login: ", b"Password: ", b"flag{telnet_shell}\r\n"])
    return packets


def dns_arp_icmp() -> list:
    packets = []
    # DNS query with a long label (tunnel indicator) and a normal one.
    packets.append(Ether() / IP(src="10.0.0.5", dst="8.8.8.8") /
                   UDP(sport=5353, dport=53) /
                   DNS(id=1, rd=1,
                       qd=DNSQR(qname="ZmxhZ3tkbnNfdHVubmVsfQ.example.com")))
    packets.append(Ether() / IP(src="8.8.8.8", dst="10.0.0.5") /
                   UDP(sport=53, dport=5353) /
                   DNS(id=1, qr=1, qd=DNSQR(qname="ZmxhZ3tkbnNfdHVubmVsfQ.example.com")))
    packets.append(Ether() / IP(src="10.0.0.5", dst="8.8.8.8") /
                   UDP(sport=5354, dport=53) /
                   DNS(id=2, rd=1, qd=DNSQR(qname="ctf.local")))
    # ARP: two MACs claiming the gateway address + a gratuitous ARP.
    packets.append(Ether(src="aa:aa:aa:aa:aa:01", dst="ff:ff:ff:ff:ff:ff") /
                   ARP(op=2, psrc="10.0.0.1", hwsrc="aa:aa:aa:aa:aa:01",
                       pdst="10.0.0.5", hwdst="ff:ff:ff:ff:ff:ff"))
    packets.append(Ether(src="bb:bb:bb:bb:bb:02", dst="ff:ff:ff:ff:ff:ff") /
                   ARP(op=2, psrc="10.0.0.1", hwsrc="bb:bb:bb:bb:bb:02",
                       pdst="10.0.0.5", hwdst="ff:ff:ff:ff:ff:ff"))
    packets.append(Ether(src="aa:aa:aa:aa:aa:01", dst="ff:ff:ff:ff:ff:ff") /
                   ARP(op=2, psrc="10.0.0.9", hwsrc="aa:aa:aa:aa:aa:01",
                       pdst="10.0.0.9", hwdst="ff:ff:ff:ff:ff:ff"))
    # ICMP with a readable covert payload.
    packets.append(Ether() / IP(src="10.0.0.5", dst="10.0.0.9") /
                   ICMP(type=8, id=1, seq=1) / Raw(b"flag{icmp_payload}"))
    packets.append(Ether() / IP(src="10.0.0.9", dst="10.0.0.5") /
                   ICMP(type=0, id=1, seq=1) / Raw(b"flag{icmp_payload}"))
    return packets


def modbus_mqtt() -> list:
    packets = []
    # Modbus/TCP: read holding registers then a write single register.
    read_req = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 0, 10)
    read_resp = struct.pack(">HHHBBB", 1, 0, 5, 1, 3, 4) + b"\x00\x2a\x00\x2b"
    write_req = struct.pack(">HHHBBHH", 2, 0, 6, 1, 6, 0, 10)
    write_resp = struct.pack(">HHHBBHH", 2, 0, 6, 1, 6, 0, 10)
    packets += tcp_stream("10.0.0.5", 40010, "10.0.0.50", 502,
                          [read_req, write_req], [read_resp, write_resp])
    # MQTT connect + publish (QoS0).
    connect = (b"\x10\x12\x00\x04MQTT\x04\x02\x00\x3c\x00\x06client")
    connack = b"\x20\x02\x00\x00"
    publish = b"\x30\x14\x00\x07sensorsflag{ow}hello mqtt"
    packets += tcp_stream("10.0.0.5", 40011, "10.0.0.60", 1883,
                          [connect, publish], [connack])
    return packets


def ws_frame(opcode: int, payload: bytes, *, fin: bool = True,
             mask: bytes | None = None, rsv1: bool = False) -> bytes:
    """Build one WebSocket frame (client frames are masked in the capture)."""
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


def websocket_capture() -> list:
    """WebSocket Upgrade + masked text/binary frames + permessage-deflate."""
    key = b"dGhlIHNhbXBsZSBub25jZQ=="
    accept = base64.b64encode(
        hashlib.sha1(key + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
    request = (b"GET /ws HTTP/1.1\r\nHost: ctf.local\r\n"
               b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
               b"Sec-WebSocket-Key: " + key + b"\r\n"
               b"Sec-WebSocket-Version: 13\r\n"
               b"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
    response = (b"HTTP/1.1 101 Switching Protocols\r\n"
                b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                b"Sec-WebSocket-Accept: " + accept + b"\r\n"
                b"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n")
    mask = b"\x11\x22\x33\x44"
    text = ws_frame(1, b"flag{ws_text}", mask=mask)
    # Fragmented binary message: first frame + continuation.
    binary = (ws_frame(2, b"bin:", fin=False, mask=mask)
              + ws_frame(0, b"flag{ws_fragment}", mask=mask))
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    compressed = compressor.compress(b"compressed flag{ws_deflate}") + compressor.flush()
    deflated = ws_frame(2, compressed, mask=mask, rsv1=True)
    ping = ws_frame(9, b"ping", mask=mask)
    welcome = ws_frame(1, b"welcome")
    packets = tcp_stream("10.0.0.5", 40020, "10.0.0.90", 80,
                         [request, text, binary, deflated, ping],
                         [response, welcome])
    return packets


def redis_nonstandard() -> list:
    """Redis RESP on port 16379 so detection must not rely on 6379."""
    auth = b"*2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n"
    set_key = b"*3\r\n$3\r\nSET\r\n$4\r\nflag\r\n$16\r\nflag{redis_move}\r\n"
    response = b"+OK\r\n"
    packets = tcp_stream("10.0.0.5", 40021, "10.0.0.70", 16379,
                         [auth, set_key], [response])
    return packets


def bson(values: dict) -> bytes:
    """Tiny BSON encoder for the MongoDB sample capture."""
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
            body += b"\x03" + name + bson(value)
        elif isinstance(value, tuple) and value and value[0] == "oid":
            body += b"\x07" + name + bytes.fromhex(value[1])
        elif isinstance(value, (list, tuple)):
            body += b"\x04" + name + bson(
                {str(index): item for index, item in enumerate(value)})
        elif isinstance(value, bytes):
            body += (b"\x05" + name + struct.pack("<i", len(value))
                     + b"\x00" + value)
        elif value is None:
            body += b"\x0A" + name
        else:
            raise TypeError(f"unsupported BSON value: {type(value)}")
    body += b"\x00"
    return struct.pack("<i", len(body) + 4) + bytes(body)


def mongo_op_msg(command: dict, documents=(), flags: int = 0) -> bytes:
    body = struct.pack("<I", flags) + b"\x00" + bson(command)
    if documents:
        payload = identifier = b"documents\x00"
        payload += b"".join(bson(document) for document in documents)
        body += b"\x01" + struct.pack("<i", len(payload) + 4) + payload
    return struct.pack("<iiii", 16 + len(body), 1, 0, 2013) + body


def pg_message(kind: bytes, body: bytes) -> bytes:
    return kind + struct.pack(">i", len(body) + 4) + body


def pg_startup(params: dict) -> bytes:
    payload = struct.pack(">i", 196608)
    for key, value in params.items():
        payload += key.encode() + b"\x00" + str(value).encode() + b"\x00"
    payload += b"\x00"
    return struct.pack(">i", len(payload) + 4) + payload


def protocol_deep() -> list:
    """Deep Redis (RESP3), PostgreSQL (extended query/COPY) and MongoDB."""
    packets = []
    # --- Redis 6379: RESP3 HELLO/AUTH, EVAL, MOVED and a Pub/Sub push.
    script = b"return redis.call('get',KEYS[1])"
    hello = (b"*5\r\n$5\r\nHELLO\r\n$1\r\n3\r\n$4\r\nAUTH\r\n"
             b"$5\r\nadmin\r\n$6\r\nsecret\r\n")
    eval_command = (b"*4\r\n$4\r\nEVAL\r\n$%d\r\n" % len(script) + script
                    + b"\r\n$1\r\n1\r\n$7\r\nflagkey\r\n")
    redis_flag = b"flag{redis_resp3}"
    push = (b">3\r\n$7\r\nmessage\r\n$4\r\nnews\r\n$%d\r\n"
            % len(redis_flag) + redis_flag + b"\r\n")
    moved = b"-MOVED 3999 10.0.0.70:6381\r\n"
    packets += tcp_stream("10.0.0.5", 40030, "10.0.0.70", 6379,
                          [hello, eval_command], [b"+OK\r\n", moved, push])
    # --- PostgreSQL: startup + Parse/Bind/Execute with a text parameter and
    # cleartext authentication.
    startup = pg_startup({"user": "alice", "database": "app",
                          "application_name": "psql"})
    parse = pg_message(b"P", b"\x00SELECT * FROM users WHERE name=$1\x00"
                       + struct.pack(">h", 1) + struct.pack(">i", 25))
    bind_value = b"alice"
    bind = pg_message(b"B", b"\x00\x00" + struct.pack(">h", 1)
                      + struct.pack(">h", 0) + struct.pack(">h", 1)
                      + struct.pack(">i", len(bind_value)) + bind_value
                      + struct.pack(">h", 0))
    execute = pg_message(b"E", b"\x00" + struct.pack(">i", 0))
    auth_ok = pg_message(b"R", struct.pack(">i", 3))
    password = pg_message(b"p", b"pg_secret\x00")
    complete = pg_message(b"C", b"SELECT 1\x00")
    ready = pg_message(b"Z", b"I")
    packets += tcp_stream("10.0.0.5", 40031, "10.0.0.80", 5432,
                          [startup, parse, bind, execute],
                          [auth_ok])
    packets += tcp_stream("10.0.0.5", 40032, "10.0.0.80", 5432,
                          [password], [complete, ready])
    # COPY FROM STDIN carrying a tab separated flag row.
    copy_startup = pg_startup({"user": "alice", "database": "app"})
    copy_in = pg_message(b"G", b"\x00\x00\x00")
    copy_data = pg_message(b"d", b"1\tflag{pg_copy}\n")
    copy_done = pg_message(b"c", b"")
    packets += tcp_stream("10.0.0.5", 40033, "10.0.0.80", 5432,
                          [copy_startup, copy_data, copy_done],
                          [copy_in, complete, ready])
    # --- MongoDB: OP_MSG query with credentials + GridFS files/chunks.
    file_id = "00112233445566778899aabb"
    grid_flag = b"flag{mongo_gridfs}"
    find_users = mongo_op_msg(
        {"find": "users", "$db": "app"},
        [{"user": "alice", "password": "mongo_pass"}])
    grid_files = mongo_op_msg(
        {"find": "fs.files", "$db": "app"},
        [{"_id": ("oid", file_id), "filename": "flag.txt",
          "length": len(grid_flag), "chunkSize": len(grid_flag),
          "contentType": "text/plain"}])
    grid_chunks = mongo_op_msg(
        {"insert": "fs.chunks", "$db": "app"},
        [{"_id": ("oid", "00112233445566778899aacc"),
          "files_id": ("oid", file_id), "n": 0, "data": grid_flag}])
    packets += tcp_stream("10.0.0.5", 40034, "10.0.0.90", 27017,
                          [find_users, grid_files, grid_chunks], [])
    return packets


def h2_int(value: int, prefix_bits: int) -> bytes:
    """HPACK integer encoding (RFC 7541 section 5.1)."""
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([value])
    out = bytearray([limit])
    value -= limit
    while value >= 128:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def hpack_literal(name_index: int, value: str) -> bytes:
    """Literal header field without indexing, indexed name."""
    raw = value.encode()
    prefix = h2_int(name_index, 4)
    return bytes([0x00 | prefix[0]]) + prefix[1:] + h2_int(len(raw), 7) + raw


def hpack_new(name: str, value: str) -> bytes:
    """Literal header field without indexing, new name."""
    name_b, value_b = name.encode(), value.encode()
    return b"\x00" + h2_int(len(name_b), 7) + name_b + h2_int(len(value_b), 7) + value_b


def h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    return (len(payload).to_bytes(3, "big") + bytes([frame_type, flags])
            + struct.pack(">I", stream_id & 0x7FFFFFFF) + payload)


def http2_deep() -> list:
    """HTTP/2 with HPACK requests, a gRPC stream and DATA bodies."""
    preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = h2_frame(4, 0, 0, struct.pack(">HI", 3, 100))
    request_headers = (
        b"\x82\x87"                       # :method GET, :scheme https
        + hpack_literal(4, "/flag{http2_deep}")
        + hpack_literal(1, "ctf.local")
        + hpack_new("authorization", "Basic YWRtaW46aHR0cDJwYXNz")
        + hpack_new("user-agent", "fnet-http2-test"))
    client = [preface + settings,
              h2_frame(1, 0x04, 1, request_headers),
              h2_frame(0, 0x01, 1, b"ping flag{http2_body}")]
    response_headers = (
        b"\x88"                           # :status 200
        + hpack_new("content-type", "text/html")
        + hpack_new("set-cookie", "session=http2token"))
    server = [settings + h2_frame(4, 0x01, 0, b""),
              h2_frame(1, 0x04, 1, response_headers),
              h2_frame(0, 0x01, 1, b"<html>flag{http2_response}</html>")]
    packets = tcp_stream("10.0.0.5", 40100, "10.0.0.90", 8448,
                         client, server)
    # Second connection: gRPC over HTTP/2 with a Protobuf message.
    grpc_headers = (
        b"\x82\x87"
        + hpack_literal(4, "/pkg.Greeter/SayHello")
        + hpack_literal(1, "grpc.local")
        + hpack_new("content-type", "application/grpc")
        + hpack_new("te", "trailers"))
    proto = b"\x0a\x03foo\x12\x0bflag{grpc}"  # field 1 "foo", field 2 "flag{grpc}"
    grpc_body = b"\x00" + struct.pack(">I", len(proto)) + proto
    grpc_server_headers = (
        b"\x88" + hpack_new("content-type", "application/grpc")
        + hpack_new("grpc-status", "0"))
    packets += tcp_stream(
        "10.0.0.5", 40101, "10.0.0.90", 8448,
        [preface + settings, h2_frame(1, 0x04, 1, grpc_headers),
         h2_frame(0, 0x01, 1, grpc_body)],
        [settings + h2_frame(4, 0x01, 0, b""),
         h2_frame(1, 0x04, 1, grpc_server_headers),
         h2_frame(0, 0x01, 1, b"\x00" + struct.pack(">I", 0))])
    return packets


def ber(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        header = bytes([length])
    else:
        raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + header + content


def ber_int(value: int) -> bytes:
    if value == 0:
        return ber(0x02, b"\x00")
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return ber(0x02, raw)


def ber_str(value: str, tag: int = 0x04) -> bytes:
    return ber(tag, value.encode())


def ldap_message(message_id: int, operation: bytes) -> bytes:
    return ber(0x30, ber_int(message_id) + operation)


def ldap_deep() -> list:
    """LDAP bind, search and entry attributes on the non-default port 1389."""
    bind_request = ldap_message(1, ber(
        0x60, ber_int(3) + ber_str("cn=admin,dc=ctf,dc=local")
        + ber(0x80, b"ldap_pass")))
    bind_response = ldap_message(1, ber(
        0x61, ber(0x0a, b"\x00") + ber_str("") + ber_str("")))
    filter_present = ber(0x87, b"objectClass")
    search_request = ldap_message(2, ber(
        0x63, ber_str("dc=ctf,dc=local") + ber(0x0a, b"\x02")
        + ber(0x0a, b"\x00") + ber_int(0) + ber_int(0) + ber(0x01, b"\x00")
        + filter_present
        + ber(0x30, ber_str("sAMAccountName") + ber_str("userPassword")
              + ber_str("description"))))
    attributes = b"".join(
        ber(0x30, ber_str(name) + ber(0x31, ber_str(value)))
        for name, value in (
            ("sAMAccountName", "alice"),
            ("userPassword", "P@ssw0rd"),
            ("description", "flag{ldap_entry}"),
            ("memberOf", "CN=Domain Admins,CN=Users,DC=ctf,DC=local"),
        ))
    entry = ldap_message(2, ber(
        0x64, ber_str("cn=alice,dc=ctf,dc=local") + ber(0x30, attributes)))
    done = ldap_message(2, ber(
        0x65, ber(0x0a, b"\x00") + ber_str("") + ber_str("")))
    return tcp_stream("10.0.0.5", 40110, "10.0.0.20", 1389,
                      [bind_request, search_request],
                      [bind_response, entry, done])


def smb2_header(command: int, message_id: int, *, tree_id: int = 0,
                session_id: int = 0x1122334455667788,
                flags: int = 0, status: int = 0) -> bytes:
    return (b"\xfeSMB" + struct.pack("<HH", 64, 1) + struct.pack("<I", status)
            + struct.pack("<HH", command, 32) + struct.pack("<I", flags)
            + struct.pack("<I", 0) + struct.pack("<Q", message_id)
            + struct.pack("<I", 0xFEFF) + struct.pack("<I", tree_id)
            + struct.pack("<Q", session_id) + b"\x00" * 16)


def nbss(payload: bytes) -> bytes:
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def smb2_deep() -> list:
    """SMB2 negotiate/session/tree/create/write/read with a flag file."""
    file_id = b"FILEID01FLAG0001"
    share = "\\\\FS01\\share"
    file_name = "flag.txt"
    flag = b"flag{smb2_file}"
    type1 = ntlmssp_type1()
    type2 = ntlmssp_type2()
    type3 = ntlmssp_type3("alice", "CTF", "KALI")

    neg_req = nbss(smb2_header(0, 1) + struct.pack(
        "<HHHHI", 36, 1, 1, 0, 0) + b"\x00" * 16 + b"\x00" * 8
        + struct.pack("<H", 0x0311))
    neg_resp = nbss(smb2_header(0, 1, flags=1) + struct.pack(
        "<HHHH", 65, 1, 0x0311, 0) + b"\x11" * 16
        + struct.pack("<IIII", 0x40, 1 << 20, 1 << 20, 1 << 20)
        + b"\x00" * 16 + struct.pack("<HHI", 0, 0, 0))

    def session_setup(message_id: int, blob: bytes, response: bool) -> bytes:
        body = struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0,
                           88 if blob else 0, len(blob), 0) + blob
        return nbss(smb2_header(1, message_id, flags=1 if response else 0)
                    + body)

    tree_path = share.encode("utf-16le")
    tree_req = nbss(smb2_header(3, 4) + struct.pack(
        "<HHHH", 9, 0, 72, len(tree_path)) + tree_path)
    tree_resp = nbss(smb2_header(3, 4, tree_id=1, flags=1) + struct.pack(
        "<HHIII", 16, 1, 0, 0, 0x001F01FF))
    name_b = file_name.encode("utf-16le")
    create_body = bytearray(56)
    struct.pack_into("<H", create_body, 0, 57)
    struct.pack_into("<I", create_body, 24, 0x0012019F)
    struct.pack_into("<I", create_body, 28, 0x80)
    struct.pack_into("<I", create_body, 32, 7)
    struct.pack_into("<I", create_body, 36, 2)
    struct.pack_into("<I", create_body, 40, 0x40)
    struct.pack_into("<H", create_body, 44, 120)
    struct.pack_into("<H", create_body, 46, len(name_b))
    create_req = nbss(smb2_header(5, 5, tree_id=1) + bytes(create_body) + name_b)
    create_resp_body = bytearray(88)
    struct.pack_into("<H", create_resp_body, 0, 89)
    create_resp_body[2] = 1
    struct.pack_into("<I", create_resp_body, 4, 2)
    struct.pack_into("<I", create_resp_body, 56, 0x80)
    create_resp_body[64:80] = file_id
    create_resp = nbss(smb2_header(5, 5, tree_id=1, flags=1)
                       + bytes(create_resp_body))

    write_body = bytearray(48)
    struct.pack_into("<H", write_body, 0, 49)
    struct.pack_into("<H", write_body, 2, 112)
    struct.pack_into("<I", write_body, 4, len(flag))
    struct.pack_into("<Q", write_body, 8, 0)
    write_body[16:32] = file_id
    write_req = nbss(smb2_header(9, 6, tree_id=1)
                     + bytes(write_body) + flag)
    write_resp = nbss(smb2_header(9, 6, tree_id=1, flags=1)
                      + struct.pack("<HHIIHH", 17, 0, len(flag), 0, 0, 0))

    read_body = bytearray(48)
    struct.pack_into("<H", read_body, 0, 49)
    struct.pack_into("<I", read_body, 4, 4096)
    struct.pack_into("<Q", read_body, 8, 0)
    read_body[16:32] = file_id
    read_req = nbss(smb2_header(8, 7, tree_id=1) + bytes(read_body))
    read_resp = nbss(smb2_header(8, 7, tree_id=1, flags=1)
                     + struct.pack("<HBBIIHH", 17, 80, 0, len(flag), 0, 0, 0)
                     + flag)

    client = [neg_req, session_setup(2, type1, False),
              session_setup(3, type3, False), tree_req, create_req,
              write_req, read_req]
    server = [neg_resp, session_setup(2, type2, True),
              session_setup(3, b"", True), tree_resp, create_resp,
              write_resp, read_resp]
    return tcp_stream("10.0.0.5", 40120, "10.0.0.10", 445, client, server)


def wifi_eapol() -> list:
    """WPA2 four-way handshake with PMKID plus a WPA3/SAE beacon."""
    packets = []
    ap = "aa:bb:cc:dd:ee:ff"
    sta = "11:22:33:44:55:66"
    pmkid = bytes.fromhex("00112233445566778899aabbccddeeff")
    anonce = b"\x01" * 32
    snonce = b"\x02" * 32

    def key_info(ack=0, mic=1, secure=0, install=0) -> int:
        return (2 | (2 << 3) | (ack << 7) | (mic << 8)
                | (secure << 9) | (install << 10))

    def eapol(addr1: str, addr2: str, body: bytes):
        key = b"\x02" + body
        frame = bytes([2, 3]) + struct.pack("!H", len(key)) + key
        return (RadioTap() / Dot11(type=2, subtype=0, addr1=addr1,
                                   addr2=addr2, addr3=ap)
                / LLC() / SNAP(code=0x888E) / Raw(frame))

    def key_body(info: int, nonce: bytes, mic: bytes = b"", data: bytes = b"") -> bytes:
        return (struct.pack("!HH", info, 16) + b"\x00" * 8 + nonce
                + b"\x00" * 16 + b"\x00" * 8 + b"\x00" * 8
                + (mic or b"\x00" * 16) + struct.pack("!H", len(data)) + data)

    pmkid_kde = b"\xdd\x14\x00\x0f\xac\x04" + pmkid
    m1 = eapol(sta, ap, key_body(key_info(ack=1, mic=0), anonce, data=pmkid_kde))
    m2 = eapol(ap, sta, key_body(key_info(mic=1), snonce, b"\x33" * 16))
    m3 = eapol(sta, ap, key_body(key_info(ack=1, mic=1, secure=1, install=1),
                                 anonce, b"\x44" * 16))
    m4 = eapol(ap, sta, key_body(key_info(mic=1, secure=1), snonce,
                                 b"\x55" * 16))
    rsn_psk = bytes.fromhex("0100000fac040100000fac040100000fac020000")
    beacon = (RadioTap() / Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff",
                                 addr2=ap, addr3=ap)
              / Dot11Beacon(cap="ESS") / Dot11Elt(ID="SSID", info="testnet")
              / Dot11Elt(ID="RSNinfo", info=rsn_psk))
    packets += [beacon, m1, m2, m3, m4]
    # WPA3/SAE: beacon advertising SAE plus an authentication frame.
    sae_ap = "66:77:88:99:aa:bb"
    rsn_sae = bytes.fromhex("0100000fac040100000fac040100000fac080000")
    sae_beacon = (RadioTap() / Dot11(type=0, subtype=8,
                                     addr1="ff:ff:ff:ff:ff:ff",
                                     addr2=sae_ap, addr3=sae_ap)
                  / Dot11Beacon(cap="ESS") / Dot11Elt(ID="SSID", info="sae-net")
                  / Dot11Elt(ID="RSNinfo", info=rsn_sae))
    sae_auth = (RadioTap() / Dot11(type=0, subtype=11, addr1=sae_ap,
                                   addr2=sta, addr3=sae_ap)
                / Raw(struct.pack("!HHH", 3, 1, 0)))
    packets += [sae_beacon, sae_auth]
    return packets


# Self-signed test certificate (CN=test.example.org, SAN includes
# alt.example.org) used by the TLS certificate-chain test.  The key is
# deliberately *not* shipped; tests that need key matching generate one.
TLS_TEST_CERT = base64.b64decode(
    "MIIDJDCCAgygAwIBAgIUD/8Xr1RFayYB4Rc1RnZaLDma+acwDQYJKoZIhvcNAQELBQAwGzEZ"
    "MBcGA1UEAwwQdGVzdC5leGFtcGxlLm9yZzAeFw0yNjExMTcwMDQ2MjFaFw0yNjEyMTcwMDQ2"
    "MjFaMBsxGTAXBgNVBAMMEHRlc3QuZXhhbXBsZS5vcmcwggEiMA0GCSqGSIb3DQEBAQUAA4IB"
    "DwAwggEKAoIBAQCjOiiDzSmp+dCs7k2M9w85GhOlE7/WQEFJR9g8i/tNbBFQES0l7AyNjfEH"
    "fTUojHyvfLOnKgwfmAdZih6pcp4Zv27Qw67pdHmQAATIoYi7lRAmkbj8/lRAsP40byNAxp+O"
    "+rY1BBlSb7Fu5e4se1rMsVAf8TBtZ8JfgU0NjP1IePfCnWO2fsTUPgHNGehnbZ9apxP1v23/"
    "sWVLx2y2/pK/ELunteH4LlHGblOklqQ+qYrg0K9l9UZYxSn9d4/u960IF0a48/JjDdrr6xA8"
    "lvjYZf6MgPAmdIlWDJnlOVq+JpE1BVgRgRfVBs+FdP80TNRE4yPbvNBhTrNtHElAF6IBAgMB"
    "AAGjYDBeMB0GA1UdDgQWBBS1yQabpr9Bqyi651dvPvQc1i5prTAPBgNVHRMBAf8EBTADAQH/"
    "MCwGA1UdEQQlMCOCEHRlc3QuZXhhbXBsZS5vcmeCD2FsdC5leGFtcGxlLm9yZzANBgkqhkiG"
    "9w0BAQsFAAOCAQEAmy3HJHNkb+afHXfqtbI5IHKSRRIQnTT0CO3Eruc2iC9eEScJcaPk+ZJA"
    "/ngh/sw0zvhpIldIR+5Yv468Pulop5Ff0U7nRbuZRN+c2BZ6yCUPmAtLd3tptMBP3z3Hw1wz"
    "18x8qGFM43rELrDcOKjjSTVb/RjYC4sa2GFVFIn0IFYNV9FmX1l9TtbLWL8KhGI/Z6KMKFqg"
    "ksVCcgRqRdf1oekNUkt9Sfwpq3fh2+Fyzi/5m49fCZMSmnqD914t4iX6wfI3AFSifJZ6SJNq"
    "jq0qODoMKRLPg9IVN7ZDwy4ZUKsxR5RAWEmiV/1urDEE59jiDia44slADNgO9RfM3wahqg==")


def tls_record(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + b"\x03\x03" + struct.pack("!H", len(body)) + body


def tls_handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def tls_extension(kind: int, data: bytes) -> bytes:
    return struct.pack("!HH", kind, len(data)) + data


def tls_client_hello_handshake(sni: str) -> bytes:
    name = sni.encode()
    sni_data = (struct.pack("!H", len(name) + 3) + b"\x00"
                + struct.pack("!H", len(name)) + name)
    alpn_data = struct.pack("!H", 3) + b"\x02h3"
    extensions = (tls_extension(0x0000, sni_data)
                  + tls_extension(0x0010, alpn_data)
                  + tls_extension(0x002B, b"\x02\x03\x04"))
    body = (b"\x03\x03" + b"\x22" * 32 + b"\x00"
            + struct.pack("!H", 2) + b"\x13\x01"
            + b"\x01\x00" + struct.pack("!H", len(extensions)) + extensions)
    return tls_handshake(1, body)


def tls_client_hello(sni: str) -> bytes:
    return tls_record(22, tls_client_hello_handshake(sni))


def tls_deep() -> list:
    """TLS 1.3 handshake with a certificate chain and a KeyUpdate record."""
    hello = tls_client_hello("test.example.org")
    server_hello = tls_record(22, tls_handshake(
        2, b"\x03\x03" + b"\x33" * 32 + b"\x00" + b"\x13\x01" + b"\x00"))
    cert_body = (len(TLS_TEST_CERT) + 3).to_bytes(3, "big") \
        + len(TLS_TEST_CERT).to_bytes(3, "big") + TLS_TEST_CERT
    certificate = tls_record(22, tls_handshake(11, cert_body))
    key_update = tls_record(22, tls_handshake(24, b"\x00"))
    done = tls_record(22, tls_handshake(14, b""))
    return tcp_stream("10.1.1.1", 40000, "10.1.1.2", 443,
                      [hello], [server_hello + certificate + key_update + done])


QUIC_SALTS = {
    1: bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"),
    0x6B3343CF: bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"),
}


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    import hmac
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    import hmac
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(secret, block + info + bytes([counter]),
                         hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _quic_varint(value: int) -> bytes:
    if value < 64:
        return bytes([value])
    if value < 16384:
        return struct.pack("!H", value | 0x4000)
    if value < 2 ** 30:
        return struct.pack("!I", value | 0x80000000)
    return struct.pack("!Q", value | 0xC000000000000000)


def quic_initial(dcid: bytes, scid: bytes, sni: str, *,
                 version: int = 1, pn: int = 0) -> bytes:
    """Seal one client Initial packet (RFC 9001) for the QUIC fixture."""
    salt = QUIC_SALTS[version]
    initial_secret = _hkdf_extract(salt, dcid)
    secret = _hkdf_expand_label(initial_secret, b"client in", 32)
    prefix = b"quicv2" if version == 0x6B3343CF else b"quic"
    key = _hkdf_expand_label(secret, prefix + b" key", 16)
    iv = _hkdf_expand_label(secret, prefix + b" iv", 12)
    hp = _hkdf_expand_label(secret, prefix + b" hp", 16)
    hello = tls_client_hello_handshake(sni)
    crypto = b"\x06" + _quic_varint(0) + _quic_varint(len(hello)) + hello
    crypto += b"\x00" * max(0, 1100 - len(crypto))
    pn_length = 1
    # RFC 9369 remaps the long-header packet types: v2 Initial is 0b01.
    first = 0xD0 if version == 0x6B3343CF else 0xC0
    header = (bytes([first | (pn_length - 1)]) + struct.pack("!I", version)
              + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid
              + b"\x00" + _quic_varint(pn_length + len(crypto) + 16)
              + bytes([pn]))
    nonce = bytes(a ^ b for a, b in
                  zip(iv, bytes(4) + pn.to_bytes(8, "big")))
    packet = bytearray(header + aes_gcm_encrypt(crypto, key, nonce, header))
    sample = bytes(packet[len(header) - pn_length + 4:
                          len(header) - pn_length + 20])
    mask = aes_encrypt_block(sample, hp)
    packet[0] ^= mask[0] & 0x0F
    for index in range(pn_length):
        packet[len(header) - pn_length + index] ^= mask[1 + index]
    return bytes(packet)


def _usb_mmapped(rec_type: str, xfer: int, ep: int, dev: int, irp: int,
                 data: bytes, bus: int = 256, ts: int = 1700000000) -> bytes:
    """One Linux-mmapped USB record (pcap linktype 220, 64-byte header).

    The header layout matches wiretap's ``USB_LINUX_MMAPPED``: id/type/
    xfer/ep/dev/bus, setup+data flags, timestamps, then an 8-byte setup area
    padded so the header totals 64 bytes.  ``bus`` is passed byte-swapped
    because Wireshark reads it big-endian.
    """
    header = struct.pack(
        "<QBBBBHbbqiiiI",
        irp, ord(rec_type), xfer, ep, dev, bus,
        -1, 0 if data else -1, ts, 0, 0, len(data), len(data))
    return header.ljust(64, b"\x00") + data


def usb_hid_capture(reports: list[bytes]) -> list:
    """USBPcap-style interrupt-IN reports for the HID analysers.

    Yields a submit/complete URB pair per report so tshark surfaces each
    payload as ``usb.capdata`` (the filter used by checkBox_16/17).
    """
    packets = []
    for index, report in enumerate(reports):
        irp = index * 2 + 1
        packets.append(Raw(_usb_mmapped("S", 1, 0x81, 1, irp, b"")))
        packets.append(Raw(_usb_mmapped("C", 1, 0x81, 1, irp, report)))
    return packets


def usb_kbd_capture() -> list:
    """Keyboard reports typing flag{usb_kbd} followed by Enter."""
    text = "flag{usb_kbd}\n"
    plain = {ch: code for code, ch in [
        (0x04, "a"), (0x05, "b"), (0x07, "d"), (0x09, "f"), (0x0A, "g"),
        (0x0E, "k"), (0x0F, "l"), (0x16, "s"), (0x18, "u"), (0x28, "\n"),
    ]}
    shifted = {"{": 0x2F, "}": 0x30, "_": 0x2D}
    reports = [bytes(8)]
    for ch in text:
        if ch in shifted:
            reports.append(bytes([0x02, 0, shifted[ch], 0, 0, 0, 0, 0]))
        elif ch in plain:
            reports.append(bytes([0, 0, plain[ch], 0, 0, 0, 0, 0]))
        else:
            continue
        reports.append(bytes(8))
    return usb_hid_capture(reports)


def usb_mouse_capture() -> list:
    """Mouse reports drawing a square with two left clicks."""
    reports = [bytes([0, 0, 0, 0])]
    steps = [(2, 0)] * 40 + [(0, 2)] * 40 + [(-2, 0)] * 40 + [(0, -2)] * 40
    for dx, dy in steps:
        reports.append(bytes([0, dx & 0xFF, dy & 0xFF, 0]))
    reports.append(bytes([1, 0, 0, 0]))
    reports.append(bytes([0, 0, 0, 0]))
    reports.append(bytes([1, 0, 0, 0]))
    reports.append(bytes([0, 0, 0, 0]))
    return usb_hid_capture(reports)


# Self-signed RDP test certificate (CN=rdp.ctf.local) embedded in the
# Certificate message of the RDP fixture handshake.  The matching private
# key is deliberately not shipped; the session is decryptable through the
# deterministic NSS keylog written to ``rdp_keylog.txt`` (see ``_rdp_tls``).
RDP_TEST_CERT = base64.b64decode(
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM4RENDQWRpZ0F3SUJBZ0lV"
    "Q01LY05KYURQS2NLNGxiV1RRUGhDSjJON0xFd0RRWUpLb1pJaHZjTkFRRUwKQlFB"
    "d0dERVdNQlFHQTFVRUF3d05jbVJ3TG1OMFppNXNiMk5oYkRBZUZ3MHlOakV4TVRj"
    "d05UVXdOVFJhRncwMApOakV4TVRJd05UVXdOVFJhTUJneEZqQVVCZ05WQkFNTURY"
    "SmtjQzVqZEdZdWJHOWpZV3d3Z2dFaU1BMEdDU3FHClNJYjNEUUVCQVFVQUE0SUJE"
    "d0F3Z2dFS0FvSUJBUURFcUh3bWVVc1MzMFBWcGJVR1ZPRXEzQkdHQjBkU2pOS3IK"
    "UjBjMkpWWVVvUW1PVXNXUmlVY01ybEpjUzdCTVBtdEdUNFZGYWsyaFhRVEVRSHZF"
    "d1A5RUFMay9CaXJNWU4xRAppTHpVbTAwRkcyOXhyQ2pqdEI1eDkySFVxL0h4SnY4"
    "czVoN1ZCU1dEejd1eGJyWXhZVWVQV3ArMlE3NGVNUyt6CjI3MWJ3aXdsUmVKRmJs"
    "NWoza1JsOVh2QUVaYit2dVFjQXZpeFlaaTZHTHhtQmNtR01ESFkzbjN0SUFEZWRU"
    "SFAKL2JLd0hkYUtrTmk0bDczQkFZZ3dodmpGYkIzUy9WTWpGc0p2Q3R1UERDRUN2"
    "K251VEh5NHl4NzZLaGZMdlJiNwpmN0FRQ054bnMvZXNMWk9oUzBFWW5VR2ZSQnJE"
    "ZGl3UmZwbGdCU211RVNWUGJpWVhORW41QWdNQkFBR2pNakF3Ck1CMEdBMVVkRGdR"
    "V0JCU3BLZXhEQUlNTEFJalBLb1ByMXdDNm1kelZyREFQQmdOVkhSTUJBZjhFQlRB"
    "REFRSC8KTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFDam1xdmhHMkNJeWd2a0ZP"
    "ZHlKU1BMZlUzQjFZdnVXcUwzZVdzVQpGVnBIV2Q1MDdNT29DajAyMWVKdXF1VXdL"
    "eG9kTzQvZ0dlRUlRUTVycTcwckVRclVOU3dNQitrVzlLYzJDWnlpCkRYTXV0Q3Za"
    "ak1XSnE3RTZPZjBtbm5zRi9iSDhSbGx1S3J4bTFHZ1RkYUpMTG0zU1U4U1ptVHFm"
    "NzNvRzZjcFcKWFFJczVQdnROdWhSOGlyZmFYQkkrWnRHcUtVSDl0V0owVEI3aW1X"
    "M3Q1dDhndEhlbTJmR0FtNWdEeFEyM1hYVgpHWmFMRVFSMDlub3E1Y0hJQlIwejJo"
    "bjJpWFBVR2pnR1BMUndPVGxhYmEwSTZ2Y3ZBK1hQNXY2Y3pZNzhXWGk0CnJnZzRP"
    "TGFWTG92UXhyWFdVSzYrWm9HMnZ2QUlaRXBidkkxanlQcWpzR1FGYUU3SAotLS0t"
    "LUVORCBDRVJUSUZJQ0FURS0tLS0tCg==")
def _pem_der(pem: bytes) -> bytes:
    """Extract the DER body of the first PEM block."""
    body = b"".join(line for line in pem.splitlines()
                    if not line.startswith(b"-----"))
    return base64.b64decode(body)


def _der_walk(data: bytes) -> list:
    """Flatten a DER structure into (tag, content) children."""
    items = []
    offset = 0
    while offset < len(data):
        tag = data[offset]
        offset += 1
        length = data[offset]
        offset += 1
        if length & 0x80:
            size = length & 0x7F
            length = int.from_bytes(data[offset:offset + size], "big")
            offset += size
        items.append((tag, data[offset:offset + length]))
        offset += length
    return items


def _rsa_public_key(cert_pem: bytes) -> tuple:
    """Pull ``(modulus, exponent)`` out of a self-signed certificate."""
    top = _der_walk(_pem_der(cert_pem))[0][1]           # Certificate content
    tbs = _der_walk(top)[0][1]                          # tbsCertificate
    subject_key = _der_walk(tbs)[6][1]                  # subjectPublicKeyInfo
    key_bits = _der_walk(subject_key)[1][1][1:]         # BIT STRING payload
    # RSAPublicKey SEQUENCE content = concatenated modulus/exponent INTEGERs
    modulus, exponent = (value for _tag, value
                         in _der_walk(_der_walk(key_bits)[0][1]))
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


def _rsa_pkcs1_encrypt(message: bytes, modulus: int, exponent: int) -> bytes:
    size = (modulus.bit_length() + 7) // 8
    padding = bytes((index % 254) + 1
                    for index in range(size - len(message) - 3))
    block = b"\x00\x02" + padding + b"\x00" + message
    return pow(int.from_bytes(block, "big"), exponent, modulus).to_bytes(
        size, "big")


def _tls_prf(secret: bytes, label: bytes, seed: bytes, length: int) -> bytes:
    """TLS 1.2 pseudo-random function (HMAC-SHA256 based, RFC 5246 §5)."""
    import hmac

    out, block = b"", label + seed
    while len(out) < length:
        block = hmac.new(secret, block, hashlib.sha256).digest()
        out += hmac.new(secret, block + label + seed,
                        hashlib.sha256).digest()
    return out[:length]


def _rdp_tls(cert_pem: bytes) -> dict:
    """Minimal TLS 1.2 RSA-key-exchange handshake for the RDP fixture.

    Client random, server random and premaster secret are all fixed, so the
    NSS keylog line for tshark's ``tls.keylog_file`` decryption is
    deterministic.  TLS_RSA_WITH_NULL_SHA256 keeps the record layer to
    MAC-only, which avoids a pure-Python AES while staying decryptable by
    tshark.
    """
    import hmac

    client_random = bytes(range(16, 48))
    server_random = bytes(range(64, 96))
    premaster = b"\x03\x03" + bytes(range(128, 174))
    cipher = b"\x00\x3b"  # TLS_RSA_WITH_NULL_SHA256
    hello_tail = (b"\x00" + struct.pack(">H", len(cipher)) + cipher
                  + b"\x01\x00" + b"\x00\x00")

    cert_der = _pem_der(cert_pem)
    client_hello = tls_handshake(1, b"\x03\x03" + client_random + hello_tail)
    # ServerHello carries a single cipher suite (no suites-length prefix) and
    # a single compression method byte.
    server_hello = tls_handshake(
        2, b"\x03\x03" + server_random + b"\x00" + cipher
        + b"\x00" + b"\x00\x00")
    certificate = tls_handshake(
        11, (len(cert_der) + 3).to_bytes(3, "big")
        + len(cert_der).to_bytes(3, "big") + cert_der)
    server_hello_done = tls_handshake(14, b"")
    modulus, exponent = _rsa_public_key(cert_pem)
    encrypted_premaster = _rsa_pkcs1_encrypt(premaster, modulus, exponent)
    client_key_exchange = tls_handshake(
        16, struct.pack(">H", len(encrypted_premaster)) + encrypted_premaster)

    master_secret = _tls_prf(premaster, b"master secret",
                             client_random + server_random, 48)
    keylog = "CLIENT_RANDOM %s %s" % (client_random.hex(), master_secret.hex())
    key_block = _tls_prf(master_secret, b"key expansion",
                         server_random + client_random, 64)
    client_mac, server_mac = key_block[:32], key_block[32:]
    client_seen = hashlib.sha256(client_hello + server_hello + certificate
                                 + server_hello_done).digest()
    server_seen = hashlib.sha256(client_hello + server_hello + certificate
                                 + server_hello_done
                                 + client_key_exchange).digest()
    client_finished = tls_handshake(
        20, _tls_prf(master_secret, b"client finished", client_seen, 12))
    server_finished = tls_handshake(
        20, _tls_prf(master_secret, b"server finished", server_seen, 12))

    def mac_record(side: bytes, seq: int, kind: int, content: bytes) -> bytes:
        mac = hmac.new(side, struct.pack("!Q", seq) + bytes([kind])
                       + b"\x03\x03" + struct.pack("!H", len(content))
                       + content, hashlib.sha256).digest()
        return tls_record(kind, content + mac)

    def sender(side: bytes):
        state = {"seq": 1}  # the Finished handshake consumed sequence 0

        def send(content: bytes) -> bytes:
            record = mac_record(side, state["seq"], 23, content)
            state["seq"] += 1
            return record
        return send

    return {
        "client_hello": [tls_record(22, client_hello)],
        "server_flight1": [tls_record(22, server_hello),
                           tls_record(22, certificate),
                           tls_record(22, server_hello_done)],
        "client_flight2": [tls_record(22, client_key_exchange),
                           tls_record(20, b"\x01"),
                           mac_record(client_mac, 0, 22, client_finished)],
        "server_flight2": [tls_record(20, b"\x01"),
                           mac_record(server_mac, 0, 22, server_finished)],
        "client_app": sender(client_mac),
        "server_app": sender(server_mac),
        "keylog": keylog,
    }


def rdp_keylog() -> str:
    """NSS keylog line matching the fixed RDP fixture handshake."""
    return _rdp_tls(RDP_TEST_CERT)["keylog"]


def rdp_replay_capture() -> list:
    """RDP for the checkBox_47 session-replay handler.

    The X.224 Connection Request/Confirm with RDP negotiation PDUs runs on
    TCP/13389 (the handler's ``port`` parameter) while the TLS 1.2
    RSA-key-exchange session runs on TCP/3389.  Recent Wireshark builds let
    the ``tpkt.tcp.port`` preference claim every payload on the parameter
    port before the TLS heuristic dissector gets a chance, so the encrypted
    records must live on the default RDP port, where the RDP dissector
    rejects them and hands them to the TLS heuristic.  The session decrypts
    through the deterministic NSS keylog written to ``rdp_keylog.txt``
    (tshark's ``tls.keylog_file``); PyRDP's replay conversion additionally
    needs full MCS/GCC PDUs, which this fixture keeps minimal.
    """
    def tpkt(payload: bytes) -> bytes:
        return b"\x03\x00" + struct.pack(">H", len(payload) + 4) + payload

    def dt(payload: bytes) -> bytes:
        return tpkt(b"\x02\xf0\x80" + payload)

    def neg(kind: int, protocol: int) -> bytes:
        return bytes([kind, 0x00, 0x08, 0x00]) + struct.pack("<I", protocol)

    cookie = b"Cookie: mstshash=fnet\r\n"
    # TYPE_RDP_NEG_REQ(0x01) requesting PROTOCOL_SSL(0x00000001).
    request_var = cookie + neg(0x01, 1)
    connection_request = tpkt(bytes([6 + len(request_var), 0xE0])
                              + b"\x00\x00\x00\x00\x00" + request_var)
    # TYPE_RDP_NEG_RSP(0x02) selecting PROTOCOL_SSL.
    confirm_var = neg(0x02, 1)
    connection_confirm = tpkt(bytes([6 + len(confirm_var), 0xD0])
                              + b"\x00\x00\x00\x00\x00" + confirm_var)

    tls = _rdp_tls(RDP_TEST_CERT)
    client_app = tls["client_app"](dt(b"\x7f\x65\x04"
                                      + b"flag{rdp_client_info}"))
    fastpath = (b"\x00\x0e\x0f\x00"
                + struct.pack(">H", len(b"flag{rdp_graphics}"))
                + b"flag{rdp_graphics}")
    server_app = tls["server_app"](dt(b"\x7f\x66\x04" + b"flag{rdp_server}"))
    server_fastpath = tls["server_app"](tpkt(fastpath))
    negotiation = tcp_stream("10.0.0.5", 40140, "10.0.0.88", 13389,
                             [connection_request], [connection_confirm])
    session = tcp_stream("10.0.0.5", 40142, "10.0.0.88", 3389,
                         [b"".join(tls["client_hello"]),
                          b"".join(tls["client_flight2"]), client_app],
                         [b"".join(tls["server_flight1"]),
                          b"".join(tls["server_flight2"]),
                          server_app + server_fastpath])
    return negotiation + session


def quic_capture() -> list:
    """QUIC v1 and v2 Initial packets carrying SNI/ALPN metadata."""
    flows = [
        ("10.2.2.10", 51000, "10.2.2.20", b"\x01\x02\x03\x04\x05\x06\x07\x08",
         b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10", "quic.example.org", 1),
        ("10.2.2.11", 51001, "10.2.2.21", b"\x11\x12\x13\x14\x15\x16\x17\x18",
         b"\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20", "cdn.example.org", 0x6B3343CF),
    ]
    packets = []
    for src, sport, dst, dcid, scid, sni, version in flows:
        payload = quic_initial(dcid, scid, sni, version=version)
        packets.append(Ether() / IP(src=src, dst=dst) / UDP(sport=sport,
                                                            dport=443) / payload)
    return packets


def bluetooth_capture() -> list:
    """Bluetooth HCI H4 (linktype 201, direction pseudo-header) sample.

    One LE scan command pair plus two ACL/ATT read responses carrying a
    flag, so checkBox_21 dumps HCI tables and checkBox_40 surfaces btatt
    values.
    """
    def h4_dir(direction, h4frame):
        return struct.pack(">I", direction) + h4frame

    def h4_cmd(opcode, body=b""):
        return bytes([0x01]) + struct.pack("<HH", opcode, len(body)) + body

    def h4_evt(code, body):
        return bytes([0x04]) + struct.pack("<BB", code, len(body)) + body

    def acl(handle, payload):
        return bytes([0x02]) + struct.pack("<HH", handle | 0x2000,
                                           len(payload)) + payload

    def l2cap(cid, payload):
        return struct.pack("<HH", len(payload), cid) + payload

    def att_read_rsp(value):
        return bytes([0x0b]) + value

    packets = [
        h4_dir(1, h4_cmd(0x2007, b"\x01")),                    # LE Set Scan Enable
        h4_dir(0, h4_evt(0x0e, b"\x01\x20\x07\x00")),          # Command Complete
        h4_dir(0, acl(0x0040, l2cap(0x0004, att_read_rsp(b"flag{ble_ctf}")))),
        h4_dir(0, acl(0x0040, l2cap(0x0004, att_read_rsp(b"Device Name")))),
    ]
    return [Raw(p) for p in packets]


def build(only: list[str] | None = None) -> dict[str, Path]:
    OUT.mkdir(parents=True, exist_ok=True)
    groups = {
        "http_ntlm.pcap": http_capture(),
        "ftp_smtp_telnet.pcap": ftp_smtp_telnet(),
        "dns_arp_icmp.pcap": dns_arp_icmp(),
        "modbus_mqtt.pcap": modbus_mqtt(),
        "websocket.pcap": websocket_capture(),
        "redis_nonstandard.pcap": redis_nonstandard(),
        "protocol_deep.pcap": protocol_deep(),
        "http2_deep.pcap": http2_deep(),
        "ldap_deep.pcap": ldap_deep(),
        "smb2_deep.pcap": smb2_deep(),
        "wifi_eapol.pcap": wifi_eapol(),
        "tls_deep.pcap": tls_deep(),
        "quic.pcap": quic_capture(),
        "usb_kbd.pcap": usb_kbd_capture(),
        "usb_mouse.pcap": usb_mouse_capture(),
        "bluetooth.pcap": bluetooth_capture(),
        "rdp.pcap": rdp_replay_capture(),
    }
    # Non-Ethernet encapsulations: scapy would default Raw payloads to
    # Ethernet, so override the pcap linktype per group.
    linktypes = {"usb_kbd.pcap": 220, "usb_mouse.pcap": 220,
                 "bluetooth.pcap": 201}
    if only:
        wanted = set(only)
        groups = {name: packets for name, packets in groups.items()
                  if name in wanted}
    if not only or "rdp.pcap" in wanted:
        # NSS keylog matching the fixed handshake inside rdp.pcap; feed it to
        # checkBox_47 (rdp.handler) via --param rdp_private_key=rdp_keylog.txt.
        (OUT / "rdp_keylog.txt").write_text(rdp_keylog() + "\n",
                                            encoding="ascii")
    written = {}
    for name, packets in groups.items():
        path = OUT / name
        wrpcap(str(path), packets, linktype=linktypes.get(name, 1))
        written[name] = path
        print(f"{path}  ({len(packets)} packets)")
    return written


if __name__ == "__main__":
    build(sys.argv[1:] or None)
