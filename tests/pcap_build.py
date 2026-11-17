"""Helpers to build tiny multi-protocol pcap fixtures without scapy.

The builders emit classic libpcap files (link type Ethernet) with
hand-crafted Ethernet/IPv4/TCP frames, checksums included.  Only the
standard library is used so the tests run everywhere.
"""
from __future__ import annotations

import struct


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_checksum(header: bytes) -> int:
    return _checksum(header)


def tcp_session(src: str, sport: int, dst: str, dport: int,
                client_payloads: list, server_payloads: list,
                *, seq_c: int = 1001, seq_s: int = 5001) -> list[bytes]:
    """Frames for one TCP session: payload-carrying packets in order."""
    packets: list[bytes] = []
    for index in range(max(len(client_payloads), len(server_payloads))):
        if index < len(client_payloads):
            payload = client_payloads[index]
            packets.append(tcp_packet(src, sport, dst, dport, seq_c, payload,
                                      ack=seq_s))
            seq_c += len(payload)
        if index < len(server_payloads):
            payload = server_payloads[index]
            packets.append(tcp_packet(dst, dport, src, sport, seq_s, payload,
                                      ack=seq_c))
            seq_s += len(payload)
    return packets


def tcp_packet(src: str, sport: int, dst: str, dport: int, seq: int,
               payload: bytes, *, ack: int = 1, flags: int = 0x18) -> bytes:
    """One Ethernet/IPv4/TCP frame carrying ``payload``."""
    src_parts = [int(part) for part in src.split(".")]
    dst_parts = [int(part) for part in dst.split(".")]

    tcp = struct.pack(">HHIIBBHHH", sport, dport, seq, ack,
                      (5 << 4), flags, 65535, 0, 0)
    total_length = 20 + len(tcp) + len(payload)
    ip_header = bytearray(struct.pack(
        ">BBHHHBBH4s4s", 0x45, 0, total_length, 0x1234, 0x4000, 64, 6, 0,
        bytes(src_parts), bytes(dst_parts)))
    ip_header[10:12] = struct.pack(">H", ipv4_checksum(bytes(ip_header)))
    frame = (b"\x02\x00\x00\x00\x00\x01" + b"\x02\x00\x00\x00\x00\x02"
             + b"\x08\x00" + bytes(ip_header) + tcp + payload)
    return frame


def write_pcap(path, packets, *, step_ms: int = 10) -> None:
    """Write frames as a classic libpcap file."""
    records = bytearray()
    timestamp = 1_700_000_000
    for index, packet in enumerate(packets):
        usec = (index * step_ms * 1000) % 1_000_000
        records += struct.pack("<IIII", timestamp, usec, len(packet),
                               len(packet)) + packet
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    with open(path, "wb") as handle:
        handle.write(header + bytes(records))
