"""Pure parsing tests for :mod:`fnet.utils.ssh` (no tshark needed)."""
from __future__ import annotations

import struct
import unittest

from fnet.utils import ssh


def ssh_packet(payload: bytes) -> bytes:
    pad = (8 - ((4 + 1 + len(payload)) % 8))
    if pad < 4:
        pad += 8
    packet_len = 1 + len(payload) + pad
    return struct.pack(">I", packet_len) + bytes([pad]) + payload + \
        b"\x00" * pad


def name_list(names: list[str]) -> bytes:
    raw = ",".join(names).encode()
    return struct.pack(">I", len(raw)) + raw


def kexinit() -> bytes:
    return (b"\x14" + b"\x11" * 16
            + name_list(["curve25519-sha256", "ecdh-sha2-nistp256"])
            + name_list(["ssh-ed25519"])
            + name_list(["chacha20-poly1305@openssh.com"])
            + name_list(["aes128-ctr"])
            + name_list(["umac-64-etm@openssh.com"])
            + name_list(["hmac-sha2-256"])
            + name_list(["none"]) + name_list(["zlib@openssh.com"])
            + name_list([]) + name_list([])
            + b"\x00" + struct.pack(">I", 0))


def userauth_request(user: str, method: str, password: str | None = None,
                     algorithm: str | None = None) -> bytes:
    body = (struct.pack(">I", len(user)) + user.encode()
            + struct.pack(">I", 14) + b"ssh-connection"
            + struct.pack(">I", len(method)) + method.encode())
    if method == "password":
        body += b"\x00" + struct.pack(">I", len(password)) + password.encode()
    elif method == "publickey":
        blob = b"\x01\x02\x03\x04"
        body += (b"\x01" + struct.pack(">I", len(algorithm))
                 + algorithm.encode()
                 + struct.pack(">I", len(blob)) + blob)
    return b"\x32" + body


def userauth_failure(methods: str = "password",
                     partial: bool = False) -> bytes:
    raw = methods.encode()
    return b"\x33" + struct.pack(">I", len(raw)) + raw + \
        bytes([1 if partial else 0])


class SshBannerTest(unittest.TestCase):
    def test_banner_fields(self):
        banner = parse = ssh.parse_banner(b"SSH-2.0-OpenSSH_9.6\r\n")
        self.assertIsNotNone(banner)
        fields, end = banner
        self.assertEqual(end, 21)
        self.assertEqual(fields["protocol"], "2.0")
        self.assertEqual(fields["software"], "OpenSSH_9.6")
        self.assertEqual(fields["comment"], "")

    def test_banner_with_comment(self):
        fields, _end = ssh.parse_banner(
            b"SSH-2.0-libssh_0.9.5 my comment\r\nrest")
        self.assertEqual(fields["software"], "libssh_0.9.5")
        self.assertEqual(fields["comment"], "my comment")

    def test_banner_incomplete_line_waits_for_more(self):
        self.assertIsNone(ssh.parse_banner(b"SSH-2.0-OpenSSH"))

    def test_looks_like_ssh(self):
        self.assertTrue(ssh.looks_like_ssh(b"SSH-2.0-x\r\n"))
        self.assertFalse(ssh.looks_like_ssh(b"GET / HTTP/1.1\r\n"))
        self.assertFalse(ssh.looks_like_ssh(b""))


class SshKexInitTest(unittest.TestCase):
    def test_kexinit_name_lists(self):
        payload = kexinit()
        fields = ssh.parse_kexinit(payload[1:])
        self.assertEqual(fields["kex_algorithms"],
                         ["curve25519-sha256", "ecdh-sha2-nistp256"])
        self.assertEqual(fields["server_host_key_algorithms"],
                         ["ssh-ed25519"])
        self.assertEqual(fields["encryption_algorithms_client_to_server"],
                         ["chacha20-poly1305@openssh.com"])
        self.assertEqual(fields["encryption_algorithms_server_to_client"],
                         ["aes128-ctr"])
        self.assertEqual(fields["mac_algorithms_server_to_client"],
                         ["hmac-sha2-256"])
        self.assertEqual(fields["compression_algorithms_server_to_client"],
                         ["zlib@openssh.com"])
        self.assertFalse(fields["first_kex_packet_follows"])

    def test_truncated_kexinit_returns_partial(self):
        fields = ssh.parse_kexinit(kexinit()[1:60])
        self.assertEqual(fields["kex_algorithms"],
                         ["curve25519-sha256", "ecdh-sha2-nistp256"])
        self.assertNotIn("encryption_algorithms_client_to_server", fields)


class SshStreamTest(unittest.TestCase):
    def test_stream_banner_kex_and_encryption_stop(self):
        stream = (b"SSH-2.0-OpenSSH_9.6\r\n"
                  + ssh_packet(kexinit())
                  + ssh_packet(b"\x15")  # NEWKEYS
                  + b"\x9f\xc4" * 24)   # encrypted junk
        messages = ssh.parse_stream(stream)
        kinds = [(m.kind, m.name) for m in messages]
        self.assertEqual(kinds[0], ("banner", "VERSION"))
        self.assertEqual(kinds[1], ("packet", "KEXINIT"))
        self.assertEqual(kinds[2], ("packet", "NEWKEYS"))
        self.assertEqual(kinds[-1][0], "encrypted")
        self.assertEqual(messages[-1].fields.get("remaining"), 48)

    def test_frame_lookup_used(self):
        stream = b"SSH-2.0-OpenSSH_9.6\r\n" + ssh_packet(kexinit())
        messages = ssh.parse_stream(stream,
                                    frame_lookup=lambda offset: str(offset))
        self.assertEqual([m.frame for m in messages], ["0", "21"])

    def test_garbage_is_reported_encrypted(self):
        messages = ssh.parse_stream(b"\x00\x01\x02\x03rubbish")
        self.assertTrue(all(m.kind == "encrypted" for m in messages)
                        or all(m.kind == "banner" for m in messages))


class SshUserauthTest(unittest.TestCase):
    def _stream(self, *packets: bytes) -> bytes:
        return b"SSH-2.0-OpenSSH_9.6\r\n" + b"".join(
            ssh_packet(packet) for packet in packets)

    def test_password_request_extracted(self):
        messages = ssh.parse_stream(self._stream(
            userauth_request("root", "password", "hunter2")))
        request = messages[1]
        self.assertEqual(request.name, "USERAUTH_REQUEST")
        self.assertEqual(request.fields["user"], "root")
        self.assertEqual(request.fields["method"], "password")
        self.assertEqual(request.fields["password"], "hunter2")

    def test_publickey_request_extracted(self):
        messages = ssh.parse_stream(self._stream(
            userauth_request("deploy", "publickey",
                             algorithm="ssh-ed25519")))
        self.assertEqual(messages[1].fields["user"], "deploy")
        self.assertEqual(messages[1].fields["method"], "publickey")
        self.assertEqual(messages[1].fields["algorithm"], "ssh-ed25519")
        self.assertTrue(messages[1].fields["has_signature"])

    def test_events_failures_and_success(self):
        stream = self._stream(
            userauth_request("root", "password", "wrong"),
            userauth_failure(),
            userauth_failure(),
            userauth_request("root", "password", "hunter2"),
            b"\x34",
        )
        messages = ssh.parse_stream(stream)
        events = ssh.auth_events(messages)
        kinds = [event["kind"] for event in events]
        self.assertEqual(kinds, ["request", "failure", "failure",
                                 "request", "success"])
        self.assertEqual(ssh.failure_counts(events), {"root": 2})
        self.assertEqual(events[-1]["user"], "root")

    def test_failure_without_request_has_empty_user(self):
        messages = ssh.parse_stream(self._stream(userauth_failure()))
        events = ssh.auth_events(messages)
        self.assertEqual(events[0]["user"], "")

    def test_partial_success_flag(self):
        messages = ssh.parse_stream(
            self._stream(userauth_failure("publickey,password", True)))
        self.assertTrue(messages[1].fields["partial_success"])
        self.assertIn("publickey", messages[1].fields["methods"])


if __name__ == "__main__":
    unittest.main()
