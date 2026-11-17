"""Unit tests for the SMTP/IMAP/POP3 and MIME helpers (no tshark)."""
from __future__ import annotations

import base64
import hashlib
import tempfile
import unittest
from pathlib import Path

from fnet.utils import mail

FLAG = b"flag{mail_attachment}"
BOUNDARY = b"fnet-mail-boundary"
SUBJECT_TEXT = "测试邮件"


def sample_message() -> bytes:
    """Multipart message: QP text part + base64 attachment."""
    lines = [
        b"From: Alice <alice@example.com>",
        b"To: Bob <bob@example.com>",
        b"Subject: =?utf-8?B?5rWL6K+V6YKu5Lu2?=",
        b"MIME-Version: 1.0",
        b'Content-Type: multipart/mixed; boundary="' + BOUNDARY + b'"',
        b"",
        b"--" + BOUNDARY,
        b'Content-Type: text/plain; charset="utf-8"',
        b"Content-Transfer-Encoding: quoted-printable",
        b'Content-Disposition: inline; filename="body.txt"',
        b"",
        b"caf=C3=A9 quoted printable",
        b"",
        b"--" + BOUNDARY,
        b"Content-Type: application/octet-stream",
        b"Content-Transfer-Encoding: base64",
        b'Content-Disposition: attachment; filename="flag.txt"',
        b"",
        base64.b64encode(FLAG),
        b"",
        b"--" + BOUNDARY + b"--",
        b"",
    ]
    return b"\r\n".join(lines)


class MailMimeTest(unittest.TestCase):
    def test_attachments_and_hashes(self):
        message = mail.parse_message(sample_message())
        entries = mail.attachment_entries(message)
        self.assertEqual(len(entries), 2)
        by_name = {entry["filename"]: entry for entry in entries}
        self.assertEqual(set(by_name), {"body.txt", "flag.txt"})

        flag = by_name["flag.txt"]
        self.assertEqual(flag["content_type"], "application/octet-stream")
        self.assertEqual(flag["size"], len(FLAG))
        self.assertEqual(flag["data"], FLAG)
        self.assertEqual(flag["md5"], hashlib.md5(FLAG).hexdigest())
        self.assertEqual(flag["sha256"], hashlib.sha256(FLAG).hexdigest())
        self.assertFalse(flag["inline"])

        text = by_name["body.txt"]
        self.assertTrue(text["inline"])
        self.assertEqual(
            text["data"].decode("utf-8").strip(), "café quoted printable")

    def test_save_attachments_unique_names(self):
        message = mail.parse_message(sample_message())
        with tempfile.TemporaryDirectory() as tmp:
            first = mail.save_attachments(message, tmp)
            second = mail.save_attachments(message, tmp)
            self.assertEqual(len(first), 2)
            self.assertEqual(len(second), 2)
            self.assertEqual(len(set(first + second)), 4)
            flag_path = Path(tmp) / "flag.txt"
            self.assertEqual(flag_path.read_bytes(), FLAG)
            self.assertTrue((Path(tmp) / "flag-1.txt").is_file())

    def test_header_summary_rfc2047(self):
        raw = b"\r\n".join([
            b"From: =?utf-8?B?5byg5LiJ?= <zs@example.com>",
            b"To: =?utf-8?B?5p2O5Zub?= <ls@example.com>",
            b"Cc: =?utf-8?B?546L5LqU?= <ww@example.com>",
            b"Subject: =?utf-8?B?5rWL6K+V6YKu5Lu2?=",
            b"Date: Mon, 01 Jan 2024 10:00:00 +0000",
            b"Message-ID: <id@example.com>",
            b"Reply-To: reply@example.com",
            b"Return-Path: <bounce@example.com>",
            b"",
            b"body",
            b"",
        ])
        summary = mail.header_summary(mail.parse_message(raw))
        self.assertEqual(summary["Subject"], SUBJECT_TEXT)
        self.assertIn("张三", summary["From"])
        self.assertIn("zs@example.com", summary["From"])
        self.assertIn("李四", summary["To"])
        self.assertIn("王五", summary["Cc"])
        self.assertEqual(summary["Message-ID"], "<id@example.com>")
        self.assertEqual(summary["Reply-To"], "reply@example.com")
        self.assertEqual(summary["Return-Path"], "<bounce@example.com>")
        self.assertTrue(summary["Date"].startswith("Mon, 01 Jan 2024"))

    def test_delivery_chain_two_hops(self):
        message = mail.parse_message(b"Subject: hops\r\n\r\nbody\r\n")
        message["Received"] = (
            "from mail.example (mail.example [10.0.0.1]) by mx1.example "
            "with ESMTP id ABC123 for <bob@example.com>; "
            "Mon, 1 Jan 2024 10:00:00 +0000")
        message["Received"] = (
            "from client.example (client.example [10.0.0.2]) by mail.example "
            "with ESMTPS id XYZ789; Mon, 1 Jan 2024 09:59:00 +0000")
        chain = mail.delivery_chain(message)
        self.assertEqual(len(chain), 2)
        recent = chain[0]
        self.assertTrue(recent["from"].startswith("mail.example"))
        self.assertEqual(recent["by"], "mx1.example")
        self.assertEqual(recent["with"], "ESMTP")
        self.assertEqual(recent["id"], "ABC123")
        self.assertEqual(recent["for"], "<bob@example.com>")
        self.assertTrue(recent["date"].startswith("Mon, 1 Jan 2024"))
        older = chain[1]
        self.assertEqual(older["by"], "mail.example")
        self.assertEqual(older["with"], "ESMTPS")
        self.assertEqual(older["id"], "XYZ789")


class MailTranscriptTest(unittest.TestCase):
    def test_smtp_auth_plain_and_data(self):
        token = base64.b64encode(b"\x00alice\x00s3cret")
        transcript = b"".join([
            b"220 mx.example ESMTP ready\r\n",
            b"EHLO client.example\r\n",
            b"250-mx.example\r\n",
            b"250 AUTH PLAIN LOGIN\r\n",
            b"AUTH PLAIN " + token + b"\r\n",
            b"235 2.7.0 Authentication successful\r\n",
            b"MAIL FROM:<alice@example.com>\r\n",
            b"250 OK\r\n",
            b"RCPT TO:<bob@example.com>\r\n",
            b"250 OK\r\n",
            b"DATA\r\n",
            b"354 End data with <CR><LF>.<CR><LF>\r\n",
            b"From: alice@example.com\r\n",
            b"To: bob@example.com\r\n",
            b"Subject: hi\r\n",
            b"\r\n",
            b"body\r\n",
            b".\r\n",
            b"250 OK queued\r\n",
            b"QUIT\r\n",
            b"221 Bye\r\n",
        ])
        result = mail.smtp_transcript(transcript)
        self.assertEqual(result["mail_from"], ["alice@example.com"])
        self.assertEqual(result["rcpt_to"], ["bob@example.com"])
        self.assertEqual(result["credentials"][0]["mechanism"], "PLAIN")
        self.assertEqual(result["credentials"][0]["username"], "alice")
        self.assertEqual(result["credentials"][0]["password"], "s3cret")
        self.assertEqual(len(result["messages"]), 1)
        message = result["messages"][0]
        self.assertEqual(message["summary"]["Subject"], "hi")
        self.assertEqual(message["summary"]["From"], "alice@example.com")
        self.assertEqual(message["message"].get_content().strip(), "body")
        commands = [item["command"] for item in result["commands"]]
        for expected in ("EHLO", "AUTH", "MAIL", "RCPT", "DATA", "QUIT"):
            self.assertIn(expected, commands)
        for reply in ("220", "250", "354", "221"):
            self.assertNotIn(reply, commands)

    def test_imap_login_select_and_fetch_literal(self):
        inner = b"".join([
            b"From: a@example.com\r\n",
            b"To: b@example.com\r\n",
            b"Subject: imap\r\n",
            b"MIME-Version: 1.0\r\n",
            b"Content-Type: text/plain; charset=utf-8\r\n",
            b"\r\n",
            b"imap body\r\n",
        ])
        transcript = b"".join([
            b"* OK IMAP4rev1 ready\r\n",
            b"a1 LOGIN alice s3cret\r\n",
            b"a1 OK LOGIN completed\r\n",
            b'a2 SELECT "INBOX"\r\n',
            b"* 3 EXISTS\r\n",
            b"a2 OK [READ-WRITE] SELECT completed\r\n",
            b"a3 FETCH 1 BODY[]\r\n",
            b"* 1 FETCH (BODY[] {" + str(len(inner)).encode() + b"}\r\n",
            inner,
            b")\r\n",
            b"a3 OK FETCH completed\r\n",
        ])
        result = mail.imap_transcript(transcript)
        self.assertEqual(result["credentials"][0]["username"], "alice")
        self.assertEqual(result["credentials"][0]["password"], "s3cret")
        self.assertIn("INBOX", result["mailboxes"])
        self.assertEqual(len(result["messages"]), 1)
        message = result["messages"][0]
        self.assertEqual(message["mailbox"], "INBOX")
        self.assertEqual(message["summary"]["Subject"], "imap")
        commands = [item["command"] for item in result["commands"]]
        self.assertEqual(commands, ["LOGIN", "SELECT", "FETCH"])

    def test_pop3_user_pass_retr_and_uidl(self):
        transcript = b"".join([
            b"+OK POP3 server ready\r\n",
            b"USER alice\r\n",
            b"+OK user accepted\r\n",
            b"PASS s3cret\r\n",
            b"+OK logged in\r\n",
            b"UIDL\r\n",
            b"+OK unique-id listing follows\r\n",
            b"1 ABC123\r\n",
            b".\r\n",
            b"RETR 1\r\n",
            b"+OK 120 octets\r\n",
            b"From: a@example.com\r\n",
            b"Subject: pop\r\n",
            b"\r\n",
            b"hello pop\r\n",
            b".\r\n",
            b"QUIT\r\n",
            b"+OK bye\r\n",
        ])
        result = mail.pop3_transcript(transcript)
        self.assertEqual(result["credentials"][0]["username"], "alice")
        self.assertEqual(result["credentials"][0]["password"], "s3cret")
        self.assertEqual(result["uids"], [{"message": "1", "uid": "ABC123"}])
        self.assertEqual(len(result["messages"]), 1)
        message = result["messages"][0]
        self.assertEqual(message["summary"]["Subject"], "pop")
        self.assertEqual(
            message["message"].get_content().strip(), "hello pop")
        commands = [item["command"] for item in result["commands"]]
        self.assertIn("RETR", commands)
        self.assertNotIn("+OK", commands)

    def test_garbage_returns_empty_without_raising(self):
        garbage = b"\x00\xff\x01 garbage \x02\r\n\x03\x04"
        for parser in (mail.smtp_transcript, mail.imap_transcript,
                       mail.pop3_transcript):
            result = parser(garbage)
            self.assertIsInstance(result, dict)
            self.assertEqual(result["commands"], [])
            self.assertEqual(result["credentials"], [])
            self.assertEqual(result["messages"], [])
        self.assertEqual(mail.mail_summary("pop3", garbage)["messages"], [])
        self.assertEqual(mail.mail_summary("nope", garbage)["messages"], [])
        self.assertEqual(mail.parse_message(None).get_all("Subject"), None)
        self.assertEqual(mail.attachment_entries(None), [])
        self.assertEqual(mail.delivery_chain(None), [])
        self.assertEqual(mail.header_summary(None)["Subject"], "")

    def test_truncated_transcripts_do_not_raise(self):
        truncated = [
            b"MAIL FROM:<a@example.com>\r\nDATA\r\nSubject: x\r\n",
            b"a1 APPEND INBOX {500}\r\nshort",
            b"* 1 FETCH (BODY[] {400}\r\nSubject: x",
            b"RETR 1\r\nSubject: x\r\n",
        ]
        for data in truncated:
            for parser in (mail.smtp_transcript, mail.imap_transcript,
                           mail.pop3_transcript, mail.mail_summary):
                if parser is mail.mail_summary:
                    parser("imap", data)
                else:
                    self.assertIsInstance(parser(data), dict)


if __name__ == "__main__":
    unittest.main()
