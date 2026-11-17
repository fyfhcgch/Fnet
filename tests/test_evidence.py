"""Unit tests for the log-evidence import and correlation module.

Covered here (``fnet/utils/evidence.py``):

* Suricata ``eve.json`` parsing (alert + flow, filters, bad lines);
* Zeek logs in TSV (``#fields`` headers) and JSON streaming formats for
  ``conn`` / ``http`` / ``dns`` / ``ssl`` / ``notice``;
* unified ``parse_events`` auto-detection and mixed/corrupt input;
* ``correlate`` scoring: positive matches by IP pair / port / time window,
  negative cases (out-of-window times, wrong IPs, weak scores).
"""
from __future__ import annotations

import unittest

from fnet.utils import evidence


EVE_TEXT = "\n".join([
    '{"timestamp":"2026-01-01T10:00:00.100000+0000","flow_id":42,'
    '"event_type":"alert","src_ip":"10.0.0.8","src_port":4444,'
    '"dest_ip":"203.0.113.5","dest_port":80,"proto":"TCP",'
    '"alert":{"signature":"ET WEB Shell","category":"Web Application Attack",'
    '"severity":1}}',
    '{"timestamp":"2026-01-01T10:00:01.000000+0000","flow_id":43,'
    '"event_type":"flow","src_ip":"10.0.0.8","src_port":4444,'
    '"dest_ip":"203.0.113.5","dest_port":80,"proto":"TCP"}',
    '{"timestamp":"2026-01-01T10:00:02.000000+0000","event_type":"dns",'
    '"dns":{"type":"query","rrname":"evil.example"}}',
    'not json at all',
    '{"timestamp":"2026-01-01T10:00:03.000000+0000","event_type":"alert",'
    '"src_ip":"192.168.1.2","src_port":1,"dest_ip":"192.168.1.3",'
    '"dest_port":2,"proto":"UDP","alert":{"signature":"Bad Thing",'
    '"severity":2}}',
    '',
])

ZEEK_TSV = "\n".join([
    "#separator \\x09",
    "#set_separator\t,",
    "#empty_field\t(empty)",
    "#unset_field\t-",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring",
    "1767261600.500000\tCAbc123\t10.0.0.8\t4444\t203.0.113.5\t80\ttcp\thttp",
    "#comment line that must be skipped",
    "this is not a zeek record",
    "1767261610.000000\tCdef456\t172.16.0.9\t51000\t198.51.100.7\t8080\ttcp\t-",
    "",
])

ZEEK_TSV_HTTP = "\n".join([
    "#separator \\x09",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tmethod\thost\turi\tstatus_code",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tstring\tstring\tstring\tcount",
    "1767261601.000000\tCxyz\t10.0.0.8\t4444\t203.0.113.5\t80\tGET\t203.0.113.5\t/shell.php\t200",
])

ZEEK_JSON = "\n".join([
    '{"_path":"conn","ts":1767261600.5,"uid":"CAbc123",'
    '"id":{"orig_h":"10.0.0.8","orig_p":4444,"resp_h":"203.0.113.5","resp_p":80},'
    '"proto":"tcp","service":"http"}',
    '{"_path":"http","ts":1767261601.0,"uid":"Cxyz",'
    '"id":{"orig_h":"10.0.0.8","orig_p":4444,"resp_h":"203.0.113.5","resp_p":80},'
    '"method":"POST","host":"203.0.113.5","uri":"/upload","status_code":200}',
    '{"_path":"dns","ts":1767261602.0,"uid":"Cdns",'
    '"id":{"orig_h":"10.0.0.8","orig_p":5300,"resp_h":"198.51.100.7","resp_p":53},'
    '"proto":"udp","query":"c2.example","rcode_name":"NOERROR"}',
    '{"_path":"ssl","ts":1767261603.0,"uid":"Cssl",'
    '"id":{"orig_h":"10.0.0.8","orig_p":5000,"resp_h":"198.51.100.7","resp_p":443},'
    '"server_name":"c2.example","version":"TLSv1.3"}',
    '{"_path":"notice","ts":1767261604.0,"uid":"Cnote",'
    '"id":{"orig_h":"203.0.113.9","orig_p":6667,"resp_h":"10.0.0.8","resp_p":12345},'
    '"note":"Scan::Port_Scan","msg":"10.0.0.8 scanned many ports"}',
    '{broken json',
])

#: ``files.log``-style TSV: no ``id.*`` columns, only tx/rx host sets.
ZEEK_TSV_FILES = "\n".join([
    "#separator \\x09",
    "#fields\tts\tfuid\ttx_hosts\trx_hosts",
    "#types\ttime\tstring\taddr\taddr",
    "1767261605.000000\tFabc\t198.51.100.20\t10.0.0.8",
])

# Capture-side times aligned with the fixtures above (2026-01-01 10:00 UTC).
# Epoch base for 2026-01-01T10:00:00Z is 1767261600.
T00 = "2026-01-01 10:00:00.400000"


def finding(summary, detail="", capture=T00, frame="", extra=None):
    record = {
        "kind": "webshell", "level": "warn", "frame": frame, "capture": capture,
        "time": "18:00:00", "feature": "webshell", "checkbox": "checkBox_10",
        "summary": summary, "detail": detail,
    }
    if extra:
        record["extra"] = extra
    return record


class SuricataEveTest(unittest.TestCase):
    def test_alerts_and_flows(self):
        events = evidence.parse_suricata_eve(EVE_TEXT)
        self.assertEqual(len(events), 4)
        alert = events[0]
        self.assertEqual(alert["source"], "suricata:eve")
        self.assertEqual(alert["type"], "alert")
        self.assertEqual(alert["src_ip"], "10.0.0.8")
        self.assertEqual(alert["src_port"], 4444)
        self.assertEqual(alert["dst_ip"], "203.0.113.5")
        self.assertEqual(alert["dst_port"], 80)
        self.assertEqual(alert["proto"], "tcp")
        self.assertEqual(alert["signature"], "ET WEB Shell")
        self.assertEqual(alert["category"], "Web Application Attack")
        self.assertEqual(alert["severity"], 1)
        self.assertEqual(alert["ref"], "42")
        self.assertIn("ET WEB Shell", alert["summary"])
        self.assertIn("[Web Application Attack]", alert["summary"])
        self.assertIn("severity 1", alert["summary"])
        self.assertAlmostEqual(alert["epoch"], 1767261600.1, places=3)

    def test_event_type_filter(self):
        events = evidence.parse_suricata_eve(EVE_TEXT, event_types=("alert", "flow"))
        self.assertEqual([event["type"] for event in events],
                         ["alert", "flow", "alert"])
        events = evidence.parse_suricata_eve(EVE_TEXT, event_types=["dns"])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "dns")

    def test_bad_lines_are_skipped(self):
        events = evidence.parse_suricata_eve("garbage\n[not json]\n\n")
        self.assertEqual(events, [])

    def test_empty_and_none(self):
        self.assertEqual(evidence.parse_suricata_eve(""), [])
        self.assertEqual(evidence.parse_suricata_eve(None), [])


class ZeekParseTest(unittest.TestCase):
    def test_tsv_conn_rows(self):
        events = evidence.parse_zeek(ZEEK_TSV)
        self.assertEqual(len(events), 2)
        first = events[0]
        self.assertEqual(first["source"], "zeek:tsv")
        self.assertEqual(first["type"], "conn")
        self.assertEqual(first["src_ip"], "10.0.0.8")
        self.assertEqual(first["src_port"], 4444)
        self.assertEqual(first["dst_ip"], "203.0.113.5")
        self.assertEqual(first["dst_port"], 80)
        self.assertEqual(first["proto"], "tcp")
        self.assertEqual(first["ref"], "CAbc123")
        self.assertAlmostEqual(first["epoch"], 1767261600.5, places=3)
        self.assertIn("10.0.0.8:4444 -> 203.0.113.5:80", first["summary"])
        self.assertIn("(tcp/http)", first["summary"])
        # "-"/unset service collapses out of the summary.
        self.assertNotIn("(tcp/-)", events[1]["summary"])
        self.assertIn("172.16.0.9:51000 -> 198.51.100.7:8080", events[1]["summary"])

    def test_tsv_http_rows(self):
        events = evidence.parse_zeek(ZEEK_TSV_HTTP)
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertEqual(event["type"], "http")
        self.assertEqual(event["summary"], "GET 203.0.113.5/shell.php -> 200")

    def test_json_streaming(self):
        events = evidence.parse_zeek(ZEEK_JSON)
        self.assertEqual(len(events), 5)
        types = [event["type"] for event in events]
        self.assertEqual(types, ["conn", "http", "dns", "ssl", "notice"])
        self.assertEqual(events[2]["summary"], "DNS 查询 c2.example (NOERROR)")
        self.assertEqual(events[3]["summary"], "TLS 会话 SNI=c2.example (TLSv1.3)")
        self.assertIn("Scan::Port_Scan", events[4]["summary"])
        self.assertEqual(events[4]["source"], "zeek:notice")
        self.assertEqual(events[4]["category"], "Scan::Port_Scan")

    def test_headers_and_bad_lines_tolerated(self):
        events = evidence.parse_zeek("#separator \\x09\nbroken\n{bad json}\n")
        self.assertEqual(events, [])

    def test_tsv_tx_rx_hosts_fallback(self):
        events = evidence.parse_zeek(ZEEK_TSV_FILES)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["src_ip"], "198.51.100.20")
        self.assertEqual(events[0]["dst_ip"], "10.0.0.8")

    def test_notice_direction_kept(self):
        events = evidence.parse_zeek(ZEEK_JSON)
        notice = events[4]
        self.assertEqual(notice["src_ip"], "203.0.113.9")
        self.assertEqual(notice["src_port"], 6667)
        self.assertEqual(notice["dst_ip"], "10.0.0.8")


class ParseEventsTest(unittest.TestCase):
    def test_mixed_eve_and_zeek(self):
        mixed = EVE_TEXT + "\n" + ZEEK_TSV
        events = evidence.parse_events(mixed)
        sources = {event["source"] for event in events}
        self.assertIn("suricata:eve", sources)
        self.assertIn("zeek:tsv", sources)
        self.assertEqual(len(events), 6)

    def test_malformed_input(self):
        self.assertEqual(evidence.parse_events(""), [])
        self.assertEqual(evidence.parse_events(None), [])
        self.assertEqual(evidence.parse_events("\n\nrandom text\n#x\n"), [])

    def test_parse_file(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.log"
            path.write_text(EVE_TEXT, encoding="utf-8")
            events = evidence.parse_file(path)
        self.assertEqual(len(events), 4)
        self.assertEqual(events[0]["source"], "suricata:eve")


class DetectFormatTest(unittest.TestCase):
    def test_known_formats(self):
        self.assertEqual(evidence.detect_format(EVE_TEXT), "suricata")
        self.assertEqual(evidence.detect_format(ZEEK_TSV), "zeek")
        self.assertEqual(evidence.detect_format(ZEEK_JSON), "zeek")

    def test_unknown_or_empty(self):
        self.assertEqual(evidence.detect_format(""), None)
        self.assertEqual(evidence.detect_format(None), None)
        self.assertEqual(evidence.detect_format("random text\n#comment\n"), None)


class ExtractTest(unittest.TestCase):
    def test_extract_ips(self):
        text = "attack from 10.0.0.8:4444 to 203.0.113.5 (dup 10.0.0.8), x 1.2.3.4.5"
        self.assertEqual(evidence.extract_ips(text),
                         ["10.0.0.8", "203.0.113.5"])
        self.assertEqual(evidence.extract_ips("版本 999.1.2.3 更新"), [])

    def test_extract_ports(self):
        self.assertEqual(evidence.extract_ports("443/tcp and port 8080 端口: 1337"),
                         [443, 8080, 1337])
        self.assertEqual(evidence.extract_ports("10.0.0.8:4444 hit"), [4444])
        self.assertEqual(evidence.extract_ports("no ports here"), [])
        self.assertEqual(evidence.extract_ports("99999/tcp"), [])

    def test_parse_timestamp_variants(self):
        base = evidence.parse_timestamp("2026-01-01T10:00:00+0000")
        self.assertAlmostEqual(evidence.parse_timestamp(1767261600.0), base,
                               delta=0.01)
        self.assertAlmostEqual(
            evidence.parse_timestamp("2026-01-01 10:00:00"), base, delta=0.01)
        self.assertAlmostEqual(
            evidence.parse_timestamp("2026-01-01T10:00:00Z"), base, delta=0.01)
        self.assertEqual(evidence.parse_timestamp("nonsense"), None)
        self.assertEqual(evidence.parse_timestamp(""), None)
        self.assertEqual(evidence.parse_timestamp(None), None)


class CorrelateTest(unittest.TestCase):
    def setUp(self):
        self.events = evidence.parse_events(EVE_TEXT + "\n" + ZEEK_JSON)
        self.alert, self.flow = self.events[0], self.events[1]

    def test_positive_ip_port_time(self):
        item = finding("10.0.0.8:4444 疑似 webshell 上传", detail="目标 203.0.113.5 port 80")
        pairs = evidence.correlate(self.events, [item])
        self.assertTrue(pairs)
        best = pairs[0]
        self.assertEqual(best["score"], 5)
        self.assertEqual(best["reasons"], ["ip:both", "port", "time"])
        self.assertTrue(best["port_overlap"])
        self.assertLessEqual(best["time_delta"], evidence.DEFAULT_WINDOW)
        self.assertEqual(best["event"]["type"], "alert")
        self.assertEqual(best["finding_index"], 0)

    def test_time_window_configurable(self):
        item = finding("10.0.0.8 -> 203.0.113.5 port 80",
                       capture="2026-01-01 10:20:00")
        # 20 minutes away: outside the default window but inside a 1800 s one.
        self.assertEqual(evidence.correlate(self.events, [item]), [])
        pairs = evidence.correlate(self.events, [item], window=1800)
        self.assertTrue(pairs)
        self.assertEqual(pairs[0]["reasons"], ["ip:both", "port", "time"])

    def test_no_time_keeps_ip_port_match(self):
        item = finding("10.0.0.8:4444 上传行为", detail="203.0.113.5:80")
        item.pop("capture")
        pairs = evidence.correlate(self.events, [item])
        self.assertTrue(pairs)
        self.assertEqual(pairs[0]["score"], 3)
        self.assertNotIn("time", pairs[0]["reasons"])

    def test_negative_wrong_ip(self):
        item = finding("172.16.0.9 -> 198.51.100.99 port 8080 时间异常")
        self.assertEqual(evidence.correlate(self.events, [item]), [])

    def test_negative_out_of_window_rejected(self):
        item = finding("10.0.0.8 -> 203.0.113.5 port 80",
                       capture="2026-01-01 23:59:00")
        self.assertEqual(evidence.correlate(self.events, [item]), [])

    def test_weak_single_ip_pair_without_port_or_time_rejected(self):
        # One shared IP + no port + no usable time = score 1 < min_score.
        item = finding("与 198.51.100.7 存在可疑交互", capture="")
        self.assertEqual(evidence.correlate(self.events, [item]), [])

    def test_single_ip_with_port_and_time_matches(self):
        item = finding("198.51.100.7 端口 443 上的可疑响应",
                       capture="2026-01-01 10:00:09.5")
        pairs = evidence.correlate(self.events, [item])
        self.assertTrue(pairs)
        self.assertEqual(pairs[0]["score"], 4)
        self.assertIn("port", pairs[0]["reasons"])
        self.assertIn("time", pairs[0]["reasons"])

    def test_min_score_raise(self):
        item = finding("10.0.0.8:4444 上传行为", detail="203.0.113.5:80")
        item.pop("capture")
        self.assertEqual(evidence.correlate(self.events, [item], min_score=4), [])

    def test_empty_inputs_and_skips(self):
        self.assertEqual(evidence.correlate([], [finding("x")]), [])
        self.assertEqual(evidence.correlate(self.events, []), [])
        pairs = evidence.correlate([None, "junk", self.alert],
                                   [finding("10.0.0.8 -> 203.0.113.5 port 80")])
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0]["event"]["type"], "alert")

    def test_explicit_ips_ports_override(self):
        item = finding("内网主机外联", capture="2026-01-01 10:00:00",
                       extra={"ips": "10.0.0.8,203.0.113.5", "ports": "4444,80"})
        pairs = evidence.correlate(self.events, [item])
        self.assertTrue(pairs)
        self.assertEqual(pairs[0]["score"], 5)

    def test_pairs_sorted_and_capped(self):
        items = [finding("10.0.0.8 -> 203.0.113.5 port 80",
                         capture=f"2026-01-01 10:00:0{index % 2}")
                 for index in range(4)]
        pairs = evidence.correlate(self.events, items)
        scores = [pair["score"] for pair in pairs]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertLessEqual(len(pairs), evidence.MAX_PAIRS)


if __name__ == "__main__":
    unittest.main()
