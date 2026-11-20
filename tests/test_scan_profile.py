"""端口扫描 / 行为画像（A5，``checkBox_66`` / ``flows.scan``）。

背景：``[NewStarCTF 2023]Nmap`` 是 2124 帧的 SYN 扫描（1024 个半开探针、
6 个开放端口），但此前 55 个功能里没有任何一项能识别它，``flows.tcp`` 只
输出了会话表。这些测试固定新的判定语义：

* 方向——扫描器发出的 SYN 与目标回来的 SYN+ACK 属于**同一组**，开放端口
  取反向应答的**源端口**（早期实现取错了，报出扫描器的临时端口）；
* 门槛——少量探测不报，避免把正常业务抖动当扫描；
* 三种形态——SYN 半开、SYN 部分开放、全连接。
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fnet.config import Config
from fnet.features.flows import (SCAN_MIN_PORTS, _port_ranges, scan,
                                 scan_profile)
from fnet.features.registry import FeatureContext
from fnet.logger import Logger


def row(frame, src, dst, sport, dport, syn=False, ack=False, rst=False,
        epoch=0.0, length=0, flags_str=""):
    """构造一行 ``tshark`` 输出（列顺序与 ``flows.scan`` 一致）。"""
    return [str(frame), src, dst, str(sport), str(dport),
            "True" if syn else "False", "True" if ack else "False",
            "True" if rst else "False", flags_str, str(epoch), str(length)]


class PortRangeTest(unittest.TestCase):
    def test_consecutive_ports_collapse(self):
        self.assertEqual(_port_ranges([21, 22, 23, 80, 443]),
                         "21-23,80,443")

    def test_single_port_stays_bare(self):
        self.assertEqual(_port_ranges([8080]), "8080")

    def test_duplicates_and_unordered_input(self):
        self.assertEqual(_port_ranges([443, 80, 443, 81]), "80-81,443")

    def test_empty_input(self):
        self.assertEqual(_port_ranges([]), "")

    def test_long_list_is_truncated(self):
        text = _port_ranges(list(range(0, 400, 2)), max_ranges=5)
        self.assertIn("共", text)
        self.assertTrue(text.startswith("0,2,4,6,8"))


class SynScanTest(unittest.TestCase):
    def _scan_rows(self, ports, open_ports=()):
        rows = []
        frame = 1
        for port in ports:
            rows.append(row(frame, "10.0.0.5", "10.0.0.9", 40000, port,
                             syn=True, epoch=frame))
            frame += 1
        for port in open_ports:
            rows.append(row(frame, "10.0.0.9", "10.0.0.5", port, 40000,
                             syn=True, ack=True, epoch=frame))
            frame += 1
        return rows

    def test_half_open_scan_is_detected(self):
        rows = self._scan_rows(range(1, 60))
        profile = scan_profile(rows)
        self.assertEqual(len(profile["scans"]), 1)
        scan = profile["scans"][0]
        self.assertEqual(scan["src"], "10.0.0.5")
        self.assertEqual(scan["dst"], "10.0.0.9")
        self.assertEqual(scan["kind"], "SYN 半开扫描")
        self.assertEqual(scan["probes"], 59)
        self.assertEqual(scan["open_ports"], 0)

    def test_open_ports_come_from_the_reverse_syn_ack(self):
        """回归：开放端口必须是目标回来的 SYN+ACK 的**源**端口。

        早期实现把反向应答当成 `10.0.0.9 → 10.0.0.5` 自己的一组，于是把
        扫描器的临时端口 40000 报成"开放端口"。
        """
        rows = self._scan_rows(range(1, 60), open_ports=[22, 80, 443])
        profile = scan_profile(rows)
        scan = profile["scans"][0]
        self.assertEqual(scan["open_port_list"], [22, 80, 443])
        self.assertEqual(scan["open_ports"], 3)
        self.assertNotIn(40000, scan["open_port_list"])
        self.assertEqual(scan["kind"], "SYN 扫描（部分端口开放）")

    def test_refused_ports_are_counted(self):
        rows = self._scan_rows(range(1, 30))
        rows.append(row(99, "10.0.0.9", "10.0.0.5", 25, 40000,
                        ack=True, rst=True, epoch=99))
        profile = scan_profile(rows)
        self.assertEqual(profile["scans"][0]["closed"], 1)

    def test_small_probe_count_is_not_a_scan(self):
        rows = self._scan_rows(range(1, SCAN_MIN_PORTS))
        profile = scan_profile(rows)
        self.assertEqual(profile["scans"], [])
        self.assertEqual(len(profile["flows"]), 1)
        self.assertFalse(profile["flows"][0]["is_scan"])

    def test_retransmissions_are_not_a_scan(self):
        """回归：同一端口的 SYN 重传不能被算成扫描。

        实测语料里有一组 5727 个 SYN 但只有 4 个目的端口——那是正常业务的
        超时重连。判定必须按**不同端口数**，而不是包数。
        """
        rows = []
        frame = 1
        for port in (80, 443, 8080, 3306):
            for _ in range(200):  # 每个端口重传 200 次
                rows.append(row(frame, "10.0.0.5", "10.0.0.9", 40000, port,
                                syn=True, epoch=float(frame)))
                frame += 1
        profile = scan_profile(rows)
        self.assertEqual(profile["scans"], [],
                         "4 个端口 × 200 次重传不是扫描")
        self.assertEqual(len(profile["flows"]), 1)
        self.assertEqual(profile["flows"][0]["syn_packets"], 800)
        self.assertEqual(len(profile["flows"][0]["ports"]), 4)

    def test_refusals_alone_are_not_a_scan(self):
        """回归：只有 RST 拒绝、没有任何 SYN 证据，不算扫描。

        实测语料里有一组 39 个高位端口全是 RST、零 SYN——那是普通连接
        被拒绝（服务没开），报成扫描属于误报。
        """
        rows = [row(frame, "10.0.0.9", "10.0.0.5", port, 40000,
                    ack=True, rst=True, epoch=float(frame))
                for frame, port in enumerate(range(40000, 40060), 1)]
        profile = scan_profile(rows)
        self.assertEqual(profile["scans"], [])

    def test_normal_traffic_is_not_flagged(self):
        rows = [
            row(1, "10.0.0.5", "10.0.0.9", 50000, 80, syn=True, epoch=1),
            row(2, "10.0.0.9", "10.0.0.5", 80, 50000, syn=True, ack=True, epoch=2),
            row(3, "10.0.0.5", "10.0.0.9", 50000, 80, ack=True, epoch=3, length=200),
        ]
        profile = scan_profile(rows)
        self.assertEqual(profile["scans"], [])


class ConnectScanTest(unittest.TestCase):
    def test_many_empty_sessions_is_a_connect_scan(self):
        rows = []
        frame = 1
        for port in range(1, 30):
            rows.append(row(frame, "10.0.0.5", "10.0.0.9", 40000, port,
                             syn=True, epoch=frame))
            frame += 1
            rows.append(row(frame, "10.0.0.9", "10.0.0.5", port, 40000,
                             syn=True, ack=True, epoch=frame))
            frame += 1
            rows.append(row(frame, "10.0.0.5", "10.0.0.9", 40000, port,
                             ack=True, epoch=frame))
            frame += 1
        profile = scan_profile(rows)
        self.assertEqual(len(profile["scans"]), 1)
        # 探针数已超过门槛，因此归类为 SYN 扫描（部分端口开放），
        # 但会话/数据统计必须正确。
        scan = profile["scans"][0]
        self.assertEqual(scan["sessions"], 29)
        self.assertEqual(scan["data_packets"], 0)

    def test_connect_scan_kind_without_syn_probes(self):
        """没有 SYN 记录（抓包起点在握手之后）时按全连接扫描判定。"""
        rows = []
        frame = 1
        for port in range(1, 40):
            rows.append(row(frame, "10.0.0.9", "10.0.0.5", port, 40000,
                             syn=True, ack=True, epoch=frame))
            frame += 1
        profile = scan_profile(rows)
        self.assertEqual(len(profile["scans"]), 1)
        self.assertEqual(profile["scans"][0]["kind"], "全连接扫描")


class ScanSummaryTsvTest(unittest.TestCase):
    """``scan_summary.tsv`` 每行字段数必须与表头一致。

    早期实现把「源 → 目标」拼成一列却仍写 9 列表头，下游按 TSV 解析时
    所有字段整体错位一格（源变成 "10.0.0.5 → 10.0.0.9"，判定列变成端口数）。
    """

    class _FakeTshark:
        def __init__(self, rows):
            self.rows = rows

        def fields(self, pcap, fields, display_filter="", extra=None,
                   cancel=None):
            return [list(item) for item in self.rows]

    def test_header_and_rows_have_the_same_column_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rows = [row(index, "10.0.0.5", "10.0.0.9", 40000, port,
                        syn=True, epoch=float(index))
                    for index, port in enumerate(range(1, 40), 1)]
            ctx = FeatureContext(
                config=Config(root / "config.ini"),
                logger=Logger(root / "fnet.log"),
                tshark=self._FakeTshark(rows),
                pcap=str(root / "x.pcap"),
                output_dir=root / "out",
            )
            scan(ctx)
            text = (root / "out" / "scan_summary.tsv").read_text(
                encoding="utf-8")
            lines = [line for line in text.splitlines() if line]
            self.assertGreaterEqual(len(lines), 2, "应写出表头与至少一条记录")
            header = lines[0].split("\t")
            self.assertEqual(header, ["源", "目标", "判定", "端口数", "目的端口",
                                      "SYN包", "开放", "拒绝", "置信度"])
            for line in lines[1:]:
                self.assertEqual(len(line.split("\t")), len(header), line)


class Ipv6ScanTest(unittest.TestCase):
    """IPv6 抓包里 ``ip.src`` 为空，必须回退到 ``ipv6.src``。

    否则所有 IPv6 流量都会折叠成同一个 ``"" → ""`` 组，源/目标信息全丢。
    """

    def test_ipv6_addresses_are_used_when_ip_fields_are_empty(self):
        rows = []
        for frame, port in enumerate(range(1, 40), 1):
            rows.append([str(frame), "", "", "40000", str(port),
                         "True", "False", "False", "", str(frame), "0",
                         "2001:db8::5", "2001:db8::9"])
        profile = scan_profile(rows)
        self.assertEqual(len(profile["scans"]), 1)
        scan = profile["scans"][0]
        self.assertEqual(scan["src"], "2001:db8::5")
        self.assertEqual(scan["dst"], "2001:db8::9")

    def test_ipv4_still_wins_when_present(self):
        rows = [row(i, "10.0.0.5", "10.0.0.9", 40000, port, syn=True,
                    epoch=float(i))
                for i, port in enumerate(range(1, 40), 1)]
        scan = scan_profile(rows)["scans"][0]
        self.assertEqual(scan["src"], "10.0.0.5")


class ScanConfidenceTest(unittest.TestCase):
    """置信度用于区分"铁证扫描"与"可能是正常多服务访问"。

    语料已丢，无法再收紧阈值（会连带漏掉真扫描），所以用置信度把
    "12 个端口"和"1000 个端口"分开，让人工复核有优先级。
    """

    def _rows(self, ports, payload=0):
        rows = []
        for frame, port in enumerate(ports, 1):
            rows.append(row(frame, "10.0.0.5", "10.0.0.9", 40000, port,
                            syn=True, epoch=float(frame)))
            if payload:
                rows.append(row(frame + 0.5, "10.0.0.5", "10.0.0.9", 40000,
                                port, ack=True, epoch=float(frame),
                                length=payload))
        return rows

    def test_hundreds_of_ports_is_high_confidence(self):
        scan = scan_profile(self._rows(range(1, 200)))["scans"][0]
        self.assertEqual(scan["confidence"], "高")

    def test_twenty_silent_probes_is_high_confidence(self):
        scan = scan_profile(self._rows(range(1, 30)))["scans"][0]
        self.assertEqual(scan["confidence"], "高")

    def test_a_dozen_ports_with_data_is_medium_confidence(self):
        scan = scan_profile(self._rows(range(1, 15), payload=200))["scans"][0]
        self.assertEqual(scan["confidence"], "中")

    def test_non_scan_has_no_confidence(self):
        profile = scan_profile(self._rows(range(1, 5)))
        self.assertEqual(profile["flows"][0]["confidence"], "")


class ScanRobustnessTest(unittest.TestCase):
    def test_short_rows_are_ignored(self):
        self.assertEqual(scan_profile([["1", "a"]]), {"flows": [], "scans": []})

    def test_non_numeric_ports_are_ignored(self):
        bad = ["1", "10.0.0.5", "10.0.0.9", "x", "y",
               "True", "False", "False", "", "1", "0"]
        self.assertEqual(scan_profile([bad])["flows"], [])

    def test_boolean_fields_accept_one_and_zero(self):
        rows = [["1", "10.0.0.5", "10.0.0.9", "40000", str(port),
                 "1", "0", "0", "", "1", "0"] for port in range(1, 40)]
        profile = scan_profile(rows)
        self.assertEqual(profile["scans"][0]["probes"], 39)

    def test_rate_and_duration(self):
        rows = [row(i, "10.0.0.5", "10.0.0.9", 40000, port,
                    syn=True, epoch=float(i)) for i, port in enumerate(range(1, 41), 1)]
        scan = scan_profile(rows)["scans"][0]
        self.assertGreater(scan["duration"], 0)
        self.assertGreater(scan["rate"], 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
