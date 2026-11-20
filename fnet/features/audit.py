"""跨源审计日志关联（``checkBox_65`` / ``audit.correlate``）。

云原生入侵排查的日志通常是分开落盘的：容器运行时（docker / containerd）记录
"谁在容器里执行了什么"，Kubernetes apiserver 记录"哪个 Pod IP 请求了什么、
成功还是被拒"，存储 / 数据库审计记录"哪个客户端读写了什么"。单看任何一份
日志，高危记录都淹没在成千上万条正常记录里；只有把**同一时间窗口**里的执行
记录与另一份日志里的**成功**记录对齐，攻击链才会显形。

本功能做三件事：

1. 从 ``command`` / ``cmd`` / ``command_line`` / ``argv`` 一类字段提取命令，
   按权重打分识别下载执行、管道执行 shell、base64 解码执行、反弹 shell、
   nsenter / 容器 socket 逃逸、持久化与痕迹清理等高危模式；只读命令
   （``ls`` / ``cat`` / ``ps`` …）即使命中关键字也会降级，避免刷屏。
2. 按时间间隔把高危记录聚成簇，再在 ``log_extra_paths`` 指定的其它日志里
   搜索该时间窗口内的记录，挑出结果为"成功"的那几条（``Success: true``、
   HTTP 2xx / 101、``auth_result=accepted``、未命中失败关键字）。
   支持通用 ``key: value`` 日志、JSON Lines / CSV，以及 Kubernetes 审计
   事件的嵌套字段（``requestObject.command`` 数组、``responseStatus.code``、
   ``sourceIPs``、``requestReceivedTimestamp``）。
3. 对每条关联，给出执行侧的实体 IP 与关联侧的实体 IP（字段名一并保留，
   例如 ``docker_ip`` / ``pod_ip`` / ``client_ip``），并把两侧实体的**稀有度**
   作为置信度依据——在一份上万行的日志里只出现一次的 IP，远比出现上百次
   的 IP 更可能是被特意标记的目标。

参数
----
``log_extra_paths``
    需要一起关联的其它日志，逗号 / 分号 / 换行分隔，最多 8 个。主输入
    （``ctx.pcap``）始终参与，重复路径自动去重。
``log_correlate_window``
    关联时间窗口（秒），默认 5，范围 0–3600。
``log_cluster_gap``
    把高危执行聚成同一"活动簇"的最大间隔（秒），默认 60。
``log_risk_threshold``
    命令风险分阈值，默认 45，范围 1–100。

仅使用标准库，且不调用 tshark：日志任务在没有 Wireshark 的机器上也能跑。
"""
from __future__ import annotations

import bisect
import csv
import datetime as _dt
import io
import ipaddress
import math
import re
from collections import Counter
from pathlib import Path

from fnet.features.common import clean_cell, table
from fnet.features.logs import _MAX_FINDINGS_TOTAL as _JOB_FINDINGS_TOTAL
from fnet.features.registry import FeatureContext
from fnet.utils import logfile

#: 一次最多关联多少个附加日志文件。
_MAX_EXTRA_PATHS = 8
#: 高危命令最多展示 / 记录的条数，避免一份刷屏日志写爆报告。
_MAX_RISKY = 40
#: 最多分析的"活动簇"数量（按风险分从高到低）。
_MAX_CLUSTERS = 20
#: 单个簇里最多保留的关联候选数。
_MAX_CANDIDATES = 6
#: 本功能写入的结构化结果上限（日志任务共享 findings 列表，避免刷屏）。
_MAX_FINDINGS = 60
#: 「关联 IP 对」最多写入 findings / 报告表格的条数（完整列表在 CSV）。
_MAX_PAIR_FINDINGS = 10
#: 报告表格里最多展示的关联 IP 对条数。
_MAX_PAIR_ROWS = 20
#: 逐条「跨源关联」最多写入 findings 的条数（过程信息，优先级低于 IP 对）。
_MAX_CORRELATION_FINDINGS = 20
#: 每条记录检查一次取消信号的开销摊销。
_CANCEL_EVERY = 512

#: 命令风险特征表：``(正则, 中文标签, 权重)``。权重按"单独出现即可疑"到
#: "几乎必然是恶意"递增；命中多条会累加，最终截断到 100。
_RISK_PATTERNS: tuple[tuple[str, str, int], ...] = (
    (r"\|\s*(?:sudo\s+)?(?:ba|z|k)?sh\b", "管道直接执行 shell", 60),
    (r"\|\s*(?:python[0-9.]*|perl|ruby|php|node)\b", "管道执行解释器", 55),
    (r"\bbase64\s+(?:-d|--decode|-D)\b", "base64 解码后执行", 45),
    (r"\beval\b", "eval 执行", 40),
    (r"\b(?:curl|wget)\b[^|;\n]*\|\s*\S", "下载后直接管道执行", 50),
    (r"\b(?:curl|wget)\b[^|;\n]*(?:-o|--output|-O)\s*\S*/tmp/", "下载落地到 /tmp", 35),
    (r"/dev/(?:tcp|udp)/", "bash 反弹 shell", 70),
    (r"\bnc\b[^|;\n]*\s-[a-z]*e\s", "netcat 反弹 shell", 70),
    (r"\b(?:ba|z|k)?sh\s+-i\b", "交互式 shell", 40),
    (r"\bsocat\b", "socat 隧道", 40),
    (r"\b(?:insmod|modprobe)\b", "加载内核模块", 45),
    (r"\bnsenter\b", "nsenter 逃逸", 70),
    (r"/var/run/docker\.sock|/run/(?:docker\.sock|containerd/containerd\.sock)",
     "访问容器运行时 socket", 65),
    (r"/var/lib/kubelet|/etc/kubernetes/(?:admin|controller-manager)\.conf|"
     r"/var/run/secrets/kubernetes\.io", "访问集群凭据 / kubelet", 65),
    (r"\b(?:crontab|systemctl\s+enable)\b|/etc/cron", "写入持久化任务", 35),
    (r"(?:^|[;&|]\s*)(?:useradd|adduser|passwd)\b", "账号变更", 30),
    (r"\b(?:history\s+-c|\.bash_history|unset\s+HISTFILE)", "清理命令历史", 40),
    (r"\brm\s+-(?:[A-Za-z]*r[A-Za-z]*f|[A-Za-z]*f[A-Za-z]*r)\s+/(?:\s|$)",
     "删除根目录", 60),
    (r"\bshred\b", "破坏性删除", 30),
    (r"\b(?:nmap|masscan|zmap)\b", "内网扫描", 30),
    (r"\b(?:mimikatz|procdump|lsass)\b", "凭据窃取", 60),
    (r"\b(?:curl|wget)\b\s+https?://(?:\d{1,3}\.){3}\d{1,3}", "直连 IP 下载", 30),
    (r"\bchmod\s+(?:[0-7]*[1357](?:\s|$)|\+x\b)", "赋予可执行权限", 25),
    (r"\b(?:python[0-9.]*|perl|ruby)\s+-[ce]\b[^|;\n]*"
     r"(?:socket|pty|subprocess|os\.system|base64)", "解释器内联执行可疑代码", 60),
)

#: 只读 / 信息收集类命令前缀。命中它且没有强特征时，风险分被压到阈值以下，
#: 这样 ``find / -name '*.log'``、``ps aux`` 这类巡检命令不会淹没真实告警。
_READONLY_RE = re.compile(
    r"^\s*(?:sudo\s+)?(?:ls|cat|ps|df|free|uptime|whoami|id|pwd|hostname|uname|"
    r"env|mount|netstat|ss|ifconfig|ip|top|grep|egrep|find|tail|head|wc|stat|"
    r"date|echo|printf|sort|uniq|awk|sed|du|file|which|type|lsblk|lsof)\b",
    re.IGNORECASE,
)

#: 命中这些权重的特征时，只读前缀不再降级（例如 ``cat`` 读到 kubelet 凭据）。
_STRONG_WEIGHT = 50
#: 默认的命令风险阈值（``log_risk_threshold`` 缺省值）。
_DEFAULT_THRESHOLD = 45

#: 命令可能出现的字段名。
_COMMAND_FIELDS = ("command", "cmd", "command_line", "cmdline", "argv",
                   "exec_command", "process", "process_command", "script")

#: 结果字段名，按优先级排列。
_STATE_FIELDS = ("success", "succeeded", "ok", "result", "outcome",
                 "auth_result", "status", "code", "response_code",
                 "http_status")

#: 通用解析器不认识的补充时间字段（Kubernetes 审计事件用这两个）。
_EXTRA_TIME_FIELDS = ("requestReceivedTimestamp", "stageTimestamp",
                      "eventTime", "creationTimestamp")

#: 实体 IP 字段名，按"越具体越优先"排列（``ip`` 放最后：它最泛，容易被
#: ``backup_ip`` 之类的字段抢占）。
_ENTITY_FIELDS = ("docker_ip", "container_ip", "pod_ip", "node_ip", "host_ip",
                  "client_ip", "remote_ip", "src_ip", "source_ip",
                  "source_ips", "ip_address", "address", "ip")

_TRUE_WORDS = frozenset({"true", "1", "yes", "y", "ok", "success",
                         "succeeded", "allowed", "accepted", "pass", "passed"})
_FALSE_WORDS = frozenset({"false", "0", "no", "n", "fail", "failed",
                          "failure", "denied", "rejected", "unauthorized",
                          "forbidden"})

_FAIL_RE = re.compile(
    r"unauthori[sz]ed|forbidden|denied|invalid|failed|failure|refused|"
    r"rejected|error|exception|panic|fatal|timeout|timed out",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# 参数与输入
# ---------------------------------------------------------------------------
def _int_param(value, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _float_param(value, default: float) -> float:
    try:
        number = float(str(value).strip())
    except (TypeError, ValueError):
        return default
    return number if math.isfinite(number) else default


def _extra_paths(ctx: FeatureContext) -> list[str]:
    """``log_extra_paths`` → 去重后的附加日志路径列表。"""
    raw = str(ctx.params.get("log_extra_paths") or "").strip()
    if not raw:
        return []
    found: list[str] = []
    skipped = 0
    for piece in re.split(r"[,;\n]+", raw):
        text = piece.strip().strip("\"'")
        if not text:
            continue
        path = Path(text).expanduser()
        if not path.exists():
            ctx.report(f"log_extra_paths 中的文件不存在，已跳过: {path}", "warn")
            continue
        if path.is_dir():
            ctx.report(f"log_extra_paths 指向目录，已跳过: {path}", "warn")
            continue
        if not logfile.is_log_input(path):
            ctx.report(f"log_extra_paths 中的文件不是可解析的文本日志，"
                       f"已跳过: {path}", "warn")
            continue
        # resolve() 让 ``/x/kube.log`` 与 ``/x/sub/../kube.log`` 判为同一份。
        resolved = str(path.resolve())
        if resolved in found:
            continue
        if len(found) >= _MAX_EXTRA_PATHS:
            skipped += 1
            continue
        found.append(resolved)
    if skipped:
        ctx.report(f"log_extra_paths 最多关联 {_MAX_EXTRA_PATHS} 个文件，"
                   f"其余 {skipped} 个已忽略", "warn")
    return found


def _load_many(ctx: FeatureContext) -> list[logfile.LogFile]:
    """主输入 + ``log_extra_paths``，返回解析成功的日志（主输入在前）。"""
    kind = getattr(ctx, "input_kind", "pcap")
    primary = str(getattr(ctx, "pcap", "") or "")
    paths: list[str] = []
    if primary and (kind == "log" or logfile.is_log_input(primary)):
        paths.append(str(Path(primary).expanduser().resolve()))
    for path in _extra_paths(ctx):
        if path not in paths:
            paths.append(path)
    logs: list[logfile.LogFile] = []
    for path in paths:
        log = logfile.parse_path(path)
        if not log.records:
            ctx.report(f"日志没有可解析的记录，已跳过: {path}", "warn")
            continue
        if log.truncated:
            ctx.report(f"日志超过解析上限（{logfile.MAX_RECORDS} 行），"
                       f"只分析了前 {len(log.records)} 条记录: {path}", "warn")
        logs.append(log)
    return logs


# ---------------------------------------------------------------------------
# 命令风险评分
# ---------------------------------------------------------------------------
def command_risk(command: str,
                 threshold: int = _DEFAULT_THRESHOLD) -> tuple[int, list[str]]:
    """返回 ``(0-100 的风险分, 命中的中文特征标签)``。

    ``threshold`` 决定只读命令被压到多低：命中只读前缀且没有强特征时，分数
    被压到 ``threshold - 1``，因此**一定**低于调用方的告警阈值。
    """
    text = str(command or "")
    if not text.strip():
        return 0, []
    labels: list[str] = []
    score = 0
    strong = False
    for pattern, label, weight in _RISK_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            labels.append(label)
            score += weight
            if weight >= _STRONG_WEIGHT:
                strong = True
    if not labels:
        return 0, []
    if not strong and _READONLY_RE.match(text):
        # 只读命令：压到阈值以下，除非另有强特征。
        score = min(score, max(0, threshold - 1))
    return min(score, 100), labels


def _command_of(record: logfile.LogRecord) -> str:
    """取出一条记录里完整的命令文本。

    通用 ``key: value`` 解析器把 ``|`` 当作分隔符，因此
    ``curl ... | base64 -d | bash`` 这类管道命令会被截断（甚至整段丢失）。
    只有在**确实被截断**时，才回到原始行定位命令标签、补全到行尾，再截掉后面
    属于其它字段的 ``, 字段名: 值`` 尾巴；否则直接信任解析结果——JSON/CSV 这类
    自带字段边界的格式不能往行尾扩，否则会吞掉后面的列。
    """
    raw = record.raw
    value = ""
    for name in _COMMAND_FIELDS:
        value = _field_value(record, name)
        if value:
            break
    if not _looks_truncated(record, value, raw):
        return value
    position = raw.find(value) if value else -1
    if position < 0:
        position = _command_label_offset(raw)
    if position < 0:
        return value
    text = _command_extent(raw[position:], bare_comma=not value)
    # 补全结果至少要和解析结果一致，否则说明定位错了，退回解析值。
    return text if text.startswith(value.strip()) else value


#: ``, Label:`` 形式的字段边界，命令到这里就该结束。
_FIELD_EDGE_RE = re.compile(r",\s*[A-Za-z][A-Za-z0-9 _./-]{0,30}\s*:")


def _command_extent(text: str, *, bare_comma: bool = False) -> str:
    """把命令文本截到下一个字段边界，并去掉尾部标点。

    边界优先取带标签的 ``, Label:``（例如 ``, Docker IP:  …``），因为标签是
    解析器自己也认得的字段边界。``bare_comma`` 为真时还会退一步在第一个
    ``, `` 处截断——用于"解析器整条命令都没拿到、后面跟着无标签说明文字"
    的情况（``Command: ls -l, note hello | bash``）。宁可少算风险，也不要把
    说明文字拼进命令造出假告警。
    """
    edge = _FIELD_EDGE_RE.search(text)
    cut = edge.start() if edge else len(text)
    if bare_comma:
        comma = text.find(", ")
        # 逗号落在引号里（``awk '{print $1, $2}'``）时不是字段边界。
        if 0 <= comma < cut and _quotes_balanced(text[:comma]):
            cut = comma
    return text[:cut].strip().rstrip(",;").strip()


def _quotes_balanced(text: str) -> bool:
    """``'`` 与 ``"`` 是否都已成对闭合。"""
    return all(text.count(quote) % 2 == 0 for quote in ("'", '"'))


def _looks_truncated(record: logfile.LogRecord, value: str, raw: str) -> bool:
    """解析出的命令是否被 ``|`` 等分隔符截断（需要回原文补全）。"""
    if raw.lstrip()[:1] == "{":
        return False        # JSON / JSONL：字段值自带边界
    if not value:
        # 解析器完全没拿到命令（管道在第一个值里），原文里还有标签就补全。
        return _command_label_offset(raw) >= 0
    if value not in raw:
        return False
    # 只有紧跟在该命令值之后的分隔符才算截断：``Command: curl … | bash``
    # 里 ``|`` 紧接命令，而 CSV 后续列、``Output: a | bash`` 里的 ``|``
    # 并不属于这条命令，不能把后面的列拼进来。
    tail = raw[raw.find(value) + len(value):]
    return bool(re.match(r"\s*(?:\||;|&&)", tail))


def _command_label_offset(raw: str) -> int:
    """原始行里命令字段值的起始下标（找不到返回 ``-1``）。

    标签前可以是行首，也可以是 ``,`` / ``;`` / ``:`` 之后——通用日志里常见
    ``agent: Command: …`` 这种"来源 + 字段"的嵌套写法。
    """
    for name in _COMMAND_FIELDS:
        label = re.escape(name)
        match = re.search(
            rf"(?:^|[,;:]\s*){label}\s*[:=]\s*", raw, re.IGNORECASE)
        if match:
            return match.end()
    return -1


# ---------------------------------------------------------------------------
# 字段读取（兼容 JSON 嵌套展平后的字段名）
# ---------------------------------------------------------------------------
def _indexed_values(record: logfile.LogRecord, name: str) -> list[str]:
    """展平 JSON 里 ``<prefix>_<name>_<序号>`` 的值，按序号排序。

    例：``requestObject.command = ["/bin/sh", "-c", "curl … | bash"]`` 会被
    展平成 ``requestObject.command.0`` … ``.2``，这里按序拼回一条命令。
    """
    key = logfile.norm_key(name)
    found: list[tuple[int, str]] = []
    for field_name, raw_value in record.fields.items():
        text = str(raw_value).strip()
        if not text:
            continue
        normalized = logfile.norm_key(field_name)
        tail = ""
        _, sep, after = normalized.rpartition("_" + key + "_")
        if sep:
            tail = after
        elif normalized.startswith(key + "_"):
            tail = normalized[len(key) + 1:]
        if tail.isdigit():
            found.append((int(tail), text))
    found.sort(key=lambda pair: pair[0])
    return [text for _, text in found]


def _field_value(record: logfile.LogRecord, name: str) -> str:
    """取字段值：先精确名，再 JSON 嵌套展平后的末段名，最后数组元素。

    这样既支持通用 KV 日志的 ``Command: …``，也支持 JSON 嵌套展平后的
    ``responseStatus.code``（末段 ``code``）；``requestObject.command.2``
    这类数组元素按序号拼回一条命令。只做"末段同名"匹配，避免把
    ``exit_code`` 当成 ``code``、``not_ok`` 当成 ``ok``。
    """
    return _field_match(record, name)[1]


def _field_match(record: logfile.LogRecord, name: str) -> tuple[str, str]:
    """``(实际命中的字段名, 值)``；没命中返回 ``("", "")``。

    与 :func:`_field_value` 相同，但把真实字段名一并返回，便于报告里写出
    ``client.ip`` 这种带层级的字段名，而不是笼统的 ``ip``。
    """
    value = record.value(name)
    if value:
        return name, value
    key = logfile.norm_key(name)
    for field_name, raw_value in record.fields.items():
        text = str(raw_value).strip()
        if not text:
            continue
        if logfile.norm_key(field_name) == key:
            return field_name, text
        # 只对 JSON 展平后的嵌套字段做匹配，而且要求**最后一段**就是该字段名
        # （``responseStatus.code`` → ``code``）。数组元素
        # （``requestObject.command.2``）留给 ``_indexed_values`` 处理。
        if "." not in field_name:
            continue
        if logfile.norm_key(field_name.rsplit(".", 1)[-1]) == key:
            return field_name, text
    joined = " ".join(_indexed_values(record, name))
    return (name, joined) if joined else ("", "")


def _record_epoch(record: logfile.LogRecord) -> float | None:
    """记录的时间戳；解析器没识别出的字段再补一次（如 k8s 审计事件）。

    Kubernetes 审计事件用 ``requestReceivedTimestamp`` / ``stageTimestamp``，
    不在 :mod:`fnet.utils.logfile` 的时间字段表里。没有时间就无法做跨源
    时间关联，所以这里补一轮。
    """
    if record.epoch is not None:
        return record.epoch
    for name in _EXTRA_TIME_FIELDS:
        value = _field_value(record, name)
        if not value:
            continue
        _, epoch = logfile.parse_time(value)
        if epoch is not None:
            return epoch
    return None


def _record_time(record: logfile.LogRecord) -> str:
    """展示用时间：解析器没给就退回原始时间字段。"""
    if record.time:
        return record.time
    for name in _EXTRA_TIME_FIELDS:
        value = _field_value(record, name)
        if value:
            _, epoch = logfile.parse_time(value)
            if epoch is not None:
                return _dt_from_epoch(epoch)
    return ""


def _dt_from_epoch(epoch: float) -> str:
    return _dt.datetime.fromtimestamp(epoch, tz=_dt.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S")


# ---------------------------------------------------------------------------
# 结果判定与实体提取
# ---------------------------------------------------------------------------
def success_state(record: logfile.LogRecord) -> bool | None:
    """``True`` / ``False`` / ``None``（无法判定）表示一条记录的结果。"""
    for name in _STATE_FIELDS:
        value = _field_value(record, name)
        if not value:
            continue
        low = value.strip().lower()
        if name in ("status", "code", "response_code", "http_status"):
            match = re.fullmatch(r"(\d{3})", low)
            if match:
                code = int(match.group(1))
                # 2xx/3xx 成功；101 Switching Protocols 是 exec/attach/
                # websocket 正常升级，也算成功。其余（含 4xx/5xx）失败。
                return 200 <= code < 400 or code == 101
            if low.isdigit():
                # 不是 3 位数字，就不是 HTTP 状态码（``exitCode: 0``），
                # 不能按 "0 / 1" 词表判成败，跳过该字段继续找别的信号。
                continue
            # 非数字状态（如 ``status: OK``）继续按下面的词表判定。
        if low in _TRUE_WORDS:
            return True
        if low in _FALSE_WORDS:
            return False
    if record.level == "good":
        return True
    if record.level in ("warn", "error"):
        return False
    if _FAIL_RE.search(record.message or record.raw):
        return False
    return None


def entity_ip(record: logfile.LogRecord,
              exclude: tuple[str, ...] = ()) -> tuple[str, str]:
    """``(字段名, IP)``；字段名用于在报告里说明 IP 的语义。

    ``exclude`` 里的 IP 会被跳过——例如命令文本里出现的 C2 地址，不能当成
    执行侧的实体 IP（否则会把"下载源"误报成"容器地址"）。
    """
    for name in _ENTITY_FIELDS:
        field, value = _field_match(record, name)
        if value and _is_ip(value) and value not in exclude:
            # 报出实际命中的字段名（可能是 ``client.ip`` 这种嵌套写法）。
            return field, value
    for value in record.ips:
        if _is_ip(value) and value not in exclude:
            return "", value
    return "", ""


def _is_ip(value: str) -> bool:
    """严格校验，避免把 ``dead`` / ``1:2`` 这类文本当成 IP。"""
    try:
        ipaddress.ip_address(str(value or "").strip())
    except ValueError:
        return False
    return True


def _finding(ctx: FeatureContext, state: dict, limit: int, summary: str, *,
             detail: str, level: str, extra: dict) -> None:
    """带配额的 ``add_finding``：配额用完就停止，日志行照常输出。

    ``state`` 是调用方持有的计数器（``written`` / ``dropped``），避免往
    ``ctx`` 上挂临时属性。``limit`` 是本次运行可用的结构化结果额度（已按
    job 共享配额裁剪）。
    """
    if state["written"] >= limit:
        state["dropped"] += 1
        return
    item = ctx.add_finding("log", summary, detail=detail, level=level,
                           extra=extra)
    if item is None:
        state["dropped"] += 1
    else:
        state["written"] += 1


def _ip_list(text: str) -> tuple[str, ...]:
    """命令文本里出现的 IP，用于把"下载源"排除出执行侧实体。"""
    return tuple(ip for ip in logfile.extract_ips(str(text or ""))
                 if _is_ip(ip))


def _budget_left(ctx: FeatureContext) -> int:
    """本任务还能写多少条结构化结果（与 logs.* 功能共享同一份配额）。"""
    return max(0, _JOB_FINDINGS_TOTAL - len(ctx.findings))


def _log_name(log: logfile.LogFile) -> str:
    return Path(log.path).name or log.path


#: 关联结果 CSV 的表头，空结果与有结果时保持一致。
_CORRELATION_HEADERS = ["时间", "执行侧位置", "命令", "风险分",
                        "关联侧位置", "关联记录", "关联实体 IP",
                        "该 IP 出现次数"]
#: 高危命令时间线 CSV 的表头。
_TIMELINE_HEADERS = ["风险分", "时间", "来源日志", "行号",
                     "实体字段", "实体 IP", "命令", "命中特征"]


# ---------------------------------------------------------------------------
# CSV 输出
# ---------------------------------------------------------------------------
def _csv_text(headers: list[str], rows) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(headers)
    for row in rows:
        writer.writerow(["" if cell is None else cell for cell in row])
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def _window_candidates(logs, timed_index, ip_counts, skip_index: int,
                       low: float, high: float,
                       ctx: FeatureContext) -> list[dict]:
    """时间窗口 ``[low, high]`` 内、除 ``skip_index`` 外其它日志的成功记录。"""
    candidates: list[dict] = []
    for index, log in enumerate(logs):
        if index == skip_index:
            continue
        stamps = timed_index.get(index) or []
        if not stamps:
            continue
        # 二分定位 [low, high] 区间，避免每个簇都全量扫一遍日志。
        start = bisect.bisect_left(stamps, low, key=lambda pair: pair[0])
        end = bisect.bisect_right(stamps, high, key=lambda pair: pair[0])
        for _, record in stamps[start:end]:
            ctx.check_cancel()
            if success_state(record) is not True:
                continue
            field, ip = entity_ip(record)
            ip_total = ip_counts[index].get(ip, 0) if ip else 0
            candidates.append({"log_index": index, "log": log,
                               "record": record, "ip_field": field,
                               "ip": ip, "ip_total": ip_total})
    return candidates


def correlate(ctx: FeatureContext) -> None:
    """高危执行记录识别 + 跨源时间关联。"""
    logs = _load_many(ctx)
    if not logs:
        kind = getattr(ctx, "input_kind", "pcap")
        if kind != "log" and not logfile.is_log_input(
                str(getattr(ctx, "pcap", "") or "")):
            ctx.report("当前输入不是日志文件，且未通过 log_extra_paths 指定"
                       "要关联的日志，跳过跨源日志关联", "warn")
        else:
            ctx.report("没有可分析的日志：请把日志作为输入，或用 "
                       "log_extra_paths 指定要关联的其它日志文件", "warn")
        return

    window = max(0.0, min(_float_param(
        ctx.params.get("log_correlate_window"), 5.0), 3600.0))
    gap = max(0.0, min(_float_param(
        ctx.params.get("log_cluster_gap"), 60.0), 86400.0))
    threshold = max(1, min(_int_param(
        ctx.params.get("log_risk_threshold"), _DEFAULT_THRESHOLD), 100))

    ctx.report(f"参与关联的日志 {len(logs)} 份：" +
               "、".join(f"{_log_name(log)}({len(log.records)} 条)"
                        for log in logs), "info")
    ctx.report(f"参数：关联窗口 ±{window:g} 秒，活动簇间隔 {gap:g} 秒，"
               f"命令风险阈值 {threshold}", "debug")
    if len(logs) == 1:
        ctx.report("只加载了一份日志：仅做高危命令识别；"
                   "跨源关联需要 log_extra_paths 指定其它日志", "warn")

    # 结构化结果与 logs.* 功能共享同一份 job.findings，这里只使用剩余额度。
    limit = min(_MAX_FINDINGS, _budget_left(ctx))
    if limit <= 0:
        ctx.report(f"本任务的结构化结果配额已用完（日志功能共享 "
                   f"{_JOB_FINDINGS_TOTAL} 条），本次只输出日志与 CSV", "warn")

    # -- 1. 扫描高危执行记录 -------------------------------------------
    seeds: list[dict] = []
    scanned = 0
    total = sum(len(log.records) for log in logs) or 1
    for index, log in enumerate(logs):
        for record in log.records:
            scanned += 1
            if scanned % _CANCEL_EVERY == 0:
                ctx.check_cancel()
                ctx.set_progress(min(40, 40 * scanned // total))
            command = _command_of(record)
            if not command:
                continue
            score, labels = command_risk(command, threshold)
            if score < threshold:
                continue
            # 命令里的地址（下载源/C2）不是执行侧实体，排除掉再取 IP。
            field, ip = entity_ip(record, _ip_list(command))
            seeds.append({"log_index": index, "log": log, "record": record,
                          "command": command, "score": score,
                          "labels": labels, "ip_field": field, "ip": ip,
                          "epoch": _record_epoch(record),
                          "time": _record_time(record)})

    ctx.report(f"扫描 {scanned} 条记录，命中高危命令 {len(seeds)} 条"
               f"（阈值 {threshold}）", "warn" if seeds else "good")

    if not seeds:
        ctx.report("未发现超过阈值的高危执行命令；可用 log_risk_threshold "
                   "调低阈值，或确认日志中是否存在 command 类字段", "info")
        ctx.write_output("audit_timeline.csv",
                         _csv_text(_TIMELINE_HEADERS, []))
        ctx.write_output("audit_correlations.csv",
                         _csv_text(_CORRELATION_HEADERS, []))
        ctx.set_progress(100)
        return

    seeds.sort(key=lambda item: (-item["score"],
                                 item["epoch"] if item["epoch"] is not None
                                 else float("inf")))
    table(ctx, "高危执行命令",
          ["风险分", "时间", "来源日志", "实体 IP", "命令", "命中特征"],
          [[str(seed["score"]), seed["time"] or "-",
            _log_name(seed["log"]),
            f"{seed['ip_field']}={seed['ip']}" if seed["ip"] else "-",
            seed["command"], "、".join(seed["labels"])]
           for seed in seeds[:_MAX_RISKY]], limit=_MAX_RISKY)
    if len(seeds) > _MAX_RISKY:
        ctx.report(f"共 {len(seeds)} 条高危命令，报告表格与 audit_timeline.csv "
                   f"只保留风险分最高的前 {_MAX_RISKY} 条", "warn")

    finding_state = {"written": 0, "dropped": 0}

    # -- 2. 按时间聚簇 ------------------------------------------------
    timed = [seed for seed in seeds if seed["epoch"] is not None]
    untimed = [seed for seed in seeds if seed["epoch"] is None]
    timed.sort(key=lambda item: item["epoch"])
    clusters: list[dict] = []
    for seed in timed:
        if clusters and seed["epoch"] - clusters[-1]["end"] <= gap:
            clusters[-1]["seeds"].append(seed)
            clusters[-1]["end"] = max(clusters[-1]["end"], seed["epoch"])
            clusters[-1]["score"] = max(clusters[-1]["score"], seed["score"])
        else:
            clusters.append({"start": seed["epoch"], "end": seed["epoch"],
                             "seeds": [seed], "score": seed["score"]})
    clusters.sort(key=lambda item: (-item["score"], item["start"]))
    for cluster in clusters:
        cluster["seeds"].sort(
            key=lambda item: (-item["score"], item["epoch"]))
    if len(clusters) > _MAX_CLUSTERS:
        ctx.report(f"共 {len(clusters)} 个高危活动簇，只对风险分最高的前 "
                   f"{_MAX_CLUSTERS} 个做跨源关联", "warn")

    # -- 3. 跨源关联 ---------------------------------------------------
    # 每个日志的实体 IP 出现次数，用来衡量"稀有度"（越低越可疑）；同时按
    # 时间排序一份索引，让每个簇只需二分定位时间窗口内的记录。
    ip_counts: dict[int, Counter] = {}
    timed_index: dict[int, list[tuple[float, logfile.LogRecord]]] = {}
    indexed = 0
    for index, log in enumerate(logs):
        counter: Counter = Counter()
        stamps: list[tuple[float, logfile.LogRecord]] = []
        for record in log.records:
            indexed += 1
            if indexed % _CANCEL_EVERY == 0:
                ctx.check_cancel()
                ctx.set_progress(min(70, 40 + 30 * indexed // total))
            _, ip = entity_ip(record)
            if ip:
                counter[ip] += 1
            epoch = _record_epoch(record)
            if epoch is not None:
                stamps.append((epoch, record))
        ip_counts[index] = counter
        stamps.sort(key=lambda pair: pair[0])
        timed_index[index] = stamps

    correlation_rows: list[list] = []
    pair_rows: list[list] = []
    correlation_findings: list[dict] = []
    pair_findings: list[dict] = []
    matched_clusters = 0
    candidates_capped = 0

    for position, cluster in enumerate(clusters[:_MAX_CLUSTERS]):
        ctx.check_cancel()
        ctx.set_progress(min(95, 70 + 25 * position // max(1, len(clusters))))
        low = cluster["start"] - window
        high = cluster["end"] + window
        # 依次尝试簇内的高危记录作为锚点（风险高者优先）。只排除锚点自己
        # 所在的日志，避免同一份日志自关联；其它日志即使也有高危记录
        # （例如 Kubernetes 审计里同样带 command 的 exec 事件）仍可参与。
        # 换锚点是因为"执行侧"应当是有可执行语义的那份日志——容器运行时
        # 记录通常没有 success 字段，Kubernetes 审计记录有；谁做锚点会影响
        # 能否在另一侧找到成功记录。
        anchor = None
        candidates: list[dict] = []
        tried: set[int] = set()
        for attempt in cluster["seeds"]:
            # 每份日志只试一次：同一份日志里的多条高危记录做锚点没有区别，
            # 真正需要换的是"另一份日志"。
            if attempt["log_index"] in tried:
                continue
            tried.add(attempt["log_index"])
            found = _window_candidates(
                logs, timed_index, ip_counts, attempt["log_index"],
                low, high, ctx)
            if found:
                anchor, candidates = attempt, found
                break
        if not candidates or anchor is None:
            continue
        # 同一份日志在同一时间窗口内只有一条成功记录 → 关联更确定；
        # 该记录的实体 IP 在自己日志里出现次数越少 → 越像被特意标记的目标。
        per_log: Counter = Counter(item["log_index"] for item in candidates)
        candidates.sort(key=lambda item: (per_log[item["log_index"]],
                                          item["ip_total"] or 10 ** 9,
                                          item["record"].line))
        best = candidates[:_MAX_CANDIDATES]
        matched_clusters += 1
        if len(candidates) > _MAX_CANDIDATES:
            candidates_capped += 1

        ctx.report(
            f"关联命中：{anchor['time'] or '无时间戳'} 的 "
            f"{clean_cell(anchor['command'], 80)} → "
            f"{_log_name(best[0]['log'])} 第 {best[0]['record'].line} 行",
            "warn")

        for item in best:
            record = item["record"]
            unique_note = ("该窗口内该日志唯一的成功记录"
                           if per_log[item["log_index"]] == 1
                           else f"该窗口内该日志有 {per_log[item['log_index']]} "
                                "条成功记录")
            rarity = (f"实体 {item['ip_field'] or 'ip'}={item['ip']} "
                      f"在该日志中出现 {item['ip_total']} 次"
                      if item["ip"] else "未取到实体 IP")
            correlation_rows.append([
                anchor["time"] or "-",
                f"{_log_name(anchor['log'])}:{anchor['record'].line}",
                clean_cell(anchor["command"], 120),
                anchor["score"],
                f"{_log_name(item['log'])}:{record.line}",
                clean_cell(record.raw, 160),
                f"{item['ip_field']}={item['ip']}" if item["ip"] else "-",
                item["ip_total"],
            ])
            correlation_findings.append({
                "summary": (
                    f"跨源关联：执行记录 ↔ {_log_name(item['log'])} 成功记录"
                    f"（{item['ip_field'] or 'ip'}={item['ip'] or '未知'}）"),
                "detail": (f"执行侧：{anchor['time'] or '无时间戳'} "
                           f"第 {anchor['record'].line} 行，"
                           f"{clean_cell(anchor['command'], 160)}；"
                           f"关联侧：第 {record.line} 行，"
                           f"{clean_cell(record.raw, 200)}；{unique_note}；"
                           f"{rarity}"),
                "level": "warn",
                "extra": {"time": anchor["time"],
                          "command": anchor["command"],
                          "risk": anchor["score"],
                          "exec_line": anchor["record"].line,
                          "exec_ip_field": anchor["ip_field"],
                          "exec_ip": anchor["ip"],
                          "match_log": _log_name(item["log"]),
                          "match_line": record.line,
                          "match_ip_field": item["ip_field"],
                          "match_ip": item["ip"],
                          "match_ip_total": item["ip_total"],
                          "window": window},
            })
            # 两侧都有实体 IP 时，单独给出一条"关联 IP 对"，便于直接抄走。
            if anchor["ip"] and item["ip"]:
                pair_rows.append([
                    anchor["time"] or "-",
                    anchor["ip_field"] or "ip", anchor["ip"],
                    item["ip_field"] or "ip", item["ip"],
                    clean_cell(anchor["command"], 100)])
                pair_findings.append({
                    "summary": (f"关联 IP 对：{anchor['ip_field'] or 'ip'}="
                                f"{anchor['ip']} ↔ "
                                f"{item['ip_field'] or 'ip'}={item['ip']}"),
                    "detail": (f"{anchor['time'] or '无时间戳'} 的 "
                               f"{clean_cell(anchor['command'], 160)} "
                               f"关联到该 IP 的成功记录"),
                    "level": "good",
                    "extra": {"exec_ip_field": anchor["ip_field"] or "ip",
                              "exec_ip": anchor["ip"],
                              "match_ip_field": item["ip_field"] or "ip",
                              "match_ip": item["ip"],
                              "time": anchor["time"]},
                })

    if not matched_clusters:
        ctx.report("高危执行记录在关联窗口内没有找到其它日志的成功记录："
                   "可用 log_extra_paths 补充日志，或调大 log_correlate_window",
                   "info")

    if candidates_capped:
        ctx.report(f"{candidates_capped} 个窗口内匹配到超过 {_MAX_CANDIDATES} 条"
                   f"成功记录，每个窗口只报告最可疑的 {_MAX_CANDIDATES} 条",
                   "warn")

    # -- 4. 关联 IP 对 ------------------------------------------------
    if pair_rows:
        # ``table`` 自带"仅显示前 N 条（共 M 条）"提示，完整列表在 CSV 里。
        table(ctx, "关联 IP 对（执行侧 → 关联侧）",
              ["时间", "执行侧字段", "执行侧 IP", "关联侧字段", "关联侧 IP", "命令"],
              pair_rows, limit=_MAX_PAIR_ROWS)

    # -- 5. 结构化结果 ------------------------------------------------
    # 按信息量从高到低写入：关联 IP 对（最终结论）→ 逐条关联 → 高危命令。
    # 额度紧张时优先保住结论，也不会像固定预留那样白白浪费剩余额度。
    capped: list[str] = []
    if len(pair_findings) > _MAX_PAIR_FINDINGS:
        capped.append(f"关联 IP 对 {len(pair_findings)} 组只写入前 "
                      f"{_MAX_PAIR_FINDINGS} 组")
    if len(correlation_findings) > _MAX_CORRELATION_FINDINGS:
        capped.append(f"逐条关联 {len(correlation_findings)} 条只写入前 "
                      f"{_MAX_CORRELATION_FINDINGS} 条")
    if capped:
        ctx.report("；".join(capped) + "（完整结果见 audit_correlations.csv）",
                   "warn")
    for payload in pair_findings[:_MAX_PAIR_FINDINGS]:
        _finding(ctx, finding_state, limit, **payload)
    for payload in correlation_findings[:_MAX_CORRELATION_FINDINGS]:
        _finding(ctx, finding_state, limit, **payload)
    for seed in seeds[:_MAX_RISKY]:
        record = seed["record"]
        _finding(
            ctx, finding_state, limit,
            f"高危容器/主机命令（风险 {seed['score']}）："
            f"{clean_cell(seed['command'], 90)}",
            detail=(f"第 {record.line} 行；{seed['time'] or '无时间戳'}；"
                    f"命中特征：{'、'.join(seed['labels'])}；"
                    f"实体 {seed['ip_field'] or 'ip'}={seed['ip'] or '未知'}"),
            level="warn",
            extra={"line": record.line, "time": seed["time"],
                   "command": seed["command"], "risk": seed["score"],
                   "labels": seed["labels"], "ip_field": seed["ip_field"],
                   "ip": seed["ip"], "log": _log_name(seed["log"])})

    if finding_state["dropped"]:
        ctx.report(f"结构化结果最多写入 {limit} 条（本功能上限 {_MAX_FINDINGS} "
                   f"条，且与其它日志功能共享 {_JOB_FINDINGS_TOTAL} 条），"
                   f"{finding_state['dropped']} 条未写入 findings；"
                   f"完整结果见 audit_correlations.csv / audit_timeline.csv",
                   "warn")

    # -- 6. 未带时间戳的高危命令 ---------------------------------------
    if untimed:
        ctx.report(f"另有 {len(untimed)} 条高危命令没有可解析的时间戳，"
                   "无法参与时间关联", "warn")

    ctx.write_output("audit_timeline.csv",
                     _csv_text(_TIMELINE_HEADERS,
                               [[seed["score"], seed["time"],
                                 _log_name(seed["log"]), seed["record"].line,
                                 seed["ip_field"], seed["ip"],
                                 seed["command"],
                                 "、".join(seed["labels"])]
                                for seed in seeds[:_MAX_RISKY]]))
    ctx.write_output("audit_correlations.csv",
                     _csv_text(_CORRELATION_HEADERS, correlation_rows))
    ctx.set_progress(100)
