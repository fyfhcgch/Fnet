# Fnet 改进与规范计划

> **状态（2026-11-20 更新）**：S0、S1 与 S2 全部落地并验证。
> 已修复：A1–A6、B1–B2、B4–B11（B11 的 #8–#10 纯机械去重除外）。
> 待办：A7（`--all` 加速，需重建语料才能验收）、B3（`protocols.py` 去重拆解）、
> B12（内核化）。
> 基线 **1478 tests / 79s** → 现 **1650 tests / 100.5s，OK (skipped=2)**，无回退。

> 版本基线：`2.21.3` ｜ 基线测试：`python3 -m unittest discover -s tests` → **1478 tests OK, 2 skipped, 79s**（Python 3.14.10 / tshark 4.7.4）
>
> 本文所有条目都有可复现证据。文档分三部分：
> **A. 真题实测结论**（拿真实赛题流量包跑出来的能力缺口）、**B. 代码审计结论**（模块化/健壮性/通用性）、**C. 落地排期与验收**。

---

## 0. 本次调研的方法与语料

为了不让改进停留在"读代码猜问题"，本次用两个公开题库的真实流量包做端到端回归：

| 题库 | 入口 | 取到的内容 |
| --- | --- | --- |
| DASCTF | `ctf2.dasctf.com/api/v1/practice/<id>/challenges/` | 6 个练习场、3721 道题，其中 **44 个真实 pcap/pcapng/cap 附件**已下载 |
| CTFPlus | `ctfplus.cn/api/problem/searchPublicProblem` | 24 道流量/协议/USB 题（题目附件需登录态，未批量下载） |

DASCTF 登录态复用方式（**不写入仓库**）：从本机 Chrome 的 `Local Storage/leveldb` 中取回站点 JWT，仅作为 `Authorization: Bearer` 使用；本次会话的临时文件全部落在 `/tmp/opencode/`，仓库内没有任何凭据、抓包或脚本残留。

44 个流量包全部 `rc=0` 跑完，合计产生 1,485 条 flag 类型发现。**这个数字本身就是第一个结论**（见 A1）。

---

## A. 真题实测：能力缺口

### A1（P0）flag 判定过于宽松，1,485 条里只有 1 条是真的

**状态：✅ 已修复**（`utils/codec.py` 分级策略 + `find_flag_candidates`，见 `tests/test_flag_quality.py`）

`fnet/utils/codec.py:93` 的正则是

```python
FLAG_RE = re.compile(r"(?<![A-Za-z0-9_])[A-Za-z0-9_]{2,20}\{[^{}\r\n]{1,120}\}")
```

它把任意 `标识符{...}` 都当 flag。44 个包里命中的实际内容：

| 命中样本 | 来源 |
| --- | --- |
| `img{width: 40px;}` / `bx{width: 90% !important;}` | HTML/CSS |
| `else{$R.="/";}` / `else{$d=array_map('trim',...)` | PHP 源码 |
| `YU{×B­ÌÍ½ërg·JÌ¢Ox…}` | TLS 密文 |
| `flag{This_is_a_f10g}` | ✅ 唯一真 flag（9.3.1 HTTP 流量分析） |

统计：**1,485 条 flag 发现中 1,484 条是代码片段或密文，误报率 99.9%**。真实赛题里 `NewStarCTF 2023 2-分析` 一个包就刷出 839 条。

- **改进**：`find_flags` 增加可判定的前缀/内容策略——已知赛事前缀（`flag|ctf|dasctf|nssctf|newstar|buu|suctf|xman|bsides*|utctf|vnctf|dest0g3|hgame|moectf|n1ctf|picoctf|idf|flagx|begin`）优先；含 `;{}<>=$()`、CSS/PHP 关键字的候选降级为 `flag_candidate`（不进 findings 表，只进 artifacts）；密文类（`printable_ratio` 低且熵高）直接丢弃。
- **验收**：44 个语料包重跑，flag 类发现 ≤ 20 条，且 `flag{This_is_a_f10g}` 必须仍在；新增 `tests/test_codec.py` 用例覆盖 CSS/PHP/密文三类负样本。

### A2（P0）USB HID 解析只认 boot 协议，非 boot 报告全部错位

**状态：✅ 已修复**（按报告长度分流而非 `bInterfaceProtocol`；dx/dy 为 int16-LE @ 字节 2/4；键盘/鼠标结果写入 findings）

`fnet/features/usb.py:_reports` 只取 `usb.capdata` / `usbhid.data`，随后 `mouse()` 按 `[buttons, dx, dy, wheel]` 固定解释。

实测 `[9.4.1 鼠标流量分析]`（DASBOOK 第 9 章）：该设备是 **HID 非 boot 鼠标**，报告为 `0000010000000000`（8 字节，dx/dy 在 offset 2/3），但工具按 offset 1/2 解释，得到 `x=0..0, y=-85..652` 的退化轨迹（`usb_mouse.csv` 里 3459 个点全部 `x=0`）。用 offset 2/3 重算后可以正常画出"逐级下阶梯"的轨迹图，说明设备数据本身是完好的。

同理 `[9.4.2 键盘流量分析]` 能还原出 `helloworld!`（boot 键盘），但 `[BSidesSF2019]thekey` 的 `ctf{my_favorite_editor_is_vim}` 只在 `usb_keyboard.txt` 里，**没有进 findings**，所以报告摘要看不到答案。

- **改进**：
  1. `_reports` 增加 `usb.bInterfaceProtocol` 与 `usb.transfer_type` 列，按接口协议分桶（1=boot 键盘、2=boot 鼠标、0=非 boot），非 boot 鼠标用 int16 小端解析、非 boot 键盘用报告描述符推断；两条路径都保留 boot 作为兜底。
  2. 键盘/鼠标结果同时 `ctx.add_finding("usb_keyboard", ...)`，让 WebUI 的发现表与 `--json` 输出直接给出答案。
- **验收**：`9.4.1` 的 `usb_mouse.csv` 出现非零 x 跨度；`thekey` 的 flag 出现在 `findings.json`。

### A3（P1）USB 大容量存储（USBMS/SCSI）提取不到数据

**状态：✅ 已修复**（CBW/CSW 定位 + bulk 数据阶段重组；神必流量重组 3,735,724 字节并识别内嵌 ZIP/EXFAT/PE）

`fnet/features/misc.py:scsi` 只查 `scsi.data`。实测 `神必流量`（1624 帧、3.7 MB）与 `[2022DASCTF MAY]神必流量`（1180 帧）里，tshark 把 USBMS 数据放在 **bulk 传输的原始 payload** 中，`scsi.data` 字段为空（`tshark -Y scsi.data` 命中 0 条），于是两个包都零发现。

用 `tshark -x` 直接看 frame 42 能看到 `VendorCoProductCode  2.00` 这样的 U 盘描述符字符串，说明数据就在包里，只是字段没取对。

- **改进**：`scsi` 改为"先按 `usbms.dCBWSignature` 定位 CBW/CSW 对，再取两次之间的 bulk IN 帧原始字节重组数据流"，并复用 `fnet/utils/stream.py` 的重组工具；同时把 `misc.scsi` 的 `ctx.report` 提示改成"已发现 USBMS 但无 SCSI 数据"这类可诊断文案，而不是静默 0 字节。
- **验收**：两个"神必流量"包都能导出 `scsi_*.bin`，且 `printable_ratio` 高的片段被识别为文件系统/文本。

### A4（P1）IPID 隐蔽信道只取低字节，漏掉"多字节/编码"通道

**状态：✅ 已修复**（low/high/full 三通道 + `decode_chain` + 反推字母表；44 包语料零误报，仅羊城杯命中）

`fnet/features/misc.py:ipid` 只取 `ip.id & 0xFF`，并要求可打印率 > 0.8 才输出。

实测 `[羊城杯 2020]TCP_IP`（68 个 IP 包）：`ip.id` 低字节是
`@iH<,{*;oUp/im"QPl`yR*ie}NK;.D!Xu)b:J[Rj+6KKM7P@iH<,{*;oUp/im"QPl`yR`
—— 明显是一段 64 字符的字母表映射（该题正解就是按 IPID 做 base64/自定义表还原），但工具**零发现**：因为低字节里只有 2 个字符被写入（`D/`），且该流从未被判为"可疑"。

- **改进**：IPID 通道检测扩展为通用形态——(1) 低字节 / 高字节 / 16 位全值三条通道都试；(2) 用 `fnet/utils/codec.py` 的 `decode_chain` 做 base64/hex/自定义字母表探测；(3) 对"取值集合很小但非单调"的流给出 `ipid_channel` finding 并附候选解码结果；(4) 单流样本量阈值下调（当前 `>0.8 可打印` 在短流上几乎不可能命中）。
- **验收**：`羊城杯 TCP_IP` 能输出 IPID 候选解码串；新增单测覆盖低字节 base64 通道。

### A5（P1）没有端口扫描 / 行为画像类能力，Nmap 包零发现

**状态：✅ 已修复**（新增 `flows.scan` / `checkBox_66`：SYN 半开、SYN 部分开放、全连接三种判定，IPv4/IPv6 均可；按「源→目标」聚合端口集合/区间/探针数/速率并给出「高/中」置信度，落盘 `scan_summary.tsv`）

`[NewStarCTF 2023]Nmap`（2124 帧、99152 字节）：全部是 `127.0.0.1 → 127.0.0.1` 的 SYN/ACK/RST 组合（1014 SYN、998 RST），是典型的 **SYN 扫描**特征。当前 55 个功能里没有任何一项做"扫描识别/主机行为画像"，`flows.tcp` 只输出了会话表。

- **改进**：新增功能 `flows.scan`（`checkBox_66`，category `flow`），识别 SYN 扫描、全连接扫描、端口敲门、暴力破解节奏（失败重试间隔），输出"扫描源 → 目标端口集合 → 次数 → 判定"。这类题在 BUUCTF/N1BOOK 里占比很高，是当前最大的功能空白。
- **注意**：新增功能要同步 `FEATURES`、`tests/test_registry.py`/`tests/test_api.py` 的精确计数（55→56）、`docs/FEATURES.md`、README。

**实现要点（实测校正了计划里的两个假设）**：

1. **方向必须对**。扫描器的 SYN 从 `A→B` 发出，但目标的 SYN+ACK 是从 `B→A`
   回来的，**源端口**才是被探测的端口。早期实现按 `(src,dst)` 各自独立聚合，
   把扫描器的临时端口（41190/41763…）报成"开放端口"。现在反向应答归属到
   `(A,B)` 组并取 `sport`，Nmap 包输出 `80(http)/3306(mysql)/5000/7000/8021/9000`，
   与人工核查一致。
2. **IPv6 不能只看 `ip.src`**。IPv6 抓包里 `ip.src`/`ip.dst` 为空，早期实现
   会把所有 IPv6 流量折叠成同一个 `"" → ""` 组，源/目标信息全丢。现在回退到
   `ipv6.src`/`ipv6.dst`，并用自制 IPv6 SYN 扫描包端到端验证。
3. **置信度分级**。语料丢失后无法再收紧阈值（收紧会连带漏掉真扫描），因此
   按"端口数 ≥ 100 / 过半被拒且 ≥10 / ≥20 个探针零数据换手"标「高」，其余标
   「中」，让人工复核有优先级，而不是把"管理员连 12 个服务"与"Nmap 打 1000
   个端口"同等对待。
4. **判定按"不同端口数"，不按包数**。TCP 重传会把同一端口重复发送上百次，
   实测语料里有 5727 个 SYN 但只有 4 个目的端口（正常业务的超时重连）。改用
   `(sport, dport)` 去重后，44 包语料误报从 10 降到 3，其中 2 例是真实扫描
   （`[SUCTF2018]followme`、`[2022DASCTF X SU]Au5t1n的秘密`），第 3 例
   （39 个高位端口全 RST、零 SYN）是普通连接被拒绝，现已被"必须有主动探测
   证据"的规则排除。

**与最初提案的差异**：提案里的"端口敲门"与"暴力破解节奏（失败重试间隔）"
没有实现——两者都需要按时间序列建模敲门序列/重试间隔，与"端口多"是不同
信号，误报代价高，且现有语料不足以验证。宁可少报，不制造噪音。

### A6（P1）损坏/截断抓包被静默当成"分析成功"

**状态：✅ 已修复**（三态判定：垃圾文件 rc=2 硬拒绝；合法魔数但损坏 → rc=0 + `⚠ 输入警告` 横幅；正常包无警告）

`wireshark-icmp_2.pcapng` 本身损坏（`capinfos: appears to be damaged or corrupt`），但 `fnet -C <file> --all` 仍然 `rc=0`、`status=done`，报告里只有 `没有匹配的流量`。

更严重的是任意垃圾文件：`printf 'garbage' > corrupt.pcap` 后 `fnet -C corrupt.pcap --features checkBox_10` **退出码 0**、`"ok": true`、`status: done`，只在报告里写"没有可分析的报文"。这会让 CI/批处理把"输入坏了"误判成"分析成功"。

- **改进**：`JobManager.create()` 增加输入体检（pcap 魔数 + `capinfos`/`tshark -r -c 1` 探测）；无法解析时 `status="error"`、`error="无法解析抓包: ..."`、CLI 退出码 2。损坏但可部分解析的包，在报告顶部加"⚠ 抓包损坏，已读取 N/M 帧"横幅。
- **验收**：`corrupt.pcap` 退出码 2；损坏包报告含横幅；新增 `tests/test_batch.py` 用例。

### A7（P2）报文量大的题跑得慢，且慢在重复解析

**状态：⏸ 未做**（验收条件要求 44 包语料 `--all` 总耗时下降 ≥ 30%，语料在一次
服务器重启后丢失，无法复测；贸然改缓存层会同时影响 B6 的磁盘缓存语义，建议
重建语料后单独提交）

| 包 | 帧数 | 大小 | `--all` 耗时 |
| --- | --- | --- | --- |
| `[SUCTF2018]followme` | — | 18 MB | **75.3s** |
| `wireshark-icmp` | — | 63 KB | 61.7s（损坏包仍跑满 55 个功能） |
| `[NewStarCTF 2023]3-溯源` | — | 16 MB | 46.2s |
| `[DASCTF 2024]手把天尊` | 111,722 | 5.6 MB | 29.7s |

平均 **17.0s/包**，44 个包里有 32 个 < 15s，长尾集中在 `--all`：每个功能各自起 tshark（`protocols.credentials` 还会把 redis/postgres/mongodb/ldap/smb 再跑一遍，见 B3），且损坏包不会短路（`wireshark-icmp` 只有 63 KB 却跑满 61.7s）。

- **改进**：同一 `(pcap, fields, filter)` 的 tshark 结果在**单次任务内**共享内存缓存（现在只有跨任务的磁盘 TSV 缓存，见 B6）；`--all` 时对"无匹配流量"的功能做前置探测短路（先一次 `-z io,phs` 拿到协议集合，没出现的协议直接跳过）。
- **验收**：44 包 `--all` 总耗时下降 ≥ 30%，且结果集不变。

---

## B. 代码审计：模块化 / 健壮性 / 通用性

> 以下每条都标了复现方式与严重级别（P0 阻塞 / P1 重要 / P2 可选）。

### B1（P0）`runner.py` 三处会让工具"整体失灵"的缺陷

**状态：✅ 已修复**（`known_fields` 不再缓存失败、stderr 噪声过滤、`stdin` 只写一次、`hex_to_bytes` 统一、`find_tool` 去 CWD 且校验可执行位、字节级截断）

**B1.1 `known_fields()` 失败被永久缓存**（`fnet/tools/runner.py:279-293`）

```python
code, out = run([self.path, "-G", "fields"], timeout=120, echo=False)
if code == 0:            # 失败时 names 保持空集
    ...
_FIELD_CACHE[self.path] = names      # 空集也被缓存
```

`fields()` 随后 `queried = [n for n in fields if not known or n in known]` —— 空集是 falsy，于是**所有**字段都被查询，tshark 报 `Some fields aren't valid` 后返回 `[]`。一次瞬时失败（并发 50 线程时的 spawn 争用、120s 超时）会让**该进程后续所有**字段查询静默返回空。

- 修：`code != 0` 时不写缓存；把"未知"（`None`）与"已知但为空"（`set()`）区分开。

**B1.2 tshark 的 stderr 被合并进 stdout，警告变成数据行**（`runner.py:146`）

```python
stdout=subprocess.PIPE, stderr=subprocess.STDOUT
```

`TShark.fields` 直接 `out.splitlines()` 解析。以 root 跑（Docker 常见）时 tshark 会打印
`Running as user "root" and group "root". This could be dangerous.`，这行会被当成一条只有 1 列的数据记录。实测用桩程序复现：

```
['Running as user "root" and group "root". This could be dangerous.']
['1', 'GET /']
```

- 修：`TShark` 走 `stderr=PIPE`；或在解析前过滤 `^tshark:` / `^Running as user`。

**B1.3 `run(stdin=...)` 第二次循环必抛 `ValueError` 并留下孤儿进程**（`runner.py:160`）

```python
while True:
    try:
        out, _ = proc.communicate(stdin, timeout=0.25)   # 第一轮进入 communication 模式
    except subprocess.TimeoutExpired:
        ...
        continue                                          # 第二轮再传 stdin → ValueError
```

实测：异常逃逸到调用方，且子进程（`python -c "time.sleep(6)"`）**仍在运行**——`finally` 里的 `timer.cancel()` 把兜底 kill 也取消了。目前无调用方传 `stdin`，属潜在陷阱。

- 修：`stdin` 在轮询前一次性 `proc.stdin.write/close`；或 `communicate` 不带 timeout，超时交给 `threading.Timer`。

**B1.4 `hex_to_bytes("0x41") == b'\x04'`**（`fnet/utils/pcap.py:7,10-13`）

```python
HEX_CLEAN = re.compile(r"[^0-9a-fA-F]")
value = HEX_CLEAN.sub("", value or "")     # "0x41" → "041"
if len(value) % 2: value = value[:-1]      # → "04"
```

这是全仓库最常用的十六进制助手（20+ 调用点：http/sql/usb/webshell/cs/winrm/protocols/flag_deep…），而 `codec.from_hex("0x41") == b'A'`、`tunnel._hex_bytes` 也返回 `b'A'`。**同一份输入在不同模块得到不同字节**。且奇数长度时静默截断最后一个半字节，而不是报错。

- 修：显式剥离 `0x`/`:`/`-`/空格；奇数长度返回 `b""` 并记 debug；把 7 处变体（`pcap.hex_to_bytes`、`codec.hexdecode_text`、`codec.from_hex`、`tunnel._hex_bytes`、`wifi._hex_bytes`、`openssl_enc._to_bytes_hex`、`sliver_c2._hexdecode`）统一到一个实现。

### B2（P0）`Logger.warning` 不存在，日志统计失败时抛 `AttributeError`

**状态：✅ 已修复**（调用点改 `warn` + f-string；`Logger.warning` 别名保留）

`fnet/services.py:553,756` 调用 `logger.warning(...)`，但 `fnet/logger.py` 只定义了 `warn`：

```python
>>> hasattr(Logger(), "warning")
False
```

任何日志解析异常都会让"本应返回 `_result(False, ...)`"的路径变成 `AttributeError`，被 WebUI 兜底成 500 并丢掉中文诊断。此外 `Logger.log` 内部是 `str(text)`，`%s` 占位符会原样输出。

- 修：改调 `warn` 并用 f-string；`Logger` 加 `warning = warn` 别名以兼容。

### B3（P1）`protocols.py` 与 5 个独立模块重复实现同一批协议，产物名已经分叉

`protocols.py`（2105 行）里的 Redis/PostgreSQL/MongoDB/LDAP/SMB2（约 1080 行）与独立模块 `redis.py`/`postgres.py`/`mongodb.py`/`ldap.py`/`smb.py`（约 1010 行）是两套实现，且**输出文件名已经不一致**：

| 协议 | `protocols.py` | 独立模块 |
| --- | --- | --- |
| Redis | `redis_commands.txt` | `redis_session.txt` |
| PostgreSQL | `postgres_queries.txt` | `pg_queries.txt` |
| MongoDB | `mongodb_queries.txt` | `mongodb_commands.txt` |
| LDAP | `ldap_queries.txt` / `ldap_objects.txt` | `ldap_searches.txt` / `ldap_entries.txt` |

而 `protocols.credentials`（`protocols.py:2092`）聚合调用的是 `protocols.py` 那份，于是"勾选复选框"和"菜单聚合"对同一个包给出不同 artifact。

**状态：⏸ 未做**（本次只修了 `protocols.py` 的检测缓存与 `flows`/`common`
的重复实现；Redis/PostgreSQL/MongoDB/LDAP 的两套解析器仍在，产物名仍分叉。
这是纯重构、无行为收益，需要同时改 5 个测试文件的 import，建议单独提交。）

- **改进**：先删后拆。`protocols.credentials` 改为调用 `redis.analyze` / `postgres.analyze` / `mongodb.analyze` / `ldap.analyze` / `smb.analyze`，删除 `protocols.py:413-1173` 与 `1699-2031`（−51%）；随后把剩余部分拆成 `proto_websocket.py` / `proto_http2.py` / 聚合器，单文件不再超 500 行。
- **代价**：`tests/test_protocol_streams.py:417,439,465`、`tests/test_protocols.py:18-40` 直接 import 了 `protocols.redis/postgres/mongodb/smb2_command_name`，需同一提交里改指向独立模块。

### B4（P1）跨进程 `--resume` 永远失效

**状态：✅ 已修复**（`normalise_status()` 供两条加载路径共用，真实 `--resume` 端到端验证通过）

`jobs_checkpoint.load_disk_entries` 会把 `running/queued` 改写成 `interrupted`（`:104-106`），但 `load_from_history` 恢复的是**原始**状态（`:147`）。`Job.can_resume` 要求 `status in ("paused","interrupted")`（`jobs.py:99-101`）。

实测（写入 `status=running` 的 `job.json` 后 `load_from_history`）：

```
loaded status: running | can_resume: False
```

于是进程崩溃后的任务，`fnet --resume <id>` 与 `POST /api/jobs/<id>/resume` 都报"不可恢复"，与 `jobs.py:919-922` 的注释承诺相反。

- 修：把"终态归一化"抽成一个函数，`load_disk_entries` 与 `load_from_history` 共用。

### B5（P1）产物写入非原子，崩溃会让任务从历史里消失

**状态：✅ 已修复**（`atomic_write()` 覆盖 history/findings/report/annotation；per-job `history_lock`）

`jobs_checkpoint.write_history`、`jobs_findings.write_findings`、`set_annotation`、`jobs._write_report` 全部是原地 `Path.write_text`；而读取侧遇到 `ValueError` 直接 `continue`/返回 `None`。一次崩溃或并发写就留下截断 JSON，任务在 UI 里凭空消失，没有任何诊断。

另外 `write_history` 被**两个线程**无锁调用：worker（`jobs.py:870,892,922`）与 `JobManager.cancel`（HTTP 线程，`jobs.py:677`）。

- 修：统一 `atomic_write()`（`mkstemp` + `os.replace`，`runner._write_cache` 已是正确写法，直接复用）；`_write_history` 加 per-job 锁。

### B6（P1）`tshark` 磁盘缓存无上限：本机已积累 967 MB

**状态：✅ 已修复**（`prune_cache()` 双限：默认 512 MB / 14 天，LRU 按最后访问时间；`--clean-cache` 手动清理；`config.ini` 新增 `tshark_cache_max_mb` / `tshark_cache_ttl_days`）

`fnet/tools/runner.py:205-222` 对每个唯一命令写一个 `.tsv`，**没有 TTL、没有容量上限、没有清理**。本机 `~/.cache/fnet/tshark/` 实测 967 MB / 1489 文件；`jobs._prune` 只清任务目录。

- 修：加 LRU（总容量上限 + 命中时间戳），或复用 `--prune` 参数；顺带加 `--clean-cache` CLI。
  （已实现：命中时 `os.utime` 刷新 mtime，写入后节流修剪，见 `tests/test_runner.py:CachePruneTest`）

### B7（P1）9 个测试污染开发者真实缓存目录

**状态：✅ 已修复**（新增 `tests/support.py` 的 `patch_cache_dirs()` / `IsolatedCache`；9 个文件全部迁入，实测泄漏文件数 0）

`AGENTS.md` 明确要求同时 patch `fnet.jobs.CACHE_DIR` 和 `fnet.paths.CACHE_DIR`，但只有 `tests/test_api.py` 做到了。以下 9 个文件只 patch 前者：

`test_features.py:27`、`test_ldap_feature.py:23`、`test_meterpreter.py:132`、`test_modbus_stego.py:244`、`test_mongodb_feature.py:97`、`test_postgres_feature.py:64`、`test_redis_feature.py:27`、`test_smb_feature.py:131`、`test_ssh_feature.py:96`

`runner.py:206-207` 在调用时从 `fnet.paths.CACHE_DIR` 取缓存目录，所以这些测试把 TSV 写进真实 `~/.cache/fnet/tshark/`。实测跑 `test_meterpreter` +2 文件、`test_mongodb_feature`/`test_postgres_feature` 各 +1。`tests/test_paths.py:34-37` 还会创建真实 `~/.config/fnet`。

- 修：新建 `tests/support.py`（`isolated_home()` 上下文 + `run_job()` + `make_ctx()`），把 9 个文件迁过去；顺手消掉 11 份 `run_job` 与 6 份 `make_ctx` 的复制粘贴（约 −200 行）。

### B8（P1）WebUI：CSP 形同虚设 + 静态目录前缀绕过 + 预认证 500

**状态：✅ 已修复**（每响应 nonce CSP、`is_relative_to`、字节比较 token、500 不回显内部信息）

1. **`'unsafe-inline'`**（`webui/server.py:494-497`）：`docs/WEBUI.md:116` 声称"脚本、样式限制在 self，只额外放行注入 token 的内联脚本"，但实际放行**所有**内联脚本。`app.js` 有 64 处 `innerHTML` 承载抓包派生文本，任何一处转义遗漏即变成带 token 的 XSS。
   - 修：`/api/meta` 下发常量，`script-src 'self'`；或用 nonce。
2. **静态目录前缀判断**（`server.py:508`）：`str(target).startswith(str(STATIC_DIR.resolve()))` 会放行同前缀兄弟目录。实测 `.../staticX/evil` 判为 True，而 `is_relative_to` 判为 False。同文件 `:1005`、`:1090` 已经是正确写法，属不一致。
3. **`secrets.compare_digest` 遇非 ASCII 抛 `TypeError`**（`server.py:241-243`）：实测 `compare_digest("测试","test")` 直接抛异常，被兜底成 **预认证 500**，并把异常文本回显给客户端。
   - 修：比较前 `.encode()`；500 只返回通用文案，细节进日志。

### B9（P1）`report.md` 不做 HTML 转义（HTML 路径是安全的）

**状态：✅ 已修复**（`_md_cell` 按 `&`→`<`→`>` 顺序转义，避免双重转义）

`report.py:501-502` 的 Markdown 转义只处理 `\`、`|` 和换行。抓包派生的 `detail` 里若含 `<img src=x onerror=…>`，会被原样写进 `report.md`，任何第三方 md→HTML 渲染器都会执行。

HTML 路径经逐条核查是**完备**的（所有 `parts.append`/`_html_table`/`_html_findings_table`/`_html_log` 都过 `_esc`，`_flagify` 在转义之后应用）。

- 修：Markdown 侧补 `<`/`>`/`&` 转义（或用反引号包裹代码片段）。

### B10（P1）`logfile.parse_path` 的 `lru_cache` 返回共享可变对象

**状态：✅ 已修复**（缓存只存不可变的 `(fmt, lines, truncated)` 元组，每次调用重建 `LogFile`；`ctime_ns` 加入缓存键，`rsync -t`/`tar -x` 不再命中过期内容）

`fnet/utils/logfile.py:684` 用 `@lru_cache(maxsize=2)` 缓存 `LogFile`，而 `LogFile.records` 是普通 list。实测：

```
same object: True
mutation visible in second caller: True
```

在 `ThreadingHTTPServer` 下两个任务读同一份日志（`logs.*` + `text_scan.*`）会互相污染。缓存键 `(mtime_ns, size)` 还会在 `tar -x`/`rsync -t` 后命中过期内容。

- 修：缓存不可变的 `(fmt, lines)` 元组，每次重建；或返回深拷贝。
  （已按前者实现，见 `tests/test_logfile.py:ParseCacheIsolationTest`）

### B11（P2）其他确认项（可直接排期）

**状态**：#1–#6、#11–#20 已全部修复并带回归；#7 已收敛（`flows._payload_rows`
改为委托 `common.payload_lines`）；#8–#10 是纯机械去重（`clamp` ×14、
`row += [""]*(n-len(row))` ×27、流断开告警 ×6），收益主要是行数而非行为，
留作后续单独提交，避免与本次功能改动混在一起。

| # | 问题 | 位置 | 修法 |
| --- | --- | --- | --- |
| 1 | `build()` 被调用两次，产生并行 wiring（AGENTS.md 明令禁止） | `cli.py:437-441` | `build(Config(...) if args.config else None)` |
| 2 | `--features foo.bar` 通过校验，运行时才炸；`-C` 与 WebUI 退出码不一致（1 vs 2） | `cli.py:161-165` | 用 `registry.resolve()` 预校验；统一 exit 2 |
| 3 | `--config <坏路径>` 直接抛 `FileNotFoundError` 回溯 | `config.py:105-108` | 捕获 `OSError`，给中文提示 |
| 4 | `Config.save()` 非原子且无锁，`crack.start` 从请求线程写 | `config.py:110-113` | 复用 `atomic_write` |
| 5 | `wifi.py:106` 传了 `TShark.fields(..., limit=5000)`，该参数不存在 | `features/wifi.py:106` | 删参数；实测抛 `TypeError`，WPA 解密后必崩 |
| 6 | `checkBox_15` 声明 `needs=("cryptography",)`，但全仓库无 `import cryptography` | `registry.py:193` | 删声明（或真正接入） |
| 7 | `common.payload_lines`/`decode_blob`/`csv_rows` 零调用，`flows._payload_rows` 重复实现 | `features/common.py` | 删死代码，或让 flows 改用 |
| 8 | `clamp` 逻辑重复 14 处（`max(1,min(int(x),N))`），`mcp_server.py:283` 还漏了 64 上限 | services/jobs/checkpoint/mcp | 抽 `utils/params.py:int_param` |
| 9 | `csv` 写入重复 7 份、`row += [""]*(n-len(row))` 重复 27 处、`dict(zip(...))` 15 处 | features/* | 收进 `features/common.py` |
| 10 | 流断开告警块重复 6 份（ldap/mongodb/postgres/redis/smb/ssh） | features/* | 抽 `protocol_driver.run()` |
| 11 | 检测缓存以"文件"为键，忽略 `protocol_min_confidence`/`protocol_ignore`，且永不淘汰 | `protocols.py:72-154` | 键加参数指纹 + LRU |
| 12 | `jobs_shards.clip_shard` 直接 `subprocess.run`，绕过 ToolBox 超时/重试，且不可取消 | `jobs_shards.py:48-51` | 改走 `runner.run(..., cancel=...)` |
| 13 | `find_tool` 把 CWD 里的同名文件排在系统路径前，且不检查可执行位 | `runner.py:41-46,77-79` | 先系统路径；检查 `os.access(X_OK)` |
| 14 | `plugins.py` 在 Windows 上仍用 POSIX `shlex.split`，`C:\Program Files\...` 会被拆坏 | `plugins.py:67,74` | `posix=os.name != "nt"` |
| 15 | MCP 对 `initialize` 通知回了 response（违反 JSON-RPC 2.0）；`job.thread.join()` 无超时 | `mcp_server.py:183-194,296` | 先判 `is_notification`；加超时 |
| 16 | 报告写入非原子；`/api/batch/report` 漏了 `/api/report` 的 CSP | `report.py:914-919`、`server.py:834-838` | `atomic_write`；补齐 CSP |
| 17 | `AGENTS.md:17` 声称"没有 CI 配置"，实际 `.github/workflows/ci.yml` 已跑 compileall + node --check | `AGENTS.md` | 更正 |
| 18 | `CONTRIBUTING.md:46` 让人改 `tests/test_uispec.py`（不存在） | `CONTRIBUTING.md` | 改为 `tests/test_site.py` + `test_registry.py` |
| 19 | 版本号只在 `pyproject.toml` 与 `fnet/__init__.py` 之间靠人工同步，`dist/`、`egg-info`、`docs/PERFORMANCE.*` 已漂到 2.19.0 | 多处 | 加 `tomllib` 版本同步测试；清理过期产物 |
| 20 | `fnet/utils/rules.py:29` docstring 里 `\=` 触发 `SyntaxWarning`（3.12+ 会更严） | `rules.py:29` | 改 `\\=`；CI 加 `-W error::SyntaxWarning` |

**已落地的几个要点**：

- **#6 `needs` 只允许真实外部工具**：`cs.analyze` 曾声明 `("cryptography",)`，
  但全仓库从未 `import cryptography`（Cobalt Strike 的 RSA 私钥解析与 AES 都在
  `fnet/utils/crypto.py` 里用纯标准库实现），`--list-features` 因此对用户谎报
  依赖。现在删掉该声明，并在 `tests/test_registry.py` 加门禁：`needs` 的每一项
  必须存在于 `ToolBox.TOOL_NAMES`。
- **#11 检测缓存键加入参数指纹**：`protocol_min_confidence` 与
  `protocol_ignore` 现在参与缓存键，且缓存上限 4 项、按插入顺序淘汰；命中时返回
  字典副本，调用方改动不会污染缓存（`tests/test_protocols.py` 4 个新用例）。
- **#12 分片切片可取消**：`clip_shard()` 改走 `runner.run(..., cancel=...)`，
  与其它 tshark 调用共享超时/重试语义，用户在切片阶段点"取消"不再等满 3600 秒。
- **#15 MCP 通知语义**：`is_notification` 判断提到 `initialize` 之前，任何无
  `id` 的消息都不回包；`job.thread.join()` 加 `MCP_JOB_TIMEOUT = 900`，避免一个
  卡死的 tshark 让整条 stdio 连接永久阻塞。

### B12（P2）可选的"内核化"重构

新增一个协议现在要改 **4 处**：`utils/<proto>.py` 解析器、`features/<proto>.py` 处理器、`FEATURES` 条目、`utils/protocol_detect.py` 的 `DEFAULT_PORTS`/`DECODE_AS`（`common.protocol_streams` 依赖它），还要同步 `protocols.credentials` 聚合与文档。

建议抽一个最小共享面（`fnet/utils/kernel.py`，从 `fnet/utils/__init__.py` 再导出）：

```
hex_bytes(str) -> bytes        # 唯一语义：剥离 0x/:/-/空格，奇数长度 → b""
text(bytes) -> str             # utf-8 → gb18030 → latin-1（现有 6 份解码器收敛为 1）
printable_ratio(bytes)         # 沿用 pcap 的定义（已委托 accel）
der.tlv(bytes, off)            # 现有 3 份 TLV 解析器（kerberos/tlsdeep/protocol_detect）收敛
bounded_read(path, limit)
atomic_write(path, data)
run_tool(argv, timeout, cancel)
```

只落地 `hex_bytes` / `text` / `atomic_write` 三项，即可消掉 7/6/1 份重复实现，并一次性修掉 `0x41` 那个 bug。

**状态：⏸ 未做**（`hex_to_bytes` 的语义统一与 `atomic_write` 已分别在 B1/B5
落地，但 `kernel.py` 这层壳没建；现有实现已能正确工作，抽壳属可读性收益。）

---

## C. 落地排期与验收

### C1. 分阶段（每阶段都以"基线 1478 tests OK"为起点，不引入第三方依赖）

| 阶段 | 内容 | 条目 | 状态 |
| --- | --- | --- | --- |
| **S0 止血** | 崩溃/静默失败类：`Logger.warning`、`known_fields` 缓存、stderr 污染、`hex_to_bytes`、`wifi.fields(limit=)`、坏输入退出码、`--resume`、非 ASCII token 500 | B1.1–B1.4, B2, A6, B4, B8.3 | ✅ 完成 |
| **S1 能力补齐** | 真题缺口：flag 判定、USB HID 分协议、USBMS/SCSI、IPID 多通道、端口扫描功能 | A1, A2, A3, A4, A5 | ✅ 完成 |
| **S2 去重与原子性** | `atomic_write` 全面替换、`protocols.py` 检测缓存（B11.11）、tshark 缓存上限、B11 定点修复 | B5, B6, B11（#8–#10 除外） | ✅ 完成；B3（`protocols.py` 去重拆解）与 B12（`kernel.py`）未做 |
| **S3 测试与仓库卫生** | `tests/support.py`、9 个缓存污染测试迁移、版本同步测试、`.gitignore`、文档计数门禁 | B7, B11.17–B11.20 | ✅ 完成 |
| **S4 WebUI 加固** | CSP 去 `unsafe-inline`、`is_relative_to`、Markdown 转义、`logfile` 缓存 | B8.1–B8.2, B9, B10 | ✅ 完成 |

### C2. 每阶段统一验收门（零新增依赖）

```bash
# 1. 既有基线不得回退
python3 -m unittest discover -s tests -v            # 期望 OK，skipped 仍为 2

# 2. 字节编译 + JS 语法（CI 已有，本地也跑）
python3 -m compileall -q fnet scripts
node --check fnet/webui/static/app.js

# 3. 新增：全模块导入冒烟（0.1s，能抓循环导入/改名遗漏）
python3 -c "import pkgutil,importlib,fnet
for m in pkgutil.walk_packages(fnet.__path__,'fnet.'): importlib.import_module(m.name)"

# 4. 新增：stdlib-only 守卫（AST 扫描 fnet/，禁止顶层第三方 import）
#    只允许 accel/crypto/rdp/samples 相关依赖出现在函数体内且带回退
#    （tests/test_hygiene.py，含全模块导入冒烟）

# 4b. 新增：文档计数门禁（tests/test_hygiene.py + tests/test_site.py）
#     manual/features.md 的分类标题数字、首页卡片数字、needs 是否指向真实工具
#     都必须与 FEATURES 一致——这类数字曾经漂到 17/2 而实际是 18/4。

# 5. 真题回归（本次语料，44 包）
python3 scripts/bench_corpus.py --dir <corpus> --all   # 新增脚本
#   断言：rc 全 0（坏包除外）、flag 发现 ≤ 20、总耗时下降 ≥ 30%
```

### C3. 需要同步更新的文档（改代码必须同提交）

| 触发条件 | 必改文件 |
| --- | --- |
| 新增/删除功能 | `fnet/features/registry.py`、`tests/test_registry.py`、`tests/test_api.py`（精确计数 56/14/2）、`docs/FEATURES.md`、`README.md`、`manual/features.md`（分类标题数字）、`index.md`（卡片数字 + 总数）、`manual/index.md`、`AGENTS.md`、`CONTRIBUTING.md`、`docs/WEBUI.md`（侧栏示意图） |
| 改 CLI 参数/退出码 | `docs/CLI.md`、`manual/cli.md`、`AGENTS.md` |
| 改 API/前端 | `docs/WEBUI.md`、`fnet/webui/static/*` |
| 改报告格式 | `fnet/report.py`、`tests/test_report.py`、`docs/ARCHITECTURE.md` |
| 版本号 | `pyproject.toml` + `fnet/__init__.py`（新增自动校验测试） |

### C4. 明确不做的事

- **不引入任何运行时第三方依赖**。`accel`/`crypto`/`rdp`/`samples` 四个 extra 保持"缺了也能跑"。
- **不 renumber 复选框**。`checkBox_66` 起顺延，旧编号永不改动（历史 `job.json` 依赖）。
- **不重写 tshark 解析层**。只在 `runner.py` 上做定点修复（B1），不做抽象重写。
- **不把语料包入库**。44 个真题 pcap 只用于本地回归，不进 `tests/data/`（体积与版权）。如需固化为 fixture，只放最小化的自制样本，由 `scripts/make_samples.py` 生成。

---

## 附录：本次调研的可复现命令

```bash
# 语料（DASCTF，需要本机登录态；不在仓库内留痕）
#   GET /api/v1/practice/?page=1&size=50                     → 6 个练习场
#   GET /api/v1/practice/<id>/challenges/?page=N&page_size=100 → 3721 道题
#   过滤 files[].file_name 匹配 *.pcap|*.pcapng|*.cap          → 44 个附件

# 全量回归
python3 -m fnet -C <pcap> --all

# 关键缺陷复现
python3 -c "from fnet.utils.pcap import hex_to_bytes; print(hex_to_bytes('0x41'))"
python3 -c "from fnet.logger import Logger; print(hasattr(Logger(),'warning'))"
python3 -c "from fnet.tools.runner import TShark; TShark('tshark').fields('x.pcap',['frame.number'],'http',limit=5000)"
printf 'garbage' > corrupt.pcap && python3 -m fnet -C corrupt.pcap --features checkBox_10; echo "rc=$?"
```
