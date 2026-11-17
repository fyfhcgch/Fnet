# TODO：后续路线图

已完成的功能不再逐条保留，现状见 [docs/FEATURES.md](docs/FEATURES.md) 与
`git log`。下面按“先解决真实瓶颈，再扩展覆盖面”的顺序排列。

## 工程与性能（优先）

- [ ] **流式上传**：multipart 边读边写临时文件，内存占用从 O(文件大小) 降到常量
      （当前整包读入内存，1 GiB 上限下最容易 OOM）
- [ ] **分块解析与断点续跑**：`job.json` 记录每个功能的完成状态，在功能边界
      暂停/恢复；无状态功能按帧区间分片，有状态功能（流重组、解密）整包执行
- [ ] **性能基准**：`scripts/bench.py` 生成 10MB / 100MB / 1GB 三档样本，
      记录每个功能的耗时与峰值 RSS，结果写入 `docs/PERFORMANCE.md`
- [ ] **GitHub Actions CI**：Python 3.10–3.13 矩阵 + `tshark`，跑全量 unittest
      与 `node --check`

## 协议与凭据

- [ ] **DNS / ICMP 隧道深化**：分块按序重组（base32 / base64 / hex）、隧道时间线、
      解码数据落盘；目前只做单标签解码与长标签告警
- [ ] **Kerberos 全链路**：TGT/TGS 解密（keytab 或密码）、AES 19600/19700 格式、
      PAC 解析与用户枚举时间线；目前只覆盖 etype 23
- [ ] **邮件协议**：IMAP / POP3 命令与附件还原，SMTP MIME 解析、附件哈希与投递链
- [ ] **MySQL 深化**：认证握手（`mysql_native_password` / `caching_sha2_password`）、
      结果集还原、`LOAD DATA` 与 `LOAD_FILE` 读取的文件内容
- [ ] **WPA 解密后取证**：已知 PSK 时解密 802.11 数据帧，再把明文交回 HTTP / DNS /
      凭据等功能，补齐无线侧“从破解到取证”的链路

## 分析体验

- [ ] **任务对比**：两个任务结果的 findings diff（新增/消失的凭据、flag、端点），
      WebUI 增加“对比基准”入口
- [ ] **自定义规则**：导入 YARA 或正则规则文件，命中结果写入 findings 并参与报告
- [ ] **CLI JSON 输出**：`--json` 导出 findings 与统计，便于脚本与流水线消费

## 界面

- [ ] **英文界面与语言切换**：先做界面壳与功能元数据（`title_en` / `description_en`），
      日志与报告保持中文，后续再补翻译
- [ ] **实时抓包**：选择网卡开始抓包，停止后直接进入分析
- [ ] **上传进度与取消**：大文件上传显示进度并支持中止

## 分发与生态

- [ ] **Docker 镜像**：内置 `tshark` 与可选工具，一条命令启动 WebUI
- [ ] **包发布**：确认包名可用后发布到 PyPI，提供 `pipx install` 的安装方式
