# TODO：后续路线图

已完成的功能不再逐条保留，现状见 [docs/FEATURES.md](docs/FEATURES.md)、
[docs/PERFORMANCE.md](docs/PERFORMANCE.md) 与 `git log`。下面按“先解决真实
瓶颈，再扩展覆盖面”的顺序排列。

## 工程与性能

- [x] **流式上传**：multipart 边读边写临时文件，内存占用从 O(文件大小) 降到
      常量（`_MultipartStream` / `_stream_body`，见 `fnet/webui/server.py`）
- [x] **分块解析与断点续跑**：`job.json` 记录每个功能的完成状态，在功能边界
      暂停/恢复；无状态功能按帧区间分片，有状态功能（流重组、解密）整包执行
- [x] **大文件内存上限**：关键字检测按帧区间分块扫描，1 GB 抓包峰值 RSS
      从 OOM 降到约 150 MB（`count_frames` + `chunk_frames`）
- [x] **性能基准**：`scripts/bench.py` 生成 10MB / 100MB / 1GB 三档样本，
      记录每个功能的耗时与峰值 RSS，结果写入
      [docs/PERFORMANCE.md](docs/PERFORMANCE.md)
- [x] **GitHub Actions CI**：Python 3.10–3.13 矩阵 + `tshark`，跑全量 unittest
      与 `node --check`

## 协议与凭据

- [x] **DNS / ICMP 隧道深化**：分块按序重组（base32 / base64 / hex）、隧道
      时间线、解码数据落盘（`fnet/utils/tunnel.py`）
- [x] **Kerberos 全链路**：TGT/TGS 解密（keytab / 密码 / 原始密钥）、
      18200/13100/19800/19900/19600/19700 哈希、PAC 解析与用户时间线
- [x] **邮件协议**：IMAP / POP3 命令与附件还原，SMTP MIME 解析、附件哈希与
      投递链（`fnet/utils/mail.py`）
- [x] **MySQL 深化**：认证握手（`mysql_native_password` /
      `caching_sha2_password`）、结果集还原、`LOAD DATA` 与 `LOAD_FILE`
      读取的文件内容（`fnet/utils/mysql.py`）
- [x] **WPA 解密后取证**：已知 PSK 时解密 802.11 数据帧，再把明文交回 HTTP /
      DNS / 凭据等功能（`--wpa-psk`）

## 分析体验

- [x] **任务对比**：两个任务结果的 findings diff（新增/消失的凭据、flag、
      端点），WebUI 增加“对比基准”入口，CLI 支持 `--compare`
- [x] **自定义规则**：导入 YARA 子集或正则规则文件，命中结果写入 findings 并
      参与报告；未显式指定时回退到 `paths.rules_file`
- [x] **CLI JSON 输出**：`--json` 导出 findings 与统计，便于脚本与流水线消费

## 界面

- [x] **英文界面与语言切换**：界面壳与功能元数据
      （`title_en` / `description_en` / `name_en`），日志与报告保持中文
- [x] **实时抓包**：选择网卡开始抓包，停止后直接进入分析
- [x] **上传进度与取消**：大文件上传显示进度并支持中止（`Esc`）

## 分发与生态

- [x] **Docker 镜像**：内置 `tshark` 与可选工具，一条命令启动 WebUI；
      CI 的 `docker` job 会构建镜像并轮询 `/api/health` 做冒烟（本机验证
      需能访问 Docker Hub）
- [x] **包发布准备**：PyPI 名称 `fnet` 已被其他项目占用，发行名改为
      `fnet-ctf`（命令仍是 `fnet`）；`pyproject.toml`、`publish.yml`、
      `docs/RELEASE.md` 与本地 `build`/`twine check` 均已验证
- [ ] **实际上传 PyPI**：仍需要维护者在 PyPI 配置 `fnet-ctf` 的 Trusted
      Publisher（或账号凭据）并打 `v*` 标签；没有凭据时无法由代码侧完成
