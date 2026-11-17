# 性能基准

本文件由 `scripts/bench.py` 生成，请勿手工编辑。每次发布前重新运行：

```bash
python3 scripts/bench.py --sizes 10,100,1000 --features default
```

## 运行环境

| 项目 | 值 |
| --- | --- |
| fnet | 2.19.0 |
| python | 3.14.10 |
| platform | Linux-7.3.4-zen2-2-zen-x86_64-with-glibc2.44 |
| cpu_count | 24 |
| tshark | TShark (Wireshark) 4.7.4. |
| generated | 2026-11-17 11:34:46 |

## 方法

- 抓包由脚本用标准库直接写出 pcap（1200 字节 UDP 包，含 DNS、明文与二进制载荷），不依赖 scapy。
- 每个功能在独立子进程中运行，只提交该功能，`tshark_cache=0`，因此耗时包含 tshark 解析成本。
- 峰值 RSS 取 `resource.getrusage(RUSAGE_SELF).ru_maxrss`；`RUSAGE_CHILDREN` 单独列出，表示 tshark 等外部工具的最大 RSS。
- 计时包含任务创建、报告与结构化结果落盘，单位为秒。同一台机器上重复运行会有 ±10% 波动。

## 结果

### 10.0 MB（实际 10,485,841 字节）

| 功能 | 状态 | 耗时 | 峰值 RSS | tshark 峰值 RSS | 结构化结果 |
| --- | --- | ---: | ---: | ---: | ---: |
| `checkBox_10` | done | 1.85 s | 254.9 MB | 161.4 MB | 210 |
| `checkBox_30` | done | 524 ms | 150.3 MB | 155.7 MB | 0 |
| **合计** | | **2.38 s** | | | |

### 100.0 MB（实际 104,858,628 字节）

| 功能 | 状态 | 耗时 | 峰值 RSS | tshark 峰值 RSS | 结构化结果 |
| --- | --- | ---: | ---: | ---: | ---: |
| `checkBox_10` | done | 4.13 s | 150.5 MB | 152.0 MB | 0 |
| `checkBox_30` | done | 1.51 s | 150.1 MB | 309.9 MB | 0 |
| **合计** | | **5.64 s** | | | |

### 1000.0 MB（实际 1,048,576,532 字节）

| 功能 | 状态 | 耗时 | 峰值 RSS | tshark 峰值 RSS | 结构化结果 |
| --- | --- | ---: | ---: | ---: | ---: |
| `checkBox_10` | done | 36.96 s | 150.4 MB | 152.1 MB | 0 |
| `checkBox_30` | done | 8.52 s | 149.8 MB | 1082.5 MB | 0 |
| **合计** | | **45.47 s** | | | |

