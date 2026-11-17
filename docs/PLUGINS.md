# 插件与外部工具

Fnet 的「工具」菜单由 `fnet/plugins.py` 驱动：内置工具在
`BUILTIN_TOOLS` 中声明，用户添加的工具保存在**用户配置**的
`[plugins] execute_cmd`（JSON，`name -> argv`）里，不修改仓库内文件。

> 配置文件位置遵循 `FNET_HOME` 约定（见 AGENTS.md / `fnet/paths.py`）：
> 未设置时位于 XDG 用户配置目录，Windows 上为 `%APPDATA%\fnet`。
> 下文一律用相对说明，不写死绝对路径。

## 添加一个自己的工具

WebUI「工具」菜单 → 添加工具，或直接编辑配置：

```ini
[plugins]
execute_cmd = {"MD5sum": ["md5sum"]}
```

键为工具名，值为参数数组（Windows 也用数组，避免 shell 引号问题）。
运行时会调用 `PluginManager.run(key, target)`：`target` 通常是当前流量包
路径（由后端传入，可能是任务缓存里的副本，不是原始上传路径）。

## 内置工具是怎么声明的

```python
BUILTIN_TOOLS.append({
    "key": "capinfos",          # 唯一键
    "name": "CapInfos",         # 菜单显示名
    "kind": "tool",             # tool=外部命令, url=浏览器打开
    "target": "capinfos",       # 可执行文件名（走 PATH，不写死绝对路径）
    "description": "查看抓包文件统计信息",
})
```

- `kind: "tool"` 的条目经 `fnet/tools/runner.py` 执行：参数数组、无 shell、
  可取消，找不到命令时在 WebUI 给出明确提示，不影响其他功能。
- `kind: "url"` 的条目调用 `fnet/utils/system.open_url` 打开浏览器，
  例如把 CyberChef 指向内网部署：`target` 换成你的部署地址即可。

## 最小可用示例

给「工具」菜单加一个“用 tshark 统计协议分层”的入口：

```python
# fnet/plugins.py（或后续版本的插件加载点）
BUILTIN_TOOLS.append({
    "key": "protocol-stats", "name": "协议统计", "kind": "tool",
    "target": "tshark",
    "description": "tshark -r <pcap> -q -z io,phs 的协议分层统计",
})
```

用户工具等价配置：

```ini
[plugins]
execute_cmd = {"协议统计": ["tshark", "-q", "-z", "io,phs"]}
```

注意 `target` 参数由运行时追加到命令末尾，因此用户工具应写成
“命令 + 固定参数”的形式，最后一个位置留给流量包路径。
