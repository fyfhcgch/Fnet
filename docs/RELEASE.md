# 发布说明

Fnet 的运行时只依赖 Python 标准库与系统 `tshark`。PyPI 上的发行名是
**`fnet-ctf`**（`fnet` 已被另一个项目占用），安装后仍然提供 `fnet` 命令。

```bash
pipx install fnet-ctf
# 或
python3 -m pip install fnet-ctf
fnet --version
```

## 版本号

同一版本号必须出现在两处：

- `pyproject.toml` 的 `[project].version`
- `fnet/__init__.py` 的 `__version__`

发布前检查：

```bash
python3 - <<'PY'
import re
from pathlib import Path
from fnet import __version__
text = Path("pyproject.toml").read_text()
match = re.search(r'^version = "([^"]+)"', text, re.MULTILINE)
assert match and match.group(1) == __version__, (match, __version__)
print("version:", __version__)
PY
```

## 本地构建与校验

```bash
python3 -m venv /tmp/fnet-release
/tmp/fnet-release/bin/pip install --upgrade build twine
/tmp/fnet-release/bin/python -m build
/tmp/fnet-release/bin/python -m twine check dist/*
```

构建会生成 `dist/fnet_ctf-<version>-py3-none-any.whl` 与
`dist/fnet_ctf-<version>.tar.gz`。建议在干净虚拟环境中做一次安装冒烟：

```bash
python3 -m venv /tmp/fnet-install
/tmp/fnet-install/bin/pip install dist/fnet_ctf-*.whl
/tmp/fnet-install/bin/fnet --version
/tmp/fnet-install/bin/fnet --doctor
```

## GitHub Actions 发布

`.github/workflows/publish.yml` 在推送 `v*` 标签或手动触发时运行：

1. `build`：安装 `build`/`twine`，构建 sdist 与 wheel，并执行
   `twine check`，把 `dist/` 作为 artifact 上传。
2. `publish`：使用 **PyPI Trusted Publishing（OIDC）**，仓库中不保存
   API token。

首次发布前需要维护者在 PyPI 完成一次性配置：

1. 在 PyPI 创建/认领项目 `fnet-ctf`。
2. 添加 Trusted Publisher：
   - Owner：`fyfhcgch`
   - Repository：`Fnet`
   - Workflow：`publish.yml`
   - Environment：`pypi`
3. 在 GitHub 仓库的 `Settings → Environments` 创建 `pypi` 环境（可加保护
   规则，只允许标签发布）。

完成后打标签即可发布：

```bash
git tag v2.19.0
git push origin v2.19.0
```

## 发布前检查清单

- [ ] `python3 -m unittest discover -s tests -v` 全量通过
- [ ] `node --check fnet/webui/static/app.js` 通过
- [ ] `python3 scripts/bench.py --sizes 10,100,1000 --features default` 更新
      `docs/PERFORMANCE.md`
- [ ] README / TODO / docs/FEATURES.md 与 `FEATURES` 的 37 个功能一致
- [ ] `pyproject.toml` 与 `fnet/__init__.py` 版本一致
- [ ] `twine check dist/*` 通过
- [ ] 干净环境中 `fnet --version` 与 WebUI `/api/health` 正常

## 当前阻塞

截至 2.19.0，代码侧已完成构建配置、发布工作流与本文档；实际上传仍需要：

- PyPI 账号或 Trusted Publisher 授权（由维护者配置）；
- 确认 `fnet-ctf` 名称在目标索引可用（PyPI 查询为 404，表示尚未被占用）。

没有这些凭据时，任何自动化都无法代替维护者完成上传。
