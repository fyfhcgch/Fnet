#!/usr/bin/env bash
# Install Fnet for the current user on Linux.
#
#   ./packaging/install.sh            # pip install --user + desktop entry
#   PREFIX=/usr/local sudo -E ./packaging/install.sh
#
# The script never touches the network capture configuration of Wireshark;
# Fnet only needs the `tshark` executable.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFIX="${PREFIX:-$HOME/.local}"
APPS="$PREFIX/share/applications"
ICONS="$PREFIX/share/icons/hicolor/48x48/apps"
DATA="$PREFIX/share/fnet"
PYTHON="${PYTHON:-python3}"

echo "==> 安装 Python 包到 $PREFIX"
if ! "$PYTHON" -m pip install --user --upgrade "$ROOT"; then
  cat >&2 <<'EOF'

安装失败。若发行版启用了 PEP 668（externally managed environment），
请改用虚拟环境或 pipx：

  python3 -m venv .venv && .venv/bin/pip install .
  # 或者
  pipx install .

也可以不安装，直接在仓库目录运行：

  python3 -m fnet
EOF
  exit 1
fi

echo "==> 安装图标与桌面入口"
mkdir -p "$APPS" "$ICONS" "$DATA"
cp -f "$ROOT/fnet/assets/favicon.ico" "$DATA/fnet.ico"
cp -f "$ROOT/fnet/assets/favicon.ico" "$ICONS/fnet.ico"

# Resolve the installed console script so the desktop entry works even when
# ~/.local/bin is not on the session PATH.
EXEC=""
for candidate in "$PREFIX/bin/fnet" "$HOME/.local/bin/fnet"; do
  if [[ -x "$candidate" ]]; then EXEC="$candidate"; break; fi
done
if [[ -z "$EXEC" ]]; then
  EXEC="$PYTHON -m fnet"
fi

sed -e "s|^Exec=.*|Exec=$EXEC|" \
    -e "s|^TryExec=.*|TryExec=$EXEC|" \
    -e "s|^Icon=.*|Icon=$DATA/fnet.ico|" \
    "$ROOT/packaging/fnet.desktop" > "$APPS/fnet.desktop"
chmod 644 "$APPS/fnet.desktop"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APPS" >/dev/null 2>&1 || true
fi

echo
echo "完成。可以从应用菜单启动 Fnet，或在终端运行："
echo "  fnet"
echo "首次运行请用 'fnet --doctor' 检查 tshark 是否可用。"
