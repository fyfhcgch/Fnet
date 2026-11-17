<#
Fnet Windows 一键安装（PowerShell）

与 `packaging/install.sh`（Linux）对齐的 Windows 安装路径：
安装/检查 `tshark` 与 Python，再以 pipx（或 pip）安装 `fnet-ctf`。
所有安装位置交给 winget/choco/pipx 决定，脚本不写死绝对路径。

用法：

```powershell
./install.ps1            # 全部安装
./install.ps1 -SkipTools # 只装 Python 侧
```

#>
[CmdletBinding()]
param(
    [switch]$SkipTools
)

$ErrorActionPreference = "Stop"

function Test-Command($Name) {
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

if (-not $SkipTools) {
    if (-not (Test-Command "tshark")) {
        Write-Host "[*] 未找到 tshark，尝试安装 Wireshark ..."
        if (Test-Command "winget") {
            winget install --id WiresharkFoundation.Wireshark -e --accept-source-agreements --accept-package-agreements
        } elseif (Test-Command "choco") {
            choco install -y wireshark
        } else {
            Write-Warning "未找到 winget 或 choco，请手动安装 Wireshark 并确认 tshark 在 PATH 中"
        }
    } else {
        Write-Host "[+] tshark 已安装：$(tshark -v | Select-Object -First 1)"
    }
}

if (-not (Test-Command "python")) {
    Write-Warning "未找到 python，请安装 Python 3.10+ 后重跑本脚本"
    exit 1
}

if (Test-Command "pipx") {
    pipx install fnet-ctf
} else {
    Write-Host "[*] 未找到 pipx，改用当前用户 pip 安装"
    python -m pip install --user fnet-ctf
}

python -m fnet --doctor
Write-Host "[+] 安装完成，运行 'fnet' 启动 WebUI（不要用管理员权限跑日常分析）"
