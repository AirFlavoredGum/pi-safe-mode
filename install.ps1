<#
  install.ps1 — 把本仓库部署成一个可运行的 Safe Mode（Windows）

  做四件事：
    1. 解析目标位置（SAFE_MODE_ROOT / PI_CODING_AGENT_DIR / -Root，与 paths.ts 同一套规则）
    2. 把 safe.txt、三个脚本、pi-extension\ 复制到 <root>\safe-mode\
    3. 打印接下来你必须**亲手**做的两步（同步镜像 + 生成清单）
    4. 不碰任何运行态文件（safe-manifest.json / safe-state.json / 审计 / 日志）

  为什么不让脚本顺手把清单也生成了：
    清单是「可信基线」。按设计，只有人手动跑 safe-regen.ps1 并键入 yes 才能重设基线，
    否则「模型/脚本改了实现 → 自动洗白成可信」这条路就通了（见 safe.txt §20）。

  用法：
    # 首次安装（默认装到 Pi 根目录下的 safe-mode\）
    powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Root D:\pi-agent

    # 覆盖已有安装（会提醒你先备份）
    powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Root D:\pi-agent -Force

    # 只看看会做什么
    powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Root D:\pi-agent -WhatIf
#>
[CmdletBinding()]
param(
    [string]$Root,
    [string]$SafeHome,
    [switch]$Force,
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'
$Repo = $PSScriptRoot

if (-not (Test-Path -LiteralPath (Join-Path $Repo 'safe.txt'))) {
    Write-Host "install.ps1 must run from the repository root (safe.txt not found in $Repo)." -ForegroundColor Red
    exit 2
}

# ---- 1) 目标位置（与 pi-extension/paths.ts 同一套规则）----
if (-not $Root) { $Root = $env:SAFE_MODE_ROOT }
if (-not $Root -and $env:PI_CODING_AGENT_DIR) { $Root = Split-Path -Parent $env:PI_CODING_AGENT_DIR }
if (-not $Root) {
    Write-Host 'cannot determine the Pi root.' -ForegroundColor Red
    Write-Host 'pass -Root <dir> (the directory that contains your safe-mode\ folder), or set SAFE_MODE_ROOT.' -ForegroundColor Red
    exit 2
}
if (-not $SafeHome) { $SafeHome = $env:SAFE_MODE_HOME }
if (-not $SafeHome) { $SafeHome = Join-Path $Root 'safe-mode' }
if ($env:PI_CODING_AGENT_DIR) { $AgentDir = $env:PI_CODING_AGENT_DIR } else { $AgentDir = Join-Path $Root 'agent' }
$MirrorDir = Join-Path $AgentDir 'extensions\safe-mode'

Write-Host ''
Write-Host '  Pi root        : ' -NoNewline; Write-Host $Root -ForegroundColor Cyan
Write-Host '  Safe Mode home : ' -NoNewline; Write-Host $SafeHome -ForegroundColor Cyan
Write-Host '  Mirror (loaded): ' -NoNewline; Write-Host $MirrorDir -ForegroundColor Cyan
Write-Host ''

if ((Test-Path -LiteralPath (Join-Path $SafeHome 'safe-manifest.json')) -and -not $Force) {
    Write-Host "an existing install was detected ($SafeHome\safe-manifest.json)." -ForegroundColor Yellow
    Write-Host 'Re-run with -Force to overwrite its implementation and policy.' -ForegroundColor Yellow
    Write-Host 'Tip: back up safe.txt first if you have local policy edits.' -ForegroundColor Yellow
    exit 3
}

$copies = @(
    @{ From = (Join-Path $Repo 'safe.txt');            To = (Join-Path $SafeHome 'safe.txt') },
    @{ From = (Join-Path $Repo 'safe-bootstrap.ps1');  To = (Join-Path $SafeHome 'safe-bootstrap.ps1') },
    @{ From = (Join-Path $Repo 'safe-launch.cmd');     To = (Join-Path $SafeHome 'safe-launch.cmd') },
    @{ From = (Join-Path $Repo 'safe-regen.ps1');      To = (Join-Path $SafeHome 'safe-regen.ps1') },
    @{ From = (Join-Path $Repo 'README.md');           To = (Join-Path $SafeHome 'README.md') }
)

if ($WhatIf) {
    Write-Host 'WhatIf: would create/update:' -ForegroundColor Cyan
    foreach ($c in $copies) { Write-Host "  $($c.To)" }
    Write-Host "  $SafeHome\pi-extension\**  (implementation, canonical copy)"
    Write-Host ''
    Write-Host 'WhatIf: nothing was written. Note that the mirror is NOT updated by this script;' -ForegroundColor Cyan
    Write-Host 'WhatIf: run safe-bootstrap.ps1 -Fix afterwards to sync it.' -ForegroundColor Cyan
    exit 0
}

# ---- 2) 复制 ----
New-Item -ItemType Directory -Path $SafeHome -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $SafeHome 'pi-extension') -Force | Out-Null

foreach ($c in $copies) {
    Copy-Item -LiteralPath $c.From -Destination $c.To -Force
    Write-Host "  copied $($c.To)"
}
Copy-Item -LiteralPath (Join-Path $Repo 'pi-extension') -Destination $SafeHome -Recurse -Force
Write-Host "  copied $SafeHome\pi-extension\ (recursive)"
if (-not (Test-Path -LiteralPath $MirrorDir)) {
    New-Item -ItemType Directory -Path $MirrorDir -Force | Out-Null
    Write-Host "  created $MirrorDir"
}

# ---- 3) 接下来必须由人做的两步 ----
$bootstrap = Join-Path $SafeHome 'safe-bootstrap.ps1'
$regen = Join-Path $SafeHome 'safe-regen.ps1'
Write-Host ''
Write-Host 'Next steps (both are intentionally manual):' -ForegroundColor Yellow
Write-Host "  1. powershell -NoProfile -File `"$regen`"" -ForegroundColor Yellow
Write-Host '     (type yes at the prompt — this makes the files you just installed the trusted baseline)' -ForegroundColor Yellow
Write-Host "  2. powershell -NoProfile -File `"$bootstrap`" -Fix" -ForegroundColor Yellow
Write-Host '     (syncs the Pi extension mirror from the canonical copy)' -ForegroundColor Yellow
Write-Host ''
Write-Host "Then start pi and run /safe doctor — expect: Integrity: integrity OK" -ForegroundColor Green
Write-Host 'To check without writing anything: safe-bootstrap.ps1 -VerifyOnly' -ForegroundColor Green
Write-Host ''
Write-Host 'Reminder: this layer is tool-boundary policy enforcement, not an OS sandbox.' -ForegroundColor DarkGray
