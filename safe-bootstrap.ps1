<#
  safe-bootstrap.ps1  —  Safe Mode Layer 1（外部启动前校验 / 恢复器）

  为什么需要它：
    Pi 扩展无法察觉"自己没有被加载"。如果 safe-mode 扩展被删除、被 pi config 禁用
    或被改写，扩展本身发不出任何警告。只有这个位于 Pi Home **之外**的脚本能发现。

  它做什么：
    1. 校验 D:\pi-agent\safe.txt 存在、可读、hash 与 safe-manifest.json 一致
    2. 校验 D:\pi-agent\safe-mode\（规范副本）与
       D:\pi-agent\agent\extensions\safe-mode\（Pi 自动发现用的镜像）逐文件一致
    3. 镜像缺失/被改 → 从规范副本**恢复**并记账
    4. 校验 settings.json 没有把 safe-mode 强制排除（"-" 前缀）
    5. 记录 Pi 版本到 safe-integrity.log
    6. 全部通过 → 允许启动 Pi；任一失败 → 拒绝启动（除非 -Force）

  用法：
    safe-launch.cmd                 ← 平时用这个启动 Pi
    safe-bootstrap.ps1                      ← 校验 + **修复镜像**（会写 safe-integrity.log）
    safe-bootstrap.ps1 -VerifyOnly          ← **真只读**：只报告，不修复镜像，也不写日志
    safe-bootstrap.ps1 -VerifyOnly -Force   ← 只报告，且不因失败退出非零（排查用）
    safe-bootstrap.ps1 -Fix                 ← 显式要求修复镜像（等同于默认行为）

  注意：本脚本只读 safe.txt 与扩展文件。
        带 -VerifyOnly 时它**不写任何文件**（不修复镜像、不写日志）；
        不带该开关（或带 -Fix）时才写 safe-integrity.log，并可能从规范副本恢复镜像。
        它永远不会修改 safe.txt，也不会改 settings.json。
#>

[CmdletBinding()]
param(
    [switch]$VerifyOnly,
    [switch]$Fix,
    [switch]$Force,
    [switch]$Quiet
)

$doRepair = (-not $VerifyOnly) -or [bool]$Fix

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 路径解析（与 pi-extension/paths.ts 同一套规则，均可用环境变量覆盖）
#   SAFE_MODE_ROOT       Pi 根目录（默认：本脚本所在目录（= <root>\safe-mode）的上一级）
#   SAFE_MODE_HOME       Safe Mode 家目录（默认 <root>\safe-mode）
#   PI_CODING_AGENT_DIR  Pi agent 目录（默认 <root>\agent）
# ---------------------------------------------------------------------------
if ($env:SAFE_MODE_ROOT) { $Root = $env:SAFE_MODE_ROOT } else { $Root = Split-Path -Parent $PSScriptRoot }
if (-not (Test-Path -LiteralPath $Root)) {
    Write-Host "cannot resolve the Pi root: $Root" -ForegroundColor Red
    Write-Host 'set SAFE_MODE_ROOT to the directory that contains your safe-mode\ folder.' -ForegroundColor Red
    exit 2
}
if ($env:SAFE_MODE_HOME) { $SafeHome = $env:SAFE_MODE_HOME } else { $SafeHome = Join-Path $Root 'safe-mode' }
if ($env:PI_CODING_AGENT_DIR) { $AgentDir = $env:PI_CODING_AGENT_DIR } else { $AgentDir = Join-Path $Root 'agent' }

$Policy    = Join-Path $SafeHome 'safe.txt'
$Manifest  = Join-Path $SafeHome 'safe-manifest.json'
$Impl      = Join-Path $SafeHome 'pi-extension'
$MirrorDir = Join-Path $AgentDir 'extensions\safe-mode'
$Settings  = Join-Path $AgentDir 'settings.json'
$LogFile   = Join-Path $SafeHome 'safe-integrity.log'
if ($env:SAFE_MODE_PI_PACKAGE) { $PiPkg = $env:SAFE_MODE_PI_PACKAGE } else { $PiPkg = Join-Path $Root 'current\node_modules\@earendil-works\pi-coding-agent\package.json' }

$script:Problems = New-Object System.Collections.ArrayList
$script:Actions  = New-Object System.Collections.ArrayList

function Add-Problem([string]$text) { [void]$script:Problems.Add($text) }
function Add-Action([string]$text)  { [void]$script:Actions.Add($text) }

function Write-Log([string]$text) {
    $stamp = (Get-Date).ToString('s')
    try { Add-Content -LiteralPath $LogFile -Value "$stamp  $text" -Encoding UTF8 } catch { }
}

function Get-Sha256([string]$path) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $null }
    try { return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower() }
    catch { return $null }
}

function Get-Rel([string]$base, [string]$full) {
    $b = (Resolve-Path -LiteralPath $base).Path.TrimEnd('\')
    $f = (Resolve-Path -LiteralPath $full).Path
    if ($f.StartsWith($b, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $f.Substring($b.Length).TrimStart('\')
    }
    return $f
}

if (-not $VerifyOnly) {
    Write-Log "bootstrap: start (VerifyOnly=$VerifyOnly Fix=$Fix Force=$Force)"
}

# ---------------------------------------------------------------------------
# 1) safe.txt
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Policy -PathType Leaf)) {
    Add-Problem "policy file missing: $Policy"
    $policyHash = $null
} else {
    try {
        $null = Get-Content -LiteralPath $Policy -Raw -ErrorAction Stop
        $policyHash = Get-Sha256 $Policy
    } catch {
        Add-Problem "policy file unreadable: $Policy ($($_.Exception.Message))"
        $policyHash = $null
    }
}

# ---------------------------------------------------------------------------
# 2) manifest
# ---------------------------------------------------------------------------
$manifestData = $null
if (-not (Test-Path -LiteralPath $Manifest -PathType Leaf)) {
    Add-Problem "manifest missing: $Manifest (regenerate it before launching)"
} else {
    try {
        $manifestData = Get-Content -LiteralPath $Manifest -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($null -eq $manifestData.files) { Add-Problem "manifest has no files[] array"; $manifestData = $null }
    } catch {
        Add-Problem "manifest unreadable or invalid JSON: $Manifest ($($_.Exception.Message))"
        $manifestData = $null
    }
}

if ($null -ne $manifestData -and $null -ne $policyHash) {
    if ($policyHash -ne $manifestData.policySha256) {
        Add-Problem "safe.txt hash mismatch: expected $($manifestData.policySha256.Substring(0,12))…, found $($policyHash.Substring(0,12))…"
    }
}

# ---------------------------------------------------------------------------
# 3) 规范副本 <-> 镜像：逐文件校验，必要时恢复
# ---------------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $Impl -PathType Container)) {
    Add-Problem "canonical implementation directory missing: $Impl"
}
if (-not (Test-Path -LiteralPath $MirrorDir -PathType Container)) {
    if ($doRepair) {
        Add-Action "recreate mirror directory: $MirrorDir"
        try { New-Item -ItemType Directory -Path $MirrorDir -Force | Out-Null } catch {
            Add-Problem "cannot create mirror directory: $($_.Exception.Message)"
        }
    } else {
        Add-Action "mirror directory missing (verify-only: not created): $MirrorDir"
    }
}

if (Test-Path -LiteralPath $Impl -PathType Container) {
    $canonFiles = Get-ChildItem -LiteralPath $Impl -File -Recurse
    foreach ($file in $canonFiles) {
        $rel = Get-Rel $Impl $file.FullName
        $srcHash = Get-Sha256 $file.FullName
        $dstPath = Join-Path $MirrorDir $rel
        $dstHash = Get-Sha256 $dstPath

        if ($null -eq $dstHash) {
            if (-not $doRepair) {
                Add-Action "mirror file missing (verify-only: not restored): $rel"
                continue
            }
            Add-Action "restore missing mirror file: $rel"
            try {
                $dstDir = Split-Path -Parent $dstPath
                if (-not (Test-Path -LiteralPath $dstDir)) { New-Item -ItemType Directory -Path $dstDir -Force | Out-Null }
                Copy-Item -LiteralPath $file.FullName -Destination $dstPath -Force
            } catch { Add-Problem "restore failed for $rel`: $($_.Exception.Message)" }
            continue
        }
        if ($srcHash -ne $dstHash) {
            if (-not $doRepair) {
                Add-Action "mirror file MODIFIED (verify-only: not repaired): $rel"
                continue
            }
            Add-Action "restore modified mirror file: $rel"
            try { Copy-Item -LiteralPath $file.FullName -Destination $dstPath -Force }
            catch { Add-Problem "restore failed for $rel`: $($_.Exception.Message)" }
        }
    }
}

# ---------------------------------------------------------------------------
# 4) 清单中登记的其它文件（bootstrap / launcher / 镜像副本）
# ---------------------------------------------------------------------------
if ($null -ne $manifestData) {
    foreach ($entry in $manifestData.files) {
        $abs = Join-Path $Root ($entry.path -replace '/', '\')
        $hash = Get-Sha256 $abs
        if ($null -eq $hash) {
            Add-Problem "manifest entry missing on disk: $($entry.path)"
            continue
        }
        if ($hash -ne $entry.sha256) {
            # 镜像文件刚刚已按规范副本修复，重新取一次 hash 再判定
            $hash2 = Get-Sha256 $abs
            if ($hash2 -ne $entry.sha256) {
                Add-Problem "hash mismatch: $($entry.path) (expected $($entry.sha256.Substring(0,12))…, found $($hash2.Substring(0,12))…)"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 5) settings.json 是否把 safe-mode 强制排除
# ---------------------------------------------------------------------------
if (Test-Path -LiteralPath $Settings -PathType Leaf) {
    try {
        $raw = Get-Content -LiteralPath $Settings -Raw -Encoding UTF8
        if ($raw -match '"-\s*[^"]*safe-mode') {
            Add-Problem "settings.json force-excludes safe-mode (a ""-…safe-mode"" pattern was found); /safe will not be available"
        }
    } catch { Add-Problem "cannot read settings.json: $($_.Exception.Message)" }
} else {
    Add-Problem "settings.json not found: $Settings"
}

# ---------------------------------------------------------------------------
# 6) Pi 版本记录
# ---------------------------------------------------------------------------
$piVersion = '(unknown)'
if (Test-Path -LiteralPath $PiPkg -PathType Leaf) {
    try { $piVersion = (Get-Content -LiteralPath $PiPkg -Raw -Encoding UTF8 | ConvertFrom-Json).version }
    catch { }
} else {
    Add-Problem "Pi package.json not found: $PiPkg"
}

# ---------------------------------------------------------------------------
# 报告
# ---------------------------------------------------------------------------
if (-not $Quiet) {
    Write-Host ''
    Write-Host '  Safe Mode bootstrap (Layer 1)' -ForegroundColor Cyan
    Write-Host "  Pi version      : $piVersion"
    Write-Host ("  policy hash     : " + $(if ($policyHash) { $policyHash.Substring(0,12) } else { '(unavailable)' }))
    Write-Host "  policy file     : $Policy"
    Write-Host "  impl (canonical): $Impl"
    Write-Host "  mirror (Pi)     : $MirrorDir"
    Write-Host ''
    if ($script:Actions.Count -gt 0) {
        Write-Host $(if ($doRepair) { '  Repairs performed:' } else { '  Repairs skipped (verify-only; no file was written):' }) -ForegroundColor Yellow
        foreach ($a in $script:Actions) { Write-Host "    - $a" -ForegroundColor Yellow }
        Write-Host ''
    }
    if ($script:Problems.Count -eq 0) {
        Write-Host '  RESULT: OK — integrity verified' -ForegroundColor Green
    } else {
        Write-Host '  RESULT: FAILED' -ForegroundColor Red
        foreach ($p in $script:Problems) { Write-Host "    - $p" -ForegroundColor Red }
        Write-Host ''
        Write-Host '  Higher-risk operations are refused by Safe Mode while integrity is unconfirmed.'
        Write-Host '  Run this script from an interactive PowerShell to inspect the items above.' -ForegroundColor Red
    }
    Write-Host ''
}

if (-not $VerifyOnly) {
    Write-Log ("bootstrap: result=" + $(if ($script:Problems.Count -eq 0) { 'OK' } else { 'FAILED' }) +
               "; repairs=" + $script:Actions.Count + "; problems=" + $script:Problems.Count +
               "; pi=" + $piVersion)
}

if ($script:Problems.Count -gt 0) {
    if (-not $Force) { exit 2 }
    exit 0
}
exit 0
