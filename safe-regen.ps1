<#
  safe-regen.ps1  —  重新生成 Safe Mode 完整性清单 (D:\pi-agent\safe-mode\safe-manifest.json)

  何时需要：
    - 你修改了 D:\pi-agent\safe-mode\pi-extension\ 里的实现之后
    - 你修改了 D:\pi-agent\safe-mode\safe.txt 之后
    - 你修改了 safe-bootstrap.ps1 / safe-launch.cmd / safe-regen.ps1 之后

  为什么需要人工确认：
    重新生成清单 = 把"当前文件状态"认定为正确基线。如果模型能在无人确认的情况下
    重算清单，它就能把被篡改的实现"洗白"。所以本脚本**必须由你手动运行并键入 yes**。

  它只写 safe-manifest.json，不会改 safe.txt，也不会改实现。

  不纳入清单（刻意排除）：
    - safe.txt         → 通过 policySha256 单独登记（它不是"实现文件"）
    - safe.txt.bak     → 人工回滚备份，随时可被你替换
    - safe-manifest.json / safe-state.json / safe-integrity.log / safe-audit.jsonl（及轮转文件）
      → 会自己变动，纳入就会永远校验失败
    - backup\          → 实现备份目录，不是运行的一部分
#>

[CmdletBinding()]
param()

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

# 去掉尾部反斜杠（否则下面按 $Root 前缀切相对路径时会多切掉一个字符）
$Root = $Root.TrimEnd('\')
if ($SafeHome.Length -gt 3) { $SafeHome = $SafeHome.TrimEnd('\') }
if ($AgentDir.Length -gt 3) { $AgentDir = $AgentDir.TrimEnd('\') }

$Policy    = Join-Path $SafeHome 'safe.txt'
$Manifest  = Join-Path $SafeHome 'safe-manifest.json'
$Impl      = Join-Path $SafeHome 'pi-extension'
$MirrorDir = Join-Path $AgentDir 'extensions\safe-mode'
$Extras    = @(
    (Join-Path $SafeHome 'safe-bootstrap.ps1'),
    (Join-Path $SafeHome 'safe-launch.cmd'),
    (Join-Path $SafeHome 'safe-regen.ps1')
)
if ($env:SAFE_MODE_PI_PACKAGE) { $PiPkg = $env:SAFE_MODE_PI_PACKAGE } else { $PiPkg = Join-Path $Root 'current\node_modules\@earendil-works\pi-coding-agent\package.json' }

if (-not (Test-Path -LiteralPath $Policy -PathType Leaf)) {
    Write-Host "policy file missing: $Policy" -ForegroundColor Red
    exit 2
}

function Get-Rel([string]$base, [string]$full) {
    $b = (Resolve-Path -LiteralPath $base).Path.TrimEnd('\')
    $f = (Resolve-Path -LiteralPath $full).Path
    if ($f.StartsWith($b, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $f.Substring($b.Length).TrimStart('\')
    }
    return $f
}

$targets = New-Object System.Collections.ArrayList

# 1) 实现：规范副本 + 镜像（路径记为相对 Pi 根目录，便于跨两份副本比对）
foreach ($dir in @($Impl, $MirrorDir)) {
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        Write-Host "  required directory missing: $dir" -ForegroundColor Red
        Write-Host '  Refusing to write a baseline while one of the two copies is missing:' -ForegroundColor Red
        Write-Host '  the manifest would silently stop covering it. Run safe-bootstrap.ps1 -Fix first.' -ForegroundColor Red
        exit 2
    }
    foreach ($f in Get-ChildItem -LiteralPath $dir -File -Recurse) {
        [void]$targets.Add([pscustomobject]@{ Path = (Get-Rel $Root $f.FullName); Full = $f.FullName })
    }
}

# 2) 脚本（$Extras 允许绝对路径，也允许相对 Pi 根目录的路径）
foreach ($entry in $Extras) {
    $full = if ([System.IO.Path]::IsPathRooted($entry)) { $entry } else { Join-Path $Root $entry }
    if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
        Write-Host "  required file missing: $full" -ForegroundColor Red
        Write-Host '  Refusing to write a baseline that omits it: an incomplete manifest would stop' -ForegroundColor Red
        Write-Host '  detecting later tampering with that file.' -ForegroundColor Red
        exit 2
    }
    [void]$targets.Add([pscustomobject]@{ Path = (Get-Rel $Root $full); Full = $full })
}

$targets = $targets | Sort-Object Path -Unique

$policyHash = (Get-FileHash -LiteralPath $Policy -Algorithm SHA256).Hash.ToLower()

# 当前 Pi 版本：写进清单，供扩展启动时做"版本漂移"提醒（不做"兼容/不兼容"判定）
$piVersion = '(unknown)'
if (Test-Path -LiteralPath $PiPkg -PathType Leaf) {
    try { $piVersion = (Get-Content -LiteralPath $PiPkg -Raw -Encoding UTF8 | ConvertFrom-Json).version } catch { }
}

Write-Host ''
Write-Host '  Safe Mode — regenerate integrity manifest' -ForegroundColor Cyan
Write-Host ''
Write-Host "  policy        : $Policy"
Write-Host "  policy sha256 : $policyHash"
Write-Host "  pi version    : $piVersion"
Write-Host "  manifest      : $Manifest"
Write-Host ''
Write-Host "  files to record ($($targets.Count)):"
foreach ($t in $targets) { Write-Host "    - $($t.Path)" }
Write-Host ''
Write-Host '  This freezes the CURRENT file contents as the trusted baseline.' -ForegroundColor Yellow
Write-Host '  If any of those files were modified by something other than you,' -ForegroundColor Yellow
Write-Host '  stop now and inspect them first.' -ForegroundColor Yellow
Write-Host ''
$answer = Read-Host '  Type yes to regenerate the manifest'
if ($answer -ne 'yes') {
    Write-Host '  Aborted. Manifest unchanged.' -ForegroundColor Yellow
    exit 1
}

$files = New-Object System.Collections.ArrayList
foreach ($t in $targets) {
    $hash = (Get-FileHash -LiteralPath $t.Full -Algorithm SHA256).Hash.ToLower()
    $bytes = (Get-Item -LiteralPath $t.Full).Length
    [void]$files.Add([ordered]@{ path = $t.Path; sha256 = $hash; bytes = $bytes })
}

$manifestObject = [ordered]@{
    version      = 2
    generatedAt  = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    piVersion    = $piVersion
    home         = $SafeHome
    policyPath   = $Policy
    policySha256 = $policyHash
    files        = $files
}

$json = $manifestObject | ConvertTo-Json -Depth 6

# 关键：UTF-8 **无 BOM**，否则 JSON.parse 会失败
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($Manifest, $json, $utf8NoBom)

Write-Host ''
Write-Host "  Manifest written: $Manifest" -ForegroundColor Green
Write-Host "  Recorded $($files.Count) file(s)." -ForegroundColor Green
Write-Host ''
Write-Host "  Next: powershell -NoProfile -File $(Join-Path $SafeHome 'safe-bootstrap.ps1')" -ForegroundColor Cyan
Write-Host '        (no flags = verify + repair the mirror; -VerifyOnly = read-only report)' -ForegroundColor Cyan
Write-Host ''
exit 0
