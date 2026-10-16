#Requires -Version 5.1
<#
  Seep 逆向工程工作台 —— 上游定点隔离同步与防外溢驱动 (Sync-Upstream)
  ================================================================
  适用场景：维护者拉取并合并上游开源仓库更新，保证单源入单库，零外溢。

  用法：
    powershell -ExecutionPolicy Bypass -File .\setup\sync-upstream.ps1
    powershell -ExecutionPolicy Bypass -File .\setup\sync-upstream.ps1 -Target apk-reverse
    powershell -ExecutionPolicy Bypass -File .\setup\sync-upstream.ps1 -DryRun
    powershell -ExecutionPolicy Bypass -File .\setup\sync-upstream.ps1 -CheckOnly
#>
[CmdletBinding()]
param(
    [string]$Target = 'all',
    [switch]$DryRun,
    [switch]$CheckOnly,
    [string]$Proxy = '',
    [switch]$SkipVerify
)

$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Root      = Split-Path -Parent $ScriptDir
$PyEngine  = Join-Path $ScriptDir 'sync-upstream.py'

# 探测 Python
$pythonCmd = 'python'
try {
    $ver = & python --version 2>&1
    if ($LASTEXITCODE -ne 0) { throw "python not found" }
} catch {
    if (Test-Path "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe") {
        $pythonCmd = "$env:LOCALAPPDATA\Programs\Python\Python311\python.exe"
    } else {
        Write-Host " [FAIL] 未检测到可用的 Python 解释器，请先安装 Python 3.11+" -ForegroundColor Red
        exit 1
    }
}

$pyArgs = @($PyEngine, '--target', $Target)
if ($DryRun) { $pyArgs += '--dry-run' }
if ($CheckOnly) { $pyArgs += '--check-only' }
if ($Proxy) { $pyArgs += @('--proxy', $Proxy) }

& $pythonCmd @pyArgs
$engineExit = $LASTEXITCODE

if ($engineExit -eq 2 -and -not $CheckOnly) {
    Write-Host "`n [FATAL] 防外溢安全检查未通过！已紧急拦截并阻断。" -ForegroundColor Red
    exit 2
}

if ($engineExit -ne 0 -and -not $CheckOnly) {
    exit $engineExit
}

if (-not $DryRun -and -not $CheckOnly -and -not $SkipVerify) {
    Write-Host "`n>>> 正在运行工作台格式规范化与基准自检..." -ForegroundColor Cyan
    & $pythonCmd (Join-Path $ScriptDir 'clean-format.py')
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $ScriptDir 'verify.ps1')
}

exit $engineExit
