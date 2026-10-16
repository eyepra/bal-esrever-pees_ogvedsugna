#Requires -Version 5.1
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $scriptDir 'setup\update.ps1') @args
