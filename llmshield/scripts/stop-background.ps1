$ErrorActionPreference='Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path 'data\server.pid')) { Write-Host 'No recorded background server.'; exit 0 }
$serverProcessId=[int](Get-Content -LiteralPath 'data\server.pid' -Raw)
$projectPath=(Resolve-Path '.').Path
$process=Get-CimInstance Win32_Process -Filter "ProcessId = $serverProcessId"
if (-not $process) { Write-Host 'Recorded process is no longer running.'; exit 0 }
if (-not $process.CommandLine -or $process.CommandLine -notlike "*$projectPath*" -or $process.CommandLine -notlike '*llmshield.cli*serve*') {
    throw 'Process identity does not match this lab server. No process was stopped.'
}
# A Windows venv launcher may own a child interpreter; stop only matching lab children.
Get-CimInstance Win32_Process -Filter "ParentProcessId = $serverProcessId" | ForEach-Object {
    if ($_.CommandLine -like '*llmshield.cli*serve*') { Stop-Process -Id $_.ProcessId }
}
Stop-Process -Id $serverProcessId -ErrorAction SilentlyContinue
Write-Host 'Local LLMShield background server stopped.'
