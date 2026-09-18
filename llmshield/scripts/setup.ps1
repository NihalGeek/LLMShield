param([string]$Python = 'py')
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not (Test-Path '.venv\Scripts\python.exe')) {
    if ($Python -eq 'py') { & py -3.12 -m venv .venv } else { & $Python -m venv .venv }
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.12+ is required. Supply -Python with the full python.exe path.' }
}
& '.\.venv\Scripts\python.exe' -m pip install -r requirements-lock.txt
if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed.' }
& '.\.venv\Scripts\python.exe' -m pip install --no-deps -e .
if ($LASTEXITCODE -ne 0) { throw 'Project installation failed.' }
Write-Host 'Ready. Run: .\scripts\run.ps1'
