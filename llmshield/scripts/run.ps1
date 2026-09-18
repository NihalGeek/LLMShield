param([ValidateSet('mock','ollama')][string]$Provider='mock', [string]$Model='qwen2.5:3b', [int]$Port=8765)
$ErrorActionPreference='Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$env:LLMSHIELD_PROVIDER=$Provider
$env:LLMSHIELD_MODEL=if ($Provider -eq 'ollama') { $Model } else { '' }
$env:LLMSHIELD_DATA_DIR=Join-Path (Get-Location) 'data'
& '.\.venv\Scripts\python.exe' -m llmshield.cli serve --port $Port
exit $LASTEXITCODE
