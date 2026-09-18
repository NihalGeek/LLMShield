param([ValidateSet('mock','ollama')][string]$Provider='mock', [string]$Model='qwen2.5:3b')
$ErrorActionPreference='Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
& '.\.venv\Scripts\python.exe' -m pytest -q --junitxml=reports/pytest-results.xml
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
& '.\.venv\Scripts\python.exe' -m llmshield.cli assess --provider $Provider --model $Model --report "reports/$Provider-assessment.html"
exit $LASTEXITCODE
