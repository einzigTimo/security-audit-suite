<#
  Startet die Security Audit Suite direkt aus dem Quellcode — ohne Setup-Build.
  Schnellster Weg, um neue Funktionen sofort zu sehen.
  Aus apps\security-audit-tool ausfuehren:

      powershell -ExecutionPolicy Bypass -File packaging\run.ps1
#>
$ErrorActionPreference = "Stop"
$app = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $app
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    python -m venv .venv
    & ".\.venv\Scripts\python.exe" -m pip install -r requirements.txt | Out-Null
    $env:PLAYWRIGHT_BROWSERS_PATH = "0"
    & ".\.venv\Scripts\python.exe" -m playwright install chromium
}
$env:PLAYWRIGHT_BROWSERS_PATH = "0"
& ".\.venv\Scripts\python.exe" gui.pyw
