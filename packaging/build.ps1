<#
  Ein-Befehl-Build der Security Audit Suite (Windows).
  Aus apps\security-audit-tool ausfuehren:

      powershell -ExecutionPolicy Bypass -File packaging\build.ps1

  Optionen:
      -Version 2026.08.28   Setzt die Setup-Version (Standard: aus version.json bzw. heutiges Datum)
      -Pull                 Vorher 'git pull' im Repo
      -NoInstaller          Nur die .exe bauen, kein Inno-Setup
#>
param(
    [string]$Version = "",
    [switch]$Pull,
    [switch]$NoInstaller
)
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path      # ...\packaging
$app  = Split-Path -Parent $here                             # ...\security-audit-tool
Set-Location $app

if ($Pull) {
    Write-Host "== git pull ==" -ForegroundColor Cyan
    git pull
}

# Version bestimmen
if (-not $Version) {
    if (Test-Path "version.json") {
        try { $Version = (Get-Content version.json -Raw | ConvertFrom-Json).version } catch {}
    }
    if (-not $Version) { $Version = (Get-Date -Format "yyyy.MM.dd") }
}
Write-Host "== Version: $Version ==" -ForegroundColor Cyan

# version.json auf die Build-Version stempeln, damit der Autoupdater korrekt
# vergleicht (die eingebaute Version muss dem Release-Tag entsprechen).
$vjson = [ordered]@{ version = $Version; updated = (Get-Date).ToString("s") } | ConvertTo-Json
Set-Content -Path "version.json" -Value $vjson -Encoding UTF8
Write-Host "== version.json auf $Version gesetzt ==" -ForegroundColor DarkGray

# venv sicherstellen
if (-not (Test-Path ".venv\Scripts\python.exe")) {
    Write-Host "== Lege virtuelle Umgebung an ==" -ForegroundColor Cyan
    python -m venv .venv
}
$py = ".\.venv\Scripts\python.exe"

Write-Host "== Abhaengigkeiten ==" -ForegroundColor Cyan
& $py -m pip install --upgrade pip | Out-Null
& $py -m pip install -r requirements.txt pyinstaller

# Chromium nur laden, wenn noch nicht im venv vorhanden
$env:PLAYWRIGHT_BROWSERS_PATH = "0"
$hasChromium = Get-ChildItem -Path ".venv\Lib\site-packages\playwright\driver\package\.local-browsers" -Filter "chromium-*" -Directory -ErrorAction SilentlyContinue
if (-not $hasChromium) {
    Write-Host "== Chromium laden ==" -ForegroundColor Cyan
    & $py -m playwright install chromium
} else {
    Write-Host "== Chromium bereits vorhanden ==" -ForegroundColor DarkGray
}

Write-Host "== PyInstaller-Build ==" -ForegroundColor Cyan
& $py -m PyInstaller --noconfirm --clean packaging\security-audit-suite.spec

if ($NoInstaller) {
    Write-Host "`nFertig. Programm: $app\dist\SecurityAuditSuite\SecurityAuditSuite.exe" -ForegroundColor Green
    exit 0
}

# ISCC.exe (Inno Setup Compiler) an den ueblichen Orten suchen
$isccCandidates = @(
    "$env:ProgramFiles\Inno Setup 7\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 7\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
)
$iscc = $isccCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) {
    $iscc = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
}
if (-not $iscc) {
    Write-Host "`nInno Setup (ISCC.exe) nicht gefunden." -ForegroundColor Yellow
    Write-Host "Installieren mit:  winget install JRSoftware.InnoSetup" -ForegroundColor Yellow
    Write-Host "Die .exe liegt bereits unter dist\SecurityAuditSuite\ (portabel nutzbar)." -ForegroundColor Yellow
    exit 1
}
Write-Host "== Inno Setup: $iscc ==" -ForegroundColor Cyan
& $iscc "/DAppVersion=$Version" "packaging\installer.iss"

$setup = Join-Path $app "dist\SecurityAuditSuite-$Version-Setup.exe"
if (Test-Path $setup) {
    $hash = (Get-FileHash -Algorithm SHA256 $setup).Hash.ToLowerInvariant()
    "$hash  $(Split-Path -Leaf $setup)" | Set-Content -Path "$setup.sha256" -Encoding ascii
    Write-Host "`nFERTIG. Setup: $setup" -ForegroundColor Green
    Write-Host "SHA-256: $setup.sha256" -ForegroundColor Green
} else {
    Write-Host "`nBuild lief durch, aber Setup-Datei nicht gefunden (siehe dist\)." -ForegroundColor Yellow
}
