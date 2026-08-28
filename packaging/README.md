# Paketierung — Windows

## Schnellster Weg: ein Befehl

Aus `apps\security-audit-tool` (PowerShell):

```powershell
# Fertiges Setup bauen (findet Inno Setup selbst, laedt Chromium nur bei Bedarf)
powershell -ExecutionPolicy Bypass -File packaging\build.ps1 -Pull

# Nur ausprobieren, ohne Setup — startet die App direkt aus dem Quellcode
powershell -ExecutionPolicy Bypass -File packaging\run.ps1
```

`build.ps1` erledigt alles: optionales `git pull`, virtuelle Umgebung,
Abhaengigkeiten, Chromium (nur wenn noch nicht vorhanden), PyInstaller und
Inno Setup. Der Compiler-Pfad (`ISCC.exe`) wird an den ueblichen Orten
automatisch gesucht (Inno Setup 6 und 7, System- und Nutzerinstallation).
Ergebnis: `dist\SecurityAuditSuite-<Version>-Setup.exe`.

Optionen: `-Version 2026.08.28`, `-NoInstaller` (nur die portable `.exe`).

---

# Paketierung & Release

Baut aus dem Python-Werkzeug ein installierbares Windows-Programm mit
Autoupdater. Der Build laeuft auf einem Windows-Runner (GitHub Actions); ein
lokaler Build unter Windows ist ebenso moeglich.

## Bestandteile

| Datei | Zweck |
| --- | --- |
| `security-audit-suite.spec` | PyInstaller — buendelt `gui.pyw`, `core/`, `tests/`, `version.json` und Chromium zur `.exe` |
| `rthook_playwright.py` | Runtime-Hook: findet den gebuendelten Chromium (`PLAYWRIGHT_BROWSERS_PATH=0`) |
| `installer.iss` | Inno Setup — erzeugt `SecurityAuditSuite-<version>-Setup.exe` mit Startmenue, Desktop-Icon, Deinstallation |
| `icon.ico` / `icon.png` | Platzhalter-Produkticon (Navy-Schild). Gegen das echte Icon tauschen. |
| `../../.github/workflows/security-audit-suite-release.yml` | CI: baut Setup und haengt es an das Release |

## Chromium im Bundle

`requirements.txt` pinnt **playwright==1.56.0**; dazu gehoert Chromium-Revision
1194. Der Build installiert Chromium mit `PLAYWRIGHT_BROWSERS_PATH=0` in das
playwright-Paket, PyInstaller bettet es ueber `collect_data_files("playwright")`
ein, und der Runtime-Hook setzt zur Laufzeit `PLAYWRIGHT_BROWSERS_PATH=0`. Das
Werkzeug scannt damit ohne Nachinstallation.

Folge: Das Bundle enthaelt einen vollstaendigen Browser (rund 0,5 GB
entpackt); das komprimierte Setup ist deutlich kleiner. Die Kette wurde
end-to-end gegen ein lokales Ziel verifiziert: die gebaute Binary startet
Chromium aus dem Bundle und fuehrt alle 31 Tests aus.

## Release erzeugen

Die Releases des Werkzeugs nutzen die Tag-Konvention **`sat-vX.Y.Z`**.
Der Autoupdater sucht genau nach diesem Praefix.

```bash
git tag sat-v2026.08.28
git push origin sat-v2026.08.28
```

Der Workflow baut daraufhin `SecurityAuditSuite-2026.08.28-Setup.exe`, laedt es
als Artefakt hoch und haengt es an das GitHub-Release mit demselben Tag. Der
Autoupdater im Programm (`Updates`-Knopf) findet dieses Asset beim naechsten
Start.

`workflow_dispatch` (Reiter „Actions" → „Run workflow") baut ein Test-Setup
ohne Release-Upload.

## Lokaler Build unter Windows

```powershell
cd apps\security-audit-tool
python -m pip install -r requirements.txt pyinstaller
$env:PLAYWRIGHT_BROWSERS_PATH = "0"; python -m playwright install chromium
pyinstaller --noconfirm --clean packaging\security-audit-suite.spec
# Inno Setup 6 vorausgesetzt:
& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" /DAppVersion=DEV packaging\installer.iss
# Ergebnis: dist\SecurityAuditSuite-DEV-Setup.exe
```

## Code-Signing (empfohlen, offen)

Setup und `.exe` sind unsigniert — Windows SmartScreen warnt entsprechend. Fuer
Produktivbetrieb ein Authenticode-Zertifikat einbinden: `signtool sign` nach dem
PyInstaller-Schritt und nach dem Inno-Build (bzw. Inno `SignTool`-Direktive).
Das Zertifikat gehoert als verschluesseltes CI-Secret hinterlegt, nicht ins
Repository.
