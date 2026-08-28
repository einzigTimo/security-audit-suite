# Packaging — Windows

## Fastest path: one command

From the repository root (PowerShell):

```powershell
# Build the finished setup (finds Inno Setup itself, downloads Chromium only if needed)
powershell -ExecutionPolicy Bypass -File packaging\build.ps1

# Just try it out, no setup — starts the app directly from source
powershell -ExecutionPolicy Bypass -File packaging\run.ps1
```

`build.ps1` does everything: optional `git pull` (with `-Pull`), virtual
environment, dependencies, Chromium (only if not already present), PyInstaller,
and Inno Setup. The compiler path (`ISCC.exe`) is located automatically in the
usual places (Inno Setup 6 and 7, system and user installations). Result:
`dist\SecurityAuditSuite-<version>-Setup.exe`.

Options: `-Version 1.0.1`, `-NoInstaller` (portable `.exe` only), `-Pull`.

---

# Packaging & Release

Turns the Python tool into an installable Windows program with an auto-updater.
The build runs on a Windows runner (GitHub Actions); a local build on Windows
works just as well.

## Components

| File | Purpose |
| --- | --- |
| `security-audit-suite.spec` | PyInstaller — bundles `gui.pyw`, `core/`, `tests/`, `version.json` and Chromium into the `.exe` |
| `rthook_playwright.py` | Runtime hook: finds the bundled Chromium (`PLAYWRIGHT_BROWSERS_PATH=0`) |
| `installer.iss` | Inno Setup — produces `SecurityAuditSuite-<version>-Setup.exe` with Start menu, desktop icon, uninstall |
| `icon.ico` / `icon.png` | Placeholder product icon (navy shield). Swap for the real icon. |
| `../.github/workflows/release.yml` | CI: builds the setup and attaches it to the release |

## Chromium in the bundle

`requirements.txt` pins **playwright==1.56.0**, which corresponds to Chromium
revision 1194. The build installs Chromium with `PLAYWRIGHT_BROWSERS_PATH=0`
into the playwright package, PyInstaller embeds it via
`collect_data_files("playwright")`, and the runtime hook sets
`PLAYWRIGHT_BROWSERS_PATH=0` at runtime. The tool then scans without any extra
installation.

Consequence: the bundle contains a full browser (about 0.5 GB unpacked); the
compressed setup is considerably smaller. The chain was verified end-to-end
against a local target: the built binary launches Chromium from the bundle and
runs all 31 tests.

## Creating a release

Releases use the tag convention **`sat-vX.Y.Z`**. The auto-updater looks for
exactly this prefix.

```bash
git tag sat-v1.0.1
git push origin sat-v1.0.1
```

The workflow then builds `SecurityAuditSuite-1.0.1-Setup.exe`, uploads it as an
artifact, and attaches it to the GitHub release with the same tag. The in-app
auto-updater (the `Updates` button) finds this asset on the next start.

`workflow_dispatch` (the "Actions" tab → "Run workflow") builds a test setup;
provide the version as input.

## Local build on Windows

```powershell
python -m pip install -r requirements.txt pyinstaller
$env:PLAYWRIGHT_BROWSERS_PATH = "0"; python -m playwright install chromium
pyinstaller --noconfirm --clean packaging\security-audit-suite.spec
# Requires Inno Setup 6:
& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" /DAppVersion=DEV packaging\installer.iss
# Result: dist\SecurityAuditSuite-DEV-Setup.exe
```

## Code signing (recommended, not done)

The setup and `.exe` are unsigned — Windows SmartScreen will warn accordingly.
For production use, integrate an Authenticode certificate: `signtool sign` after
the PyInstaller step and after the Inno build (or the Inno `SignTool`
directive). Store the certificate as an encrypted CI secret, never in the
repository.
