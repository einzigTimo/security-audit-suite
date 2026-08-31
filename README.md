# Security Audit Suite

> 🙂 **My first public project — please be kind!**
> This is the first thing I'm sharing publicly. I built it to learn, and I'm
> proud of it. Feedback is very welcome — but please be gentle rather than
> tearing it apart. Thanks for stopping by!

A lightweight tool for **web security audits** with a graphical interface
(Python/Tkinter). It checks a target website against a catalog of common
security tests (headers, cookies, TLS/transport, CORS, HTTP methods,
information disclosure, injection indicators, and more) and produces a report.

> ⚠️ **Only use with explicit permission to test.** Run scans exclusively
> against systems you have written authorization to test. You must confirm the
> permission in the interface before every run.

## Install (for users)

The easiest way — no Python, no setup:

1. Go to the [**Releases**](../../releases/latest) page.
2. Under **Assets**, download `SecurityAuditSuite-<version>-Setup.exe`.
3. Run it and follow the installer. It bundles everything (including the
   browser it needs), so there is nothing else to install.

> Windows SmartScreen may warn because the installer is not code-signed. Choose
> *More info → Run anyway* if you trust the source.

Once installed, start **Security Audit Suite**, enter the **target URL**, choose
the inventory mode plus separate read/write intensity, confirm the permission to
test, and start the run. Every HTTP request is logged live, so you can always
see what is being checked. Target URLs and permission confirmations are kept
only for the active run and are cleared before the scan starts.

The app updates itself: the **Updates** button checks the Releases page for a
newer version. Updates are accepted only when the release contains both
`SecurityAuditSuite-<version>-Setup.exe` and the matching `.sha256` sidecar.

## Intensity model

Inventory has two levels: **Quick** for compact metadata and **Full** for deeper
fingerprinted inventory. Read intensity has levels 1-4, where level 4 maps to
the maximum deep-analysis effort. Write intensity has levels 0-4. Level 0 keeps
all write-capable tests blocked. Levels 1-4 enable the opt-in attack mode, with
level 4 using the maximum write/aggression budget.

## Run from source (for developers)

If you want to run or modify the code directly instead of using the installer:

```bash
pip install -r requirements.txt
python -m playwright install chromium
python gui.pyw
```

## Layout

| File / folder | Contents |
| --- | --- |
| `gui.pyw` | Tkinter interface |
| `core/engine.py` | `AuditEngine.run()` — loads tests, runs them, invokes the callbacks |
| `core/base_test.py` | `BaseTest` / `TestResult` — the contract every test follows |
| `core/browser.py` | Playwright/Chromium management, optionally with `storage_state` |
| `core/policy.py` | Read/write/inventory policy and compatibility mapping |
| `core/inventory.py` | Quick/full local inventory helpers without absolute-path output |
| `core/spider.py` | Simple crawling of the target site |
| `core/reporter.py` | Report generation (text/JSON/HTML) |
| `core/remediation.py` | Remediation advice per finding |
| `core/updater.py` | Optional auto-updater via GitHub Releases |
| `tests/` | Individual security tests (one module per test group) |
| `selftest/` | Self-test against a local fixture |
| `packaging/` | Windows build (PyInstaller + Inno Setup) |

## Self-test

```bash
python selftest/verify.py
```

Starts a local test fixture and verifies 46 checks in both standard and
attack-mode runs — without touching any external target.

## Windows build

See [`packaging/README.md`](packaging/README.md). In short:

```powershell
powershell -File packaging/build.ps1
```

Produces `dist/SecurityAuditSuite/` and, via Inno Setup, a Windows setup
installer. Production releases are started exclusively through the maintainer's
deploy controller ("Develop Zentrale"), which dispatches the signed GitHub
Actions release workflow; the workflow reads the version from `version.json`,
builds the setup, creates the required `.sha256` sidecar, and creates the
`sat-vX.Y.Z` release. Tags are created by the release workflow, not pushed by
hand.

## Note on language

The documentation is in English. The application's user interface is in German.

## License

MIT — see [`LICENSE`](LICENSE).

## Author

derTIMO
