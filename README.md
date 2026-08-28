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

## Getting started

```bash
pip install -r requirements.txt
python -m playwright install chromium
python gui.pyw
```

In the interface, enter the **target URL**, pick the scan intensity, confirm the
permission to test, and start the run. Every HTTP request is logged live, so you
can always see what is currently being checked.

## Layout

| File / folder | Contents |
| --- | --- |
| `gui.pyw` | Tkinter interface |
| `core/engine.py` | `AuditEngine.run()` — loads tests, runs them, invokes the callbacks |
| `core/base_test.py` | `BaseTest` / `TestResult` — the contract every test follows |
| `core/browser.py` | Playwright/Chromium management, optionally with `storage_state` |
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

Starts a local test fixture and verifies that the engine produces the expected
findings — without touching any external target.

## Windows build

See [`packaging/README.md`](packaging/README.md). In short:

```powershell
powershell -File packaging/build.ps1
```

Produces `dist/SecurityAuditSuite/` and, via Inno Setup, a Windows setup
installer. Tagging a release as `sat-vX.Y.Z` builds the setup automatically on
GitHub Actions and attaches it to the release.

## Note on language

The documentation is in English. The application's user interface is in German.

## License

MIT — see [`LICENSE`](LICENSE).

## Author

derTIMO
