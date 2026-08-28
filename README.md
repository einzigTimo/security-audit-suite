# Security Audit Suite

Ein leichtgewichtiges Werkzeug für **Web-Security-Audits** mit grafischer
Oberfläche (Python/Tkinter). Es prüft eine Ziel-Webseite gegen einen Katalog
gängiger Sicherheitstests (Header, Cookies, TLS/Transport, CORS, Methoden,
Information Disclosure, Injection-Indikatoren u. a.) und erzeugt einen Bericht.

> ⚠️ **Nur mit ausdrücklicher Testberechtigung verwenden.** Führe Scans
> ausschließlich gegen Systeme durch, für die du eine schriftliche Erlaubnis
> hast. Vor jedem Lauf ist die Berechtigung in der Oberfläche zu bestätigen.

## Start

```bash
pip install -r requirements.txt
python -m playwright install chromium
python gui.pyw
```

Trage in der Oberfläche die **Ziel-URL** ein, wähle die Scan-Intensität,
bestätige die Testberechtigung und starte den Lauf. Jede HTTP-Anfrage wird
live protokolliert, damit nachvollziehbar ist, was gerade geprüft wird.

## Aufbau

| Datei / Ordner | Inhalt |
| --- | --- |
| `gui.pyw` | Tkinter-Oberfläche |
| `core/engine.py` | `AuditEngine.run()` — lädt Tests, fährt sie ab, ruft die Callbacks |
| `core/base_test.py` | `BaseTest` / `TestResult` — Vertrag jedes Tests |
| `core/browser.py` | Playwright-Chromium-Verwaltung, optional mit `storage_state` |
| `core/spider.py` | Einfaches Crawling der Zielseite |
| `core/reporter.py` | Berichtserstellung (Text/JSON/HTML) |
| `core/remediation.py` | Handlungsempfehlungen je Befund |
| `core/updater.py` | Optionaler Auto-Updater über GitHub Releases |
| `tests/` | Einzelne Sicherheitstests (ein Modul je Testgruppe) |
| `selftest/` | Selbsttest gegen eine lokale Fixture |
| `packaging/` | Windows-Build (PyInstaller + Inno Setup) |

## Selbsttest

```bash
python selftest/verify.py
```

Startet eine lokale Test-Fixture und prüft, dass die Engine die erwarteten
Befunde liefert — ohne ein externes Ziel zu berühren.

## Windows-Build

Siehe [`packaging/README.md`](packaging/README.md). Kurz:

```powershell
powershell -File packaging/build.ps1
```

Erzeugt `dist/SecurityAuditSuite/` und daraus per Inno Setup ein Windows-Setup.

## Lizenz

MIT — siehe [`LICENSE`](LICENSE).

## Autor

derTIMO
