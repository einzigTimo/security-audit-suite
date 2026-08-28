# Selbsttest des Testkatalogs

Beweist, dass jeder Sicherheitstest **funktioniert** — nicht anhand von Zusicherungen,
sondern indem jeder Test durch seinen echten Code-Pfad gegen eine kontrollierte
Ziel-App läuft.

`fixture.py` startet dieselbe Anwendung in zwei Modi:

- **vuln** — absichtlich verwundbar (fehlende Header, offene APIs, injizierbare
  Parameter, exponierte Dateien …).
- **secure** — gehärtet (alle Schutzmaßnahmen aktiv).

`verify.py` lädt den Katalog über `AuditEngine.load_tests()` und lässt jeden
Test gegen beide Modi laufen. Erwartung:

| Modus | Erwartetes Ergebnis |
| --- | --- |
| vuln | Fund — `FAIL` oder `WARN` |
| secure | kein Fehlalarm — `PASS`, `INFO` oder `SKIPPED` |

Zwei dokumentierte Ausnahmen: `TLS-01` (HTTPS-Redirect) braucht echte Ports 80/443
und ist lokal nicht auslösbar; `INF-07` (security.txt) ist ein reiner
Best-Practice-Hinweis und meldet `INFO`, keinen Fund.

## Ausführen

```bash
pip install playwright
python -m playwright install chromium
python selftest/verify.py
```

Das Skript erzeugt sein TLS-Zertifikat zur Laufzeit (via `openssl`) in einem
temporären Verzeichnis — es wird nichts eingecheckt. Rückgabewert 0, wenn alle
Tests wie erwartet greifen.

Läuft die Fixture über HTTPS mit selbstsigniertem Zertifikat; der Browser-Context
nutzt `ignore_https_errors=True`.
