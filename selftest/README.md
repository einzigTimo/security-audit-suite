# Self-test of the test catalog

Proves that every security test **works** — not by assertion, but by running
each test through its real code path against a controlled target app.

`fixture.py` starts the same application in two modes:

- **vuln** — intentionally vulnerable (missing headers, open APIs, injectable
  parameters, exposed files, …).
- **secure** — hardened (all protections active).

`verify.py` loads the catalog via `AuditEngine.load_tests()` and runs every test
against both modes. Expectation:

| Mode | Expected result |
| --- | --- |
| vuln | finding — `FAIL` or `WARN` |
| secure | no false positive — `PASS`, `INFO` or `SKIPPED` |

Two documented exceptions: `TLS-01` (HTTPS redirect) needs real ports 80/443 and
cannot be triggered locally; `INF-07` (security.txt) is a pure best-practice hint
and reports `INFO`, not a finding.

## Running

```bash
pip install playwright
python -m playwright install chromium
python selftest/verify.py
```

The script generates its TLS certificate at runtime (via `openssl`) in a
temporary directory — nothing is checked in. Returns 0 when all tests behave as
expected.

The fixture runs over HTTPS with a self-signed certificate; the browser context
uses `ignore_https_errors=True`.
