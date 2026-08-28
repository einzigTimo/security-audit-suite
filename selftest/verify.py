"""Selbsttest des Testkatalogs.

Startet die Fixture-App (verwundbar + gehaertet) und laesst jeden Test durch
seinen echten Code-Pfad gegen beide Modi laufen. Erwartung: im verwundbaren
Modus ein Fund (FAIL/WARN), im gehaerteten Modus kein Fehlalarm.

Voraussetzungen: playwright (+ chromium), openssl.
  pip install playwright && python -m playwright install chromium
  python selftest/verify.py
"""
import os
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.dirname(HERE)
sys.path.insert(0, APP)
sys.path.insert(0, HERE)

from fixture import make_server
from core.engine import AuditEngine
from playwright.sync_api import sync_playwright

VULN_PORT, SECURE_PORT = 8443, 8444
VULN_MAY_PASS = {"TLS-01", "TLS-03", "TLS-04", "TLS-05"}  # TLS-Ebene: lokale Fixture bietet keinen verwundbaren Fall
INFO_ONLY = {"INF-07"}       # reiner Best-Practice-Hinweis


def ensure_cert(dirpath):
    cert = os.path.join(dirpath, "cert.pem")
    key = os.path.join(dirpath, "key.pem")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
         "-out", cert, "-days", "30", "-nodes", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    return cert, key


def serve(port, mode, cert, key):
    srv = make_server(port, mode, cert, key)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run_suite(page, browser_ctx, base_url):
    tests = AuditEngine({"url": base_url}).load_tests()
    ctx = {
        "page": page, "context": browser_ctx, "base_url": base_url,
        "config": {}, "has_session": True, "ui_available": True,
        "discovered_urls": [f"{base_url}/search?q=1", f"{base_url}/api/items?id=1"],
        "intensity": "Deep (Insane - Time-Based)",
    }
    out = {}
    for t in sorted(tests, key=lambda x: x.test_id):
        try:
            r = t.run(ctx)
            out[t.test_id] = (r.status, r.title, r.message)
        except Exception as e:
            out[t.test_id] = ("TOOL_ERROR", getattr(t, "title", "?"), str(e))
    return out


def launch(p):
    exe = os.environ.get("SAS_CHROME_PATH")
    return p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()


def main():
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = ensure_cert(tmp)
        serve(VULN_PORT, "vuln", cert, key)
        serve(SECURE_PORT, "secure", cert, key)

        with sync_playwright() as p:
            browser = launch(p)
            with browser.new_context(ignore_https_errors=True) as c1:
                vuln = run_suite(c1.new_page(), c1, f"https://127.0.0.1:{VULN_PORT}")
            with browser.new_context(ignore_https_errors=True) as c2:
                secure = run_suite(c2.new_page(), c2, f"https://127.0.0.1:{SECURE_PORT}")
            browser.close()

    ids = sorted(set(vuln) | set(secure))
    print(f"{'ID':10}{'Titel':34}{'vuln':>8}   {'secure':>8}   Urteil")
    print("-" * 90)
    problems = 0
    for tid in ids:
        vs, title, vmsg = vuln.get(tid, ("—", "?", ""))
        ss, _, smsg = secure.get(tid, ("—", "?", ""))
        vuln_ok = vs in ("FAIL", "WARN") or tid in VULN_MAY_PASS or (tid in INFO_ONLY and vs in ("INFO", "PASS"))
        secure_ok = ss in ("PASS", "INFO", "SKIPPED")
        verdict = "OK" if (vuln_ok and secure_ok) else "PROBLEM"
        if verdict != "OK":
            problems += 1
        print(f"{tid:10}{title[:32]:34}{vs:>8}   {ss:>8}   {verdict}")
        if verdict != "OK":
            print(f"           vuln:   {vmsg}")
            print(f"           secure: {smsg}")
    print("-" * 90)
    print(f"Tests gesamt: {len(ids)} | Probleme: {problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
