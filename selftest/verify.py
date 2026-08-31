"""Selbsttest des Testkatalogs.

Startet die Fixture-App (verwundbar + gehaertet) und laesst jeden Test durch
seinen echten Code-Pfad gegen beide Modi laufen. Erwartung: im verwundbaren
Modus ein Fund (FAIL/WARN), im gehaerteten Modus kein Fehlalarm.

Voraussetzungen: playwright (+ chromium), openssl.
  pip install playwright && python -m playwright install chromium
  python selftest/verify.py
"""
import os
import ipaddress
import shutil
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone

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
    openssl = shutil.which("openssl")
    if openssl:
        subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-keyout", key,
             "-out", cert, "-days", "30", "-nodes", "-subj", "/CN=127.0.0.1",
             "-addext", "subjectAltName=IP:127.0.0.1"],
            check=True, capture_output=True,
        )
        return cert, key

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .sign(private_key, hashes.SHA256())
    )
    with open(key, "wb") as handle:
        handle.write(private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(cert, "wb") as handle:
        handle.write(certificate.public_bytes(serialization.Encoding.PEM))
    return cert, key


def serve(port, mode, cert, key):
    srv = make_server(port, mode, cert, key)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run_suite(page, browser_ctx, base_url, aggressive=False):
    tests = AuditEngine({"url": base_url}).load_tests()
    ctx = {
        "page": page, "context": browser_ctx, "base_url": base_url,
        "config": {}, "has_session": True, "ui_available": True,
        "discovered_urls": [f"{base_url}/search?q=1", f"{base_url}/api/items?id=1"],
        "intensity": "Deep (Insane - Time-Based)",
        "aggressive": aggressive, "aggression": 10,
    }
    out = {}
    for t in sorted(tests, key=lambda x: x.test_id):
        # Gate wie in der Engine: nur-aggressive Tests ohne Angriffsmodus -> SKIPPED.
        if getattr(t, "requires_aggressive", False) and not aggressive:
            out[t.test_id] = ("SKIPPED", getattr(t, "title", "?"), "Nur im Angriffsmodus.")
            continue
        try:
            r = t.run(ctx)
            out[t.test_id] = (r.status, r.title, r.message)
        except Exception as e:
            out[t.test_id] = ("TOOL_ERROR", getattr(t, "title", "?"), str(e))
    return out


def launch(p):
    exe = os.environ.get("SAS_CHROME_PATH")
    return p.chromium.launch(executable_path=exe) if exe else p.chromium.launch()


def evaluate(label, vuln, secure, aggressive_pass):
    ids = sorted(set(vuln) | set(secure))
    print(f"\n=== {label} ===")
    print(f"{'ID':10}{'Titel':34}{'vuln':>8}   {'secure':>8}   Urteil")
    print("-" * 90)
    problems = 0
    for tid in ids:
        vs, title, vmsg = vuln.get(tid, ("—", "?", ""))
        ss, _, smsg = secure.get(tid, ("—", "?", ""))
        # Im nicht-aggressiven Durchlauf sind nur-aggressive Tests erwartet SKIPPED.
        if not aggressive_pass and vs == "SKIPPED" and ss == "SKIPPED":
            vuln_ok = secure_ok = True
        else:
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
    return problems


def main():
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = ensure_cert(tmp)
        serve(VULN_PORT, "vuln", cert, key)
        serve(SECURE_PORT, "secure", cert, key)

        vuln_url = f"https://127.0.0.1:{VULN_PORT}"
        secure_url = f"https://127.0.0.1:{SECURE_PORT}"
        with sync_playwright() as p:
            browser = launch(p)
            # Durchlauf 1: Standard (nicht-aggressiv) - wie bisher.
            with browser.new_context(ignore_https_errors=True) as c1:
                vuln = run_suite(c1.new_page(), c1, vuln_url)
            with browser.new_context(ignore_https_errors=True) as c2:
                secure = run_suite(c2.new_page(), c2, secure_url)
            # Durchlauf 2: Angriffsmodus (schreibend/destruktiv).
            with browser.new_context(ignore_https_errors=True) as c3:
                vuln_a = run_suite(c3.new_page(), c3, vuln_url, aggressive=True)
            with browser.new_context(ignore_https_errors=True) as c4:
                secure_a = run_suite(c4.new_page(), c4, secure_url, aggressive=True)
            browser.close()

    problems = evaluate("Standard-Durchlauf", vuln, secure, aggressive_pass=False)
    problems += evaluate("Angriffsmodus-Durchlauf", vuln_a, secure_a, aggressive_pass=True)
    print("=" * 90)
    print(f"GESAMT Probleme: {problems}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
