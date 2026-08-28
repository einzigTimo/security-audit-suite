"""Tiefe TLS-/Zertifikatspruefungen ueber die Standardbibliothek (ssl).

Verbindet direkt auf Socket-Ebene, da Playwrights HTTP-Client keine
Protokoll-/Zertifikatsdetails liefert. Nur fuer HTTPS-Ziele.
"""
import os
import socket
import ssl
import tempfile
import time
from urllib.parse import urlparse

from core.base_test import BaseTest


def _target(ctx):
    u = urlparse(ctx["base_url"])
    if u.scheme != "https":
        return None
    return u.hostname, (u.port or 443)


def _peer(host, port):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=10) as sock:
        with c.wrap_socket(sock, server_hostname=host) as ss:
            return ss.version(), ss.cipher(), ss.getpeercert(binary_form=True)


class CertExpiryTest(BaseTest):
    test_id = "TLS-03"; title = "Zertifikatsablauf"; severity = "high"

    def run(self, ctx):
        tgt = _target(ctx)
        if not tgt:
            return self.skipped("Nur fuer HTTPS-Ziele.")
        try:
            _, _, der = _peer(*tgt)
            pem = ssl.DER_cert_to_PEM_cert(der)
            with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
                f.write(pem); path = f.name
            try:
                info = ssl._ssl._test_decode_cert(path)
            finally:
                os.unlink(path)
        except Exception as e:
            return self.skipped(f"Zertifikat nicht auswertbar: {e}")
        not_after = info.get("notAfter")
        if not not_after:
            return self.skipped("Kein Ablaufdatum im Zertifikat.")
        remaining = ssl.cert_time_to_seconds(not_after) - time.time()
        days = int(remaining / 86400)
        if remaining <= 0:
            return self.fail(f"Zertifikat ist abgelaufen (seit {-days} Tagen).")
        if days < 15:
            return self.warn(f"Zertifikat laeuft in {days} Tagen ab — rechtzeitig erneuern.")
        return self.ok(f"Zertifikat gueltig, laeuft in {days} Tagen ab.")


class LegacyProtocolTest(BaseTest):
    test_id = "TLS-04"; title = "Veraltete TLS-Protokolle"; severity = "medium"

    def run(self, ctx):
        tgt = _target(ctx)
        if not tgt:
            return self.skipped("Nur fuer HTTPS-Ziele.")
        host, port = tgt
        weak = []
        for name, ver in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
            try:
                c = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                c.check_hostname = False
                c.verify_mode = ssl.CERT_NONE
                c.minimum_version = ver
                c.maximum_version = ver
                with socket.create_connection((host, port), timeout=8) as sock:
                    with c.wrap_socket(sock, server_hostname=host):
                        weak.append(name)
            except Exception:
                pass
        if weak:
            return self.warn("Server akzeptiert veraltete Protokolle: " + ", ".join(weak))
        return self.ok("Keine veralteten TLS-Protokolle (1.0/1.1) akzeptiert.")


class TlsVersionTest(BaseTest):
    test_id = "TLS-05"; title = "Ausgehandelte TLS-Verbindung"; severity = "medium"

    def run(self, ctx):
        tgt = _target(ctx)
        if not tgt:
            return self.skipped("Nur fuer HTTPS-Ziele.")
        try:
            version, cipher, _ = _peer(*tgt)
        except Exception as e:
            return self.skipped(f"TLS-Verbindung nicht moeglich: {e}")
        name = cipher[0] if cipher else "?"
        if version in ("TLSv1", "TLSv1.1", "SSLv3"):
            return self.warn(f"Schwache Verbindung ausgehandelt: {version} ({name}).")
        return self.ok(f"Verbindung: {version} ({name}).")
