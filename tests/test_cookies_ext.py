"""Erweiterte Cookie-Pruefungen: sichere Namenspraefixe."""
from core.base_test import BaseTest


class CookiePrefixTest(BaseTest):
    test_id = "CKE-04"; title = "Cookie-Praefixe (__Host-/__Secure-)"; severity = "low"

    def run(self, ctx):
        page = ctx["page"]
        try:
            page.goto(ctx["base_url"], wait_until="domcontentloaded", timeout=15000)
            cookies = ctx["context"].cookies()
        except Exception as e:
            return self.error(e)
        session_like = [c for c in cookies
                        if any(k in c["name"].lower() for k in ("sess", "sid", "auth", "token", "jwt"))]
        if not session_like:
            return self.skipped("Keine session-artigen Cookies gefunden.")
        unprefixed = [c["name"] for c in session_like
                      if not (c["name"].startswith("__Host-") or c["name"].startswith("__Secure-"))]
        if unprefixed:
            return self.warn("Session-Cookies ohne __Host-/__Secure-Praefix: " + ", ".join(unprefixed))
        return self.ok("Session-Cookies mit sicherem Namenspraefix.")
