"""Cookie-Sicherheitsattribute: Secure, HttpOnly, SameSite."""
from core.base_test import BaseTest


def _cookies(ctx):
    page = ctx["page"]
    page.goto(ctx["base_url"], wait_until="domcontentloaded", timeout=15000)
    return ctx["context"].cookies()


class SecureCookieTest(BaseTest):
    test_id = "CKE-01"; title = "Secure-Flag Cookies"; severity = "medium"

    def run(self, ctx):
        try:
            cookies = _cookies(ctx)
        except Exception as e:
            return self.error(e)
        if not cookies:
            return self.skipped("Keine Cookies gesetzt.")
        insecure = [c["name"] for c in cookies if not c.get("secure")]
        if insecure:
            return self.fail("Cookies ohne Secure: " + ", ".join(insecure))
        return self.ok("Alle Cookies mit Secure-Flag.")


class HttpOnlyCookieTest(BaseTest):
    test_id = "CKE-02"; title = "HttpOnly Cookies"; severity = "medium"

    def run(self, ctx):
        try:
            cookies = _cookies(ctx)
        except Exception as e:
            return self.error(e)
        if not cookies:
            return self.skipped("Keine Cookies gesetzt.")
        exposed = [c["name"] for c in cookies if not c.get("httpOnly")]
        if exposed:
            return self.warn("Cookies ohne HttpOnly (JS-lesbar): " + ", ".join(exposed))
        return self.ok("Alle Cookies mit HttpOnly.")


class SameSiteCookieTest(BaseTest):
    test_id = "CKE-03"; title = "SameSite Attribut"; severity = "low"

    def run(self, ctx):
        try:
            cookies = _cookies(ctx)
        except Exception as e:
            return self.error(e)
        if not cookies:
            return self.skipped("Keine Cookies gesetzt.")
        missing = [c["name"] for c in cookies if c.get("sameSite", "None") in ("None", None)]
        if missing:
            return self.warn("Cookies ohne wirksames SameSite: " + ", ".join(missing))
        return self.ok("Alle Cookies mit SameSite (Lax/Strict).")
