"""Gefaehrliche HTTP-Methoden."""
from core.base_test import BaseTest, Http, header_get


class HttpMethodsTest(BaseTest):
    test_id = "MTH-01"; title = "HTTP-Methoden"; severity = "low"

    def run(self, ctx):
        h = Http(ctx)
        try:
            r = h.fetch(ctx["base_url"], method="OPTIONS")
        except Exception as e:
            return self.error(e)
        allow = header_get(r, "allow").upper()
        risky = [m for m in ("TRACE", "TRACK", "PUT", "DELETE", "CONNECT") if m in allow]
        # TRACE zusaetzlich aktiv pruefen (Cross-Site Tracing).
        try:
            t = h.fetch(ctx["base_url"], method="TRACE")
            if t.status == 200 and "trace" in (t.text()[:200].lower()):
                risky.append("TRACE(aktiv)")
        except Exception:
            pass
        if risky:
            return self.warn("Aktivierte Methoden: " + ", ".join(dict.fromkeys(risky)))
        return self.ok("Keine gefaehrlichen HTTP-Methoden aktiv.")
