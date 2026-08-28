"""Transport: HTTPS-Erzwingung und Mixed Content."""
import re
from core.base_test import BaseTest, Http, header_get, body_of


class HttpsRedirectTest(BaseTest):
    test_id = "TLS-01"; title = "HTTPS-Redirect"; severity = "high"

    def run(self, ctx):
        base = ctx["base_url"]
        if not base.startswith("https"):
            return self.skipped("Ziel ist nicht per HTTPS erreichbar.")
        http_url = "http://" + base.split("://", 1)[1]
        try:
            r = Http(ctx).get(http_url, max_redirects=0)
        except Exception:
            # Kein HTTP-Listener erreichbar gilt als sicher (kein Klartext-Port).
            return self.ok("Kein erreichbarer HTTP-Endpunkt.")
        loc = header_get(r, "location")
        if r.status in (301, 302, 307, 308) and loc.startswith("https"):
            return self.ok(f"HTTP wird auf HTTPS umgeleitet ({r.status}).")
        if r.status == 200:
            return self.fail("HTTP liefert Inhalt ohne Weiterleitung auf HTTPS.")
        return self.warn(f"Unerwartete HTTP-Antwort: {r.status} -> {loc or 'ohne Location'}")


class MixedContentTest(BaseTest):
    test_id = "TLS-02"; title = "Mixed Content"; severity = "medium"

    def run(self, ctx):
        base = ctx["base_url"]
        if not base.startswith("https"):
            return self.skipped("Nur relevant fuer HTTPS-Ziele.")
        try:
            r = Http(ctx).get(base)
        except Exception as e:
            return self.error(e)
        body = body_of(r)
        refs = re.findall(r'(?:src|href)\s*=\s*["\'](http://[^"\']+)["\']', body, re.I)
        refs = [u for u in refs if not u.startswith("http://localhost")]
        if refs:
            sample = ", ".join(dict.fromkeys(refs))[:200]
            return self.warn(f"{len(refs)} unsichere http-Ressource(n): {sample}")
        return self.ok("Keine unsicheren http-Ressourcen eingebunden.")
