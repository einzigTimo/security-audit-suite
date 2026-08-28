"""Sicherheits-Header und Informations-Leaks in Antwort-Headern."""
from core.base_test import BaseTest, Http, header_get


class HSTSTest(BaseTest):
    test_id = "HDR-01"; title = "HSTS Header"; severity = "medium"

    def run(self, ctx):
        try:
            r = Http(ctx).get(ctx["base_url"])
        except Exception as e:
            return self.error(e)
        hsts = header_get(r, "strict-transport-security")
        if not hsts:
            return self.warn("Strict-Transport-Security fehlt.")
        if "max-age=0" in hsts.replace(" ", ""):
            return self.warn("HSTS mit max-age=0 (deaktiviert).")
        return self.ok(f"HSTS aktiv ({hsts}).")


class CSPTest(BaseTest):
    test_id = "HDR-02"; title = "Content-Security-Policy"; severity = "medium"

    def run(self, ctx):
        try:
            r = Http(ctx).get(ctx["base_url"])
        except Exception as e:
            return self.error(e)
        csp = header_get(r, "content-security-policy")
        if not csp:
            return self.warn("Content-Security-Policy fehlt.")
        weak = [t for t in ("unsafe-inline", "unsafe-eval") if t in csp]
        if "default-src *" in csp or "script-src *" in csp:
            return self.warn("CSP erlaubt Wildcard-Quellen.")
        if weak:
            return self.warn(f"CSP erlaubt {' und '.join(weak)}.")
        return self.ok("CSP gesetzt und ohne offensichtliche Schwaechen.")


class ClickjackingTest(BaseTest):
    test_id = "HDR-03"; title = "X-Frame-Options / Clickjacking"; severity = "medium"

    def run(self, ctx):
        try:
            r = Http(ctx).get(ctx["base_url"])
        except Exception as e:
            return self.error(e)
        xfo = header_get(r, "x-frame-options").lower()
        csp = header_get(r, "content-security-policy").lower()
        if "deny" in xfo or "sameorigin" in xfo or "frame-ancestors" in csp:
            return self.ok("Framing eingeschraenkt (X-Frame-Options/frame-ancestors).")
        return self.warn("Kein Clickjacking-Schutz (X-Frame-Options/frame-ancestors fehlt).")


class ContentTypeOptionsTest(BaseTest):
    test_id = "HDR-04"; title = "X-Content-Type-Options"; severity = "low"

    def run(self, ctx):
        try:
            r = Http(ctx).get(ctx["base_url"])
        except Exception as e:
            return self.error(e)
        if header_get(r, "x-content-type-options").lower() == "nosniff":
            return self.ok("nosniff gesetzt.")
        return self.warn("X-Content-Type-Options: nosniff fehlt.")


class ReferrerPolicyTest(BaseTest):
    test_id = "HDR-05"; title = "Referrer-Policy"; severity = "low"

    def run(self, ctx):
        try:
            r = Http(ctx).get(ctx["base_url"])
        except Exception as e:
            return self.error(e)
        rp = header_get(r, "referrer-policy").lower()
        safe = ("no-referrer", "strict-origin", "same-origin")
        if any(s in rp for s in safe):
            return self.ok(f"Referrer-Policy: {rp}")
        if rp:
            return self.warn(f"Referrer-Policy schwach: {rp}")
        return self.warn("Referrer-Policy fehlt.")


class ServerInfoTest(BaseTest):
    test_id = "HDR-06"; title = "Server-/Technologie-Leak"; severity = "low"

    def run(self, ctx):
        import re
        try:
            r = Http(ctx).get(ctx["base_url"])
        except Exception as e:
            return self.error(e)
        leaks = []
        for h in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            v = header_get(r, h)
            if v and re.search(r"\d", v):
                leaks.append(f"{h}: {v}")
        if leaks:
            return self.warn("Versionsinfo im Header: " + " | ".join(leaks))
        return self.ok("Keine Versionsinfo in den Headern.")
