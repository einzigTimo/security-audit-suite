"""Subresource Integrity und CSRF-Schutz-Indikatoren."""
import re
from core.base_test import BaseTest, Http, body_of


class SubresourceIntegrityTest(BaseTest):
    test_id = "SRI-01"; title = "Subresource Integrity"; severity = "low"

    def run(self, ctx):
        try:
            body = body_of(Http(ctx).get(ctx["base_url"]))
        except Exception as e:
            return self.error(e)
        base = ctx["base_url"].split("://", 1)[-1].split("/")[0]
        ext = re.findall(r'<script\b[^>]*\bsrc=["\'](https?://[^"\']+)["\'][^>]*>', body, re.I)
        ext = [t for t in ext if base not in t]
        if not ext:
            return self.ok("Keine externen Skripte ohne Integritaetspruefung.")
        without = [t for t in ext if "integrity=" not in _tag_for(body, t)]
        if without:
            return self.warn(f"{len(without)} externe(s) Skript(e) ohne integrity-Attribut (SRI).")
        return self.ok("Externe Skripte mit Subresource Integrity.")


def _tag_for(body, src):
    m = re.search(r'<script\b[^>]*' + re.escape(src) + r'[^>]*>', body, re.I)
    return m.group(0) if m else ""


class CsrfTokenTest(BaseTest):
    test_id = "CSRF-01"; title = "CSRF-Schutz (Formulare)"; severity = "medium"

    def run(self, ctx):
        try:
            body = body_of(Http(ctx).get(ctx["base_url"]))
        except Exception as e:
            return self.error(e)
        forms = re.findall(r'<form\b[^>]*method=["\']?post["\']?[^>]*>(.*?)</form>', body, re.I | re.S)
        if not forms:
            return self.skipped("Keine POST-Formulare auf der Startseite.")
        token_pat = re.compile(r'name=["\'][^"\']*(csrf|token|_token|authenticity)[^"\']*["\']', re.I)
        unprotected = sum(1 for f in forms if not token_pat.search(f))
        if unprotected:
            return self.warn(f"{unprotected} POST-Formular(e) ohne erkennbares CSRF-Token.")
        return self.ok("POST-Formulare enthalten CSRF-Token.")
