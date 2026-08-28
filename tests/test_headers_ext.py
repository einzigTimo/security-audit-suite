"""Erweiterte Header-Pruefungen: Permissions-Policy, Cross-Origin-Isolation,
Caching sensibler Antworten."""
from core.base_test import BaseTest, Http, header_get


class PermissionsPolicyTest(BaseTest):
    test_id = "HDR-07"; title = "Permissions-Policy"; severity = "low"

    def run(self, ctx):
        try:
            r = Http(ctx).get(ctx["base_url"])
        except Exception as e:
            return self.error(e)
        pp = header_get(r, "permissions-policy") or header_get(r, "feature-policy")
        if pp:
            return self.ok(f"Permissions-Policy gesetzt ({pp[:60]}).")
        return self.warn("Permissions-Policy fehlt — Browser-Funktionen (Kamera, Geolocation, …) nicht eingeschraenkt.")


class CrossOriginPolicyTest(BaseTest):
    test_id = "HDR-08"; title = "Cross-Origin-Isolation"; severity = "low"

    def run(self, ctx):
        try:
            r = Http(ctx).get(ctx["base_url"])
        except Exception as e:
            return self.error(e)
        missing = [h for h in ("cross-origin-opener-policy", "cross-origin-resource-policy")
                   if not header_get(r, h)]
        if not missing:
            return self.ok("COOP und CORP gesetzt.")
        return self.warn("Fehlend: " + ", ".join(missing) + " — schwaecherer Schutz gegen Cross-Origin-Angriffe.")


class CacheControlTest(BaseTest):
    test_id = "HDR-09"; title = "Cache-Control (sensible Bereiche)"; severity = "low"

    def run(self, ctx):
        # Prueft geschuetzte/dynamische Pfade auf no-store, damit Antworten mit
        # ggf. sensiblen Inhalten nicht zwischengespeichert werden.
        h = Http(ctx)
        for path in ("/account", "/dashboard", "/api/me", "/profile"):
            try:
                r = h.get(h.abs(path), max_redirects=0)
            except Exception:
                continue
            if r.status == 200:
                cc = header_get(r, "cache-control").lower()
                if "no-store" not in cc and "private" not in cc:
                    return self.warn(f"{path} ohne no-store/private — moegliches Caching sensibler Inhalte.")
        return self.ok("Sensible Bereiche mit angemessenem Cache-Control (oder nicht erreichbar).")
