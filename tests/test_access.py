"""Zugriffskontrolle: unautorisierter Zugriff auf geschuetzte Bereiche und APIs,
IDOR/BOLA und Mass Assignment. Die session-gebundenen Tests laufen nur mit
erfasster Session (sonst BLOCKED durch die Engine)."""
from core.base_test import BaseTest, Http, header_get, body_of

PII_MARKERS = ("email", "@", "password", "\"role\"", "ssn", "iban", "creditcard")


def _looks_like_data(body):
    low = body.lower()
    return any(m in low for m in PII_MARKERS)


class DirectUrlBypassTest(BaseTest):
    test_id = "RBAC-01"; title = "Direct URL Bypass"; severity = "critical"

    def run(self, ctx):
        h = Http(ctx)
        for path in ("/dashboard", "/admin", "/settings", "/account", "/api/me"):
            try:
                r = h.get(h.abs(path), max_redirects=0)
            except Exception:
                continue
            loc = header_get(r, "location").lower()
            redirected_to_login = r.status in (301, 302, 303, 307, 308) and ("login" in loc or "signin" in loc or "auth" in loc)
            if r.status == 200 and not redirected_to_login:
                return self.fail(f"Geschuetzter Bereich ohne Anmeldung erreichbar: {path}")
        return self.ok("Geschuetzte Bereiche verlangen Anmeldung.")


class ApiBypassTest(BaseTest):
    test_id = "API-01"; title = "API Bypass"; severity = "critical"

    def run(self, ctx):
        h = Http(ctx)
        for path in ("/api/users", "/api/profile", "/api/admin", "/api/orders", "/api/accounts"):
            try:
                r = h.get(h.abs(path))
            except Exception:
                continue
            if r.status == 200 and _looks_like_data(body_of(r)):
                return self.fail(f"API liefert Daten ohne Autorisierung: {path}")
        return self.ok("APIs verlangen Autorisierung.")


class IDORTest(BaseTest):
    test_id = "API-02"; title = "IDOR / BOLA"; severity = "critical"; requires_session = True

    def run(self, ctx):
        h = Http(ctx)
        seen = 0
        for i in range(1, 8):
            for tmpl in ("/api/users/{}", "/api/orders/{}", "/api/accounts/{}", "/api/documents/{}"):
                try:
                    r = h.get(h.abs(tmpl.format(i)))
                except Exception:
                    continue
                if r.status == 200 and _looks_like_data(body_of(r)):
                    seen += 1
        if seen >= 3:
            return self.fail(f"Fortlaufende Objekt-IDs frei abrufbar ({seen} Treffer) — IDOR/BOLA.")
        return self.ok("Kein offensichtliches IDOR/BOLA.")


class MassAssignmentTest(BaseTest):
    test_id = "API-03"; title = "Mass Assignment"; severity = "high"; requires_session = True

    def run(self, ctx):
        # Sendet ein Privileg-Feld an einen Profil-Endpunkt und prueft die Antwort
        # auf Uebernahme. Nur mit erfasster Session (autorisiert) aktiv.
        h = Http(ctx)
        for path in ("/api/profile", "/api/users/me", "/api/account"):
            try:
                r = h.fetch(h.abs(path), method="PATCH",
                            data={"role": "auditor-probe", "isAdmin": False},
                            headers={"content-type": "application/json"})
            except Exception:
                continue
            if r.status in (200, 201) and "auditor-probe" in body_of(r).lower():
                return self.fail(f"Server uebernimmt clientseitige Rollen-/Rechtefelder ({path}).")
        return self.ok("Kein Mass Assignment erkannt.")
