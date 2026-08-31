"""Zugriffskontrolle: unautorisierter Zugriff auf geschuetzte Bereiche und APIs,
IDOR/BOLA und Mass Assignment. Die session-gebundenen Tests laufen nur mit
erfasster Session (sonst BLOCKED durch die Engine)."""
from core.base_test import BaseTest, Http, header_get, body_of, scaled

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
        # Angriffsmodus skaliert die Anzahl geprobter IDs (8..80).
        span = scaled(ctx, 8, 80) if ctx.get("aggressive") else 8
        for i in range(1, span):
            for tmpl in ("/api/users/{}", "/api/orders/{}", "/api/accounts/{}", "/api/documents/{}"):
                try:
                    r = h.get(h.abs(tmpl.format(i)))
                except Exception:
                    continue
                if r.status == 200 and _looks_like_data(body_of(r)):
                    seen += 1
        if seen >= 3:
            # Angriffsmodus: destruktive Bestaetigung per DELETE auf eine gefundene ID.
            if ctx.get("aggressive"):
                for i in range(1, 4):
                    try:
                        r = h.fetch(h.abs(f"/api/users/{i}"), method="DELETE")
                    except Exception:
                        continue
                    if r.status in (200, 204) and (r.status == 204 or "delet" in body_of(r).lower()):
                        return self.fail(f"IDOR destruktiv bestaetigt: fremder Datensatz per DELETE "
                                         f"entfernbar (/api/users/{i}).", severity="critical")
            return self.fail(f"Fortlaufende Objekt-IDs frei abrufbar ({seen} Treffer) — IDOR/BOLA.")
        return self.ok("Kein offensichtliches IDOR/BOLA.")


class MassAssignmentTest(BaseTest):
    test_id = "API-03"; title = "Mass Assignment"; severity = "high"; requires_session = True
    requires_aggressive = True

    def run(self, ctx):
        # Sendet ein Privileg-Feld an einen Profil-Endpunkt und prueft die Antwort.
        # Wegen PATCH ausschliesslich nach aktivem Opt-in.
        h = Http(ctx)
        # Angriffsmodus: echte Rechteausweitung (isAdmin=true) statt harmloser Probe.
        aggressive = ctx.get("aggressive")
        if aggressive:
            probe = {"role": "auditor-admin", "isAdmin": True}
        else:
            probe = {"role": "auditor-probe", "isAdmin": False}
        for path in ("/api/profile", "/api/users/me", "/api/account"):
            try:
                r = h.fetch(h.abs(path), method="PATCH", data=probe,
                            headers={"content-type": "application/json"})
            except Exception:
                continue
            if r.status not in (200, 201):
                continue
            body = body_of(r).lower().replace(" ", "")
            if aggressive and '"isadmin":true' in body:
                return self.fail(f"Privileg-Eskalation bestaetigt: Server uebernimmt isAdmin=true "
                                 f"({path}).", severity="critical")
            if "auditor-probe" in body or (aggressive and "auditor-admin" in body):
                return self.fail(f"Server uebernimmt clientseitige Rollen-/Rechtefelder ({path}).")
        return self.ok("Kein Mass Assignment erkannt.")
