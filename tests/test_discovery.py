"""Content-Discovery: Aufspueren typischer sensibler Pfade (Admin-Oberflaechen,
Backups, alte Endpunkte, API-Dokumentation)."""
from core.base_test import BaseTest, Http, body_of, header_get

# Pfade, die auf oeffentlich nicht erwuenschte Ressourcen hindeuten.
PATHS = [
    "/admin", "/administrator", "/wp-admin/", "/phpmyadmin/", "/.well-known/",
    "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql", "/database.sql",
    "/old/", "/test/", "/dev/", "/staging/", "/.svn/entries", "/.htaccess",
    "/swagger", "/swagger-ui.html", "/api-docs", "/openapi.json", "/graphql",
    "/actuator", "/actuator/health", "/server-status", "/.DS_Store", "/console",
]


class ContentDiscoveryTest(BaseTest):
    test_id = "DISC-01"; title = "Content-Discovery (sensible Pfade)"; severity = "medium"

    def run(self, ctx):
        h = Http(ctx)
        try:
            miss = h.get(h.abs("/__sollte_nicht_existieren_" + "aud1t__"), max_redirects=0)
            baseline = miss.status  # typische Antwort fuer 'nicht vorhanden'
        except Exception:
            baseline = 404
        hits = []
        for path in PATHS:
            try:
                r = h.get(h.abs(path), max_redirects=0)
            except Exception:
                continue
            # Als Treffer zaehlt eine echte, andere Antwort als die 404-Baseline.
            if r.status in (200, 401, 403) and r.status != baseline:
                loc = header_get(r, "location").lower()
                if r.status == 200 and ("login" in loc or "signin" in loc):
                    continue
                marker = "" if r.status == 200 else f" ({r.status})"
                hits.append(path + marker)
        if hits:
            return self.warn("Erreichbare sensible Pfade: " + ", ".join(hits[:12]) +
                             (" …" if len(hits) > 12 else ""))
        return self.ok("Keine typischen sensiblen Pfade erreichbar.")
