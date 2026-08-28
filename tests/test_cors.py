"""CORS-Fehlkonfiguration: Reflektion beliebiger Origins, Wildcard mit Credentials."""
from core.base_test import BaseTest, Http, header_get


class CorsTest(BaseTest):
    test_id = "CORS-01"; title = "CORS-Konfiguration"; severity = "high"

    def run(self, ctx):
        h = Http(ctx)
        probe = "https://evil.example.com"
        for path in ("", "/api", "/api/me", "/api/users"):
            try:
                r = h.get(h.abs(path or "/"), headers={"Origin": probe})
            except Exception:
                continue
            acao = header_get(r, "access-control-allow-origin")
            acac = header_get(r, "access-control-allow-credentials").lower()
            if acao == probe and acac == "true":
                return self.fail(f"CORS reflektiert beliebige Origin mit Credentials ({path or '/'}).")
            if acao == "*" and acac == "true":
                return self.fail("CORS erlaubt Wildcard-Origin zusammen mit Credentials.")
            if acao == probe:
                return self.warn(f"CORS reflektiert beliebige Origin ({path or '/'}).")
        return self.ok("CORS restriktiv (keine Origin-Reflektion).")
