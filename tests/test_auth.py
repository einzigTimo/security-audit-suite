"""Authentifizierungs- und Session-naehere Pruefungen: Schutz vor
Brute-Force am Login und Analyse ausgestellter JWTs."""
import time
from core.base_test import BaseTest, Http, header_get


class RateLimitTest(BaseTest):
    test_id = "AUTH-01"; title = "Rate-Limiting am Login"; severity = "medium"

    def run(self, ctx):
        # Viele Fehlversuche kosten Zeit — daher nur ab Medium.
        if ctx.get("intensity", "").startswith("Fast"):
            return self.skipped("Nur ab Intensitaet 'Medium'.")
        h = Http(ctx)
        login = h.abs(ctx.get("config", {}).get("login_path", "/login"))
        limited = False
        seen_any = False
        for i in range(18):
            try:
                r = h.fetch(login, method="POST",
                            data={"username": "audit", "password": f"wrong{i}"},
                            headers={"content-type": "application/x-www-form-urlencoded"})
            except Exception:
                continue
            seen_any = True
            if r.status == 429 or "retry-after" in {k.lower() for k in _headers(r)}:
                limited = True
                break
        if not seen_any:
            return self.skipped("Login-Endpunkt nicht erreichbar.")
        if limited:
            return self.ok("Login drosselt wiederholte Fehlversuche (429/Retry-After).")
        return self.warn("Kein erkennbares Rate-Limiting am Login — Brute-Force erleichtert.")


def _headers(r):
    try:
        return list(r.headers.keys())
    except Exception:
        return []


class JwtAnalysisTest(BaseTest):
    test_id = "AUTH-02"; title = "JWT-Analyse"; severity = "high"; requires_session = True

    def run(self, ctx):
        import base64, json
        try:
            ctx["page"].goto(ctx["base_url"], wait_until="domcontentloaded", timeout=15000)
            cookies = ctx["context"].cookies()
        except Exception as e:
            return self.error(e)
        tokens = []
        for c in cookies:
            v = c.get("value", "")
            parts = v.split(".")
            if v.count(".") == 2 and parts[0] and parts[1]:
                tokens.append(v)
        if not tokens:
            return self.skipped("Kein JWT in den Cookies gefunden.")
        for tok in tokens:
            try:
                head = json.loads(_b64(tok.split(".")[0]))
            except Exception:
                continue
            alg = str(head.get("alg", "")).lower()
            if alg == "none":
                return self.fail("JWT mit alg=none akzeptiert — Signatur kann umgangen werden.")
            try:
                payload = json.loads(_b64(tok.split(".")[1]))
                if "exp" not in payload:
                    return self.warn("JWT ohne Ablaufzeit (exp) — Token bleibt unbegrenzt gueltig.")
            except Exception:
                pass
        return self.ok("JWT verwendet eine signierende Alg und enthaelt eine Ablaufzeit.")


def _b64(seg):
    import base64
    seg += "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg.encode()).decode("utf-8", "replace")
