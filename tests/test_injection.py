"""Aktive Injektionstests. Nicht-destruktiv: nur lesende Anfragen mit Payloads,
eindeutige Marker zur Erkennung, zeitbasierte Techniken nur bei Deep."""
import time
import re
from core.base_test import BaseTest, Http, header_get, body_of

# Kandidaten-Parameter fuer generische Query-Injektion.
PARAMS = ("id", "q", "search", "name", "query", "user", "page", "file", "path", "next", "url", "redirect")


def _param_endpoints(ctx):
    """Aus dem Spider gefundene URLs mit Query-Parametern, plus Basis-URL."""
    urls = [ctx["base_url"]]
    for u in ctx.get("discovered_urls", []):
        if "?" in u and u not in urls:
            urls.append(u)
    return urls[:20]


class SQLInjectionTest(BaseTest):
    test_id = "INJ-01"; title = "SQL Injection"; severity = "critical"

    SQL_ERRORS = ("sql syntax", "mysql_fetch", "ora-01756", "odbc sql", "sqlite_", "postgresql",
                  "syntax error at or near", "unclosed quotation mark", "sqlexception",
                  "you have an error in your sql")

    def run(self, ctx):
        h = Http(ctx)
        base = ctx["base_url"]
        deep = "Deep" in ctx.get("intensity", "")
        # 1) Fehlerbasiert
        for param in PARAMS[:6]:
            try:
                r = h.get(f"{base}/api/items?{param}=1'")
            except Exception:
                continue
            if any(e in body_of(r).lower() for e in self.SQL_ERRORS):
                return self.fail(f"Fehlerbasierte SQLi ueber Parameter '{param}'.")
        # 2) Zeitbasiert (nur Deep — kostet Laufzeit)
        if deep:
            for param in ("id", "q"):
                try:
                    t0 = time.time()
                    h.get(f"{base}/api/items?{param}=1'%20AND%20SLEEP(5)--%20-")
                    if time.time() - t0 > 4.5:
                        return self.fail(f"Zeitbasierte SQLi ueber Parameter '{param}'.")
                except Exception:
                    pass
        return self.ok("Keine SQL-Injection erkannt.")


class ReflectedXSSTest(BaseTest):
    test_id = "INJ-02"; title = "Reflected XSS"; severity = "high"

    def run(self, ctx):
        h = Http(ctx)
        marker = "xssAUD1T"
        payload = f"<svg/onload=alert('{marker}')>"
        for param in PARAMS[:8]:
            try:
                r = h.get(f"{ctx['base_url']}/search?{param}={payload}")
            except Exception:
                continue
            body = body_of(r)
            ctype = header_get(r, "content-type").lower()
            if "html" in ctype and payload in body:
                return self.fail(f"Reflektiertes, ungefiltertes XSS ueber Parameter '{param}'.")
        return self.ok("Keine reflektierte XSS erkannt.")


class OpenRedirectTest(BaseTest):
    test_id = "INJ-03"; title = "Open Redirect"; severity = "medium"

    def run(self, ctx):
        h = Http(ctx)
        target = "https://evil.example.com/aud1t"
        for param in ("next", "url", "redirect", "returnUrl", "return", "dest", "continue"):
            for payload in (target, "//evil.example.com/aud1t"):
                try:
                    r = h.get(f"{ctx['base_url']}/login?{param}={payload}", max_redirects=0)
                except Exception:
                    continue
                loc = header_get(r, "location")
                if r.status in (301, 302, 303, 307, 308) and ("evil.example.com" in loc):
                    return self.fail(f"Open Redirect ueber Parameter '{param}' -> {loc}")
        return self.ok("Keine offene Weiterleitung erkannt.")


class PathTraversalTest(BaseTest):
    test_id = "INJ-04"; title = "Path Traversal / LFI"; severity = "critical"

    def run(self, ctx):
        h = Http(ctx)
        payloads = ("../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
                    "..\\..\\..\\..\\windows\\win.ini")
        for param in ("file", "path", "name", "template", "page", "download"):
            for p in payloads:
                try:
                    r = h.get(f"{ctx['base_url']}/api/files?{param}={p}")
                except Exception:
                    continue
                body = body_of(r).lower()
                if r.status == 200 and ("root:x:0:0" in body or "[extensions]" in body or "for 16-bit app support" in body):
                    return self.fail(f"Path Traversal ueber Parameter '{param}'.")
        return self.ok("Kein Path Traversal erkannt.")


class CommandInjectionTest(BaseTest):
    test_id = "INJ-05"; title = "Command Injection"; severity = "critical"

    def run(self, ctx):
        # Zeitbasiert und daher nur bei Deep — vermeidet Fehlalarme und Last.
        if "Deep" not in ctx.get("intensity", ""):
            return self.skipped("Nur bei Intensitaet 'Deep' (zeitbasiert).")
        h = Http(ctx)
        for param in ("host", "ip", "cmd", "ping", "domain", "target"):
            for payload in ("127.0.0.1;sleep 5", "127.0.0.1%26%26sleep%205", "127.0.0.1|sleep 5"):
                try:
                    t0 = time.time()
                    h.get(f"{ctx['base_url']}/api/ping?{param}={payload}")
                    if time.time() - t0 > 4.5:
                        return self.fail(f"Zeitbasierte Command Injection ueber Parameter '{param}'.")
                except Exception:
                    pass
        return self.ok("Keine Command Injection erkannt.")


class SSTITest(BaseTest):
    test_id = "INJ-06"; title = "Server-Side Template Injection"; severity = "high"

    def run(self, ctx):
        h = Http(ctx)
        # 7*7 -> 49 als eindeutiger, harmloser Indikator.
        for param in ("name", "q", "search", "template", "msg"):
            try:
                r = h.get(f"{ctx['base_url']}/search?{param}=aud%7B%7B7*7%7D%7Dit")
            except Exception:
                continue
            if "aud49it" in body_of(r):
                return self.fail(f"SSTI ueber Parameter '{param}' (7*7 wurde ausgewertet).")
        return self.ok("Keine Template-Injection erkannt.")
