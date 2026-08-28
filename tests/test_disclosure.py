"""Informationspreisgabe: exponierte Pfade, Verzeichnisse, Fehlerseiten."""
from core.base_test import BaseTest, Http, header_get, body_of


class RobotsTest(BaseTest):
    test_id = "INF-01"; title = "robots.txt"; severity = "info"

    def run(self, ctx):
        try:
            r = Http(ctx).get(Http(ctx).abs("/robots.txt"))
        except Exception as e:
            return self.error(e)
        if r.status != 200:
            return self.ok("Keine robots.txt.")
        body = body_of(r)
        interesting = [ln for ln in body.splitlines()
                       if ln.lower().startswith("disallow") and ln.split(":", 1)[-1].strip() not in ("", "/")]
        if interesting:
            return self.warn("robots.txt nennt sensible Pfade: " + "; ".join(interesting[:5]))
        return self.ok("robots.txt vorhanden und unauffaellig.")


class DirectoryListingTest(BaseTest):
    test_id = "INF-02"; title = "Directory Listing"; severity = "medium"

    def run(self, ctx):
        h = Http(ctx)
        for path in ("/", "/static/", "/assets/", "/uploads/", "/files/", "/images/"):
            try:
                r = h.get(h.abs(path))
            except Exception:
                continue
            if r.status == 200 and "index of /" in body_of(r).lower():
                return self.fail(f"Directory Listing aktiv unter {path}")
        return self.ok("Kein Directory Listing gefunden.")


class GitExposureTest(BaseTest):
    test_id = "INF-03"; title = ".git-Verzeichnis"; severity = "high"

    def run(self, ctx):
        h = Http(ctx)
        try:
            r = h.get(h.abs("/.git/config"))
        except Exception as e:
            return self.error(e)
        if r.status == 200 and "[core]" in body_of(r).lower():
            return self.fail("/.git/config oeffentlich erreichbar (Quellcode-Leak moeglich).")
        return self.ok("/.git nicht oeffentlich erreichbar.")


class EnvExposureTest(BaseTest):
    test_id = "INF-04"; title = "Konfigurations-/Secret-Dateien"; severity = "critical"

    def run(self, ctx):
        h = Http(ctx)
        hits = []
        for path in ("/.env", "/appsettings.json", "/web.config", "/config.php", "/.aws/credentials"):
            try:
                r = h.get(h.abs(path))
            except Exception:
                continue
            if r.status == 200:
                body = body_of(r).lower()
                if any(k in body for k in ("secret", "password", "connectionstring", "api_key", "aws_", "key=")):
                    hits.append(path)
        if hits:
            return self.fail("Sensible Dateien erreichbar: " + ", ".join(hits))
        return self.ok("Keine exponierten Konfig-/Secret-Dateien.")


class ErrorLeakTest(BaseTest):
    test_id = "INF-05"; title = "Stacktrace-/Fehler-Leak"; severity = "medium"

    def run(self, ctx):
        h = Http(ctx)
        try:
            r = h.get(h.abs("/this-path-should-not-exist-" + "aud1t"))
        except Exception as e:
            return self.error(e)
        body = body_of(r).lower()
        markers = ("traceback (most recent call last)", "system.exception", "stack trace",
                   "at system.", "microsoft .net", "sqlexception", "org.springframework",
                   "warning: ", "fatal error", "line ")
        strong = ("traceback (most recent call last)", "system.exception", "stack trace",
                  "at system.", "sqlexception", "org.springframework")
        if any(m in body for m in strong):
            return self.fail("Fehlerseite gibt einen Stacktrace preis.")
        if "exception" in body and "line" in body:
            return self.warn("Fehlerseite koennte interne Details preisgeben.")
        return self.ok("Keine Stacktraces auf Fehlerseiten.")


class SourceMapTest(BaseTest):
    test_id = "INF-06"; title = "Source Maps"; severity = "low"

    def run(self, ctx):
        import re
        h = Http(ctx)
        try:
            body = body_of(h.get(ctx["base_url"]))
        except Exception as e:
            return self.error(e)
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js)["\']', body, re.I)
        for src in scripts[:8]:
            try:
                r = h.get(h.abs(src) + ".map")
            except Exception:
                continue
            if r.status == 200 and '"sources"' in body_of(r):
                return self.warn(f"Source Map erreichbar: {src}.map")
        return self.ok("Keine erreichbaren Source Maps.")


class SecurityTxtTest(BaseTest):
    test_id = "INF-07"; title = "security.txt"; severity = "info"

    def run(self, ctx):
        h = Http(ctx)
        for path in ("/.well-known/security.txt", "/security.txt"):
            try:
                r = h.get(h.abs(path))
            except Exception:
                continue
            if r.status == 200 and "contact" in body_of(r).lower():
                return self.ok("security.txt vorhanden.")
        return self.info("Keine security.txt (Best-Practice-Empfehlung).")
