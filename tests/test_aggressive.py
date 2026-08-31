"""Nur im Angriffsmodus (requires_aggressive=True): schreibende und
destruktive Proben. Diese Tests legen Daten an, laden Dateien hoch oder
provozieren serverseitige Anfragen. Sie laufen ausschliesslich mit dem
opt-in Angriffsmodus gegen eigene/autorisierte Systeme."""
import json
from core.base_test import BaseTest, Http, header_get, body_of


class StoredXSSTest(BaseTest):
    test_id = "STOR-01"; title = "Stored / Persistent XSS"; severity = "high"
    requires_aggressive = True

    def run(self, ctx):
        if not ctx.get("aggressive"):
            return self.skipped("Nur im Angriffsmodus.")
        h = Http(ctx)
        marker = "stor3dAUD1T"
        payload = f"<img src=x onerror=alert('{marker}')>"
        try:
            h.fetch(h.abs("/comments"), method="POST",
                    data={"comment": payload, "author": "auditor"},
                    headers={"content-type": "application/json"})
            r = h.get(h.abs("/comments"))
        except Exception as e:
            return self.error(e)
        body = body_of(r)
        ctype = header_get(r, "content-type").lower()
        if "html" in ctype and payload in body:
            return self.fail("Stored/Persistent XSS: gespeicherter Payload wird ungefiltert ausgeliefert.")
        return self.ok("Kein Stored XSS erkannt (Eingabe wird kodiert oder nicht gespeichert).")


class FileUploadTest(BaseTest):
    test_id = "UPLOAD-01"; title = "Unrestricted File Upload"; severity = "high"
    requires_aggressive = True

    def run(self, ctx):
        if not ctx.get("aggressive"):
            return self.skipped("Nur im Angriffsmodus.")
        h = Http(ctx)
        marker = "upl0adAUD1T"
        content = f"<html><script>alert('{marker}')</script></html>"
        fname = "aud1t.html"
        boundary = "----auditBOUNDARY7f3a"
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{fname}"\r\n'
            f"Content-Type: text/html\r\n\r\n"
            f"{content}\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        try:
            r = h.fetch(h.abs("/upload"), method="POST", data=body,
                        headers={"content-type": f"multipart/form-data; boundary={boundary}"})
        except Exception as e:
            return self.error(e)
        if r.status not in (200, 201):
            return self.ok("Upload abgelehnt oder nicht vorhanden.")
        # Ablageort ermitteln (JSON-Feld url oder Location-Header).
        loc = ""
        try:
            loc = (json.loads(body_of(r) or "{}") or {}).get("url", "")
        except Exception:
            loc = ""
        loc = loc or header_get(r, "location")
        if not loc:
            return self.warn("Upload akzeptiert, Ablageort nicht ermittelbar — manuell pruefen.")
        try:
            r2 = h.get(h.abs(loc))
        except Exception:
            return self.warn("Upload akzeptiert, Abruf der Datei fehlgeschlagen — manuell pruefen.")
        ctype = header_get(r2, "content-type").lower()
        if marker in body_of(r2) and ("html" in ctype or "svg" in ctype):
            return self.fail("Unrestricted File Upload: ausfuehrbare Datei gespeichert und als "
                             "aktiver Inhalt (HTML/SVG) ausgeliefert.")
        return self.ok("Upload wird nicht als aktiver Inhalt ausgeliefert.")


class SSRFTest(BaseTest):
    test_id = "SSRF-01"; title = "Server-Side Request Forgery"; severity = "high"
    requires_aggressive = True

    def run(self, ctx):
        if not ctx.get("aggressive"):
            return self.skipped("Nur im Angriffsmodus.")
        h = Http(ctx)
        marker = "ssrfAUD1T"
        internal = f"http://127.0.0.1/internal-{marker}"
        for param in ("url", "target", "dest", "uri", "path", "callback", "next", "image"):
            try:
                r = h.get(f"{ctx['base_url']}/api/fetch?{param}={internal}")
            except Exception:
                continue
            if marker in body_of(r):
                return self.fail(f"SSRF ueber Parameter '{param}': Server ruft die angegebene URL ab "
                                 f"und spiegelt die Antwort.")
        return self.ok("Keine SSRF erkannt.")
