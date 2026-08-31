"""Lokale Ziel-App in zwei Modi: 'vuln' (verwundbar) und 'secure' (gehaertet).
Dient ausschliesslich der Verifikation des Testkatalogs."""
import base64
import html
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs


def _b64u(obj):
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")


# vuln: alg=none (leere Signatur); secure: signierendes Verfahren mit Ablauf
JWT_NONE = _b64u({"alg": "none", "typ": "JWT"}) + "." + _b64u({"sub": "1"}) + "."
JWT_OK = _b64u({"alg": "HS256", "typ": "JWT"}) + "." + _b64u({"sub": "1", "exp": 9999999999}) + ".c2ln"

_login_attempts = 0
_login_lock = threading.Lock()

# Persistenter Zustand je Modus (vuln/secure) fuer schreibende Angriffs-Proben.
_state_lock = threading.Lock()
_comments = {"vuln": [], "secure": []}
_uploads = {"vuln": {}, "secure": {}}


def _guess_ctype(name):
    low = name.lower()
    if low.endswith(".html") or low.endswith(".htm"):
        return "text/html"
    if low.endswith(".svg"):
        return "image/svg+xml"
    if low.endswith(".js"):
        return "application/javascript"
    return "application/octet-stream"


def _parse_multipart(raw, ctype):
    """Minimaler Multipart-Parser: erstes Datei-Teil -> (filename, bytes)."""
    if "boundary=" not in ctype:
        return None, None
    boundary = ("--" + ctype.split("boundary=", 1)[1].strip().strip('"')).encode()
    for part in raw.split(boundary):
        if b"filename=" not in part:
            continue
        head, _, content = part.partition(b"\r\n\r\n")
        if not content:
            continue
        try:
            hdr = head.decode("utf-8", "replace")
            fname = hdr.split("filename=", 1)[1].split('"')[1]
        except Exception:
            fname = "upload.bin"
        return fname, content.rsplit(b"\r\n", 1)[0]
    return None, None


class Handler(BaseHTTPRequestHandler):
    MODE = "vuln"

    def log_message(self, *a):
        pass

    # ---- Antwort-Helfer --------------------------------------------------
    def _send(self, code, body="", ctype="text/html", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response_only(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if self.MODE == "secure":
            self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            self.send_header("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Server", "nginx")
        else:
            self.send_header("Server", "Apache/2.4.1 (Win32) PHP/7.2.1")
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _q(self, name):
        return parse_qs(urlparse(self.path).query).get(name, [""])[0]

    def _any_q(self):
        return parse_qs(urlparse(self.path).query)

    # ---- Methoden --------------------------------------------------------
    def do_OPTIONS(self):
        allow = "GET, POST, HEAD, OPTIONS" if self.MODE == "secure" else "GET, POST, PUT, DELETE, TRACE, OPTIONS"
        self._send(204, "", extra=[("Allow", allow)])

    def do_TRACE(self):
        if self.MODE == "secure":
            self._send(405, "Method Not Allowed")
        else:
            self._send(200, "TRACE " + self.path, ctype="message/http")

    def do_PATCH(self):
        self._route_write("PATCH")

    def do_PUT(self):
        self._route_write("PUT")

    def do_POST(self):
        self._route_write("POST")

    def do_DELETE(self):
        self._route_write("DELETE")

    def _route_write(self, method):
        path = urlparse(self.path).path
        if path == "/login" and method == "POST":
            return self._login_post()
        if path == "/comments" and method == "POST":
            return self._comments_post()
        if path == "/upload" and method == "POST":
            return self._upload_post()
        if path.startswith("/api/users/") and method == "DELETE":
            return self._user_delete(path)
        return self._api_write()

    def _read_body(self):
        length = int(self.headers.get("content-length", 0) or 0)
        return self.rfile.read(length) if length else b""

    def _comments_post(self):
        raw = self._read_body()
        try:
            payload = json.loads(raw or b"{}")
            text = str(payload.get("comment") or payload.get("text") or "")
        except Exception:
            text = parse_qs(raw.decode("utf-8", "replace")).get("comment", [""])[0]
        with _state_lock:
            _comments[self.MODE].append(text)
        return self._send(201, json.dumps({"status": "ok"}), ctype="application/json")

    def _upload_post(self):
        raw = self._read_body()
        fname, content = _parse_multipart(raw, self.headers.get("content-type", ""))
        if not fname:
            return self._send(400, "no file")
        low = fname.lower()
        dangerous = low.endswith((".html", ".htm", ".svg", ".js", ".php", ".phtml", ".exe"))
        if self.MODE == "secure" and dangerous:
            return self._send(403, json.dumps({"error": "file type not allowed"}),
                              ctype="application/json")
        with _state_lock:
            _uploads[self.MODE][fname] = content
        return self._send(200, json.dumps({"url": f"/uploads/{fname}"}), ctype="application/json")

    def _user_delete(self, path):
        uid = path.rstrip("/").split("/")[-1]
        if self.MODE == "secure":
            return self._send(401, "unauthorized")
        return self._send(200, json.dumps({"deleted": uid, "status": "ok"}),
                          ctype="application/json")

    def _login_post(self):
        global _login_attempts
        if self.MODE == "secure":
            with _login_lock:
                _login_attempts += 1
                n = _login_attempts
            if n > 5:
                return self._send(429, "too many requests", extra=[("Retry-After", "60")])
            return self._send(401, "unauthorized")
        return self._send(401, "unauthorized")

    def _api_write(self):
        if urlparse(self.path).path == "/login":
            return self._login_post()
        length = int(self.headers.get("content-length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        if self.MODE == "vuln":
            # Uebernimmt clientseitige Felder ungeprueft (Mass Assignment).
            try:
                payload = json.loads(raw or b"{}")
            except Exception:
                payload = {}
            merged = {"id": 1, "name": "user", **payload}
            self._send(200, json.dumps(merged), ctype="application/json")
        else:
            self._send(200, json.dumps({"id": 1, "name": "user"}), ctype="application/json")

    def do_GET(self):
        p = urlparse(self.path).path
        origin = self.headers.get("Origin", "")
        secure = self.MODE == "secure"

        # CORS-Header (nur vuln reflektiert)
        cors = []
        if origin and not secure:
            cors = [("Access-Control-Allow-Origin", origin), ("Access-Control-Allow-Credentials", "true")]

        # Startseite mit Cookie
        if p == "/":
            if secure:
                cookie_headers = [
                    ("Set-Cookie", "__Host-sid=abc123; Secure; HttpOnly; SameSite=Strict; Path=/"),
                    ("Set-Cookie", f"__Host-jwt={JWT_OK}; Secure; HttpOnly; SameSite=Strict; Path=/"),
                ]
                jq = "jquery-3.7.1.min.js"
                # externes Skript mit Integritaetspruefung + nur https-Ressourcen
                extra_scripts = '<script src="https://cdn.example.com/lib.js" integrity="sha384-x" crossorigin></script><script src="/app.js"></script>'
                form = '<form method="post" action="/login"><input type="hidden" name="csrf_token" value="abc"><input name="user"></form>'
            else:
                cookie_headers = [
                    ("Set-Cookie", "sid=abc123; Path=/"),
                    ("Set-Cookie", "track=xyz; Secure; SameSite=None; Path=/"),
                    ("Set-Cookie", f"jwt={JWT_NONE}; Path=/"),
                ]
                jq = "jquery-3.4.1.min.js"
                extra_scripts = '<script src="http://cdn.evil.example.com/track.js"></script><script src="https://cdn.example.com/lib.js"></script><script src="/app.js"></script>'
                form = '<form method="post" action="/login"><input name="user"><input name="pass" type="password"></form>'
            body = f"<!doctype html><html><head><title>Ziel</title>" \
                   f'<script src="/vendor/{jq}"></script>{extra_scripts}</head><body>Start{form}</body></html>'
            return self._send(200, body, extra=cors + cookie_headers)

        if p == "/robots.txt":
            if secure:
                return self._send(404, "not found")
            return self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /backup\n", ctype="text/plain")

        if p.rstrip("/") in ("/static", "/assets", "/uploads"):
            if secure:
                return self._send(404, "not found")
            return self._send(200, "<html><head><title>Index of /static</title></head><body><h1>Index of /static</h1></body></html>")

        if p == "/.git/config":
            if secure:
                return self._send(404, "not found")
            return self._send(200, "[core]\n\trepositoryformatversion = 0\n\tbare = false\n", ctype="text/plain")

        if p in ("/.env", "/appsettings.json", "/web.config", "/config.php"):
            if secure:
                return self._send(404, "not found")
            return self._send(200, "SECRET_KEY=s3cr3t\nDB_PASSWORD=hunter2\nAPI_KEY=abcd\n", ctype="text/plain")

        if p == "/app.js":
            return self._send(200, "console.log('app');", ctype="application/javascript")
        if p == "/app.js.map":
            if secure:
                return self._send(404, "not found")
            return self._send(200, '{"version":3,"sources":["src/app.ts"],"mappings":""}', ctype="application/json")

        if p in ("/.well-known/security.txt", "/security.txt"):
            if secure:
                return self._send(200, "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\n", ctype="text/plain")
            return self._send(404, "not found")

        if p == "/api/items":
            val = self._q("id") or self._q("q")
            up = val.upper()
            if not secure and "'" in val and "SLEEP" not in up:
                return self._send(500, "You have an error in your SQL syntax near '''")
            if not secure and "SLEEP" in up:
                time.sleep(5)
                return self._send(200, "[]", ctype="application/json")
            # Boolean-basierte SQLi: wahre Bedingung liefert Daten, falsche nicht.
            if not secure and "1=1" in val:
                return self._send(200, json.dumps([{"id": 1}, {"id": 2}, {"id": 3}]),
                                  ctype="application/json")
            if not secure and "1=2" in val:
                return self._send(200, "[]", ctype="application/json")
            return self._send(200, "[]", ctype="application/json")

        if p == "/search":
            q = self._q("q") or self._q("name") or self._q("search") or self._q("query") or self._q("msg")
            if secure:
                return self._send(200, f"<html><body>Suche: {html.escape(q)}</body></html>")
            rendered = q.replace("{{7*7}}", "49")  # simuliert SSTI-Auswertung
            return self._send(200, f"<html><body>Suche: {rendered}</body></html>")

        if p == "/login":
            qs = self._any_q()
            for key in ("next", "url", "redirect", "returnUrl", "return", "dest", "continue"):
                if key in qs:
                    dest = qs[key][0]
                    if secure:
                        return self._send(302, "", extra=[("Location", "/dashboard")])
                    return self._send(302, "", extra=[("Location", dest)])
            return self._send(200, "<html><body>Login</body></html>", extra=cors)

        if p == "/api/files":
            name = self._q("file") or self._q("path") or self._q("name")
            if not secure and ("etc/passwd" in name or "%2fetc%2fpasswd" in name.lower()):
                return self._send(200, "root:x:0:0:root:/root:/bin/bash\n", ctype="text/plain")
            if not secure and "win.ini" in name.lower():
                return self._send(200, "[extensions]\n; for 16-bit app support\n", ctype="text/plain")
            return self._send(400, "bad request")

        if p == "/api/ping":
            host = self._q("host") or self._q("ip") or self._q("cmd") \
                or self._q("ping") or self._q("domain") or self._q("target")
            low = host.lower()
            if not secure and "sleep" in low:
                time.sleep(5)
                return self._send(200, "pong", ctype="text/plain")
            # Command Injection mit direktem Output: echo <marker> wird ausgegeben.
            if not secure and "echo" in low:
                marker = host.split("echo", 1)[1].strip().strip(";|&")
                return self._send(200, f"PING 127.0.0.1\n{marker}\n", ctype="text/plain")
            return self._send(200 if secure else 400, "pong")

        # Stored XSS: gespeicherte Kommentare ausgeben (vuln roh, secure kodiert).
        if p == "/comments":
            with _state_lock:
                items = list(_comments[self.MODE])
            if secure:
                rows = "".join(f"<li>{html.escape(c)}</li>" for c in items)
            else:
                rows = "".join(f"<li>{c}</li>" for c in items)
            return self._send(200, f"<html><body><ul>{rows}</ul></body></html>")

        # Hochgeladene Dateien ausliefern.
        if p.startswith("/uploads/"):
            name = p.split("/uploads/", 1)[1]
            with _state_lock:
                data = _uploads[self.MODE].get(name)
            if data is None:
                return self._send(404, "not found")
            if secure:
                # Gehaertet: nie als aktiver Inhalt, immer als Download-Text.
                return self._send(200, data, ctype="text/plain",
                                  extra=[("Content-Disposition", "attachment")])
            return self._send(200, data, ctype=_guess_ctype(name))

        # SSRF: Server ruft eine uebergebene URL ab und spiegelt sie (nur vuln).
        if p == "/api/fetch":
            target = ""
            for key in ("url", "target", "dest", "uri", "path", "callback", "next", "image"):
                target = self._q(key)
                if target:
                    break
            if secure:
                return self._send(400, "blocked: URL not in allowlist")
            return self._send(200, f"<html><body>proxied {target}</body></html>")

        # Geschuetzte Bereiche
        if p in ("/dashboard", "/admin", "/settings", "/account", "/api/me"):
            if secure:
                return self._send(302, "", extra=[("Location", "/login")])
            return self._send(200, "<html><body>Geheimes Dashboard</body></html>")

        # APIs mit Daten
        if p in ("/api/users", "/api/profile", "/api/admin", "/api/orders", "/api/accounts"):
            if secure:
                return self._send(401, "unauthorized")
            return self._send(200, json.dumps([{"id": 1, "email": "a@b.de", "role": "admin"}]),
                              ctype="application/json", extra=cors)

        # IDOR-Objekte
        if p.startswith("/api/users/") or p.startswith("/api/orders/") or p.startswith("/api/accounts/") or p.startswith("/api/documents/"):
            if secure:
                return self._send(401, "unauthorized")
            return self._send(200, json.dumps({"id": p.split("/")[-1], "email": "user@example.com"}),
                              ctype="application/json")

        # Unbekannt: Fehlerseite
        if secure:
            return self._send(404, "<html><body>Nicht gefunden</body></html>")
        return self._send(500, "<html><body><pre>Traceback (most recent call last):\n  File \"app.py\", line 42, in handler\n    raise ValueError(x)\nValueError: boom</pre></body></html>")


def make_server(port, mode, certfile, keyfile):
    import ssl
    httpd = ThreadingHTTPServer(("127.0.0.1", port), type("H", (Handler,), {"MODE": mode}))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd
