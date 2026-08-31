from dataclasses import dataclass, field


@dataclass
class TestResult:
    test_id: str
    title: str
    status: str
    severity: str
    message: str
    evidence: list = field(default_factory=list)


# Statuswerte, die einzeln gezaehlt werden. Alles Uebrige faellt in der
# Oberflaeche unter OTHER (BLOCKED, NOT_APPLICABLE, TOOL_ERROR, ERROR, SKIPPED).
PRIMARY_STATUSES = ("PASS", "FAIL", "WARN")


class BaseTest:
    """Vertrag jedes Sicherheitstests.

    Ein Test setzt die Klassenattribute test_id/title/severity und implementiert
    run(context). severity ist eine von: critical, high, medium, low, info.
    requires_session/requires_ui steuern, ob der Test ohne erfasste Session bzw.
    ohne erkanntes Login-Formular uebersprungen wird (BLOCKED/NOT_APPLICABLE).
    """

    test_id: str = "BASE"
    title: str = "Base Test"
    severity: str = "info"
    requires_session: bool = False
    requires_ui: bool = False
    # requires_aggressive: Test fuehrt schreibende/destruktive Proben aus und
    # laeuft nur im opt-in Angriffsmodus (sonst SKIPPED durch die Engine).
    requires_aggressive: bool = False

    def run(self, context) -> TestResult:
        raise NotImplementedError

    # ---- Ergebnis-Helfer -------------------------------------------------

    def ok(self, message="OK.", evidence=None):
        return TestResult(self.test_id, self.title, "PASS", "info", message, evidence or [])

    def fail(self, message, severity=None, evidence=None):
        return TestResult(self.test_id, self.title, "FAIL", severity or self.severity, message, evidence or [])

    def warn(self, message, severity=None, evidence=None):
        return TestResult(self.test_id, self.title, "WARN", severity or self.severity, message, evidence or [])

    def info(self, message, evidence=None):
        return TestResult(self.test_id, self.title, "INFO", "info", message, evidence or [])

    def error(self, message):
        return TestResult(self.test_id, self.title, "TOOL_ERROR", "high", str(message))

    def skipped(self, message="Uebersprungen."):
        return TestResult(self.test_id, self.title, "SKIPPED", "info", message)


class Http:
    """Duenner HTTP-Helfer ueber Playwrights APIRequestContext.

    Kapselt page.request, damit die Tests knapp bleiben und Ausnahmen einheitlich
    behandelt werden. max_redirects=0 erlaubt das Pruefen von Redirect-Zielen.
    """

    def __init__(self, ctx):
        self._req = ctx["page"].request
        self.base_url = ctx["base_url"]
        self._log = ctx.get("log_request")
        self._active_allowed = bool(ctx.get("aggressive"))

    def _trace(self, method, url):
        if self._log:
            shown = url[len(self.base_url):] if url.startswith(self.base_url) else url
            self._log(method, shown or "/")

    def get(self, url, **kw):
        kw.setdefault("timeout", 15000)
        self._trace("GET", url)
        return self._req.get(url, **kw)

    def head(self, url, **kw):
        kw.setdefault("timeout", 15000)
        self._trace("HEAD", url)
        return self._req.head(url, **kw)

    def fetch(self, url, method="GET", **kw):
        method = str(method).upper()
        if method in {"POST", "PUT", "PATCH", "DELETE"} and not self._active_allowed:
            raise PermissionError(
                f"{method} ist nur nach ausdruecklichem Opt-in fuer aktive Pruefungen erlaubt."
            )
        kw.setdefault("timeout", 15000)
        kw["method"] = method
        self._trace(method, url)
        return self._req.fetch(url, **kw)

    def abs(self, path):
        if path.startswith("http"):
            return path
        return f"{self.base_url}{path if path.startswith('/') else '/' + path}"


def aggression(ctx):
    """Staerkestufe des Angriffsmodus als int 1..10 (Standard 5)."""
    try:
        return max(1, min(10, int(ctx.get("aggression", 5))))
    except Exception:
        return 5


def scaled(ctx, lo, hi):
    """Menge linear zur Staerkestufe: Stufe 1 -> lo, Stufe 10 -> hi."""
    level = aggression(ctx)
    return int(round(lo + (hi - lo) * (level - 1) / 9))


def header_get(response, name, default=""):
    """Case-insensitiver Header-Zugriff (Playwright liefert lower-case Keys)."""
    try:
        return response.headers.get(name.lower(), default)
    except Exception:
        return default


def body_of(response, limit=200_000):
    """Antworttext defensiv lesen; bei Binaerinhalt leer."""
    try:
        return response.text()[:limit]
    except Exception:
        return ""
