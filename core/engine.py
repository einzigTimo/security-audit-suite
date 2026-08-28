import importlib
import pkgutil
import sys
import os
from core.base_test import BaseTest, TestResult
from core.browser import BrowserManager
from core.spider import Spider

class AuditEngine:
    def __init__(self, config):
        self.config = config
        self.results = []
        self.stop_requested = False
        self.progress_callback = None
        self.log_callback = None
        self.current_test_callback = None
        self.result_callback = None
        self.discovered_urls = []

    def log(self, msg):
        if self.log_callback:
            self.log_callback(msg)

    def load_tests(self):
        tests = []
        test_dir = os.path.join(os.path.dirname(__file__), "..", "tests")
        test_dir = os.path.abspath(test_dir)
        if test_dir not in sys.path:
            sys.path.insert(0, test_dir)
        for _, name, _ in pkgutil.iter_modules([test_dir]):
            if name.startswith("test_"):
                mod = importlib.import_module(name)
                for attr in dir(mod):
                    obj = getattr(mod, attr)
                    if isinstance(obj, type) and issubclass(obj, BaseTest) and obj is not BaseTest:
                        tests.append(obj())
        return tests

    def run(self):
        base_url = self.config["url"].rstrip("/")
        intensity = self.config.get("intensity", "Fast (Baseline)")

        bm = BrowserManager(headless=self.config.get("headless", False), storage_state=self.config.get("session_file"))
        page = bm.start()

        tests = self.load_tests()
        has_session = bool(self.config.get("session_file"))
        ui_available = False

        self.log("PRE-FLIGHT: Technische Vorpruefung")
        try:
            res = page.goto(base_url, wait_until="domcontentloaded", timeout=15000)
            if not res or res.status >= 500:
                self.log("  -> [BLOCKED] System nicht erreichbar.")
                bm.stop()
                return self.results
        except Exception as e:
            self.log(f"  -> [BLOCKED] Verbindungsfehler: {e}")
            bm.stop()
            return self.results

        if "login.microsoftonline" in page.url.lower() or "entra" in page.url.lower():
            self.log("  -> [INFO] SSO erkannt.")
        else:
            login_url = f"{base_url}{self.config.get('login_path', '/login')}"
            try:
                page.goto(login_url, wait_until="domcontentloaded", timeout=10000)
                email_sel = self.config.get("email_sel", "input[type='email']")
                pass_sel = self.config.get("pass_sel", "input[type='password']")
                if page.locator(email_sel).count() > 0 and page.locator(pass_sel).count() > 0:
                    ui_available = True
            except:
                pass

        if intensity != "Fast (Baseline)":
            self.log("SPIDER: Crawle Anwendung...")
            self.discovered_urls = Spider(page, base_url).crawl()
            self.log(f"  -> [INFO] {len(self.discovered_urls)} URLs gefunden.")

        self.log(f"\nStarte {len(tests)} Tests (Intensitaet: {intensity})...\n")
        ctx = {
            "page": page, "context": bm.get_context(), "base_url": base_url,
            "config": self.config, "has_session": has_session, "ui_available": ui_available,
            "discovered_urls": self.discovered_urls, "intensity": intensity,
            "log_request": lambda method, path: self.log(f"      \u00b7 {method} {path}"),
        }

        for i, test in enumerate(tests, 1):
            if self.stop_requested:
                break
            self.log(f"[{i}/{len(tests)}] {test.test_id}: {test.title}")
            if self.current_test_callback:
                self.current_test_callback(f"{test.test_id}: {test.title}")
            try:
                if test.requires_session and not has_session:
                    result = TestResult(test.test_id, test.title, "BLOCKED", test.severity, "Keine Session erfasst.")
                elif test.requires_ui and not ui_available:
                    result = TestResult(test.test_id, test.title, "NOT_APPLICABLE", test.severity, "Kein lokales Login-Formular.")
                else:
                    result = test.run(ctx)
            except Exception as e:
                result = TestResult(test.test_id, test.title, "TOOL_ERROR", test.severity, str(e))
            self.results.append({"test_id": result.test_id, "title": result.title, "status": result.status, "severity": result.severity, "message": result.message})
            self.log(f"  -> [{result.status}] {result.message}")
            if self.result_callback:
                self.result_callback(result.status)
            if self.progress_callback:
                self.progress_callback(i, len(tests))

        bm.stop()
        return self.results

    def stop(self):
        self.stop_requested = True