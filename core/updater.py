"""Autoupdater ueber GitHub Releases.

Prueft die Releases dieses Repositorys auf eine neuere Version des Werkzeugs,
laedt das passende Windows-Setup herunter und startet es. Faellt offline auf
ein lokales update.zip zurueck (Zip-Slip-sicher entpackt).

Das Werkzeug nutzt eine eigene Tag-Konvention `sat-vX.Y.Z`, damit sich seine
Releases nicht mit denen des uebergeordneten Projekts mischen.
"""
import json
import os
import shutil
import ssl
import subprocess
import sys
import urllib.request
import zipfile
from datetime import datetime

REPO = "einzigTimo/security-audit-suite"
TAG_PREFIX = "sat-v"
API_RELEASES = f"https://api.github.com/repos/{REPO}/releases"
# Setup-Asset, das der CI-Build hochlaedt (siehe .github/workflows).
ASSET_SUFFIX = "-Setup.exe"


def parse_version(text):
    """'2026.08.27' / '8.3.1' -> vergleichbares Tupel. Nicht-numerische Teile 0."""
    parts = []
    for chunk in str(text).strip().lstrip("vV").replace("-", ".").split("."):
        parts.append(int(chunk) if chunk.isdigit() else 0)
    return tuple(parts) or (0,)


class AppUpdater:
    def __init__(self, base_dir, token=None):
        self.base_dir = base_dir
        self.update_dir = os.path.join(base_dir, "updates")
        self.version_file = os.path.join(base_dir, "version.json")
        # Token fuer private Repos: Argument, Datei .gh_token oder Umgebung.
        self.token = token or self._read_token()

    # ---- Version -------------------------------------------------------
    def get_current_version(self):
        try:
            with open(self.version_file, "r", encoding="utf-8-sig") as f:
                return json.load(f).get("version", "0.0.0")
        except Exception:
            return "0.0.0"

    def _read_token(self):
        env = os.environ.get("SAS_GITHUB_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if env:
            return env
        path = os.path.join(self.base_dir, ".gh_token")
        try:
            if os.path.exists(path):
                return open(path, encoding="utf-8").read().strip()
        except Exception:
            pass
        return None

    # ---- GitHub-Abfrage ------------------------------------------------
    def _api_get(self, url):
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "SecurityAuditSuite-Updater",
        })
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def check_online(self):
        """Neuere Version ermitteln. Rueckgabe {version, tag, url, name} oder None.

        Wirft bei Netzwerk-/Auth-Fehlern eine Exception, damit die Oberflaeche
        den Grund anzeigen kann.
        """
        releases = self._api_get(API_RELEASES)
        current = parse_version(self.get_current_version())
        best = None
        for rel in releases:
            tag = rel.get("tag_name", "")
            if not tag.startswith(TAG_PREFIX) or rel.get("draft"):
                continue
            version = tag[len(TAG_PREFIX):]
            if parse_version(version) <= current:
                continue
            asset = next((a for a in rel.get("assets", [])
                          if a.get("name", "").endswith(ASSET_SUFFIX)), None)
            if not asset:
                continue
            cand = {"version": version, "tag": tag,
                    "url": asset["browser_download_url"], "name": asset["name"]}
            if best is None or parse_version(version) > parse_version(best["version"]):
                best = cand
        return best

    def download(self, url, filename):
        os.makedirs(self.update_dir, exist_ok=True)
        dest = os.path.join(self.update_dir, filename)
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityAuditSuite-Updater"})
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=120, context=ctx) as resp, open(dest, "wb") as f:
            shutil.copyfileobj(resp, f)
        return dest

    def run_installer(self, installer_path):
        """Startet das Setup und signalisiert der App, sich zu beenden."""
        if os.name == "nt":
            os.startfile(installer_path)  # noqa: S606 - vom Nutzer ausgeloest
        else:
            subprocess.Popen(["xdg-open", installer_path])

    # ---- Lokaler Fallback (Zip-Slip-sicher) ----------------------------
    def check_local_zip(self):
        path = os.path.join(self.update_dir, "update.zip")
        return path if os.path.exists(path) else None

    def apply_local_zip(self, zip_path):
        temp_dir = os.path.join(self.update_dir, "temp_extract")
        try:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            os.makedirs(temp_dir)
            base = os.path.realpath(temp_dir)
            with zipfile.ZipFile(zip_path, "r") as z:
                for member in z.namelist():
                    target = os.path.realpath(os.path.join(temp_dir, member))
                    if target != base and not target.startswith(base + os.sep):
                        raise ValueError(f"Unsicherer Pfad im Archiv: {member}")
                z.extractall(temp_dir)
            for item in os.listdir(temp_dir):
                src = os.path.join(temp_dir, item)
                dst = os.path.join(self.base_dir, item)
                if os.path.isdir(src):
                    if os.path.exists(dst):
                        shutil.rmtree(dst)
                    shutil.copytree(src, dst)
                else:
                    shutil.copy2(src, dst)
            shutil.rmtree(temp_dir)
            os.remove(zip_path)
            new_version = datetime.now().strftime("%Y.%m.%d")
            with open(self.version_file, "w", encoding="utf-8") as f:
                json.dump({"version": new_version, "updated": datetime.now().isoformat()}, f)
            return True
        except Exception as e:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            return str(e)
