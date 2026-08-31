"""Cryptographically bound updates from the public project releases.

Every installer and local update archive needs a matching ``.sha256`` sidecar.
No credentials are read or transmitted by this module.
"""
import hashlib
import hmac
import json
import os
import re
import shutil
import ssl
import subprocess
import urllib.parse
import urllib.request
import zipfile

REPO = "einzigTimo/security-audit-suite"
TAG_PREFIX = "sat-v"
API_RELEASES = f"https://api.github.com/repos/{REPO}/releases"
ASSET_SUFFIX = "-Setup.exe"
MAX_CHECKSUM_BYTES = 64 * 1024


class UpdateVerificationError(RuntimeError):
    """The update is not cryptographically bound to an expected digest."""


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_sha256(text, expected_name):
    digest_pattern = re.compile(r"^[0-9a-fA-F]{64}$")
    for raw_line in str(text).splitlines():
        line = raw_line.strip()
        if digest_pattern.fullmatch(line):
            return line.lower()
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or not digest_pattern.fullmatch(parts[0]):
            continue
        named = parts[1].lstrip("* ").strip()
        if os.path.basename(named) == expected_name:
            return parts[0].lower()
    raise UpdateVerificationError("SHA-256-Pruefsumme ist ungueltig oder passt nicht zum Asset.")


def verify_sha256(path, expected_digest):
    if not hmac.compare_digest(sha256_file(path), str(expected_digest).lower()):
        raise UpdateVerificationError("SHA-256-Pruefung fehlgeschlagen; Update wird verworfen.")
    return True


def _trusted_release_url(url):
    parsed = urllib.parse.urlparse(str(url))
    prefix = f"/{REPO}/releases/download/"
    return parsed.scheme == "https" and parsed.hostname == "github.com" and parsed.path.startswith(prefix)


def parse_version(text):
    """'2026.08.27' / '8.3.1' -> vergleichbares Tupel. Nicht-numerische Teile 0."""
    parts = []
    for chunk in str(text).strip().lstrip("vV").replace("-", ".").split("."):
        parts.append(int(chunk) if chunk.isdigit() else 0)
    return tuple(parts) or (0,)


class AppUpdater:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.update_dir = os.path.join(base_dir, "updates")
        self.version_file = os.path.join(base_dir, "version.json")

    # ---- Version -------------------------------------------------------
    def get_current_version(self):
        try:
            with open(self.version_file, "r", encoding="utf-8-sig") as f:
                return json.load(f).get("version", "0.0.0")
        except Exception:
            return "0.0.0"

    # ---- GitHub-Abfrage ------------------------------------------------
    def _api_get(self, url):
        req = urllib.request.Request(url, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "SecurityAuditSuite-Updater",
        })
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def check_online(self):
        """Neuere Version ermitteln. Rueckgabe {version, tag, url, checksum_url, name} oder None.

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
            assets = rel.get("assets", [])
            asset = next((a for a in assets if a.get("name", "").endswith(ASSET_SUFFIX)), None)
            if not asset:
                continue
            checksum_name = asset.get("name", "") + ".sha256"
            checksum = next((a for a in assets if a.get("name") == checksum_name), None)
            if not checksum:
                continue
            asset_url = asset.get("browser_download_url", "")
            checksum_url = checksum.get("browser_download_url", "")
            if not _trusted_release_url(asset_url) or not _trusted_release_url(checksum_url):
                continue
            cand = {
                "version": version,
                "tag": tag,
                "url": asset_url,
                "checksum_url": checksum_url,
                "name": asset["name"],
            }
            if best is None or parse_version(version) > parse_version(best["version"]):
                best = cand
        return best

    def _read_checksum(self, url, filename):
        if not _trusted_release_url(url):
            raise UpdateVerificationError("Nicht vertrauenswuerdige Checksum-URL.")
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityAuditSuite-Updater"})
        with urllib.request.urlopen(req, timeout=30, context=ssl.create_default_context()) as resp:
            payload = resp.read(MAX_CHECKSUM_BYTES + 1)
        if len(payload) > MAX_CHECKSUM_BYTES:
            raise UpdateVerificationError("Checksum-Datei ist unerwartet gross.")
        return parse_sha256(payload.decode("ascii", "strict"), filename)

    def download(self, url, filename, checksum_url):
        safe_name = os.path.basename(filename)
        if safe_name != filename or not safe_name.endswith(ASSET_SUFFIX):
            raise UpdateVerificationError("Ungueltiger Update-Dateiname.")
        if not _trusted_release_url(url):
            raise UpdateVerificationError("Nicht vertrauenswuerdige Download-URL.")
        expected = self._read_checksum(checksum_url, safe_name)
        os.makedirs(self.update_dir, exist_ok=True)
        dest = os.path.join(self.update_dir, safe_name)
        partial = dest + ".part"
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityAuditSuite-Updater"})
        ctx = ssl.create_default_context()
        try:
            with urllib.request.urlopen(req, timeout=120, context=ctx) as resp, open(partial, "wb") as f:
                shutil.copyfileobj(resp, f)
            verify_sha256(partial, expected)
            os.replace(partial, dest)
        except Exception:
            if os.path.exists(partial):
                os.remove(partial)
            raise
        return dest, expected

    def run_installer(self, installer_path, expected_digest):
        """Verifiziert erneut und startet erst dann das freigegebene Setup."""
        verify_sha256(installer_path, expected_digest)
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
        checksum_path = zip_path + ".sha256"
        try:
            if not os.path.isfile(checksum_path):
                raise UpdateVerificationError("Verpflichtende update.zip.sha256 fehlt.")
            with open(checksum_path, "r", encoding="ascii") as handle:
                checksum_text = handle.read(MAX_CHECKSUM_BYTES + 1)
            if len(checksum_text) > MAX_CHECKSUM_BYTES:
                raise UpdateVerificationError("Checksum-Datei ist unerwartet gross.")
            expected = parse_sha256(checksum_text, os.path.basename(zip_path))
            verify_sha256(zip_path, expected)
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
            os.makedirs(temp_dir)
            base = os.path.realpath(temp_dir)
            with zipfile.ZipFile(zip_path, "r") as z:
                for member in z.namelist():
                    target = os.path.realpath(os.path.join(temp_dir, member))
                    if target != base and not target.startswith(base + os.sep):
                        raise UpdateVerificationError("Unsicherer Pfad im Update-Archiv.")
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
            os.remove(checksum_path)
            return True
        except Exception as e:
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            return str(e)
