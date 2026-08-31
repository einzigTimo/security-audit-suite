"""Local, value-redacting public-readiness and secret scan."""

from __future__ import annotations

import re
import sys
import subprocess
from pathlib import Path


TEXT_NAMES = {"LICENSE", "NOTICE", ".gitignore"}
TEXT_SUFFIXES = {".py", ".pyw", ".md", ".txt", ".json", ".iss", ".spec", ".yml", ".yaml", ".toml", ".ps1"}
FORBIDDEN_DIRS = {
    ".claude", ".mcp", ".agent-state", "build", "dist", "reports", "logs",
    "sessions", "browser-state", "graphify-out", "__pycache__", ".pytest_cache",
    "." + "project" + "atlas",
}
FORBIDDEN_FILES = {".env", ".gh_token", "storage-state.json"}
FORBIDDEN_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".pyc", ".log"}

CONTENT_RULES = {
    "PRIVATE_BRAND": re.compile("Studio" + r"\s+" + "Hamburg", re.I),
    "PRIVATE_TOOL": re.compile("Project" + "Atlas", re.I),
    "INTERNAL_PRODUCT_A": re.compile("Arbeit" + "sschutz", re.I),
    "INTERNAL_PRODUCT_B": re.compile("Berechtigungs" + "verwaltung", re.I),
    "INTERNAL_PRODUCT_C": re.compile(r"ASA[- ]?" + "Kompass", re.I),
    "LOCAL_USER_PATH": re.compile(r"[A-Za-z]:[\\/]Users[\\/][^\\/\s\"']+", re.I),
    "PRIVATE_KEY": re.compile("BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY"),
    "GITHUB_TOKEN": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    "URL_CREDENTIALS": re.compile(r"https?://[^\s/:]+:[^\s/@]+@", re.I),
}


def scan(root: Path) -> list[tuple[str, str, int]]:
    findings: list[tuple[str, str, int]] = []
    forbidden_dir_names = {item.lower() for item in FORBIDDEN_DIRS}
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-co", "--exclude-standard"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    for rel in sorted(line for line in listed.stdout.splitlines() if line.strip()):
        relative = Path(rel)
        path = root / relative
        if not path.is_file():
            continue
        for part in relative.parts[:-1]:
            if part.lower() in forbidden_dir_names:
                findings.append(("FORBIDDEN_DIRECTORY", relative.as_posix(), 0))
                break
        lower_name = path.name.lower()
        if lower_name in FORBIDDEN_FILES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
            findings.append(("FORBIDDEN_FILE", relative.as_posix(), 0))
        if path.name not in TEXT_NAMES and path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError):
            findings.append(("UNREADABLE_TEXT", relative.as_posix(), 0))
            continue
        for code, pattern in CONTENT_RULES.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append((code, relative.as_posix(), line))
    return findings


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    findings = scan(root)
    if findings:
        print(f"PUBLIC_READINESS=FAIL findings={len(findings)}")
        for code, relative, line in findings:
            location = f"{relative}:{line}" if line else relative
            print(f"{code} {location}")
        return 1
    print("PUBLIC_READINESS=PASS findings=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
