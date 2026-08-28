# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller-Spezifikation fuer die Security Audit Suite.

Buendelt gui.pyw samt core/, tests/ und version.json zu einer Windows-.exe.
Chromium wird ueber PLAYWRIGHT_BROWSERS_PATH=0 in das playwright-Paket
installiert (siehe CI-Workflow) und hier als Datenbaum eingebunden, damit das
Werkzeug ohne Nachinstallation scannt.
"""
import os
from PyInstaller.utils.hooks import collect_data_files, collect_dynamic_libs, collect_submodules

APP_DIR = os.path.abspath(os.path.join(os.path.dirname(SPECPATH), ""))
ROOT = os.path.dirname(SPECPATH)  # apps/security-audit-tool

datas = [
    (os.path.join(ROOT, "version.json"), "."),
    (os.path.join(ROOT, "tests"), "tests"),
]
# playwright-Paketdaten inkl. der lokal installierten Browser (.local-browsers)
datas += collect_data_files("playwright", include_py_files=False)
binaries = collect_dynamic_libs("playwright")

# Alle core- und tests-Module automatisch erfassen. Die Engine laedt die Tests
# dynamisch (pkgutil/importlib); collect_submodules stellt sicher, dass jeder
# Test — auch kuenftig hinzukommende — samt Abhaengigkeiten gebuendelt wird.
hidden = collect_submodules("core") + collect_submodules("tests")

a = Analysis(
    [os.path.join(ROOT, "gui.pyw")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[os.path.join(ROOT, "packaging", "rthook_playwright.py")],
    excludes=[],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, [], exclude_binaries=True,
    name="SecurityAuditSuite",
    console=False,
    icon=os.path.join(ROOT, "packaging", "icon.ico"),
)
coll = COLLECT(
    exe, a.binaries, a.datas,
    name="SecurityAuditSuite",
)
