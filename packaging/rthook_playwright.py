"""Zur Laufzeit im gepackten Zustand: playwright-Browser aus dem Bundle nutzen.

PLAYWRIGHT_BROWSERS_PATH=0 weist playwright an, die Browser im eigenen
Paketverzeichnis zu suchen — genau dorthin bettet der Build sie ein.
"""
import os
os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", "0")
