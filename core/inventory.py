"""Inventory helpers with quick/full depth and local-path redaction."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class InventoryItem:
    kind: str
    name: str
    relative_path: str = ""
    size: int | None = None
    sha256: str | None = None
    metadata: dict = field(default_factory=dict)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def local_project_inventory(root, mode="quick", limit=500) -> list[InventoryItem]:
    """Return a redacted inventory for a local project root.

    Results intentionally use relative paths only. ``quick`` captures names,
    file sizes and counts. ``full`` additionally records SHA-256 fingerprints.
    """

    base = Path(root).resolve()
    selected_mode = str(mode or "quick").strip().lower()
    if selected_mode not in {"quick", "full"}:
        selected_mode = "quick"
    items: list[InventoryItem] = [
        InventoryItem("root", base.name, metadata={"inventory_mode": selected_mode}),
    ]
    if not base.exists() or not base.is_dir():
        return items

    count = 0
    skip = {".git", "__pycache__", ".pytest_cache", "build", "dist", ".venv", "venv"}
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [name for name in dirnames if name not in skip]
        current = Path(dirpath)
        rel_dir = "" if current == base else current.relative_to(base).as_posix()
        for filename in sorted(filenames):
            if count >= limit:
                items.append(InventoryItem("truncated", "limit", metadata={"limit": limit}))
                return items
            path = current / filename
            try:
                size = path.stat().st_size
            except OSError:
                continue
            rel = f"{rel_dir}/{filename}" if rel_dir else filename
            digest = _hash_file(path) if selected_mode == "full" else None
            items.append(InventoryItem("file", filename, relative_path=rel, size=size, sha256=digest))
            count += 1
    return items
