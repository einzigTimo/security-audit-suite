"""Run policy for read/write intensity, inventory mode and effort levels."""

from __future__ import annotations

from dataclasses import dataclass


READ_LEVELS = {
    1: "Passive baseline",
    2: "Standard crawl",
    3: "Deep analysis",
    4: "Maximal effort",
}

WRITE_LEVELS = {
    0: "Off",
    1: "Minimal probes",
    2: "Controlled writes",
    3: "Aggressive validation",
    4: "Maximal effort",
}

INVENTORY_MODES = {"quick", "full"}


@dataclass(frozen=True)
class RunPolicy:
    read_level: int = 1
    write_level: int = 0
    inventory_mode: str = "quick"

    @property
    def aggressive(self) -> bool:
        return self.write_level > 0

    @property
    def aggression(self) -> int:
        return {0: 0, 1: 2, 2: 5, 3: 8, 4: 10}[self.write_level]

    @property
    def legacy_intensity(self) -> str:
        if self.read_level <= 1:
            return "Fast (Baseline)"
        if self.read_level == 2:
            return "Medium (Spider + Fuzzing)"
        return "Deep (Insane - Time-Based)"

    @property
    def max_effort(self) -> bool:
        return self.read_level == 4 or self.write_level == 4

    def to_context(self) -> dict:
        return {
            "read_level": self.read_level,
            "write_level": self.write_level,
            "inventory_mode": self.inventory_mode,
            "intensity": self.legacy_intensity,
            "aggressive": self.aggressive,
            "aggression": self.aggression or 5,
            "max_effort": self.max_effort,
        }


def clamp_int(value, minimum, maximum, fallback):
    try:
        return max(minimum, min(maximum, int(value)))
    except (TypeError, ValueError):
        return fallback


def build_policy(read_level=1, write_level=0, inventory_mode="quick") -> RunPolicy:
    mode = str(inventory_mode or "quick").strip().lower()
    if mode not in INVENTORY_MODES:
        mode = "quick"
    return RunPolicy(
        read_level=clamp_int(read_level, 1, 4, 1),
        write_level=clamp_int(write_level, 0, 4, 0),
        inventory_mode=mode,
    )
