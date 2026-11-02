"""Divergence Score and the six-level escalation ladder.

D = P + S + W + A, each 0-3, range 0-12.
The level follows from D. The Critic may lower a level; it may not raise one.
"""
from __future__ import annotations
from dataclasses import dataclass

LEVEL_NAMES = ["affirm", "correct", "challenge", "adjudicate", "scathing", "terminal"]

# (d_min, d_max, level)
BANDS = [(0, 1, 0), (2, 3, 1), (4, 5, 2), (6, 8, 3), (9, 10, 4), (11, 12, 5)]

# Gate each level permits (validator rule 2.9)
ALLOWED_GATES = {
    0: {"ALLOW"},
    1: {"ALLOW"},
    2: {"CONDITIONAL", "DENY"},
    3: {"CONDITIONAL", "DENY"},
    4: {"DENY"},
    5: {"ESCALATE"},
}

# Minimum resolved citations per level (policy P3)
EVIDENCE_FLOOR = {0: 1, 1: 1, 2: 1, 3: 2, 4: 3, 5: 2}

# A level-4 verdict must cite at least one of these chapters
LEVEL4_REQUIRED_CHAPTERS = {15, 16, 21}

AXES = {
    "P": "Problem fidelity",
    "S": "Solution validity",
    "W": "Work conformance",
    "A": "Access depth",
}


@dataclass(frozen=True)
class Axis:
    score: int
    why: str

    def __post_init__(self):
        if not 0 <= self.score <= 3:
            raise ValueError(f"axis score out of range: {self.score}")


def level_for_d(d: int) -> int:
    if not 0 <= d <= 12:
        raise ValueError(f"D out of range: {d}")
    for lo, hi, lvl in BANDS:
        if lo <= d <= hi:
            return lvl
    raise AssertionError("unreachable")


def max_claimable_level(d: int, unresolved_any: bool) -> int:
    """P1: an unresolved citation drops the ceiling by one level."""
    lvl = level_for_d(d)
    return max(0, lvl - 1) if unresolved_any else lvl


def required_chapter_ok(level: int, chapters: set[int]) -> bool:
    if level < 4:
        return True
    return bool(chapters & LEVEL4_REQUIRED_CHAPTERS)
