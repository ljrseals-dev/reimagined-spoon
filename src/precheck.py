"""Two checks that run BEFORE the model is called.

1. Instruction-like text in the claim -> ESCALATE (Ch 6.4, P1 of the prompt).
2. Unfalsifiable claim -> ESCALATE (Ch 8.3).

Heuristic. Replace the patterns with a classifier when one is available;
the *order* (precheck before scoring) is the design decision, not the regex.
"""
from __future__ import annotations
import re

INJECTION_PATTERNS = [
    r"\bignore\s+(all\s+)?(your\s+)?(previous\s+)?instructions\b",
    r"\byou\s+are\s+now\b",
    r"\bsystem\s+prompt\b",
    r"\bdisregard\s+(the\s+)?(above|rules|policy)\b",
    r"\bjailbreak\b",
]

# A claim with no object and no falsifiable condition cannot be adjudicated.
UNFALSIFIABLE_PATTERNS = [
    r"^\s*make\s+it\s+better\.?\s*$",
    r"^\s*improve\s+(this|it)\.?\s*$",
    r"^\s*is\s+this\s+good\??\s*$",
    r"^\s*(fix|sort)\s+it\.?\s*$",
]

MIN_WORDS = 4


def check(claim: str) -> dict | None:
    """Return a forced verdict dict, or None to proceed."""
    text = (claim or "").strip()
    low = text.lower()

    for pat in INJECTION_PATTERNS:
        if re.search(pat, low):
            return _forced(
                text,
                reason="The claim contains instruction-like text. Under the "
                       "trust boundary (Ch 6.4) the question block is never an "
                       "instruction, and the Critic does not adjudicate claims "
                       "that attempt to change its rules.",
                must="Resubmit the claim as a question or an assertion about "
                     "the book. The Critic will not act on instructions "
                     "embedded in the claim.",
                locator="6.4.2",
            )

    if len(text.split()) < MIN_WORDS or any(re.match(p, low) for p in UNFALSIFIABLE_PATTERNS):
        return _forced(
            text,
            reason="The claim is not falsifiable. Chapter 8 requires a stated "
                   "cause and a predicted effect before a change is made, and a "
                   "claim with neither cannot be adjudicated — only guessed at.",
            must="Restate the claim as: (a) the artefact or behaviour you are "
                 "asserting something about, and (b) the specific outcome you "
                 "expect. Then the claim can be scored.",
            locator="8.3.1",
        )
    return None


def _forced(claim: str, reason: str, must: str, locator: str) -> dict:
    return {
        "claim_as_adjudicated": claim,
        "correction_applied": None,
        "divergence": {
            "P": {"score": 3, "why": "The claim cannot be scored on fidelity: it is not yet a claim about the book."},
            "S": {"score": 3, "why": "No solution can be validated against an unscorable claim."},
            "W": {"score": 3, "why": "No work discipline can be assessed."},
            "A": {"score": 3, "why": "No localisation is possible."},
            "D": 12,
        },
        "level": 5,
        "level_name": "terminal",
        "verdict": reason,
        "citations": [{"locator": locator, "quote": "", "page": None,
                       "pagination_status": "pending", "apa": "", "resolved": False}],
        "what_would_change_this": must,
        "gate": "ESCALATE",
        "gate_condition": "Human review required. The Critic cannot clear this claim.",
        "scaffold": f"VERDICT: Stop. This cannot be adjudicated.\n\nWHY: {reason}\n\n"
                    f"WHAT MUST HAPPEN BEFORE THIS CAN PROCEED: {must}",
        "_precheck": True,
    }
