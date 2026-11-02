"""Build a conforming response object from a compact fixture spec."""
from __future__ import annotations
import json

from scorer import LEVEL_NAMES, level_for_d
from resolver import Resolver

D_FOR_LEVEL = {0: 0, 1: 2, 2: 4, 3: 6, 4: 9, 5: 11}


def build(spec: dict, resolver: Resolver) -> str:
    level = spec.get("level", 0)
    gate = spec.get("gate", "ALLOW")
    locators = spec.get("locators", [])
    verdict = spec.get("verdict", "See citations.")
    d = spec.get("D", D_FOR_LEVEL.get(level, 0))

    citations = []
    for loc in locators:
        r = resolver.resolve_citation(_phrase_for(resolver, loc), chapter=None)
        if r["found"] and r["locator"] == loc:
            citations.append({"locator": r["locator"], "quote": r["quote"],
                              "page": r["page"], "pagination_status": r["pagination_status"],
                              "apa": r["apa"], "resolved": True})
        else:
            citations.append({"locator": loc, "quote": spec.get("fake_quote", ""),
                              "page": None, "pagination_status": "pending",
                              "apa": "", "resolved": False})

    # Distribute D across the four axes so that the sum is exact.
    # Prefer a balanced distribution that never exceeds 3 per axis.
    base = d // 4
    rem = d % 4
    scores = [min(3, base + (1 if i < rem else 0)) for i in range(4)]
    # Ensure we never invent scores that would push the sum over D
    while sum(scores) > d:
        for i in range(4):
            if scores[i] > 0:
                scores[i] -= 1
                break

    # When a correction is applied, claim_as_adjudicated must differ from the original claim.
    original_claim = spec.get("claim", "")
    correction = spec.get("correction")
    if correction:
        claim_as_adj = correction   # the restated, corrected claim
    else:
        claim_as_adj = original_claim

    obj = {
        "claim_as_adjudicated": claim_as_adj,
        "correction_applied": correction,
        "divergence": {
            k: {"score": scores[i], "why": "fixture"}
            for i, k in enumerate("PSWA")
        },
        "level": level,
        "level_name": LEVEL_NAMES[level],
        "verdict": verdict,
        "citations": citations,
        "what_would_change_this": spec.get("wwct") if level >= 2 else None,
        "gate": gate,
        "gate_condition": spec.get("gate_condition") if gate in {"DENY", "ESCALATE"} else None,
        "scaffold": spec.get("scaffold", f"VERDICT: {verdict}"),
    }
    obj["divergence"]["D"] = sum(obj["divergence"][k]["score"] for k in "PSWA")
    return json.dumps(obj)


def _phrase_for(resolver: Resolver, locator: str) -> str:
    for e in resolver.entries:
        if e["locator"] == locator:
            return e["text"][:80]
    return locator
