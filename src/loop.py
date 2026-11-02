"""The bounded loop. Bound = 2: a Level 4 verdict needing three repairs
should have been a Level 5."""
from __future__ import annotations

from models import Model
from resolver import Resolver
from validator import validate
from repair import build as build_repair
from precheck import check as precheck

BOUND = 2


def adjudicate(claim: str, model: Model, resolver: Resolver, system_prompt: str) -> dict:
    # 1. trust boundary and falsifiability, before the model is called
    forced = precheck(claim)
    if forced:
        forced["_attempts"] = 0
        forced["_first_pass"] = True
        forced["_violations"] = []
        return forced

    user = f"<user_claim>\n{claim}\n</user_claim>"
    attempts, first_pass, last_violations = 0, False, []

    while attempts <= BOUND:
        raw = model.complete(system_prompt, user)
        obj, violations = validate(raw, claim, resolver)

        if not violations and obj is not None:
            obj["_attempts"] = attempts
            obj["_first_pass"] = (attempts == 0)
            obj["_violations"] = last_violations
            return obj

        last_violations = violations
        if attempts == BOUND:
            break
        user = (f"<user_claim>\n{claim}\n</user_claim>\n\n"
                f"<rejected_response>\n{raw}\n</rejected_response>\n\n"
                f"{build_repair(violations)}")
        attempts += 1

    return {
        "claim_as_adjudicated": claim,
        "correction_applied": None,
        "divergence": {"P": {"score": 3, "why": "unresolved"}, "S": {"score": 3, "why": "unresolved"},
                       "W": {"score": 3, "why": "unresolved"}, "A": {"score": 3, "why": "unresolved"}, "D": 12},
        "level": 5, "level_name": "terminal",
        "verdict": "The Critic could not produce a valid adjudication within the repair bound.",
        "citations": [],
        "what_would_change_this": "A human reviewer must inspect the rejected responses and the violations.",
        "gate": "ESCALATE",
        "gate_condition": f"Bound reached after {BOUND} repairs.",
        "scaffold": "VERDICT: Stop. The Critic failed its own contract.\n\nWHY: validator violations persisted past the bound.",
        "_attempts": attempts, "_first_pass": False, "_violations": last_violations,
    }
