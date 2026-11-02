"""Validator: Level 1 (shape), Level 2 (the rules), Level 3 (verbatim).

Returns a list of violations. A violation names the rule and the evidence,
because a repair message that says only 'fail' gives the model nothing.
"""
from __future__ import annotations
import json

from scorer import (ALLOWED_GATES, EVIDENCE_FLOOR, level_for_d,
                    max_claimable_level, required_chapter_ok)
from resolver import Resolver

PERSONAL_ATTACK = [
    "you are careless", "you are wrong", "you are lazy", "you are stupid",
    "you are ignorant", "you don't understand", "you failed to",
]


def validate(raw: str, claim: str, resolver: Resolver) -> tuple[dict | None, list[dict]]:
    v: list[dict] = []

    # ---- Level 1: shape ---------------------------------------------------
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, [{"rule": "L1.parse",
                       "evidence": f"response is not valid JSON ({exc.msg} at pos {exc.pos})",
                       "correction": "Return only a JSON object, with no prose before or after it."}]

    if not isinstance(obj, dict):
        return None, [{"rule": "L1.type", "evidence": "top level is not an object",
                       "correction": "Return a single JSON object."}]

    required = ["claim_as_adjudicated", "correction_applied", "divergence", "level",
                "level_name", "verdict", "citations", "what_would_change_this",
                "gate", "gate_condition", "scaffold"]
    missing = [k for k in required if k not in obj]
    if missing:
        return obj, [{"rule": "L1.fields", "evidence": f"missing {missing}",
                      "correction": f"Add the missing fields: {missing}."}]

    citations = obj.get("citations") or []
    if not isinstance(citations, list):
        return obj, [{"rule": "L1.citations", "evidence": "citations is not a list",
                      "correction": "citations must be an array of citation objects."}]

    # ---- Level 2: the rules ----------------------------------------------
    level = obj["level"]
    if not isinstance(level, int) or not 0 <= level <= 5:
        v.append({"rule": "2.1", "evidence": f"level={level!r}",
                  "correction": "level must be an integer 0-5."})
        return obj, v

    d = ((obj.get("divergence") or {}).get("D"))
    if not isinstance(d, int) or not 0 <= d <= 12:
        v.append({"rule": "2.2", "evidence": f"D={d!r}",
                  "correction": "divergence.D must be an integer 0-12, computed as P+S+W+A."})
    else:
        axes = [obj["divergence"].get(k, {}).get("score") for k in "PSWA"]
        if all(isinstance(a, int) for a in axes) and sum(axes) != d:
            v.append({"rule": "2.2", "evidence": f"P+S+W+A={sum(axes)} but D={d}",
                      "correction": "D must equal the sum of the four axis scores."})

        unresolved = any(not c.get("resolved", False) for c in citations)
        ceiling = max_claimable_level(d, unresolved)
        if level > ceiling:
            why = "an unresolved citation drops the ceiling by one level" if unresolved else "D does not support this level"
            v.append({"rule": "2.2", "evidence": f"D={d} supports level {level_for_d(d)}; claimed {level}; {why}",
                      "correction": f"Lower the level to {ceiling} or supply resolved citations that raise D."})

    if level >= 2 and not (obj.get("what_would_change_this") or "").strip():
        v.append({"rule": "2.3", "evidence": f"level {level} with no what_would_change_this",
                  "correction": "State the single falsifiable condition that would lower the verdict (P5)."})

    gate = obj.get("gate")
    if gate in {"DENY", "ESCALATE"}:
        if not (obj.get("what_would_change_this") or "").strip():
            v.append({"rule": "2.4", "evidence": f"gate {gate} with no what_would_change_this",
                      "correction": "A DENY or ESCALATE must state what would change it."})
        if not (obj.get("gate_condition") or "").strip():
            v.append({"rule": "2.4", "evidence": f"gate {gate} with no gate_condition",
                      "correction": "State the condition attached to the gate."})

    resolved = [c for c in citations if c.get("resolved")]
    floor = EVIDENCE_FLOOR.get(level, 1)
    if len(resolved) < floor:
        v.append({"rule": "2.5", "evidence": f"level {level} requires {floor} resolved citation(s); found {len(resolved)}",
                  "correction": f"Supply {floor} resolved citation(s), or lower the level to the highest your evidence supports."})

    if level >= 4:
        chapters = {resolver.chapter_of(c.get("locator", "")) for c in resolved} - {None}
        if not required_chapter_ok(level, chapters):
            v.append({"rule": "2.5", "evidence": f"level {level} cites chapters {sorted(chapters)}; none from 15, 16 or 21",
                      "correction": "Level 4 requires one citation from Chapters 15-16 (case studies) or 21 (the catalogue)."})

    for c in citations:
        if c.get("resolved"):
            if not (c.get("locator") or "").strip():
                v.append({"rule": "2.6", "evidence": "resolved citation with empty locator",
                          "correction": "Every resolved citation needs a locator."})
            n = len((c.get("quote") or "").split())
            if n == 0 or n > 40:
                v.append({"rule": "2.6", "evidence": f"quote length {n} words at {c.get('locator')}",
                          "correction": "A resolved quote must be 1-40 words."})

    if level == 5 and gate != "ESCALATE":
        v.append({"rule": "2.7", "evidence": f"level 5 with gate {gate}",
                  "correction": "Level 5 is always ESCALATE."})

    if obj.get("correction_applied"):
        if obj.get("claim_as_adjudicated", "").strip() == claim.strip():
            v.append({"rule": "2.8", "evidence": "correction_applied is set but the claim is unchanged",
                      "correction": "If a correction was applied, claim_as_adjudicated must differ from the user's text."})

    if gate not in ALLOWED_GATES.get(level, set()):
        v.append({"rule": "2.9", "evidence": f"level {level} permits {sorted(ALLOWED_GATES[level])}, gate={gate}",
                  "correction": f"Set the gate to one of {sorted(ALLOWED_GATES[level])}."})

    low = (obj.get("scaffold") or "").lower()
    for phrase in PERSONAL_ATTACK:
        if phrase in low:
            v.append({"rule": "2.10", "evidence": f"scaffold contains {phrase!r}",
                      "correction": "Severity is directed at the work, never at the author (P4). Rewrite the scaffold."})
            break

    # ---- Level 3: verbatim -----------------------------------------------
    for c in resolved:
        if c.get("quote") and not resolver.verbatim_at(c.get("locator", ""), c["quote"]):
            v.append({"rule": "L3.verbatim",
                      "evidence": f"quote at {c.get('locator')} does not appear verbatim: {c['quote'][:60]!r}",
                      "correction": "Resolve the quote with resolve_citation before asserting it. Do not paraphrase as a quote."})

    return obj, v
