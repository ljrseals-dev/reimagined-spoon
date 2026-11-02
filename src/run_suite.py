"""Run the suite. Record first-pass and final-pass separately."""
from __future__ import annotations
import json
import sys
from pathlib import Path

from models import FixtureModel, load_prompt
from resolver import Resolver
from loop import adjudicate
from stub import build as build_fixture
from logger import Logger

sys.path.insert(0, str(Path(__file__).parent))


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    resolver = Resolver(root / "corpus" / "index.sample.json")
    prompt = load_prompt(root / "prompt" / "critic.v1.0.md")
    suite = json.loads((root / "suite" / "v1.0.json").read_text(encoding="utf-8"))
    log = Logger(root / "logs" / "runs.jsonl")

    rows, fp, fpassed = [], 0, 0
    for case in suite["cases"]:
        spec = case.get("stub")
        if case.get("precheck"):
            model = FixtureModel("{}")
        else:
            first = build_fixture({**spec, "claim": case["claim"]}, resolver)
            repair = build_fixture({**spec, **case.get("repair", spec), "claim": case["claim"]}, resolver) \
                if "repair" in case else None
            model = FixtureModel(first, repair)

        result = adjudicate(case["claim"], model, resolver, prompt)
        log.write(case["id"], case["claim"], result, "fixture-v1")

        got = (result["level"], result["gate"])
        want = (case["expected"]["level"], case["expected"]["gate"])
        ok = got == want and not any(f in str(result.get("scaffold", "")) or f == result["gate"]
                                     for f in case.get("forbidden", []))
        if result.get("_first_pass"):
            fp += 1
        if ok:
            fpassed += 1

        note = ""
        if result.get("_attempts"):
            note = f"repaired x{result['_attempts']}"
        if result.get("_precheck"):
            note = "precheck"
        rows.append((case["id"], case["category"], f"L{want[0]}/{want[1]}",
                     f"L{got[0]}/{got[1]}", "pass" if result.get("_first_pass") else "fail",
                     "pass" if ok else "fail", note))

    w = max(len(r[0]) for r in rows)
    print(f"\nSUITE v{suite['version']} — {len(rows)} cases — model: fixture-v1\n")
    print(f"{'ID':<{w}}  {'Category':<12} {'Expected':<14} {'Got':<14} {'First':<6} {'Final':<6} Note")
    print("-" * 96)
    for r in rows:
        print(f"{r[0]:<{w}}  {r[1]:<12} {r[2]:<14} {r[3]:<14} {r[4]:<6} {r[5]:<6} {r[6]}")

    n = len(rows)
    print(f"\nFirst-pass: {fp}/{n} ({100*fp/n:.1f}%)")
    print(f"Final-pass: {fpassed}/{n} ({100*fpassed/n:.1f}%)")
    print(f"Repair rate: {100*(n-fp)/n:.1f}%")
    print(f"\n{json.dumps(log.summary(), indent=2)}\n")
    return 0 if fpassed == n else 1


if __name__ == "__main__":
    raise SystemExit(main())
