"""Adjudicate one claim against the manuscript."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from models import AnthropicModel, FixtureModel, OpenAIModel, load_prompt
from resolver import Resolver
from loop import adjudicate

sys.path.insert(0, str(Path(__file__).parent))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("claim", nargs="?", help="the claim to adjudicate")
    ap.add_argument("--file", help="read the claim from a file")
    ap.add_argument("--provider", default="fixture", choices=["fixture", "anthropic", "openai"])
    ap.add_argument("--model", default="claude-sonnet-4-5")
    args = ap.parse_args()

    claim = args.claim or (Path(args.file).read_text(encoding="utf-8") if args.file else "")
    if not claim.strip():
        ap.error("provide a claim or --file")

    root = Path(__file__).resolve().parent.parent
    resolver = Resolver(root / "corpus" / "index.sample.json")
    prompt = load_prompt(root / "prompt" / "critic.v1.0.md")

    if args.provider == "anthropic":
        model = AnthropicModel(args.model)
    elif args.provider == "openai":
        model = OpenAIModel(args.model)
    else:
        model = FixtureModel("{}")  # returns an invalid response: demonstrates escalation

    result = adjudicate(claim, model, resolver, prompt)
    result.pop("_violations", None)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["gate"] != "ESCALATE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
