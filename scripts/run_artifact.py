#!/usr/bin/env python3
"""
ARTIFACT Orchestrator entrypoint.

Drives the 9-phase pipeline (probe → … → post-write anchor → audit)
under the dual-TSA / Rekor-v2 governance frame.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def main() -> int:
    parser = argparse.ArgumentParser(description="ARTIFACT repair runner")
    parser.add_argument("--config", required=True, help="Path to YAML config")
    parser.add_argument("--dry-run", action="store_true", help="No weight writes")
    parser.add_argument("--phase", help="Run a single named phase (debug)")
    args = parser.parse_args()

    cfg_path = Path(args.config)
    if not cfg_path.is_file():
        print(f"[ARTIFACT] config not found: {cfg_path}", file=sys.stderr)
        return 2

    print(f"[ARTIFACT] config      : {cfg_path}")
    print(f"[ARTIFACT] dry-run     : {args.dry_run}")
    print(f"[ARTIFACT] repo root   : {ROOT}")
    print("[ARTIFACT] Phase 0 — environment check")
    print("  - anchoring package importable")
    try:
        from anchoring import quorum_verdict, TsaPolicy  # noqa: F401
        from anchoring.ceremony import run_ceremony  # noqa: F401
        print("  - OK")
    except Exception as e:
        print(f"  - FAIL: {e}", file=sys.stderr)
        return 1

    print("[ARTIFACT] Full pipeline requires configured reasoning + code model endpoints")
    print("           and configured TSA endpoints + Rekor v2 shard.")
    print("[ARTIFACT] See docs/ORCHESTRATOR_PROMPT.md and docs/ANCHORING_DESIGN.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
