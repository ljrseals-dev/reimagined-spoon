"""Log every response; compute the four rates, severity distribution and
the citation resolution ratio."""
from __future__ import annotations
import json
from datetime import datetime, timezone
from pathlib import Path


class Logger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, case_id: str, claim: str, result: dict, model_version: str) -> None:
        resolved = sum(1 for c in result.get("citations", []) if c.get("resolved"))
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "case": case_id, "claim": claim,
            "D": (result.get("divergence") or {}).get("D"),
            "level": result.get("level"), "gate": result.get("gate"),
            "attempts": result.get("_attempts", 0),
            "first_pass": result.get("_first_pass", False),
            "violations": [v["rule"] for v in result.get("_violations", [])],
            "citations_resolved": resolved,
            "citations_attempted": len(result.get("citations", [])),
            "model_version": model_version,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def summary(self) -> dict:
        if not self.path.exists():
            return {}
        recs = [json.loads(l) for l in self.path.read_text(encoding="utf-8").splitlines() if l]
        n = len(recs) or 1
        dist = {i: 0 for i in range(6)}
        for r in recs:
            dist[r["level"]] = dist.get(r["level"], 0) + 1
        attempted = sum(r["citations_attempted"] for r in recs)
        return {
            "responses": len(recs),
            "first_pass_rate": round(100 * sum(r["first_pass"] for r in recs) / n, 1),
            "repair_rate": round(100 * sum(not r["first_pass"] for r in recs) / n, 1),
            "escalation_rate": round(100 * sum(r["gate"] == "ESCALATE" for r in recs) / n, 1),
            "severity_distribution": dist,
            "citation_resolution_ratio": round(
                (sum(r["citations_resolved"] for r in recs) / attempted) if attempted else 1.0, 3),
        }
