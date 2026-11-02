"""Build the repair message. Four parts: violation, evidence, correction, scope."""
from __future__ import annotations

SCOPE = ("SCOPE: correct only the violations above. Do not change the verdict "
         "text, the axes that were not named, or the scaffold's reasoning.")


def build(violations: list[dict]) -> str:
    lines = ["Your previous response was rejected by the validator.", ""]
    for i, viol in enumerate(violations, 1):
        lines += [
            f"VIOLATION {i}: Rule {viol['rule']} failed.",
            f"EVIDENCE: {viol['evidence']}.",
            f"REQUIRED CORRECTION: {viol['correction']}",
            "",
        ]
    lines.append(SCOPE)
    lines.append("")
    lines.append("Return only the corrected JSON object.")
    return "\n".join(lines)
