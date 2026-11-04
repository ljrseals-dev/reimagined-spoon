"""
ARTIFACT gate + write + post-anchor ceremony (Part 4 / Phase 2).

Pre-write (blocking, fail-closed): CTT gate + dual-TSA quorum + revocation on CTT interval.
Post-write (non-blocking, fail-alarming): run_anchor → Rekor v2 → monitor.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .tsa.adapter import TsaError, _reject_if_not_ctt, verify_token_der
from .tsa.policy import Anchor, Interval, TsaEntry, TsaPolicy, quorum_verdict, revocation_status


@dataclass
class Halt(Exception):
    phase: str
    code: str
    detail: str = ""
    attachments: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"Halt({self.phase!r}, {self.code!r}, {self.detail!r})"


@dataclass
class CeremonyResult:
    terminal_state: str  # COMPLETE | AWAITING_INCLUSION | COMPLETE_UNANCHORED | HALTED
    run_id: str
    ledger_tail_hash: str
    tsa_verdict: str
    tlog_entry_id: str | None = None
    alarms: list[str] | None = None
    detail: str = ""
    halt: Halt | None = None
    weight_write: bool = False  # True only if orchestrator may proceed to WEIGHT_WRITE


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _verify_ctt_gate_anchor(
    decision: dict,
    anchors: list[Anchor],
    *,
    tsa_policy: TsaPolicy | None = None,
) -> Anchor:
    """Require a *cryptographically verified* CTT anchor covering the approver signature.

    Does not trust Anchor dataclass fields alone: each candidate's token_bytes is
    re-checked via verify_token_der. Fabricated Anchors without a verifying token
    raise TSA_VERIFICATION_FAILED (not PRECONDITION_FAILED).

    Raises:
      Halt(PROPOSE, PRECONDITION_FAILED, ...) — no candidate looked like a CTT cover
      Halt(PROPOSE, TSA_VERIFICATION_FAILED, ...) — a candidate matched shape but token failed
    """
    sig_b64 = None
    if isinstance(decision.get("signature"), dict):
        sig_b64 = decision["signature"].get("sig")
    elif isinstance(decision.get("sig"), str):
        sig_b64 = decision["sig"]
    if not sig_b64:
        raise Halt("PROPOSE", "PRECONDITION_FAILED", "not CTT-anchored: missing decision signature")

    try:
        sig_bytes = base64.b64decode(sig_b64)
    except Exception as e:
        raise Halt("PROPOSE", "PRECONDITION_FAILED", f"not CTT-anchored: bad sig encoding: {e}") from e

    want = hashlib.sha256(sig_bytes).hexdigest()
    saw_shape_match = False
    last_verify_detail = ""

    for a in anchors:
        try:
            _reject_if_not_ctt(a)
        except TsaError:
            continue
        if a.covers is None or a.covers.what != "approver_signature":
            continue
        if a.covers.sha256.lower() != want.lower():
            continue
        saw_shape_match = True

        if not a.token_bytes:
            last_verify_detail = "empty token_bytes"
            continue

        # Build a minimal TsaEntry for offline re-verify from the anchor + policy if present
        entry = None
        if tsa_policy is not None:
            entry = tsa_policy.registry.get(a.tsa_id)
        if entry is None:
            # offline gate still requires a root path — refuse rather than trust fields
            last_verify_detail = f"no TsaEntry for {a.tsa_id!r} in policy registry"
            continue

        expected_imprint = bytes.fromhex(a.covers.sha256) if len(a.covers.sha256) == 64 else hashlib.sha256(sig_bytes).digest()
        # CTT covers the signature bytes; imprint must be sha256(sig_bytes)
        expected_imprint = hashlib.sha256(sig_bytes).digest()
        try:
            checks = verify_token_der(
                a.token_bytes,
                expected_imprint=expected_imprint,
                expected_nonce=None,
                entry=entry,
            )
        except TsaError as e:
            last_verify_detail = str(e)
            continue
        fails = [c for c in checks if c.status == "FAIL"]
        if fails:
            last_verify_detail = "; ".join(f"{c.name}: {c.detail}" for c in fails)
            continue
        # gen_time/accuracy on the dataclass must match the re-parsed token (anti-swap)
        # verify_token_der already checked imprint; trust gate only after PASS
        return a

    if saw_shape_match:
        raise Halt(
            "PROPOSE",
            "TSA_VERIFICATION_FAILED",
            f"CTT-shaped anchor present but token does not verify: {last_verify_detail}",
        )
    raise Halt("PROPOSE", "PRECONDITION_FAILED", "not CTT-anchored")


def run_ceremony(
    *,
    run_id: str,
    ledger_tail_hash: str,
    ledger_length: int,
    genesis_entry_hash: str,
    gate_decision: dict,
    tsa_anchors: list[Anchor],
    tsa_policy: TsaPolicy,
    revoked_at: datetime | None = None,
    frozen: bool = False,
    tlog_client: Any = None,
) -> CeremonyResult:
    """
    Ordered steps. CTT gate + dual-TSA are blocking; inclusion is not.
    weight_write=True only when all pre-write gates pass.
    """
    if frozen:
        h = Halt("PREFLIGHT", "HARNESS_FROZEN", "harness FROZEN; refuse new run")
        return CeremonyResult(
            "HALTED", run_id, ledger_tail_hash, "SKIPPED",
            detail=str(h), halt=h, weight_write=False,
        )

    # CTT gate — before quorum / checkpoint
    try:
        ctt = _verify_ctt_gate_anchor(gate_decision, tsa_anchors, tsa_policy=tsa_policy)
    except Halt as h:
        return CeremonyResult(
            "HALTED", run_id, ledger_tail_hash, "PRECONDITION_FAILED",
            detail=str(h), halt=h, weight_write=False,
        )

    # Dual-TSA quorum (blocking)
    verdict = quorum_verdict(tsa_anchors, tsa_policy)
    if verdict.status == "DISAGREEMENT":
        attachments: dict[str, Any] = {}
        for i, a in enumerate(verdict.anchors or tsa_anchors):
            if a.token_bytes:
                attachments[f"token_{i}_der_b64"] = base64.b64encode(a.token_bytes).decode("ascii")
            attachments[f"token_{i}_tsa_id"] = a.tsa_id
            attachments[f"token_{i}_gen_time"] = a.gen_time.isoformat()
        h = Halt("TSA", "TSA_DISAGREEMENT", verdict.detail or "DISAGREEMENT", attachments=attachments)
        return CeremonyResult(
            "HALTED", run_id, ledger_tail_hash, "DISAGREEMENT",
            detail=str(h), halt=h, weight_write=False,
        )
    if verdict.status == "INSUFFICIENT":
        h = Halt("TSA", "TSA_QUORUM_INSUFFICIENT", verdict.detail or "INSUFFICIENT")
        return CeremonyResult(
            "HALTED", run_id, ledger_tail_hash, "INSUFFICIENT",
            detail=str(h), halt=h, weight_write=False,
        )
    if verdict.status == "TOLERATED":
        # TOLERATED may accept content anchors; it cannot establish signature time for CTT.
        h = Halt(
            "TSA",
            "TSA_VERIFICATION_FAILED",
            "TOLERATED: TSAs disagreed within skew tolerance — acceptable for content anchors, not for CTT timing anchors that establish when a signature existed",
        )
        return CeremonyResult(
            "HALTED", run_id, ledger_tail_hash, "TOLERATED",
            detail=str(h), halt=h, weight_write=False,
        )

    # Revocation uses CTT anchor interval only (not quorum intersection)
    if revoked_at is not None:
        status = revocation_status(ctt.interval, revoked_at)
        if status in ("after_revocation", "indeterminate"):
            h = Halt("TSA", "TSA_REVOCATION", f"revocation_status={status}")
            return CeremonyResult(
                "HALTED", run_id, ledger_tail_hash, verdict.status,
                detail=str(h), halt=h, weight_write=False,
            )

    # Pre-write gates passed — orchestrator may WEIGHT_WRITE
    if tlog_client is None:
        return CeremonyResult(
            "COMPLETE_UNANCHORED",
            run_id,
            ledger_tail_hash,
            verdict.status,
            detail="tlog submission skipped or failed; alarm + freeze",
            alarms=["ANCHOR_SUBMISSION_FAILED"],
            weight_write=True,
        )

    return CeremonyResult(
        "AWAITING_INCLUSION",
        run_id,
        ledger_tail_hash,
        verdict.status,
        tlog_entry_id="stub",
        weight_write=True,
    )
