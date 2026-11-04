"""TSA registry, interval algebra, dual-TSA quorum, revocation status."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


@dataclass(frozen=True)
class TsaEntry:
    tsa_id: str
    role: str  # "primary" | "witness"
    url: str
    operator_id: str  # REQUIRED, distinct from tsa_id; two tsa_ids with one operator_id are ONE TSA (enforced in Phase 5)
    policy_oid: str
    root_pem_path: str
    root_fingerprint_sha256: str
    max_accuracy_s: float
    distrust_after: str | None  # REQUIRED, ISO-8601 or an explicit None meaning "no known distrust"
    not_after: str | None = None
    allow_ess_v1: bool = False
    jurisdiction: str = ""
    time_source: str = ""


@dataclass(frozen=True)
class TsaPolicy:
    registry: dict[str, TsaEntry]
    quorum: int = 2
    max_skew_s: float = 2.0
    require_distinct_operators: bool = True
    require_distinct_jurisdictions: bool = False
    max_accuracy_s: float = 1.0


@dataclass(frozen=True)
class Interval:
    lo: datetime
    hi: datetime

    def intersects(self, other: "Interval") -> bool:
        return self.lo <= other.hi and other.lo <= self.hi


@dataclass(frozen=True)
class Covers:
    """What the TSA token is bound to (imprint preimage class)."""
    what: str  # e.g. "approver_signature" | "run_anchor" | "payload"
    sha256: str  # hex digest of the covered bytes


@dataclass(frozen=True)
class Anchor:
    tsa_id: str
    gen_time: datetime
    accuracy_s: float
    mode: str  # REQUIRED: "CTT" | "TTC" — no default
    covers: Covers | None = None
    token_bytes: bytes = b""
    nonce: str = ""
    policy_oid: str = ""
    serial: str = ""
    hash_algorithm: str = "sha256"

    def __post_init__(self) -> None:
        if self.mode not in ("CTT", "TTC"):
            raise ValueError(f"Anchor.mode must be CTT or TTC, got {self.mode!r}")

    @property
    def interval(self) -> Interval:
        delta = timedelta(seconds=self.accuracy_s)
        return Interval(self.gen_time - delta, self.gen_time + delta)


@dataclass(frozen=True)
class Verdict:
    status: str  # CONFIRMED | TOLERATED | DISAGREEMENT | INSUFFICIENT
    earliest: datetime | None = None
    latest: datetime | None = None
    gap: timedelta | None = None
    anchors: list[Anchor] = field(default_factory=list)
    detail: str = ""


def _parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


@dataclass(frozen=True)
class AcceptResult:
    accepted: bool
    reason: str = ""  # e.g. OK | DISTRUST_AFTER | UNCORROBORATED | BACKDATED | CORROBORATED_BY_SECOND_TSA | CORROBORATED_BY_SANDWICH


def _corroborated_by_second_tsa(anchor: Anchor, policy: TsaPolicy, peers: list[Anchor] | None = None) -> bool:
    """True if another non-distrusted TSA's interval overlaps this anchor's interval."""
    peers = peers or []
    entry = policy.registry.get(anchor.tsa_id)
    if entry is None:
        return False
    for p in peers:
        if p.tsa_id == anchor.tsa_id:
            continue
        pe = policy.registry.get(p.tsa_id)
        if pe is None:
            continue
        # peer must not itself be past distrust
        pd = _parse_iso(pe.distrust_after)
        if pd is not None and p.gen_time >= pd:
            continue
        if p.interval.intersects(anchor.interval):
            return True
    return False


def _corroborated_by_sandwich(
    anchor: Anchor,
    *,
    entry_index: int | None,
    source: Any,
    slack_s: float = 30.0,
) -> bool:
    """T_before - slack <= gen_time+accuracy and gen_time-accuracy <= T_after + slack."""
    if source is None or entry_index is None:
        return False
    before = source.checkpoints_before(entry_index)
    after = source.checkpoints_after(entry_index)
    if not before or not after:
        return False
    t_before = max(c.first_observed_at for c in before)
    t_after = min(c.first_observed_at for c in after)
    slack = timedelta(seconds=slack_s)
    # gen_time interval must sit inside the observation sandwich (with slack)
    lo = anchor.interval.lo
    hi = anchor.interval.hi
    return (t_before - slack) <= hi and lo <= (t_after + slack)


def accept_anchor(
    anchor: Anchor,
    policy: TsaPolicy,
    *,
    peers: list[Anchor] | None = None,
    entry_index: int | None = None,
    checkpoint_source: Any = None,
    sandwich_slack_s: float = 30.0,
) -> AcceptResult:
    """Full accept with corroboration for pre-distrust_after tokens.

    Post-distrust tokens are always rejected (DISTRUST_AFTER).
    Pre-distrust tokens need second-TSA or sandwich corroboration.
    """
    entry = policy.registry.get(anchor.tsa_id)
    if entry is None:
        return AcceptResult(False, "UNKNOWN_TSA")
    if anchor.accuracy_s > min(entry.max_accuracy_s, policy.max_accuracy_s):
        return AcceptResult(False, "ACCURACY_EXCEEDED")
    not_after = _parse_iso(entry.not_after)
    if not_after and anchor.gen_time > not_after:
        return AcceptResult(False, "PAST_NOT_AFTER")

    distrust = _parse_iso(entry.distrust_after)
    if distrust is None:
        return AcceptResult(True, "OK")

    if anchor.gen_time >= distrust:
        return AcceptResult(False, "DISTRUST_AFTER")

    # Pre-distrust: need independent corroboration
    if _corroborated_by_second_tsa(anchor, policy, peers):
        return AcceptResult(True, "CORROBORATED_BY_SECOND_TSA")
    if _corroborated_by_sandwich(
        anchor, entry_index=entry_index, source=checkpoint_source, slack_s=sandwich_slack_s
    ):
        return AcceptResult(True, "CORROBORATED_BY_SANDWICH")

    # Claimed time outside sandwich when sandwich exists → BACKDATED
    if checkpoint_source is not None and entry_index is not None:
        before = checkpoint_source.checkpoints_before(entry_index)
        after = checkpoint_source.checkpoints_after(entry_index)
        if before and after:
            return AcceptResult(False, "BACKDATED")
    return AcceptResult(False, "UNCORROBORATED")


def _accept(anchor: Anchor, policy: TsaPolicy) -> bool:
    """Backward-compatible boolean accept (no peers/sandwich)."""
    return accept_anchor(anchor, policy).accepted


def quorum_verdict(anchors: list[Anchor], policy: TsaPolicy) -> Verdict:
    eligible = [a for a in anchors if _accept(a, policy)]
    if len(eligible) < policy.quorum:
        return Verdict(
            "INSUFFICIENT",
            detail=f"{len(eligible)} usable of {policy.quorum} required",
        )

    if policy.require_distinct_operators:
        # simplistic: distinct tsa_id is treated as distinct operator
        if len({a.tsa_id for a in eligible}) < policy.quorum:
            return Verdict("INSUFFICIENT", detail="operators not distinct")

    lo = max(a.interval.lo for a in eligible)
    hi = min(a.interval.hi for a in eligible)

    if lo <= hi:
        return Verdict("CONFIRMED", earliest=lo, latest=hi, anchors=eligible)

    gap = lo - hi
    if gap <= timedelta(seconds=policy.max_skew_s):
        return Verdict(
            "TOLERATED",
            earliest=hi,
            latest=lo,
            gap=gap,
            anchors=eligible,
            detail="TSA_SKEW within tolerance",
        )
    return Verdict(
        "DISAGREEMENT",
        earliest=hi,
        latest=lo,
        gap=gap,
        anchors=eligible,
        detail="gap exceeds max_skew_s; halt",
    )


def revocation_status(sig_interval: Interval, revoked_at: datetime) -> str:
    """Three-valued: before_revocation | after_revocation | indeterminate."""
    if sig_interval.hi < revoked_at:
        return "before_revocation"
    if sig_interval.lo > revoked_at:
        return "after_revocation"
    return "indeterminate"
