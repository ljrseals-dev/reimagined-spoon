"""Phase 3: CTT re-verify at gate, required TsaEntry fields, corroboration + sandwich."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from anchoring.ceremony import Halt, _verify_ctt_gate_anchor
from anchoring.tsa.policy import (
    AcceptResult,
    Anchor,
    Covers,
    TsaEntry,
    TsaPolicy,
    accept_anchor,
)
from anchoring.tlog.config import Checkpoint, FixtureCheckpointSource

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tsa"
REAL_TOKEN = (FIXTURES / "valid_token.tsr").read_bytes()
ROOT = FIXTURES / "root.pem"


def _entry(**kw) -> TsaEntry:
    base = dict(
        tsa_id="tsa-a",
        role="primary",
        url="https://a.example",
        operator_id="op-a",
        policy_oid="1.2.3",
        root_pem_path=str(ROOT),
        root_fingerprint_sha256="replace_me",
        max_accuracy_s=1.0,
        distrust_after=None,
    )
    base.update(kw)
    return TsaEntry(**base)


def _policy(entries: list[TsaEntry] | None = None) -> TsaPolicy:
    if entries is None:
        entries = [
            _entry(tsa_id="tsa-a", operator_id="op-a"),
            _entry(tsa_id="tsa-b", operator_id="op-b", role="witness"),
        ]
    return TsaPolicy(registry={e.tsa_id: e for e in entries}, quorum=2, max_skew_s=2.0)


def _sig():
    sig = b"approver-sig-bytes-v1"
    return {
        "signature": {"sig": base64.b64encode(sig).decode(), "key_id": "k"},
    }, hashlib.sha256(sig).hexdigest()


# ----- Commit 1: re-verify -----
def test_reeverifies_token_at_gate():
    decision, digest = _sig()
    a = Anchor(
        tsa_id="tsa-a",
        gen_time=datetime.now(timezone.utc),
        accuracy_s=0.5,
        mode="CTT",
        covers=Covers("approver_signature", digest),
        token_bytes=b"\x30\x82" + b"\xff" * 50,  # corrupt
    )
    with pytest.raises(Halt) as ei:
        _verify_ctt_gate_anchor(decision, [a], tsa_policy=_policy())
    assert ei.value.code == "TSA_VERIFICATION_FAILED"


def test_ctt_gate_rejects_unverified_fabricated_anchor():
    decision, digest = _sig()
    a = Anchor(
        tsa_id="tsa-a",
        gen_time=datetime.now(timezone.utc),
        accuracy_s=0.5,
        mode="CTT",
        covers=Covers("approver_signature", digest),
        token_bytes=REAL_TOKEN,  # real token, wrong imprint
    )
    with pytest.raises(Halt) as ei:
        _verify_ctt_gate_anchor(decision, [a], tsa_policy=_policy())
    assert ei.value.code == "TSA_VERIFICATION_FAILED"
    assert "token does not verify" in ei.value.detail


# ----- Commit 2: required fields -----
def test_distrust_after_required_no_default():
    with pytest.raises(TypeError):
        TsaEntry(
            tsa_id="t", role="primary", url="https://t",
            operator_id="op", policy_oid="1", root_pem_path="/dev/null",
            root_fingerprint_sha256="aa", max_accuracy_s=1.0,
            # distrust_after omitted
        )


def test_operator_id_required_no_default():
    with pytest.raises(TypeError):
        TsaEntry(
            tsa_id="t", role="primary", url="https://t",
            policy_oid="1", root_pem_path="/dev/null",
            root_fingerprint_sha256="aa", max_accuracy_s=1.0,
            distrust_after=None,
            # operator_id omitted
        )


# ----- Commit 3+4: corroboration + sandwich -----
def test_backdated_token_rejected_by_sandwich_not_flag():
    """gen_time before distrust_after, but outside sandwich window → BACKDATED."""
    now = datetime.now(timezone.utc)
    distrust = (now + timedelta(days=30)).isoformat()
    entry = _entry(distrust_after=distrust)
    policy = _policy([entry, _entry(tsa_id="tsa-b", operator_id="op-b", distrust_after=distrust)])

    # Token claims time long ago; sandwich observations are recent
    anchor = Anchor(
        tsa_id="tsa-a",
        gen_time=now - timedelta(days=365),
        accuracy_s=0.5,
        mode="CTT",
    )
    cps = FixtureCheckpointSource([
        Checkpoint(size=10, root=b"\x00" * 32, first_observed_at=now - timedelta(hours=1)),
        Checkpoint(size=20, root=b"\x01" * 32, first_observed_at=now - timedelta(minutes=30)),
        Checkpoint(size=30, root=b"\x02" * 32, first_observed_at=now - timedelta(minutes=5)),
    ])
    # entry_index 15 → before: size 10; after: size 20, 30
    r = accept_anchor(
        anchor, policy,
        entry_index=15,
        checkpoint_source=cps,
        sandwich_slack_s=60.0,
    )
    assert r.accepted is False
    assert r.reason == "BACKDATED", r  # not DISTRUST_AFTER


def test_corroborated_by_second_tsa_passes():
    now = datetime.now(timezone.utc)
    distrust = (now + timedelta(days=1)).isoformat()
    policy = _policy([
        _entry(tsa_id="tsa-a", operator_id="op-a", distrust_after=distrust),
        _entry(tsa_id="tsa-b", operator_id="op-b", distrust_after=None),  # trusted peer
    ])
    a = Anchor(tsa_id="tsa-a", gen_time=now, accuracy_s=0.5, mode="CTT")
    b = Anchor(tsa_id="tsa-b", gen_time=now + timedelta(seconds=0.1), accuracy_s=0.5, mode="CTT")
    r = accept_anchor(a, policy, peers=[a, b])
    assert r.accepted is True
    assert r.reason == "CORROBORATED_BY_SECOND_TSA"


def test_corroborated_by_sandwich_passes():
    now = datetime.now(timezone.utc)
    distrust = (now + timedelta(days=1)).isoformat()
    policy = _policy([_entry(distrust_after=distrust)])
    # gen_time sits between observation times
    gen = now - timedelta(minutes=20)
    anchor = Anchor(tsa_id="tsa-a", gen_time=gen, accuracy_s=1.0, mode="CTT")
    cps = FixtureCheckpointSource([
        Checkpoint(size=10, root=b"\x00" * 32, first_observed_at=now - timedelta(minutes=40)),
        Checkpoint(size=30, root=b"\x01" * 32, first_observed_at=now - timedelta(minutes=5)),
    ])
    r = accept_anchor(
        anchor, policy,
        entry_index=15,
        checkpoint_source=cps,
        sandwich_slack_s=120.0,
    )
    assert r.accepted is True
    assert r.reason == "CORROBORATED_BY_SANDWICH"


def test_no_corroboration_available_rejects():
    now = datetime.now(timezone.utc)
    distrust = (now + timedelta(days=1)).isoformat()
    policy = _policy([_entry(distrust_after=distrust)])  # only one TSA, no peer
    anchor = Anchor(tsa_id="tsa-a", gen_time=now, accuracy_s=0.5, mode="CTT")
    r = accept_anchor(anchor, policy, peers=[anchor], entry_index=None, checkpoint_source=None)
    assert r.accepted is False
    assert r.reason == "UNCORROBORATED"


def test_post_distrust_always_rejects():
    now = datetime.now(timezone.utc)
    distrust = (now - timedelta(days=1)).isoformat()
    policy = _policy([_entry(distrust_after=distrust)])
    anchor = Anchor(tsa_id="tsa-a", gen_time=now, accuracy_s=0.5, mode="CTT")
    r = accept_anchor(anchor, policy)
    assert r.accepted is False
    assert r.reason == "DISTRUST_AFTER"
