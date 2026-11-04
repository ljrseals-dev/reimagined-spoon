"""Phase 2: CTT gate (with token re-verify), revocation on CTT interval, quorum halt attachments."""
from __future__ import annotations

import base64
import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from anchoring.ceremony import Halt, _verify_ctt_gate_anchor, run_ceremony
from anchoring.tsa.policy import Anchor, Covers, TsaEntry, TsaPolicy, revocation_status

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tsa"
REAL_TOKEN = (FIXTURES / "valid_token.tsr").read_bytes()
ROOT = FIXTURES / "root.pem"
PREIMAGE = (FIXTURES / "imprint_preimage.bin").read_bytes()
# For CTT the covered bytes are the approver signature, not the fixture preimage.
# Re-verify expects imprint == sha256(sig_bytes). So for tests that need a PASSING
# re-verify we must either (a) use a token issued over sha256(sig) or (b) test the
# fabricated / shape path. The real fixture token covers imprint of PREIMAGE.
# Tests that need full green path through re-verify will use matching setup.


def _policy() -> TsaPolicy:
    reg = {
        "tsa-a": TsaEntry(
            tsa_id="tsa-a", role="primary", url="https://a.example",
            operator_id="op-a", distrust_after=None, policy_oid="1.2.3",
            root_pem_path=str(ROOT), root_fingerprint_sha256="replace_me", max_accuracy_s=1.0,
        ),
        "tsa-b": TsaEntry(
            tsa_id="tsa-b", role="witness", url="https://b.example",
            operator_id="op-b", distrust_after=None, policy_oid="1.2.3",
            root_pem_path=str(ROOT), root_fingerprint_sha256="replace_me", max_accuracy_s=1.0,
        ),
    }
    return TsaPolicy(registry=reg, quorum=2, max_skew_s=2.0)


def _sig_decision(sig_bytes: bytes = b"approver-sig-bytes-v1") -> tuple[dict, str, bytes]:
    b64 = base64.b64encode(sig_bytes).decode("ascii")
    digest = hashlib.sha256(sig_bytes).hexdigest()
    decision = {"signature": {"sig": b64, "key_id": "approver-1"}}
    return decision, digest, sig_bytes


def _ctt_anchor(digest: str, *, tsa_id: str = "tsa-a", gen: datetime | None = None,
                accuracy_s: float = 0.5, token: bytes = b"") -> Anchor:
    now = gen or datetime.now(timezone.utc)
    return Anchor(
        tsa_id=tsa_id,
        gen_time=now,
        accuracy_s=accuracy_s,
        mode="CTT",
        covers=Covers("approver_signature", digest),
        token_bytes=token,
    )


# ---------------------------------------------------------------------------
# CTT gate shape + re-verify
# ---------------------------------------------------------------------------
def test_ctt_gate_rejects_ttc():
    decision, digest, _ = _sig_decision()
    a = Anchor(
        tsa_id="tsa-a",
        gen_time=datetime.now(timezone.utc),
        accuracy_s=0.5,
        mode="TTC",
        covers=Covers("approver_signature", digest),
        token_bytes=REAL_TOKEN,
    )
    with pytest.raises(Halt) as ei:
        _verify_ctt_gate_anchor(decision, [a], tsa_policy=_policy())
    assert ei.value.code == "PRECONDITION_FAILED"


def test_ctt_gate_rejects_wrong_cover_hash():
    decision, _, _ = _sig_decision()
    a = _ctt_anchor("00" * 32, token=REAL_TOKEN)
    with pytest.raises(Halt) as ei:
        _verify_ctt_gate_anchor(decision, [a], tsa_policy=_policy())
    assert ei.value.code == "PRECONDITION_FAILED"


def test_ctt_gate_rejects_wrong_what():
    decision, digest, _ = _sig_decision()
    a = Anchor(
        tsa_id="tsa-a",
        gen_time=datetime.now(timezone.utc),
        accuracy_s=0.5,
        mode="CTT",
        covers=Covers("run_anchor", digest),
        token_bytes=REAL_TOKEN,
    )
    with pytest.raises(Halt) as ei:
        _verify_ctt_gate_anchor(decision, [a], tsa_policy=_policy())
    assert ei.value.code == "PRECONDITION_FAILED"


def test_ctt_gate_rejects_unverified_fabricated_anchor():
    """Shape matches CTT + covers, but token is corrupted / wrong request → TSA_VERIFICATION_FAILED."""
    decision, digest, _ = _sig_decision()
    # Corrupted DER
    a = _ctt_anchor(digest, token=b"\x30\x82" + b"\x00" * 40)
    with pytest.raises(Halt) as ei:
        _verify_ctt_gate_anchor(decision, [a], tsa_policy=_policy())
    assert ei.value.code == "TSA_VERIFICATION_FAILED", ei.value
    assert "token does not verify" in ei.value.detail

    # Real token but issued over a *different* imprint (fixture preimage ≠ sig)
    b = _ctt_anchor(digest, token=REAL_TOKEN)
    with pytest.raises(Halt) as ei2:
        _verify_ctt_gate_anchor(decision, [b], tsa_policy=_policy())
    assert ei2.value.code == "TSA_VERIFICATION_FAILED"


def test_ctt_gate_rejects_empty_token_as_verification_failure():
    decision, digest, _ = _sig_decision()
    a = _ctt_anchor(digest, token=b"")
    with pytest.raises(Halt) as ei:
        _verify_ctt_gate_anchor(decision, [a], tsa_policy=_policy())
    assert ei.value.code == "TSA_VERIFICATION_FAILED"


# ---------------------------------------------------------------------------
# Test 4: revocation three-case — vary accuracy_s (operator-tunable) on same gen_time
# ---------------------------------------------------------------------------
def test_revocation_three_case_on_ctt_interval():
    """Same gen_time; accuracy_s is what the operator/TSA token carries.

    Case 1: wide accuracy → revoked_at inside interval → indeterminate → reject
    Case 2: tight accuracy → interval entirely before revoked_at → accept
    Case 3: tight accuracy → interval entirely after revoked_at → reject

    This models an operator choosing a tighter-accuracy TSA to resolve indeterminacy,
    not three unrelated synthetic intervals.
    """
    now = datetime.now(timezone.utc)
    decision, digest, _ = _sig_decision()
    # Wide accuracy (still ≤ max_accuracy_s=1.0)
    wide_a = _ctt_anchor(digest, gen=now, accuracy_s=0.9, token=b"")
    wide_b = _ctt_anchor(digest, tsa_id="tsa-b", gen=now, accuracy_s=0.9, token=b"")
    # Gate will fail verification on empty token — for revocation path we need
    # to reach past CTT gate. Use a bypass: only test revocation_status algebra
    # here for the three cases, and ceremony path via monkeypatch of gate.

    # Algebra (operator-visible)
    assert revocation_status(wide_a.interval, now) == "indeterminate"
    tight = _ctt_anchor(digest, gen=now, accuracy_s=0.1, token=b"")
    assert revocation_status(tight.interval, now + timedelta(seconds=10)) == "before_revocation"
    assert revocation_status(tight.interval, now - timedelta(seconds=10)) == "after_revocation"

    # Ceremony path: patch gate to return the CTT anchor so revocation runs
    import anchoring.ceremony as cer
    from unittest import mock

    def _gate(decision, anchors, tsa_policy=None):
        return anchors[0]

    with mock.patch.object(cer, "_verify_ctt_gate_anchor", side_effect=_gate):
        r1 = run_ceremony(
            run_id="r1", ledger_tail_hash="a" * 64, ledger_length=1,
            genesis_entry_hash="b" * 64, gate_decision=decision,
            tsa_anchors=[wide_a, wide_b], tsa_policy=_policy(), revoked_at=now,
        )
        assert r1.terminal_state == "HALTED" and r1.weight_write is False
        assert r1.halt and r1.halt.code == "TSA_REVOCATION"

        tight_b = _ctt_anchor(digest, tsa_id="tsa-b", gen=now, accuracy_s=0.1, token=b"")
        r2 = run_ceremony(
            run_id="r2", ledger_tail_hash="a" * 64, ledger_length=1,
            genesis_entry_hash="b" * 64, gate_decision=decision,
            tsa_anchors=[tight, tight_b], tsa_policy=_policy(),
            revoked_at=now + timedelta(seconds=10),
        )
        assert r2.weight_write is True

        r3 = run_ceremony(
            run_id="r3", ledger_tail_hash="a" * 64, ledger_length=1,
            genesis_entry_hash="b" * 64, gate_decision=decision,
            tsa_anchors=[tight, tight_b], tsa_policy=_policy(),
            revoked_at=now - timedelta(seconds=10),
        )
        assert r3.terminal_state == "HALTED" and r3.weight_write is False
        assert r3.halt and r3.halt.code == "TSA_REVOCATION"


# ---------------------------------------------------------------------------
# DISAGREEMENT / INSUFFICIENT / TOLERATED
# ---------------------------------------------------------------------------
def test_disagreement_halts_with_token_attachments():
    decision, digest, _ = _sig_decision()
    now = datetime.now(timezone.utc)
    tok_a = b"\x30\x82" + b"A" * 40
    tok_b = b"\x30\x82" + b"B" * 40
    a = _ctt_anchor(digest, tsa_id="tsa-a", gen=now, accuracy_s=0.1, token=tok_a)
    b = _ctt_anchor(digest, tsa_id="tsa-b", gen=now + timedelta(seconds=30), accuracy_s=0.1, token=tok_b)
    import anchoring.ceremony as cer
    from unittest import mock
    with mock.patch.object(cer, "_verify_ctt_gate_anchor", side_effect=lambda d, anchors, tsa_policy=None: anchors[0]):
        r = run_ceremony(
            run_id="r-dis", ledger_tail_hash="a" * 64, ledger_length=1,
            genesis_entry_hash="b" * 64, gate_decision=decision,
            tsa_anchors=[a, b], tsa_policy=_policy(),
        )
    assert r.terminal_state == "HALTED" and r.weight_write is False
    assert r.halt and r.halt.code == "TSA_DISAGREEMENT"
    att = r.halt.attachments
    assert att.get("token_0_der_b64") == base64.b64encode(tok_a).decode("ascii")
    assert att.get("token_1_der_b64") == base64.b64encode(tok_b).decode("ascii")


def test_insufficient_halts_with_code():
    decision, digest, _ = _sig_decision()
    now = datetime.now(timezone.utc)
    a = _ctt_anchor(digest, tsa_id="tsa-a", gen=now, token=b"x")
    import anchoring.ceremony as cer
    from unittest import mock
    with mock.patch.object(cer, "_verify_ctt_gate_anchor", side_effect=lambda d, anchors, tsa_policy=None: anchors[0]):
        r = run_ceremony(
            run_id="r-ins", ledger_tail_hash="a" * 64, ledger_length=1,
            genesis_entry_hash="b" * 64, gate_decision=decision,
            tsa_anchors=[a], tsa_policy=_policy(),
        )
    assert r.terminal_state == "HALTED" and r.weight_write is False
    assert r.halt is not None and r.halt.code == "TSA_QUORUM_INSUFFICIENT"


def test_tolerated_cannot_establish_signature_time():
    decision, digest, _ = _sig_decision()
    now = datetime.now(timezone.utc)
    a = _ctt_anchor(digest, tsa_id="tsa-a", gen=now, accuracy_s=0.1, token=b"x")
    b = _ctt_anchor(digest, tsa_id="tsa-b", gen=now + timedelta(seconds=1.5), accuracy_s=0.1, token=b"y")
    import anchoring.ceremony as cer
    from unittest import mock
    with mock.patch.object(cer, "_verify_ctt_gate_anchor", side_effect=lambda d, anchors, tsa_policy=None: anchors[0]):
        r = run_ceremony(
            run_id="r-tol", ledger_tail_hash="a" * 64, ledger_length=1,
            genesis_entry_hash="b" * 64, gate_decision=decision,
            tsa_anchors=[a, b], tsa_policy=_policy(),
        )
    assert r.terminal_state == "HALTED" and r.weight_write is False
    assert r.halt and r.halt.code == "TSA_VERIFICATION_FAILED"
    assert "content anchors" in r.halt.detail.lower() or "TOLERATED" in r.halt.detail
    assert "timing" in r.halt.detail.lower() or "CTT" in r.halt.detail
