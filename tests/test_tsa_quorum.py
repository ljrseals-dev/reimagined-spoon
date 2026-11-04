"""Must-pass tests from the design (subset runnable offline)."""
from datetime import datetime, timedelta, timezone

from anchoring.tsa.policy import (
    Anchor,
    TsaEntry,
    TsaPolicy,
    quorum_verdict,
    revocation_status,
    Interval,
)


def _policy() -> TsaPolicy:
    reg = {
        "tsa-a": TsaEntry(
            tsa_id="tsa-a", role="primary", url="https://a.example",
            operator_id="op-a", distrust_after=None, policy_oid="1.2.3", root_pem_path="/dev/null",
            root_fingerprint_sha256="aa", max_accuracy_s=1.0,
        ),
        "tsa-b": TsaEntry(
            tsa_id="tsa-b", role="witness", url="https://b.example",
            operator_id="op-b", distrust_after=None, policy_oid="1.2.3", root_pem_path="/dev/null",
            root_fingerprint_sha256="bb", max_accuracy_s=1.0,
        ),
    }
    return TsaPolicy(registry=reg, quorum=2, max_skew_s=2.0)


def test_confirmed_overlap():
    now = datetime.now(timezone.utc)
    a = Anchor("tsa-a", now, 0.5, mode="CTT")
    b = Anchor("tsa-b", now + timedelta(seconds=0.2), 0.5, mode="CTT")
    v = quorum_verdict([a, b], _policy())
    assert v.status == "CONFIRMED"


def test_disagreement_beyond_tolerance():
    now = datetime.now(timezone.utc)
    a = Anchor("tsa-a", now, 0.1, mode="CTT")
    b = Anchor("tsa-b", now + timedelta(seconds=10), 0.1, mode="CTT")
    v = quorum_verdict([a, b], _policy())
    assert v.status == "DISAGREEMENT"
    assert v.gap and v.gap.total_seconds() > 2.0


def test_insufficient_quorum_no_fallback():
    now = datetime.now(timezone.utc)
    a = Anchor("tsa-a", now, 0.5, mode="CTT")
    v = quorum_verdict([a], _policy())
    assert v.status == "INSUFFICIENT"


def test_revocation_indeterminate_rejects():
    now = datetime.now(timezone.utc)
    iv = Interval(now - timedelta(seconds=1), now + timedelta(seconds=1))
    assert revocation_status(iv, now) == "indeterminate"
    assert revocation_status(iv, now + timedelta(seconds=5)) == "before_revocation"
    assert revocation_status(iv, now - timedelta(seconds=5)) == "after_revocation"


if __name__ == "__main__":
    test_confirmed_overlap()
    test_disagreement_beyond_tolerance()
    test_insufficient_quorum_no_fallback()
    test_revocation_indeterminate_rejects()
    print("tsa quorum tests OK")
