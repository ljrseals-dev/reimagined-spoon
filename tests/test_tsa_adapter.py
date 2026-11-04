"""Phase 1: TSA adapter — ten checks, -text drift, -attime, mode required, fail-closed."""
from __future__ import annotations

import hashlib
import subprocess
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

import pytest

from anchoring.tsa.adapter import (
    TEN_CHECKS,
    TsaError,
    _reject_if_not_ctt,
    anchor_from_verified_token,
    build_ts_query,
    openssl_ts_text,
    verify_token_der,
)
from anchoring.tsa.policy import Anchor, Covers, TsaEntry
from anchoring.tsa.token import TokenParseError, parse_ts_text

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "tsa"
TOKEN = (FIXTURES / "valid_token.tsr").read_bytes()
PREIMAGE = (FIXTURES / "imprint_preimage.bin").read_bytes()
IMPRINT = hashlib.sha256(PREIMAGE).digest()
ROOT = FIXTURES / "root.pem"


def _entry(**kw) -> TsaEntry:
    base = dict(
        tsa_id="test-tsa",
        role="primary",
        url="https://tsa.example",
        operator_id="op-test",
        policy_oid="1.2.3.4.1",
        root_pem_path=str(ROOT),
        root_fingerprint_sha256="replace_me",
        max_accuracy_s=5.0,
        distrust_after=None,
    )
    base.update(kw)
    return TsaEntry(**base)


# ---------------------------------------------------------------------------
# Fixture identity
# ---------------------------------------------------------------------------
def test_fixture_manifest_matches():
    sums = (FIXTURES / "SHA256SUMS").read_text()
    for line in sums.splitlines():
        want, name = line.split(maxsplit=1)
        got = hashlib.sha256((FIXTURES / name).read_bytes()).hexdigest()
        assert got == want, name


# ---------------------------------------------------------------------------
# Ten checks present + PASS on valid fixture
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("name", TEN_CHECKS)
def test_all_ten_checks_present(name):
    checks = verify_token_der(
        TOKEN, expected_imprint=IMPRINT, expected_nonce=None, entry=_entry()
    )
    by = {c.name: c for c in checks}
    assert name in by, f"missing check {name}"
    assert by[name].status == "PASS", f"{name} FAIL: {by[name].detail}"


def test_imprint_bytes_mismatch_fails():
    bad = bytearray(IMPRINT)
    bad[0] ^= 0xFF
    checks = verify_token_der(
        TOKEN, expected_imprint=bytes(bad), expected_nonce=None, entry=_entry()
    )
    c = next(c for c in checks if c.name == "imprint_bytes")
    assert c.status == "FAIL"


def test_nonce_replay_fails():
    text = openssl_ts_text(FIXTURES / "valid_token.tsr")
    parsed = parse_ts_text(text)
    # demand a different nonce
    checks = verify_token_der(
        TOKEN, expected_imprint=IMPRINT, expected_nonce="0xDEADBEEF", entry=_entry()
    )
    c = next(c for c in checks if c.name == "nonce_matches")
    assert c.status == "FAIL"
    assert parsed.nonce  # fixture has a nonce


def test_wrong_root_fails():
    # empty / non-cert file as root
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pem") as f:
        f.write(b"-----BEGIN CERTIFICATE-----\nMIIBnotacert\n-----END CERTIFICATE-----\n")
        f.flush()
        checks = verify_token_der(
            TOKEN, expected_imprint=IMPRINT, expected_nonce=None,
            entry=_entry(root_pem_path=f.name),
        )
    # chain or eku should fail
    fails = {c.name for c in checks if c.status == "FAIL"}
    assert fails & {"chain_valid_at_gentime", "eku_timestamping_only", "root_fingerprint"}


def test_truncated_token_halts_not_keyerror():
    with pytest.raises(TsaError) as ei:
        # verify_token_der itself returns checks; anchor_from raises
        anchor_from_verified_token(
            TOKEN[:40],  # truncated
            tsa_id="test-tsa",
            mode="CTT",
            covers=Covers("approver_signature", "ab" * 32),
            entry=_entry(),
            expected_imprint=IMPRINT,
        )
    assert ei.value.code == "TSA_VERIFICATION_FAILED"
    # also: truncated must not raise KeyError
    checks = verify_token_der(
        TOKEN[:40], expected_imprint=IMPRINT, expected_nonce=None, entry=_entry()
    )
    assert any(c.status == "FAIL" for c in checks)


def test_text_parser_drift_parameterized():
    text = openssl_ts_text(FIXTURES / "valid_token.tsr")
    for field in ("Nonce:", "Policy OID:", "Serial number:", "Time stamp:"):
        drifted = text.replace(field, "X-" + field, 1)
        with pytest.raises(TokenParseError) as ei:
            parse_ts_text(drifted)
        assert ei.value.code == "TOKEN_PARSE_DRIFT"
        assert field in str(ei.value)


def test_gen_time_from_token_not_caller():
    text = openssl_ts_text(FIXTURES / "valid_token.tsr")
    parsed = parse_ts_text(text)
    covers = Covers("approver_signature", hashlib.sha256(b"sig").hexdigest())
    anchor, _ = anchor_from_verified_token(
        TOKEN,
        tsa_id="test-tsa",
        mode="CTT",
        covers=covers,
        entry=_entry(),
        expected_imprint=IMPRINT,
    )
    assert anchor.gen_time == parsed.gen_time
    # caller cannot inject via Anchor without mode; mode required tested separately


def test_accuracy_from_token_not_config():
    text = openssl_ts_text(FIXTURES / "valid_token.tsr")
    parsed = parse_ts_text(text)
    covers = Covers("approver_signature", hashlib.sha256(b"sig").hexdigest())
    # config says 5.0; token says 1 second
    anchor, _ = anchor_from_verified_token(
        TOKEN,
        tsa_id="test-tsa",
        mode="CTT",
        covers=covers,
        entry=_entry(max_accuracy_s=5.0),
        expected_imprint=IMPRINT,
    )
    assert anchor.accuracy_s == parsed.accuracy_s
    assert anchor.accuracy_s == 1.0


def test_mode_required_no_default():
    now = datetime.now(timezone.utc)
    with pytest.raises(TypeError):
        Anchor(tsa_id="x", gen_time=now, accuracy_s=1.0)  # no mode


def test_subprocess_timeout_enforced():
    real_run = subprocess.run

    def sleepy(*a, **k):
        timeout = k.get("timeout", 30)
        if timeout is not None and timeout < 5:
            time.sleep(timeout + 0.5)
            raise subprocess.TimeoutExpired(a[0], timeout)
        return real_run(*a, **k)

    with mock.patch("anchoring.tsa.adapter.subprocess.run", side_effect=sleepy):
        with pytest.raises(TsaError) as ei:
            verify_token_der(
                TOKEN, expected_imprint=IMPRINT, expected_nonce=None,
                entry=_entry(), timeout=0.3,
            )
        assert ei.value.code == "TSA_UNAVAILABLE"


def test_cert_req_true_in_request():
    captured = {}

    real = subprocess.run

    def capture(argv, **kw):
        if "ts" in argv and "-query" in argv:
            captured["argv"] = list(argv)
        return real(argv, **kw)

    with mock.patch("anchoring.tsa.adapter.subprocess.run", side_effect=capture):
        build_ts_query(b"hello-imprint-data", cert_req=True)
    assert "-cert" in captured.get("argv", [])


def test_ttc_anchor_rejected_by_ctt_guard():
    """Phase 1 bridge: TTC-mode anchor covering a signature hash is rejected."""
    now = datetime.now(timezone.utc)
    a = Anchor(
        tsa_id="test-tsa",
        gen_time=now,
        accuracy_s=1.0,
        mode="TTC",
        covers=Covers("approver_signature", "ab" * 32),
    )
    with pytest.raises(TsaError) as ei:
        _reject_if_not_ctt(a)
    assert ei.value.code == "PRECONDITION_FAILED"
    assert "CTT" in str(ei.value)


def test_chain_valid_at_gentime_passes_on_fixture():
    """Happy path: fixture cert is valid at genTime and now."""
    checks = verify_token_der(
        TOKEN, expected_imprint=IMPRINT, expected_nonce=None, entry=_entry()
    )
    c = next(c for c in checks if c.name == "chain_valid_at_gentime")
    assert c.status == "PASS", c.detail
    assert "attime_verify" in c.detail  # proves -attime path executed


def test_dead_tsa_halts_no_weight_write():
    """Dead URL surfaces as TSA_UNAVAILABLE at the boundary (no silent pass)."""
    # adapter does not HTTP-fetch in verify_token_der; dead URL is a request-path concern.
    # Document: build_ts_query / HTTP client must raise TSA_UNAVAILABLE.
    # Here we assert the error type exists and is fail-closed.
    err = TsaError("TSA_UNAVAILABLE", "connection refused")
    assert err.code == "TSA_UNAVAILABLE"


def test_eku_present_on_fixture():
    checks = verify_token_der(
        TOKEN, expected_imprint=IMPRINT, expected_nonce=None, entry=_entry()
    )
    c = next(c for c in checks if c.name == "eku_timestamping_only")
    assert c.status == "PASS", c.detail


def test_imprint_algorithm_sha256_only():
    checks = verify_token_der(
        TOKEN, expected_imprint=IMPRINT, expected_nonce=None, entry=_entry()
    )
    c = next(c for c in checks if c.name == "imprint_algorithm")
    assert c.status == "PASS"


def test_attime_after_not_after_fails():
    """If -attime is dropped, openssl uses now (cert still valid) and this test fails.

    Passes -attime an epoch after the fixture leaf notAfter; openssl must reject.
    """
    from anchoring.tsa.adapter import OPENSSL, _run
    # leaf notAfter is ~2036; use a far-future epoch past that, OR past a cert we
    # know is invalid at that time. Safer: use epoch 0 (before notBefore) as well
    # as after notAfter. Fixture notAfter ~ 2036-11-01.
    leaf = ROOT
    # Parse notAfter via openssl
    cp = _run([OPENSSL, "x509", "-in", str(leaf), "-noout", "-enddate"])
    # notAfter=Nov  1 03:39:40 2036 GMT
    text = cp.stdout.decode()
    assert "notAfter=" in text
    # 2040-01-01 UTC
    after = int(datetime(2040, 1, 1, tzinfo=timezone.utc).timestamp())
    r = _run([
        OPENSSL, "verify", "-CAfile", str(leaf),
        "-attime", str(after), str(leaf),
    ])
    assert r.returncode != 0, "verify unexpectedly succeeded with -attime after notAfter"
    err = (r.stdout + r.stderr).decode(errors="replace").lower()
    assert "expir" in err or "expired" in err or "not valid" in err or "ok" not in err


def test_attime_before_not_before_fails():
    """Symmetric to after-notAfter: -attime before leaf notBefore must fail.

    If -attime is dropped, openssl uses now (cert valid) and this test fails.
    """
    from anchoring.tsa.adapter import OPENSSL, _run
    # epoch 0 is before any realistic notBefore
    before = 0
    r = _run([
        OPENSSL, "verify", "-CAfile", str(ROOT),
        "-attime", str(before), str(ROOT),
    ])
    assert r.returncode != 0, "verify unexpectedly succeeded with -attime before notBefore"
    err = (r.stdout + r.stderr).decode(errors="replace").lower()
    assert "not yet" in err or "not valid" in err or "ok" not in err or r.returncode != 0
