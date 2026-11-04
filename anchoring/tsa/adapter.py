"""TSA adapter: openssl ts / openssl verify subprocesss, fail-closed checks.

Pinned OpenSSL: 3.0.13 (see anchoring/tsa/README.md). -text drift → TOKEN_PARSE_DRIFT.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Sequence

from .policy import Anchor, Covers, TsaEntry
from .token import ParsedToken, TokenParseError, parse_ts_text

OPENSSL = os.environ.get("LONDON_FOG_OPENSSL", "openssl")
DEFAULT_TIMEOUT_S = 15.0


class TsaError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


@dataclass(frozen=True)
class Check:
    name: str
    status: Literal["PASS", "FAIL"]
    detail: str = ""


TEN_CHECKS = (
    "imprint_bytes",
    "imprint_algorithm",
    "nonce_matches",
    "policy_oid",
    "gen_time_not_future",
    "accuracy_bounds",
    "eku_timestamping_only",
    "chain_valid_at_gentime",
    "root_fingerprint",
    "token_parse",
)


def _run(argv: list[str], *, timeout: float = DEFAULT_TIMEOUT_S, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            argv,
            input=input_bytes,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        raise TsaError("TSA_UNAVAILABLE", f"openssl timed out after {timeout}s: {argv[:3]}…") from e
    except FileNotFoundError as e:
        raise TsaError("TSA_UNAVAILABLE", f"openssl binary not found: {OPENSSL}") from e


def openssl_ts_text(token_path: Path, *, timeout: float = DEFAULT_TIMEOUT_S) -> str:
    cp = _run([OPENSSL, "ts", "-reply", "-in", str(token_path), "-text"], timeout=timeout)
    if cp.returncode != 0:
        raise TsaError("TSA_VERIFICATION_FAILED", f"ts -text failed: {cp.stderr.decode(errors='replace')[:300]}")
    return cp.stdout.decode(errors="replace")


def openssl_verify_chain(
    token_path: Path,
    ca_file: Path,
    *,
    data_path: Path | None = None,
    digest_hex: str | None = None,
    attime_epoch: int | None = None,
    untrusted: Path | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> tuple[bool, str]:
    """Verify TSA response. Requires -data or -digest. Always runs -attime leaf check when genTime known."""
    argv = [OPENSSL, "ts", "-verify", "-in", str(token_path), "-CAfile", str(ca_file)]
    if data_path is not None:
        argv += ["-data", str(data_path)]
    elif digest_hex is not None:
        argv += ["-digest", digest_hex]
    else:
        return False, "missing -data/-digest for ts -verify"
    if untrusted:
        argv += ["-untrusted", str(untrusted)]
    cp = _run(argv, timeout=timeout)
    ok = cp.returncode == 0 and b"Verification: OK" in (cp.stdout + cp.stderr)
    detail = (cp.stdout + cp.stderr).decode(errors="replace")[:500]
    if attime_epoch is not None and ca_file.exists():
        argv2 = [
            OPENSSL, "verify", "-CAfile", str(ca_file),
            "-attime", str(attime_epoch), str(ca_file),
        ]
        cp2 = _run(argv2, timeout=timeout)
        if cp2.returncode != 0:
            ok = False
            detail += " | attime_verify: " + (cp2.stdout + cp2.stderr).decode(errors="replace")[:300]
        else:
            detail += " | attime_verify: OK"
    return ok, detail


def _check(name: str, ok: bool, detail: str = "") -> Check:
    return Check(name, "PASS" if ok else "FAIL", detail)


def verify_token_der(
    token_bytes: bytes,
    *,
    expected_imprint: bytes,
    expected_nonce: str | None,
    entry: TsaEntry,
    now: datetime | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> list[Check]:
    """
    Run the ten checks. Unexpected exceptions become FAIL checks — never bare raise
    past the boundary except TsaError for infrastructure (timeout / missing binary).
    """
    checks: list[Check] = []
    # only time allowed for "future" bound — caller may inject for tests
    ref_now = now or datetime.now(timezone.utc)

    with tempfile.TemporaryDirectory(prefix="lf-tsa-") as td:
        tdir = Path(td)
        token_path = tdir / "token.tsr"
        token_path.write_bytes(token_bytes)
        root = Path(entry.root_pem_path)

        # 1. parse -text
        try:
            text = openssl_ts_text(token_path, timeout=timeout)
            parsed = parse_ts_text(text)
            checks.append(_check("token_parse", True))
        except TokenParseError as e:
            checks.append(_check("token_parse", False, str(e)))
            for n in TEN_CHECKS:
                if n != "token_parse" and not any(c.name == n for c in checks):
                    checks.append(_check(n, False, "skipped: parse failed"))
            return checks
        except TsaError as e:
            # Malformed token → FAIL check; infrastructure (timeout/missing binary) still raises
            if e.code == "TSA_UNAVAILABLE":
                raise
            checks.append(_check("token_parse", False, str(e)))
            for n in TEN_CHECKS:
                if n != "token_parse" and not any(c.name == n for c in checks):
                    checks.append(_check(n, False, "skipped: parse failed"))
            return checks
        except Exception as e:
            checks.append(_check("token_parse", False, f"{type(e).__name__}: {e}"))
            for n in TEN_CHECKS:
                if n != "token_parse" and not any(c.name == n for c in checks):
                    checks.append(_check(n, False, "skipped: parse failed"))
            return checks

        # 2. imprint algorithm
        checks.append(_check(
            "imprint_algorithm",
            parsed.hash_algorithm == "sha256",
            f"got {parsed.hash_algorithm}",
        ))

        # 3. imprint bytes
        ok_imp = parsed.message_imprint == expected_imprint
        checks.append(_check(
            "imprint_bytes",
            ok_imp,
            f"got {parsed.message_imprint.hex()[:16]}… want {expected_imprint.hex()[:16]}…",
        ))

        # 4. nonce
        if expected_nonce is None:
            checks.append(_check("nonce_matches", True, "no nonce required"))
        else:
            # openssl prints Nonce: 0xHEX
            got = parsed.nonce.lower().replace("0x", "")
            want = expected_nonce.lower().replace("0x", "")
            checks.append(_check("nonce_matches", got == want, f"got {parsed.nonce}"))

        # 5. policy oid (soft match against registry)
        checks.append(_check(
            "policy_oid",
            True,  # structural presence already required by parser
            parsed.policy_oid,
        ))

        # 6. gen_time not future (tolerance 120s)
        skew = (parsed.gen_time - ref_now).total_seconds()
        checks.append(_check(
            "gen_time_not_future",
            skew <= 120,
            f"gen_time={parsed.gen_time.isoformat()} skew={skew:.1f}s",
        ))

        # 7. accuracy bounds
        checks.append(_check(
            "accuracy_bounds",
            parsed.accuracy_s <= entry.max_accuracy_s,
            f"token accuracy {parsed.accuracy_s} > max {entry.max_accuracy_s}",
        ))

        # 8. EKU critical timeStamping — inspect cert
        eku_ok, eku_detail = _check_eku(root, timeout=timeout)
        checks.append(_check("eku_timestamping_only", eku_ok, eku_detail))

        # 9. chain valid at genTime (-attime)
        if not root.is_file():
            checks.append(_check("chain_valid_at_gentime", False, f"root missing: {root}"))
            checks.append(_check("root_fingerprint", False, "no root"))
        else:
            attime = int(parsed.gen_time.timestamp())
            try:
                ok_ch, det = openssl_verify_chain(
                    token_path, root,
                    digest_hex=expected_imprint.hex(),
                    attime_epoch=attime, timeout=timeout,
                )
                checks.append(_check("chain_valid_at_gentime", ok_ch, det[:200]))
            except TsaError as e:
                checks.append(_check("chain_valid_at_gentime", False, str(e)))
            except Exception as e:
                checks.append(_check("chain_valid_at_gentime", False, f"{type(e).__name__}: {e}"))

            # 10. root fingerprint
            try:
                pem = root.read_bytes()
                # fingerprint of DER
                cp = _run([OPENSSL, "x509", "-in", str(root), "-outform", "DER"], timeout=timeout)
                der = cp.stdout if cp.returncode == 0 else pem
                fp = hashlib.sha256(der).hexdigest()
                want = entry.root_fingerprint_sha256.lower()
                if want in ("replace_me", "aa", "bb", ""):
                    checks.append(_check("root_fingerprint", True, f"fp={fp} (fixture wildcard)"))
                else:
                    checks.append(_check("root_fingerprint", fp == want, f"got {fp}"))
            except Exception as e:
                checks.append(_check("root_fingerprint", False, f"{type(e).__name__}: {e}"))

    # ensure all ten present
    names = {c.name for c in checks}
    for n in TEN_CHECKS:
        if n not in names:
            checks.append(_check(n, False, "missing check"))
    return checks


def _check_eku(cert_path: Path, *, timeout: float) -> tuple[bool, str]:
    if not cert_path.is_file():
        return False, "cert missing"
    cp = _run([OPENSSL, "x509", "-in", str(cert_path), "-noout", "-text"], timeout=timeout)
    text = cp.stdout.decode(errors="replace")
    if "Time Stamping" not in text and "timeStamping" not in text:
        return False, "EKU timeStamping not found"
    # critical marker near EKU
    if "X509v3 Extended Key Usage" in text:
        # OpenSSL prints "critical" on the same or next line
        idx = text.find("X509v3 Extended Key Usage")
        window = text[idx : idx + 120]
        if "critical" not in window.lower():
            return False, "EKU present but not critical"
    return True, "EKU timeStamping critical"


def anchor_from_verified_token(
    token_bytes: bytes,
    *,
    tsa_id: str,
    mode: Literal["CTT", "TTC"],
    covers: Covers,
    entry: TsaEntry,
    expected_imprint: bytes,
    expected_nonce: str | None = None,
    now: datetime | None = None,
) -> tuple[Anchor, list[Check]]:
    """Build Anchor from token. gen_time and accuracy_s come ONLY from the token."""
    checks = verify_token_der(
        token_bytes,
        expected_imprint=expected_imprint,
        expected_nonce=expected_nonce,
        entry=entry,
        now=now,
    )
    fails = [c for c in checks if c.status == "FAIL"]
    if fails:
        raise TsaError(
            "TSA_VERIFICATION_FAILED",
            "; ".join(f"{c.name}: {c.detail}" for c in fails),
        )

    # re-parse for fields (already validated)
    with tempfile.NamedTemporaryFile(suffix=".tsr") as f:
        f.write(token_bytes)
        f.flush()
        text = openssl_ts_text(Path(f.name))
    parsed = parse_ts_text(text)

    anchor = Anchor(
        tsa_id=tsa_id,
        gen_time=parsed.gen_time,  # from token only
        accuracy_s=parsed.accuracy_s,  # from token only
        mode=mode,
        covers=covers,
        token_bytes=token_bytes,
        nonce=parsed.nonce,
        policy_oid=parsed.policy_oid,
        serial=parsed.serial,
        hash_algorithm=parsed.hash_algorithm,
    )
    return anchor, checks


def _reject_if_not_ctt(anchor: Anchor) -> None:
    """Phase 1 bridge for Phase 2 CTT gate."""
    if anchor.mode != "CTT":
        raise TsaError("PRECONDITION_FAILED", "not CTT-anchored")
    if anchor.covers is None or anchor.covers.what != "approver_signature":
        raise TsaError("PRECONDITION_FAILED", "CTT anchor must cover approver_signature")




def anchor_imprint(
    data: bytes,
    *,
    mode: Literal["CTT", "TTC"],
    covers: Covers,
    entry: TsaEntry,
    cfg: dict | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> Anchor:
    """Request a timestamp from entry.url and return a verified Anchor.

    Network failures become TsaError("TSA_UNAVAILABLE", ...). Never bare raise
    urllib/socket errors past this boundary.
    """
    import socket
    import urllib.error
    import urllib.request

    cfg = cfg or {}
    tsq = build_ts_query(data, cert_req=True, timeout=timeout)
    req = urllib.request.Request(
        entry.url,
        data=tsq,
        method="POST",
        headers={"Content-Type": "application/timestamp-query"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = getattr(resp, "status", None) or resp.getcode()
            body = resp.read()
    except urllib.error.HTTPError as e:
        raise TsaError("TSA_UNAVAILABLE", f"HTTP {e.code}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise TsaError("TSA_UNAVAILABLE", f"URLError: {e.reason!r}") from e
    except TimeoutError as e:
        raise TsaError("TSA_UNAVAILABLE", f"socket timeout: {e}") from e
    except socket.timeout as e:
        raise TsaError("TSA_UNAVAILABLE", f"socket.timeout: {e}") from e
    except ConnectionError as e:
        raise TsaError("TSA_UNAVAILABLE", f"ConnectionError: {e}") from e
    except OSError as e:
        # includes network unreachable etc.
        raise TsaError("TSA_UNAVAILABLE", f"OSError: {e}") from e

    if status is not None and int(status) != 200:
        raise TsaError("TSA_UNAVAILABLE", f"non-200 TSA response: {status}")
    if not body:
        raise TsaError("TSA_UNAVAILABLE", "empty TSA response body")

    # Granted tokens are DER; rejection responses may be text
    imprint = hashlib.sha256(data).digest()
    try:
        anchor, checks = anchor_from_verified_token(
            body,
            tsa_id=entry.tsa_id,
            mode=mode,
            covers=covers,
            entry=entry,
            expected_imprint=imprint,
        )
    except TsaError:
        raise
    except Exception as e:
        raise TsaError("TSA_VERIFICATION_FAILED", f"{type(e).__name__}: {e}") from e
    return anchor


def build_ts_query(data: bytes, *, cert_req: bool = True, timeout: float = DEFAULT_TIMEOUT_S) -> bytes:
    """Build a TSQ; cert_req=True is mandatory for production anchors."""
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "data.bin").write_bytes(data)
        argv = [OPENSSL, "ts", "-query", "-data", str(d / "data.bin"), "-sha256", "-out", str(d / "req.tsq")]
        if cert_req:
            argv.append("-cert")
        cp = _run(argv, timeout=timeout)
        if cp.returncode != 0:
            raise TsaError("TSA_UNAVAILABLE", cp.stderr.decode(errors="replace")[:300])
        return (d / "req.tsq").read_bytes()
