"""Phase 0: ledger primitives (JCS hashing, flock/fsync append, chain verification)."""
from __future__ import annotations

import ast
import base64
import contextlib
import hashlib
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

from anchoring.ledger import (
    GENESIS_PARENT, BACKEND, Ed25519Signer, JcsError, LedgerError, append_entry,
    canonicalize, compute_entry_hash, init_ledger, verify_chain,
)
from anchoring.ledger import _jcs_lite

try:
    import rfc8785
except ImportError:
    rfc8785 = None

REPO = Path(__file__).resolve().parents[1]


@contextlib.contextmanager
def ledger(extra: int = 0):
    d = tempfile.mkdtemp(prefix="lf-ledger-")
    try:
        signer = Ed25519Signer.generate("test-key")
        path = os.path.join(d, "ledger.jsonl")
        init_ledger(path, signer)
        for i in range(extra):
            append_entry(path, "TEST", {"i": i, "msg": f"entry {i}"}, signer)
        yield path, signer, {signer.key_id: signer.public_key_bytes}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _code(fn, *a, **kw) -> str:
    with pytest.raises(LedgerError) as e:
        fn(*a, **kw)
    return e.value.code


# 1. Tamper ---------------------------------------------------------------- #
def test_tamper_every_bit_of_a_middle_entry_is_detected():
    """Flip one bit at EVERY byte of a middle entry (two bit positions). verify_chain must raise
    CHAIN_INTEGRITY_FAILED each time. (The 'ceremony halts' half of the spec test lands in Phase 8:
    ceremony.py has no preflight yet; it will call verify_chain and surface this same code.)"""
    with ledger(extra=5) as (path, _, keys):
        good = verify_chain(path, keys)
        data = Path(path).read_bytes()
        lines = data.split(b"\n")[:-1]
        start = sum(len(l) + 1 for l in lines[:3])
        end = start + len(lines[3]) + 1  # includes the entry's newline
        survivors = []
        for off in range(start, end):
            for mask in (0x01, 0x80):
                b = bytearray(data)
                b[off] ^= mask
                Path(path).write_bytes(bytes(b))
                try:
                    verify_chain(path, keys)
                    survivors.append((off, mask))
                except LedgerError as e:
                    assert e.code == "CHAIN_INTEGRITY_FAILED", (off, mask, e.code)
        assert not survivors, f"tampering went undetected at {survivors[:5]}"
        Path(path).write_bytes(data)
        assert verify_chain(path, keys) == good


def test_delete_swap_duplicate_and_garbage_are_detected():
    with ledger(extra=4) as (path, _, keys):
        data = Path(path).read_bytes()
        L = data.split(b"\n")[:-1]
        cases = {
            "delete middle": L[:2] + L[3:],
            "swap": [L[0], L[2], L[1]] + L[3:],
            "duplicate": L[:3] + [L[2]] + L[3:],
            "garbage line": L + [b"not json"],
            "blank line": L[:2] + [b""] + L[2:],
            "drop genesis": L[1:],
        }
        for name, lines in cases.items():
            Path(path).write_bytes(b"\n".join(lines) + b"\n")
            assert _code(verify_chain, path, keys) == "CHAIN_INTEGRITY_FAILED", name


def test_noncanonical_but_equivalent_signature_encoding_is_rejected():
    """Flipping an unused base64 bit decodes to the same signature; the strict canonical check must catch it."""
    with ledger(extra=1) as (path, _, keys):
        obj = json.loads(Path(path).read_text().splitlines()[1])
        sig = obj["sig"]
        assert sig.endswith("==")
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        last = sig[-3]
        twin = alphabet[alphabet.index(last) ^ 1]  # differs only in an unused low bit
        forged = sig[:-3] + twin + "=="
        assert base64.b64decode(forged) == base64.b64decode(sig) and forged != sig
        text = Path(path).read_text().splitlines()
        text[1] = text[1].replace(sig, forged)
        Path(path).write_text("\n".join(text) + "\n")
        assert _code(verify_chain, path, keys) == "CHAIN_INTEGRITY_FAILED"


def test_genesis_shape_and_signature_trust():
    with ledger(extra=2) as (path, signer, keys):
        first = json.loads(Path(path).read_text().splitlines()[0])
        b = first["body"]
        assert (b["seq"], b["parent_hash"], b["entry_type"]) == (0, GENESIS_PARENT, "GENESIS")
        assert first["key_id"] == "test-key" and first["sig"]
        verify_chain(path, keys)
        other = Ed25519Signer.generate("test-key")  # same id, different key
        assert _code(verify_chain, path, {"test-key": other.public_key_bytes}) == "CHAIN_INTEGRITY_FAILED"
        assert _code(verify_chain, path, {"someone-else": signer.public_key_bytes}) == "CHAIN_INTEGRITY_FAILED"
        assert _code(verify_chain, path, {}) == "NO_TRUSTED_KEYS"


def test_legacy_placeholder_ledger_is_rejected_loudly():
    legacy = REPO / "audit" / "legacy" / "ledger.jsonl.bak"
    assert legacy.is_file()
    signer = Ed25519Signer.generate("k")
    assert _code(verify_chain, legacy, {"k": signer.public_key_bytes}) == "CHAIN_INTEGRITY_FAILED"
    assert not (REPO / "audit" / "ledger.jsonl").exists()  # no fake genesis committed


def test_tail_truncation_is_not_detectable_by_the_chain_alone():
    """Documented limit: dropping the NEWEST entries leaves a valid shorter chain. The run_anchor in the
    transparency log (Phases 4/7/8) is what covers this; do not claim the ledger alone does."""
    with ledger(extra=3) as (path, _, keys):
        lines = Path(path).read_bytes().split(b"\n")[:-1]
        full = verify_chain(path, keys)
        Path(path).write_bytes(b"\n".join(lines[:-1]) + b"\n")
        assert verify_chain(path, keys) != full


def test_init_refuses_existing_ledger_and_append_requires_genesis():
    with ledger() as (path, signer, _):
        assert _code(init_ledger, path, signer) == "LEDGER_EXISTS"
    d = tempfile.mkdtemp()
    try:
        p = os.path.join(d, "x.jsonl")
        assert _code(append_entry, p, "T", {}, Ed25519Signer.generate("k")) == "LEDGER_IO_ERROR"  # missing file
        Path(p).write_bytes(b"")
        assert _code(append_entry, p, "T", {}, Ed25519Signer.generate("k")) == "EMPTY_LEDGER"
    finally:
        shutil.rmtree(d, ignore_errors=True)


# 2. fsync / I-O failure --------------------------------------------------- #
def test_fsync_failure_aborts_and_leaves_no_partial_entry():
    with ledger(extra=2) as (path, signer, keys):
        before_bytes, before_hash = Path(path).read_bytes(), verify_chain(path, keys)
        with mock.patch("os.fsync", side_effect=OSError("disk gone")):
            assert _code(append_entry, path, "TEST", {"x": 1}, signer) == "FSYNC_FAILED"
        assert Path(path).read_bytes() == before_bytes
        assert verify_chain(path, keys) == before_hash
        append_entry(path, "TEST", {"x": 2}, signer)  # ledger still usable
        verify_chain(path, keys)


def test_partial_write_is_rolled_back():
    with ledger(extra=1) as (path, signer, keys):
        before = Path(path).read_bytes()
        real, calls = os.write, []

        def flaky(fd, data):
            if not calls:
                calls.append(1)
                return real(fd, bytes(data)[: len(data) // 2])  # half the entry lands...
            raise OSError("ENOSPC")  # ...then the disk fills

        with mock.patch("os.write", side_effect=flaky):
            assert _code(append_entry, path, "TEST", {"x": 1}, signer) == "LEDGER_IO_ERROR"
        assert Path(path).read_bytes() == before
        verify_chain(path, keys)


def test_torn_tail_is_refused_by_append_and_verify():
    with ledger(extra=2) as (path, signer, keys):
        with open(path, "ab") as f:
            f.write(b'{"body":')  # crash mid-append
        assert _code(append_entry, path, "TEST", {}, signer) == "TORN_TAIL"
        assert _code(verify_chain, path, keys) == "CHAIN_INTEGRITY_FAILED"


# 3. Concurrent writers ---------------------------------------------------- #
def _hold_lock(path, ready, release):
    import fcntl
    fd = os.open(path, os.O_RDWR | os.O_APPEND)
    fcntl.flock(fd, fcntl.LOCK_EX)
    ready.set()
    release.wait(15)
    os.close(fd)


def test_second_writer_blocks_on_flock_not_corrupts():
    ctx = multiprocessing.get_context("fork")
    with ledger() as (path, signer, keys):
        ready, release = ctx.Event(), ctx.Event()
        holder = ctx.Process(target=_hold_lock, args=(path, ready, release))
        holder.start()
        try:
            assert ready.wait(10)
            size = os.path.getsize(path)
            out: dict = {}
            t = threading.Thread(target=lambda: out.setdefault("h", append_entry(path, "TEST", {"w": 1}, signer)))
            t.start()
            time.sleep(0.6)
            assert t.is_alive(), "writer did not block while another process held the lock"
            assert os.path.getsize(path) == size, "bytes were written while the lock was held"
        finally:
            release.set()
            holder.join(10)
        t.join(10)
        assert not t.is_alive() and "h" in out
        assert verify_chain(path, keys) == out["h"]


def _hammer(path, signer, w, n):
    for i in range(n):
        append_entry(path, "TEST", {"w": w, "i": i}, signer)


def test_concurrent_processes_produce_one_valid_chain():
    ctx = multiprocessing.get_context("fork")
    W, N = 4, 20
    with ledger() as (path, signer, keys):
        procs = [ctx.Process(target=_hammer, args=(path, signer, w, N)) for w in range(W)]
        [p.start() for p in procs]
        [p.join(60) for p in procs]
        assert all(p.exitcode == 0 for p in procs)
        verify_chain(path, keys)  # seq contiguous, every parent hash linked
        entries = [json.loads(l)["body"] for l in Path(path).read_text().splitlines()]
        assert len(entries) == 1 + W * N
        assert {(e["payload"]["w"], e["payload"]["i"]) for e in entries[1:]} == {(w, i) for w in range(W) for i in range(N)}


# 4. Locale independence --------------------------------------------------- #
_FIXTURE_SRC = repr({
    "seq": 7, "parent_hash": "0" * 64, "entry_type": "LOCALE_PROBE", "ts": "2026-11-04T00:00:00.000000Z",
    "payload": {"I": 1, "i": 2, "n": 3, "\u0130": 4, "\u0131": 5, "\U0001F600": 6, "\ufb33": 7},
})
# Hand-written canonical form (keys by UTF-16 code unit: ..., U+0131, U+1F600 (D83D), U+FB33):
_EXPECTED_CANON = (
    '{"entry_type":"LOCALE_PROBE","parent_hash":"' + "0" * 64 + '","payload":{"I":1,"i":2,"n":3,'
    '"\u0130":4,"\u0131":5,"\U0001F600":6,"\ufb33":7},"seq":7,"ts":"2026-11-04T00:00:00.000000Z"}'
).encode("utf-8")


def test_entry_hash_is_locale_independent_and_matches_hand_canonical_form():
    """Hash must be identical under every installable locale; skip if fewer than 2 locales available.

    A test whose result depends on an unavailable facility is SKIPPED, never PASSED.
    """
    import locale
    want = hashlib.sha256(_EXPECTED_CANON).hexdigest()
    assert compute_entry_hash(ast.literal_eval(_FIXTURE_SRC)) == want

    candidates = ["C", "C.UTF-8", "POSIX", "en_US.UTF-8", "tr_TR.UTF-8", "ja_JP.UTF-8"]
    available = []
    for loc in candidates:
        try:
            locale.setlocale(locale.LC_ALL, loc)
            available.append(loc)
        except locale.Error:
            pass
    locale.setlocale(locale.LC_ALL, "C")
    if len(available) < 2:
        pytest.skip(
            f"only {len(available)} of {len(candidates)} locales installable ({available}); "
            "cannot prove independence across locales"
        )

    script = (
        "import sys, ast, locale; sys.path.insert(0, sys.argv[1])\n"
        "loc = sys.argv[2]\n"
        "locale.setlocale(locale.LC_ALL, loc)\n"
        "from anchoring.ledger import compute_entry_hash\n"
        f"print(compute_entry_hash(ast.literal_eval({_FIXTURE_SRC!r})))\n"
    )
    seen = {}
    for loc in available:
        out = subprocess.run(
            [sys.executable, "-c", script, str(REPO), loc],
            capture_output=True, text=True, check=True,
        )
        seen[loc] = out.stdout.strip()
    assert set(seen.values()) == {want}, seen



# 5. Floats / unsafe values ------------------------------------------------ #
@pytest.mark.parametrize("bad", [
    {"x": 1.5}, {"x": 1.0}, {"x": [1, 2, {"y": 0.1}]}, {"x": {"y": {"z": float("nan")}}},
    {"x": float("inf")}, {"x": 2**53}, {"x": -(2**53)}, {"x": b"bytes"}, {"x": (1, 2)},
    {"x": {1, 2}}, {1: "non-str key"}, {"x": "\ud800"},
])
def test_unsafe_values_abort_the_append(bad):
    with ledger(extra=1) as (path, signer, keys):
        before = Path(path).read_bytes()
        assert _code(append_entry, path, "TEST", bad, signer) == "JCS_UNSAFE_VALUE"
        assert Path(path).read_bytes() == before
        verify_chain(path, keys)


def test_shim_itself_refuses_floats_loudly():
    for bad in (1.0, 0.1, 1e-7, float("nan"), {"a": [2.5]}):
        with pytest.raises(JcsError):
            _jcs_lite.dumps(bad)


def test_safe_extremes_are_accepted():
    with ledger() as (path, signer, keys):
        append_entry(path, "TEST", {"max": 2**53 - 1, "min": -(2**53 - 1), "t": True, "n": None, "l": [0, -0]}, signer)
        verify_chain(path, keys)


# 6. Shim == rfc8785 (conditional) ----------------------------------------- #
_FIXTURES = [
    {}, [], None, True, 0, -1, 2**53 - 1, "", "plain", "a\tb\nc\"d\\e/f",
    {"b": 1, "a": 2, "": 3}, {"\U0001F600": 1, "\ufb33": 2, "\u00f6": 3, "\u20ac": 4, "\r": 5, "1": 6, "\u0080": 7},
    {"nested": {"z": [1, "two", None, False, {"k": "v"}], "a": []}, "s": "\u00e9\u4e2d\U0001F600"},
    "\x00\x01\x1f\x7f\u2028\u2029",
]


@pytest.mark.skipif(rfc8785 is None, reason="rfc8785 not installed: shim-vs-library comparison NOT RUN")
@pytest.mark.parametrize("fixture", _FIXTURES)
def test_shim_matches_rfc8785_on_integer_only_fixtures(fixture):
    assert _jcs_lite.dumps(fixture) == rfc8785.dumps(fixture)


def test_backend_reports_honestly():
    assert BACKEND == ("rfc8785" if rfc8785 is not None else "shim")


# 7. RFC 8785 string escaping and key ordering ----------------------------- #
def test_string_escaping_per_rfc8785_3_2_2_2():
    esc = {"\b": '"\\b"', "\t": '"\\t"', "\n": '"\\n"', "\f": '"\\f"', "\r": '"\\r"', '"': '"\\""', "\\": '"\\\\"'}
    for ch, want in esc.items():
        assert canonicalize(ch) == want.encode()
    assert canonicalize("\x00") == b'"\\u0000"'
    assert canonicalize("\x0b") == b'"\\u000b"'          # lowercase hex
    assert canonicalize("\x1f") == b'"\\u001f"'
    assert canonicalize("\x7f") == b'"\x7f"'              # DEL is NOT escaped
    assert canonicalize("/") == b'"/"'                    # solidus is NOT escaped
    assert canonicalize("\u2028\u2029") == '"\u2028\u2029"'.encode("utf-8")
    assert canonicalize("\u00e9") == '"\u00e9"'.encode("utf-8")
    assert canonicalize("\U0001F600") == '"\U0001F600"'.encode("utf-8")
    for ch, want in {**esc, "\x00": '"\\u0000"', "\x1f": '"\\u001f"', "\x7f": '"\x7f"'}.items():
        assert _jcs_lite.dumps(ch) == want.encode("utf-8")  # shim agrees regardless of backend


def test_keys_sort_by_utf16_code_units_not_codepoints():
    obj = {"\u20ac": "Euro Sign", "\r": "Carriage Return", "\ufb33": "Hebrew Letter Dalet With Dagesh",
           "1": "One", "\U0001F600": "Emoji: Grinning Face", "\u0080": "Control", "\u00f6": "Latin Small Letter O With Diaeresis"}
    want = ["\r", "1", "\u0080", "\u00f6", "\u20ac", "\U0001F600", "\ufb33"]  # RFC 8785 s3.2.3 order
    assert sorted(obj) != want  # plain sorted() (code points) puts U+FB33 BEFORE U+1F600
    for dumps in (canonicalize, _jcs_lite.dumps):
        keys = list(json.loads(dumps(obj)).keys())
        assert keys == want


def test_no_bare_json_dumps_sort_keys_in_ledger_package():
    for f in (REPO / "anchoring" / "ledger").glob("*.py"):
        src = f.read_text()
        assert "sort_keys" not in src, f"{f.name}: bare json.dumps(sort_keys=True) is not JCS"
        assert "json.dumps" not in src, f"{f.name}: hash input must come from jcs.canonicalize"


# --- gap-closers found by mutation testing ------------------------------- #
def _forge_line(signer, seq, parent, payload) -> bytes:
    """A perfectly valid, correctly signed, self-consistent entry -- with whatever parent we choose."""
    body = {"seq": seq, "parent_hash": parent, "entry_type": "TEST",
            "ts": "2026-01-01T00:00:00.000000Z", "payload": payload}
    h = compute_entry_hash(body)
    sig = base64.b64encode(signer.sign(bytes.fromhex(h))).decode()
    return canonicalize({"body": body, "entry_hash": h, "key_id": signer.key_id, "sig": sig}) + b"\n"


def test_correctly_signed_entry_with_wrong_parent_link_is_rejected():
    """seq contiguous, hash right, signature right, ONLY the parent link is wrong (a splice/fork)."""
    with ledger(extra=1) as (path, signer, keys):
        lines = Path(path).read_bytes().split(b"\n")[:-1]
        genesis_hash = json.loads(lines[0])["entry_hash"]
        e1_hash = json.loads(lines[1])["entry_hash"]
        control = Path(path).read_bytes() + _forge_line(signer, 2, e1_hash, {"ok": 1})
        Path(path).write_bytes(control)
        verify_chain(path, keys)  # control: with the right parent it verifies
        bad = Path(path).read_bytes().rsplit(b"\n", 2)[0] + b"\n" + _forge_line(signer, 2, genesis_hash, {"ok": 1})
        Path(path).write_bytes(bad)
        with pytest.raises(LedgerError) as e:
            verify_chain(path, keys)
        assert e.value.code == "CHAIN_INTEGRITY_FAILED" and "parent_hash" in str(e.value)


def test_noncanonical_encodings_of_valid_entries_are_rejected():
    with ledger(extra=1) as (path, _, keys):
        raw = Path(path).read_bytes()
        lines = raw.split(b"\n")[:-1]
        obj = json.loads(lines[1])
        text = lines[1].decode()
        variants = {
            "spaces": json.dumps(obj).encode(),
            "reordered keys": json.dumps(dict(reversed(list(obj.items()))), separators=(",", ":")).encode(),
            "unicode escape": text.replace("entry 0", "\\u0065ntry 0").encode(),
            "duplicate key": text.replace('{"body"', '{"key_id":"test-key","body"', 1).encode(),
            "float spelling": text.replace('"seq":1', '"seq":1.0', 1).encode(),
            "trailing space": (text + " ").encode(),
        }
        for name, v in variants.items():
            assert v != lines[1], name
            Path(path).write_bytes(b"\n".join([lines[0], v]) + b"\n")
            assert _code(verify_chain, path, keys) == "CHAIN_INTEGRITY_FAILED", name
        Path(path).write_bytes(raw)
        verify_chain(path, keys)


def test_float_guard_is_independent_of_the_serializer_backend():
    """With the rfc8785 backend a float would be formatted, not refused -- the guard must stop it first."""
    from anchoring.ledger import jcs

    class FakeLib:  # stands in for a backend that happily serializes floats
        @staticmethod
        def dumps(o):
            return json.dumps(o, separators=(",", ":")).encode()

    with pytest.raises(JcsError):
        jcs.assert_jcs_safe({"x": 1.5})
    with mock.patch.object(jcs, "_rfc8785", FakeLib):
        for bad in (1.5, {"x": [0.1]}, float("nan")):
            with pytest.raises(JcsError):
                jcs.canonicalize(bad)
        with ledger() as (path, signer, _):
            assert _code(append_entry, path, "TEST", {"x": 1.5}, signer) == "JCS_UNSAFE_VALUE"
