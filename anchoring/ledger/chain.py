"""Hash-chained, Ed25519-signed, append-only ledger (Phase 0).

On-disk format: one canonical-JCS line per entry, newline-terminated:
    {"body": {seq, parent_hash, entry_type, ts, payload},
     "entry_hash": sha256(JCS(body)) as lowercase hex,
     "key_id": ..., "sig": base64(Ed25519(entry_hash bytes))}

Writers take an exclusive flock, read the tail FROM THE FILE (there is no
cached tail pointer to advance early), write, then fsync. If the write or the
fsync fails, the file is truncated back to its previous length and the call
raises; the entry is never left half-visible. If even that rollback fails the
tail is torn, which append_entry and verify_chain both refuse (fail closed).

Known limit (by design): a chain alone cannot detect truncation of the newest
entries. That is what the run_anchor in the transparency log is for.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from . import jcs

try:
    import fcntl
except ImportError:  # Windows: refuse to run rather than silently lose the lock guarantee
    fcntl = None  # type: ignore[assignment]

GENESIS_PARENT = "0" * 64
_BODY_KEYS = frozenset({"seq", "parent_hash", "entry_type", "ts", "payload"})
_LINE_KEYS = frozenset({"body", "entry_hash", "key_id", "sig"})
_HEX = frozenset("0123456789abcdef")


class LedgerError(Exception):
    def __init__(self, code: str, msg: str = ""):
        self.code = code
        super().__init__(f"{code}: {msg}" if msg else code)


def _require_posix() -> None:
    if fcntl is None:
        raise LedgerError("UNSUPPORTED_PLATFORM", "flock-based ledger requires POSIX")


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def compute_entry_hash(body: Mapping[str, Any]) -> str:
    """sha256 over RFC 8785 canonical JSON of the entry body, lowercase hex."""
    try:
        return hashlib.sha256(jcs.canonicalize(body)).hexdigest()
    except jcs.JcsError as e:
        raise LedgerError("JCS_UNSAFE_VALUE", str(e)) from e


# ------------------------------------------------------------------ parsing --
def _no_dupes(pairs):
    d: dict = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _reject(token):
    raise ValueError(f"non-integer number {token!r}")


def _parse_line(line: bytes) -> dict:
    """Strict: UTF-8, no dup keys, integers only, and byte-identical to its own canonical form."""
    obj = json.loads(
        line.decode("utf-8"),
        object_pairs_hook=_no_dupes,
        parse_float=_reject,
        parse_constant=_reject,
    )
    if type(obj) is not dict:
        raise ValueError("line is not an object")
    if jcs.canonicalize(obj) != line:
        raise ValueError("line is not canonical JCS")
    return obj


def _is_hex64(s: Any) -> bool:
    return type(s) is str and len(s) == 64 and set(s) <= _HEX


def _self_check(obj: dict) -> str:
    """Shape + entry_hash recomputation. Returns entry_hash. Raises ValueError."""
    if set(obj) != _LINE_KEYS:
        raise ValueError("unexpected line keys")
    body = obj["body"]
    if type(body) is not dict or set(body) != _BODY_KEYS:
        raise ValueError("unexpected body keys")
    if type(body["seq"]) is not int or body["seq"] < 0:
        raise ValueError("bad seq")
    if not _is_hex64(body["parent_hash"]):
        raise ValueError("bad parent_hash")
    if type(body["entry_type"]) is not str or not body["entry_type"]:
        raise ValueError("bad entry_type")
    if type(body["ts"]) is not str or type(body["payload"]) is not dict:
        raise ValueError("bad ts/payload")
    if not _is_hex64(obj["entry_hash"]) or compute_entry_hash(body) != obj["entry_hash"]:
        raise ValueError("entry_hash does not match body")
    if type(obj["key_id"]) is not str or type(obj["sig"]) is not str:
        raise ValueError("bad key_id/sig")
    return obj["entry_hash"]


def _verify_sig(obj: dict, trusted_keys: Mapping[str, bytes]) -> None:
    pub = trusted_keys.get(obj["key_id"])
    if pub is None:
        raise ValueError(f"key_id {obj['key_id']!r} is not trusted")
    raw = base64.b64decode(obj["sig"], validate=True)
    if base64.b64encode(raw).decode("ascii") != obj["sig"]:  # non-canonical base64 = malleable
        raise ValueError("signature base64 is not canonical")
    if len(raw) != 64:
        raise ValueError("signature length")
    try:
        Ed25519PublicKey.from_public_bytes(bytes(pub)).verify(raw, bytes.fromhex(obj["entry_hash"]))
    except InvalidSignature as e:
        raise ValueError("signature invalid") from e


# ------------------------------------------------------------------- verify --
def _verify_bytes(data: bytes, trusted_keys: Mapping[str, bytes]) -> str:
    if not data:
        raise LedgerError("CHAIN_INTEGRITY_FAILED", "ledger is empty (no GENESIS)")
    if not data.endswith(b"\n"):
        raise LedgerError("CHAIN_INTEGRITY_FAILED", "torn tail: file does not end with newline")
    prev = GENESIS_PARENT
    final = prev
    for i, line in enumerate(data.split(b"\n")[:-1]):
        try:
            obj = _parse_line(line)
            h = _self_check(obj)
            body = obj["body"]
            if body["seq"] != i:
                raise ValueError(f"seq {body['seq']} != expected {i}")
            if body["parent_hash"] != prev:
                raise ValueError("parent_hash does not link to previous entry")
            if (body["entry_type"] == "GENESIS") != (i == 0):
                raise ValueError("GENESIS must be exactly entry 0")
            _verify_sig(obj, trusted_keys)
        except Exception as e:  # any failure, expected or not, fails the chain
            raise LedgerError("CHAIN_INTEGRITY_FAILED", f"entry {i}: {e}") from e
        prev = final = h
    return final


def verify_chain(path: str | os.PathLike, trusted_keys: Mapping[str, bytes]) -> str:
    """Verify seq monotonicity, parent linkage, hash recomputation and Ed25519
    signatures (against `trusted_keys`: key_id -> raw 32-byte public key).
    Returns the final entry hash. Raises LedgerError on ANY problem."""
    _require_posix()
    if not trusted_keys:
        raise LedgerError("NO_TRUSTED_KEYS", "verify_chain requires at least one trusted key")
    try:
        with open(os.fspath(path), "rb") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)
            data = f.read()
    except OSError as e:
        raise LedgerError("LEDGER_IO_ERROR", repr(e)) from e
    try:
        return _verify_bytes(data, trusted_keys)
    except LedgerError:
        raise
    except Exception as e:
        raise LedgerError("CHAIN_INTEGRITY_FAILED", f"unexpected {e!r}") from e


# ------------------------------------------------------------------- append --
def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    off = 0
    while off < len(view):
        n = os.write(fd, view[off:])
        if n <= 0:
            raise OSError("short write")
        off += n


def _read_last_line(fd: int, size: int) -> bytes:
    if size == 0:
        raise LedgerError("EMPTY_LEDGER", "no GENESIS; call init_ledger first")
    buf = b""
    pos = size
    while True:
        step = min(65536, pos)
        pos -= step
        buf = os.pread(fd, step, pos) + buf
        if buf[-1:] != b"\n":
            raise LedgerError("TORN_TAIL", "ledger does not end with newline; refusing to append")
        inner = buf[:-1]
        cut = inner.rfind(b"\n")
        if cut != -1 or pos == 0:
            return inner[cut + 1 :]


def _commit(fd: int, size: int, seq: int, parent: str, entry_type: str,
            payload: dict, signer: Any, ts: str | None) -> str:
    body = {"seq": seq, "parent_hash": parent, "entry_type": entry_type,
            "ts": ts if ts is not None else _now(), "payload": payload}
    h = compute_entry_hash(body)
    try:
        sig = base64.b64encode(signer.sign(bytes.fromhex(h))).decode("ascii")
        line = jcs.canonicalize({"body": body, "entry_hash": h, "key_id": signer.key_id, "sig": sig}) + b"\n"
    except LedgerError:
        raise
    except Exception as e:
        raise LedgerError("SIGN_FAILED", repr(e)) from e
    stage, code = "write", "LEDGER_IO_ERROR"
    try:
        _write_all(fd, line)
        stage, code = "fsync", "FSYNC_FAILED"
        os.fsync(fd)
    except Exception as e:
        try:
            os.ftruncate(fd, size)  # entry must not stay visible
        except OSError as e2:
            raise LedgerError("LEDGER_IO_ERROR",
                              f"{stage} failed ({e!r}) AND rollback failed ({e2!r}); tail is torn") from e
        raise LedgerError(code, f"{stage} failed, entry rolled back: {e!r}") from e
    return h


def init_ledger(path: str | os.PathLike, signer: Any, *, ts: str | None = None) -> str:
    """Create the ledger with a signed GENESIS entry (seq 0, parent 0*64). Refuses to touch a non-empty file."""
    _require_posix()
    p = os.fspath(path)
    try:
        os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
        fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    except OSError as e:
        raise LedgerError("LEDGER_IO_ERROR", repr(e)) from e
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        size = os.fstat(fd).st_size
        if size != 0:
            raise LedgerError("LEDGER_EXISTS", "refusing to initialise a non-empty ledger")
        h = _commit(fd, 0, 0, GENESIS_PARENT, "GENESIS",
                    {"schema": "artifact.ledger.v1", "signer_key_id": signer.key_id}, signer, ts)
        dfd = os.open(os.path.dirname(os.path.abspath(p)), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return h
    except LedgerError:
        raise
    except Exception as e:
        raise LedgerError("LEDGER_IO_ERROR", repr(e)) from e
    finally:
        os.close(fd)


def append_entry(path: str | os.PathLike, entry_type: str, payload: dict, signer: Any,
                 *, ts: str | None = None) -> str:
    """Append one signed entry; returns its entry_hash. Fail-closed on every error."""
    _require_posix()
    if not isinstance(entry_type, str) or not entry_type or entry_type == "GENESIS":
        raise LedgerError("BAD_ENTRY_TYPE", "entry_type must be a non-empty str other than GENESIS")
    if type(payload) is not dict:
        raise LedgerError("JCS_UNSAFE_VALUE", "payload must be a dict")
    try:
        jcs.assert_jcs_safe(payload)
    except jcs.JcsError as e:
        raise LedgerError("JCS_UNSAFE_VALUE", str(e)) from e
    try:
        fd = os.open(os.fspath(path), os.O_RDWR | os.O_APPEND)
    except OSError as e:
        raise LedgerError("LEDGER_IO_ERROR", repr(e)) from e
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)  # blocks while another writer holds it
        size = os.fstat(fd).st_size
        try:
            tail = _parse_line(_read_last_line(fd, size))
            tail_hash = _self_check(tail)
        except LedgerError:
            raise
        except Exception as e:
            raise LedgerError("CHAIN_INTEGRITY_FAILED", f"tail entry unreadable: {e}") from e
        return _commit(fd, size, tail["body"]["seq"] + 1, tail_hash, entry_type, payload, signer, ts)
    except LedgerError:
        raise
    except Exception as e:
        raise LedgerError("LEDGER_IO_ERROR", repr(e)) from e
    finally:
        os.close(fd)  # also releases the flock
