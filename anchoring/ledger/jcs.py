"""Canonical JSON (RFC 8785) for ledger hashing.

Backend: `rfc8785` when importable, else the integer-only shim. Either way the
SAME acceptance policy runs first (assert_jcs_safe): ledger entries may contain
only None/bool/int/str/list/dict, ints within +/-(2**53-1), str keys, valid
Unicode. Floats are rejected on every backend so a ledger that verifies in one
environment cannot fail to verify in another.
"""
from __future__ import annotations

from typing import Any

from ._jcs_lite import JcsError
from . import _jcs_lite

try:  # pragma: no cover - depends on environment
    import rfc8785 as _rfc8785
except ImportError:
    _rfc8785 = None

BACKEND = "rfc8785" if _rfc8785 is not None else "shim"
MAX_SAFE_INT = 2**53 - 1


def assert_jcs_safe(obj: Any, _depth: int = 0) -> None:
    if _depth > 64:
        raise JcsError("nesting too deep")
    t = type(obj)
    if obj is None or t is bool:
        return
    if t is int:
        if abs(obj) > MAX_SAFE_INT:
            raise JcsError(f"integer outside +/-(2**53-1): {obj}")
        return
    if t is str:
        try:
            obj.encode("utf-8")
        except UnicodeEncodeError as e:
            raise JcsError(f"string is not valid Unicode: {e}") from e
        return
    if t is list:
        for v in obj:
            assert_jcs_safe(v, _depth + 1)
        return
    if t is dict:
        for k, v in obj.items():
            if type(k) is not str:
                raise JcsError("object keys must be str")
            assert_jcs_safe(k, _depth + 1)
            assert_jcs_safe(v, _depth + 1)
        return
    raise JcsError(f"type {t.__name__} is not allowed in ledger data (floats are rejected)")


def canonicalize(obj: Any) -> bytes:
    assert_jcs_safe(obj)
    if _rfc8785 is not None:
        return _rfc8785.dumps(obj)
    return _jcs_lite.dumps(obj)
