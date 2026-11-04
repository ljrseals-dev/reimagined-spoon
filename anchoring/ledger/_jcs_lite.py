"""Minimal RFC 8785 (JCS) serializer for INTEGER-AND-STRING-ONLY data.

Sandbox fallback only. Production uses the `rfc8785` package (pyproject.toml).
It is safe to use here because every ledger entry is integer/str/bool/None/
dict/list; it REFUSES floats (never formats them), which is where hand-rolled
JCS diverges from ECMAScript number formatting (1e-7 vs 1e-07 and friends).

  * object keys sort by UTF-16 code units (NOT code points, NOT sorted()):
    U+1F600 (surrogates D83D DE00) sorts BEFORE U+FB33.
  * string escaping per RFC 8785 s3.2.2.2: \\b \\t \\n \\f \\r \\" \\\\ as two-char
    escapes, other C0 controls as lowercase \\u00xx, everything else literal.
"""
from __future__ import annotations

from typing import Any


class JcsError(ValueError):
    pass


_ESC = {0x08: "\\b", 0x09: "\\t", 0x0A: "\\n", 0x0C: "\\f", 0x0D: "\\r", 0x22: '\\"', 0x5C: "\\\\"}


def _string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if o in _ESC:
            out.append(_ESC[o])
        elif o < 0x20:
            out.append(f"\\u{o:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(k: str) -> bytes:
    try:
        return k.encode("utf-16-be")  # big-endian bytes compare == code-unit compare
    except UnicodeEncodeError as e:
        raise JcsError(f"key is not valid Unicode: {e}") from e


def _ser(obj: Any, depth: int) -> str:
    if depth > 64:
        raise JcsError("nesting too deep")
    t = type(obj)
    if obj is None:
        return "null"
    if t is bool:
        return "true" if obj else "false"
    if t is int:
        return str(obj)
    if t is float:
        raise JcsError("floats are not supported by the JCS shim (integer-only)")
    if t is str:
        return _string(obj)
    if t is list:
        return "[" + ",".join(_ser(v, depth + 1) for v in obj) + "]"
    if t is dict:
        for k in obj:
            if type(k) is not str:
                raise JcsError("object keys must be str")
        items = sorted(obj.items(), key=lambda kv: _utf16_key(kv[0]))
        return "{" + ",".join(_string(k) + ":" + _ser(v, depth + 1) for k, v in items) + "}"
    raise JcsError(f"unsupported type {t.__name__}")


def dumps(obj: Any) -> bytes:
    try:
        return _ser(obj, 0).encode("utf-8")
    except UnicodeEncodeError as e:
        raise JcsError(f"string is not valid Unicode: {e}") from e
