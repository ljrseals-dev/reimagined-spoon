"""RFC 3161 token -text parser (OpenSSL 3.0.x format). Fail-closed on field drift."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone


class TokenParseError(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


# Required fields — any absence is TOKEN_PARSE_DRIFT (parameterized tests cover each).
_REQUIRED = (
    ("Nonce:", re.compile(r"^Nonce:\s*(.+)$", re.M)),
    ("Policy OID:", re.compile(r"^Policy OID:\s*(.+)$", re.M)),
    ("Serial number:", re.compile(r"^Serial number:\s*(.+)$", re.M)),
    ("Time stamp:", re.compile(r"^Time stamp:\s*(.+)$", re.M)),
)

_HASH_ALG = re.compile(r"^Hash Algorithm:\s*(\S+)", re.M)
_ACCURACY = re.compile(
    r"^Accuracy:\s*(?:0x([0-9a-fA-F]+)|(\d+))\s*seconds", re.M
)
_MSG_DATA = re.compile(
    r"Message data:\s*\n((?:[ \t]+[0-9a-fA-F].*\n)+)", re.M
)


@dataclass(frozen=True)
class ParsedToken:
    nonce: str
    policy_oid: str
    serial: str
    gen_time: datetime
    hash_algorithm: str
    message_imprint: bytes
    accuracy_s: float
    raw_text: str


def _parse_gen_time(s: str) -> datetime:
    s = s.strip()
    # OpenSSL: "Nov  4 03:39:58 2026 GMT"
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
        try:
            dt = datetime.strptime(s.replace("  ", " "), fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    # ISO fallback
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError as e:
        raise TokenParseError("TOKEN_PARSE_DRIFT", f"Time stamp unparseable: {s!r}") from e


def parse_ts_text(text: str) -> ParsedToken:
    missing = [name for name, rx in _REQUIRED if not rx.search(text)]
    if missing:
        raise TokenParseError(
            "TOKEN_PARSE_DRIFT",
            f"required field(s) absent from -text: {missing}",
        )

    def _g(name: str, rx: re.Pattern) -> str:
        m = rx.search(text)
        assert m  # checked above
        return m.group(1).strip()

    nonce = _g("Nonce:", _REQUIRED[0][1])
    policy = _g("Policy OID:", _REQUIRED[1][1])
    serial = _g("Serial number:", _REQUIRED[2][1])
    ts_raw = _g("Time stamp:", _REQUIRED[3][1])
    gen_time = _parse_gen_time(ts_raw)

    hm = _HASH_ALG.search(text)
    if not hm:
        raise TokenParseError("TOKEN_PARSE_DRIFT", "Hash Algorithm: absent")
    hash_alg = hm.group(1).lower()

    accuracy_s = 1.0
    am = _ACCURACY.search(text)
    if am:
        accuracy_s = float(int(am.group(1), 16) if am.group(1) else am.group(2))

    imprint = b""
    mm = _MSG_DATA.search(text)
    if mm:
        hex_bytes = re.findall(r"\b[0-9a-fA-F]{2}\b", mm.group(1))
        imprint = bytes(int(h, 16) for h in hex_bytes)

    return ParsedToken(
        nonce=nonce,
        policy_oid=policy,
        serial=serial,
        gen_time=gen_time,
        hash_algorithm=hash_alg,
        message_imprint=imprint,
        accuracy_s=accuracy_s,
        raw_text=text,
    )
