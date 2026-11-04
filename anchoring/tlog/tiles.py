"""C2SP tlog-tiles fetch + node derivation (Rekor v2 tile layout).

Geometry (tile height 8): the tile at level L, number N holds up to 256
consecutive hashes of tree level 8*L -- nodes N*256 .. N*256 + 255 of that
level. A node at tree level k = 8*L + r is therefore NOT stored directly when
r > 0: it is the fold of the 2**r consecutive level-8L hashes that start at
index (idx << r). (The pre-fix code used idx >> r, which is the wrong
direction.)

Only COMPLETE nodes live in tiles. The right edge of a log whose size is not a
power of two also has incomplete nodes (their hash is the RFC 6962 MTH of the
leaves that exist); those are derived by `subtree_hash`, never fetched.

API NOTE: node() and subtree_hash() take the tree size explicitly, because the
size decides whether the tile is full (`/tile/L/N`) or partial
(`/tile/L/N.p/W`) in the C2SP URL scheme.
"""
from __future__ import annotations

from hashlib import sha256
from typing import Any

TILE_HEIGHT = 8
TILE_WIDTH = 1 << TILE_HEIGHT  # 256 hashes per full tile
MAX_TILE_LEVEL = 63


class TlogError(Exception):
    def __init__(self, code: str, msg: str = ""):
        self.code = code
        super().__init__(f"{code}: {msg}" if msg else code)


def _hash_children(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right).digest()


def tile_path(level: int, index: int, width: int) -> str:
    """C2SP tlog-tiles path, e.g. tile/0/x001/x234/067 or tile/1/000.p/2.

    The index is written as zero-padded 3-digit groups, every group but the
    last prefixed with 'x'. width < 256 selects the partial-tile form.
    """
    if not (0 <= level <= MAX_TILE_LEVEL):
        raise TlogError("BAD_TILE_ADDRESS", f"level {level}")
    if index < 0:
        raise TlogError("BAD_TILE_ADDRESS", f"index {index}")
    if not (1 <= width <= TILE_WIDTH):
        raise TlogError("BAD_TILE_ADDRESS", f"width {width}")
    digits = str(index)
    digits = digits.rjust(-(-len(digits) // 3) * 3, "0")
    groups = [digits[i : i + 3] for i in range(0, len(digits), 3)]
    path = "/".join(["x" + g for g in groups[:-1]] + [groups[-1]])
    out = f"tile/{level}/{path}"
    if width < TILE_WIDTH:
        out += f".p/{width}"
    return out


def _fold(hashes: list[bytes]) -> bytes:
    """Root of the perfect binary tree whose leaves are `hashes` (power-of-two length)."""
    n = len(hashes)
    if n == 0 or n & (n - 1):
        raise TlogError("TILE_MALFORMED", "fold window is not a power of two")
    row = hashes
    while len(row) > 1:
        row = [_hash_children(row[i], row[i + 1]) for i in range(0, len(row), 2)]
    return row[0]


class TileStore:
    """Fetches and caches C2SP tlog-tiles; derives node hashes on demand."""

    def __init__(self, base_url: str, session: Any = None, cache: dict | None = None):
        self.base_url = base_url.rstrip("/")
        self.session = session
        # `cache or {}` would silently discard a caller's empty dict.
        self.cache: dict[tuple[int, int, int], list[bytes]] = {} if cache is None else cache

    def _tile(self, level: int, number: int, width: int) -> list[bytes]:
        key = (level, number, width)  # tiles are immutable per (level, number, width)
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        if self.session is None:
            raise TlogError("NO_SESSION", "live fetch requires an HTTP session")
        url = f"{self.base_url}/{tile_path(level, number, width)}"
        try:
            r = self.session.get(url, timeout=30)
            r.raise_for_status()
            raw = r.content
        except TlogError:
            raise
        except Exception as e:  # fail closed: any fetch problem is a TlogError
            raise TlogError("TILE_FETCH_FAILED", f"{url}: {e!r}") from e
        if not isinstance(raw, (bytes, bytearray)) or len(raw) != 32 * width:
            raise TlogError("TILE_MALFORMED", f"{url}: expected {32 * width} bytes")
        hashes = [bytes(raw[i : i + 32]) for i in range(0, len(raw), 32)]
        self.cache[key] = hashes
        return hashes

    def node(self, k: int, idx: int, size: int) -> bytes:
        """Hash of the COMPLETE node at tree level k, index idx, in a tree of `size` leaves."""
        if k < 0 or idx < 0 or size < 1 or ((idx + 1) << k) > size:
            raise TlogError("NODE_NOT_COMPLETE", f"node({k},{idx}) in size {size}")
        level, r = divmod(k, TILE_HEIGHT)
        first = idx << r                         # leftmost level-8L descendant
        count = 1 << r
        number = first >> TILE_HEIGHT
        complete_at_level = size >> (TILE_HEIGHT * level)
        width = min(TILE_WIDTH, complete_at_level - number * TILE_WIDTH)
        hashes = self._tile(level, number, width)
        start = first - number * TILE_WIDTH
        return _fold(hashes[start : start + count])

    def subtree_hash(self, k: int, idx: int, size: int) -> bytes:
        """RFC 6962 hash of the level-k, index-idx node, complete or right-edge-incomplete."""
        lo = idx << k
        hi = min((idx + 1) << k, size)
        if k < 0 or idx < 0 or lo >= size:
            raise TlogError("NODE_OUT_OF_RANGE", f"node({k},{idx}) in size {size}")
        return self._range_hash(lo, hi, size)

    def _range_hash(self, lo: int, hi: int, size: int) -> bytes:
        n = hi - lo
        if n & (n - 1) == 0 and lo % n == 0:  # complete, aligned power-of-two subtree
            k = n.bit_length() - 1
            return self.node(k, lo >> k, size)
        split = 1 << ((n - 1).bit_length() - 1)  # largest power of two < n
        return _hash_children(
            self._range_hash(lo, lo + split, size),
            self._range_hash(lo + split, hi, size),
        )
