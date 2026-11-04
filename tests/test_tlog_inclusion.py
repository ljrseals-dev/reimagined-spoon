"""Phase -1: verify_inclusion + TileStore against an independent RFC 6962 reference.

The reference (RefLog) and the fake tile server (FakeSession) are written here,
from RFC 6962 s2.1 and the C2SP tlog-tiles URL grammar, and share no code with
anchoring/. A bug in anchoring/ therefore cannot also hide inside the oracle.
"""
from __future__ import annotations

import functools
import re
from hashlib import sha256

import pytest

from anchoring.tlog.config import Checkpoint
from anchoring.tlog.inclusion import verify_inclusion
from anchoring.tlog.tiles import TileStore, TlogError, tile_path

BASE = "https://log.test"


def _h(left: bytes, right: bytes) -> bytes:
    return sha256(b"\x01" + left + right).digest()


class RefLog:
    """Reference Merkle tree: MTH exactly as RFC 6962 s2.1 defines it."""

    def __init__(self, n: int):
        self.n = n
        self.leaves = [sha256(b"\x00" + i.to_bytes(8, "big")).digest() for i in range(n)]
        self._memo: dict[tuple[int, int], bytes] = {}

    def mth(self, lo: int, hi: int) -> bytes:
        key = (lo, hi)
        if key not in self._memo:
            n = hi - lo
            if n == 1:
                r = self.leaves[lo]
            else:
                k = 1
                while k * 2 < n:  # largest power of two strictly less than n
                    k *= 2
                r = _h(self.mth(lo, lo + k), self.mth(lo + k, hi))
            self._memo[key] = r
        return self._memo[key]

    @property
    def root(self) -> bytes:
        return self.mth(0, self.n)


@functools.lru_cache(maxsize=None)
def ref_log(n: int) -> RefLog:
    return RefLog(n)


class _Resp:
    def __init__(self, status: int, content: bytes = b""):
        self.status, self.content = status, content

    def raise_for_status(self) -> None:
        if self.status != 200:
            raise RuntimeError(f"HTTP {self.status}")


_URL = re.compile(r"^https://log\.test/tile/(\d{1,2})/((?:x\d{3}/)*\d{3})(?:\.p/(\d{1,3}))?$")


class FakeSession:
    """Serves tiles per the C2SP grammar; refuses anything malformed or not yet complete."""

    def __init__(self, log: RefLog, tamper: dict | None = None):
        self.log, self.tamper, self.requested = log, tamper or {}, []

    def get(self, url: str, timeout=None):
        self.requested.append(url)
        m = _URL.match(url)
        if not m:
            return _Resp(404)
        level = int(m.group(1))
        number = int(m.group(2).replace("x", "").replace("/", ""))
        width = int(m.group(3)) if m.group(3) else 256
        if m.group(3) and not (1 <= width <= 255):
            return _Resp(404)
        complete = self.log.n >> (8 * level)
        if number * 256 + width > complete:
            return _Resp(404)
        raw = b"".join(
            self.log.mth(j << (8 * level), (j + 1) << (8 * level))
            for j in range(number * 256, number * 256 + width)
        )
        fn = self.tamper.get((level, number, width))
        return _Resp(200, fn(raw) if fn else raw)


def _store(n: int, **kw) -> tuple[TileStore, FakeSession, RefLog]:
    log = ref_log(n)
    sess = FakeSession(log, **kw)
    return TileStore(BASE, session=sess), sess, log


def _check(n: int, i: int) -> None:
    store, _, log = _store(n)
    verify_inclusion(log.leaves[i], i, Checkpoint(size=n, root=log.root), store)


# --------------------------------------------------------------------------- #
# 1. All 153 (size, index) vectors, sizes 1..17                               #
# --------------------------------------------------------------------------- #
VECTORS = [(n, i) for n in range(1, 18) for i in range(n)]


def test_vector_set_is_all_153_cases():
    assert len(VECTORS) == 153


@pytest.mark.parametrize("size,index", VECTORS)
def test_inclusion_all_small_vectors(size, index):
    _check(size, index)


# --------------------------------------------------------------------------- #
# 2. The old verify_inclusion demonstrably fails the 20 known cases          #
# --------------------------------------------------------------------------- #
LEGACY_FAILURES = {
    (3, 2), (5, 4), (6, 4), (6, 5), (7, 6), (9, 8), (10, 8), (10, 9), (11, 8), (11, 9),
    (11, 10), (12, 8), (12, 9), (12, 10), (12, 11), (13, 12), (14, 12), (14, 13), (15, 14),
    (17, 16),
}


def _legacy_verify_inclusion(leaf_hash_bytes, index, cp, tiles):
    """Pre-fix body, verbatim (the `n -= 1; continue` branch is the defect)."""
    acc, idx, n = leaf_hash_bytes, index, cp.size
    k = 0
    while n > 1:
        if idx == n - 1 and idx % 2 == 0:
            n -= 1
            continue
        sib = tiles.node(k, idx ^ 1)
        left, right = (acc, sib) if idx % 2 == 0 else (sib, acc)
        acc = sha256(b"\x01" + left + right).digest()
        idx >>= 1
        n = (n + 1) >> 1
        k += 1
    if acc != cp.root:
        raise TlogError("INCLUSION_FAILED", "recomputed root != checkpoint root")


class _CorrectNodes:
    """Reference-correct node source, so only the legacy LOOP can be at fault."""

    def __init__(self, log: RefLog):
        self.log = log

    def node(self, k: int, idx: int) -> bytes:
        lo, hi = idx << k, min((idx + 1) << k, self.log.n)
        if lo >= self.log.n:
            raise TlogError("NODE_OUT_OF_RANGE")
        return self.log.mth(lo, hi)


def _legacy_fails(n: int, i: int) -> bool:
    log = ref_log(n)
    try:
        _legacy_verify_inclusion(log.leaves[i], i, Checkpoint(size=n, root=log.root), _CorrectNodes(log))
    except Exception:
        return True
    return False


def test_legacy_fails_exactly_the_20_known_cases():
    failing = {v for v in VECTORS if _legacy_fails(*v)}
    assert len(failing) == 20
    assert failing == LEGACY_FAILURES


@pytest.mark.parametrize("size,index", sorted(LEGACY_FAILURES))
def test_fixed_implementation_passes_each_legacy_failure(size, index):
    assert _legacy_fails(size, index)  # the old code is broken here...
    _check(size, index)                # ...and the new code is not.


# --------------------------------------------------------------------------- #
# 3. Larger logs: exercises tile levels 0, 1 and 2 and full/partial tiles    #
# --------------------------------------------------------------------------- #
_BIG = [
    (255, [0, 1, 127, 253, 254]),
    (256, [0, 1, 128, 254, 255]),
    (257, [0, 1, 255, 256]),
    (511, [0, 255, 256, 509, 510]),
    (513, [0, 256, 511, 512]),
    (600, [0, 1, 300, 598, 599]),
    (1000, [0, 255, 256, 511, 512, 998, 999]),
    (65541, [0, 255, 256, 65535, 65536, 65539, 65540]),
]


@pytest.mark.parametrize("size,index", [(n, i) for n, idxs in _BIG for i in idxs])
def test_inclusion_larger_logs(size, index):
    _check(size, index)


def test_partial_and_full_tile_urls_follow_c2sp_layout():
    n = 600  # level 0: tiles 0,1 full + tile 2 partial (88); level 1: one partial tile (2)
    store, sess, log = _store(n)
    verify_inclusion(log.leaves[599], 599, Checkpoint(size=n, root=log.root), store)
    want = {"tile/0/002.p/88", "tile/1/000.p/2"}
    got = {u[len(BASE) + 1 :] for u in sess.requested}
    assert want <= got, got
    assert not any(u.endswith("tile/0/002") for u in sess.requested)  # never ask for a not-yet-full tile


def test_tile_path_examples():
    assert tile_path(0, 1234067, 256) == "tile/0/x001/x234/067"  # C2SP spec example
    assert tile_path(0, 0, 256) == "tile/0/000"
    assert tile_path(3, 5, 256) == "tile/3/005"
    assert tile_path(0, 1000, 256) == "tile/0/x001/000"
    assert tile_path(1, 0, 2) == "tile/1/000.p/2"
    assert tile_path(0, 1234067, 255) == "tile/0/x001/x234/067.p/255"


@pytest.mark.parametrize("lvl,idx,w", [(-1, 0, 256), (64, 0, 256), (0, -1, 256), (0, 0, 0), (0, 0, 257)])
def test_tile_path_rejects_bad_addresses(lvl, idx, w):
    with pytest.raises(TlogError) as e:
        tile_path(lvl, idx, w)
    assert e.value.code == "BAD_TILE_ADDRESS"


# --------------------------------------------------------------------------- #
# 4. TileStore.node / subtree_hash vs the reference                          #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("size", [600, 65541])
def test_node_matches_reference_at_every_level(size):
    store, _, log = _store(size)
    checked = 0
    for k in range(0, 17):
        complete = size >> k
        if complete == 0:
            continue
        for idx in sorted({0, complete // 2, complete - 1}):
            assert store.node(k, idx, size) == log.mth(idx << k, (idx + 1) << k), (k, idx)
            checked += 1
    assert checked > 20


def test_node_right_direction_regression():
    """idx << r, not idx >> r: node(1, 3) is leaves 6..7, not a fold around leaf 1."""
    store, _, log = _store(600)
    assert store.node(1, 3, 600) == log.mth(6, 8)
    assert store.node(3, 7, 600) == log.mth(56, 64)
    assert store.node(5, 2, 600) == log.mth(64, 96)


def test_subtree_hash_covers_incomplete_right_edge():
    n = 17
    store, _, log = _store(n)
    for k in range(0, 6):
        for idx in range(0, ((n - 1) >> k) + 1):
            lo, hi = idx << k, min((idx + 1) << k, n)
            assert store.subtree_hash(k, idx, n) == log.mth(lo, hi), (k, idx)


def test_node_refuses_incomplete_or_out_of_range():
    store, _, _ = _store(17)
    for k, idx in [(1, 8), (2, 4), (0, 17), (5, 0)]:
        with pytest.raises(TlogError) as e:
            store.node(k, idx, 17)
        assert e.value.code == "NODE_NOT_COMPLETE"
    with pytest.raises(TlogError) as e:
        store.subtree_hash(0, 17, 17)
    assert e.value.code == "NODE_OUT_OF_RANGE"


# --------------------------------------------------------------------------- #
# 5. Failure modes: tamper, bad input, fetch errors -- all fail closed       #
# --------------------------------------------------------------------------- #
def _flip_first_byte_of(position: int):
    def f(raw: bytes) -> bytes:
        b = bytearray(raw)
        b[position * 32] ^= 0x01
        return bytes(b)

    return f


def test_tampered_tile_fails_inclusion():
    n, i = 11, 3  # leaf 2 is the level-0 sibling of leaf 3
    store, _, log = _store(n, tamper={(0, 0, 11): _flip_first_byte_of(2)})
    with pytest.raises(TlogError) as e:
        verify_inclusion(log.leaves[i], i, Checkpoint(size=n, root=log.root), store)
    assert e.value.code == "INCLUSION_FAILED"


def test_wrong_leaf_and_wrong_root_fail_inclusion():
    store, _, log = _store(11)
    with pytest.raises(TlogError) as e:
        verify_inclusion(log.leaves[4], 3, Checkpoint(size=11, root=log.root), store)
    assert e.value.code == "INCLUSION_FAILED"
    with pytest.raises(TlogError) as e:
        verify_inclusion(log.leaves[3], 3, Checkpoint(size=11, root=bytes(32)), store)
    assert e.value.code == "INCLUSION_FAILED"


@pytest.mark.parametrize("size,index", [(11, 11), (11, -1), (0, 0), (1, 1)])
def test_index_out_of_range(size, index):
    log = ref_log(max(size, 1))
    with pytest.raises(TlogError) as e:
        verify_inclusion(log.leaves[0], index, Checkpoint(size=size, root=log.root), TileStore(BASE))
    assert e.value.code == "INDEX_OUT_OF_RANGE"


def test_malformed_inputs():
    store, _, log = _store(5)
    with pytest.raises(TlogError) as e:
        verify_inclusion(b"short", 0, Checkpoint(size=5, root=log.root), store)
    assert e.value.code == "MALFORMED_INPUT"
    with pytest.raises(TlogError) as e:
        verify_inclusion(log.leaves[0], 0, Checkpoint(size=5, root=b"short"), store)
    assert e.value.code == "MALFORMED_INPUT"


class _Boom:
    def __init__(self, exc: Exception):
        self.exc = exc

    def get(self, url, timeout=None):
        raise self.exc


@pytest.mark.parametrize("exc", [ConnectionError("down"), KeyError("x"), RuntimeError("boom")])
def test_fetch_errors_become_tlog_errors(exc):
    log = ref_log(11)
    store = TileStore(BASE, session=_Boom(exc))
    with pytest.raises(TlogError) as e:
        verify_inclusion(log.leaves[3], 3, Checkpoint(size=11, root=log.root), store)
    assert e.value.code == "TILE_FETCH_FAILED"


def test_no_session_is_an_error_not_a_pass():
    log = ref_log(11)
    with pytest.raises(TlogError) as e:
        verify_inclusion(log.leaves[3], 3, Checkpoint(size=11, root=log.root), TileStore(BASE))
    assert e.value.code == "NO_SESSION"


def test_malformed_tile_length_rejected():
    store, _, log = _store(11, tamper={(0, 0, 11): lambda raw: raw[:-1]})
    with pytest.raises(TlogError) as e:
        verify_inclusion(log.leaves[3], 3, Checkpoint(size=11, root=log.root), store)
    assert e.value.code == "TILE_MALFORMED"


def test_unexpected_exception_in_a_store_fails_closed():
    class Weird:
        def subtree_hash(self, *a):
            raise KeyError("surprise")

    log = ref_log(11)
    with pytest.raises(TlogError) as e:
        verify_inclusion(log.leaves[3], 3, Checkpoint(size=11, root=log.root), Weird())
    assert e.value.code == "INCLUSION_UNVERIFIABLE"


# --------------------------------------------------------------------------- #
# 6. Cache behaviour                                                         #
# --------------------------------------------------------------------------- #
def test_cache_is_used_and_caller_supplied_empty_dict_is_kept():
    log = ref_log(600)
    shared: dict = {}
    sess = FakeSession(log)
    store = TileStore(BASE, session=sess, cache=shared)
    cp = Checkpoint(size=600, root=log.root)
    verify_inclusion(log.leaves[599], 599, cp, store)
    assert shared and store.cache is shared  # `cache or {}` used to discard the empty dict
    before = len(sess.requested)
    verify_inclusion(log.leaves[599], 599, cp, store)
    assert len(sess.requested) == before  # immutable tiles: second pass is served from cache
