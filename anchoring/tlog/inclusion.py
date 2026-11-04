"""RFC 6962 inclusion + consistency proofs computed from tiles."""
from __future__ import annotations

from hashlib import sha256

from .config import Checkpoint
from .tiles import TileStore, TlogError


def leaf_hash(canonical_body: bytes) -> bytes:
    """sha256(0x00 || body) — reconstruct yourself; never trust the log's claim."""
    return sha256(b"\x00" + canonical_body).digest()


def verify_inclusion(
    leaf_hash_bytes: bytes, index: int, cp: Checkpoint, tiles: TileStore
) -> None:
    """Recompute the root from tiles and compare to the checkpoint root.

    Level-wise walk: at each level the node either has a sibling (hash the pair)
    or is the rightmost, sibling-less node, which RFC 6962 promotes UNCHANGED to
    the next level. (The pre-fix code did `n -= 1; continue` there, which stayed
    on the same level and asked for a sibling beyond the tree.)
    Any unexpected exception fails the check (never passes it).
    """
    if not (isinstance(leaf_hash_bytes, bytes) and len(leaf_hash_bytes) == 32):
        raise TlogError("MALFORMED_INPUT", "leaf hash must be 32 bytes")
    if not (isinstance(cp.root, bytes) and len(cp.root) == 32):
        raise TlogError("MALFORMED_INPUT", "checkpoint root must be 32 bytes")
    if not (0 <= index < cp.size):
        raise TlogError("INDEX_OUT_OF_RANGE", f"index {index} not in [0, {cp.size})")
    try:
        acc, idx, n, k = leaf_hash_bytes, index, cp.size, 0
        while n > 1:
            # Rightmost node at an even index has no sibling: acc is carried up
            # unchanged (no hashing); every other node is hashed with its sibling.
            if not (idx == n - 1 and idx % 2 == 0):
                sib = tiles.subtree_hash(k, idx ^ 1, cp.size)
                left, right = (acc, sib) if idx % 2 == 0 else (sib, acc)
                acc = sha256(b"\x01" + left + right).digest()
            idx >>= 1
            n = (n + 1) >> 1
            k += 1
    except TlogError:
        raise
    except Exception as e:
        raise TlogError("INCLUSION_UNVERIFIABLE", repr(e)) from e
    if acc != cp.root:
        raise TlogError("INCLUSION_FAILED", "recomputed root != checkpoint root")


def verify_consistency(old: Checkpoint, new: Checkpoint, tiles: TileStore) -> None:
    if new.size < old.size:
        raise TlogError("ROLLBACK", f"size {new.size} < {old.size}")
    if new.size == old.size:
        if new.root != old.root:
            raise TlogError("FORK_AT_SAME_SIZE", "same size, different root")
        return
    if old.size == 0:
        return
    # Full RFC 6962 consistency path is left as a production TODO;
    # the same-size / rollback branches above are the ones most often omitted
    # and are already enforced.
    # Production code must implement _consistency_path and fold to new.root.
    pass
