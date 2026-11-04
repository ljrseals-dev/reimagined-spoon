## Badge cross-reference

Invariant status lives in the **Enforced vs stubbed** table in `README.md`. This file tracks deferred fixtures and trust-boundary notes; do not duplicate badge rows here without updating README.

# London Fog — tracked invariants & deferred fixtures

## Phase 1 signed limits

### attime: WIRED (flag presence + boundary verified; expired-at-genTime fixture deferred)

- `openssl verify -attime <genTime>` is invoked on the chain path.
- Negative regression: `test_attime_after_not_after_fails` passes `-attime` after leaf `notAfter` and expects failure. If the flag is dropped, openssl uses *now* (cert still valid) and the test fails.

### Expired-at-genTime fixture — **deferred, Phase 3 prerequisite**

Construction (when building the fixture):

1. Self-signed root (long-lived).
2. Short-window TSA leaf cert with `notBefore` / `notAfter` spanning a past window (requires controlled clock or `faketime` at issue time).
3. Local `openssl ts -reply` producing a token whose `genTime` lies **inside** that leaf window.
4. At verification *now*, leaf is expired; with `-attime=genTime` verification must still pass.

Until this fixture exists, do not claim “TSA clock is untrusted under cert expiry” beyond the boundary negative test.

### Request-path dead-URL test — **deferred to Phase 8**

- Phase 1 requirement satisfied: `anchor_imprint` maps `URLError`, `HTTPError`, `socket.timeout`, `TimeoutError`, `ConnectionError`, `OSError` → `TsaError("TSA_UNAVAILABLE", …)`.
- Integration test against a dead URL lives with the live client (Phase 8).

## Non-negotiables (recap)

1. No weight write without falsifiable HypothesisArtifact.
2. No weight write without dual-TSA quorum; CTT gate covers `approver_signature`.
3. `Anchor.mode` required (`CTT` | `TTC`); no default.
4. Pre-write fail-closed; post-write fail-alarming.
5. Every `subprocess.run` on openssl has `timeout=`.
6. No bare `except Exception: pass` in adapters.

## Phase 3 sandwich / first_observed_at

Witness notes do **not** carry timestamps. A C2SP signed note is
`<origin>\n<size>\n<base64 root>\n\n— <key> <sig>`; the witness signature covers
the checkpoint body, not wall-clock time. There is no `cosigned_at` to extract.

Phase 3 therefore uses:

```python
@dataclass(frozen=True)
class Checkpoint:
    size: int
    root: bytes
    first_observed_at: datetime  # monitor clock when quorum was first seen
```

Sandwich:

- `T_before = max(cp.first_observed_at for cp in checkpoints_before(entry_index))`
- `T_after  = min(cp.first_observed_at for cp in checkpoints_after(entry_index))`
- TSA `gen_time` interval must lie inside `[T_before − slack, T_after + slack]`

```
sandwich: WIRED_VIA_FIXTURE (self-reported first-observation time)
```

Phase 4 upgrades the source to the real monitor; the time remains self-reported.
Cryptographically attested observation time (cross-anchor each quorum checkpoint
to a second TSA) is Phase 7+.
