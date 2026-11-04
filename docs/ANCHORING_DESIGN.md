# ARTIFACT Anchoring Design (TSA + Rekor v2 + Monitor)

Source: design text integrated 2026-11-03.

## Core decision

Three anchors, three jobs — do not conflate them.

| Anchor | Property | Latency | Mode | Fails closed by |
|--------|----------|---------|------|-----------------|
| Hash chain (local ledger) | Integrity, ordering, tamper-evidence | Zero | Prevention | Refusing the write |
| RFC 3161 TSA | When a signature existed | 10–500 ms | Prevention | Refusing the write |
| Transparency log (Rekor v2) | Non-equivocation, public commitment | 1–30 s, eventual | Detection | COMPLETE_UNANCHORED + freeze |

- **Pre-write**: chain + dual-TSA. Synchronous, fail-closed.
- **Post-write**: tlog + monitor. Asynchronous, fail-alarming. Freeze is the control.

A transparency log without a monitor is a receipt nobody reads.

## Package layout

```
anchoring/
  tsa/policy.py      # TsaEntry, TsaPolicy, quorum_verdict, revocation_status
  tlog/
    config.py        # TlogConfig, Checkpoint
    tiles.py         # TileStore (C2SP tlog-tiles)
    inclusion.py     # verify_inclusion, verify_consistency
  monitor/loop.py    # MonitorState, TlogMonitor, Alarm
  ceremony.py        # ordered gate → write → post-anchor ceremony
```

## Ceremony order (must not reorder)

1. [pre]   chain verified; harness not FROZEN; TSA registry fresh
2. [gate]  approver signs decision (two-factor)
3. [gate]  TSA primary + witness → quorum_verdict == CONFIRMED   ← BLOCKING
4. [gate]  revocation_status != after / indeterminate
5. [write] checkpoint → execute → post-hash (rollback on failure)
6. [post]  assemble run_anchor.json; sign with orchestrator key
7. [post]  submit hashedrekord v2 → persist TLE
8. [post]  verify inclusion against latest witnessed checkpoint (non-blocking)
9. [post]  COMPLETE | AWAITING_INCLUSION | COMPLETE_UNANCHORED
10. [bg]   monitor: consistency + identity + temporal sandwich

## Must-pass tests (see tests/test_tsa_quorum.py + expand)

1. Dual-TSA disagreement beyond tolerance → DISAGREEMENT, halt
2. INSUFFICIENT quorum → halt, no single-TSA fallback
3. Backdated token after TSA compromise → rejected by temporal sandwich
4. Revocation inside accuracy interval → indeterminate → reject
5. Consistency failure → EQUIVOCATION_SUSPECTED, P0, durable freeze
6. Same size / different root → same P0
7. Tampered tile → INCLUSION_FAILED
8. Unknown kind/apiVersion → graceful failure
9. Unexpected identity entry → P0 + freeze
10. Stale checkpoint → P2, no state advance
11. Witness quorum lost → P1 + freeze
12. Dead log URL → write succeeds, terminal COMPLETE_UNANCHORED, alarm fires

## Caveats (do not ignore)

- Resolve Rekor shard URL via signing config / TUF; do not hardcode log2025-1.
- Witness keys come from witness operators, not the signer’s config.
- Temporal sandwich runs at audit time (needs C_before and C_after).
- accuracy is a TSA claim; policy cap limits damage, does not eliminate trust.
- Monitor coverage is per-shard; keep scanning frozen shards for identity anomalies.
- Unfreeze is an approver-signed ledger entry (same ceremony as a gate decision).
