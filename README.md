# London Fog 🌁

**Research Scaffold for Auditable, Sparse Neural Weight Edits**

> *The weights are a fog. We do not clear the fog. We place a beacon, time-stamp the placement, and prove that no one moved the beacon after the fact.*

London Fog is the research name for the governance harness previously sketched as *supreme-goggles / ARTIFACT*.  
It is a **scaffold**, not a product: a set of contracts, adapters, and failure modes for performing *defect-removal* weight edits that are:

- **Sparse** (≤ 0.1 % of parameters by default)
- **Falsifiable** (every edit begins with a mechanistic hypothesis that can be disproved)
- **Pre-authorized** by dual RFC-3161 timestamps (fail-closed)
- **Post-anchored** in a public transparency log (fail-alarming)
- **Fully reversible** to an atomic checkpoint

No knowledge is injected. No capability is added. Only a specified defect is removed, under signed, hash-chained oversight.

---


## Architecture decision (branch `london-fog-phases`)

**Choice: (a) Merge — complementary layers**

| Layer | Tree | Role |
|-------|------|------|
| **ARTIFACT** (pre–London-Fog scaffold) | On GitHub `main` today as `artifact/` | Weight-edit harness: probe, hypothesis, sparse edit, verify, checkpoint of tensors |
| **London Fog** (this branch content) | `anchoring/`, `tests/test_tlog_*`, `tests/test_tsa_*`, `tests/test_phase*` | Pre-write fail-closed gate (dual-TSA + CTT re-verify) and post-write detection (tlog + monitor) |

`anchoring/ceremony.py` does **not** write weights. It returns `weight_write=True` only after CTT + quorum + revocation gates pass. The orchestrator / ARTIFACT harness remains responsible for the actual tensor write and atomic model checkpoint.

**Integration (follow-up commit):** wire `artifact/harness.py` (or `scripts/run_artifact.py`) to call `run_ceremony(...)` before any weight write and to refuse the write when `CeremonyResult.weight_write` is false.

Until that wire-up lands, the badge marks ARTIFACT as **present on main, not yet integrated** with the gate.

## What this is for

Modern model-editing literature (ROME, MEMIT, weight-space programming, abliteration, etc.) has shown that small, structured changes to weights can change behaviour. The open problem is no longer “can we edit?” but:

> *How do we know the edit was authorised, happened when we claim, touched only what we intended, and can be rolled back without trusting the editor?*

London Fog is a research scaffold for that question. It separates three distinct jobs that are routinely conflated:

| Anchor | Property | Latency | Mode |
|--------|----------|---------|------|
| Local hash-chain | Integrity, ordering, tamper-evidence | 0 | Prevention — refuse the write |
| Dual RFC-3161 TSA | When a signature existed | 10–500 ms | Prevention — refuse the write |
| Rekor v2 + monitor | Non-equivocation, public commitment | 1–30 s (eventual) | Detection — `COMPLETE_UNANCHORED` + freeze |

Pre-write is synchronous and fail-closed.  
Post-write is asynchronous and fail-alarming.  
A transparency log without a monitor is a receipt nobody reads.

---

## The questions people actually ask

These are the questions that recur in papers, forums, alignment discussions, and engineering reviews. London Fog is organised around them.

### On the edit itself

1. Can you really change behaviour by touching only a fraction of a percent of the weights?
2. How do you know you removed a *defect* rather than suppressed a capability the model still “knows”?
3. Does the edit generalise to paraphrases, or only to the exact prompt you tested?
4. What happens to neighbouring facts and related capabilities?
5. Is the original knowledge overwritten or merely suppressed? (Recent work suggests suppression is common.)
6. How sparse is “sparse enough”? Why 0.1 %? Why not 0.01 % or 1 %?
7. Can sequential edits accumulate until the model collapses?
8. What is the difference between a rank-one update, a directional ablation, and a full fine-tune?
9. If an LLM can propose the weight change, who validates that the proposal is mechanistic rather than cargo-cult?
10. How do you prevent the editor from “fixing” by changing weights that only affect the evaluation set?

### On reversibility and safety

11. Is every edit reversible to a bit-exact prior state?
12. What is an atomic checkpoint in practice?
13. If the regression suite is green, does that mean nothing else broke?
14. What if the defect you removed was load-bearing for something you care about?
15. Can an edit alter the model’s ability to evaluate or modify itself (RSI surface)?
16. Who decides that a change is a “defect” rather than a value judgement?
17. What is the human-gate threshold and why is it 0.05 %?
18. What happens if the human never responds?
19. Can the same process be used to *add* capabilities? (Explicitly out of scope.)
20. How do you stop an authorised edit from being used as cover for a second, unauthorised change?

### On time and proof

21. How do you prove the edit was authorised *before* the weights were written?
22. Why isn’t a single timestamp authority enough?
23. What happens if one TSA is compromised and can backdate?
24. What is interval algebra and why do point timestamps lie?
25. What is a dual-TSA quorum and what does `DISAGREEMENT` force you to do?
26. Why is “close enough” (a few seconds of skew) logged as a warning rather than ignored?
27. What is the temporal sandwich and why does it survive TSA key compromise?
28. Why can’t inclusion in a public log be a synchronous precondition for the write?
29. What is the difference between “accepted by the log” and “provably in a witnessed checkpoint”?
30. Why does Rekor v2 force a separate TSA?

### On the transparency log and monitor

31. What exactly gets logged — every ledger entry or one run-anchor?
32. Why is the run-anchor signed by the orchestrator key?
33. How do you verify inclusion from tiles instead of a live per-entry API?
34. What is a consistency proof and why must you check same-size / different-root?
35. What is split-view and why do witnesses exist?
36. What does the monitor actually alarm on?
37. What is an unexpected identity entry and why is it P0?
38. Why must the freeze be a durable harness flag, not a Slack message?
39. Who is allowed to clear a freeze, and how is that clearance itself audited?
40. What happens if your monitor only watches the current year’s shard?

### On trust roots and operations

41. Where do TSA roots, log keys, and witness keys come from?
42. Why must witness keys *not* come from the same config file as the log URL?
43. How do you rotate a TSA without invalidating historical evidence?
44. What is the difference between certificate expiry and key compromise?
45. Why is `distrust_after` asymmetric?
46. How long do you keep archive timestamps?
47. What does `COMPLETE_UNANCHORED` mean in a compliance report?
48. Can the whole system be run offline after the fact for audit?
49. What is the cost of the hourly monitor job?
50. What tests must pass before you claim the scaffold is more than theatre?

(There are more. The design documents and test list are the rest of the questionnaire.)

---

## Repository layout

```
london-fog / supreme-goggles/
├── README.md
├── docs/
│   ├── ANCHORING_DESIGN.md
│   ├── INVARIANTS.md                # deferred fixtures, sandwich trust boundary
│   └── ORCHESTRATOR_PROMPT.md       # research orchestrator contract (if present)
├── config/examples/weight_edit_repair.yaml
├── scripts/
│   ├── run_artifact.py
│   └── reproduce_qwen.py
├── anchoring/
│   ├── tsa/                         # policy, token parser, adapter (RFC 3161)
│   ├── tlog/                        # tiles, inclusion, consistency (partial)
│   ├── ledger/                      # JCS hash-chain
│   ├── monitor/loop.py
│   └── ceremony.py
├── tests/                           # phase -1 … 3 suites
├── audit/
│   ├── README.md                    # no committed ledger; created at first run
│   └── legacy/                      # pre-chain placeholder (rejected by verify_chain)
└── checkpoints/ probes/ edits/ reports/
```

## Quick check

```bash
cd supreme-goggles   # or london-fog
PYTHONPATH=. python tests/test_tsa_quorum.py
PYTHONPATH=. python scripts/run_artifact.py \
  --config config/examples/weight_edit_repair.yaml --dry-run
```


## Enforced vs stubbed (badge)

| Invariant | Status | Evidence |
|-----------|--------|----------|
| `verify_inclusion` correct for all sizes 1–17 | **Enforced** | `tests/test_tlog_inclusion.py` (153 vectors) |
| `verify_inclusion` not vulnerable to sibling-promotion bug | **Enforced** | `test_legacy_fails_exactly_the_20_known_cases` |
| `TileStore.node` ancestor = `idx << r` | **Enforced** | `test_node_right_direction_regression` |
| C2SP tile URL layout (incl. `.p/W`) | **Enforced** | `test_tile_path_examples` |
| Ledger JCS (integer-only shim) | **Enforced (shim)** | `tests/test_ledger.py` |
| Ledger JCS (full `rfc8785`) | **Enforced when rfc8785 installed** | shim-vs-library tests SKIPPED when missing |
| Ledger locale independence | **Enforced** when ≥2 locales installable; else **SKIPPED** with reason | `test_entry_hash_is_locale_independent…` |
| RFC 3161 adapter: 10 checks | **Enforced** | `tests/test_tsa_adapter.py` |
| `attime` boundary (post-`notAfter`) | **Enforced** | `test_attime_after_not_after_fails` |
| `attime` boundary (pre-`notBefore`) | **Enforced** | `test_attime_before_not_before_fails` |
| `attime` expired-at-genTime fixture | **DEFERRED** | `docs/INVARIANTS.md` |
| CTT/TTC enforcement in gate | **Enforced** | `tests/test_phase2.py` |
| Pre-write CTT token re-verification | **Enforced** | `test_reeverifies_token_at_gate` |
| TSA distrust corroboration | **Enforced** | `tests/test_phase3.py` |
| Temporal sandwich | **WIRED_VIA_FIXTURE** | self-reported `first_observed_at` |
| `verify_consistency` (append / fork-extension path) | **NOT IMPLEMENTED** | `pass` after TODO in `inclusion.py` |
| Monitor tick (live checkpoint) | **STUBBED** | returns `MONITOR_STUB` |
| Atomic checkpoint + rollback of weights | **NOT IMPLEMENTED** | Phase 6+ |
| ARTIFACT scaffold (`artifact/` on main) | **COEXIST — not integrated** | Gate authorizes; ARTIFACT writes; wire-up pending |
| Config model endpoints | **Parameterized** | `config/examples/weight_edit_repair.yaml` |
| Ceremony terminal `COMPLETE` | **Not claimed without inclusion** | only `COMPLETE_UNANCHORED` / `AWAITING_INCLUSION` / `HALTED` |

Rows marked SKIPPED inherit an honest skip reason from pytest, not a silent pass.

## Core invariants (non-negotiable)

1. No weight write without a falsifiable HypothesisArtifact.
2. No weight write without dual-TSA quorum (`CONFIRMED` or logged `TOLERATED`).
3. Sparsity ≤ 0.1 %; human four-eyes above 0.05 %.
4. Every action is signed and hash-chained.
5. Pre-write fail-closed; post-write fail-alarming.
6. Never fall back to a single TSA “just this once.”
7. Never advance the monitor’s accepted head before consistency and identity checks pass.
8. Unfreeze requires an approver-signed ledger entry (same ceremony as a gate decision).
9. RSI surface: abort if the edit would alter the model’s ability to self-modify or self-evaluate.

## Status

Research scaffold. Live weight edits require:

- Target model weights
- Reasoning + code model API endpoints (parameterized in config; not product claims)
- Configured dual-TSA endpoints and root PEMs
- Rekor v2 shard resolved via TUF / signing-config (do not hard-code)
- Orchestrator Ed25519 key for run-anchor signatures

The fog does not clear. The beacon is timed, sparse, and reversible.

---

*London Fog — Research Scaffold*  
*Formerly tracked under the working name supreme-goggles / ARTIFACT*
