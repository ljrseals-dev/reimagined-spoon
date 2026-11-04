# TSA adapter (Phase 1)

## Architecture

Shell-out to **OpenSSL** (`ts -query`, `ts -reply`, `ts -verify`, `ts -text`, `x509 -text`, `verify -attime`).

No `asn1crypto` / pure-Python ASN.1 path. The subprocess boundary is intentional:

- Token format drift surfaces as `TOKEN_PARSE_DRIFT` when required `-text` fields disappear.
- Every `subprocess.run` has an explicit `timeout=` (default 15s). A hung `openssl` is `TSA_UNAVAILABLE`, not a hung gate.

## Pinned OpenSSL

**OpenSSL 3.0.13** (the version in the London Fog CI / reference sandbox).

If `-text` field labels change in a future OpenSSL, `parse_ts_text` raises `TOKEN_PARSE_DRIFT` rather than mis-parsing. The parameterized drift tests lock the four required labels:

- `Nonce:`
- `Policy OID:`
- `Serial number:`
- `Time stamp:`

## Modes

`Anchor.mode` is required and has **no default**:

- `CTT` — signature-bound (covers `approver_signature`) — required for the pre-write gate
- `TTC` — content/time binding for other artifacts — rejected by the CTT gate helper

## Checks (ten)

`imprint_bytes`, `imprint_algorithm`, `nonce_matches`, `policy_oid`, `gen_time_not_future`, `accuracy_bounds`, `eku_timestamping_only`, `chain_valid_at_gentime`, `root_fingerprint`, `token_parse`.

Unexpected exceptions inside a check become `FAIL` with the exception text — never a bare `except Exception: pass`.
