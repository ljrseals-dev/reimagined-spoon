`audit/ledger.jsonl` is created at first run by `anchoring.ledger.init_ledger(path, signer)`, which writes a signed
GENESIS entry (seq 0, parent `0`*64). No ledger or private key is committed to this repository.
