"""Rekor v2 / C2SP tlog configuration and checkpoint primitives."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class TlogConfig:
    base_url: str  # e.g. https://log2025-1.rekor.sigstore.dev
    origin: str  # checkpoint key name == log origin
    log_public_key_pem: str
    witness_keys: dict[str, bytes]  # name -> ed25519 pubkey (from WITNESS operators)
    witnesses_required: int = 2
    max_checkpoint_age_s: int = 3600


@dataclass(frozen=True)
class Checkpoint:
    """Witnessed log head.

    first_observed_at is the monitor's own clock when quorum was first seen —
    self-reported, labeled as such (see docs/INVARIANTS.md). Not a
    cryptographically attested wall-clock from the witness note.
    Optional only for pure inclusion/consistency tests that do not exercise the sandwich;
    production monitor paths must set it.
    """
    size: int
    root: bytes  # 32-byte root hash
    first_observed_at: datetime | None = None
    origin: str = ""
    note: str = ""  # raw signed note for audit


@runtime_checkable
class CheckpointSource(Protocol):
    def checkpoints_before(self, entry_index: int) -> list[Checkpoint]:
        """Checkpoints with size <= entry_index (heads that predate the entry)."""
        ...

    def checkpoints_after(self, entry_index: int) -> list[Checkpoint]:
        """Checkpoints with size > entry_index (heads that postdate the entry)."""
        ...


@dataclass(frozen=True)
class FixtureCheckpointSource:
    """Phase 3: hardcoded list so sandwich logic is testable before Phase 4."""
    checkpoints: list[Checkpoint]

    def checkpoints_before(self, entry_index: int) -> list[Checkpoint]:
        return [c for c in self.checkpoints if c.size <= entry_index]

    def checkpoints_after(self, entry_index: int) -> list[Checkpoint]:
        return [c for c in self.checkpoints if c.size > entry_index]
