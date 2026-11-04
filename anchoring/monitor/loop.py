"""Tlog monitor: consistency + identity alarms, durable freeze."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from ..tlog.config import Checkpoint, TlogConfig
from ..tlog.inclusion import verify_consistency
from ..tlog.tiles import TileStore, TlogError


@dataclass
class Alarm:
    severity: str  # P0 | P1 | P2
    code: str
    detail: str = ""
    freeze: bool = False
    entry: Any = None


@dataclass
class MonitorState:
    origin: str
    accepted_size: int
    accepted_root: bytes
    last_accepted_at: str
    skew_warnings_in_window: int = 0
    seen_entry_hashes: set[str] = field(default_factory=set)
    frozen: bool = False


class IdentityMatcher(Protocol):
    key_id: str

    def matches(self, entry: Any) -> bool: ...
    def is_expected(self, entry: Any) -> bool: ...


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class TlogMonitor:
    def __init__(
        self,
        cfg: TlogConfig,
        state: MonitorState,
        identity: IdentityMatcher,
        store: TileStore,
    ):
        self.cfg = cfg
        self.state = state
        self.identity = identity
        self.store = store

    def _fetch_checkpoint(self) -> str:
        # Production: GET {base_url}/checkpoint
        raise NotImplementedError("wire to live Rekor v2 /checkpoint")

    def _scan_new(self, cp: Checkpoint):
        # Production: walk tiles from accepted_size .. cp.size
        return []

    def tick(self) -> list[Alarm]:
        alarms: list[Alarm] = []
        try:
            # note = self._fetch_checkpoint()
            # cp = verify_checkpoint(note, self.cfg)  # §2.3 steps 1–6
            raise NotImplementedError("checkpoint fetch + verify")
        except TlogError as e:
            return [Alarm("P0", "CHECKPOINT_UNVERIFIABLE", str(e), freeze=True)]
        except NotImplementedError:
            # stub path for sandbox
            return [Alarm("P2", "MONITOR_STUB", "live checkpoint path not wired")]

        # The real tick continues:
        # 1. verify_consistency → EQUIVOCATION_SUSPECTED (P0, freeze)
        # 2. staleness check
        # 3. identity scan → UNEXPECTED_IDENTITY_ENTRY (P0, freeze)
        # 4. only then advance accepted_size / root
        return alarms

    def set_freeze(self, reason: str) -> None:
        self.state.frozen = True
        # durable flag checked by orchestrator _preflight

    def clear_freeze(self, approver_signed_ledger_entry: dict) -> None:
        """Clearance is itself an approver-signed ledger entry (same ceremony as gate)."""
        if not approver_signed_ledger_entry.get("signature"):
            raise ValueError("unfreeze requires signed clearance")
        self.state.frozen = False
