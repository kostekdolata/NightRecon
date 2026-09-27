"""Backend-neutral engagement evidence storage interfaces.

This layer deliberately defines storage semantics without selecting SQLite,
PostgreSQL, files, IPC, or a workspace service. Standalone Nights and composed
NightRecon installations can therefore share the same contract.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from nightrecon_shared_core.contracts import EngagementEnvelope, EvidenceRecord


class EngagementStore(Protocol):
    """Minimal append/read contract for shared NightRecon engagement evidence."""

    def append(self, record: EvidenceRecord) -> None:
        """Persist one immutable evidence record.

        Implementations must reject a conflicting duplicate evidence_id rather
        than silently overwrite existing evidence.
        """

    def append_envelope(self, envelope: EngagementEnvelope) -> None:
        """Persist every record in one already-validated engagement envelope."""

    def records(
        self,
        engagement_id: str,
        *,
        source_night: str | None = None,
        evidence_type: str | None = None,
    ) -> tuple[EvidenceRecord, ...]:
        """Return deterministic evidence for one engagement."""


@dataclass(frozen=True)
class EvidenceConflictError(ValueError):
    evidence_id: str

    def __str__(self) -> str:
        return f"conflicting evidence_id already exists: {self.evidence_id}"


class InMemoryEngagementStore:
    """Reference store used for tests and ephemeral standalone workflows."""

    def __init__(self) -> None:
        self._records: dict[tuple[str, str], EvidenceRecord] = {}

    def append(self, record: EvidenceRecord) -> None:
        key = (record.engagement_id, record.evidence_id)
        existing = self._records.get(key)
        if existing is None:
            self._records[key] = record
            return
        if existing != record:
            raise EvidenceConflictError(record.evidence_id)

    def append_envelope(self, envelope: EngagementEnvelope) -> None:
        # Validate all conflicts before mutating so envelope append is atomic.
        for record in envelope.records:
            key = (record.engagement_id, record.evidence_id)
            existing = self._records.get(key)
            if existing is not None and existing != record:
                raise EvidenceConflictError(record.evidence_id)
        for record in envelope.records:
            self._records[(record.engagement_id, record.evidence_id)] = record

    def records(
        self,
        engagement_id: str,
        *,
        source_night: str | None = None,
        evidence_type: str | None = None,
    ) -> tuple[EvidenceRecord, ...]:
        if not isinstance(engagement_id, str) or not engagement_id.strip():
            raise ValueError("engagement_id must be a nonblank string")
        matches = [
            record
            for (stored_engagement, _), record in self._records.items()
            if stored_engagement == engagement_id
            and (source_night is None or record.source_night == source_night)
            and (evidence_type is None or record.evidence_type == evidence_type)
        ]
        return tuple(sorted(matches, key=lambda item: item.evidence_id))

    def engagements(self) -> tuple[str, ...]:
        """Return known engagement IDs deterministically."""

        return tuple(sorted({engagement_id for engagement_id, _ in self._records}))

    def extend(self, records: Iterable[EvidenceRecord]) -> None:
        """Append records one by one; intended for adapters, not transactions."""

        for record in records:
            self.append(record)
