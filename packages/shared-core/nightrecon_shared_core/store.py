"""Backend-neutral engagement evidence storage interfaces."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

from nightrecon_shared_core.contracts import (
    EngagementEnvelope,
    EngagementMetadata,
    EvidenceRecord,
)


class EngagementStore(Protocol):
    def set_metadata(self, metadata: EngagementMetadata) -> None: ...
    def metadata(self, engagement_id: str) -> EngagementMetadata | None: ...
    def replace_metadata(self, metadata: EngagementMetadata) -> None: ...
    def append(self, record: EvidenceRecord) -> None: ...
    def append_envelope(self, envelope: EngagementEnvelope) -> None: ...
    def export_envelope(self, engagement_id: str) -> EngagementEnvelope: ...
    def records(
        self,
        engagement_id: str,
        *,
        source_night: str | None = None,
        evidence_type: str | None = None,
    ) -> tuple[EvidenceRecord, ...]: ...


@dataclass(frozen=True)
class EvidenceConflictError(ValueError):
    evidence_id: str

    def __str__(self) -> str:
        return f"conflicting evidence_id already exists: {self.evidence_id}"


@dataclass(frozen=True)
class MetadataConflictError(ValueError):
    engagement_id: str

    def __str__(self) -> str:
        return f"conflicting engagement metadata already exists: {self.engagement_id}"


class InMemoryEngagementStore:
    def __init__(self) -> None:
        self._records: dict[tuple[str, str], EvidenceRecord] = {}
        self._metadata: dict[str, EngagementMetadata] = {}

    def set_metadata(self, metadata: EngagementMetadata) -> None:
        existing = self._metadata.get(metadata.engagement_id)
        if existing is None:
            self._metadata[metadata.engagement_id] = metadata
            return
        if existing != metadata:
            raise MetadataConflictError(metadata.engagement_id)

    def metadata(self, engagement_id: str) -> EngagementMetadata | None:
        if not isinstance(engagement_id, str) or not engagement_id.strip():
            raise ValueError("engagement_id must be a nonblank string")
        return self._metadata.get(engagement_id)

    def replace_metadata(self, metadata: EngagementMetadata) -> None:
        if metadata.engagement_id not in self._metadata:
            raise ValueError(f"engagement metadata not found: {metadata.engagement_id}")
        self._metadata[metadata.engagement_id] = metadata

    def append(self, record: EvidenceRecord) -> None:
        key = (record.engagement_id, record.evidence_id)
        existing = self._records.get(key)
        if existing is None:
            self._records[key] = record
            return
        if existing != record:
            raise EvidenceConflictError(record.evidence_id)

    def append_envelope(self, envelope: EngagementEnvelope) -> None:
        if envelope.metadata is not None:
            existing_metadata = self._metadata.get(envelope.engagement_id)
            if existing_metadata is not None and existing_metadata != envelope.metadata:
                raise MetadataConflictError(envelope.engagement_id)
        for record in envelope.records:
            key = (record.engagement_id, record.evidence_id)
            existing = self._records.get(key)
            if existing is not None and existing != record:
                raise EvidenceConflictError(record.evidence_id)
        if envelope.metadata is not None:
            self._metadata[envelope.engagement_id] = envelope.metadata
        for record in envelope.records:
            self._records[(record.engagement_id, record.evidence_id)] = record

    def export_envelope(self, engagement_id: str) -> EngagementEnvelope:
        return EngagementEnvelope(
            engagement_id=engagement_id,
            metadata=self.metadata(engagement_id),
            records=self.records(engagement_id),
        )

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
        return tuple(sorted(
            set(self._metadata) | {engagement_id for engagement_id, _ in self._records}
        ))

    def extend(self, records: Iterable[EvidenceRecord]) -> None:
        for record in records:
            self.append(record)
