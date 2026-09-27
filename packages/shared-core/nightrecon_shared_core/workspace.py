"""Shared workspace coordination over backend-neutral engagement evidence stores.

The local implementation is intentionally simple and network-free. It derives
workspace views from the canonical engagement store instead of maintaining a
second index. File-backed workspaces support serialized local writers; a future
multi-process service/database backend must provide its own concurrency control.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from nightrecon_shared_core.contracts import EngagementEnvelope
from nightrecon_shared_core.file_store import FileEngagementStore


@dataclass(frozen=True)
class WorkspaceSummary:
    engagement_id: str
    name: str | None
    status: str | None
    source_nights: tuple[str, ...]
    record_count: int
    evidence_types: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceBreakdown:
    source_night_counts: tuple[tuple[str, int], ...]
    evidence_type_counts: tuple[tuple[str, int], ...]


@dataclass(frozen=True)
class MergeReport:
    engagement_id: str
    applied: bool
    added_records: int
    identical_records: int
    evidence_conflicts: tuple[str, ...]
    metadata_conflict: bool
    source_nights: tuple[str, ...]


class WorkspaceStore(Protocol):
    def summaries(self) -> tuple[WorkspaceSummary, ...]: ...
    def summary(self, engagement_id: str) -> WorkspaceSummary: ...
    def evidence_breakdown(self, engagement_id: str) -> EvidenceBreakdown: ...
    def envelope(self, engagement_id: str) -> EngagementEnvelope: ...
    def merge_envelope(self, envelope: EngagementEnvelope) -> MergeReport: ...


class LocalWorkspace:
    """Local workspace root shared by independently installed Night apps."""

    STORE_FILENAME = "engagements.json"

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        if self.root.exists() and not self.root.is_dir():
            raise ValueError("workspace root must be a directory")
        self.store = FileEngagementStore(self.root / self.STORE_FILENAME)

    def _exists(self, engagement_id: str) -> bool:
        return engagement_id in self.store.engagements()

    def envelope(self, engagement_id: str) -> EngagementEnvelope:
        if not self._exists(engagement_id):
            raise ValueError(f"engagement not found: {engagement_id}")
        return self.store.export_envelope(engagement_id)

    def summary(self, engagement_id: str) -> WorkspaceSummary:
        envelope = self.envelope(engagement_id)
        metadata = envelope.metadata
        return WorkspaceSummary(
            engagement_id=engagement_id,
            name=None if metadata is None else metadata.name,
            status=None if metadata is None else metadata.status,
            source_nights=tuple(sorted({r.source_night for r in envelope.records})),
            record_count=len(envelope.records),
            evidence_types=tuple(sorted({r.evidence_type for r in envelope.records})),
        )

    def summaries(self) -> tuple[WorkspaceSummary, ...]:
        return tuple(self.summary(item) for item in self.store.engagements())

    def evidence_breakdown(self, engagement_id: str) -> EvidenceBreakdown:
        self.envelope(engagement_id)
        records = self.store.records(engagement_id)
        by_night = Counter(record.source_night for record in records)
        by_type = Counter(record.evidence_type for record in records)
        return EvidenceBreakdown(
            source_night_counts=tuple(sorted(by_night.items())),
            evidence_type_counts=tuple(sorted(by_type.items())),
        )

    def merge_envelope(self, envelope: EngagementEnvelope) -> MergeReport:
        current = (
            self.store.export_envelope(envelope.engagement_id)
            if self._exists(envelope.engagement_id)
            else EngagementEnvelope(engagement_id=envelope.engagement_id, records=())
        )
        metadata_conflict = (
            current.metadata is not None
            and envelope.metadata is not None
            and current.metadata != envelope.metadata
        )
        existing = {record.evidence_id: record for record in current.records}
        conflicts: list[str] = []
        identical = 0
        added = 0
        for record in envelope.records:
            previous = existing.get(record.evidence_id)
            if previous is None:
                added += 1
            elif previous == record:
                identical += 1
            else:
                conflicts.append(record.evidence_id)

        if metadata_conflict or conflicts:
            source_nights = tuple(sorted({
                record.source_night
                for record in current.records + envelope.records
            }))
            return MergeReport(
                engagement_id=envelope.engagement_id,
                applied=False,
                added_records=0,
                identical_records=identical,
                evidence_conflicts=tuple(sorted(conflicts)),
                metadata_conflict=metadata_conflict,
                source_nights=source_nights,
            )

        self.store.append_envelope(envelope)
        merged = self.store.export_envelope(envelope.engagement_id)
        return MergeReport(
            engagement_id=envelope.engagement_id,
            applied=True,
            added_records=added,
            identical_records=identical,
            evidence_conflicts=(),
            metadata_conflict=False,
            source_nights=tuple(sorted({r.source_night for r in merged.records})),
        )

    def import_file(self, path: str | Path) -> MergeReport:
        envelope = EngagementEnvelope.from_json(
            Path(path).read_text(encoding="utf-8")
        )
        return self.merge_envelope(envelope)

    def export_file(self, engagement_id: str, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            self.envelope(engagement_id).to_json() + "\n",
            encoding="utf-8",
        )
