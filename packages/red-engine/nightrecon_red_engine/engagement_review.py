"""Secret-safe engagement evidence review for Red Night operators."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nightrecon_shared_core.contracts import EngagementEnvelope, EvidenceRecord


@dataclass(frozen=True)
class EvidenceReviewItem:
    evidence_id: str
    source_night: str
    evidence_type: str
    observed_at: str
    provenance: str
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "source_night": self.source_night,
            "evidence_type": self.evidence_type,
            "observed_at": self.observed_at,
            "provenance": self.provenance,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class EngagementEvidenceReview:
    engagement_id: str
    total_records: int
    source_night_counts: tuple[tuple[str, int], ...]
    evidence_type_counts: tuple[tuple[str, int], ...]
    records_with_limitations: int
    limitations: tuple[tuple[str, int], ...]
    items: tuple[EvidenceReviewItem, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "engagement_id": self.engagement_id,
            "total_records": self.total_records,
            "source_night_counts": [
                {"source_night": key, "count": count}
                for key, count in self.source_night_counts
            ],
            "evidence_type_counts": [
                {"evidence_type": key, "count": count}
                for key, count in self.evidence_type_counts
            ],
            "records_with_limitations": self.records_with_limitations,
            "limitations": [
                {"limitation": text, "count": count}
                for text, count in self.limitations
            ],
            "items": [item.to_dict() for item in self.items],
        }


def _matches(
    record: EvidenceRecord,
    *,
    source_night: str | None,
    evidence_type: str | None,
) -> bool:
    return (
        (source_night is None or record.source_night == source_night)
        and (evidence_type is None or record.evidence_type == evidence_type)
    )


def build_engagement_evidence_review(
    envelope: EngagementEnvelope,
    *,
    source_night: str | None = None,
    evidence_type: str | None = None,
    max_items: int = 500,
) -> EngagementEvidenceReview:
    """Build a bounded review index without exposing raw evidence payload data."""

    if max_items < 1 or max_items > 5000:
        raise ValueError("max_items must be between 1 and 5000")

    selected = tuple(
        record for record in envelope.records
        if _matches(
            record,
            source_night=source_night,
            evidence_type=evidence_type,
        )
    )
    ordered = tuple(sorted(
        selected,
        key=lambda item: (item.observed_at, item.evidence_id),
    ))
    source_counts = Counter(item.source_night for item in selected)
    type_counts = Counter(item.evidence_type for item in selected)
    limitation_counts = Counter(
        limitation
        for item in selected
        for limitation in item.limitations
    )

    items = tuple(
        EvidenceReviewItem(
            evidence_id=item.evidence_id,
            source_night=item.source_night,
            evidence_type=item.evidence_type,
            observed_at=item.observed_at,
            provenance=item.provenance,
            limitations=item.limitations,
        )
        for item in ordered[:max_items]
    )

    return EngagementEvidenceReview(
        engagement_id=envelope.engagement_id,
        total_records=len(selected),
        source_night_counts=tuple(sorted(source_counts.items())),
        evidence_type_counts=tuple(sorted(type_counts.items())),
        records_with_limitations=sum(bool(item.limitations) for item in selected),
        limitations=tuple(sorted(
            limitation_counts.items(),
            key=lambda item: (-item[1], item[0]),
        )),
        items=items,
    )
