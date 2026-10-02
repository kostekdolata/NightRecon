"""Professional, secret-safe engagement reporting for Red Night."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nightrecon_shared_core.contracts import EngagementEnvelope
from nightrecon_red_engine.engagement_review import (
    EngagementEvidenceReview,
    build_engagement_evidence_review,
)
from nightrecon_red_engine.remediation_retest import RemediationFinding


@dataclass(frozen=True)
class EngagementProfessionalReport:
    engagement_id: str
    name: str | None
    status: str | None
    executive_summary: str
    evidence_summary: EngagementEvidenceReview
    remediation_status_counts: tuple[tuple[str, int], ...]
    open_remediation_items: tuple[dict[str, str], ...]
    limitations: tuple[str, ...]
    interpretation: str

    def to_dict(self) -> dict[str, object]:
        return {
            "engagement_id": self.engagement_id,
            "name": self.name,
            "status": self.status,
            "executive_summary": self.executive_summary,
            "evidence_summary": self.evidence_summary.to_dict(),
            "remediation_status_counts": [
                {"status": status, "count": count}
                for status, count in self.remediation_status_counts
            ],
            "open_remediation_items": list(self.open_remediation_items),
            "limitations": list(self.limitations),
            "interpretation": self.interpretation,
        }


def build_engagement_professional_report(
    envelope: EngagementEnvelope,
    *,
    remediation_findings: tuple[RemediationFinding, ...] = (),
) -> EngagementProfessionalReport:
    """Build a deterministic engagement report from secret-safe metadata."""

    metadata = envelope.metadata
    review = build_engagement_evidence_review(envelope)
    status_counts = Counter(
        finding.status.value
        for finding in remediation_findings
        if finding.engagement_id == envelope.engagement_id
    )
    relevant = tuple(
        finding for finding in remediation_findings
        if finding.engagement_id == envelope.engagement_id
    )

    open_items = tuple(
        {
            "finding_id": finding.finding_id,
            "title": finding.title,
            "status": finding.status.value,
            "remediation": finding.remediation,
        }
        for finding in sorted(relevant, key=lambda item: item.finding_id)
        if finding.status.value not in {"verified", "accepted"}
    )

    limitations = tuple(
        text for text, _ in review.limitations
    )
    source_count = len(review.source_night_counts)
    evidence_count = review.total_records
    if evidence_count:
        executive_summary = (
            f"Engagement evidence contains {evidence_count} record(s) from "
            f"{source_count} Night source(s), with "
            f"{review.records_with_limitations} record(s) carrying explicit "
            "limitations."
        )
    else:
        executive_summary = (
            "No engagement evidence records are available; assessment conclusions "
            "must be treated as incomplete."
        )

    return EngagementProfessionalReport(
        engagement_id=envelope.engagement_id,
        name=None if metadata is None else metadata.name,
        status=None if metadata is None else metadata.status,
        executive_summary=executive_summary,
        evidence_summary=review,
        remediation_status_counts=tuple(sorted(status_counts.items())),
        open_remediation_items=open_items,
        limitations=limitations,
        interpretation=(
            "This report summarizes recorded evidence and remediation state. "
            "It does not convert inferred relationships, vulnerability matches, "
            "or graph paths into exploitability, compromise, likelihood, impact, "
            "or risk verdicts. Raw evidence payload data is intentionally omitted."
        ),
    )
