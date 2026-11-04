"""Read-only quality labels for external observations.

A quality label is not validation, scope authorization, or exploitability proof.
No data is written and no execution capability is exposed by this module.
"""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_shared_core.contracts import EvidenceRecord


@dataclass(frozen=True)
class ImportedEvidenceQuality:
    evidence_id: str
    engagement_id: str
    verification: str
    provenance: str
    source_count: int
    limitations: tuple[str, ...]
    requires_independent_validation: bool = True


def assess_imported_evidence(
    records: tuple[EvidenceRecord, ...],
) -> tuple[ImportedEvidenceQuality, ...]:
    """Classify only explicit third-party imports; reject unsupported assertions.

    Multiple import sources are *not* independent corroboration. No supplied
    'verified' claim may upgrade imported evidence to confirmed.
    """
    assessments = []
    seen = set()
    for record in records:
        if (
            record.source_night != "red"
            or record.evidence_type != "external-network-observation"
            or record.provenance != "third-party-import"
        ):
            raise ValueError("Unsupported evidence type or provenance")
        if record.evidence_id in seen or not record.evidence_id:
            raise ValueError("Duplicate or missing evidence identifier")
        seen.add(record.evidence_id)
        data = record.data
        if not isinstance(data, dict) or data.get("verification") != "unverified":
            raise ValueError("Imported evidence must remain unverified")
        sources = data.get("import_sources")
        if (
            not isinstance(sources, list)
            or not sources
            or any(not isinstance(s, str) or not s.strip() for s in sources)
        ):
            raise ValueError("Imported evidence requires explicit source references")
        limitations = tuple(record.limitations)
        if not limitations or any(not isinstance(s, str) or not s.strip() for s in limitations):
            raise ValueError("Imported evidence must retain its limitations")
        assessments.append(
            ImportedEvidenceQuality(
                evidence_id=record.evidence_id,
                engagement_id=record.engagement_id,
                verification="unverified",
                provenance="third-party-import",
                source_count=len(set(sources)),
                limitations=limitations,
            )
        )
    return tuple(sorted(assessments, key=lambda item: item.evidence_id))
