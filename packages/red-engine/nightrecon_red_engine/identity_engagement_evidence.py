"""Bridge identity evidence into the portable engagement evidence schema.

This module is deliberately pure and network-free. It converts already-observed
identity facts into the same EvidenceRecord vocabulary consumed by the unified
attack graph and shared engagement workspace.
"""

from __future__ import annotations

from hashlib import sha256

from nightrecon_red_engine.graph_identity_evidence import IdentityEvidenceBundle
from nightrecon_shared_core.contracts import EvidenceRecord


def _properties(values: tuple[tuple[str, str], ...]) -> dict[str, str]:
    keys = [key for key, _ in values]
    if len(keys) != len(set(keys)):
        raise ValueError("identity evidence properties must have unique keys")
    return dict(values)


def _evidence_id(
    *,
    engagement_id: str,
    evidence_type: str,
    natural_key: str,
    observed_at: str,
    provenance: str,
) -> str:
    material = (
        f"{engagement_id}:{evidence_type}:{natural_key}:"
        f"{observed_at}:{provenance}"
    )
    return "red-identity-" + sha256(material.encode("utf-8")).hexdigest()


def identity_bundle_to_engagement_records(
    bundle: IdentityEvidenceBundle,
    *,
    engagement_id: str,
    observed_at: str,
) -> tuple[EvidenceRecord, ...]:
    """Convert observed identity facts into graph-compatible engagement records."""

    records: list[EvidenceRecord] = []

    for item in bundle.identities:
        data: dict[str, object] = {
            "identity_key": item.natural_key,
            "label": item.label,
        }
        if item.identity_type:
            data["identity_type"] = item.identity_type
        if item.properties:
            data["properties"] = _properties(item.properties)
        records.append(EvidenceRecord(
            engagement_id=engagement_id,
            evidence_id=_evidence_id(
                engagement_id=engagement_id,
                evidence_type="identity.observation",
                natural_key=item.natural_key,
                observed_at=observed_at,
                provenance=item.source_id,
            ),
            source_night="red",
            evidence_type="identity.observation",
            observed_at=observed_at,
            provenance=item.source_id,
            data=data,
            limitations=(
                "Read-only observed identity evidence.",
                "No privilege or exploitability verdict.",
            ),
        ))

    for item in bundle.groups:
        data = {
            "group_key": item.natural_key,
            "label": item.label,
        }
        if item.properties:
            data["properties"] = _properties(item.properties)
        records.append(EvidenceRecord(
            engagement_id=engagement_id,
            evidence_id=_evidence_id(
                engagement_id=engagement_id,
                evidence_type="group.observation",
                natural_key=item.natural_key,
                observed_at=observed_at,
                provenance=item.source_id,
            ),
            source_night="red",
            evidence_type="group.observation",
            observed_at=observed_at,
            provenance=item.source_id,
            data=data,
            limitations=(
                "Read-only observed directory group evidence.",
                "No privilege or exploitability verdict.",
            ),
        ))

    for item in bundle.memberships:
        natural_key = (
            f"{item.member_kind.value}:{item.member_key}"
            f"->member-of->{item.group_key}"
        )
        records.append(EvidenceRecord(
            engagement_id=engagement_id,
            evidence_id=_evidence_id(
                engagement_id=engagement_id,
                evidence_type="graph.relationship",
                natural_key=natural_key,
                observed_at=observed_at,
                provenance=item.source_id,
            ),
            source_night="red",
            evidence_type="graph.relationship",
            observed_at=observed_at,
            provenance=item.source_id,
            data={
                "source_kind": item.member_kind.value,
                "source_key": item.member_key,
                "target_kind": "group",
                "target_key": item.group_key,
                "relationship": "member-of",
                "evidence_state": item.evidence_state.value,
            },
            limitations=(
                "Observed directory membership only.",
                "Membership does not independently prove privilege or compromise.",
            ),
        ))

    for item in bundle.permissions:
        natural_key = (
            f"{item.subject_kind.value}:{item.subject_key}"
            f"->permission:{item.natural_key}->"
            f"{item.target_kind.value}:{item.target_key}"
        )
        data = {
            "source_kind": item.subject_kind.value,
            "source_key": item.subject_key,
            "target_kind": item.target_kind.value,
            "target_key": item.target_key,
            "relationship": "permission",
            "evidence_state": item.evidence_state.value,
            "permission_key": item.natural_key,
            "label": item.label,
        }
        if item.properties:
            data["properties"] = _properties(item.properties)
        records.append(EvidenceRecord(
            engagement_id=engagement_id,
            evidence_id=_evidence_id(
                engagement_id=engagement_id,
                evidence_type="graph.relationship",
                natural_key=natural_key,
                observed_at=observed_at,
                provenance=item.source_id,
            ),
            source_night="red",
            evidence_type="graph.relationship",
            observed_at=observed_at,
            provenance=item.source_id,
            data=data,
            limitations=(
                "Observed permission relationship only.",
                "Permission does not independently prove exploitability.",
            ),
        ))

    return tuple(sorted(records, key=lambda item: item.evidence_id))
