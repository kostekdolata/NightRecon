"""High-level coverage review for Red Night identity evidence."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from nightrecon_red_engine.identity_collection import IdentityCollectionResult


@dataclass(frozen=True)
class IdentityCoverageReview:
    """Describe collected identity evidence and explicit coverage limits."""

    level: str
    summary: str
    identities: int
    groups: int
    memberships: int
    roles: int
    permissions: int
    relationships: int
    relationship_types: tuple[tuple[str, int], ...]
    limitations: tuple[str, ...]
    open_acceptance_gates: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "level": self.level,
            "summary": self.summary,
            "identities": self.identities,
            "groups": self.groups,
            "memberships": self.memberships,
            "roles": self.roles,
            "permissions": self.permissions,
            "relationships": self.relationships,
            "relationship_types": [
                {"relationship": name, "count": count}
                for name, count in self.relationship_types
            ],
            "limitations": list(self.limitations),
            "open_acceptance_gates": list(self.open_acceptance_gates),
        }


def build_identity_coverage_review(
    result: IdentityCollectionResult,
) -> IdentityCoverageReview:
    """Summarize evidence completeness without inferring privilege or risk."""

    if not isinstance(result, IdentityCollectionResult):
        raise ValueError("result must be IdentityCollectionResult")

    evidence = result.evidence
    counts = Counter(
        item.relationship for item in evidence.relationships
    )
    relationship_types = tuple(sorted(counts.items()))

    open_gates: list[str] = []
    if not evidence.permissions:
        open_gates.append(
            "Broader read-only ACL/security-descriptor permission evidence "
            "has not been demonstrated in this collection."
        )
    open_gates.append(
        "Live authorized specialist-tool comparison remains an external "
        "acceptance gate."
    )

    if result.truncated or result.unresolved_members or result.limitations:
        level = "limited"
        summary = (
            "Identity evidence was collected, but provider-reported limits or "
            "unresolved references make the result incomplete."
        )
    elif evidence.identities or evidence.groups:
        level = "collected"
        summary = (
            "Identity evidence was collected without provider-reported "
            "truncation; external acceptance gates remain."
        )
    else:
        level = "empty"
        summary = "No identity or group evidence was collected."

    limitations = tuple(dict.fromkeys((
        *result.limitations,
        *(
            (f"{result.unresolved_members} membership reference(s) were unresolved.",)
            if result.unresolved_members
            else ()
        ),
    )))

    return IdentityCoverageReview(
        level=level,
        summary=summary,
        identities=len(evidence.identities),
        groups=len(evidence.groups),
        memberships=len(evidence.memberships),
        roles=len(evidence.roles),
        permissions=len(evidence.permissions),
        relationships=len(evidence.relationships),
        relationship_types=relationship_types,
        limitations=limitations,
        open_acceptance_gates=tuple(open_gates),
    )
