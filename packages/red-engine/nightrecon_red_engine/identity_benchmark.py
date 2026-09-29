"""Deterministic evidence-quality benchmarks for read-only identity collection.

The benchmark compares opaque normalized natural keys and relationship topology.
It never needs raw directory labels or DNs. Runtime is reported separately and
is deliberately excluded from the deterministic benchmark fingerprint.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json

from nightrecon_red_engine.graph_builder import IdentityGraphBuilder
from nightrecon_red_engine.graph_identity_evidence import IdentityEvidenceBundle
from nightrecon_red_engine.graph_identity_projection import (
    add_identity_evidence_to_identity_graph,
)
from nightrecon_red_engine.graph_snapshot import (
    create_identity_graph_snapshot_manifest,
)
from nightrecon_red_engine.identity_collection import IdentityCollectionResult


def _unique(values: tuple[str, ...], field: str) -> tuple[str, ...]:
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ValueError(f"{field} must contain nonblank strings")
    if len(values) != len(set(values)):
        raise ValueError(f"{field} must not contain duplicates")
    return tuple(sorted(values))


def _identity_keys(bundle: IdentityEvidenceBundle) -> tuple[str, ...]:
    return _unique(
        tuple(item.natural_key for item in bundle.identities),
        "identity keys",
    )


def _group_keys(bundle: IdentityEvidenceBundle) -> tuple[str, ...]:
    return _unique(
        tuple(item.natural_key for item in bundle.groups),
        "group keys",
    )


def _membership_keys(
    bundle: IdentityEvidenceBundle,
) -> tuple[tuple[str, str, str], ...]:
    values = tuple(
        sorted(
            (
                item.member_kind.value,
                item.member_key,
                item.group_key,
            )
            for item in bundle.memberships
        )
    )
    if len(values) != len(set(values)):
        raise ValueError("membership evidence must not contain duplicates")
    return values


def _role_keys(bundle: IdentityEvidenceBundle) -> tuple[str, ...]:
    return _unique(
        tuple(item.natural_key for item in bundle.roles),
        "role keys",
    )


def _relationship_keys(
    bundle: IdentityEvidenceBundle,
) -> tuple[tuple[object, ...], ...]:
    values = tuple(sorted(
        (
            item.source_kind.value,
            item.source_key,
            item.relationship,
            item.target_kind.value,
            item.target_key,
            item.evidence_state.value,
            tuple(sorted(item.properties)),
        )
        for item in bundle.relationships
    ))
    if len(values) != len(set(values)):
        raise ValueError("identity relationship evidence must not contain duplicates")
    return values


def _missed_reasons(
    *,
    missed_count: int,
    unresolved_members: int,
    limitations: tuple[str, ...],
) -> tuple[str, ...]:
    reasons = list(limitations)
    if unresolved_members:
        reasons.append(
            f"{unresolved_members} membership reference(s) were unresolved."
        )
    if missed_count and not reasons:
        reasons.append(
            "Expected evidence was absent without a provider-reported truncation reason."
        )
    return tuple(dict.fromkeys(reasons))


@dataclass(frozen=True)
class IdentityBenchmarkResult:
    """Label-free comparison of expected and observed identity evidence."""

    expected_identities: int
    discovered_expected_identities: int
    missed_identities: int
    invented_identities: int
    expected_groups: int
    discovered_expected_groups: int
    missed_groups: int
    invented_groups: int
    expected_memberships: int
    discovered_expected_memberships: int
    missed_memberships: int
    invented_memberships: int
    expected_roles: int
    discovered_expected_roles: int
    missed_roles: int
    invented_roles: int
    expected_relationships: int
    discovered_expected_relationships: int
    missed_relationships: int
    invented_relationships: int
    unresolved_members: int
    provider_requests: int
    provider_duration_ms: int
    truncated: bool
    expected_coverage_complete: bool
    unexpected_evidence_present: bool
    limitations: tuple[str, ...]
    missed_reasons: tuple[str, ...]
    graph_sha256: str
    benchmark_sha256: str

    def to_dict(self) -> dict[str, object]:
        return {
            "expected_identities": self.expected_identities,
            "discovered_expected_identities": self.discovered_expected_identities,
            "missed_identities": self.missed_identities,
            "invented_identities": self.invented_identities,
            "expected_groups": self.expected_groups,
            "discovered_expected_groups": self.discovered_expected_groups,
            "missed_groups": self.missed_groups,
            "invented_groups": self.invented_groups,
            "expected_memberships": self.expected_memberships,
            "discovered_expected_memberships": self.discovered_expected_memberships,
            "missed_memberships": self.missed_memberships,
            "invented_memberships": self.invented_memberships,
            "expected_roles": self.expected_roles,
            "discovered_expected_roles": self.discovered_expected_roles,
            "missed_roles": self.missed_roles,
            "invented_roles": self.invented_roles,
            "expected_relationships": self.expected_relationships,
            "discovered_expected_relationships": self.discovered_expected_relationships,
            "missed_relationships": self.missed_relationships,
            "invented_relationships": self.invented_relationships,
            "unresolved_members": self.unresolved_members,
            "provider_requests": self.provider_requests,
            "provider_duration_ms": self.provider_duration_ms,
            "truncated": self.truncated,
            "expected_coverage_complete": self.expected_coverage_complete,
            "unexpected_evidence_present": self.unexpected_evidence_present,
            "limitations": list(self.limitations),
            "missed_reasons": list(self.missed_reasons),
            "graph_sha256": self.graph_sha256,
            "benchmark_sha256": self.benchmark_sha256,
        }


def benchmark_identity_collection(
    result: IdentityCollectionResult,
    expected: IdentityEvidenceBundle,
) -> IdentityBenchmarkResult:
    """Compare collected evidence with one explicit benchmark expectation."""

    if not isinstance(result, IdentityCollectionResult):
        raise ValueError("result must be IdentityCollectionResult")
    if not isinstance(expected, IdentityEvidenceBundle):
        raise ValueError("expected must be IdentityEvidenceBundle")

    expected_identities = set(_identity_keys(expected))
    observed_identities = set(_identity_keys(result.evidence))
    expected_groups = set(_group_keys(expected))
    observed_groups = set(_group_keys(result.evidence))
    expected_memberships = set(_membership_keys(expected))
    observed_memberships = set(_membership_keys(result.evidence))
    expected_roles = set(_role_keys(expected))
    observed_roles = set(_role_keys(result.evidence))
    expected_relationships = set(_relationship_keys(expected))
    observed_relationships = set(_relationship_keys(result.evidence))

    found_identities = expected_identities & observed_identities
    found_groups = expected_groups & observed_groups
    found_memberships = expected_memberships & observed_memberships
    missed_identities = expected_identities - observed_identities
    missed_groups = expected_groups - observed_groups
    missed_memberships = expected_memberships - observed_memberships
    invented_identities = observed_identities - expected_identities
    invented_groups = observed_groups - expected_groups
    invented_memberships = observed_memberships - expected_memberships
    found_roles = expected_roles & observed_roles
    missed_roles = expected_roles - observed_roles
    invented_roles = observed_roles - expected_roles
    found_relationships = expected_relationships & observed_relationships
    missed_relationships = expected_relationships - observed_relationships
    invented_relationships = observed_relationships - expected_relationships

    graph = add_identity_evidence_to_identity_graph(
        IdentityGraphBuilder().build(),
        result.evidence,
    )
    graph_sha256 = create_identity_graph_snapshot_manifest(graph).graph_sha256

    total_missed = (
        len(missed_identities)
        + len(missed_groups)
        + len(missed_memberships)
        + len(missed_roles)
        + len(missed_relationships)
    )
    total_invented = (
        len(invented_identities)
        + len(invented_groups)
        + len(invented_memberships)
        + len(invented_roles)
        + len(invented_relationships)
    )
    reasons = _missed_reasons(
        missed_count=total_missed,
        unresolved_members=result.unresolved_members,
        limitations=result.limitations,
    )

    fingerprint_payload = {
        "expected": {
            "identities": sorted(expected_identities),
            "groups": sorted(expected_groups),
            "memberships": sorted(expected_memberships),
            "roles": sorted(expected_roles),
            "relationships": sorted(expected_relationships),
        },
        "observed": {
            "identities": sorted(observed_identities),
            "groups": sorted(observed_groups),
            "memberships": sorted(observed_memberships),
            "roles": sorted(observed_roles),
            "relationships": sorted(observed_relationships),
        },
        "unresolved_members": result.unresolved_members,
        "provider_requests": result.provider_requests,
        "truncated": result.truncated,
        "limitations": list(result.limitations),
        "graph_sha256": graph_sha256,
    }
    benchmark_sha256 = sha256(
        json.dumps(
            fingerprint_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()

    return IdentityBenchmarkResult(
        expected_identities=len(expected_identities),
        discovered_expected_identities=len(found_identities),
        missed_identities=len(missed_identities),
        invented_identities=len(invented_identities),
        expected_groups=len(expected_groups),
        discovered_expected_groups=len(found_groups),
        missed_groups=len(missed_groups),
        invented_groups=len(invented_groups),
        expected_memberships=len(expected_memberships),
        discovered_expected_memberships=len(found_memberships),
        missed_memberships=len(missed_memberships),
        invented_memberships=len(invented_memberships),
        expected_roles=len(expected_roles),
        discovered_expected_roles=len(found_roles),
        missed_roles=len(missed_roles),
        invented_roles=len(invented_roles),
        expected_relationships=len(expected_relationships),
        discovered_expected_relationships=len(found_relationships),
        missed_relationships=len(missed_relationships),
        invented_relationships=len(invented_relationships),
        unresolved_members=result.unresolved_members,
        provider_requests=result.provider_requests,
        provider_duration_ms=result.provider_duration_ms,
        truncated=result.truncated,
        expected_coverage_complete=total_missed == 0,
        unexpected_evidence_present=total_invented > 0,
        limitations=result.limitations,
        missed_reasons=reasons,
        graph_sha256=graph_sha256,
        benchmark_sha256=benchmark_sha256,
    )
