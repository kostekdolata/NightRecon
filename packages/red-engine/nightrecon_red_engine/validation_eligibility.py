"""Exact proposal-only candidate-to-technique eligibility planning.

Batch 2 matches reviewed technique metadata to exact nodes already present in a
validation candidate. It never selects a technique for the operator, calls an
adapter, consumes authorization state, resolves credentials, or mutates an
engagement.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import ipaddress

from nightrecon_red_engine.graph_models import (
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)
from nightrecon_red_engine.graph_validation import assert_valid_identity_graph
from nightrecon_red_engine.validation_candidates import (
    ValidationCandidate,
    ValidationCandidateCompilation,
)
from nightrecon_red_engine.validation_techniques import (
    BUILTIN_VALIDATION_TECHNIQUE_REGISTRY,
    ValidationTechniqueDefinition,
    ValidationTechniqueRegistry,
)


ELIGIBILITY_INTERPRETATION = (
    "Eligibility is a proposal-only compatibility result over existing graph "
    "evidence. It is not automatic technique selection and does not establish "
    "authorization, exploitability, likelihood, impact, compromise, or "
    "permission to execute."
)


@dataclass(frozen=True)
class ValidationEligibilityLimits:
    max_candidates: int = 256
    max_techniques: int = 128
    max_targets_per_candidate: int = 16
    max_options: int = 4_096
    max_rejections: int = 32_768

    def __post_init__(self) -> None:
        for field in (
            "max_candidates",
            "max_techniques",
            "max_targets_per_candidate",
            "max_options",
            "max_rejections",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 1:
                raise ValueError(f"{field} must be a positive integer")


@dataclass(frozen=True, order=True)
class EligibilityEvidenceSource:
    source_type: str
    source_id: str

    def to_dict(self) -> dict[str, str]:
        return {
            "source_type": self.source_type,
            "source_id": self.source_id,
        }


@dataclass(frozen=True)
class ValidationEligibilityOption:
    eligibility_id: str
    candidate_id: str
    path_id: str
    technique_id: str
    target_node_id: str
    target_kind: str
    path_evidence_ids: tuple[str, ...]
    target_provenance: tuple[EligibilityEvidenceSource, ...]
    expected_evidence_keys: tuple[str, ...]
    impact: str
    requires_approval: bool
    adapter_kind: str
    cleanup_mode: str
    execution_mode: str = "proposal-only"
    interpretation: str = ELIGIBILITY_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "eligibility_id": self.eligibility_id,
            "candidate_id": self.candidate_id,
            "path_id": self.path_id,
            "technique_id": self.technique_id,
            "target_node_id": self.target_node_id,
            "target_kind": self.target_kind,
            "path_evidence_ids": list(self.path_evidence_ids),
            "target_provenance": [
                item.to_dict() for item in self.target_provenance
            ],
            "expected_evidence_keys": list(self.expected_evidence_keys),
            "impact": self.impact,
            "requires_approval": self.requires_approval,
            "adapter_kind": self.adapter_kind,
            "cleanup_mode": self.cleanup_mode,
            "execution_mode": self.execution_mode,
            "interpretation": self.interpretation,
        }


@dataclass(frozen=True)
class ValidationEligibilityRejection:
    candidate_id: str
    technique_id: str
    reason: str
    compatible_target_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "technique_id": self.technique_id,
            "reason": self.reason,
            "compatible_target_count": self.compatible_target_count,
        }


@dataclass(frozen=True)
class ValidationEligibilityPlan:
    options: tuple[ValidationEligibilityOption, ...]
    rejections: tuple[ValidationEligibilityRejection, ...]
    candidate_count: int
    technique_count: int
    interpretation: str = ELIGIBILITY_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "options": [item.to_dict() for item in self.options],
            "rejections": [item.to_dict() for item in self.rejections],
            "candidate_count": self.candidate_count,
            "technique_count": self.technique_count,
            "interpretation": self.interpretation,
        }


def _properties(node: GraphNode) -> dict[str, str]:
    return dict(node.properties)


def _canonical_ip(value: str) -> bool:
    try:
        return str(ipaddress.ip_address(value)) == value
    except ValueError:
        return False


def _canonical_port(value: str) -> bool:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= parsed <= 65_535 and str(parsed) == value


def _canonical_host(value: str) -> bool:
    if not value or value != value.strip():
        return False
    try:
        return str(ipaddress.ip_address(value)) == value
    except ValueError:
        normalized = value.casefold().rstrip(".")
        return (
            normalized == value
            and not any(character.isspace() for character in value)
        )


def classify_validation_target(node: GraphNode) -> str | None:
    if node.kind is GraphNodeKind.ASSET:
        return "asset"

    if node.kind is not GraphNodeKind.SERVICE:
        return None

    properties = _properties(node)
    surface_type = properties.get("surface_type", "")
    if surface_type:
        if surface_type not in {"web", "api"}:
            return None
        if not _canonical_host(properties.get("origin_host", "")):
            return None
        if not _canonical_port(properties.get("origin_port", "")):
            return None
        if properties.get("origin_scheme") not in {"http", "https"}:
            return None
        return surface_type

    if properties.get("protocol") != "tcp":
        return None
    if not _canonical_ip(properties.get("address", "")):
        return None
    if not _canonical_port(properties.get("port", "")):
        return None
    return "service"


def _candidate_id(
    path_id: str,
    edge_ids: tuple[str, ...],
    evidence_ids: tuple[str, ...],
) -> str:
    material = "\x1f".join((path_id, *edge_ids, *evidence_ids))
    return "validation-candidate-" + sha256(material.encode("utf-8")).hexdigest()


def _path_id(edge_ids: tuple[str, ...]) -> str:
    return "atlas-" + sha256("\x1f".join(edge_ids).encode("utf-8")).hexdigest()


def _edge_evidence_ids(
    edge_ids: tuple[str, ...],
    edges: dict[str, object],
) -> tuple[str, ...]:
    return tuple(sorted({
        item.source_id
        for edge_id in edge_ids
        for item in edges[edge_id].provenance
        if item.source_type == "engagement-evidence"
    }))


def _candidate_nodes(
    graph: IdentityGraph,
    candidate: ValidationCandidate,
) -> tuple[GraphNode, ...]:
    if candidate.execution_mode != "proposal-only":
        raise ValueError("validation candidate execution mode is not proposal-only")
    if candidate.required_capability != "validation.run":
        raise ValueError("validation candidate capability is not validation.run")
    if not candidate.approval_required or not candidate.scope_review_required:
        raise ValueError("validation candidate review gates must remain enabled")
    if not candidate.edge_ids or len(candidate.node_ids) != len(candidate.edge_ids) + 1:
        raise ValueError("validation candidate path shape is invalid")

    nodes = {item.node_id: item for item in graph.nodes}
    edges = {item.edge_id: item for item in graph.edges}

    selected_nodes: list[GraphNode] = []
    selected_edges = []
    for node_id in candidate.node_ids:
        node = nodes.get(node_id)
        if node is None:
            raise ValueError("validation candidate references a missing graph node")
        selected_nodes.append(node)

    for index, edge_id in enumerate(candidate.edge_ids):
        edge = edges.get(edge_id)
        if edge is None:
            raise ValueError("validation candidate references a missing graph edge")
        if (
            edge.source_node_id != candidate.node_ids[index]
            or edge.target_node_id != candidate.node_ids[index + 1]
        ):
            raise ValueError(
                "validation candidate path sequence does not match graph"
            )
        selected_edges.append(edge)

    expected_path_id = _path_id(candidate.edge_ids)
    if candidate.path_id != expected_path_id:
        raise ValueError("validation candidate path identifier is stale or invalid")

    expected_evidence_ids = _edge_evidence_ids(candidate.edge_ids, edges)
    if candidate.evidence_ids != expected_evidence_ids:
        raise ValueError("validation candidate evidence identifiers are stale")

    expected_candidate_id = _candidate_id(
        candidate.path_id,
        candidate.edge_ids,
        candidate.evidence_ids,
    )
    if candidate.candidate_id != expected_candidate_id:
        raise ValueError("validation candidate identifier is stale or invalid")

    observed = sum(
        edge.evidence_state is GraphEvidenceState.OBSERVED
        for edge in selected_edges
    )
    inferred = sum(
        edge.evidence_state is GraphEvidenceState.INFERRED
        for edge in selected_edges
    )
    if (
        candidate.observed_hops != observed
        or candidate.inferred_hops != inferred
    ):
        raise ValueError("validation candidate hop evidence is stale")

    return tuple(selected_nodes)


def _requirements_satisfied(
    technique: ValidationTechniqueDefinition,
    node: GraphNode,
) -> bool:
    properties = _properties(node)
    for key in technique.eligibility_required_properties:
        if not properties.get(key):
            return False
    for key, value in technique.eligibility_required_values:
        if properties.get(key) != value:
            return False
    return True


def _provenance(
    node: GraphNode,
) -> tuple[EligibilityEvidenceSource, ...]:
    return tuple(
        EligibilityEvidenceSource(item.source_type, item.source_id)
        for item in node.provenance
    )


def validation_eligibility_id(
    candidate_id: str,
    technique_id: str,
    target_node_id: str,
) -> str:
    material = "\x1f".join(
        (candidate_id, technique_id, target_node_id)
    ).encode("utf-8")
    return "validation-eligibility-" + sha256(material).hexdigest()


def plan_validation_eligibility(
    graph: IdentityGraph,
    compilation: ValidationCandidateCompilation,
    *,
    registry: ValidationTechniqueRegistry = (
        BUILTIN_VALIDATION_TECHNIQUE_REGISTRY
    ),
    limits: ValidationEligibilityLimits | None = None,
) -> ValidationEligibilityPlan:
    """Return every exact reviewed option; never choose one automatically."""

    assert_valid_identity_graph(graph)
    active = limits or ValidationEligibilityLimits()
    candidates = tuple(sorted(
        compilation.candidates,
        key=lambda item: item.candidate_id,
    ))
    techniques = registry.list()

    if len(candidates) > active.max_candidates:
        raise ValueError("validation eligibility candidate ceiling exceeded")
    if len(techniques) > active.max_techniques:
        raise ValueError("validation eligibility technique ceiling exceeded")

    options: list[ValidationEligibilityOption] = []
    rejections: list[ValidationEligibilityRejection] = []

    for candidate in candidates:
        path_nodes = _candidate_nodes(graph, candidate)
        classified = tuple(
            (node, kind)
            for node in path_nodes
            if (kind := classify_validation_target(node)) is not None
        )
        if len(classified) > active.max_targets_per_candidate:
            raise ValueError("validation eligibility target ceiling exceeded")

        for technique in techniques:
            compatible = tuple(
                (node, kind)
                for node, kind in classified
                if kind in technique.target_kinds
            )
            eligible = tuple(
                (node, kind)
                for node, kind in compatible
                if _requirements_satisfied(technique, node)
            )

            if not eligible:
                rejections.append(ValidationEligibilityRejection(
                    candidate_id=candidate.candidate_id,
                    technique_id=technique.technique_id,
                    reason=(
                        "no-exact-target-kind"
                        if not compatible
                        else "target-evidence-prerequisites-not-satisfied"
                    ),
                    compatible_target_count=len(compatible),
                ))
                if len(rejections) > active.max_rejections:
                    raise ValueError(
                        "validation eligibility rejection ceiling exceeded"
                    )
                continue

            for node, kind in eligible:
                options.append(ValidationEligibilityOption(
                    eligibility_id=validation_eligibility_id(
                        candidate.candidate_id,
                        technique.technique_id,
                        node.node_id,
                    ),
                    candidate_id=candidate.candidate_id,
                    path_id=candidate.path_id,
                    technique_id=technique.technique_id,
                    target_node_id=node.node_id,
                    target_kind=kind,
                    path_evidence_ids=candidate.evidence_ids,
                    target_provenance=_provenance(node),
                    expected_evidence_keys=technique.evidence_keys,
                    impact=technique.impact,
                    requires_approval=technique.requires_approval,
                    adapter_kind=technique.adapter_kind,
                    cleanup_mode=technique.cleanup_mode,
                ))
                if len(options) > active.max_options:
                    raise ValueError(
                        "validation eligibility option ceiling exceeded"
                    )

    return ValidationEligibilityPlan(
        options=tuple(sorted(
            options,
            key=lambda item: (
                item.candidate_id,
                item.technique_id,
                item.target_node_id,
            ),
        )),
        rejections=tuple(sorted(
            rejections,
            key=lambda item: (
                item.candidate_id,
                item.technique_id,
                item.reason,
            ),
        )),
        candidate_count=len(candidates),
        technique_count=len(techniques),
    )
