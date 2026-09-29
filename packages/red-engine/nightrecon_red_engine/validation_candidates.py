"""Bounded proposal-only validation candidates from attack-path evidence.

This module never executes validation, consumes authorization state, resolves
credentials, or mutates an engagement. It compiles deterministic review
candidates that must later pass the normal authorization and approval boundary.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from nightrecon_red_engine.attack_path_atlas import AttackPathAtlas
from nightrecon_red_engine.graph_models import IdentityGraph
from nightrecon_red_engine.graph_validation import assert_valid_identity_graph


CANDIDATE_INTERPRETATION = (
    "Proposal-only validation candidate. Candidate presence does not establish "
    "exploitability, authorization, likelihood, impact, compromise, or permission "
    "to execute. Any later validation must independently pass engagement scope, "
    "capability, approval, budget, and revocation checks."
)


@dataclass(frozen=True)
class ValidationCandidateLimits:
    max_candidates: int = 256
    max_nodes_per_candidate: int = 16
    max_edges_per_candidate: int = 15
    max_evidence_ids_per_candidate: int = 128

    def __post_init__(self) -> None:
        for field in (
            "max_candidates",
            "max_nodes_per_candidate",
            "max_edges_per_candidate",
            "max_evidence_ids_per_candidate",
        ):
            value = getattr(self, field)
            if type(value) is not int or value < 1:
                raise ValueError(f"{field} must be a positive integer")


@dataclass(frozen=True)
class ValidationCandidate:
    candidate_id: str
    path_id: str
    start_node_id: str
    target_node_id: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    observed_hops: int
    inferred_hops: int
    required_capability: str = "validation.run"
    approval_required: bool = True
    scope_review_required: bool = True
    execution_mode: str = "proposal-only"
    interpretation: str = CANDIDATE_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "candidate_id": self.candidate_id,
            "path_id": self.path_id,
            "start_node_id": self.start_node_id,
            "target_node_id": self.target_node_id,
            "node_ids": list(self.node_ids),
            "edge_ids": list(self.edge_ids),
            "evidence_ids": list(self.evidence_ids),
            "observed_hops": self.observed_hops,
            "inferred_hops": self.inferred_hops,
            "required_capability": self.required_capability,
            "approval_required": self.approval_required,
            "scope_review_required": self.scope_review_required,
            "execution_mode": self.execution_mode,
            "interpretation": self.interpretation,
        }


@dataclass(frozen=True)
class ValidationCandidateCompilation:
    candidates: tuple[ValidationCandidate, ...]
    source_path_count: int
    truncated: bool
    truncation_reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "candidates": [item.to_dict() for item in self.candidates],
            "source_path_count": self.source_path_count,
            "truncated": self.truncated,
            "truncation_reasons": list(self.truncation_reasons),
        }


def _candidate_id(
    path_id: str,
    edge_ids: tuple[str, ...],
    evidence_ids: tuple[str, ...],
) -> str:
    material = "\x1f".join((path_id, *edge_ids, *evidence_ids))
    return "validation-candidate-" + sha256(material.encode("utf-8")).hexdigest()


def compile_validation_candidates(
    graph: IdentityGraph,
    atlas: AttackPathAtlas,
    *,
    limits: ValidationCandidateLimits | None = None,
) -> ValidationCandidateCompilation:
    """Compile deterministic path review proposals without executing anything."""

    assert_valid_identity_graph(graph)
    active = limits or ValidationCandidateLimits()
    nodes = {item.node_id: item for item in graph.nodes}
    edges = {item.edge_id: item for item in graph.edges}

    source_paths = tuple(sorted(atlas.paths, key=lambda item: item.path_id))
    truncation_reasons: list[str] = []
    selected = source_paths
    if len(selected) > active.max_candidates:
        selected = selected[:active.max_candidates]
        truncation_reasons.append("validation candidate ceiling reached")

    candidates: list[ValidationCandidate] = []
    for path in selected:
        if not path.edge_ids or len(path.node_ids) != len(path.edge_ids) + 1:
            raise ValueError("attack-path atlas contains an invalid path shape")
        if (
            path.start_node_id != path.node_ids[0]
            or path.target_node_id != path.node_ids[-1]
        ):
            raise ValueError("attack-path atlas endpoints do not match path nodes")
        if len(path.node_ids) > active.max_nodes_per_candidate:
            raise ValueError("validation candidate exceeds node ceiling")
        if len(path.edge_ids) > active.max_edges_per_candidate:
            raise ValueError("validation candidate exceeds edge ceiling")
        if len(path.evidence_ids) > active.max_evidence_ids_per_candidate:
            raise ValueError("validation candidate exceeds evidence ceiling")

        for node_id in path.node_ids:
            if node_id not in nodes:
                raise ValueError(
                    "validation candidate references a missing graph node"
                )
        for index, edge_id in enumerate(path.edge_ids):
            edge = edges.get(edge_id)
            if edge is None:
                raise ValueError(
                    "validation candidate references a missing graph edge"
                )
            if (
                edge.source_node_id != path.node_ids[index]
                or edge.target_node_id != path.node_ids[index + 1]
            ):
                raise ValueError(
                    "validation candidate path sequence does not match graph"
                )

        candidates.append(ValidationCandidate(
            candidate_id=_candidate_id(
                path.path_id,
                path.edge_ids,
                path.evidence_ids,
            ),
            path_id=path.path_id,
            start_node_id=path.start_node_id,
            target_node_id=path.target_node_id,
            node_ids=path.node_ids,
            edge_ids=path.edge_ids,
            evidence_ids=path.evidence_ids,
            observed_hops=path.observed_hops,
            inferred_hops=path.inferred_hops,
        ))

    return ValidationCandidateCompilation(
        candidates=tuple(candidates),
        source_path_count=len(source_paths),
        truncated=bool(truncation_reasons),
        truncation_reasons=tuple(truncation_reasons),
    )
