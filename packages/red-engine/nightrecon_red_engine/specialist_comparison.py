"""Reproducible fixture-based comparison metrics for v0.42 exposure intelligence.

The harness measures Red Night against an explicit expected fixture. It is not
an external specialist-product result and must not be used to claim parity.
"""

from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter

from nightrecon_red_engine.attack_path_atlas import (
    AttackPathAtlasLimits,
    build_cross_domain_attack_path_atlas,
)
from nightrecon_red_engine.graph_models import GraphNodeKind, IdentityGraph


COMPARISON_INTERPRETATION = (
    "Fixture comparison only. These measurements do not establish parity with "
    "Nmap, Burp, BloodHound, Metasploit, Caldera, Cobalt Strike, or another "
    "specialist product. Live authorized comparison evidence remains separate."
)


@dataclass(frozen=True, order=True)
class ExpectedPathSignature:
    start_key: str
    target_key: str
    relationships: tuple[str, ...]


@dataclass(frozen=True, order=True)
class ExpectedEdgeSignature:
    source_key: str
    target_key: str
    relationship: str
    evidence_state: str


@dataclass(frozen=True)
class SpecialistComparisonExpectation:
    paths: tuple[ExpectedPathSignature, ...]
    edges: tuple[ExpectedEdgeSignature, ...]
    operator_steps: int

    def __post_init__(self) -> None:
        if self.operator_steps < 0:
            raise ValueError("operator_steps must not be negative")
        if len(self.paths) != len(set(self.paths)):
            raise ValueError("expected paths must be unique")
        if len(self.edges) != len(set(self.edges)):
            raise ValueError("expected edges must be unique")


@dataclass(frozen=True)
class SpecialistComparisonResult:
    expected_paths: int
    matched_paths: int
    missed_paths: int
    invented_paths: int
    expected_edges: int
    matched_edges: int
    missed_edges: int
    invented_edges: int
    evidence_complete_paths: int
    evidence_incomplete_paths: int
    operator_steps: int
    duration_ms: float
    atlas_truncated: bool
    interpretation: str = COMPARISON_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "expected_paths": self.expected_paths,
            "matched_paths": self.matched_paths,
            "missed_paths": self.missed_paths,
            "invented_paths": self.invented_paths,
            "expected_edges": self.expected_edges,
            "matched_edges": self.matched_edges,
            "missed_edges": self.missed_edges,
            "invented_edges": self.invented_edges,
            "evidence_complete_paths": self.evidence_complete_paths,
            "evidence_incomplete_paths": self.evidence_incomplete_paths,
            "operator_steps": self.operator_steps,
            "duration_ms": self.duration_ms,
            "atlas_truncated": self.atlas_truncated,
            "interpretation": self.interpretation,
        }


def run_specialist_fixture_comparison(
    graph: IdentityGraph,
    expectation: SpecialistComparisonExpectation,
    *,
    start_kinds: tuple[GraphNodeKind, ...] = (
        GraphNodeKind.IDENTITY,
        GraphNodeKind.GROUP,
        GraphNodeKind.ASSET,
        GraphNodeKind.SERVICE,
    ),
    atlas_limits: AttackPathAtlasLimits | None = None,
) -> SpecialistComparisonResult:
    started = perf_counter()
    atlas = build_cross_domain_attack_path_atlas(
        graph,
        start_kinds=start_kinds,
        limits=atlas_limits,
    )
    duration_ms = (perf_counter() - started) * 1000.0

    nodes = {item.node_id: item for item in graph.nodes}
    actual_paths = {
        ExpectedPathSignature(
            nodes[path.start_node_id].natural_key,
            nodes[path.target_node_id].natural_key,
            path.relationships,
        )
        for path in atlas.paths
    }
    expected_paths = set(expectation.paths)

    actual_edges = {
        ExpectedEdgeSignature(
            nodes[edge.source_node_id].natural_key,
            nodes[edge.target_node_id].natural_key,
            edge.relationship,
            edge.evidence_state.value,
        )
        for edge in graph.edges
    }
    expected_edges = set(expectation.edges)

    evidence_complete = sum(
        bool(path.provenance_sources)
        and all(item.source_id for item in path.provenance_sources)
        for path in atlas.paths
    )

    return SpecialistComparisonResult(
        expected_paths=len(expected_paths),
        matched_paths=len(actual_paths & expected_paths),
        missed_paths=len(expected_paths - actual_paths),
        invented_paths=len(actual_paths - expected_paths),
        expected_edges=len(expected_edges),
        matched_edges=len(actual_edges & expected_edges),
        missed_edges=len(expected_edges - actual_edges),
        invented_edges=len(actual_edges - expected_edges),
        evidence_complete_paths=evidence_complete,
        evidence_incomplete_paths=len(atlas.paths) - evidence_complete,
        operator_steps=expectation.operator_steps,
        duration_ms=duration_ms,
        atlas_truncated=atlas.truncated,
    )
