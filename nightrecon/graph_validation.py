"""Consistency validation for NightRecon identity graphs."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon.graph_models import GraphEvidenceState, GraphNodeKind, IdentityGraph


@dataclass(frozen=True)
class GraphValidationIssue:
    """One deterministic graph consistency issue."""

    code: str
    subject_id: str
    message: str


def validate_identity_graph(graph: IdentityGraph) -> tuple[GraphValidationIssue, ...]:
    """Return deterministic consistency issues without mutating the graph."""

    issues: list[GraphValidationIssue] = []
    nodes_by_id = {node.node_id: node for node in graph.nodes}

    if len(nodes_by_id) != len(graph.nodes):
        issues.append(
            GraphValidationIssue(
                code="duplicate-node-id",
                subject_id="graph",
                message="Graph contains duplicate node identifiers.",
            )
        )

    edge_ids: set[str] = set()

    for node in graph.nodes:
        if not node.provenance:
            issues.append(
                GraphValidationIssue(
                    code="missing-node-provenance",
                    subject_id=node.node_id,
                    message="Graph node has no provenance.",
                )
            )

    for edge in graph.edges:
        if edge.edge_id in edge_ids:
            issues.append(
                GraphValidationIssue(
                    code="duplicate-edge-id",
                    subject_id=edge.edge_id,
                    message="Graph contains duplicate edge identifiers.",
                )
            )
        edge_ids.add(edge.edge_id)

        source = nodes_by_id.get(edge.source_node_id)
        target = nodes_by_id.get(edge.target_node_id)

        if source is None:
            issues.append(
                GraphValidationIssue(
                    code="missing-edge-source",
                    subject_id=edge.edge_id,
                    message="Graph edge source node is missing.",
                )
            )
        if target is None:
            issues.append(
                GraphValidationIssue(
                    code="missing-edge-target",
                    subject_id=edge.edge_id,
                    message="Graph edge target node is missing.",
                )
            )
        if not edge.provenance:
            issues.append(
                GraphValidationIssue(
                    code="missing-edge-provenance",
                    subject_id=edge.edge_id,
                    message="Graph edge has no provenance.",
                )
            )

        if source is not None and target is not None:
            issues.extend(_validate_relationship(edge, source.kind, target.kind))

    return tuple(
        sorted(
            issues,
            key=lambda issue: (issue.code, issue.subject_id, issue.message),
        )
    )


def assert_valid_identity_graph(graph: IdentityGraph) -> None:
    """Raise when consistency validation finds one or more issues."""

    issues = validate_identity_graph(graph)
    if not issues:
        return

    details = "; ".join(
        f"{issue.code}:{issue.subject_id}"
        for issue in issues
    )
    raise ValueError(f"identity graph validation failed: {details}")


def _validate_relationship(edge, source_kind, target_kind):
    issues: list[GraphValidationIssue] = []

    allowed = {
        "exposes": (GraphNodeKind.ASSET, GraphNodeKind.SERVICE),
        "matched-vulnerability": (
            GraphNodeKind.SERVICE,
            GraphNodeKind.VULNERABILITY,
        ),
        "has-assessment-finding": (
            GraphNodeKind.SERVICE,
            GraphNodeKind.ASSESSMENT_FINDING,
        ),
    }
    expected = allowed.get(edge.relationship)

    if expected is not None and (source_kind, target_kind) != expected:
        issues.append(
            GraphValidationIssue(
                code="invalid-relationship-kinds",
                subject_id=edge.edge_id,
                message=(
                    f"{edge.relationship} requires "
                    f"{expected[0].value}->{expected[1].value}."
                ),
            )
        )

    if (
        edge.relationship in allowed
        and edge.evidence_state is not GraphEvidenceState.OBSERVED
    ):
        issues.append(
            GraphValidationIssue(
                code="invalid-evidence-state",
                subject_id=edge.edge_id,
                message=(
                    f"{edge.relationship} must remain observed evidence."
                ),
            )
        )

    return issues
