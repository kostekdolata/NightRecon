"""Attach existing NightRecon assessment findings to service graph nodes."""

from __future__ import annotations

from nightrecon_red_engine.assessment_engine import ServiceAssessmentResult
from nightrecon_red_engine.graph_builder import GraphBuildLimits, IdentityGraphBuilder
from nightrecon_red_engine.graph_models import (
    GraphEdge,
    GraphEvidenceState,
    GraphNode,
    GraphNodeKind,
    GraphProvenance,
    IdentityGraph,
)


def add_assessment_findings_to_identity_graph(
    graph: IdentityGraph,
    assessments: tuple[ServiceAssessmentResult, ...],
    *,
    observed_at: str = "",
    limits: GraphBuildLimits | None = None,
) -> IdentityGraph:
    """Add completed assessment findings without changing assessment execution."""

    builder = IdentityGraphBuilder(limits)
    service_nodes_by_key: dict[str, GraphNode] = {}

    for node in graph.nodes:
        builder.add_node(node)
        if node.kind is GraphNodeKind.SERVICE:
            service_nodes_by_key[node.natural_key] = node

    for edge in graph.edges:
        builder.add_edge(edge)

    for service_result in assessments:
        service_key = f"{service_result.address}:{service_result.port}/tcp"
        service_node = service_nodes_by_key.get(service_key)
        if service_node is None:
            raise ValueError(
                f"assessment result service is missing from graph: {service_key}"
            )

        for execution in service_result.executions:
            if execution.status != "completed":
                continue

            for index, finding in enumerate(execution.findings):
                provenance = (
                    GraphProvenance(
                        source_type="assessment",
                        source_id=(
                            f"{execution.check_id}:"
                            f"{service_result.address}:"
                            f"{service_result.port}:"
                            f"{index}"
                        ),
                        observed_at=observed_at.strip(),
                    ),
                )

                properties: list[tuple[str, str]] = [
                    ("check_id", finding.check_id),
                    ("summary", finding.summary),
                ]
                if finding.severity:
                    properties.append(("severity", finding.severity))
                if finding.remediation:
                    properties.append(("remediation", finding.remediation))
                if finding.evidence:
                    properties.append(
                        ("evidence", " | ".join(finding.evidence))
                    )
                if execution.check_source:
                    properties.append(
                        ("check_source", execution.check_source)
                    )
                if execution.check_source_version:
                    properties.append(
                        (
                            "check_source_version",
                            execution.check_source_version,
                        )
                    )

                finding_node = GraphNode.create(
                    kind=GraphNodeKind.ASSESSMENT_FINDING,
                    natural_key=(
                        f"{service_key}:"
                        f"{execution.check_id}:"
                        f"{index}"
                    ),
                    label=finding.title,
                    provenance=provenance,
                    properties=tuple(properties),
                )
                builder.add_node(finding_node)
                builder.add_edge(
                    GraphEdge.create(
                        source_node_id=service_node.node_id,
                        target_node_id=finding_node.node_id,
                        relationship="has-assessment-finding",
                        evidence_state=GraphEvidenceState.OBSERVED,
                        provenance=provenance,
                    )
                )

    return builder.build()
