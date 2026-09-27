"""Compose NightRecon evidence into one deterministic identity graph."""

from __future__ import annotations

from nightrecon.assessment_engine import ServiceAssessmentResult
from nightrecon.asset_inventory import AssetInventory
from nightrecon.graph_assessment import add_assessment_findings_to_identity_graph
from nightrecon.graph_builder import GraphBuildLimits
from nightrecon.graph_models import IdentityGraph
from nightrecon.graph_projection import (
    add_vulnerability_evidence_to_identity_graph,
    build_identity_graph_from_asset_inventory,
)
from nightrecon.graph_threat_context import add_threat_context_to_identity_graph
from nightrecon.graph_validation import assert_valid_identity_graph
from nightrecon.threat_context import ThreatContextResult
from nightrecon.vulnerability_intelligence import ServiceVulnerabilityResult


def build_identity_graph(
    *,
    inventory: AssetInventory,
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...] = (),
    threat_context: tuple[ThreatContextResult, ...] = (),
    assessments: tuple[ServiceAssessmentResult, ...] = (),
    vulnerability_observed_at: str = "",
    threat_context_observed_at: str = "",
    assessment_observed_at: str = "",
    limits: GraphBuildLimits | None = None,
) -> IdentityGraph:
    """Build one graph snapshot from existing NightRecon evidence only."""

    graph = build_identity_graph_from_asset_inventory(
        inventory,
        limits=limits,
    )
    graph = add_vulnerability_evidence_to_identity_graph(
        graph,
        vulnerabilities,
        observed_at=vulnerability_observed_at,
        limits=limits,
    )
    graph = add_threat_context_to_identity_graph(
        graph,
        threat_context,
        observed_at=threat_context_observed_at,
        limits=limits,
    )
    graph = add_assessment_findings_to_identity_graph(
        graph,
        assessments,
        observed_at=assessment_observed_at,
        limits=limits,
    )
    assert_valid_identity_graph(graph)
    return graph
