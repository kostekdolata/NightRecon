"""Compose NightRecon evidence into one deterministic identity graph."""

from __future__ import annotations

from nightrecon.assessment_engine import ServiceAssessmentResult
from nightrecon.asset_inventory import AssetInventory
from nightrecon.graph_assessment import add_assessment_findings_to_identity_graph
from nightrecon.graph_builder import GraphBuildLimits
from nightrecon.graph_critical_asset import (
    CriticalAssetEvidence,
    add_critical_asset_evidence_to_identity_graph,
)
from nightrecon.graph_identity_evidence import IdentityEvidenceBundle
from nightrecon.graph_identity_projection import add_identity_evidence_to_identity_graph
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
    identity_evidence: IdentityEvidenceBundle | None = None,
    critical_assets: tuple[CriticalAssetEvidence, ...] = (),
    vulnerability_observed_at: str = "",
    threat_context_observed_at: str = "",
    assessment_observed_at: str = "",
    identity_observed_at: str = "",
    critical_asset_observed_at: str = "",
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
    graph = add_identity_evidence_to_identity_graph(
        graph,
        identity_evidence or IdentityEvidenceBundle.empty(),
        observed_at=identity_observed_at,
        limits=limits,
    )
    graph = add_critical_asset_evidence_to_identity_graph(
        graph,
        critical_assets,
        observed_at=critical_asset_observed_at,
        limits=limits,
    )
    assert_valid_identity_graph(graph)
    return graph
