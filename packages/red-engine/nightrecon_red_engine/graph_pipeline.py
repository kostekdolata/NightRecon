"""Compose NightRecon evidence into one deterministic identity graph."""

from __future__ import annotations

from nightrecon_red_engine.assessment_engine import ServiceAssessmentResult
from nightrecon_red_engine.asset_inventory import AssetInventory
from nightrecon_red_engine.graph_assessment import add_assessment_findings_to_identity_graph
from nightrecon_red_engine.graph_builder import GraphBuildLimits
from nightrecon_red_engine.graph_correlation import (
    CrossSurfaceCorrelationLimits,
    CrossSurfaceCorrelationResult,
    correlate_exact_cross_surface_evidence,
)
from nightrecon_red_engine.graph_critical_asset import (
    CriticalAssetEvidence,
    add_critical_asset_evidence_to_identity_graph,
)
from nightrecon_red_engine.graph_identity_evidence import IdentityEvidenceBundle
from nightrecon_red_engine.graph_identity_projection import add_identity_evidence_to_identity_graph
from nightrecon_red_engine.graph_models import IdentityGraph
from nightrecon_red_engine.graph_projection import (
    add_vulnerability_evidence_to_identity_graph,
    build_identity_graph_from_asset_inventory,
)
from nightrecon_red_engine.graph_threat_context import add_threat_context_to_identity_graph
from nightrecon_red_engine.graph_validation import assert_valid_identity_graph
from nightrecon_red_engine.graph_web_surface import (
    WebSurfaceEvidence,
    add_web_surface_evidence_to_graph,
)
from nightrecon_red_engine.threat_context import ThreatContextResult
from nightrecon_red_engine.vulnerability_intelligence import ServiceVulnerabilityResult


def build_identity_graph(
    *,
    inventory: AssetInventory,
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...] = (),
    threat_context: tuple[ThreatContextResult, ...] = (),
    assessments: tuple[ServiceAssessmentResult, ...] = (),
    identity_evidence: IdentityEvidenceBundle | None = None,
    web_surfaces: tuple[WebSurfaceEvidence, ...] = (),
    critical_assets: tuple[CriticalAssetEvidence, ...] = (),
    vulnerability_observed_at: str = "",
    threat_context_observed_at: str = "",
    assessment_observed_at: str = "",
    identity_observed_at: str = "",
    web_surface_observed_at: str = "",
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
    graph = add_web_surface_evidence_to_graph(
        graph,
        web_surfaces,
        observed_at=web_surface_observed_at,
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


def build_correlated_identity_graph(
    *,
    inventory: AssetInventory,
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...] = (),
    threat_context: tuple[ThreatContextResult, ...] = (),
    assessments: tuple[ServiceAssessmentResult, ...] = (),
    identity_evidence: IdentityEvidenceBundle | None = None,
    web_surfaces: tuple[WebSurfaceEvidence, ...] = (),
    critical_assets: tuple[CriticalAssetEvidence, ...] = (),
    vulnerability_observed_at: str = "",
    threat_context_observed_at: str = "",
    assessment_observed_at: str = "",
    identity_observed_at: str = "",
    web_surface_observed_at: str = "",
    critical_asset_observed_at: str = "",
    limits: GraphBuildLimits | None = None,
    correlation_limits: CrossSurfaceCorrelationLimits | None = None,
) -> CrossSurfaceCorrelationResult:
    """Build the normal evidence graph, then add exact cross-surface correlations."""

    graph = build_identity_graph(
        inventory=inventory,
        vulnerabilities=vulnerabilities,
        threat_context=threat_context,
        assessments=assessments,
        identity_evidence=identity_evidence,
        web_surfaces=web_surfaces,
        critical_assets=critical_assets,
        vulnerability_observed_at=vulnerability_observed_at,
        threat_context_observed_at=threat_context_observed_at,
        assessment_observed_at=assessment_observed_at,
        identity_observed_at=identity_observed_at,
        web_surface_observed_at=web_surface_observed_at,
        critical_asset_observed_at=critical_asset_observed_at,
        limits=limits,
    )
    result = correlate_exact_cross_surface_evidence(
        graph,
        limits=correlation_limits,
    )
    assert_valid_identity_graph(result.graph)
    return result
