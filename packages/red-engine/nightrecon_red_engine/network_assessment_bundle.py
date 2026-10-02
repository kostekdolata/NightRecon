"""Reusable high-level network assessment bundle for Red Night."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.environment_network_intelligence import (
    HostNetworkAssessment,
    build_environment_network_intelligence,
)
from nightrecon_red_engine.network_assessment_intelligence import (
    NetworkAssessmentIntelligence,
    build_network_assessment_intelligence,
)
from nightrecon_red_engine.network_context_intelligence import (
    NetworkContextIntelligence,
    build_network_context_intelligence,
)
from nightrecon_red_engine.network_evidence_completeness import (
    NetworkEvidenceCompleteness,
    build_network_evidence_completeness,
)
from nightrecon_red_engine.network_executive_assessment import (
    NetworkExecutiveAssessment,
    build_network_executive_assessment,
)
from nightrecon_red_engine.network_operator_brief import (
    NetworkOperatorBrief,
    build_network_operator_brief,
)
from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult
from nightrecon_red_engine.threat_context import ThreatContextResult
from nightrecon_red_engine.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
)


@dataclass(frozen=True)
class NetworkAssessmentBundle:
    """One consistent high-level assessment assembled from raw evidence."""

    host: str
    assessment: NetworkAssessmentIntelligence
    operator_brief: NetworkOperatorBrief
    context: NetworkContextIntelligence
    completeness: NetworkEvidenceCompleteness
    executive_assessment: NetworkExecutiveAssessment

    def to_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "assessment": self.assessment.to_dict(),
            "operator_brief": self.operator_brief.to_dict(),
            "context": self.context.to_dict(),
            "completeness": self.completeness.to_dict(),
            "executive_assessment": self.executive_assessment.to_dict(),
        }


def build_network_assessment_bundle(
    *,
    host: str,
    tcp_results: tuple[TcpPortResult, ...] = (),
    services: tuple[ServiceDetectionResult, ...] = (),
    vulnerability_intelligence_enabled: bool = False,
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...] = (),
    threat_context_enabled: bool = False,
    threat_context: tuple[ThreatContextResult, ...] = (),
) -> NetworkAssessmentBundle:
    """Build all high-level network assessment layers consistently."""

    if not host.strip():
        raise ValueError("host must not be empty.")

    assessment = build_network_assessment_intelligence(
        tcp_results=tcp_results,
        services=services,
    )
    environment = build_environment_network_intelligence(
        (HostNetworkAssessment(host=host, assessment=assessment),)
    )
    operator_brief = build_network_operator_brief(environment)
    context = build_network_context_intelligence(
        vulnerability_intelligence_enabled=vulnerability_intelligence_enabled,
        vulnerabilities=vulnerabilities,
        threat_context_enabled=threat_context_enabled,
        threat_context=threat_context,
    )
    completeness = build_network_evidence_completeness(
        tcp_results=tcp_results,
        services=services,
        vulnerability_intelligence_enabled=vulnerability_intelligence_enabled,
        vulnerabilities=vulnerabilities,
        threat_context_enabled=threat_context_enabled,
        threat_context=threat_context,
    )
    executive = build_network_executive_assessment(
        operator_brief=operator_brief,
        context=context,
        completeness=completeness,
    )

    return NetworkAssessmentBundle(
        host=host,
        assessment=assessment,
        operator_brief=operator_brief,
        context=context,
        completeness=completeness,
        executive_assessment=executive,
    )
