"""High-level correlation of network, vulnerability, and threat evidence."""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.threat_context import ThreatContextResult
from nightrecon_red_engine.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
    summarize_vulnerabilities,
)


NETWORK_CONTEXT_INTERPRETATION = (
    "Context is derived from observed service identities and configured "
    "vulnerability/threat-intelligence providers. Matches are evidence for "
    "review, not proof of exploitability, compromise, likelihood, or impact."
)


@dataclass(frozen=True)
class NetworkContextIntelligence:
    """High-level context layered on top of network exposure evidence."""

    headline: str
    overview: str
    evidence_quality: str
    notable_context: tuple[str, ...]
    coverage_gaps: tuple[str, ...]
    recommended_next_actions: tuple[str, ...]
    interpretation: str = NETWORK_CONTEXT_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "overview": self.overview,
            "evidence_quality": self.evidence_quality,
            "notable_context": list(self.notable_context),
            "coverage_gaps": list(self.coverage_gaps),
            "recommended_next_actions": list(self.recommended_next_actions),
            "interpretation": self.interpretation,
        }


def build_network_context_intelligence(
    *,
    vulnerability_intelligence_enabled: bool,
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...] = (),
    threat_context_enabled: bool,
    threat_context: tuple[ThreatContextResult, ...] = (),
) -> NetworkContextIntelligence:
    """Summarize existing vulnerability and external threat evidence."""

    notable: list[str] = []
    gaps: list[str] = []
    actions: list[str] = []

    if vulnerability_intelligence_enabled:
        vulnerability_summary = summarize_vulnerabilities(vulnerabilities)
        if vulnerability_summary.total_findings:
            severity_parts = []
            for label, count in (
                ("critical", vulnerability_summary.critical_count),
                ("high", vulnerability_summary.high_count),
                ("medium", vulnerability_summary.medium_count),
                ("low", vulnerability_summary.low_count),
                ("unknown", vulnerability_summary.unknown_count),
            ):
                if count:
                    severity_parts.append(f"{count} {label}")

            detail = ", ".join(severity_parts) or (
                f"{vulnerability_summary.total_findings} finding(s)"
            )
            notable.append(
                "Vulnerability intelligence returned "
                f"{vulnerability_summary.total_findings} matched finding(s) "
                f"({detail})."
            )
            actions.append(
                "Review matched vulnerability records against exact software "
                "identity, affected-version criteria, configuration, and "
                "vendor remediation guidance."
            )
        elif vulnerabilities:
            notable.append(
                "Vulnerability lookups completed without matched findings "
                "in the supplied provider evidence."
            )
        else:
            gaps.append(
                "Vulnerability intelligence is enabled but no service lookup "
                "results are available."
            )

        if vulnerability_summary.failed_lookups:
            gaps.append(
                f"{vulnerability_summary.failed_lookups} vulnerability "
                "lookup(s) failed and reduce evidence completeness."
            )
    else:
        gaps.append("Vulnerability intelligence was not enabled.")

    if threat_context_enabled:
        known_exploited = tuple(
            item for item in threat_context if item.known_exploited
        )
        epss_available = tuple(
            item for item in threat_context
            if item.epss_probability is not None
        )
        provider_errors = {
            error
            for item in threat_context
            for error in item.errors
            if error
        }

        if known_exploited:
            notable.append(
                f"{len(known_exploited)} vulnerability identifier(s) appear "
                "in the supplied known-exploited evidence."
            )
            actions.append(
                "Review known-exploited matches promptly against asset "
                "exposure, affected-version evidence, and required vendor or "
                "catalog remediation actions."
            )

        if epss_available:
            notable.append(
                f"External exploitation-probability context is available for "
                f"{len(epss_available)} vulnerability identifier(s)."
            )

        if not threat_context:
            gaps.append(
                "Threat-context enrichment is enabled but no enriched "
                "vulnerability records are available."
            )

        if provider_errors:
            gaps.append(
                f"{len(provider_errors)} threat-context provider error(s) "
                "reduce evidence completeness."
            )
    else:
        gaps.append("External threat-context enrichment was not enabled.")

    if notable:
        headline = "Network exposure has correlated security context"
        overview = (
            "Observed service exposure has additional vulnerability and/or "
            "external threat evidence available for operator review."
        )
    else:
        headline = "No correlated security context confirmed"
        overview = (
            "The supplied evidence does not currently add matched vulnerability "
            "or external threat context to the network exposure view."
        )

    if notable and not gaps:
        evidence_quality = "high"
    elif notable and len(gaps) <= 1:
        evidence_quality = "moderate"
    else:
        evidence_quality = "limited"

    if not actions:
        actions.append(
            "Improve software identity and intelligence-provider coverage "
            "before drawing conclusions from network exposure alone."
        )

    return NetworkContextIntelligence(
        headline=headline,
        overview=overview,
        evidence_quality=evidence_quality,
        notable_context=tuple(notable),
        coverage_gaps=tuple(gaps),
        recommended_next_actions=tuple(dict.fromkeys(actions)),
    )
