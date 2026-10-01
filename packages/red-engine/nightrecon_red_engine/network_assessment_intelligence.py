"""High-level network assessment intelligence for Red Night.

This layer converts deterministic network evidence into concise operator-facing
assessment feedback. It is descriptive: it does not claim exploitability,
likelihood, compromise, or an autonomous execution decision.
"""

from __future__ import annotations

from dataclasses import dataclass

from nightrecon_red_engine.service_detection import ServiceDetectionResult
from nightrecon_red_engine.tcp_scanner import TcpPortResult
from nightrecon_red_engine.udp_scanner import UdpPortResult


NETWORK_INTELLIGENCE_INTERPRETATION = (
    "High-level assessment feedback derived from observed network evidence. "
    "Exposure and service presence do not by themselves establish a "
    "vulnerability, exploitability, compromise, likelihood, or business impact."
)


@dataclass(frozen=True)
class NetworkAssessmentIntelligence:
    """High-level operator-facing network assessment feedback."""

    headline: str
    overview: str
    notable_exposures: tuple[str, ...]
    confidence: str
    coverage_gaps: tuple[str, ...]
    recommended_next_actions: tuple[str, ...]
    evidence_summary: tuple[str, ...]
    interpretation: str = NETWORK_INTELLIGENCE_INTERPRETATION

    def to_dict(self) -> dict[str, object]:
        return {
            "headline": self.headline,
            "overview": self.overview,
            "notable_exposures": list(self.notable_exposures),
            "confidence": self.confidence,
            "coverage_gaps": list(self.coverage_gaps),
            "recommended_next_actions": list(self.recommended_next_actions),
            "evidence_summary": list(self.evidence_summary),
            "interpretation": self.interpretation,
        }


def build_network_assessment_intelligence(
    *,
    tcp_results: tuple[TcpPortResult, ...] = (),
    services: tuple[ServiceDetectionResult, ...] = (),
    udp_results: tuple[UdpPortResult, ...] = (),
) -> NetworkAssessmentIntelligence:
    """Build deterministic high-level feedback from existing scan evidence."""

    open_tcp = tuple(item for item in tcp_results if item.is_open)
    open_udp = tuple(item for item in udp_results if item.state == "open")
    unresolved_udp = tuple(
        item for item in udp_results if item.state == "open|filtered"
    )
    service_names = tuple(
        sorted({
            item.service
            for item in services
            if item.error_code == 0 and item.service
        })
    )

    exposure_notes: list[str] = []
    next_actions: list[str] = []
    gaps: list[str] = []
    evidence: list[str] = []

    if open_tcp or open_udp:
        evidence.append(
            f"Observed {len(open_tcp)} responsive TCP port(s) and "
            f"{len(open_udp)} positively responding UDP port(s)."
        )
    else:
        evidence.append(
            "No positively responsive TCP or UDP services were observed "
            "in the supplied evidence."
        )

    if service_names:
        evidence.append(
            "Identified services: " + ", ".join(service_names) + "."
        )

    remote_admin = {
        "ssh",
        "rdp",
        "telnet",
    }
    data_services = {
        "smb",
        "mysql",
        "postgresql",
        "redis",
    }
    web_services = {
        "http",
        "http-alt",
        "https",
    }
    infrastructure_services = {
        "dns",
        "ntp",
        "snmp",
        "dhcp-server",
        "dhcp-client",
        "mdns",
    }

    present = set(service_names)
    udp_hints = {
        item.service_hint
        for item in open_udp
        if item.service_hint != "unknown"
    }
    present.update(udp_hints)

    if present & remote_admin:
        names = ", ".join(sorted(present & remote_admin))
        exposure_notes.append(
            f"Remote administration services are exposed ({names}), "
            "making access-control and authentication review important."
        )
        next_actions.append(
            "Review remote administration access controls, authentication "
            "requirements, and intended network reachability."
        )

    if present & data_services:
        names = ", ".join(sorted(present & data_services))
        exposure_notes.append(
            f"Data or file-service exposure is present ({names}); verify "
            "that network access matches the intended trust boundary."
        )
        next_actions.append(
            "Validate data-service exposure, authentication, segmentation, "
            "and least-privilege access."
        )

    if present & web_services:
        exposure_notes.append(
            "Web-facing services are present and should be assessed together "
            "with TLS, headers, application behavior, and authenticated paths."
        )
        next_actions.append(
            "Continue with web/TLS assessment and authenticated application "
            "coverage where authorized."
        )

    if present & infrastructure_services:
        names = ", ".join(sorted(present & infrastructure_services))
        exposure_notes.append(
            f"Infrastructure services are exposed ({names}); configuration "
            "and network-boundary review is warranted."
        )
        next_actions.append(
            "Review infrastructure-service configuration, intended exposure, "
            "and whether management/query access is appropriately restricted."
        )

    if unresolved_udp:
        gaps.append(
            f"{len(unresolved_udp)} UDP port(s) remain open|filtered because "
            "silence cannot distinguish filtering from an open service."
        )
        next_actions.append(
            "Resolve ambiguous UDP exposure with approved protocol-aware "
            "follow-up or corroborating network evidence."
        )

    unidentified_open_tcp = {
        item.port for item in open_tcp
    } - {
        item.port for item in services if item.error_code == 0
    }
    if unidentified_open_tcp:
        gaps.append(
            f"{len(unidentified_open_tcp)} open TCP port(s) lack service "
            "identification evidence."
        )
        next_actions.append(
            "Collect bounded service/version evidence for unidentified open "
            "TCP ports."
        )

    weak_service_evidence = tuple(
        item for item in services
        if item.error_code == 0
        and item.service == "unknown"
        and item.service_fingerprint is None
        and item.software_identity is None
    )
    if weak_service_evidence:
        gaps.append(
            f"{len(weak_service_evidence)} service(s) remain weakly identified."
        )

    confirmed_udp = sum(
        1 for item in open_udp if item.protocol_match is True
    )
    medium_udp = sum(
        1 for item in open_udp if item.protocol_match is not True
    )

    if open_tcp or open_udp:
        if (
            not unresolved_udp
            and not unidentified_open_tcp
            and not weak_service_evidence
            and medium_udp == 0
        ):
            confidence = "high"
        elif len(gaps) <= 1:
            confidence = "moderate"
        else:
            confidence = "limited"
    else:
        confidence = "limited"

    total_exposed = len(open_tcp) + len(open_udp)
    if total_exposed == 0:
        headline = "No responsive network services confirmed"
        overview = (
            "The supplied evidence does not confirm responsive TCP or UDP "
            "services. This should be treated as a coverage result, not proof "
            "that the host has no network exposure."
        )
    elif len(exposure_notes) >= 3:
        headline = "Broad network service exposure observed"
        overview = (
            "The host presents multiple service categories across the assessed "
            "network surface. Review should focus on whether each exposed "
            "service is necessary, correctly segmented, and strongly "
            "authenticated/configured."
        )
    else:
        headline = "Network service exposure observed"
        overview = (
            "Responsive network services were observed. The main assessment "
            "priority is to confirm intended exposure, strengthen service "
            "identification, and investigate the most security-relevant "
            "service categories."
        )

    if confirmed_udp:
        evidence.append(
            f"{confirmed_udp} UDP response(s) matched an expected protocol "
            "structure."
        )

    if medium_udp:
        evidence.append(
            f"{medium_udp} responsive UDP service(s) are open but not "
            "protocol-confirmed."
        )

    if not next_actions:
        next_actions.append(
            "Correlate this network evidence with vulnerability, identity, "
            "application, and asset-context findings before drawing conclusions."
        )

    return NetworkAssessmentIntelligence(
        headline=headline,
        overview=overview,
        notable_exposures=tuple(exposure_notes),
        confidence=confidence,
        coverage_gaps=tuple(gaps),
        recommended_next_actions=tuple(dict.fromkeys(next_actions)),
        evidence_summary=tuple(evidence),
    )
