"""Evidence-backed exposure prioritisation without exploit execution."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ExposureEvidence:
    vulnerability_id: str
    reachable: bool
    cvss_score: float | None = None
    kev_listed: bool = False
    epss_probability: float | None = None
    validation_state: str = ""
    preconditions_met: bool | None = None
    existing_access: bool = False
    identity_path_present: bool = False


@dataclass(frozen=True)
class ExposurePriority:
    vulnerability_id: str
    priority: str
    exploitability_confidence: str
    reasons: tuple[str, ...]
    limitations: tuple[str, ...]


def prioritize_exposure(item: ExposureEvidence) -> ExposurePriority:
    if not item.vulnerability_id.strip():
        raise ValueError("vulnerability_id must not be empty")
    if item.cvss_score is not None and not 0 <= item.cvss_score <= 10:
        raise ValueError("cvss_score must be between 0 and 10")
    if item.epss_probability is not None and not 0 <= item.epss_probability <= 1:
        raise ValueError("epss_probability must be between 0 and 1")

    reasons = []
    limitations = []

    if not item.reachable:
        return ExposurePriority(
            vulnerability_id=item.vulnerability_id,
            priority="low",
            exploitability_confidence="limited",
            reasons=("service is not currently evidenced as reachable",),
            limitations=("Reachability may change with network position or policy.",),
        )

    reasons.append("service is evidenced as reachable")

    if item.validation_state == "confirmed":
        confidence = "confirmed"
        reasons.append("controlled validation confirmed the reviewed property")
    elif item.preconditions_met is True and item.existing_access:
        confidence = "strong"
        reasons.append("documented preconditions and existing access are present")
    elif item.preconditions_met is True:
        confidence = "moderate"
        reasons.append("documented preconditions are present")
    else:
        confidence = "limited"
        limitations.append(
            "Exploitability is not confirmed; missing or unverified preconditions remain."
        )

    weight = 0
    if item.cvss_score is not None:
        if item.cvss_score >= 9:
            weight += 3
            reasons.append("critical CVSS severity")
        elif item.cvss_score >= 7:
            weight += 2
            reasons.append("high CVSS severity")
        elif item.cvss_score >= 4:
            weight += 1
            reasons.append("medium CVSS severity")
    if item.kev_listed:
        weight += 3
        reasons.append("listed in CISA KEV")
    if item.epss_probability is not None and item.epss_probability >= 0.5:
        weight += 2
        reasons.append("elevated EPSS probability")
    if item.existing_access:
        weight += 1
        reasons.append("existing authorized access context is present")
    if item.identity_path_present:
        weight += 1
        reasons.append("evidence-backed identity/attack path reaches the asset")
    if item.validation_state == "confirmed":
        weight += 2

    priority = "high" if weight >= 5 else "medium" if weight >= 2 else "low"
    return ExposurePriority(
        vulnerability_id=item.vulnerability_id,
        priority=priority,
        exploitability_confidence=confidence,
        reasons=tuple(reasons),
        limitations=tuple(limitations),
    )
