"""Threat-context enrichment for NightRecon vulnerability intelligence."""

from dataclasses import dataclass
from typing import Protocol

from nightrecon.vulnerability_intelligence import (
    ServiceVulnerabilityResult,
)


@dataclass(frozen=True)
class KevRecord:
    """CISA Known Exploited Vulnerabilities metadata for one CVE."""

    vulnerability_id: str
    date_added: str = ""
    due_date: str = ""
    known_ransomware_campaign_use: str = ""
    required_action: str = ""


@dataclass(frozen=True)
class EpssRecord:
    """FIRST EPSS exploitation-likelihood metadata for one CVE."""

    vulnerability_id: str
    probability: float
    percentile: float
    date: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.probability <= 1.0:
            raise ValueError(
                "probability must be between 0.0 and 1.0."
            )

        if not 0.0 <= self.percentile <= 1.0:
            raise ValueError(
                "percentile must be between 0.0 and 1.0."
            )


@dataclass(frozen=True)
class ThreatContextResult:
    """External threat context bound to one CVE."""

    vulnerability_id: str
    known_exploited: bool = False
    kev_date_added: str = ""
    kev_due_date: str = ""
    kev_known_ransomware_campaign_use: str = ""
    kev_required_action: str = ""
    epss_probability: float | None = None
    epss_percentile: float | None = None
    epss_date: str = ""
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class ThreatContextSummary:
    """Descriptive summary of external threat-context evidence."""

    cves_enriched: int
    known_exploited_count: int
    epss_available_count: int
    provider_error_count: int
    max_epss_probability: float | None = None
    max_epss_percentile: float | None = None


def summarize_threat_context(
    results: tuple[ThreatContextResult, ...],
) -> ThreatContextSummary:
    """Return descriptive counts for threat-context evidence."""

    probabilities = [
        result.epss_probability
        for result in results
        if result.epss_probability is not None
    ]
    percentiles = [
        result.epss_percentile
        for result in results
        if result.epss_percentile is not None
    ]
    unique_errors = {
        error
        for result in results
        for error in result.errors
        if error
    }

    return ThreatContextSummary(
        cves_enriched=len(results),
        known_exploited_count=sum(
            1
            for result in results
            if result.known_exploited
        ),
        epss_available_count=sum(
            1
            for result in results
            if result.epss_probability is not None
        ),
        provider_error_count=len(unique_errors),
        max_epss_probability=(
            max(probabilities)
            if probabilities
            else None
        ),
        max_epss_percentile=(
            max(percentiles)
            if percentiles
            else None
        ),
    )


class KevProvider(Protocol):
    """Provider contract for known-exploited vulnerability data."""

    name: str

    def lookup(
        self,
        vulnerability_ids: tuple[str, ...],
    ) -> dict[str, KevRecord]:
        """Return KEV records keyed by CVE ID."""


class EpssProvider(Protocol):
    """Provider contract for EPSS vulnerability data."""

    name: str

    def lookup(
        self,
        vulnerability_ids: tuple[str, ...],
    ) -> dict[str, EpssRecord]:
        """Return EPSS records keyed by CVE ID."""


def enrich_threat_context(
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...],
    kev_provider: KevProvider,
    epss_provider: EpssProvider,
) -> tuple[ThreatContextResult, ...]:
    """Enrich unique CVE findings with fail-soft KEV and EPSS evidence."""

    vulnerability_ids = _unique_vulnerability_ids(
        vulnerabilities
    )

    if not vulnerability_ids:
        return ()

    errors: list[str] = []

    try:
        kev_records = kev_provider.lookup(
            vulnerability_ids
        )
    except Exception as exc:
        kev_records = {}
        errors.append(
            f"{kev_provider.name}: "
            f"{str(exc) or exc.__class__.__name__}"
        )

    try:
        epss_records = epss_provider.lookup(
            vulnerability_ids
        )
    except Exception as exc:
        epss_records = {}
        errors.append(
            f"{epss_provider.name}: "
            f"{str(exc) or exc.__class__.__name__}"
        )

    results: list[ThreatContextResult] = []

    for vulnerability_id in vulnerability_ids:
        kev = kev_records.get(vulnerability_id)
        epss = epss_records.get(vulnerability_id)

        results.append(
            ThreatContextResult(
                vulnerability_id=vulnerability_id,
                known_exploited=kev is not None,
                kev_date_added=(
                    kev.date_added
                    if kev is not None
                    else ""
                ),
                kev_due_date=(
                    kev.due_date
                    if kev is not None
                    else ""
                ),
                kev_known_ransomware_campaign_use=(
                    kev.known_ransomware_campaign_use
                    if kev is not None
                    else ""
                ),
                kev_required_action=(
                    kev.required_action
                    if kev is not None
                    else ""
                ),
                epss_probability=(
                    epss.probability
                    if epss is not None
                    else None
                ),
                epss_percentile=(
                    epss.percentile
                    if epss is not None
                    else None
                ),
                epss_date=(
                    epss.date
                    if epss is not None
                    else ""
                ),
                errors=tuple(errors),
            )
        )

    return tuple(results)


def _unique_vulnerability_ids(
    vulnerabilities: tuple[ServiceVulnerabilityResult, ...],
) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []

    for service_result in vulnerabilities:
        for finding in service_result.lookup.findings:
            vulnerability_id = (
                finding.vulnerability_id.strip()
            )

            if (
                vulnerability_id
                and vulnerability_id not in seen
            ):
                ordered.append(vulnerability_id)
                seen.add(vulnerability_id)

    return tuple(ordered)
