"""Evidence-based operating-system fingerprinting for NightRecon."""

from dataclasses import dataclass

from nightrecon.service_detection import ServiceDetectionResult


@dataclass(frozen=True)
class OperatingSystemEvidence:
    """One explicit OS/platform observation from a detected service."""

    address: str
    port: int
    service: str
    platform: str
    family: str
    source: str
    evidence: str


@dataclass(frozen=True)
class OperatingSystemFingerprint:
    """Aggregated host OS fingerprint derived from explicit evidence."""

    platform: str = ""
    family: str = ""
    confidence: str = ""
    evidence: tuple[OperatingSystemEvidence, ...] = ()
    candidates: tuple[str, ...] = ()


def build_operating_system_fingerprint(
    services: tuple[ServiceDetectionResult, ...],
) -> OperatingSystemFingerprint | None:
    """Aggregate explicit service platform observations for one host."""

    observations: list[OperatingSystemEvidence] = []

    for service in services:
        fingerprint = service.service_fingerprint

        if (
            fingerprint is None
            or not fingerprint.platform.strip()
        ):
            continue

        platform, family = _normalize_platform(
            fingerprint.platform
        )

        observations.append(
            OperatingSystemEvidence(
                address=service.address,
                port=service.port,
                service=service.service,
                platform=platform,
                family=family,
                source=fingerprint.source,
                evidence=fingerprint.evidence,
            )
        )

    if not observations:
        return None

    platforms = tuple(
        sorted(
            {
                observation.platform
                for observation in observations
            }
        )
    )

    if len(platforms) > 1:
        return OperatingSystemFingerprint(
            confidence="conflicting",
            evidence=tuple(observations),
            candidates=platforms,
        )

    platform = platforms[0]
    families = {
        observation.family
        for observation in observations
        if observation.family
    }
    family = (
        next(iter(families))
        if len(families) == 1
        else ""
    )

    independent_sources = {
        (
            observation.port,
            observation.service,
            observation.source,
        )
        for observation in observations
    }

    confidence = (
        "high"
        if len(independent_sources) >= 2
        else "medium"
    )

    return OperatingSystemFingerprint(
        platform=platform,
        family=family,
        confidence=confidence,
        evidence=tuple(observations),
    )


def _normalize_platform(
    value: str,
) -> tuple[str, str]:
    normalized = value.strip()
    lowered = normalized.lower()

    mappings = (
        ("ubuntu", "Ubuntu", "Linux"),
        ("debian", "Debian", "Linux"),
        ("red hat", "Red Hat Enterprise Linux", "Linux"),
        ("rhel", "Red Hat Enterprise Linux", "Linux"),
        ("centos", "CentOS", "Linux"),
        ("alpine", "Alpine Linux", "Linux"),
        ("freebsd", "FreeBSD", "BSD"),
        ("openbsd", "OpenBSD", "BSD"),
        ("windows", "Windows", "Windows"),
        ("unix", "Unix", "Unix"),
    )

    for token, platform, family in mappings:
        if token in lowered:
            return platform, family

    return normalized, ""
