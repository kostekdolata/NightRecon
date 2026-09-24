"""Security header analysis for NightRecon."""

from dataclasses import dataclass


SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
)


@dataclass(frozen=True)
class SecurityHeaderAnalysis:
    """Observed presence of common HTTP security headers."""

    present: tuple[str, ...]
    missing: tuple[str, ...]


def analyze_security_headers(
    headers: dict[str, str],
) -> SecurityHeaderAnalysis:
    """Identify present and missing security headers."""

    normalized = {
        name.lower(): value
        for name, value in headers.items()
    }

    present = tuple(
        header
        for header in SECURITY_HEADERS
        if header in normalized
    )

    missing = tuple(
        header
        for header in SECURITY_HEADERS
        if header not in normalized
    )

    return SecurityHeaderAnalysis(
        present=present,
        missing=missing,
    )