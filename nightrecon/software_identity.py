"""Structured software identity for vulnerability intelligence."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SoftwareIdentity:
    """Explicitly observed software product and version."""

    product: str
    version: str
    source: str
    evidence: str


def parse_http_server_identity(
    server: str,
) -> SoftwareIdentity | None:
    """Extract product/version from an explicit HTTP Server value."""

    evidence = server.strip()

    if not evidence:
        return None

    first_token = evidence.split()[0]

    if "/" not in first_token:
        return None

    product, version = first_token.split("/", 1)
    product = product.strip()
    version = version.strip()

    if not product or not version:
        return None

    return SoftwareIdentity(
        product=product,
        version=version,
        source="http-server",
        evidence=evidence,
    )
