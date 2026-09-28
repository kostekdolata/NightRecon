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


def parse_ssh_banner_identity(
    banner: str,
) -> SoftwareIdentity | None:
    """Extract an explicit OpenSSH product/version from an SSH banner."""

    evidence = banner.strip()

    if not evidence.startswith("SSH-"):
        return None

    parts = evidence.split("-", 2)

    if len(parts) != 3:
        return None

    software_token = parts[2].split()[0]

    prefix = "OpenSSH_"

    if not software_token.startswith(prefix):
        return None

    version = software_token[len(prefix):].strip()

    if not version:
        return None

    return SoftwareIdentity(
        product="OpenSSH",
        version=version,
        source="banner",
        evidence=evidence,
    )
