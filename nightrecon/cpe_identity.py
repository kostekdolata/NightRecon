"""Deterministic CPE 2.3 identities for explicitly observed software."""

from dataclasses import dataclass
import re

from nightrecon.software_identity import SoftwareIdentity


@dataclass(frozen=True)
class CpeIdentity:
    """Canonical CPE components for one known software identity."""

    part: str
    vendor: str
    product: str
    version: str
    update: str = "*"

    def to_cpe23(self) -> str:
        """Return the canonical CPE 2.3 formatted name."""

        return ":".join(
            (
                "cpe",
                "2.3",
                self.part,
                self.vendor,
                self.product,
                self.version,
                self.update,
                "*",
                "*",
                "*",
                "*",
                "*",
                "*",
            )
        )


def cpe_identity_from_software(
    software_identity: SoftwareIdentity,
) -> CpeIdentity | None:
    """Map supported observed software to a deterministic CPE identity."""

    product = software_identity.product.strip().lower()
    version = software_identity.version.strip()

    if not version:
        return None

    if product == "nginx":
        return CpeIdentity(
            part="a",
            vendor="nginx",
            product="nginx",
            version=version,
        )

    if product == "apache":
        return CpeIdentity(
            part="a",
            vendor="apache",
            product="http_server",
            version=version,
        )

    if product == "openssh":
        match = re.fullmatch(
            r"(\d+(?:\.\d+)*)(p\d+)?",
            version,
            re.IGNORECASE,
        )

        if match is None:
            return None

        base_version, patch = match.groups()

        return CpeIdentity(
            part="a",
            vendor="openbsd",
            product="openssh",
            version=base_version,
            update=patch.lower() if patch else "*",
        )

    return None
