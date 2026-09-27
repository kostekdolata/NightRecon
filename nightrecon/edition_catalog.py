"""Read-only product-edition catalog; no edition execution is exposed here."""

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Edition:
    slug: str
    name: str
    purpose: str
    foundation_status: str
    standalone_available: bool = False

    def to_record(self) -> dict[str, str | bool]:
        return asdict(self)


# This catalog describes product boundaries, not installable editions. Existing
# capabilities continue to use the common CLI until isolation gates exist.
EDITIONS: tuple[Edition, ...] = (
    Edition(
        "white",
        "White",
        "Engagement authorization, scope, approvals, audit, and exercise control.",
        "partial foundation",
    ),
    Edition(
        "blue",
        "Blue",
        "Defensive telemetry, detection, prevention, and remediation validation.",
        "planned",
    ),
    Edition(
        "red",
        "Red",
        "Authorized reconnaissance and bounded adversarial validation.",
        "partial foundation",
    ),
    Edition(
        "purple",
        "Purple",
        "Correlate approved Red activity with Blue defensive evidence.",
        "planned",
    ),
    Edition(
        "black",
        "Black-box",
        "Authorized, knowledge-limited external assessment.",
        "partial foundation",
    ),
)
