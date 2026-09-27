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
        "White Night",
        "Engagement authorization, scope, approvals, audit, and exercise control.",
        "partial foundation",
    ),
    Edition(
        "blue",
        "Blue Night",
        "Defensive telemetry, detection, prevention, and remediation validation.",
        "planned",
    ),
    Edition(
        "red",
        "Red Night",
        "Authorized reconnaissance and bounded adversarial validation.",
        "partial foundation",
    ),
    Edition(
        "purple",
        "Purple Night",
        "Correlate approved Red Night activity with Blue Night defensive evidence.",
        "planned",
    ),
    Edition(
        "black",
        "Black Night",
        "Authorized, knowledge-limited external assessment.",
        "partial foundation",
    ),
)
