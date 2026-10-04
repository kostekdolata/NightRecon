"""Network-free Night edition identity and fail-closed command ownership policy."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class Edition:
    slug: str
    name: str
    purpose: str
    foundation_status: str
    standalone_available: bool = False

    def to_record(self) -> dict[str, str | bool]:
        return asdict(self)


EDITIONS: tuple[Edition, ...] = (
    Edition("white", "White Night",
            "Engagement authorization, scope, approvals, audit, and exercise control.",
            "partial foundation"),
    Edition("blue", "Blue Night",
            "Defensive telemetry, control validation, detection coverage, and remediation validation.",
            "planned"),
    Edition("red", "Red Night",
            "Authorized reconnaissance and bounded adversarial validation.",
            "partial foundation", standalone_available=True),
    Edition("purple", "Purple Night",
            "Correlate approved Red Night activity with Blue Night defensive evidence.",
            "planned"),
    Edition("black", "Black Night",
            "Authorized, knowledge-limited external assessment.",
            "partial foundation"),
)


class EditionRouteError(ValueError):
    """An edition cannot dispatch the requested command."""


_COMMANDS = MappingProxyType({
    "white": frozenset({"approval", "audit", "editions", "evidence", "policy"}),
    "blue": frozenset({"editions"}),
    "red": frozenset({
        "editions", "infra", "api", "assets", "checks", "discover",
        "crawl", "scan", "pentest", "run-all", "identity", "workspace",
    }),
    "purple": frozenset({"editions"}),
    "black": frozenset({"editions"}),
})


def available_commands(edition: str) -> tuple[str, ...]:
    if edition not in _COMMANDS:
        raise EditionRouteError("Unknown NightRecon edition.")
    return tuple(sorted(_COMMANDS[edition]))


def edition_name(edition: str) -> str:
    try:
        return next(item.name for item in EDITIONS if item.slug == edition)
    except StopIteration as exc:
        raise EditionRouteError("Unknown NightRecon edition.") from exc
