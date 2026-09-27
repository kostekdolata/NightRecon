"""Fail-closed command boundary for future standalone edition launchers.

This gateway is not an installer or a substitute for the existing scope checks.
Standalone distributions will call it through their own entry points.
"""

from __future__ import annotations

from collections.abc import Sequence
from types import MappingProxyType

from nightrecon.cli import main as legacy_main
from nightrecon.edition_catalog import EDITIONS


class EditionRouteError(ValueError):
    """An edition cannot dispatch the requested command."""


# Only already-implemented commands are listed. An unlisted command is denied
# before the shared CLI can parse it or reach any network-capable operation.
# Black-box needs a reviewed outside-in starting-knowledge policy before any
# generic discovery command may be routed through its future launcher.
_COMMANDS = MappingProxyType({
    "white": frozenset({"editions"}),
    "blue": frozenset({"editions"}),
    "red": frozenset({
        "editions", "infra", "api", "assets", "checks", "discover",
        "crawl", "scan",
    }),
    "purple": frozenset({"editions"}),
    "black": frozenset({"editions"}),
})


def available_commands(edition: str) -> tuple[str, ...]:
    """Return deterministic commands for one known edition."""

    if edition not in _COMMANDS:
        raise EditionRouteError("Unknown NightRecon edition.")
    return tuple(sorted(_COMMANDS[edition]))


def run_edition_cli(edition: str, argv: Sequence[str]) -> None:
    """Dispatch only a command explicitly owned by the selected edition."""

    allowed = available_commands(edition)
    arguments = tuple(argv)

    if not arguments or arguments[0] in {"-h", "--help"}:
        name = next(item.name for item in EDITIONS if item.slug == edition)
        print(f"NightRecon {name} command boundary")
        print("Available commands: " + ", ".join(allowed))
        print("Standalone edition packaging is not yet available.")
        return

    if arguments[0] == "--version":
        legacy_main(arguments)
        return

    if arguments[0] not in allowed:
        raise EditionRouteError("Command is not available in this edition.")

    legacy_main(arguments)
