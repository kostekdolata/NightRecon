"""Fail-closed execution adapter for Night edition launchers.

Command ownership policy lives in :mod:`nightrecon.edition_policy`, which is
network-free. This adapter preserves legacy CLI execution until engine
isolation is complete; it is not an installer or a substitute for scope checks.
"""

from __future__ import annotations

from collections.abc import Sequence

from nightrecon.cli import main as legacy_main
from nightrecon.edition_policy import (
    EditionRouteError,
    available_commands,
    edition_name,
)


def run_edition_cli(edition: str, argv: Sequence[str]) -> None:
    """Dispatch only a command explicitly owned by the selected edition."""

    allowed = available_commands(edition)
    arguments = tuple(argv)

    if not arguments or arguments[0] in {"-h", "--help"}:
        print(f"NightRecon {edition_name(edition)} command boundary")
        print("Available commands: " + ", ".join(allowed))
        print("Standalone edition packaging is not yet available.")
        return

    if arguments[0] == "--version":
        legacy_main(arguments)
        return

    if arguments[0] not in allowed:
        raise EditionRouteError("Command is not available in this edition.")

    if edition == "red" and arguments[0] == "identity":
        from nightrecon.red_directory_cli import main as identity_main

        identity_main(arguments[1:])
        return

    if edition == "red" and arguments[0] == "workspace":
        from nightrecon.red_workspace_cli import main as workspace_main

        workspace_main(arguments[1:])
        return

    if edition == "red" and arguments[0] in {
        "network-env",
        "syn-scan",
        "packet",
        "web-replay",
        "web-proxy",
    }:
        from nightrecon_red_engine.red_cli import main as red_main

        red_main(arguments)
        return

    legacy_main(arguments)
