"""Informational CLI for the White Night package foundation."""

from __future__ import annotations

import argparse
import json
from importlib.metadata import PackageNotFoundError, version
from typing import Sequence

from nightrecon_shared_core.editions import EDITIONS, edition_name

from nightrecon_white_engine.capabilities import (
    WHITE_ACTIVE_COMMANDS,
    WHITE_EDITION_SLUG,
    WHITE_OWNED_COMMANDS,
)


def _version() -> str:
    try:
        return version("nightrecon-white-night")
    except PackageNotFoundError:
        return "0.1.0a1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="white-night-app",
        description=(
            "NightRecon White Night command boundary. "
            "Batch 2 is an informational package foundation only."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"White Night {_version()}",
    )

    subparsers = parser.add_subparsers(dest="command", title="commands")
    editions_parser = subparsers.add_parser(
        "editions",
        help="Show the NightRecon product catalog and readiness state.",
    )
    editions_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the edition catalog as JSON.",
    )
    return parser


def _print_editions(as_json: bool) -> None:
    records = [edition.to_record() for edition in EDITIONS]
    if as_json:
        print(json.dumps(records, indent=2, sort_keys=True))
        return

    for edition in EDITIONS:
        availability = "available" if edition.standalone_available else "not yet available"
        print(f"{edition.name}: {edition.foundation_status}; standalone {availability}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        print()
        print(f"{edition_name(WHITE_EDITION_SLUG)} foundation capabilities:")
        for capability in WHITE_FOUNDATION_CAPABILITIES_FOR_DISPLAY:
            print(f"  - {capability}")
        print("Active commands: none")
        return 0

    if args.command == "editions":
        _print_editions(args.json)
        return 0

    parser.error("Command is not available in this edition.")
    return 2


# Separate display constant avoids making the foundational capability tuple an
# argparse concern while keeping the normal help output explicit.
WHITE_FOUNDATION_CAPABILITIES_FOR_DISPLAY = (
    "independent package boundary",
    "shared-core policy consumer",
    "standalone deployment target",
    "composed full-stack deployment target",
    "Live USB deployment target",
)

assert WHITE_OWNED_COMMANDS == ("editions",)
assert WHITE_ACTIVE_COMMANDS == ()
