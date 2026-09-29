"""Network-free CLI for the White Night control-plane foundation."""

from __future__ import annotations

import argparse
import json
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Sequence

from nightrecon_shared_core.editions import EDITIONS, edition_name

from nightrecon_white_engine.capabilities import (
    WHITE_ACTIVE_COMMANDS,
    WHITE_EDITION_SLUG,
    WHITE_OWNED_COMMANDS,
)
from nightrecon_white_engine.engagement_domain import EngagementDefinition
from nightrecon_white_engine.policy_compiler import (
    CompiledPolicyBundle,
    compile_engagement_policy,
)


def _version() -> str:
    try:
        return version("nightrecon-white-night")
    except PackageNotFoundError:
        return "0.1.0a3"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="white-night-app",
        description=(
            "NightRecon White Night command boundary. "
            "Current operations are local and network-free."
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

    policy_parser = subparsers.add_parser(
        "policy",
        help="Compile or verify a local White Night policy bundle.",
    )
    policy_operations = policy_parser.add_subparsers(
        dest="policy_operation",
        required=True,
    )

    compiling = policy_operations.add_parser(
        "compile",
        help="Compile an engagement definition into shared-core policy.",
    )
    compiling.add_argument("input", help="Engagement definition JSON file.")
    compiling.add_argument(
        "--output",
        help="Optional destination for canonical compiled bundle JSON.",
    )

    verifying = policy_operations.add_parser(
        "verify",
        help="Verify fingerprints and structure of a compiled policy bundle.",
    )
    verifying.add_argument("input", help="Compiled policy bundle JSON file.")

    return parser


def _print_editions(as_json: bool) -> None:
    records = [edition.to_record() for edition in EDITIONS]
    if as_json:
        print(json.dumps(records, indent=2, sort_keys=True))
        return

    for edition in EDITIONS:
        availability = "available" if edition.standalone_available else "not yet available"
        print(f"{edition.name}: {edition.foundation_status}; standalone {availability}")


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def _compile_policy(input_path: str, output_path: str | None) -> None:
    payload = json.loads(_read_text(input_path))
    engagement = EngagementDefinition.from_dict(payload)
    bundle = compile_engagement_policy(engagement)
    serialized = bundle.to_json()
    if output_path is not None:
        Path(output_path).write_text(serialized + "\n", encoding="utf-8")
    print(serialized)


def _verify_policy(input_path: str) -> None:
    bundle = CompiledPolicyBundle.from_json(_read_text(input_path))
    print(json.dumps(
        {
            "bundle_fingerprint": bundle.bundle_fingerprint,
            "engagement_id": bundle.engagement_id,
            "integrity": "valid",
            "policy_fingerprint": bundle.policy_fingerprint,
        },
        sort_keys=True,
    ))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
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

        if args.command == "policy" and args.policy_operation == "compile":
            _compile_policy(args.input, args.output)
            return 0

        if args.command == "policy" and args.policy_operation == "verify":
            _verify_policy(args.input)
            return 0

        parser.error("Command is not available in this edition.")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        parser.error(str(exc))
    return 2


WHITE_FOUNDATION_CAPABILITIES_FOR_DISPLAY = (
    "independent package boundary",
    "shared-core policy consumer",
    "standalone deployment target",
    "composed full-stack deployment target",
    "Live USB deployment target",
    "deterministic local ROE-to-policy compilation",
)

assert WHITE_OWNED_COMMANDS == ("editions", "policy")
assert WHITE_ACTIVE_COMMANDS == ()
