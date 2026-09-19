"""Command-line interface for NightRecon."""

import argparse

from nightrecon import __version__
from nightrecon.scope import Scope
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nightrecon",
        description=(
            "NightRecon - modular reconnaissance and penetration testing "
            "platform for authorized security assessments."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"NightRecon {__version__}",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
    )

    scan_parser = subparsers.add_parser(
        "scan",
        help="Create a scan session for an authorized target.",
    )

    scan_parser.add_argument(
        "target",
        help="Authorized target hostname, IP address, or CIDR range.",
    )

    scan_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help=(
            "Authorized scope rule. May be supplied multiple times. "
            "Example: --scope 192.168.1.0/24"
        ),
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        try:
            target = parse_target(args.target)
            scope = Scope.from_values(args.scope)
        except ValueError as exc:
            parser.error(str(exc))

        if not scope.is_authorized(target):
            parser.error(
                f"Target '{target.value}' is outside the authorized scope."
            )

        session = ScanSession.create(
            target=target,
            scope_rules=tuple(args.scope),
        )

        store = ResultStore()
        output_path = store.save_session(session)

        print(f"NightRecon scan target: {target.value}")
        print(f"Target type: {target.target_type.value}")
        print("Scope authorization: approved")
        print(f"Session ID: {session.session_id}")
        print(f"Session status: {session.status}")
        print(f"Result file: {output_path}")
        print("No network activity performed.")


if __name__ == "__main__":
    main()
