"""Command-line interface for NightRecon."""

import argparse

from nightrecon import __version__
from nightrecon.config import NightReconConfig
from nightrecon.logging import NightReconLogger
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

    scan_parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Connection timeout in seconds. Default: 2.0",
    )

    scan_parser.add_argument(
        "--workers",
        type=int,
        default=50,
        help="Maximum concurrent workers. Default: 50",
    )

    scan_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    scan_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        try:
            target = parse_target(args.target)
            scope = Scope.from_values(args.scope)

            config = NightReconConfig(
                connect_timeout=args.timeout,
                max_workers=args.workers,
                results_dir=args.results_dir,
                logs_dir=args.logs_dir,
            )
        except ValueError as exc:
            parser.error(str(exc))

        logger = NightReconLogger(config.logs_dir)

        if not scope.is_authorized(target):
            logger.write(
                "scan.rejected",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="outside_authorized_scope",
            )

            parser.error(
                f"Target '{target.value}' is outside the authorized scope."
            )

        session = ScanSession.create(
            target=target,
            scope_rules=tuple(args.scope),
        )

        store = ResultStore(config.results_dir)
        output_path = store.save_session(session)

        logger.write(
            "scan.created",
            session_id=session.session_id,
            target=target.value,
            target_type=target.target_type.value,
            scope=args.scope,
            status=session.status,
            connect_timeout=config.connect_timeout,
            max_workers=config.max_workers,
        )

        print(f"NightRecon scan target: {target.value}")
        print(f"Target type: {target.target_type.value}")
        print("Scope authorization: approved")
        print(f"Session ID: {session.session_id}")
        print(f"Session status: {session.status}")
        print(f"Connection timeout: {config.connect_timeout}")
        print(f"Max workers: {config.max_workers}")
        print(f"Result file: {output_path}")
        print("No network activity performed.")


if __name__ == "__main__":
    main()
