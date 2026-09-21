"""Command-line interface for NightRecon."""

import argparse

from nightrecon import __version__
from nightrecon.config import NightReconConfig
from nightrecon.logging import NightReconLogger
from nightrecon.ports import parse_ports
from nightrecon.report import TcpScanReport
from nightrecon.resolver import resolve_target
from nightrecon.scope import Scope
from nightrecon.service_detection import detect_services
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import TargetType, parse_target
from nightrecon.tcp_scanner import scan_tcp_ports


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
        help="Scan an authorized target.",
    )

    scan_parser.add_argument(
        "target",
        help="Authorized target hostname or IP address.",
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
        "--ports",
        default="80,443",
        help=(
            "TCP ports to scan. Supports lists and ranges. "
            "Default: 80,443"
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
            ports = parse_ports(args.ports)

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

        if target.target_type == TargetType.CIDR:
            logger.write(
                "scan.rejected",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="cidr_active_scan_not_supported",
            )

            parser.error(
                "Active TCP scanning of CIDR targets is not supported yet."
            )

        try:
            resolution = resolve_target(target)
        except ValueError as exc:
            logger.write(
                "resolution.failed",
                target=target.value,
                target_type=target.target_type.value,
                reason=str(exc),
            )
            parser.error(str(exc))

        session = ScanSession.create(
            target=target,
            scope_rules=tuple(args.scope),
        )

        all_results = []

        for address in resolution.addresses:
            results = scan_tcp_ports(
                address=address,
                ports=ports,
                timeout=config.connect_timeout,
                max_workers=config.max_workers,
            )

            all_results.extend(results)

        all_services = []

        for address in resolution.addresses:
            open_ports = tuple(
                result.port
                for result in all_results
                if result.address == address and result.is_open
            )

            if not open_ports:
                continue

            services = detect_services(
                address=address,
                ports=open_ports,
                timeout=config.connect_timeout,
                max_workers=config.max_workers,
            )

            all_services.extend(services)

        report = TcpScanReport.create(
            session=session,
            resolved_addresses=resolution.addresses,
            ports_requested=ports,
            results=tuple(all_results),
            services=tuple(all_services),
        )

        store = ResultStore(config.results_dir)
        output_path = store.save_report(report)

        open_ports = report.open_ports

        logger.write(
            "scan.completed",
            session_id=report.session_id,
            target=report.target,
            target_type=report.target_type,
            scope=args.scope,
            ports=list(report.ports_requested),
            resolved_addresses=list(report.resolved_addresses),
            open_ports=[
                {
                    "address": result.address,
                    "port": result.port,
                }
                for result in open_ports
            ],
            status=report.status,
        )

        print(f"NightRecon scan target: {report.target}")
        print(f"Target type: {report.target_type}")
        print("Scope authorization: approved")

        print("Resolved addresses:")
        for address in report.resolved_addresses:
            print(f"  - {address}")

        print(f"Ports requested: {len(report.ports_requested)}")
        print(f"Open ports: {len(open_ports)}")

        for result in open_ports:
            print(f"  OPEN {result.address}:{result.port}")

        for service in report.services:
            print(
                f"  SERVICE {service.address}:{service.port} "
                f"{service.service}"
            )

            if service.banner:
                print(f"    Banner: {service.banner}")

        print(f"Session ID: {report.session_id}")
        print(f"Session status: {report.status}")
        print(f"Connection timeout: {config.connect_timeout}")
        print(f"Max workers: {config.max_workers}")
        print(f"Result file: {output_path}")


if __name__ == "__main__":
    main()