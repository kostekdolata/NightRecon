"""Command-line interface for NightRecon."""

import argparse
import os

from nightrecon import __version__
from nightrecon import report
from nightrecon import config
from nightrecon.config import NightReconConfig
from nightrecon.logging import NightReconLogger
from nightrecon.nvd_provider import NvdVulnerabilityProvider
from nightrecon.ports import parse_ports
from nightrecon.report import TcpScanReport
from nightrecon.resolver import resolve_target
from nightrecon.scope import Scope
from nightrecon.service_detection import detect_services
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import TargetType, parse_target
from nightrecon.tcp_scanner import scan_tcp_ports
from nightrecon.vulnerability_intelligence import (
    enrich_service_vulnerabilities,
    summarize_vulnerabilities,
)


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

    scan_parser.add_argument(
        "--vuln-lookup",
        action="store_true",
        help=(
            "Query supported vulnerability intelligence providers for "
            "explicitly observed software identities. Disabled by default."
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

            if target.target_type == TargetType.HOSTNAME:
                services = detect_services(
                    address=address,
                    ports=open_ports,
                    timeout=config.connect_timeout,
                    max_workers=config.max_workers,
                    server_hostname=target.value,
            )
            else:
                services = detect_services(
                    address=address,
                    ports=open_ports,
                    timeout=config.connect_timeout,
                    max_workers=config.max_workers,
        )

            all_services.extend(services)

        all_vulnerabilities = ()

        if args.vuln_lookup:
            provider = NvdVulnerabilityProvider(
                api_key=os.environ.get(
                    "NIGHTRECON_NVD_API_KEY"
                ),
            )
            all_vulnerabilities = enrich_service_vulnerabilities(
                provider=provider,
                services=tuple(all_services),
            )

        report = TcpScanReport.create(
            session=session,
            resolved_addresses=resolution.addresses,
            ports_requested=ports,
            results=tuple(all_results),
            services=tuple(all_services),
            vulnerability_intelligence_enabled=args.vuln_lookup,
            vulnerabilities=all_vulnerabilities,
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

            if service.http_status:
                print(f"    HTTP Status: {service.http_status}")

            if service.http_server:
                print(f"    Server: {service.http_server}")

            if service.software_identity is not None:
                print(
                    "    Software: "
                    f"{service.software_identity.product} "
                    f"{service.software_identity.version}"
                )

            if service.security_headers_present:
                print(
                    "    Security Headers Present: "
                    f"{', '.join(service.security_headers_present)}"
                )

            if service.security_headers_missing:
                print(
                    "    Security Headers Missing: "
                    f"{', '.join(service.security_headers_missing)}"
                )

            if service.tls_version:
                print(f"    TLS Version: {service.tls_version}")

            if service.tls_cipher:
                print(f"    TLS Cipher: {service.tls_cipher}")

            if service.tls_certificate_subject:
                print(
                    "    Certificate Subject: "
                    f"{service.tls_certificate_subject}"
                )

            if service.tls_certificate_issuer:
                print(
                    "    Certificate Issuer: "
                    f"{service.tls_certificate_issuer}"
                )

            if service.tls_certificate_not_before:
                print(
                    "    Certificate Valid From: "
                    f"{service.tls_certificate_not_before}"
                )

            if service.tls_certificate_not_after:
                print(
                    "    Certificate Valid Until: "
                    f"{service.tls_certificate_not_after}"
                )
            if service.tls_certificate_sans:
                print(
                    "    Certificate SANs: "
                    f"{', '.join(service.tls_certificate_sans)}"
                )
            if service.tls_certificate_sha256:
                print(
                    "    Certificate SHA-256: "
                    f"{service.tls_certificate_sha256}"
                )


        for vulnerability in report.vulnerabilities:
            lookup = vulnerability.lookup

            if lookup.error:
                print(
                    f"  VULN INTEL {vulnerability.address}:"
                    f"{vulnerability.port} {vulnerability.service} "
                    f"provider={lookup.provider} "
                    f"error={lookup.error}"
                )
                continue

            print(
                f"  VULN INTEL {vulnerability.address}:"
                f"{vulnerability.port} {vulnerability.service} "
                f"provider={lookup.provider} "
                f"matches={len(lookup.findings)}"
            )

            for finding in lookup.findings:
                details = [
                    f"    {finding.vulnerability_id}",
                ]

                if finding.severity:
                    details.append(
                        f"severity={finding.severity}"
                    )

                if finding.cvss_score is not None:
                    details.append(
                        f"cvss={finding.cvss_score}"
                    )

                print(" ".join(details))

        if report.vulnerability_intelligence_enabled:
            vulnerability_summary = summarize_vulnerabilities(
                report.vulnerabilities
            )

            print(
                "Vulnerability Summary: "
                f"services={vulnerability_summary.services_queried} "
                f"successful={vulnerability_summary.successful_lookups} "
                f"failed={vulnerability_summary.failed_lookups} "
                f"matches={vulnerability_summary.total_findings}"
            )
            print(
                "Severity: "
                f"critical={vulnerability_summary.critical_count} "
                f"high={vulnerability_summary.high_count} "
                f"medium={vulnerability_summary.medium_count} "
                f"low={vulnerability_summary.low_count} "
                f"none={vulnerability_summary.none_count} "
                f"unknown={vulnerability_summary.unknown_count}"
            )

            if vulnerability_summary.max_cvss_score is not None:
                print(
                    "Max CVSS observed: "
                    f"{vulnerability_summary.max_cvss_score}"
                )

        print(f"Session ID: {report.session_id}")
        print(f"Session status: {report.status}")
        print(f"Connection timeout: {config.connect_timeout}")
        print(f"Max workers: {config.max_workers}")
        print(f"Result file: {output_path}")

    if __name__ == "__main__":
        main()
