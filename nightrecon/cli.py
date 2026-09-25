"""Command-line interface for NightRecon."""

import argparse
import os
import sys

from nightrecon import __version__
from nightrecon import report
from nightrecon import config
from nightrecon.asset_inventory import (
    AssetChangeEvent,
    apply_discovery_report,
    apply_scan_report,
)
from nightrecon.asset_inventory_store import AssetInventoryStore
from nightrecon.assessment_engine import (
    CheckIntrusiveness,
    CheckRegistry,
    assess_services,
    summarize_assessments,
)
from nightrecon.check_catalog import load_check_catalog
from nightrecon.check_feed import fetch_signed_check_feed
from nightrecon.check_pack_manager import (
    install_pack_from_verified_feed,
    plan_verified_check_feed,
    sync_verified_check_feed,
)
from nightrecon.check_pack_store import CheckPackStore
from nightrecon.check_pack_signing import (
    load_signed_check_pack_file,
    parse_trusted_key_specs,
)
from nightrecon.config import NightReconConfig
from nightrecon.cisa_kev_provider import CisaKevProvider
from nightrecon.discovery_report import HostDiscoveryReport
from nightrecon.epss_provider import FirstEpssProvider
from nightrecon.host_discovery import (
    discover_hosts,
    enrich_reverse_dns,
)
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
from nightrecon.threat_context import (
    enrich_threat_context,
    summarize_threat_context,
)
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

    assets_parser = subparsers.add_parser(
        "assets",
        help="Inspect the persistent NightRecon asset inventory.",
    )

    assets_subparsers = assets_parser.add_subparsers(
        dest="assets_command",
        title="asset commands",
    )

    assets_list_parser = assets_subparsers.add_parser(
        "list",
        help="List persistent assets without network activity.",
    )

    assets_list_parser.add_argument(
        "--inventory-dir",
        default="inventory",
        help=(
            "Persistent NightRecon asset inventory directory. "
            "Default: inventory"
        ),
    )

    assets_history_parser = assets_subparsers.add_parser(
        "history",
        help="Inspect persisted asset changes without network activity.",
    )

    assets_history_parser.add_argument(
        "--inventory-dir",
        default="inventory",
        help=(
            "Persistent NightRecon asset inventory directory. "
            "Default: inventory"
        ),
    )

    assets_history_parser.add_argument(
        "--address",
        help="Filter history by exact asset IP address.",
    )

    assets_history_parser.add_argument(
        "--limit",
        type=int,
        help="Return only the most recent N matching changes.",
    )

    checks_parser = subparsers.add_parser(
        "checks",
        help="Inspect installed assessment checks.",
    )

    checks_subparsers = checks_parser.add_subparsers(
        dest="checks_command",
        title="check commands",
    )

    checks_list_parser = checks_subparsers.add_parser(
        "list",
        help="List installed assessment checks.",
    )

    checks_list_parser.add_argument(
        "--check",
        action="append",
        dest="check_ids",
        help="Filter by exact check ID. May be repeated.",
    )

    checks_list_parser.add_argument(
        "--family",
        action="append",
        dest="check_families",
        help="Filter by check family. May be repeated.",
    )

    checks_list_parser.add_argument(
        "--tag",
        action="append",
        dest="check_tags",
        help="Filter by check tag. May be repeated.",
    )

    checks_list_parser.add_argument(
        "--check-pack",
        action="append",
        dest="check_pack_paths",
        help=(
            "Load a signed declarative check-pack JSON file. "
            "May be repeated."
        ),
    )

    checks_list_parser.add_argument(
        "--check-pack-key",
        action="append",
        dest="check_pack_keys",
        help=(
            "Trust an Ed25519 check-pack signer using "
            "KEY_ID=BASE64_PUBLIC_KEY. May be repeated."
        ),
    )

    checks_list_parser.add_argument(
        "--installed-check-packs",
        action="store_true",
        help=(
            "Load all active locally installed signed check packs."
        ),
    )

    checks_list_parser.add_argument(
        "--check-store-dir",
        default=".nightrecon",
        help=(
            "Local NightRecon state directory for installed packs. "
            "Default: .nightrecon"
        ),
    )

    checks_feed_parser = checks_subparsers.add_parser(
        "feed",
        help="Inspect a signed declarative check feed.",
    )

    checks_feed_parser.add_argument(
        "--url",
        help="HTTPS URL of the signed check-feed manifest.",
    )

    checks_feed_parser.add_argument(
        "--feed-key",
        action="append",
        dest="feed_keys",
        help=(
            "Trust an Ed25519 feed signer using "
            "KEY_ID=BASE64_PUBLIC_KEY. May be repeated."
        ),
    )

    checks_feed_parser.add_argument(
        "--install-pack",
        help=(
            "Install one advertised signed check pack into the local "
            "verified pack store."
        ),
    )

    checks_feed_parser.add_argument(
        "--pack-key",
        action="append",
        dest="feed_pack_keys",
        help=(
            "Trust a check-pack signer using "
            "KEY_ID=BASE64_PUBLIC_KEY. May be repeated."
        ),
    )

    checks_feed_parser.add_argument(
        "--store-dir",
        default=".nightrecon",
        help=(
            "Local NightRecon state directory for installed packs. "
            "Default: .nightrecon"
        ),
    )

    checks_feed_parser.add_argument(
        "--sync",
        action="store_true",
        help=(
            "Synchronize all advertised packs into the local verified "
            "pack store."
        ),
    )

    checks_feed_parser.add_argument(
        "--plan",
        action="store_true",
        help=(
            "Compare the verified feed with local installed-pack state "
            "without downloading or activating packs."
        ),
    )

    checks_feed_parser.add_argument(
        "--list-installed",
        action="store_true",
        help=(
            "List locally installed check packs without network access."
        ),
    )

    checks_feed_parser.add_argument(
        "--rollback-pack",
        help=(
            "Reverify and reactivate the previous cached version of one "
            "installed check pack without network access."
        ),
    )

    discover_parser = subparsers.add_parser(
        "discover",
        help="Discover responsive hosts in an authorized CIDR.",
    )

    discover_parser.add_argument(
        "target",
        help="Authorized CIDR target.",
    )

    discover_parser.add_argument(
        "--scope",
        action="append",
        required=True,
        help=(
            "Authorized scope rule. May be supplied multiple times. "
            "The discovery CIDR must be fully contained in scope."
        ),
    )

    discover_parser.add_argument(
        "--ports",
        default="22,80,443,445",
        help=(
            "TCP ports used only for host reachability evidence. "
            "Default: 22,80,443,445"
        ),
    )

    discover_parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-port connection timeout in seconds. Default: 1.0",
    )

    discover_parser.add_argument(
        "--workers",
        type=int,
        default=100,
        help="Maximum concurrent host probes. Default: 100",
    )

    discover_parser.add_argument(
        "--max-hosts",
        type=int,
        default=1024,
        help=(
            "Hard maximum number of host addresses permitted in one "
            "discovery run. Default: 1024"
        ),
    )

    discover_parser.add_argument(
        "--reverse-dns",
        action="store_true",
        help=(
            "Attempt fail-soft reverse-DNS enrichment for responsive "
            "hosts after TCP discovery."
        ),
    )

    discover_parser.add_argument(
        "--results-dir",
        default="results",
        help="Directory for result files. Default: results",
    )

    discover_parser.add_argument(
        "--logs-dir",
        default="logs",
        help="Directory for audit logs. Default: logs",
    )

    discover_parser.add_argument(
        "--update-inventory",
        action="store_true",
        help=(
            "Merge discovery evidence into the persistent asset inventory."
        ),
    )

    discover_parser.add_argument(
        "--inventory-dir",
        default="inventory",
        help=(
            "Persistent NightRecon asset inventory directory. "
            "Default: inventory"
        ),
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
        "--update-inventory",
        action="store_true",
        help=(
            "Merge scan evidence into the persistent asset inventory."
        ),
    )

    scan_parser.add_argument(
        "--inventory-dir",
        default="inventory",
        help=(
            "Persistent NightRecon asset inventory directory. "
            "Default: inventory"
        ),
    )

    scan_parser.add_argument(
        "--vuln-lookup",
        action="store_true",
        help=(
            "Query supported vulnerability intelligence providers for "
            "explicitly observed software identities. Disabled by default."
        ),
    )

    scan_parser.add_argument(
        "--threat-context",
        action="store_true",
        help=(
            "Enrich CVE findings with CISA KEV and FIRST EPSS evidence. "
            "Requires --vuln-lookup."
        ),
    )

    scan_parser.add_argument(
        "--assessment",
        action="store_true",
        help=(
            "Run the assessment-check engine against detected services. "
            "Disabled by default."
        ),
    )

    scan_parser.add_argument(
        "--check",
        action="append",
        dest="assessment_check_ids",
        help=(
            "Run only an exact assessment check ID. May be repeated. "
            "Requires --assessment."
        ),
    )

    scan_parser.add_argument(
        "--check-family",
        action="append",
        dest="assessment_check_families",
        help=(
            "Run only assessment checks in a family. May be repeated. "
            "Requires --assessment."
        ),
    )

    scan_parser.add_argument(
        "--check-tag",
        action="append",
        dest="assessment_check_tags",
        help=(
            "Run assessment checks matching a tag. May be repeated. "
            "Requires --assessment."
        ),
    )

    scan_parser.add_argument(
        "--max-check-intrusiveness",
        choices=(
            "passive",
            "safe-active",
            "intrusive",
        ),
        default="safe-active",
        help=(
            "Maximum assessment-check intrusiveness. "
            "Destructive checks are not available from this scan command. "
            "Default: safe-active"
        ),
    )

    scan_parser.add_argument(
        "--check-pack",
        action="append",
        dest="check_pack_paths",
        help=(
            "Load a signed declarative assessment check-pack. "
            "May be repeated. Requires --assessment."
        ),
    )

    scan_parser.add_argument(
        "--check-pack-key",
        action="append",
        dest="check_pack_keys",
        help=(
            "Trust an Ed25519 check-pack signer using "
            "KEY_ID=BASE64_PUBLIC_KEY. May be repeated. "
            "Requires --assessment."
        ),
    )

    scan_parser.add_argument(
        "--installed-check-packs",
        action="store_true",
        help=(
            "Load all active locally installed signed check packs. "
            "Requires --assessment and --check-pack-key."
        ),
    )

    scan_parser.add_argument(
        "--check-store-dir",
        default=".nightrecon",
        help=(
            "Local NightRecon state directory for installed packs. "
            "Default: .nightrecon"
        ),
    )

    return parser


def _load_requested_check_pack_checks(
    paths: tuple[str, ...],
    key_specs: tuple[str, ...],
) -> tuple[object, ...]:
    """Load explicitly requested signed declarative check packs."""

    trusted_keys = parse_trusted_key_specs(
        key_specs
    )
    checks: list[object] = []

    for path in paths:
        pack = load_signed_check_pack_file(
            path,
            trusted_keys=trusted_keys,
        )
        checks.extend(pack.checks)

    return tuple(checks)


def _load_installed_check_pack_checks(
    store_dir: str,
    key_specs: tuple[str, ...],
) -> tuple[object, ...]:
    """Load and reverify all active locally installed check packs."""

    trusted_keys = parse_trusted_key_specs(
        key_specs
    )

    if not trusted_keys:
        raise ValueError(
            "--installed-check-packs requires --check-pack-key."
        )

    store = CheckPackStore(
        store_dir
    )
    checks: list[object] = []

    for pack_id in store.list_pack_ids():
        pack = store.load_active(
            pack_id,
            trusted_keys=trusted_keys,
        )
        checks.extend(
            pack.checks
        )

    return tuple(checks)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "assets":
        if args.assets_command == "history":
            try:
                history = AssetInventoryStore(
                    args.inventory_dir
                ).load_change_history(
                    address=args.address,
                    limit=args.limit,
                )
            except ValueError as exc:
                parser.error(str(exc))

            print(f"Asset changes: {len(history)}")

            for event in history:
                change = event.change
                line = (
                    f"ASSET CHANGE {change.address} "
                    f"{change.change_type}"
                )

                if change.port is not None:
                    line += f" port={change.port}"

                if change.before:
                    line += f" before={change.before}"

                if change.after:
                    line += f" after={change.after}"

                line += (
                    f" source={event.source_type}"
                    f" session={event.session_id}"
                    f" observed_at={event.observed_at}"
                )
                print(line)

            return

        if args.assets_command != "list":
            parser.error(
                "The assets command requires a subcommand."
            )

        try:
            inventory = AssetInventoryStore(
                args.inventory_dir
            ).load()
        except ValueError as exc:
            parser.error(str(exc))

        print(f"Assets: {len(inventory.assets)}")

        for asset in inventory.assets:
            hostnames = (
                ",".join(asset.hostnames)
                if asset.hostnames
                else "-"
            )
            services = (
                ",".join(
                    (
                        f"{service.port}/{service.service}/"
                        f"{service.product or '-'}/"
                        f"{service.version or '-'}"
                    )
                    for service in asset.services
                )
                if asset.services
                else "-"
            )

            print(
                f"ASSET {asset.address} "
                f"hostnames={hostnames} "
                f"services={services}"
            )

        return

    if args.command == "checks":
        if args.checks_command == "feed":
            selected_actions = sum(
                bool(value)
                for value in (
                    args.install_pack,
                    args.sync,
                    args.plan,
                    args.list_installed,
                    args.rollback_pack,
                )
            )

            if selected_actions > 1:
                parser.error(
                    "Choose only one of --install-pack, --sync, --plan, "
                    "--list-installed, or --rollback-pack."
                )

            if args.list_installed:
                store = CheckPackStore(
                    args.store_dir
                )
                pack_ids = store.list_pack_ids()

                if not pack_ids:
                    print("No installed check packs.")

                for pack_id in pack_ids:
                    active = store.active_version(
                        pack_id
                    )
                    print(
                        f"Installed Pack: {pack_id} "
                        f"active={active or '-'}"
                    )

                    for record in store.list_versions(
                        pack_id
                    ):
                        marker = (
                            "yes"
                            if record.version == active
                            else "no"
                        )
                        print(
                            f"  version={record.version} "
                            f"active={marker} "
                            f"signer={record.signer_key_id or '-'} "
                            f"sha256={record.sha256 or '-'}"
                        )

                return

            if args.rollback_pack:
                if not args.feed_pack_keys:
                    parser.error(
                        "--rollback-pack requires --pack-key."
                    )

                try:
                    trusted_pack_keys = parse_trusted_key_specs(
                        tuple(args.feed_pack_keys or ())
                    )
                    store = CheckPackStore(
                        args.store_dir
                    )
                    restored = store.rollback_verified(
                        args.rollback_pack,
                        trusted_keys=trusted_pack_keys,
                    )
                except ValueError as exc:
                    parser.error(str(exc))

                print(
                    f"Rolled back: {args.rollback_pack} "
                    f"active={restored}"
                )
                return

            if not args.url:
                parser.error(
                    "--url is required unless using "
                    "--list-installed or --rollback-pack."
                )

            if not args.feed_keys:
                parser.error(
                    "--feed-key is required for feed operations."
                )

            if (
                (args.install_pack or args.sync)
                and not args.feed_pack_keys
            ):
                option = (
                    "--install-pack"
                    if args.install_pack
                    else "--sync"
                )
                parser.error(
                    f"{option} requires --pack-key."
                )

            try:
                trusted_feed_keys = parse_trusted_key_specs(
                    tuple(args.feed_keys or ())
                )
                feed = fetch_signed_check_feed(
                    args.url,
                    trusted_keys=trusted_feed_keys,
                )
            except ValueError as exc:
                parser.error(str(exc))

            print(
                f"Feed: {feed.feed_id} "
                f"generated_at={feed.generated_at or '-'}"
            )

            if not feed.packs:
                print("No check packs advertised.")

            for entry in feed.packs:
                print(
                    f"{entry.pack_id} "
                    f"version={entry.version} "
                    f"signer={entry.signer_key_id} "
                    f"sha256={entry.sha256} "
                    f"url={entry.url}"
                )

            if args.plan:
                try:
                    store = CheckPackStore(
                        args.store_dir
                    )
                    store.validate_feed(
                        feed,
                        source_url=args.url,
                    )
                    plans = plan_verified_check_feed(
                        feed=feed,
                        store=store,
                    )
                except ValueError as exc:
                    parser.error(str(exc))

                for plan in plans:
                    line = (
                        f"PLAN {plan.pack_id} "
                        f"status={plan.status} "
                        f"advertised={plan.advertised_version} "
                        f"active={plan.active_version or '-'} "
                        "download_required="
                        f"{'yes' if plan.download_required else 'no'}"
                    )

                    if plan.error:
                        line += f" error={plan.error}"

                    print(line)

            if args.install_pack:
                try:
                    trusted_pack_keys = parse_trusted_key_specs(
                        tuple(args.feed_pack_keys or ())
                    )
                    store = CheckPackStore(
                        args.store_dir
                    )
                    store.accept_feed(
                        feed,
                        source_url=args.url,
                    )
                    installed = install_pack_from_verified_feed(
                        feed=feed,
                        pack_id=args.install_pack,
                        pack_trusted_keys=trusted_pack_keys,
                        store=store,
                    )
                except ValueError as exc:
                    parser.error(str(exc))

                print(
                    f"Installed: {installed.pack_id} "
                    f"version={installed.version} "
                    f"signer={installed.signer_key_id} "
                    f"sha256={installed.sha256}"
                )

            if args.sync:
                try:
                    trusted_pack_keys = parse_trusted_key_specs(
                        tuple(args.feed_pack_keys or ())
                    )
                    store = CheckPackStore(
                        args.store_dir
                    )
                    store.accept_feed(
                        feed,
                        source_url=args.url,
                    )
                    sync_results = sync_verified_check_feed(
                        feed=feed,
                        pack_trusted_keys=trusted_pack_keys,
                        store=store,
                    )
                except ValueError as exc:
                    parser.error(str(exc))

                for result in sync_results:
                    line = (
                        f"SYNC {result.pack_id} "
                        f"status={result.status} "
                        f"advertised={result.advertised_version} "
                        f"previous={result.previous_version or '-'} "
                        f"active={result.active_version or '-'}"
                    )

                    if result.error:
                        line += f" error={result.error}"

                    print(line)

            return

        if args.checks_command != "list":
            parser.error(
                "The checks command requires a subcommand."
            )

        try:
            pack_checks = _load_requested_check_pack_checks(
                tuple(args.check_pack_paths or ()),
                tuple(args.check_pack_keys or ()),
            )
            installed_checks = (
                _load_installed_check_pack_checks(
                    args.check_store_dir,
                    tuple(args.check_pack_keys or ()),
                )
                if args.installed_check_packs
                else ()
            )
        except ValueError as exc:
            parser.error(str(exc))

        catalog = load_check_catalog(
            additional_checks=(
                pack_checks
                + installed_checks
            )
        )
        registry = CheckRegistry()
        plugin_errors = list(catalog.errors)

        for check in catalog.checks:
            try:
                registry.register(check)
            except ValueError as exc:
                plugin_errors.append(str(exc))

        selected = registry.select(
            check_ids=tuple(args.check_ids or ()),
            families=tuple(args.check_families or ()),
            tags=tuple(args.check_tags or ()),
        )

        if not selected:
            print("No assessment checks matched.")

        for check in selected:
            metadata = check.metadata
            tags = (
                ",".join(metadata.tags)
                if metadata.tags
                else "-"
            )
            services = (
                ",".join(metadata.supported_services)
                if metadata.supported_services
                else "*"
            )

            print(
                f"{metadata.check_id} "
                f"family={metadata.family} "
                "intrusiveness="
                f"{metadata.intrusiveness.value} "
                f"tags={tags} "
                f"services={services}"
            )

        for error in plugin_errors:
            print(
                f"Plugin error: {error}",
                file=sys.stderr,
            )

        return

    if args.command == "discover":
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

        logger = NightReconLogger(
            config.logs_dir
        )

        if not scope.is_authorized(target):
            logger.write(
                "discovery.rejected",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="outside_authorized_scope",
            )
            parser.error(
                f"Target '{target.value}' is outside the authorized scope."
            )

        if target.target_type != TargetType.CIDR:
            logger.write(
                "discovery.rejected",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason="cidr_required",
            )
            parser.error(
                "discover requires a CIDR target."
            )

        try:
            discovery_results = discover_hosts(
                cidr=target.value,
                ports=ports,
                timeout=config.connect_timeout,
                max_workers=config.max_workers,
                max_hosts=args.max_hosts,
            )

            if args.reverse_dns:
                discovery_results = enrich_reverse_dns(
                    discovery_results,
                    max_workers=config.max_workers,
                )
        except ValueError as exc:
            logger.write(
                "discovery.failed",
                target=target.value,
                target_type=target.target_type.value,
                scope=args.scope,
                reason=str(exc),
            )
            parser.error(str(exc))

        session = ScanSession.create(
            target=target,
            scope_rules=tuple(args.scope),
        )
        discovery_report = HostDiscoveryReport.create(
            session=session,
            ports_requested=ports,
            max_hosts=args.max_hosts,
            results=discovery_results,
        )
        store = ResultStore(
            config.results_dir
        )
        output_path = store.save_discovery_report(
            discovery_report
        )

        inventory_update = None
        inventory_path = None

        if args.update_inventory:
            try:
                inventory_store = AssetInventoryStore(
                    args.inventory_dir
                )
                current_inventory = inventory_store.load()
                inventory_update = apply_discovery_report(
                    current_inventory,
                    discovery_report,
                )
                inventory_path = inventory_store.save(
                    inventory_update.inventory
                )
                inventory_store.append_change_events(
                    tuple(
                        AssetChangeEvent(
                            observed_at=discovery_report.created_at,
                            session_id=discovery_report.session_id,
                            source_type="discovery",
                            change=change,
                        )
                        for change in inventory_update.changes
                    )
                )
            except ValueError as exc:
                parser.error(str(exc))

        logger.write(
            "discovery.completed",
            session_id=discovery_report.session_id,
            target=discovery_report.target,
            target_type=discovery_report.target_type,
            scope=args.scope,
            ports=list(
                discovery_report.ports_requested
            ),
            hosts_tested=len(
                discovery_report.results
            ),
            responsive_hosts=[
                result.address
                for result in discovery_report.responsive_hosts
            ],
            status=discovery_report.status,
        )

        print(
            "NightRecon discovery target: "
            f"{discovery_report.target}"
        )
        print(
            f"Target type: {discovery_report.target_type}"
        )
        print("Scope authorization: approved")
        print(
            "Discovery ports: "
            f"{','.join(str(port) for port in discovery_report.ports_requested)}"
        )
        print(
            f"Hosts tested: {len(discovery_report.results)}"
        )
        print(
            "Responsive hosts: "
            f"{len(discovery_report.responsive_hosts)}"
        )

        for result in discovery_report.responsive_hosts:
            port_text = (
                str(result.port)
                if result.port is not None
                else "-"
            )
            line = (
                f"  RESPONSIVE {result.address} "
                f"method={result.method} "
                f"observation={result.observation} "
                f"port={port_text}"
            )

            if result.hostname:
                line += (
                    f" hostname={result.hostname}"
                )

            print(line)

        print(
            f"Session ID: {discovery_report.session_id}"
        )
        print(
            f"Session status: {discovery_report.status}"
        )
        print(
            f"Connection timeout: {config.connect_timeout}"
        )
        print(
            f"Max workers: {config.max_workers}"
        )
        print(
            f"Max hosts: {args.max_hosts}"
        )
        print(
            f"Result file: {output_path}"
        )
        if inventory_update is not None:
            print(
                f"Inventory changes: {len(inventory_update.changes)}"
            )

            for change in inventory_update.changes:
                line = (
                    f"ASSET CHANGE {change.address} "
                    f"{change.change_type}"
                )

                if change.port is not None:
                    line += f" port={change.port}"

                if change.before:
                    line += f" before={change.before}"

                if change.after:
                    line += f" after={change.after}"

                print(line)

            print(
                f"Inventory file: {inventory_path}"
            )

        return

    if args.command == "scan":
        if (
            (
                args.assessment_check_ids
                or args.assessment_check_families
                or args.assessment_check_tags
            )
            and not args.assessment
        ):
            parser.error(
                "--check/--check-family/--check-tag require --assessment."
            )

        if (
            args.installed_check_packs
            and not args.assessment
        ):
            parser.error(
                "--installed-check-packs requires --assessment."
            )

        if (
            (
                args.check_pack_paths
                or args.check_pack_keys
            )
            and not args.assessment
        ):
            parser.error(
                "--check-pack/--check-pack-key require --assessment."
            )

        if (
            args.installed_check_packs
            and not args.check_pack_keys
        ):
            parser.error(
                "--installed-check-packs requires --check-pack-key."
            )

        if args.threat_context and not args.vuln_lookup:
            parser.error(
                "--threat-context requires --vuln-lookup."
            )

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

        all_assessments = ()
        assessment_catalog_errors = ()

        if args.assessment:
            try:
                pack_checks = _load_requested_check_pack_checks(
                    tuple(args.check_pack_paths or ()),
                    tuple(args.check_pack_keys or ()),
                )
                installed_checks = (
                    _load_installed_check_pack_checks(
                        args.check_store_dir,
                        tuple(args.check_pack_keys or ()),
                    )
                    if args.installed_check_packs
                    else ()
                )
            except ValueError as exc:
                parser.error(str(exc))

            catalog = load_check_catalog(
                additional_checks=(
                    pack_checks
                    + installed_checks
                )
            )
            assessment_catalog_errors = catalog.errors
            registry = CheckRegistry()

            for check in catalog.checks:
                registry.register(check)

            selected_checks = registry.select(
                check_ids=tuple(
                    args.assessment_check_ids or ()
                ),
                families=tuple(
                    args.assessment_check_families or ()
                ),
                tags=tuple(
                    args.assessment_check_tags or ()
                ),
            )

            all_assessments = assess_services(
                target=target.value,
                services=tuple(all_services),
                checks=selected_checks,
                max_intrusiveness=CheckIntrusiveness(
                    args.max_check_intrusiveness
                ),
                authorized=True,
            )

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

        all_threat_context = ()

        if args.threat_context:
            all_threat_context = enrich_threat_context(
                vulnerabilities=all_vulnerabilities,
                kev_provider=CisaKevProvider(),
                epss_provider=FirstEpssProvider(),
            )

        report = TcpScanReport.create(
            session=session,
            resolved_addresses=resolution.addresses,
            ports_requested=ports,
            results=tuple(all_results),
            services=tuple(all_services),
            assessment_enabled=args.assessment,
            assessment_catalog_errors=assessment_catalog_errors,
            assessments=all_assessments,
            vulnerability_intelligence_enabled=args.vuln_lookup,
            vulnerabilities=all_vulnerabilities,
            threat_context_enabled=args.threat_context,
            threat_context=all_threat_context,
        )

        store = ResultStore(config.results_dir)
        output_path = store.save_report(report)

        inventory_update = None
        inventory_path = None

        if args.update_inventory:
            try:
                inventory_store = AssetInventoryStore(
                    args.inventory_dir
                )
                current_inventory = inventory_store.load()
                inventory_update = apply_scan_report(
                    current_inventory,
                    report,
                )
                inventory_path = inventory_store.save(
                    inventory_update.inventory
                )
                inventory_store.append_change_events(
                    tuple(
                        AssetChangeEvent(
                            observed_at=report.created_at,
                            session_id=report.session_id,
                            source_type="scan",
                            change=change,
                        )
                        for change in inventory_update.changes
                    )
                )
            except ValueError as exc:
                parser.error(str(exc))

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


        for service_assessment in report.assessments:
            print(
                "  ASSESSMENT "
                f"{service_assessment.address}:"
                f"{service_assessment.port} "
                f"{service_assessment.service}"
            )

            for execution in service_assessment.executions:
                print(
                    "    CHECK "
                    f"{execution.check_id} "
                    f"status={execution.status}"
                )

                if execution.reason:
                    print(
                        "      Reason: "
                        f"{execution.reason}"
                    )

                if execution.error:
                    print(
                        "      Error: "
                        f"{execution.error}"
                    )

                for finding in execution.findings:
                    severity = (
                        finding.severity
                        or "unspecified"
                    )
                    print(
                        "      FINDING "
                        f"{finding.check_id} "
                        f"severity={severity}"
                    )
                    print(
                        "        Title: "
                        f"{finding.title}"
                    )
                    print(
                        "        Summary: "
                        f"{finding.summary}"
                    )

                    for evidence in finding.evidence:
                        print(
                            "        Evidence: "
                            f"{evidence}"
                        )

                    if finding.remediation:
                        print(
                            "        Remediation: "
                            f"{finding.remediation}"
                        )

        if report.assessment_enabled:
            assessment_summary = summarize_assessments(
                report.assessments
            )
            print(
                "Assessment Summary: "
                f"services={assessment_summary.services_assessed} "
                f"completed={assessment_summary.checks_completed} "
                f"skipped={assessment_summary.checks_skipped} "
                f"errors={assessment_summary.checks_errored} "
                f"findings={assessment_summary.findings}"
            )

            for error in report.assessment_catalog_errors:
                print(
                    "Assessment Catalog Error: "
                    f"{error}"
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

                if finding.match_basis:
                    details.append(
                        f"basis={finding.match_basis}"
                    )

                if finding.matched_identifier:
                    details.append(
                        "identifier="
                        f"{finding.matched_identifier}"
                    )

                print(" ".join(details))

        for context in report.threat_context:
            print(
                "  THREAT CONTEXT "
                f"{context.vulnerability_id} "
                "known_exploited="
                f"{'yes' if context.known_exploited else 'no'}"
            )

            if context.known_exploited:
                print(
                    "    KEV "
                    f"date_added={context.kev_date_added or 'unknown'} "
                    f"due_date={context.kev_due_date or 'unknown'}"
                )

                if context.kev_known_ransomware_campaign_use:
                    print(
                        "    KEV ransomware_use="
                        f"{context.kev_known_ransomware_campaign_use}"
                    )

                if context.kev_required_action:
                    print(
                        "    KEV required_action="
                        f"{context.kev_required_action}"
                    )

            if context.epss_probability is not None:
                print(
                    "    EPSS "
                    f"probability={context.epss_probability} "
                    f"percentile={context.epss_percentile} "
                    f"date={context.epss_date or 'unknown'}"
                )

            for error in context.errors:
                print(
                    "    Threat Context Error: "
                    f"{error}"
                )

        if report.threat_context_enabled:
            threat_summary = summarize_threat_context(
                report.threat_context
            )

            print(
                "Threat Context Summary: "
                f"cves={threat_summary.cves_enriched} "
                "known_exploited="
                f"{threat_summary.known_exploited_count} "
                "epss_available="
                f"{threat_summary.epss_available_count} "
                "provider_errors="
                f"{threat_summary.provider_error_count}"
            )

            if (
                threat_summary.max_epss_probability
                is not None
            ):
                print(
                    "Max EPSS: "
                    "probability="
                    f"{threat_summary.max_epss_probability} "
                    "percentile="
                    f"{threat_summary.max_epss_percentile}"
                )

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
        if inventory_update is not None:
            print(
                f"Inventory changes: {len(inventory_update.changes)}"
            )

            for change in inventory_update.changes:
                line = (
                    f"ASSET CHANGE {change.address} "
                    f"{change.change_type}"
                )

                if change.port is not None:
                    line += f" port={change.port}"

                if change.before:
                    line += f" before={change.before}"

                if change.after:
                    line += f" after={change.after}"

                print(line)

            print(
                f"Inventory file: {inventory_path}"
            )


    if __name__ == "__main__":
        main()
