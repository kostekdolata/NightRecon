"""Persistent asset inventory and deterministic change tracking for NightRecon."""

from __future__ import annotations

from dataclasses import dataclass, replace
import ipaddress

from nightrecon.discovery_report import HostDiscoveryReport
from nightrecon.report import TcpScanReport
from nightrecon.service_detection import ServiceDetectionResult


@dataclass(frozen=True)
class AssetServiceRecord:
    """Latest observed state for one TCP service on an asset."""

    port: int
    service: str
    product: str = ""
    version: str = ""
    tls_certificate_sha256: str = ""


@dataclass(frozen=True)
class AssetRecord:
    """Persistent evidence-backed record for one IP asset."""

    address: str
    first_seen: str
    last_seen: str
    last_checked_at: str
    hostnames: tuple[str, ...] = ()
    last_discovery_responsive: bool | None = None
    discovery_methods: tuple[str, ...] = ()
    services: tuple[AssetServiceRecord, ...] = ()
    source_session_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AssetChange:
    """One deterministic change observed while updating the inventory."""

    address: str
    change_type: str
    port: int | None = None
    before: str = ""
    after: str = ""


@dataclass(frozen=True)
class AssetChangeEvent:
    """Persisted change event produced by one NightRecon observation."""

    observed_at: str
    session_id: str
    source_type: str
    change: AssetChange


@dataclass(frozen=True)
class AssetInventory:
    """Current persistent NightRecon asset state."""

    assets: tuple[AssetRecord, ...] = ()
    schema_version: int = 1
    updated_at: str = ""

    @classmethod
    def empty(cls) -> "AssetInventory":
        return cls()


@dataclass(frozen=True)
class AssetInventoryUpdate:
    """Updated inventory plus changes produced by one observation."""

    inventory: AssetInventory
    changes: tuple[AssetChange, ...]


def apply_discovery_report(
    inventory: AssetInventory,
    report: HostDiscoveryReport,
) -> AssetInventoryUpdate:
    """Merge one host-discovery report into the asset inventory."""

    assets = {
        asset.address: asset
        for asset in inventory.assets
    }
    changes: list[AssetChange] = []

    for result in report.results:
        existing = assets.get(result.address)

        if existing is None and not result.responsive:
            continue

        if existing is None:
            hostnames = (
                (result.hostname,)
                if result.hostname
                else ()
            )
            assets[result.address] = AssetRecord(
                address=result.address,
                first_seen=report.created_at,
                last_seen=report.created_at,
                last_checked_at=report.created_at,
                hostnames=hostnames,
                last_discovery_responsive=True,
                discovery_methods=(result.method,),
                source_session_ids=(report.session_id,),
            )
            changes.append(
                AssetChange(
                    address=result.address,
                    change_type="new-asset",
                )
            )
            continue

        hostnames = existing.hostnames
        if (
            result.hostname
            and result.hostname not in hostnames
        ):
            hostnames = hostnames + (result.hostname,)
            changes.append(
                AssetChange(
                    address=result.address,
                    change_type="hostname-added",
                    after=result.hostname,
                )
            )

        methods = _append_unique(
            existing.discovery_methods,
            result.method,
        )
        sessions = _append_unique(
            existing.source_session_ids,
            report.session_id,
        )

        if result.responsive:
            if existing.last_discovery_responsive is False:
                changes.append(
                    AssetChange(
                        address=result.address,
                        change_type="host-responsive",
                    )
                )

            assets[result.address] = replace(
                existing,
                last_seen=report.created_at,
                last_checked_at=report.created_at,
                hostnames=hostnames,
                last_discovery_responsive=True,
                discovery_methods=methods,
                source_session_ids=sessions,
            )
        else:
            if existing.last_discovery_responsive is True:
                changes.append(
                    AssetChange(
                        address=result.address,
                        change_type="host-unresponsive",
                    )
                )

            assets[result.address] = replace(
                existing,
                last_checked_at=report.created_at,
                hostnames=hostnames,
                last_discovery_responsive=False,
                discovery_methods=methods,
                source_session_ids=sessions,
            )

    return AssetInventoryUpdate(
        inventory=AssetInventory(
            assets=_sorted_assets(
                tuple(assets.values())
            ),
            schema_version=inventory.schema_version,
            updated_at=report.created_at,
        ),
        changes=tuple(changes),
    )


def apply_scan_report(
    inventory: AssetInventory,
    report: TcpScanReport,
) -> AssetInventoryUpdate:
    """Merge one completed TCP scan report into the asset inventory."""

    assets = {
        asset.address: asset
        for asset in inventory.assets
    }
    changes: list[AssetChange] = []

    services_by_key = {
        (service.address, service.port): service
        for service in report.services
    }

    for address in report.resolved_addresses:
        port_results = tuple(
            result
            for result in report.results
            if result.address == address
        )
        open_ports = {
            result.port
            for result in port_results
            if result.is_open
        }
        existing = assets.get(address)

        if existing is None and not open_ports:
            continue

        if existing is None:
            hostnames = (
                (report.target,)
                if report.target_type == "hostname"
                else ()
            )
            existing = AssetRecord(
                address=address,
                first_seen=report.created_at,
                last_seen=report.created_at,
                last_checked_at=report.created_at,
                hostnames=hostnames,
                source_session_ids=(report.session_id,),
            )
            assets[address] = existing
            changes.append(
                AssetChange(
                    address=address,
                    change_type="new-asset",
                )
            )

        old_services = {
            service.port: service
            for service in existing.services
        }
        new_services = dict(old_services)
        requested_ports = {
            result.port
            for result in port_results
        }

        for port in sorted(requested_ports):
            if port in open_ports:
                detected = services_by_key.get(
                    (address, port)
                )
                observed = _service_record(
                    port,
                    detected,
                )
                previous = old_services.get(port)

                if previous is None:
                    changes.append(
                        AssetChange(
                            address=address,
                            change_type="port-opened",
                            port=port,
                            after=observed.service,
                        )
                    )
                else:
                    if previous.service != observed.service:
                        changes.append(
                            AssetChange(
                                address=address,
                                change_type="service-changed",
                                port=port,
                                before=previous.service,
                                after=observed.service,
                            )
                        )

                    previous_software = _software_text(
                        previous
                    )
                    observed_software = _software_text(
                        observed
                    )

                    if (
                        previous_software
                        != observed_software
                        and (
                            previous_software
                            or observed_software
                        )
                    ):
                        changes.append(
                            AssetChange(
                                address=address,
                                change_type="software-changed",
                                port=port,
                                before=previous_software,
                                after=observed_software,
                            )
                        )

                new_services[port] = observed
            elif port in old_services:
                previous = old_services[port]
                changes.append(
                    AssetChange(
                        address=address,
                        change_type="port-closed",
                        port=port,
                        before=previous.service,
                    )
                )
                new_services.pop(port, None)

        hostnames = existing.hostnames
        if (
            report.target_type == "hostname"
            and report.target not in hostnames
        ):
            hostnames = hostnames + (report.target,)
            changes.append(
                AssetChange(
                    address=address,
                    change_type="hostname-added",
                    after=report.target,
                )
            )

        sessions = _append_unique(
            existing.source_session_ids,
            report.session_id,
        )

        assets[address] = replace(
            existing,
            last_seen=(
                report.created_at
                if open_ports
                else existing.last_seen
            ),
            last_checked_at=report.created_at,
            hostnames=hostnames,
            services=tuple(
                sorted(
                    new_services.values(),
                    key=lambda item: item.port,
                )
            ),
            source_session_ids=sessions,
        )

    return AssetInventoryUpdate(
        inventory=AssetInventory(
            assets=_sorted_assets(
                tuple(assets.values())
            ),
            schema_version=inventory.schema_version,
            updated_at=report.created_at,
        ),
        changes=tuple(changes),
    )


def _service_record(
    port: int,
    detected: ServiceDetectionResult | None,
) -> AssetServiceRecord:
    if detected is None:
        return AssetServiceRecord(
            port=port,
            service="unknown",
        )

    product = ""
    version = ""

    if detected.software_identity is not None:
        product = detected.software_identity.product
        version = detected.software_identity.version

    return AssetServiceRecord(
        port=port,
        service=detected.service,
        product=product,
        version=version,
        tls_certificate_sha256=(
            detected.tls_certificate_sha256
        ),
    )


def _software_text(
    service: AssetServiceRecord,
) -> str:
    if service.product and service.version:
        return f"{service.product} {service.version}"

    return service.product or service.version


def _append_unique(
    values: tuple[str, ...],
    value: str,
) -> tuple[str, ...]:
    if not value or value in values:
        return values

    return values + (value,)


def _sorted_assets(
    assets: tuple[AssetRecord, ...],
) -> tuple[AssetRecord, ...]:
    return tuple(
        sorted(
            assets,
            key=lambda asset: ipaddress.ip_address(
                asset.address
            ),
        )
    )
