"""Passive local-host intelligence and explicitly filtered tool readiness.

This collects no credentials, process arguments, documents or network targets.
No pentesting executable is launched, and discovered IPs are NEVER authorised
assessment targets by virtue of appearing in this snapshot.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import ipaddress
import importlib
import socket
import platform
import shutil

from .network_environment import collect_network_environment

TOOL_COMMANDS = {
    "nmap": ("nmap.exe", "nmap"),
    "tshark": ("tshark.exe", "tshark"),
    "nuclei": ("nuclei.exe", "nuclei"),
}
TOOL_REQUIREMENTS = {
    "nmap": ("os", "architecture", "interfaces", "addresses", "routes", "tool_candidate"),
    "tshark": ("os", "architecture", "interfaces", "addresses", "tool_candidate"),
    "nuclei": ("os", "architecture", "addresses", "routes", "tool_candidate"),
    "zap": ("os", "architecture", "local_service_configuration"),
    "metasploit": ("os", "architecture", "local_service_configuration"),
}
SCHEMA = 1
MAX_ITEMS = 128


@dataclass(frozen=True)
class HostToolCandidate:
    tool: str
    path: str | None
    state: str
    provenance: str

    def as_dict(self) -> dict:
        return {
            "tool": self.tool,
            "path": self.path,
            "state": self.state,
            "provenance": self.provenance,
            "trusted_for_execution": False,
        }


@dataclass(frozen=True)
class HostPreflightSnapshot:
    schema: int
    collected_at: str
    os: str
    architecture: str
    interfaces: tuple[dict, ...]
    addresses: tuple[dict, ...]
    routes: tuple[dict, ...]
    candidates: tuple[HostToolCandidate, ...]
    errors: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "schema": self.schema, "collected_at": self.collected_at,
            "os": self.os, "architecture": self.architecture,
            "interfaces": list(self.interfaces), "addresses": list(self.addresses),
            "routes": list(self.routes),
            "tools": [c.as_dict() for c in self.candidates],
            "errors": list(self.errors),
            "scope_authorisation_inferred": False,
            "network_scan_performed": False,
            "limitations": [
                "Discovered addresses, routes and binaries are not approved scan targets or trusted executables.",
                "No process, privileged service, tool version command or network probe was started.",
                "Interface IP addresses require a locally available collector and may be incomplete.",
            ],
        }


def collect_host_preflight() -> HostPreflightSnapshot:
    """Collect bounded local metadata only, without probing external targets."""
    errors: list[str] = []
    try:
        network = collect_network_environment()
        errors.extend(network.collection_errors[:MAX_ITEMS])
        interfaces = tuple(
            {"name": i.name[:128], "index": i.index, "source": "local-interface-index"}
            for i in network.interfaces[:MAX_ITEMS]
        )
        routes = []
        for item in network.routes[:MAX_ITEMS]:
            try:
                destination = str(ipaddress.ip_network(item.destination, strict=False))
                try:
                    gateway = str(ipaddress.ip_address(item.gateway)) if item.gateway else None
                except ValueError:
                    gateway = None  # Windows on-link routes have no gateway address.
            except ValueError:
                errors.append("Invalid local route metadata omitted")
                continue
            routes.append({
                "destination": destination, "gateway": gateway,
                "interface": item.interface[:128], "family": item.family,
                "metric": item.metric, "source": "local-route-table",
            })
    except (OSError, ValueError, RuntimeError) as exc:
        interfaces = ()
        routes = []
        errors.append("Local network inventory unavailable: " + type(exc).__name__)
    addresses: list[dict] = []
    try:
        psutil = importlib.import_module("psutil")
        for name, values in sorted(psutil.net_if_addrs().items())[:MAX_ITEMS]:
            for item in values[:MAX_ITEMS]:
                if item.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                try:
                    addr = str(ipaddress.ip_address(item.address.split("%", 1)[0]))
                except ValueError:
                    errors.append("Invalid interface address omitted")
                    continue
                addresses.append({
                    "interface": name[:128], "address": addr,
                    "family": "ipv4" if item.family == socket.AF_INET else "ipv6",
                    "source": "local-interface-api",
                })
                if len(addresses) >= MAX_ITEMS:
                    break
            if len(addresses) >= MAX_ITEMS:
                break
    except (ImportError, AttributeError):
        errors.append("Interface IP address collector unavailable: optional psutil not installed")
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append("Interface IP address collector failed: " + type(exc).__name__)
    candidates = []
    for tool, commands in TOOL_COMMANDS.items():
        found = None
        for executable in commands:
            found = shutil.which(executable)
            if found:
                break
        if found:
            try:
                path = Path(found).resolve(strict=True)
                if not path.is_file():
                    found = None
                else:
                    found = str(path)
            except OSError:
                found = None
        candidates.append(HostToolCandidate(
            tool, found, "unverified-present" if found else "missing",
            "local-path-lookup-only",
        ))
    return HostPreflightSnapshot(
        schema=SCHEMA, collected_at=datetime.now(timezone.utc).isoformat(),
        os=platform.system()[:64], architecture=platform.machine()[:64],
        interfaces=interfaces, addresses=tuple(addresses), routes=tuple(routes),
        candidates=tuple(candidates), errors=tuple(errors[:MAX_ITEMS]),
    )


def route_host_context(snapshot: HostPreflightSnapshot, tool: str) -> dict:
    """Give a module only its approved fields, never unrestricted host state."""
    if tool not in TOOL_REQUIREMENTS:
        raise ValueError("Unsupported host-context consumer")
    fields = TOOL_REQUIREMENTS[tool]
    context = snapshot.as_dict()
    result = {"schema": snapshot.schema, "collected_at": snapshot.collected_at,
              "consumer": tool, "authorised_targets": [],
              "execution_approval": False}
    for field in fields:
        if field == "tool_candidate":
            result["tool_candidate"] = next(
                (c.as_dict() for c in snapshot.candidates if c.tool == tool),
                {"tool": tool, "state": "missing", "trusted_for_execution": False},
            )
        elif field == "local_service_configuration":
            result[field] = "not-probed"
        else:
            result[field] = context[field]
    return result


def assess_tool_readiness(snapshot: HostPreflightSnapshot, tool: str) -> dict:
    """Bounded per-tool readiness from passive facts, never execution authority.

    This result can be consumed by desktop UI and plan preparation. It cannot
    satisfy transactional authorisation, executable provenance, or approvals.
    """
    context = route_host_context(snapshot, tool)
    candidate = context.get("tool_candidate")
    interfaces = context.get("interfaces", [])
    addresses = context.get("addresses", [])
    routes = context.get("routes", [])
    facts = {
        "interface_count": len(interfaces),
        "address_count": len(addresses),
        "route_count": len(routes),
        "observed_address_families": sorted({
            record.get("family") for record in addresses
            if isinstance(record, dict)
            and record.get("family") in ("ipv4", "ipv6")
        }),
    }
    missing = []
    required = []
    if tool in TOOL_COMMANDS:
        required.extend(("approved-tool-digest", "registered-engagement"))
        if candidate is None or candidate["state"] != "unverified-present":
            missing.append("tool-executable-not-discovered")
        if tool == "tshark":
            required.extend(("operator-selected-offline-capture", "capture-root"))
        else:
            required.append("operator-approved-exact-target")
            if tool == "nuclei":
                required.append("operator-approved-http-origin")
        status = "missing-dependency" if missing else "unverified"
    else:
        required.extend(("operator-configured-loopback-endpoint", "protected-api-secret"))
        if tool == "metasploit":
            required.append("trusted-local-rpc-tls")
        status = "not-probed"
    return {
        **context,
        "readiness": {
            "state": status,
            "tool": tool,
            "observed_facts": facts,
            "required_before_execution": required,
            "missing_dependencies": missing,
            "executable_trust_confirmed": False,
            "engagement_scope_confirmed": False,
            "approval_confirmed": False,
            "network_scan_performed": False,
            "limitations": [
                "Passive host discovery is not an executable provenance check.",
                "Discovered local or VPN addresses are not automatically eligible scan targets.",
                "All actions still require independent live policy checks.",
            ],
        },
    }
