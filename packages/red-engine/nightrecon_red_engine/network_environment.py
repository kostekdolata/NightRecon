"""Local route and interface awareness for Red Night network assessments.

Collection is deliberately read-only and uses fixed operating-system commands.
Parsing is separated from collection so tests stay deterministic and network-free.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import platform
import re
import socket
import subprocess


@dataclass(frozen=True)
class NetworkInterface:
    name: str
    index: int


@dataclass(frozen=True)
class RouteEntry:
    destination: str
    gateway: str = ""
    interface: str = ""
    metric: int | None = None
    family: str = "ipv4"


@dataclass(frozen=True)
class NetworkEnvironmentSnapshot:
    interfaces: tuple[NetworkInterface, ...]
    routes: tuple[RouteEntry, ...]
    default_routes: tuple[RouteEntry, ...]
    collection_errors: tuple[str, ...] = ()


def list_interfaces() -> tuple[NetworkInterface, ...]:
    """Return local interface names/indexes without sending network traffic."""
    values = socket.if_nameindex()
    return tuple(sorted(
        (NetworkInterface(name=name, index=index) for index, name in values),
        key=lambda item: (item.index, item.name),
    ))


def parse_linux_ip_route(text: str, *, family: str = "ipv4") -> tuple[RouteEntry, ...]:
    """Parse bounded Linux route-command output."""
    results: list[RouteEntry] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        destination = parts[0]
        if destination == "default":
            destination = "0.0.0.0/0" if family == "ipv4" else "::/0"
        try:
            ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        gateway = ""
        interface = ""
        metric: int | None = None
        if "via" in parts:
            index = parts.index("via")
            if index + 1 < len(parts):
                gateway = parts[index + 1]
        if "dev" in parts:
            index = parts.index("dev")
            if index + 1 < len(parts):
                interface = parts[index + 1]
        if "metric" in parts:
            index = parts.index("metric")
            if index + 1 < len(parts):
                try:
                    metric = int(parts[index + 1])
                except ValueError:
                    metric = None
        results.append(RouteEntry(
            destination=str(ipaddress.ip_network(destination, strict=False)),
            gateway=gateway,
            interface=interface,
            metric=metric,
            family=family,
        ))
    return tuple(results)


_WINDOWS_ROUTE_RE = re.compile(
    r"^\s*(?P<dest>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<mask>\d+\.\d+\.\d+\.\d+)\s+"
    r"(?P<gateway>\S+)\s+(?P<interface>\S+)\s+(?P<metric>\d+)\s*$"
)


def parse_windows_route_print(text: str) -> tuple[RouteEntry, ...]:
    """Parse IPv4 active routes from Windows route output."""
    results: list[RouteEntry] = []
    for line in text.splitlines():
        match = _WINDOWS_ROUTE_RE.match(line)
        if match is None:
            continue
        try:
            network = ipaddress.IPv4Network(
                (match.group("dest"), match.group("mask")),
                strict=False,
            )
        except (ValueError, ipaddress.NetmaskValueError):
            continue
        results.append(RouteEntry(
            destination=str(network),
            gateway=match.group("gateway"),
            interface=match.group("interface"),
            metric=int(match.group("metric")),
            family="ipv4",
        ))
    return tuple(results)


def _run_fixed(command: tuple[str, ...]) -> str:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"{command[0]} exited with code {completed.returncode}"
        )
    return completed.stdout


def collect_network_environment() -> NetworkEnvironmentSnapshot:
    """Collect local route/interface state without target network activity."""
    errors: list[str] = []
    try:
        interfaces = list_interfaces()
    except OSError as exc:
        interfaces = ()
        errors.append(f"interface collection failed: {type(exc).__name__}")

    routes: list[RouteEntry] = []
    system = platform.system().lower()
    if system == "linux":
        for command, family in (
            (("ip", "-4", "route", "show"), "ipv4"),
            (("ip", "-6", "route", "show"), "ipv6"),
        ):
            try:
                routes.extend(parse_linux_ip_route(
                    _run_fixed(command),
                    family=family,
                ))
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
                errors.append(
                    f"{family} route collection failed: {type(exc).__name__}"
                )
    elif system == "windows":
        try:
            routes.extend(parse_windows_route_print(
                _run_fixed(("route", "print", "-4"))
            ))
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
            errors.append(
                f"ipv4 route collection failed: {type(exc).__name__}"
            )
    else:
        errors.append(f"route collection unsupported on {system or 'unknown'}")

    ordered = tuple(sorted(
        routes,
        key=lambda item: (
            item.family,
            ipaddress.ip_network(item.destination, strict=False).prefixlen,
            item.destination,
            item.interface,
        ),
    ))
    defaults = tuple(
        item for item in ordered
        if item.destination in {"0.0.0.0/0", "::/0"}
    )
    return NetworkEnvironmentSnapshot(
        interfaces=interfaces,
        routes=ordered,
        default_routes=defaults,
        collection_errors=tuple(errors),
    )
