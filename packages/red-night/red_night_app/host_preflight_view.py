"""Bounded, read-only desktop presentation of local host preflight results.

Only approved inventory fields reach the widget: no executable paths, tokens,
raw errors, untrusted process output or automatically authorised scan targets.
"""
from __future__ import annotations

import ipaddress


def describe_host_preflight(report: dict) -> str:
    """Create a compact human-readable host snapshot without launching tools."""
    if not isinstance(report, dict) or report.get("schema") != 1:
        return "Host preflight unavailable (unsupported result)."
    lines = [
        "PASSIVE LOCAL HOST PREFLIGHT",
        f"OS: {str(report.get('os') or 'unknown')[:64]}  /  "
        f"Architecture: {str(report.get('architecture') or 'unknown')[:64]}",
        f"Collected: {str(report.get('collected_at') or 'unknown')[:48]}",
        "Interface addresses (discovered, not approved targets):",
    ]
    for record in (report.get("addresses") or [])[:16]:
        if not isinstance(record, dict):
            continue
        try:
            address = str(ipaddress.ip_address(str(record.get("address", ""))))
        except ValueError:
            continue
        family = "IPv6" if ":" in address else "IPv4"
        label = str(record.get("interface") or "unknown")[:48]
        lines.append(f"  {label}: {family} {address}")
    if len(lines) == 4:
        lines.append("  No interface IP addresses available")
    lines.append("Local routes:")
    route_count = 0
    for record in (report.get("routes") or [])[:10]:
        if not isinstance(record, dict):
            continue
        try:
            network = str(ipaddress.ip_network(str(record.get("destination")), strict=False))
        except ValueError:
            continue
        route_count += 1
        lines.append(f"  {network}")
    if route_count == 0:
        lines.append("  No usable route data")
    lines.append("Installed tool candidates (not execution-approved):")
    for tool in (report.get("tools") or [])[:10]:
        if not isinstance(tool, dict) or tool.get("tool") not in ("nmap", "tshark", "nuclei"):
            continue
        state = tool.get("state")
        lines.append(f"  {tool['tool']}: {state if state in ('missing', 'unverified-present') else 'unknown'}")
    warnings = report.get("errors") or []
    lines.append(f"Collection warnings: {min(len(warnings), 128)}")
    lines.append("No network scan performed. Detected addresses do not grant scope.")
    return "\n".join(lines)
