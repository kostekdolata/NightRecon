"""Compatibility re-export for the Red Night host discovery engine."""

from nightrecon.red_host_discovery import (
    HostDiscoveryResult,
    discover_hosts,
    enrich_reverse_dns,
    probe_host,
)

__all__ = [
    "HostDiscoveryResult",
    "discover_hosts",
    "enrich_reverse_dns",
    "probe_host",
]
