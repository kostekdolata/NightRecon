"""Red Night ownership facade for existing bounded host discovery."""

from nightrecon.host_discovery import (
    HostDiscoveryResult,
    discover_hosts,
    enrich_reverse_dns,
    probe_host,
)

__all__ = ["HostDiscoveryResult", "discover_hosts", "enrich_reverse_dns", "probe_host"]
