"""Read-only comparison of Nmap observations. Never initiates network activity."""
from dataclasses import dataclass
from .nmap_import import NmapEvidence

@dataclass(frozen=True)
class PortChange:
    address: str
    protocol: str
    port: int
    before: str
    after: str

def compare_nmap_scans(before: NmapEvidence, after: NmapEvidence, allowed_addresses: frozenset[str]) -> tuple[PortChange, ...]:
    def index(snapshot):
        return {(host.address, service.protocol, service.port): service.state
                for host in snapshot.hosts if host.address in allowed_addresses
                for service in host.services}
    old, new = index(before), index(after)
    return tuple(PortChange(*key, old.get(key, "not-observed"), new.get(key, "not-observed"))
                 for key in sorted(old.keys() | new.keys()) if old.get(key) != new.get(key))
