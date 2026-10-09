"""Read-only correlation of imported third-party evidence.

This does not modify Red Night's authoritative asset inventory. It intentionally
does not infer exploitability, vulnerability or ownership from imported data.
"""
from __future__ import annotations
from dataclasses import dataclass
import ipaddress

from .nmap_import import NmapEvidence
from .pcap_import import PcapEvidence
from .metasploit_catalogue import MetasploitCatalogue


@dataclass(frozen=True)
class HostEvidence:
    address: str
    discovered_by_nmap: bool
    observed_in_pcap: bool
    services: tuple[tuple[str, int, str, str], ...]


@dataclass(frozen=True)
class EvidenceSummary:
    status: str
    hosts: tuple[HostEvidence, ...]
    module_references: tuple[str, ...]
    sources: tuple[str, ...]


def correlate_imports(
    nmap: NmapEvidence | None = None,
    pcap: PcapEvidence | None = None,
    modules: MetasploitCatalogue | None = None,
    allowed_addresses: frozenset[str] = frozenset(),
) -> EvidenceSummary:
    """Correlate only exact, authorised IPs; empty allowlist admits nothing.

    This is not a scope-authorisation service: caller must obtain its allowlist
    from Red Night's existing engagement policy, never from third-party input.
    """
    allowed = frozenset(str(ipaddress.ip_address(a)) for a in allowed_addresses)
    records: dict[str, dict] = {}
    sources = []
    if nmap is not None:
        sources.append(nmap.source)
        for host in nmap.hosts:
            if host.address not in allowed:
                continue
            rec = records.setdefault(host.address, {"nmap": False, "pcap": False, "services": set()})
            rec["nmap"] = True
            for svc in host.services:
                rec["services"].add((svc.protocol, svc.port, svc.state, svc.name))
    if pcap is not None:
        sources.append(pcap.source)
        for conversation in pcap.conversations:
            for address in (conversation.source, conversation.destination):
                if address not in allowed:
                    continue
                rec = records.setdefault(address, {"nmap": False, "pcap": False, "services": set()})
                rec["pcap"] = True
    refs = set()
    if modules is not None:
        sources.append(modules.source)
        for module in modules.modules:
            refs.update(module.references)
    hosts = tuple(
        HostEvidence(ip, row["nmap"], row["pcap"], tuple(sorted(row["services"])))
        for ip, row in sorted(records.items())
    )
    return EvidenceSummary(
        status="unverified-imported-evidence",
        hosts=hosts,
        module_references=tuple(sorted(refs)),
        sources=tuple(sources),
    )
