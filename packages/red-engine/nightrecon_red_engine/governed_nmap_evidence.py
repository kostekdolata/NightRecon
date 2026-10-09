"""Convert bounded governed Nmap command output into scoped evidence.

Only invoke after execution by the transactional command executor. Output is
still an unverified observation; Nmap service names do not confirm a CVE.
"""
from __future__ import annotations
import ipaddress
from .governed_command_runner import CommandOutcome
from .nmap_import import NmapEvidence, parse_nmap_xml

def parse_governed_nmap_result(*, outcome: CommandOutcome, target: str) -> NmapEvidence:
    expected = str(ipaddress.ip_address(target))
    if outcome.name != "nmap-bounded-connect" or outcome.returncode != 0:
        raise ValueError("Successful governed Nmap command required")
    evidence = parse_nmap_xml(outcome.stdout.encode("utf-8"))
    if not evidence.hosts:
        raise ValueError("Nmap returned no observed hosts")
    if any(host.address != expected for host in evidence.hosts):
        raise PermissionError("Nmap evidence contains out-of-scope host")
    if any(service.protocol != "tcp" or service.port not in (22,80,443)
           for host in evidence.hosts for service in host.services):
        raise PermissionError("Unexpected service observation outside bounded scan")
    return evidence
