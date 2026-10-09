"""Bounded, passive import of Nmap XML observations.

This adapter never runs Nmap, opens sockets, or modifies Red Night's scan engine.
Imported service names and versions remain unverified third-party observations.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
from pathlib import Path
import xml.etree.ElementTree as ET

MAX_XML_BYTES = 8 * 1024 * 1024
MAX_HOSTS = 4096
MAX_PORTS_PER_HOST = 4096


@dataclass(frozen=True)
class ImportedService:
    protocol: str
    port: int
    state: str
    name: str
    product: str
    version: str


@dataclass(frozen=True)
class ImportedHost:
    address: str
    status: str
    services: tuple[ImportedService, ...]


@dataclass(frozen=True)
class NmapEvidence:
    source: str
    hosts: tuple[ImportedHost, ...]


def parse_nmap_xml(data: bytes) -> NmapEvidence:
    """Parse an untrusted, size-bounded Nmap XML export without side effects."""
    if len(data) > MAX_XML_BYTES:
        raise ValueError("Nmap XML exceeds the configured size limit.")
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("DTD and entities are prohibited in Nmap XML.")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError("Invalid Nmap XML document.") from exc
    if root.tag != "nmaprun":
        raise ValueError("Expected an Nmap nmaprun XML document.")

    host_elements = root.findall("host")
    if len(host_elements) > MAX_HOSTS:
        raise ValueError("Too many hosts in Nmap XML.")

    hosts = []
    for host in host_elements:
        status_node = host.find("status")
        status = status_node.get("state", "unknown") if status_node is not None else "unknown"
        address = ""
        for candidate in host.findall("address"):
            raw = candidate.get("addr", "")
            try:
                parsed = ipaddress.ip_address(raw)
            except ValueError:
                continue
            if candidate.get("addrtype", "") in ("ipv4", "ipv6"):
                address = str(parsed)
                break
        if not address:
            continue

        ports_node = host.find("ports")
        port_elements = ports_node.findall("port") if ports_node is not None else []
        if len(port_elements) > MAX_PORTS_PER_HOST:
            raise ValueError("Too many ports for an Nmap host.")
        services = []
        for element in port_elements:
            protocol = element.get("protocol", "")
            if protocol not in ("tcp", "udp"):
                continue
            try:
                port = int(element.get("portid", ""))
            except ValueError:
                continue
            if not 1 <= port <= 65535:
                continue
            state_node = element.find("state")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            service_node = element.find("service")
            attrs = service_node.attrib if service_node is not None else {}
            services.append(ImportedService(
                protocol=protocol,
                port=port,
                state=state[:32],
                name=attrs.get("name", "")[:128],
                product=attrs.get("product", "")[:256],
                version=attrs.get("version", "")[:128],
            ))
        hosts.append(ImportedHost(address, status[:32], tuple(services)))
    return NmapEvidence(source="nmap-xml-unverified", hosts=tuple(hosts))


def import_nmap_xml_file(path: str | Path) -> NmapEvidence:
    """Read at most MAX_XML_BYTES + 1 bytes from a local XML export."""
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_XML_BYTES + 1)
    return parse_nmap_xml(data)
