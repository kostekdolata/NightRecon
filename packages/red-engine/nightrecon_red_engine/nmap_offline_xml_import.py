"""Bounded offline Nmap XML evidence import. Never invokes Nmap or network IO."""
from __future__ import annotations

import hashlib
import ipaddress
import xml.etree.ElementTree as ET


class NmapOfflineImportError(ValueError):
    """Untrusted, malformed, excessive or out-of-scope Nmap XML."""


def import_nmap_xml(payload: bytes, *, allowed_addresses: tuple[str, ...],
                    source_name: str = "nmap.xml", max_bytes: int = 2_000_000,
                    max_hosts: int = 256, max_ports: int = 4096) -> dict:
    """Import exact-address, open-port observations without vulnerability verdicts.

    An explicit independent allowlist is mandatory. This is not authorization
    to scan and never interprets a port state as proof of exploitability.
    """
    if (type(max_bytes) is not int or not 0 < max_bytes <= 10_000_000
            or type(max_hosts) is not int or not 0 < max_hosts <= 1000
            or type(max_ports) is not int or not 0 < max_ports <= 10000):
        raise NmapOfflineImportError("Invalid resource budget")
    if (not isinstance(payload, bytes) or not 0 < len(payload) <= max_bytes
            or b"<!DOCTYPE" in payload.upper() or b"<!ENTITY" in payload.upper()):
        raise NmapOfflineImportError("Invalid XML payload")
    if (not isinstance(allowed_addresses, tuple) or not allowed_addresses
            or len(allowed_addresses) > 1000 or not isinstance(source_name, str)
            or not 0 < len(source_name) <= 256):
        raise NmapOfflineImportError("Explicit address scope and source required")
    try:
        scope = {str(ipaddress.ip_address(address)) for address in allowed_addresses}
        if len(scope) != len(allowed_addresses):
            raise ValueError("Duplicate address")
        root = ET.fromstring(payload)
    except (ValueError, TypeError, ET.ParseError) as exc:
        raise NmapOfflineImportError("Invalid scope or XML") from exc
    if root.tag != "nmaprun":
        raise NmapOfflineImportError("Not an Nmap XML report")
    hosts = root.findall("host")
    if len(hosts) > max_hosts:
        raise NmapOfflineImportError("Host budget exceeded")
    observations = []
    count = 0
    for host in hosts:
        addresses = host.findall("address")
        valid = []
        for address in addresses:
            if address.get("addrtype") not in ("ipv4", "ipv6"):
                continue
            try:
                valid.append(str(ipaddress.ip_address(address.get("addr", ""))))
            except ValueError as exc:
                raise NmapOfflineImportError("Malformed host address") from exc
        if not valid or any(address not in scope for address in valid):
            raise NmapOfflineImportError("Host outside exact address scope")
        if len(valid) != 1:
            raise NmapOfflineImportError("Ambiguous host addresses")
        ports_node = host.find("ports")
        ports = [] if ports_node is None else ports_node.findall("port")
        count += len(ports)
        if count > max_ports:
            raise NmapOfflineImportError("Port budget exceeded")
        for port in ports:
            protocol = port.get("protocol")
            number = port.get("portid")
            if protocol not in ("tcp", "udp") or not isinstance(number, str) or not number.isascii() or not number.isdecimal():
                raise NmapOfflineImportError("Invalid protocol or port")
            port_number = int(number)
            if not 1 <= port_number <= 65535:
                raise NmapOfflineImportError("Invalid port number")
            state = port.find("state")
            if state is None or state.get("state") not in ("open", "closed", "filtered", "open|filtered", "closed|filtered", "unfiltered"):
                raise NmapOfflineImportError("Invalid port state")
            observations.append({
                "address": valid[0], "protocol": protocol, "port": port_number,
                "observed_state": state.get("state"),
                "classification": "unverified_tool_observation",
            })
    return {
        "schema": "red.nmap_offline_xml_import.v1",
        "source_tool": "Nmap", "source_name": source_name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "authority": "untrusted_offline_import",
        "record_count": len(observations), "observations": observations,
        "limitations": "Offline Nmap observations do not establish authorization, current exposure, vulnerability or exploitability.",
    }
