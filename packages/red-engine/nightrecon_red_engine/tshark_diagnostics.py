"""Offline protocol diagnostics for bounded TShark JSON exports.

Extracts aggregate DNS response codes and HTTP status codes. No packet data,
hostnames, credentials, addresses, or request bodies are persisted.
"""
from __future__ import annotations

from dataclasses import dataclass
import json

MAX_BYTES = 8 * 1024 * 1024
MAX_PACKETS = 10000

@dataclass(frozen=True)
class ProtocolDiagnostics:
    source: str
    packet_count: int
    dns_response_codes: tuple[tuple[str, int], ...]
    http_status_codes: tuple[tuple[str, int], ...]


def summarize_protocol_diagnostics(data: bytes) -> ProtocolDiagnostics:
    if len(data) > MAX_BYTES:
        raise ValueError("TShark export exceeds size limit")
    try:
        packets = json.loads(data)
    except (UnicodeError, ValueError) as exc:
        raise ValueError("Invalid TShark export") from exc
    if not isinstance(packets, list) or len(packets) > MAX_PACKETS:
        raise ValueError("Invalid TShark packet collection")

    dns_counts: dict[str, int] = {}
    http_counts: dict[str, int] = {}
    for packet in packets:
        if not isinstance(packet, dict):
            raise ValueError("Invalid packet entry")
        source = packet.get("_source", {})
        if not isinstance(source, dict):
            raise ValueError("Invalid packet source")
        layers = source.get("layers", {})
        if not isinstance(layers, dict):
            raise ValueError("Invalid packet layers")
        for name, field, counts in (
            ("dns", "dns.flags.rcode", dns_counts),
            ("http", "http.response.code", http_counts),
        ):
            layer = layers.get(name)
            if layer is None:
                continue
            if not isinstance(layer, dict):
                raise ValueError("Invalid protocol layer")
            value = layer.get(field)
            if isinstance(value, list):
                value = value[0] if value else None
            if value is None:
                continue
            if not isinstance(value, (str, int)):
                raise ValueError("Invalid protocol status field")
            code = str(value)
            if not code.isdecimal() or len(code) > 3:
                raise ValueError("Invalid protocol status code")
            counts[code] = counts.get(code, 0) + 1

    return ProtocolDiagnostics(
        source="tshark-protocol-aggregate-unverified",
        packet_count=len(packets),
        dns_response_codes=tuple(sorted(dns_counts.items())),
        http_status_codes=tuple(sorted(http_counts.items())),
    )
