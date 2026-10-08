"""Bounded packet intelligence for authorized Red Night assessments.

The packet layer stores metadata and hashes rather than raw application payloads
by default. Full bytes remain available in operator-owned PCAP files.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
import ipaddress
import time
from typing import Iterable


MAX_CAPTURE_PACKETS = 5000
MAX_CAPTURE_SECONDS = 60.0
MAX_PCAP_PACKETS = 100_000


class PacketRuntimeUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class PacketObservation:
    packet_id: str
    timestamp: float
    src: str
    dst: str
    transport: str
    src_port: int | None = None
    dst_port: int | None = None
    length: int = 0
    protocol: str = "unknown"
    payload_sha256: str = ""
    tcp_flags: str = ""
    tcp_sequence: int | None = None
    dns_name: str = ""
    http_method: str = ""
    http_path: str = ""
    tls_sni: str = ""
    note: str = ""


@dataclass(frozen=True)
class ConversationStats:
    endpoint_a: str
    endpoint_b: str
    transport: str
    packets: int
    bytes: int
    first_seen: float
    last_seen: float


@dataclass(frozen=True)
class StreamSummary:
    stream_id: str
    client: str
    server: str
    transport: str
    packet_ids: tuple[str, ...]
    packets: int
    bytes: int
    first_seen: float
    last_seen: float
    protocol_hints: tuple[str, ...]


@dataclass(frozen=True)
class TrafficFinding:
    finding_id: str
    kind: str
    severity: str
    summary: str
    packet_ids: tuple[str, ...]
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class PacketEvidenceLink:
    finding_ref: str
    packet_ids: tuple[str, ...]
    reason: str


@dataclass(frozen=True)
class ExtractedNetworkArtifact:
    artifact_type: str
    value: str
    packet_ids: tuple[str, ...]


@dataclass(frozen=True)
class FindingCorrelationKey:
    finding_ref: str
    address: str
    port: int | None = None
    protocol: str = ""


@dataclass(frozen=True)
class PacketIntelligenceReport:
    packets: tuple[PacketObservation, ...]
    conversations: tuple[ConversationStats, ...]
    streams: tuple[StreamSummary, ...]
    findings: tuple[TrafficFinding, ...]
    artifacts: tuple[ExtractedNetworkArtifact, ...] = ()


def _packet_id(
    timestamp: float,
    src: str,
    dst: str,
    transport: str,
    src_port: int | None,
    dst_port: int | None,
    length: int,
    payload_hash: str,
) -> str:
    material = "|".join(
        (
            f"{timestamp:.9f}",
            src,
            dst,
            transport,
            str(src_port or 0),
            str(dst_port or 0),
            str(length),
            payload_hash,
        )
    )
    return "pkt-" + sha256(material.encode("utf-8")).hexdigest()[:24]


def _protocol_hint(
    transport: str,
    src_port: int | None,
    dst_port: int | None,
    payload: bytes,
) -> tuple[str, dict[str, str]]:
    ports = {src_port, dst_port}
    metadata: dict[str, str] = {}

    if 53 in ports:
        return "dns", metadata
    if 22 in ports:
        return "ssh", metadata
    if 445 in ports or 139 in ports:
        return "smb", metadata
    if 443 in ports or 8443 in ports:
        return "tls", metadata

    if transport == "tcp" and payload:
        upper = payload[:32].upper()
        for method in (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH "):
            if upper.startswith(method):
                first = payload.split(b"\r\n", 1)[0]
                parts = first.decode("latin-1", "replace").split()
                metadata["http_method"] = parts[0] if parts else ""
                path = parts[1] if len(parts) > 1 else "/"
                metadata["http_path"] = path.split("?", 1)[0][:512]
                return "http", metadata
        if payload.startswith(b"HTTP/"):
            return "http", metadata

    return "unknown", metadata


def observation_from_scapy(packet: object) -> PacketObservation | None:
    """Convert one Scapy packet into secret-minimized metadata."""
    try:
        from scapy.layers.dns import DNS, DNSQR
        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.packet import Raw
    except Exception as exc:
        raise PacketRuntimeUnavailable("Scapy packet support is unavailable.") from exc

    if packet.haslayer(IP):
        layer = packet.getlayer(IP)
        src, dst = str(layer.src), str(layer.dst)
    elif packet.haslayer(IPv6):
        layer = packet.getlayer(IPv6)
        src, dst = str(layer.src), str(layer.dst)
    else:
        return None

    transport = "other"
    src_port: int | None = None
    dst_port: int | None = None
    flags = ""
    sequence: int | None = None

    if packet.haslayer(TCP):
        tcp = packet.getlayer(TCP)
        transport = "tcp"
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        flags = str(tcp.flags)
        sequence = int(tcp.seq)
    elif packet.haslayer(UDP):
        udp = packet.getlayer(UDP)
        transport = "udp"
        src_port, dst_port = int(udp.sport), int(udp.dport)

    payload = b""
    if packet.haslayer(Raw):
        try:
            payload = bytes(packet.getlayer(Raw).load)
        except Exception:
            payload = b""

    protocol, metadata = _protocol_hint(
        transport,
        src_port,
        dst_port,
        payload,
    )
    dns_name = ""
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            value = packet.getlayer(DNSQR).qname
            dns_name = value.decode("idna", "replace").rstrip(".")[:253]
            protocol = "dns"
        except Exception:
            dns_name = ""

    payload_hash = sha256(payload).hexdigest() if payload else ""
    timestamp = float(getattr(packet, "time", time.time()))
    length = len(bytes(packet))
    return PacketObservation(
        packet_id=_packet_id(
            timestamp, src, dst, transport, src_port, dst_port, length, payload_hash
        ),
        timestamp=timestamp,
        src=src,
        dst=dst,
        transport=transport,
        src_port=src_port,
        dst_port=dst_port,
        length=length,
        protocol=protocol,
        payload_sha256=payload_hash,
        tcp_flags=flags,
        tcp_sequence=sequence,
        dns_name=dns_name,
        http_method=metadata.get("http_method", ""),
        http_path=metadata.get("http_path", ""),
    )


def import_pcap(path: str, *, max_packets: int = MAX_PCAP_PACKETS) -> tuple[PacketObservation, ...]:
    if max_packets < 1 or max_packets > MAX_PCAP_PACKETS:
        raise ValueError(f"max_packets must be between 1 and {MAX_PCAP_PACKETS}.")
    try:
        from scapy.utils import PcapReader
    except Exception as exc:
        raise PacketRuntimeUnavailable("Scapy is required for PCAP import.") from exc

    observations: list[PacketObservation] = []
    with PcapReader(path) as reader:
        for index, packet in enumerate(reader):
            if index >= max_packets:
                break
            observation = observation_from_scapy(packet)
            if observation is not None:
                observations.append(observation)
    return tuple(observations)


def export_pcap(packets: Iterable[object], path: str) -> None:
    try:
        from scapy.utils import wrpcap
    except Exception as exc:
        raise PacketRuntimeUnavailable("Scapy is required for PCAP export.") from exc
    wrpcap(path, list(packets))


def capture_live(
    *,
    interface: str | None = None,
    packet_count: int = 500,
    timeout_seconds: float = 10.0,
    bpf_filter: str = "",
) -> tuple[PacketObservation, ...]:
    """Capture local traffic only; this function sends no packets."""
    if packet_count < 1 or packet_count > MAX_CAPTURE_PACKETS:
        raise ValueError(
            f"packet_count must be between 1 and {MAX_CAPTURE_PACKETS}."
        )
    if timeout_seconds <= 0 or timeout_seconds > MAX_CAPTURE_SECONDS:
        raise ValueError(
            f"timeout_seconds must be between 0 and {MAX_CAPTURE_SECONDS}."
        )
    try:
        from scapy.sendrecv import sniff
    except Exception as exc:
        raise PacketRuntimeUnavailable(
            "Scapy/Npcap or libpcap is required for live capture."
        ) from exc

    captured = sniff(
        iface=interface or None,
        count=packet_count,
        timeout=timeout_seconds,
        filter=bpf_filter or None,
        store=True,
    )
    results = []
    for packet in captured:
        observation = observation_from_scapy(packet)
        if observation is not None:
            results.append(observation)
    return tuple(results)


def filter_packets(
    packets: tuple[PacketObservation, ...],
    *,
    host: str = "",
    protocol: str = "",
    port: int | None = None,
) -> tuple[PacketObservation, ...]:
    if host:
        ipaddress.ip_address(host)
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535.")
    normalized_protocol = protocol.strip().lower()
    return tuple(
        item for item in packets
        if (not host or host in {item.src, item.dst})
        and (not normalized_protocol or item.protocol == normalized_protocol)
        and (
            port is None
            or port in {item.src_port, item.dst_port}
        )
    )


def build_conversations(
    packets: tuple[PacketObservation, ...],
) -> tuple[ConversationStats, ...]:
    grouped: dict[tuple[str, str, str], list[PacketObservation]] = defaultdict(list)
    for packet in packets:
        endpoints = tuple(sorted((packet.src, packet.dst)))
        grouped[(endpoints[0], endpoints[1], packet.transport)].append(packet)

    results = []
    for (a, b, transport), items in grouped.items():
        results.append(ConversationStats(
            endpoint_a=a,
            endpoint_b=b,
            transport=transport,
            packets=len(items),
            bytes=sum(item.length for item in items),
            first_seen=min(item.timestamp for item in items),
            last_seen=max(item.timestamp for item in items),
        ))
    return tuple(sorted(
        results,
        key=lambda item: (-item.bytes, item.endpoint_a, item.endpoint_b, item.transport),
    ))


def build_streams(
    packets: tuple[PacketObservation, ...],
) -> tuple[StreamSummary, ...]:
    grouped: dict[
        tuple[str, int | None, str, int | None, str],
        list[PacketObservation],
    ] = defaultdict(list)

    for packet in packets:
        if packet.transport not in {"tcp", "udp"}:
            continue
        left = (packet.src, packet.src_port or 0)
        right = (packet.dst, packet.dst_port or 0)
        if left <= right:
            key = (packet.src, packet.src_port, packet.dst, packet.dst_port, packet.transport)
        else:
            key = (packet.dst, packet.dst_port, packet.src, packet.src_port, packet.transport)
        grouped[key].append(packet)

    streams = []
    for key, items in grouped.items():
        a, a_port, b, b_port, transport = key
        ordered = tuple(sorted(
            items,
            key=lambda item: (
                item.timestamp,
                item.tcp_sequence if item.tcp_sequence is not None else -1,
                item.packet_id,
            ),
        ))
        stream_material = f"{a}:{a_port}-{b}:{b_port}-{transport}"
        hints = tuple(sorted({
            item.protocol for item in ordered if item.protocol != "unknown"
        }))
        streams.append(StreamSummary(
            stream_id="stream-" + sha256(stream_material.encode()).hexdigest()[:20],
            client=f"{a}:{a_port or 0}",
            server=f"{b}:{b_port or 0}",
            transport=transport,
            packet_ids=tuple(item.packet_id for item in ordered),
            packets=len(ordered),
            bytes=sum(item.length for item in ordered),
            first_seen=ordered[0].timestamp,
            last_seen=ordered[-1].timestamp,
            protocol_hints=hints,
        ))
    return tuple(sorted(streams, key=lambda item: item.stream_id))


def detect_suspicious_traffic(
    packets: tuple[PacketObservation, ...],
) -> tuple[TrafficFinding, ...]:
    findings: list[TrafficFinding] = []

    dns_by_source: dict[str, list[PacketObservation]] = defaultdict(list)
    syn_by_source: dict[str, list[PacketObservation]] = defaultdict(list)
    cleartext_auth: list[PacketObservation] = []

    for packet in packets:
        if packet.protocol == "dns" and packet.dns_name:
            dns_by_source[packet.src].append(packet)
        if packet.transport == "tcp" and "S" in packet.tcp_flags and "A" not in packet.tcp_flags:
            syn_by_source[packet.src].append(packet)
        if (
            packet.protocol == "http"
            and packet.http_method in {"POST", "PUT", "PATCH"}
            and packet.dst_port == 80
        ):
            cleartext_auth.append(packet)

    for source, items in sorted(dns_by_source.items()):
        unique = {item.dns_name for item in items}
        if len(items) >= 25 and len(unique) >= 20:
            packet_ids = tuple(item.packet_id for item in items[:50])
            findings.append(TrafficFinding(
                finding_id="traffic-dns-burst-" + sha256(source.encode()).hexdigest()[:12],
                kind="dns-burst",
                severity="medium",
                summary="High-volume diverse DNS querying observed.",
                packet_ids=packet_ids,
                evidence=(
                    f"source={source}",
                    f"queries={len(items)}",
                    f"unique_names={len(unique)}",
                ),
            ))

    for source, items in sorted(syn_by_source.items()):
        destinations = {(item.dst, item.dst_port) for item in items}
        if len(destinations) >= 20:
            findings.append(TrafficFinding(
                finding_id="traffic-syn-fanout-" + sha256(source.encode()).hexdigest()[:12],
                kind="syn-fanout",
                severity="low",
                summary="Broad TCP SYN fan-out observed.",
                packet_ids=tuple(item.packet_id for item in items[:100]),
                evidence=(
                    f"source={source}",
                    f"unique_destinations={len(destinations)}",
                ),
            ))

    if cleartext_auth:
        findings.append(TrafficFinding(
            finding_id="traffic-cleartext-http-write",
            kind="cleartext-http-write",
            severity="medium",
            summary="State-changing HTTP traffic was observed over cleartext transport.",
            packet_ids=tuple(item.packet_id for item in cleartext_auth[:100]),
            evidence=(f"packets={len(cleartext_auth)}",),
        ))

    return tuple(findings)


def extract_network_artifacts(
    packets: tuple[PacketObservation, ...],
) -> tuple[ExtractedNetworkArtifact, ...]:
    grouped: dict[tuple[str, str], list[str]] = defaultdict(list)

    for packet in packets:
        candidates = (
            ("dns-name", packet.dns_name),
            ("http-path", packet.http_path),
            ("tls-sni", packet.tls_sni),
        )
        for artifact_type, value in candidates:
            cleaned = value.strip()
            if cleaned:
                grouped[(artifact_type, cleaned)].append(packet.packet_id)

    return tuple(
        ExtractedNetworkArtifact(
            artifact_type=artifact_type,
            value=value,
            packet_ids=tuple(dict.fromkeys(packet_ids)),
        )
        for (artifact_type, value), packet_ids in sorted(grouped.items())
    )


def correlate_findings_to_packets(
    keys: tuple[FindingCorrelationKey, ...],
    packets: tuple[PacketObservation, ...],
) -> tuple[PacketEvidenceLink, ...]:
    links: list[PacketEvidenceLink] = []

    for key in keys:
        if not key.finding_ref.strip():
            raise ValueError("finding_ref must not be empty")
        if key.port is not None and not 1 <= key.port <= 65535:
            raise ValueError("correlation port must be between 1 and 65535")

        protocol = key.protocol.strip().lower()
        matched = tuple(
            packet.packet_id
            for packet in packets
            if key.address in {packet.src, packet.dst}
            and (
                key.port is None
                or key.port in {packet.src_port, packet.dst_port}
            )
            and (
                not protocol
                or protocol in {packet.protocol, packet.transport}
            )
        )
        if matched:
            links.append(PacketEvidenceLink(
                finding_ref=key.finding_ref,
                packet_ids=tuple(dict.fromkeys(matched)),
                reason=(
                    "automatic packet correlation by observed "
                    "address/port/protocol evidence"
                ),
            ))

    return tuple(links)


def analyze_packets(
    packets: tuple[PacketObservation, ...],
) -> PacketIntelligenceReport:
    return PacketIntelligenceReport(
        packets=packets,
        conversations=build_conversations(packets),
        streams=build_streams(packets),
        findings=detect_suspicious_traffic(packets),
        artifacts=extract_network_artifacts(packets),
    )


def link_finding_to_packets(
    finding_ref: str,
    packet_ids: tuple[str, ...],
    *,
    reason: str,
) -> PacketEvidenceLink:
    if not finding_ref.strip():
        raise ValueError("finding_ref must not be empty.")
    if not packet_ids:
        raise ValueError("at least one packet_id is required.")
    if not reason.strip():
        raise ValueError("reason must not be empty.")
    return PacketEvidenceLink(
        finding_ref=finding_ref.strip(),
        packet_ids=tuple(dict.fromkeys(packet_ids)),
        reason=reason.strip(),
    )
