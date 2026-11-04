"""Deep PCAP analysis with bounded TCP byte-stream reassembly."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from nightrecon_red_engine.packet_intelligence import (
    MAX_PCAP_PACKETS,
    PacketIntelligenceReport,
    PacketObservation,
    PacketRuntimeUnavailable,
    analyze_packets,
    observation_from_scapy,
)
from nightrecon_red_engine.tcp_stream_reassembly import (
    ReassembledStream,
    TcpSegment,
    reassemble_tcp_segments,
)


@dataclass(frozen=True)
class DeepPacketReport:
    packet_report: PacketIntelligenceReport
    reassembled_tcp_streams: tuple[ReassembledStream, ...]


def analyze_pcap_deep(
    path: str,
    *,
    max_packets: int = MAX_PCAP_PACKETS,
) -> DeepPacketReport:
    if max_packets < 1 or max_packets > MAX_PCAP_PACKETS:
        raise ValueError(
            f"max_packets must be between 1 and {MAX_PCAP_PACKETS}"
        )

    try:
        from scapy.layers.inet import TCP
        from scapy.packet import Raw
        from scapy.utils import PcapReader
    except Exception as exc:
        raise PacketRuntimeUnavailable(
            "Scapy is required for deep PCAP analysis."
        ) from exc

    observations: list[PacketObservation] = []
    streams: dict[
        tuple[str, int, str, int],
        list[TcpSegment],
    ] = defaultdict(list)

    with PcapReader(path) as reader:
        for index, packet in enumerate(reader):
            if index >= max_packets:
                break

            observation = observation_from_scapy(packet)
            if observation is None:
                continue
            observations.append(observation)

            if (
                observation.transport == "tcp"
                and observation.src_port is not None
                and observation.dst_port is not None
                and observation.tcp_sequence is not None
                and packet.haslayer(TCP)
                and packet.haslayer(Raw)
            ):
                try:
                    payload = bytes(packet.getlayer(Raw).load)
                except Exception:
                    payload = b""
                if payload:
                    key = (
                        observation.src,
                        observation.src_port,
                        observation.dst,
                        observation.dst_port,
                    )
                    streams[key].append(TcpSegment(
                        packet_id=observation.packet_id,
                        sequence=observation.tcp_sequence,
                        payload=payload,
                    ))

    reassembled: list[ReassembledStream] = []
    for (
        _src,
        src_port,
        _dst,
        dst_port,
    ), segments in sorted(streams.items()):
        try:
            reassembled.append(reassemble_tcp_segments(
                tuple(segments),
                src_port=src_port,
                dst_port=dst_port,
            ))
        except ValueError:
            continue

    packet_tuple = tuple(observations)
    return DeepPacketReport(
        packet_report=analyze_packets(packet_tuple),
        reassembled_tcp_streams=tuple(reassembled),
    )
