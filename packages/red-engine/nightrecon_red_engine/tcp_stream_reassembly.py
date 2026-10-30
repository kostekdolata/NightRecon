"""Bounded TCP stream reassembly for packet metadata analysis.

The reassembler operates on supplied segments and returns bounded reconstructed
byte ranges plus hashes. It does not persist credentials or arbitrary payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256

from nightrecon_red_engine.protocol_dissectors import ProtocolMetadata, dissect_payload


MAX_REASSEMBLED_STREAM_BYTES = 262_144
MAX_STREAM_SEGMENTS = 4096


@dataclass(frozen=True)
class TcpSegment:
    packet_id: str
    sequence: int
    payload: bytes

    def __post_init__(self) -> None:
        if not self.packet_id.strip():
            raise ValueError("packet_id must not be empty")
        if self.sequence < 0:
            raise ValueError("sequence must not be negative")


@dataclass(frozen=True)
class ReassembledStream:
    packet_ids: tuple[str, ...]
    bytes_reassembled: int
    sha256: str
    truncated: bool
    gaps_detected: bool
    protocol: ProtocolMetadata | None = None


def reassemble_tcp_segments(
    segments: tuple[TcpSegment, ...],
    *,
    src_port: int | None = None,
    dst_port: int | None = None,
    max_bytes: int = MAX_REASSEMBLED_STREAM_BYTES,
) -> ReassembledStream:
    if not segments:
        raise ValueError("at least one TCP segment is required")
    if len(segments) > MAX_STREAM_SEGMENTS:
        raise ValueError(
            f"segment count exceeds MAX_STREAM_SEGMENTS={MAX_STREAM_SEGMENTS}"
        )
    if max_bytes < 1 or max_bytes > MAX_REASSEMBLED_STREAM_BYTES:
        raise ValueError(
            f"max_bytes must be between 1 and {MAX_REASSEMBLED_STREAM_BYTES}"
        )

    ordered = tuple(sorted(
        segments,
        key=lambda item: (item.sequence, item.packet_id),
    ))

    base = ordered[0].sequence
    buffer = bytearray()
    packet_ids: list[str] = []
    gaps = False
    truncated = False

    for segment in ordered:
        if not segment.payload:
            continue
        offset = segment.sequence - base
        if offset > len(buffer):
            gaps = True
            break
        if offset < 0:
            continue

        overlap = len(buffer) - offset
        data = segment.payload[overlap:] if overlap > 0 else segment.payload
        if not data:
            packet_ids.append(segment.packet_id)
            continue

        remaining = max_bytes - len(buffer)
        if remaining <= 0:
            truncated = True
            break
        if len(data) > remaining:
            buffer.extend(data[:remaining])
            packet_ids.append(segment.packet_id)
            truncated = True
            break

        buffer.extend(data)
        packet_ids.append(segment.packet_id)

    raw = bytes(buffer)
    return ReassembledStream(
        packet_ids=tuple(dict.fromkeys(packet_ids)),
        bytes_reassembled=len(raw),
        sha256=sha256(raw).hexdigest(),
        truncated=truncated,
        gaps_detected=gaps,
        protocol=dissect_payload(
            raw,
            src_port=src_port,
            dst_port=dst_port,
        ) if raw else None,
    )
