"""Passive, bounded PCAP conversation metadata import for Red Night.

This adapter never captures traffic, executes external tools or retains payloads.
Only classic PCAP (not PCAPNG) with Ethernet / raw IPv4 or IPv6 link types is supported.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import ipaddress
import struct

MAX_PCAP_BYTES = 16 * 1024 * 1024
MAX_PACKETS = 100_000
MAX_CAPTURED_PACKET = 262_144


@dataclass(frozen=True)
class PacketConversation:
    source: str
    destination: str
    protocol: str
    packets: int


@dataclass(frozen=True)
class PcapEvidence:
    source: str
    packet_count: int
    decoded_packets: int
    conversations: tuple[PacketConversation, ...]


def parse_pcap(data: bytes) -> PcapEvidence:
    """Return metadata only, never packet contents or inferred vulnerabilities."""
    if len(data) > MAX_PCAP_BYTES:
        raise ValueError("PCAP exceeds the configured size limit.")
    if len(data) < 24:
        raise ValueError("Truncated PCAP global header.")

    magic = data[:4]
    if magic in (b"\\xd4\\xc3\\xb2\\xa1", b"\\x4d\\x3c\\xb2\\xa1"):
        endian = "<"
    elif magic in (b"\\xa1\\xb2\\xc3\\xd4", b"\\xa1\\xb2\\x3c\\x4d"):
        endian = ">"
    else:
        raise ValueError("Unsupported PCAP format or byte order.")

    major, minor, _, _, snaplen, network = struct.unpack_from(endian + "HHiIII", data, 4)
    if (major, minor) != (2, 4) or snaplen < 1:
        raise ValueError("Invalid PCAP header.")
    if network not in (1, 101, 228, 229):
        raise ValueError("Unsupported PCAP link type.")

    counts: dict[tuple[str, str, str], int] = {}
    offset, packets, decoded = 24, 0, 0
    while offset < len(data):
        if len(data) - offset < 16:
            raise ValueError("Truncated PCAP packet header.")
        _, _, included, original = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if included > MAX_CAPTURED_PACKET or included > snaplen or included > original:
            raise ValueError("Invalid PCAP packet length.")
        if included > len(data) - offset:
            raise ValueError("Truncated PCAP packet data.")
        frame = memoryview(data)[offset:offset + included]
        offset += included
        packets += 1
        if packets > MAX_PACKETS:
            raise ValueError("Too many PCAP packets.")

        family = None
        raw = frame
        if network == 1:
            if len(frame) < 14:
                continue
            ethertype = struct.unpack_from("!H", frame, 12)[0]
            cursor = 14
            # Single or stacked VLAN tags.
            for _ in range(2):
                if ethertype not in (0x8100, 0x88A8) or len(frame) < cursor + 4:
                    break
                ethertype = struct.unpack_from("!H", frame, cursor + 2)[0]
                cursor += 4
            raw = frame[cursor:]
            family = 4 if ethertype == 0x0800 else 6 if ethertype == 0x86DD else None
        elif network in (101, 228, 229):
            family = 4 if network == 228 else 6 if network == 229 else (raw[0] >> 4 if raw else None)

        if family == 4:
            if len(raw) < 20 or raw[0] >> 4 != 4:
                continue
            header_length = (raw[0] & 15) * 4
            if header_length < 20 or len(raw) < header_length:
                continue
            src = str(ipaddress.IPv4Address(bytes(raw[12:16])))
            dst = str(ipaddress.IPv4Address(bytes(raw[16:20])))
            protocol_num = raw[9]
        elif family == 6:
            if len(raw) < 40 or raw[0] >> 4 != 6:
                continue
            src = str(ipaddress.IPv6Address(bytes(raw[8:24])))
            dst = str(ipaddress.IPv6Address(bytes(raw[24:40])))
            protocol_num = raw[6]
        else:
            continue

        protocol = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmpv6"}.get(protocol_num, "other")
        key = (src, dst, protocol)
        counts[key] = counts.get(key, 0) + 1
        decoded += 1

    return PcapEvidence(
        source="pcap-metadata-unverified",
        packet_count=packets,
        decoded_packets=decoded,
        conversations=tuple(PacketConversation(*key, count) for key, count in sorted(counts.items())),
    )


def import_pcap_file(path: str | Path) -> PcapEvidence:
    with Path(path).open("rb") as stream:
        return parse_pcap(stream.read(MAX_PCAP_BYTES + 1))
