"""Passive bounded PCAPNG interface and packet-block inventory.

Does not capture live traffic, decode payloads or execute external software.
Validates section lengths and byte order before iterating blocks.
"""
from __future__ import annotations
from dataclasses import dataclass
import struct
from pathlib import Path

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_BLOCKS = 200_000
SECTION_MAGIC = b"\x0a\x0d\x0d\x0a"

@dataclass(frozen=True)
class PcapngEvidence:
    source: str
    sections: int
    interfaces: int
    enhanced_packets: int
    simple_packets: int
    other_blocks: int

def parse_pcapng(data: bytes) -> PcapngEvidence:
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("PCAPNG exceeds size limit")
    if len(data) < 28 or data[:4] != SECTION_MAGIC:
        raise ValueError("Expected PCAPNG section header")
    offset = 0
    endian = None
    sections = interfaces = enhanced = simple = other = blocks = 0
    while offset < len(data):
        if blocks >= MAX_BLOCKS:
            raise ValueError("Too many PCAPNG blocks")
        if len(data) - offset < 12:
            raise ValueError("Truncated PCAPNG block")
        is_section = data[offset:offset + 4] == SECTION_MAGIC
        if is_section:
            if len(data) - offset < 28:
                raise ValueError("Truncated PCAPNG section")
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                raise ValueError("Invalid PCAPNG byte-order magic")
        elif endian is None:
            raise ValueError("PCAPNG block without section")
        block_type, total = struct.unpack_from(endian + "II", data, offset)
        if total < 12 or total % 4 != 0 or offset + total > len(data):
            raise ValueError("Invalid PCAPNG block length")
        trailing = struct.unpack_from(endian + "I", data, offset + total - 4)[0]
        if trailing != total:
            raise ValueError("Inconsistent PCAPNG block length")
        if is_section:
            if total < 28:
                raise ValueError("Invalid PCAPNG section size")
            sections += 1
        elif block_type == 1:
            interfaces += 1
        elif block_type == 6:
            if total < 32:
                raise ValueError("Invalid enhanced packet block")
            enhanced += 1
        elif block_type == 3:
            if total < 16:
                raise ValueError("Invalid simple packet block")
            simple += 1
        else:
            other += 1
        blocks += 1
        offset += total
    return PcapngEvidence("pcapng-blocks-unverified", sections, interfaces, enhanced, simple, other)

def import_pcapng_file(path: str | Path) -> PcapngEvidence:
    with Path(path).open("rb") as handle:
        return parse_pcapng(handle.read(MAX_FILE_BYTES + 1))
