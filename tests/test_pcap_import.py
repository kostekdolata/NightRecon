"""Passive PCAP metadata adapter regression tests."""
import ipaddress
import struct
import tempfile
import unittest
from pathlib import Path

from nightrecon_red_engine.pcap_import import (
    MAX_PCAP_BYTES, import_pcap_file, parse_pcap,
)


def capture(ethernet=True):
    header = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1 if ethernet else 101)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 6
    ip[12:16] = ipaddress.IPv4Address("192.0.2.10").packed
    ip[16:20] = ipaddress.IPv4Address("198.51.100.20").packed
    frame = (b"\x00" * 12 + b"\x08\x00" if ethernet else b"") + bytes(ip)
    return header + struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame


class PcapImportTests(unittest.TestCase):
    def test_passive_conversation_metadata(self):
        result = parse_pcap(capture())
        self.assertEqual(result.source, "pcap-metadata-unverified")
        self.assertEqual((result.packet_count, result.decoded_packets), (1, 1))
        self.assertEqual(
            [(c.source, c.destination, c.protocol, c.packets) for c in result.conversations],
            [("192.0.2.10", "198.51.100.20", "tcp", 1)],
        )

    def test_raw_ip_link_type(self):
        self.assertEqual(parse_pcap(capture(False)).decoded_packets, 1)

    def test_no_payload_preserved(self):
        self.assertFalse(hasattr(parse_pcap(capture()), "packets"))

    def test_rejects_truncated_records(self):
        with self.assertRaisesRegex(ValueError, "Truncated"):
            parse_pcap(capture()[:-1])

    def test_rejects_pcapng(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            parse_pcap(b"\x0a\x0d\x0d\x0a" + b"\x00" * 32)

    def test_rejects_oversized_capture(self):
        with self.assertRaisesRegex(ValueError, "size limit"):
            parse_pcap(b"x" * (MAX_PCAP_BYTES + 1))

    def test_file_import(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "sample.pcap"
            path.write_bytes(capture())
            self.assertEqual(import_pcap_file(path), parse_pcap(capture()))


if __name__ == "__main__":
    unittest.main()
