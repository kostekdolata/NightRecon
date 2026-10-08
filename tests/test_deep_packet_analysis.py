"""Tests for deep PCAP stream analysis."""

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

from nightrecon_red_engine.deep_packet_analysis import analyze_pcap_deep


class DeepPacketAnalysisTests(unittest.TestCase):
    def test_http_request_is_reassembled_from_multiple_tcp_segments(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.pcap"
            packets = [
                IP(src="192.0.2.10", dst="192.0.2.20")
                / TCP(sport=51000, dport=80, flags="PA", seq=100)
                / Raw(load=b"GET /hea"),
                IP(src="192.0.2.10", dst="192.0.2.20")
                / TCP(sport=51000, dport=80, flags="PA", seq=108)
                / Raw(load=b"lth HTTP/1.1\r\nHost: example.test\r\n\r\n"),
            ]
            wrpcap(str(path), packets)

            report = analyze_pcap_deep(str(path))

        self.assertEqual(len(report.packet_report.packets), 2)
        self.assertEqual(len(report.reassembled_tcp_streams), 1)
        stream = report.reassembled_tcp_streams[0]
        self.assertIsNotNone(stream.protocol)
        self.assertEqual(stream.protocol.protocol, "http")
        self.assertEqual(stream.protocol.get("path"), "/health")


if __name__ == "__main__":
    unittest.main()
