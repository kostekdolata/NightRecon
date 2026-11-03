"""Tests for packet-intelligence metadata, streams, and findings."""

import unittest

from nightrecon_red_engine.packet_intelligence import (
    FindingCorrelationKey,
    PacketObservation,
    analyze_packets,
    correlate_findings_to_packets,
    filter_packets,
    link_finding_to_packets,
)


class PacketIntelligenceTests(unittest.TestCase):
    def fixture(self):
        return (
            PacketObservation(
                packet_id="p1",
                timestamp=1.0,
                src="192.0.2.10",
                dst="192.0.2.20",
                transport="tcp",
                src_port=51000,
                dst_port=80,
                length=100,
                protocol="http",
                tcp_flags="PA",
                tcp_sequence=10,
                http_method="POST",
                http_path="/login",
            ),
            PacketObservation(
                packet_id="p2",
                timestamp=2.0,
                src="192.0.2.20",
                dst="192.0.2.10",
                transport="tcp",
                src_port=80,
                dst_port=51000,
                length=200,
                protocol="http",
                tcp_flags="PA",
                tcp_sequence=20,
            ),
            PacketObservation(
                packet_id="p3",
                timestamp=3.0,
                src="192.0.2.10",
                dst="192.0.2.53",
                transport="udp",
                src_port=53000,
                dst_port=53,
                length=70,
                protocol="dns",
                dns_name="example.test",
            ),
        )

    def test_filtering_by_host_protocol_and_port(self):
        packets = self.fixture()
        self.assertEqual(len(filter_packets(packets, host="192.0.2.10")), 3)
        self.assertEqual(len(filter_packets(packets, protocol="dns")), 1)
        self.assertEqual(len(filter_packets(packets, port=80)), 2)

    def test_analysis_builds_conversations_streams_and_cleartext_finding(self):
        report = analyze_packets(self.fixture())
        self.assertEqual(len(report.conversations), 2)
        self.assertEqual(len(report.streams), 2)
        self.assertTrue(any(
            item.kind == "cleartext-http-write"
            for item in report.findings
        ))

    def test_packet_evidence_link_deduplicates_ids(self):
        link = link_finding_to_packets(
            "finding-1",
            ("p1", "p1", "p2"),
            reason="supports observed traffic",
        )
        self.assertEqual(link.packet_ids, ("p1", "p2"))

    def test_artifacts_and_automatic_finding_packet_correlation(self):
        report = analyze_packets(self.fixture())
        self.assertTrue(any(
            item.artifact_type == "dns-name"
            and item.value == "example.test"
            for item in report.artifacts
        ))

        links = correlate_findings_to_packets(
            (
                FindingCorrelationKey(
                    finding_ref="finding-http",
                    address="192.0.2.20",
                    port=80,
                    protocol="http",
                ),
            ),
            self.fixture(),
        )
        self.assertEqual(len(links), 1)
        self.assertEqual(
            links[0].packet_ids,
            ("p1", "p2"),
        )


if __name__ == "__main__":
    unittest.main()
