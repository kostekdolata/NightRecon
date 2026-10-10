"""Unit tests for read-only multi-tool evidence correlation."""
import unittest

from nightrecon_red_engine.evidence_correlation import correlate_imports
from nightrecon_red_engine.nmap_import import NmapEvidence, ImportedHost, ImportedService
from nightrecon_red_engine.pcap_import import PcapEvidence, PacketConversation
from nightrecon_red_engine.metasploit_catalogue import MetasploitCatalogue, ModuleSummary


class CorrelationTests(unittest.TestCase):
    def setUp(self):
        self.nmap = NmapEvidence("nmap-xml-unverified", (
            ImportedHost("192.0.2.1", "up", (ImportedService("tcp", 443, "open", "https", "", ""),)),
            ImportedHost("198.51.100.2", "up", ()),
        ))
        self.pcap = PcapEvidence("pcap-metadata-unverified", 3, 3, (
            PacketConversation("192.0.2.1", "203.0.113.4", "tcp", 3),
        ))
        self.modules = MetasploitCatalogue("metasploit-catalogue-unverified", (
            ModuleSummary("auxiliary/scanner/example", "auxiliary", "Example", "", ("CVE-2020-0001",)),
        ))

    def test_empty_allowlist_excludes_all_hosts(self):
        result = correlate_imports(self.nmap, self.pcap, self.modules)
        self.assertEqual(result.hosts, ())
        self.assertEqual(result.status, "unverified-imported-evidence")

    def test_correlates_approved_host_without_inventing_vulnerabilities(self):
        result = correlate_imports(
            self.nmap, self.pcap, self.modules,
            frozenset({"192.0.2.1"}),
        )
        self.assertEqual(len(result.hosts), 1)
        self.assertTrue(result.hosts[0].discovered_by_nmap)
        self.assertTrue(result.hosts[0].observed_in_pcap)
        self.assertEqual(result.hosts[0].services, (("tcp", 443, "open", "https"),))
        self.assertEqual(result.module_references, ("CVE-2020-0001",))
        self.assertFalse(hasattr(result.hosts[0], "vulnerabilities"))

    def test_suppresses_out_of_scope_capture_addresses(self):
        result = correlate_imports(
            pcap=self.pcap, allowed_addresses=frozenset({"203.0.113.4"})
        )
        self.assertEqual([h.address for h in result.hosts], ["203.0.113.4"])
        self.assertFalse(result.hosts[0].discovered_by_nmap)

    def test_rejects_invalid_allowlist_ip(self):
        with self.assertRaises(ValueError):
            correlate_imports(allowed_addresses=frozenset({"not an ip"}))

    def test_sources_remain_explicit(self):
        result = correlate_imports(self.nmap, self.pcap, self.modules)
        self.assertEqual(len(result.sources), 3)


if __name__ == "__main__":
    unittest.main()
