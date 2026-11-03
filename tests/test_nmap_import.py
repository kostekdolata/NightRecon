"""Tests for passive, bounded Nmap evidence import."""

import tempfile
import unittest
from pathlib import Path

from nightrecon_red_engine.nmap_import import (
    MAX_XML_BYTES,
    import_nmap_xml_file,
    parse_nmap_xml,
)


class NmapImportTests(unittest.TestCase):
    SAMPLE = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap">
 <host><status state="up"/><address addr="192.0.2.5" addrtype="ipv4"/>
 <ports><port protocol="tcp" portid="443"><state state="open"/>
 <service name="https" product="Example" version="1.0"/></port>
 <port protocol="udp" portid="53"><state state="open|filtered"/>
 <service name="domain"/></port></ports></host>
</nmaprun>"""

    def test_extracts_observations_without_claiming_verification(self):
        evidence = parse_nmap_xml(self.SAMPLE)
        self.assertEqual(evidence.source, "nmap-xml-unverified")
        self.assertEqual(len(evidence.hosts), 1)
        self.assertEqual(evidence.hosts[0].address, "192.0.2.5")
        self.assertEqual(evidence.hosts[0].status, "up")
        self.assertEqual(
            [(item.protocol, item.port, item.state) for item in evidence.hosts[0].services],
            [("tcp", 443, "open"), ("udp", 53, "open|filtered")],
        )

    def test_accepts_only_standard_nmap_external_dtd_without_loading_it(self):
        declaration = b'<!DOCTYPE nmaprun SYSTEM "https://nmap.org/book/nmap.dtd">'
        evidence = parse_nmap_xml(self.SAMPLE.replace(
            b'<nmaprun', declaration + b'\n<nmaprun', 1))
        self.assertEqual(evidence.hosts[0].address, "192.0.2.5")
        hostile = b'<!DOCTYPE nmaprun SYSTEM "file:///etc/passwd">'
        with self.assertRaises(ValueError):
            parse_nmap_xml(self.SAMPLE.replace(b'<nmaprun', hostile + b'\n<nmaprun', 1))

    def test_rejects_dtd_and_entity(self):
        malicious = b'<!DOCTYPE nmaprun [<!ENTITY x "test">]><nmaprun/>'
        with self.assertRaisesRegex(ValueError, "DTD"):
            parse_nmap_xml(malicious)

    def test_rejects_oversized_input(self):
        with self.assertRaisesRegex(ValueError, "size limit"):
            parse_nmap_xml(b"x" * (MAX_XML_BYTES + 1))

    def test_rejects_unexpected_root(self):
        with self.assertRaisesRegex(ValueError, "nmaprun"):
            parse_nmap_xml(b"<other/>")

    def test_skips_invalid_addresses_and_ports(self):
        data = b'<nmaprun><host><address addr="not-an-ip" addrtype="ipv4"/></host><host><address addr="2001:db8::1" addrtype="ipv6"/><ports><port protocol="tcp" portid="99999"/></ports></host></nmaprun>'
        result = parse_nmap_xml(data)
        self.assertEqual(len(result.hosts), 1)
        self.assertEqual(result.hosts[0].address, "2001:db8::1")
        self.assertEqual(result.hosts[0].services, ())

    def test_reads_from_local_export(self):
        with tempfile.TemporaryDirectory() as directory:
            filename = Path(directory) / "sample.xml"
            filename.write_bytes(self.SAMPLE)
            self.assertEqual(import_nmap_xml_file(filename), parse_nmap_xml(self.SAMPLE))


if __name__ == "__main__":
    unittest.main()
