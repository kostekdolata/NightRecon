import unittest

from nightrecon_red_engine.nmap_offline_xml_import import (
    NmapOfflineImportError, import_nmap_xml,
)

VALID = b"""<?xml version="1.0"?>
<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="443"><state state="open"/></port>
<port protocol="udp" portid="53"><state state="open|filtered"/></port></ports>
</host></nmaprun>"""


class NmapOfflineXMLImportTests(unittest.TestCase):
    def test_exact_scope_provenance_and_ambiguous_state(self):
        result = import_nmap_xml(VALID, allowed_addresses=("127.0.0.1",))
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(result["observations"][1]["observed_state"], "open|filtered")
        self.assertEqual(result["observations"][0]["classification"], "unverified_tool_observation")
        self.assertEqual(len(result["sha256"]), 64)
        self.assertEqual(result, import_nmap_xml(VALID, allowed_addresses=("127.0.0.1",)))

    def test_scope_and_missing_scope_fail_closed(self):
        for scope in ((), ("127.0.0.2",), ("127.0.0.1", "127.0.0.1")):
            with self.subTest(scope=scope), self.assertRaises(NmapOfflineImportError):
                import_nmap_xml(VALID, allowed_addresses=scope)

    def test_malformed_xml_dtd_and_bad_port_rejected(self):
        variants = (
            b"<!DOCTYPE nmaprun><nmaprun/>",
            b"<nmaprun><host>",
            VALID.replace(b'portid="443"', b'portid="65536"'),
            VALID.replace(b'state="open"', b'state="confirmed_exploitable"'),
            VALID.replace(b'addr="127.0.0.1"', b'addr="127.0.0.2"'),
        )
        for payload in variants:
            with self.subTest(payload=payload[:50]), self.assertRaises(NmapOfflineImportError):
                import_nmap_xml(payload, allowed_addresses=("127.0.0.1",))

    def test_resource_limits(self):
        with self.assertRaises(NmapOfflineImportError):
            import_nmap_xml(VALID, allowed_addresses=("127.0.0.1",), max_bytes=20)
        with self.assertRaises(NmapOfflineImportError):
            import_nmap_xml(VALID, allowed_addresses=("127.0.0.1",), max_ports=1)
        with self.assertRaises(NmapOfflineImportError):
            import_nmap_xml(VALID, allowed_addresses=("127.0.0.1",), max_hosts=0)


if __name__ == "__main__":
    unittest.main()
