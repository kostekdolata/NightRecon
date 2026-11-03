import unittest
from nightrecon_red_engine.zap_import import parse_zap_json, MAX_BYTES

class ZapImportTests(unittest.TestCase):
    def test_metadata_only(self):
        result = parse_zap_json(b'{"site":[{"@name":"https://example.org/path","alerts":[{"pluginid":"10020","name":"Missing Header","riskdesc":"Low","confidence":"Medium","instances":[{"uri":"https://example.org/secret"}]}]}]}')
        self.assertEqual(result.source, "zap-json-unverified")
        self.assertEqual(result.alerts[0].site, "https://example.org")
        self.assertEqual(result.alerts[0].count, 1)
        self.assertFalse(hasattr(result.alerts[0], "instances"))

    def test_empty_report(self):
        self.assertEqual(parse_zap_json(b'{"site":[]}').alerts, ())

    def test_invalid_schema(self):
        with self.assertRaises(ValueError):
            parse_zap_json(b'{"site":{}}')

    def test_rejects_non_http_scheme(self):
        with self.assertRaises(ValueError):
            parse_zap_json(b'{"site":[{"@name":"file:///etc/passwd"}]}')

    def test_rejects_oversized_input(self):
        with self.assertRaisesRegex(ValueError, "size limit"):
            parse_zap_json(b"x" * (MAX_BYTES + 1))

if __name__ == "__main__":
    unittest.main()
