import unittest
from nightrecon_red_engine.nuclei_import import parse_nuclei_jsonl, MAX_BYTES

class NucleiImportTests(unittest.TestCase):
    def test_jsonl_import(self):
        evidence = parse_nuclei_jsonl(b'{"template-id":"http/missing-header","info":{"severity":"low"},"matched-at":"https://example.org/private?q=secret","matcher-name":"header"}\n')
        self.assertEqual(evidence.source, "nuclei-jsonl-unverified")
        self.assertEqual(evidence.findings[0].matched_origin, "https://example.org")
        self.assertEqual(evidence.findings[0].severity, "low")

    def test_multiple_lines(self):
        data = b'{"template-id":"a"}\n{"template-id":"b"}\n'
        self.assertEqual(len(parse_nuclei_jsonl(data).findings), 2)

    def test_empty_input(self):
        self.assertEqual(parse_nuclei_jsonl(b"").findings, ())

    def test_bad_json(self):
        with self.assertRaises(ValueError):
            parse_nuclei_jsonl(b"{broken")

    def test_oversize(self):
        with self.assertRaisesRegex(ValueError, "size limit"):
            parse_nuclei_jsonl(b"x" * (MAX_BYTES+1))

if __name__ == "__main__":
    unittest.main()
