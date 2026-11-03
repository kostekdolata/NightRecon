"""Regression coverage for metadata-only Metasploit catalogue import."""
import tempfile
import unittest
from pathlib import Path

from nightrecon_red_engine.metasploit_catalogue import (
    MAX_JSON_BYTES, import_module_catalogue_file, parse_module_catalogue,
)


class MetasploitCatalogueTests(unittest.TestCase):
    SAMPLE = b'{"modules":[{"fullname":"auxiliary/scanner/example","name":"Example","description":"Read-only reference","references":["CVE-2020-0001"]}]}'

    def test_imports_only_unverified_metadata(self):
        catalogue = parse_module_catalogue(self.SAMPLE)
        self.assertEqual(catalogue.source, "metasploit-catalogue-unverified")
        self.assertEqual(catalogue.modules[0].module_type, "auxiliary")
        self.assertEqual(catalogue.modules[0].references, ("CVE-2020-0001",))

    def test_no_execution_surface(self):
        summary = parse_module_catalogue(self.SAMPLE).modules[0]
        self.assertFalse(hasattr(summary, "run"))
        self.assertFalse(hasattr(summary, "payload"))

    def test_rejects_traversal_paths(self):
        with self.assertRaisesRegex(ValueError, "path"):
            parse_module_catalogue(b'{"modules":[{"fullname":"exploit/../bad"}]}')

    def test_rejects_invalid_shapes(self):
        with self.assertRaisesRegex(ValueError, "modules"):
            parse_module_catalogue(b'{"modules":{}}')

    def test_rejects_oversized_input(self):
        with self.assertRaisesRegex(ValueError, "size limit"):
            parse_module_catalogue(b"x" * (MAX_JSON_BYTES + 1))

    def test_file_import(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "modules.json"
            path.write_bytes(self.SAMPLE)
            self.assertEqual(import_module_catalogue_file(path), parse_module_catalogue(self.SAMPLE))


if __name__ == "__main__":
    unittest.main()
