import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from nightrecon_red_engine.managed_bundle_preflight import preflight_nmap_bundle

class TestManagedBundlePreflight(unittest.TestCase):
    def test_optional_absent_is_explicitly_unavailable(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            result=preflight_nmap_bundle(components_root=root/"missing",
                manifest_path=root/"missing"/"components.json")
            self.assertFalse(result.bundled)
    def test_required_absent_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            with self.assertRaises(FileNotFoundError):
                preflight_nmap_bundle(components_root=root/"missing",
                    manifest_path=root/"missing"/"components.json",require_bundle=True)
    def test_mismatched_binary_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/"nmap").write_bytes(b"modified")
            (root/"components.json").write_text(json.dumps({"schema":1,
                "components":{"nmap":{"path":"nmap","sha256":"0"*64}}}))
            with self.assertRaises(PermissionError):
                preflight_nmap_bundle(components_root=root,
                    manifest_path=root/"components.json",require_bundle=True)
    def test_valid_manifest_preflight_succeeds_with_warning(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            (root/"nmap").write_bytes(b"fixture, never execute")
            digest=hashlib.sha256((root/"nmap").read_bytes()).hexdigest()
            (root/"components.json").write_text(json.dumps({"schema":1,
                "components":{"nmap":{"path":"nmap","sha256":digest}}}))
            result=preflight_nmap_bundle(components_root=root,
                manifest_path=root/"components.json",require_bundle=True)
            self.assertTrue(result.bundled)
            self.assertTrue(result.warnings)
