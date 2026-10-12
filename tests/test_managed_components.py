import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from nightrecon_red_engine.managed_components import resolve_managed_component

class TestManagedComponents(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.program=self.root/"nmap"
        self.program.write_bytes(b"trusted test fixture, not executable")
        self.manifest=self.root/"components.json"
        self.write_manifest("nmap",hashlib.sha256(self.program.read_bytes()).hexdigest())
    def write_manifest(self,path,sha):
        self.manifest.write_text(json.dumps({"schema":1,"components":{
            "nmap":{"path":path,"sha256":sha}}}))
    def test_managed_binary_resolves(self):
        result=resolve_managed_component(components_root=self.root,manifest_path=self.manifest)
        self.assertEqual(result.executable,self.program.resolve())
    def test_modified_binary_is_denied(self):
        self.program.write_bytes(b"replaced")
        with self.assertRaises(PermissionError):
            resolve_managed_component(components_root=self.root,manifest_path=self.manifest)
    def test_path_traversal_rejected(self):
        self.write_manifest("../nmap",hashlib.sha256(self.program.read_bytes()).hexdigest())
        with self.assertRaises(ValueError):
            resolve_managed_component(components_root=self.root,manifest_path=self.manifest)
    def test_unknown_component_denied(self):
        with self.assertRaises(PermissionError):
            resolve_managed_component(components_root=self.root,manifest_path=self.manifest,component_name="shell")
    def test_missing_manifest_denied(self):
        self.manifest.unlink()
        with self.assertRaises(FileNotFoundError):
            resolve_managed_component(components_root=self.root,manifest_path=self.manifest)
