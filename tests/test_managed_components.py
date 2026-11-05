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
    def test_nuclei_requires_own_approved_manifest_and_digest(self):
        nuclei = self.root / "nuclei"
        nuclei.write_bytes(b"synthetic nuclei binary; never executed")
        digest = hashlib.sha256(nuclei.read_bytes()).hexdigest()
        self.manifest.write_text(json.dumps({"schema": 1, "components": {
            "nmap": {"path": "nmap", "sha256": hashlib.sha256(self.program.read_bytes()).hexdigest()},
            "nuclei": {"path": "nuclei", "sha256": digest},
        }}))
        result = resolve_managed_component(
            components_root=self.root, manifest_path=self.manifest,
            component_name="nuclei",
        )
        self.assertEqual(result.executable, nuclei.resolve())
        self.assertEqual(result.sha256, digest)
        nuclei.write_bytes(b"tampered")
        with self.assertRaisesRegex(PermissionError, "digest mismatch"):
            resolve_managed_component(
                components_root=self.root, manifest_path=self.manifest,
                component_name="nuclei",
            )

    def test_nuclei_cannot_reuse_nmap_binary_or_escaped_path(self):
        digest = hashlib.sha256(self.program.read_bytes()).hexdigest()
        self.manifest.write_text(json.dumps({"schema": 1, "components": {
            "nuclei": {"path": "nmap", "sha256": digest},
        }}))
        with self.assertRaisesRegex(PermissionError, "Unsupported managed component"):
            resolve_managed_component(
                components_root=self.root, manifest_path=self.manifest,
                component_name="nuclei",
            )
        self.manifest.write_text(json.dumps({"schema": 1, "components": {
            "nuclei": {"path": "../nuclei", "sha256": digest},
        }}))
        with self.assertRaises(ValueError):
            resolve_managed_component(
                components_root=self.root, manifest_path=self.manifest,
                component_name="nuclei",
            )

    def test_tshark_requires_independently_pinned_manifest_digest(self):
        tshark = self.root / "tshark.exe"
        tshark.write_bytes(b"synthetic TShark test fixture; not executed")
        digest = hashlib.sha256(tshark.read_bytes()).hexdigest()
        self.manifest.write_text(json.dumps({"schema": 1, "components": {
            "tshark": {"path": "tshark.exe", "sha256": digest},
        }}))
        result = resolve_managed_component(
            components_root=self.root, manifest_path=self.manifest,
            component_name="tshark",
        )
        self.assertEqual(result.executable, tshark.resolve())
        self.assertEqual(result.sha256, digest)
        tshark.write_bytes(b"modified TShark")
        with self.assertRaisesRegex(PermissionError, "digest mismatch"):
            resolve_managed_component(
                components_root=self.root, manifest_path=self.manifest,
                component_name="tshark",
            )

    def test_tshark_refuses_other_tool_binary_and_path_escape(self):
        digest = hashlib.sha256(self.program.read_bytes()).hexdigest()
        for invalid_path, error in (("nmap", PermissionError), ("../tshark.exe", ValueError)):
            with self.subTest(path=invalid_path):
                self.manifest.write_text(json.dumps({"schema": 1, "components": {
                    "tshark": {"path": invalid_path, "sha256": digest},
                }}))
                with self.assertRaises(error):
                    resolve_managed_component(
                        components_root=self.root, manifest_path=self.manifest,
                        component_name="tshark",
                    )

    def test_tshark_requires_its_own_manifest_entry(self):
        with self.assertRaisesRegex(PermissionError, "no approved manifest entry"):
            resolve_managed_component(
                components_root=self.root, manifest_path=self.manifest,
                component_name="tshark",
            )

    def test_missing_manifest_denied(self):
        self.manifest.unlink()
        with self.assertRaises(FileNotFoundError):
            resolve_managed_component(components_root=self.root,manifest_path=self.manifest)
