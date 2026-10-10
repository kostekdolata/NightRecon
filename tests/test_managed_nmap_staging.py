import hashlib
import tempfile
import unittest
from pathlib import Path

from nightrecon_red_engine.managed_nmap_staging import stage_trusted_nmap
from nightrecon_red_engine.managed_components import resolve_managed_component

class TestManagedNmapStaging(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = self.root / "nmap"
        self.source.write_bytes(b"test fixture only - no execution")
        self.destination = self.root / "managed"
        self.digest = hashlib.sha256(self.source.read_bytes()).hexdigest()

    def test_stages_approved_file_and_validates_manifest(self):
        staged = stage_trusted_nmap(
            source=self.source, components_root=self.destination,
            trusted_sha256=self.digest)
        component = resolve_managed_component(
            components_root=self.destination,
            manifest_path=self.destination / "components.json")
        self.assertEqual(component.executable, staged.resolve())
        self.assertEqual(component.sha256, self.digest)

    def test_wrong_approval_rejected_without_staging(self):
        with self.assertRaises(PermissionError):
            stage_trusted_nmap(source=self.source, components_root=self.destination,
                               trusted_sha256="f"*64)
        self.assertFalse((self.destination / "nmap").exists())

    def test_existing_installation_not_replaced(self):
        stage_trusted_nmap(source=self.source, components_root=self.destination,
                           trusted_sha256=self.digest)
        with self.assertRaises(FileExistsError):
            stage_trusted_nmap(source=self.source, components_root=self.destination,
                               trusted_sha256=self.digest)
