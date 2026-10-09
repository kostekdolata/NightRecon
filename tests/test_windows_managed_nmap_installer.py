"""Guard against accidental unconditional bundling of third-party tools."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "installer" / "windows" / "red-night.iss"


class TestManagedNmapInstaller(unittest.TestCase):
    def test_nmap_payload_requires_explicit_build_flag(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("#ifdef ManagedNmapDir", source)
        self.assertIn('Source: "{#ManagedNmapDir}', source)
        self.assertIn('DestDir: "{app}\\managed-tools\\nmap"', source)
        self.assertIn("#endif", source)

    def test_existing_application_payload_still_included(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('Source: "{#SourceDir}\\*"; DestDir: "{app}"', source)
        self.assertIn("PrivilegesRequired=lowest", source)
