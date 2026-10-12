import unittest
from nightrecon_red_engine.local_diagnostics import get_local_diagnostic

class TestLocalDiagnostics(unittest.TestCase):
    def test_local_version_preset_is_fixed_and_unprivileged(self):
        command=get_local_diagnostic("local-python-version")
        self.assertTrue(command.executable.is_absolute())
        self.assertEqual(command.arguments,("--version",))
        self.assertEqual(command.capability,"external.local.diagnostics")
        self.assertFalse(command.elevated)
        self.assertEqual(command.impact,"low")
    def test_unknown_presets_rejected(self):
        with self.assertRaises(PermissionError):
            get_local_diagnostic("arbitrary-command")
