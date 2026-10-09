import sys
import tempfile
import unittest
from pathlib import Path
from nightrecon_red_engine.command_registry import CommandRegistry,execute_registered
from nightrecon_red_engine.governed_command_runner import FixedCommand

class TestCommandRegistry(unittest.TestCase):
    def setUp(self):
        self.fixed=FixedCommand("python-version",Path(sys.executable),("--version",),"external.local.diagnostics")
    def test_known_command(self):
        self.assertEqual(CommandRegistry((self.fixed,)).get("python-version"),self.fixed)
    def test_unknown_denied(self):
        with self.assertRaises(PermissionError):
            CommandRegistry((self.fixed,)).get("untrusted-shell")
    def test_duplicate_denied(self):
        with self.assertRaises(ValueError):
            CommandRegistry((self.fixed,self.fixed))
    def test_registry_has_no_request_arguments(self):
        self.assertEqual(CommandRegistry((self.fixed,)).names(),("python-version",))
