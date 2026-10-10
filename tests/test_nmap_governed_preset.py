import tempfile
import hashlib
import unittest
from pathlib import Path
from nightrecon_red_engine.nmap_governed_preset import bounded_nmap_tcp_connect

class TestNmapGovernedPreset(unittest.TestCase):
    def test_fixed_low_impact_flags(self):
        with tempfile.TemporaryDirectory() as folder:
            program=Path(folder)/"nmap"
            program.write_text("")
            result=bounded_nmap_tcp_connect(executable=program,target="192.0.2.4",trusted_sha256=hashlib.sha256(b"").hexdigest())
            self.assertEqual(result.arguments[-1],"192.0.2.4")
            self.assertEqual(result.arguments[-3:-1],("-oX","-"))
            self.assertEqual(result.executable_sha256,hashlib.sha256(b"").hexdigest())
            self.assertFalse(result.elevated)
            self.assertEqual(result.capability,"external.nmap.discovery")
    def test_rejects_target_injection(self):
        with tempfile.TemporaryDirectory() as folder:
            program=Path(folder)/"nmap"
            program.write_text("")
            with self.assertRaises(ValueError):
                bounded_nmap_tcp_connect(executable=program,target="192.0.2.4 --script vuln",trusted_sha256=hashlib.sha256(b"").hexdigest())
    def test_no_unregistered_executable(self):
        with tempfile.TemporaryDirectory() as folder:
            program=Path(folder)/"bash"
            program.write_text("")
            with self.assertRaises(ValueError):
                bounded_nmap_tcp_connect(executable=program,target="192.0.2.4",trusted_sha256=hashlib.sha256(b"").hexdigest())

    def test_executable_digest_mismatch_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            program=Path(folder)/"nmap"
            program.write_bytes(b"untrusted")
            with self.assertRaises(PermissionError):
                bounded_nmap_tcp_connect(executable=program,target="192.0.2.4",
                    trusted_sha256=hashlib.sha256(b"trusted").hexdigest())
