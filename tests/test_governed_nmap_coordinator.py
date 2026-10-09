import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from nightrecon_red_engine.governed_command_runner import CommandOutcome
from nightrecon_red_engine.governed_nmap_coordinator import execute_governed_nmap_discovery

class TestGovernedNmapCoordinator(unittest.TestCase):
    def test_disabled_by_default(self):
        with self.assertRaises(PermissionError):
            execute_governed_nmap_discovery(
                authority=None, engagement_id="lab", action_id="one",
                target="192.0.2.1", executable="/not/installed/nmap",
                trusted_sha256="0"*64, audit_path="/unused/a",
                result_audit_path="/unused/b")
    def test_untrusted_executable_denied_before_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            program=Path(folder)/"nmap"
            program.write_bytes(b"not nmap")
            with self.assertRaises(PermissionError):
                execute_governed_nmap_discovery(
                    authority=None, engagement_id="lab", action_id="one",
                    target="192.0.2.1", executable=program,
                    trusted_sha256=hashlib.sha256(b"expected").hexdigest(),
                    audit_path=Path(folder)/"a",result_audit_path=Path(folder)/"b",
                    enabled=True)
    def test_argument_injection_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            program=Path(folder)/"nmap"
            program.write_bytes(b"trusted")
            with self.assertRaises(ValueError):
                execute_governed_nmap_discovery(
                    authority=None, engagement_id="lab", action_id="one",
                    target="192.0.2.1 --script unsafe", executable=program,
                    trusted_sha256=hashlib.sha256(b"trusted").hexdigest(),
                    audit_path=Path(folder)/"a",result_audit_path=Path(folder)/"b",
                    enabled=True)

    def test_complete_scan_to_evidence_with_stubbed_execution(self):
        xml = ('<nmaprun><host><status state="up"/>'
               '<address addr="192.0.2.1" addrtype="ipv4"/>'
               '<ports><port protocol="tcp" portid="443">'
               '<state state="open"/></port></ports></host></nmaprun>')
        with tempfile.TemporaryDirectory() as folder:
            program=Path(folder)/"nmap"
            program.write_bytes(b"test binary - never executed")
            digest=hashlib.sha256(program.read_bytes()).hexdigest()
            with patch(
                "nightrecon_red_engine.governed_nmap_coordinator.execute_atomically_governed",
                return_value=CommandOutcome("nmap-bounded-connect",0,xml,""),
            ) as execute:
                result=execute_governed_nmap_discovery(
                    authority=None,engagement_id="lab",action_id="run1",
                    target="192.0.2.1",executable=program,
                    trusted_sha256=digest,audit_path=Path(folder)/"auth.jsonl",
                    result_audit_path=Path(folder)/"results.jsonl",enabled=True)
                self.assertEqual(result.evidence.hosts[0].services[0].port,443)
                self.assertEqual(execute.call_args.kwargs["command"].arguments[-1],"192.0.2.1")
                self.assertEqual(execute.call_args.kwargs["command"].executable_sha256,digest)
