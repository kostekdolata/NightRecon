"""Real Nmap integration test against this process's own loopback HTTP server.

Run only with RED_NIGHT_LIVE_NMAP_LOOPBACK=1. Never scans another host.
This proves executable -> XML -> evidence, not production policy enforcement.
"""
from __future__ import annotations
import os
import hashlib
import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nightrecon_red_engine.nmap_import import parse_nmap_xml
from nightrecon_red_engine.atomic_command_executor import execute_atomically_governed
from nightrecon_red_engine.governed_command_runner import FixedCommand
from nightrecon_red_engine.transactional_policy_authority import TransactionalPolicyAuthority
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"red-night-nmap-loopback")

    def log_message(self, *args):
        pass


@unittest.skipUnless(os.environ.get("RED_NIGHT_LIVE_NMAP_LOOPBACK") == "1",
                     "real Nmap loopback test requires explicit opt-in")
class TestLiveNmapLoopback(unittest.TestCase):
    def test_genuine_nmap_through_transactional_authority(self):
        nmap = shutil.which("nmap")
        if not nmap:
            self.fail("Real Nmap is required for governed loopback test")
        binary = Path(nmap).resolve()
        with binary.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                authority = TransactionalPolicyAuthority(root / "authority.db")
                now = datetime.now(timezone.utc)
                authority.register(EngagementExecutionPolicy(
                    engagement_id="loopback-lab", scope=("127.0.0.1",),
                    valid_from=(now - timedelta(minutes=2)).isoformat(),
                    valid_until=(now + timedelta(minutes=2)).isoformat(),
                    max_actions=1,
                    permitted_capabilities=("external.nmap.discovery",),
                    max_impact="low"), status="active")
                command = FixedCommand(
                    "nmap-loopback-integration", binary,
                    ("-sT", "-Pn", "-n", "--max-retries", "0",
                     "--max-rate", "10", "--host-timeout", "20s",
                     "-p", str(server.server_address[1]), "-oX", "-", "127.0.0.1"),
                    "external.nmap.discovery", impact="low",
                    timeout_seconds=30, executable_sha256=digest)
                kwargs = dict(command=command, engagement_id="loopback-lab",
                              engagement_status="active", target="127.0.0.1",
                              policy_store=None, ledger=None, authority=authority,
                              audit_path=root / "authorization.jsonl",
                              result_audit_path=root / "results.jsonl")
                with self.assertRaises(PermissionError):
                    execute_atomically_governed(action_id="out-of-scope", **{
                        **kwargs, "target": "192.0.2.1"})
                outcome = execute_atomically_governed(action_id="approved", **kwargs)
                self.assertEqual(outcome.returncode, 0, outcome.stderr[:1000])
                observed = parse_nmap_xml(outcome.stdout.encode("utf-8"))
                self.assertEqual({host.address for host in observed.hosts},
                                 {"127.0.0.1"})
                self.assertTrue(any(port.port == server.server_address[1]
                                    and port.state == "open"
                                    for host in observed.hosts for port in host.services))
                with self.assertRaises(PermissionError):
                    execute_atomically_governed(action_id="budget-exhausted", **kwargs)
                audits = [json.loads(line) for line in
                          (root / "results.jsonl").read_text().splitlines()]
                self.assertTrue(any(item["status"] == "completed" for item in audits))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

    def test_genuine_nmap_scan_to_xml_evidence(self):
        nmap = shutil.which("nmap")
        if not nmap:
            self.fail("Real Nmap executable is required for live loopback test")
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            port = server.server_address[1]
            command = [str(Path(nmap).resolve()), "-sT", "-Pn", "-n",
                       "--max-retries", "0", "--max-rate", "10",
                       "--host-timeout", "20s", "-p", str(port),
                       "-oX", "-", "127.0.0.1"]
            result = subprocess.run(command, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=30,
                                    check=False, shell=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace")[:2000])
            self.assertLessEqual(len(result.stdout), 8 * 1024 * 1024)
            evidence = parse_nmap_xml(result.stdout)
            self.assertEqual({host.address for host in evidence.hosts}, {"127.0.0.1"})
            self.assertTrue(any(service.protocol == "tcp" and
                                service.port == port and service.state == "open"
                                for host in evidence.hosts for service in host.services))
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)
