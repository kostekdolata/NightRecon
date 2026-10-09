"""Real Nmap integration test against this process's own loopback HTTP server.

Run only with RED_NIGHT_LIVE_NMAP_LOOPBACK=1. Never scans another host.
This proves executable -> XML -> evidence, not production policy enforcement.
"""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from nightrecon_red_engine.nmap_import import parse_nmap_xml


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
