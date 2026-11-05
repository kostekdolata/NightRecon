"""Nuclei host-origin preparation must remain inert and fail closed."""
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy
from nightrecon_red_engine.host_preflight import HostPreflightSnapshot, HostToolCandidate
from nightrecon_red_engine.host_nuclei_plan_preview import prepare_local_nuclei_plan
from nightrecon_red_engine.red_cli import main as red_main
from nightrecon_red_engine.transactional_policy_authority import TransactionalPolicyAuthority


class NucleiHostPreviewTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.binary = self.root / "nuclei.exe"
        self.binary.write_bytes(b"synthetic pinned nuclei; not executable")
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"schema": 1, "components": {
            "nuclei": {"path": "nuclei.exe", "sha256": self.digest},
        }}), encoding="utf-8")
        self.database = self.root / "authority.db"
        self.authority = TransactionalPolicyAuthority(self.database)
        self.engagement = "nuclei-local-fixture"
        self.register(("192.0.2.10",), ("external.nuclei.http-fingerprint",))
        self.snapshot = HostPreflightSnapshot(
            schema=1, collected_at=datetime.now(timezone.utc).isoformat(),
            os="Windows", architecture="AMD64",
            interfaces=({"name": "Wi-Fi", "index": 4},),
            addresses=(
                {"interface": "Wi-Fi", "family": "ipv4", "address": "192.0.2.10",
                 "source": "local-interface-api"},
                {"interface": "VPN", "family": "ipv4", "address": "198.51.100.20",
                 "source": "local-interface-api"},
            ),
            routes=({"destination": "0.0.0.0/0", "gateway": "192.0.2.1"},),
            candidates=(HostToolCandidate(
                "nuclei", str(self.binary), "unverified-present", "local-path-lookup-only",
            ),), errors=(),
        )

    def register(self, scope, capabilities):
        now = datetime.now(timezone.utc)
        self.authority.register(EngagementExecutionPolicy(
            engagement_id=self.engagement, scope=tuple(scope),
            valid_from=(now - timedelta(minutes=2)).isoformat(),
            valid_until=(now + timedelta(minutes=10)).isoformat(),
            max_actions=1, permitted_capabilities=tuple(capabilities), max_impact="low",
        ), status="active")

    def preview(self, **kwargs):
        args = dict(snapshot=self.snapshot, target="192.0.2.10",
                    origin="http://192.0.2.10:8080",
                    engagement_id=self.engagement, action_id="nuclei-self-1",
                    authority_db=self.database, components_root=self.root,
                    manifest_path=self.manifest)
        args.update(kwargs)
        return prepare_local_nuclei_plan(**args)

    def test_valid_preview_is_inert_and_never_reserves(self):
        result = self.preview()
        self.assertEqual(result["plan"]["schema"], 1)
        task = result["plan"]["tasks"][0]
        self.assertEqual(task["kind"], "nuclei")
        self.assertEqual(task["target"], "http://192.0.2.10:8080")
        self.assertEqual(task["trusted_sha256"], self.digest)
        self.assertFalse(result["action_reserved"])
        self.assertEqual(result["execution_status"], "not-started")
        with self.authority._db() as db:
            self.assertEqual(db.execute("SELECT actions_used FROM engagement_authority").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM authority_reservations").fetchone()[0], 0)

    def test_invalid_origins_never_prepare(self):
        bad = (
            "http://192.0.2.1", "https://198.51.100.20", "http://example.com",
            "http://192.0.2.10/secret", "http://192.0.2.10?x=1",
            "http://192.0.2.10#fragment", "http://user:pass@192.0.2.10",
            "http://192.0.2.10:99999", "ftp://192.0.2.10",
            "http://192.0.2.10:0",
        )
        for origin in bad:
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                self.preview(origin=origin)

    def test_scope_and_capability_are_independent_of_host_inventory(self):
        with self.assertRaisesRegex(PermissionError, "target_out_of_scope"):
            self.preview(target="198.51.100.20", origin="http://198.51.100.20")
        self.register(("198.51.100.20",), ("external.nuclei.http-fingerprint",))
        with self.assertRaisesRegex(PermissionError, "target_out_of_scope"):
            self.preview()
        self.register(("192.0.2.10",), ("external.nmap.discovery",))
        with self.assertRaises(PermissionError):
            self.preview()

    def test_digest_and_candidate_must_match_managed_manifest(self):
        self.binary.write_bytes(b"tampered")
        with self.assertRaisesRegex(PermissionError, "digest mismatch"):
            self.preview()
        self.binary.write_bytes(b"synthetic pinned nuclei; not executable")
        other = HostPreflightSnapshot(**{**self.snapshot.__dict__, "candidates": (
            HostToolCandidate("nuclei", str(self.root / "other.exe"),
                              "unverified-present", "local-path-lookup-only"),
        )})
        with self.assertRaises((PermissionError, FileNotFoundError)):
            self.preview(snapshot=other)

    def test_stale_and_invalid_snapshot_rejected(self):
        for stamp in ((datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat(),
                      (datetime.now(timezone.utc) + timedelta(minutes=2)).isoformat(),
                      "invalid", "2026-11-05T10:00:00", None):
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                self.preview(snapshot=HostPreflightSnapshot(
                    **{**self.snapshot.__dict__, "collected_at": stamp}))

    def test_public_cli_routes_only_preview_and_requires_origin(self):
        args = (
            "host-plan-preview", "--tool", "nuclei", "--target", "192.0.2.10",
            "--origin", "http://192.0.2.10:8080",
            "--engagement-id", self.engagement, "--action-id", "nuclei-self-1",
            "--authority-db", str(self.database), "--components-root", str(self.root),
            "--manifest", str(self.manifest),
        )
        with patch("nightrecon_red_engine.host_preflight.collect_host_preflight",
                   return_value=self.snapshot), contextlib.redirect_stdout(io.StringIO()) as output:
            red_main(args)
        report = json.loads(output.getvalue())
        self.assertEqual(report["plan"]["tasks"][0]["kind"], "nuclei")
        self.assertFalse(report["action_reserved"])
        with self.assertRaisesRegex(ValueError, "requires --origin"):
            red_main(tuple(item for index, item in enumerate(args)
                           if index not in (4, 5)))


if __name__ == "__main__":
    unittest.main()
