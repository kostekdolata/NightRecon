"""Fail-closed offline TShark capture preview regressions."""
import contextlib
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nightrecon_red_engine.host_preflight import HostPreflightSnapshot, HostToolCandidate
from nightrecon_red_engine.host_tshark_plan_preview import prepare_offline_tshark_plan
from nightrecon_red_engine.red_cli import main as red_main
from nightrecon_red_engine.transactional_policy_authority import TransactionalPolicyAuthority
from nightrecon_shared_core.editions import available_commands
from nightrecon_shared_core.engagement_policy import EngagementExecutionPolicy


class OfflineTsharkPreviewTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.binary = self.root / "tshark.exe"
        self.binary.write_bytes(b"synthetic TShark, never executable")
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"schema": 1, "components": {
            "tshark": {"path": "tshark.exe", "sha256": self.digest},
        }}))
        self.capture_root = self.root / "captures"
        self.capture_root.mkdir()
        self.capture = self.capture_root / "test.pcap"
        self.capture.write_bytes(b"synthetic offline test capture")
        self.database = self.root / "authority.db"
        self.authority = TransactionalPolicyAuthority(self.database)
        self.engagement = "offline-capture-lab"
        now = datetime.now(timezone.utc)
        self.authority.register(EngagementExecutionPolicy(
            engagement_id=self.engagement, scope=("192.0.2.10",),
            valid_from=(now - timedelta(minutes=2)).isoformat(),
            valid_until=(now + timedelta(minutes=10)).isoformat(),
            max_actions=1, permitted_capabilities=("external.tshark.inspect",),
            max_impact="low",
        ), status="active")
        self.snapshot = HostPreflightSnapshot(
            schema=1, collected_at=now.isoformat(),
            os="Windows", architecture="AMD64",
            interfaces=(), addresses=(), routes=(),
            candidates=(HostToolCandidate("tshark", str(self.binary), "unverified-present",
                                          "local-path-lookup-only"),), errors=(),
        )

    def preview(self, **kwargs):
        values = dict(snapshot=self.snapshot, target="192.0.2.10",
                      capture_path=self.capture, capture_root=self.capture_root,
                      engagement_id=self.engagement, action_id="capture-01",
                      authority_db=self.database, components_root=self.root,
                      manifest_path=self.manifest)
        values.update(kwargs)
        return prepare_offline_tshark_plan(**values)

    def test_preview_is_inert_with_bounded_capture_and_no_reservation(self):
        report = self.preview()
        self.assertFalse(report["action_reserved"])
        self.assertTrue(report["execution_opt_in_required"])
        self.assertEqual(report["execution_status"], "not-started")
        task = report["plan"]["tasks"][0]
        self.assertEqual(task["kind"], "tshark")
        self.assertEqual(task["target"], "192.0.2.10")
        self.assertEqual(task["capture_path"], str(self.capture.resolve()))
        self.assertEqual(task["trusted_sha256"], self.digest)
        with self.authority._db() as db:
            self.assertEqual(db.execute(
                "SELECT actions_used FROM engagement_authority").fetchone()[0], 0)
            self.assertEqual(db.execute(
                "SELECT COUNT(*) FROM authority_reservations").fetchone()[0], 0)

    def test_outside_capture_and_empty_or_oversized_file_are_rejected(self):
        outside = self.root / "outside.pcap"
        outside.write_bytes(b"outside capture")
        with self.assertRaises(PermissionError):
            self.preview(capture_path=outside)
        self.capture.write_bytes(b"")
        with self.assertRaises(ValueError):
            self.preview()
        with self.capture.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            self.preview()

    def test_capture_symlink_and_directory_are_rejected(self):
        with self.assertRaises(ValueError):
            self.preview(capture_path=self.capture_root)
        link = self.capture_root / "linked.pcap"
        try:
            link.symlink_to(self.capture)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable without permissions")
        with self.assertRaises(PermissionError):
            self.preview(capture_path=link)

    def test_policy_denies_out_of_scope_and_nonexistent_engagement(self):
        with self.assertRaisesRegex(PermissionError, "target_out_of_scope"):
            self.preview(target="198.51.100.20")
        with self.assertRaisesRegex(PermissionError, "not registered"):
            self.preview(engagement_id="missing")
        with self.assertRaises(FileNotFoundError):
            self.preview(authority_db=self.root / "missing.db")

    def test_tshark_tampering_and_candidate_mismatch_fail_closed(self):
        self.binary.write_bytes(b"tampered")
        with self.assertRaisesRegex(PermissionError, "digest mismatch"):
            self.preview()
        self.binary.write_bytes(b"synthetic TShark, never executable")
        changed = HostPreflightSnapshot(**{**self.snapshot.__dict__, "candidates": (
            HostToolCandidate("tshark", str(self.root / "different.exe"),
                              "unverified-present", "local-path-lookup-only"),
        )})
        with self.assertRaises((PermissionError, FileNotFoundError)):
            self.preview(snapshot=changed)

    def test_snapshot_timestamp_and_explicit_attribution_are_required(self):
        for stamp in ("invalid", None, "2026-11-05T10:00:00",
                      (datetime.now(timezone.utc) - timedelta(minutes=6)).isoformat()):
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                self.preview(snapshot=HostPreflightSnapshot(
                    **{**self.snapshot.__dict__, "collected_at": stamp}))
        with self.assertRaises(ValueError):
            self.preview(target="192.0.2.0/24")

    def test_public_cli_returns_only_preview_without_execution(self):
        self.assertIn("host-capture-preview", available_commands("red"))
        args = (
            "host-capture-preview", "--target", "192.0.2.10",
            "--capture", str(self.capture), "--capture-root", str(self.capture_root),
            "--engagement-id", self.engagement, "--action-id", "capture-01",
            "--authority-db", str(self.database), "--components-root", str(self.root),
            "--manifest", str(self.manifest),
        )
        with patch("nightrecon_red_engine.host_preflight.collect_host_preflight",
                   return_value=self.snapshot), contextlib.redirect_stdout(io.StringIO()) as out:
            red_main(args)
        data = json.loads(out.getvalue())
        self.assertFalse(data["action_reserved"])
        self.assertEqual(data["plan"]["tasks"][0]["kind"], "tshark")


if __name__ == "__main__":
    unittest.main()
