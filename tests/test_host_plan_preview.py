"""Host-sourced but independently governed Nmap plan preview regressions."""
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
from nightrecon_red_engine.host_plan_preview import prepare_local_nmap_plan
from nightrecon_red_engine.red_cli import main as public_red_main
from nightrecon_red_engine.transactional_policy_authority import TransactionalPolicyAuthority
from nightrecon_shared_core.editions import available_commands


class HostPlanPreviewTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.bin = self.root / "nmap.exe"
        self.bin.write_bytes(b"locally-managed-synthetic-nmap-no-execution")
        self.digest = hashlib.sha256(self.bin.read_bytes()).hexdigest()
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({
            "schema": 1, "components": {
                "nmap": {"path": "nmap.exe", "sha256": self.digest},
            },
        }), encoding="utf-8")
        self.db = self.root / "authority.db"
        self.engagement_id = "operator-lab"
        self.authority = TransactionalPolicyAuthority(self.db)
        self.register(("192.0.2.10",))
        self.snapshot = HostPreflightSnapshot(
            schema=1,
            collected_at=datetime.now(timezone.utc).isoformat(),
            os="Windows", architecture="AMD64",
            interfaces=({"name": "Wi-Fi", "index": 4},),
            addresses=(
                {"interface": "Wi-Fi", "family": "ipv4",
                 "address": "192.0.2.10", "source": "local-interface-api"},
                {"interface": "VPN", "family": "ipv4",
                 "address": "198.51.100.20", "source": "local-interface-api"},
            ),
            routes=({"destination": "0.0.0.0/0", "gateway": "192.0.2.1"},),
            candidates=(HostToolCandidate(
                "nmap", str(self.bin), "unverified-present", "local-path-lookup-only",
            ),),
            errors=(),
        )

    def register(self, scope):
        now = datetime.now(timezone.utc)
        self.authority.register(EngagementExecutionPolicy(
            engagement_id=self.engagement_id,
            scope=tuple(scope),
            valid_from=(now - timedelta(minutes=2)).isoformat(),
            valid_until=(now + timedelta(minutes=10)).isoformat(),
            max_actions=1,
            permitted_capabilities=("external.nmap.discovery",),
            max_impact="low",
        ), status="active")

    def preview(self, **changes):
        args = {
            "snapshot": self.snapshot, "target": "192.0.2.10",
            "engagement_id": self.engagement_id, "action_id": "self-01",
            "authority_db": self.db, "components_root": self.root,
            "manifest_path": self.manifest,
        }
        args.update(changes)
        return prepare_local_nmap_plan(**args)

    def test_local_operator_selected_host_creates_inert_valid_batch_task(self):
        result = self.preview()
        self.assertEqual(result["execution_status"], "not-started")
        self.assertFalse(result["action_reserved"])
        self.assertTrue(result["execution_opt_in_required"])
        self.assertEqual(result["plan"]["schema"], 1)
        self.assertEqual(result["plan"]["tasks"][0]["target"], "192.0.2.10")
        self.assertEqual(result["plan"]["tasks"][0]["trusted_sha256"], self.digest)
        with self.authority._db() as db:
            self.assertEqual(
                db.execute("SELECT actions_used FROM engagement_authority").fetchone()[0], 0,
            )
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM authority_reservations").fetchone()[0], 0,
            )

    def test_stale_and_future_dated_host_inventory_fail_closed(self):
        now = datetime.now(timezone.utc)
        for stamp in (
            now - timedelta(minutes=6),
            now + timedelta(minutes=2),
        ):
            with self.subTest(timestamp=stamp.isoformat()):
                snapshot = HostPreflightSnapshot(
                    **{**self.snapshot.__dict__, "collected_at": stamp.isoformat()}
                )
                with self.assertRaisesRegex(ValueError, "stale or future-dated"):
                    self.preview(snapshot=snapshot)
        with self.authority._db() as db:
            self.assertEqual(
                db.execute("SELECT actions_used FROM engagement_authority").fetchone()[0], 0,
            )

    def test_missing_or_naive_host_inventory_timestamp_fails_closed(self):
        for stamp in ("invalid", "", "2026-11-05T10:00:00", None):
            with self.subTest(timestamp=stamp):
                snapshot = HostPreflightSnapshot(
                    **{**self.snapshot.__dict__, "collected_at": stamp}
                )
                with self.assertRaisesRegex(ValueError, "invalid collection timestamp"):
                    self.preview(snapshot=snapshot)

    def test_vpn_address_discovered_but_not_authorised_is_denied(self):
        with self.assertRaisesRegex(PermissionError, "target_out_of_scope"):
            self.preview(target="198.51.100.20")

    def test_remote_route_gateway_not_selected_from_inventory(self):
        with self.assertRaisesRegex(PermissionError, "not found"):
            self.preview(target="192.0.2.1")

    def test_manifest_mismatch_and_relocated_binary_fail_closed(self):
        self.manifest.write_text(json.dumps({
            "schema": 1, "components": {
                "nmap": {"path": "nmap.exe", "sha256": "0" * 64},
            },
        }), encoding="utf-8")
        with self.assertRaisesRegex(PermissionError, "digest mismatch"):
            self.preview()
        self.manifest.write_text(json.dumps({
            "schema": 1, "components": {
                "nmap": {"path": "nmap.exe", "sha256": self.digest},
            },
        }), encoding="utf-8")
        fake = HostPreflightSnapshot(
            **{**self.snapshot.__dict__, "candidates": (
                HostToolCandidate("nmap", str(self.root / "not-approved.exe"),
                                  "unverified-present", "local-path-lookup-only"),
            )}
        )
        with self.assertRaises((PermissionError, FileNotFoundError)):
            self.preview(snapshot=fake)

    def test_absent_registered_authority_is_rejected(self):
        with self.assertRaises(FileNotFoundError):
            self.preview(authority_db=self.root / "missing.db")
        with self.assertRaisesRegex(PermissionError, "not registered"):
            self.preview(engagement_id="not-registered")

    def test_public_cli_previews_without_running_executor(self):
        self.assertIn("host-plan-preview", available_commands("red"))
        args = (
            "host-plan-preview", "--target", "192.0.2.10",
            "--engagement-id", self.engagement_id, "--action-id", "self-01",
            "--authority-db", str(self.db), "--components-root", str(self.root),
            "--manifest", str(self.manifest),
        )
        with patch(
            "nightrecon_red_engine.host_preflight.collect_host_preflight",
            return_value=self.snapshot,
        ), patch(
            "nightrecon_red_engine.advanced_cli.prepare_local_nmap_plan",
            create=True,
        ) as unexpected:
            # The implementation imports the preparation function inside the
            # dispatch body, not as a global. This stand-in must not be used.
            with contextlib.redirect_stdout(io.StringIO()) as out:
                public_red_main(args)
        result = json.loads(out.getvalue())
        self.assertEqual(result["execution_status"], "not-started")
        self.assertEqual(result["plan"]["tasks"][0]["kind"], "nmap")
        unexpected.assert_not_called()


if __name__ == "__main__":
    unittest.main()
