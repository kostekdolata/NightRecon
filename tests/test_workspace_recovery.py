"""Tests for Red Night workspace backup and recovery."""

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from nightrecon_red_engine.workspace_recovery import (
    MANIFEST_NAME,
    create_workspace_backup,
    restore_workspace_backup,
    verify_workspace_backup,
)


class WorkspaceRecoveryTests(unittest.TestCase):
    def test_backup_verify_restore_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "workspace"
            source.mkdir()
            (source / "engagements.json").write_text(
                '{"engagements":[]}
', encoding="utf-8"
            )
            nested = source / "nested"
            nested.mkdir()
            (nested / "audit.jsonl").write_text(
                '{"event":"x"}
', encoding="utf-8"
            )
            archive = root / "backup.nrwb"

            created = create_workspace_backup(source, archive)
            verified = verify_workspace_backup(archive)
            restored = root / "restored"
            recovered = restore_workspace_backup(archive, restored)

            self.assertEqual(created, verified)
            self.assertEqual(verified, recovered)
            self.assertEqual(
                (restored / "engagements.json").read_bytes(),
                (source / "engagements.json").read_bytes(),
            )
            self.assertEqual(
                (restored / "nested" / "audit.jsonl").read_bytes(),
                (source / "nested" / "audit.jsonl").read_bytes(),
            )
            self.assertEqual(created.authorization_effect, "none")

    def test_tampered_payload_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "workspace"
            source.mkdir()
            (source / "engagements.json").write_text("original", encoding="utf-8")
            archive = root / "backup.nrwb"
            create_workspace_backup(source, archive)

            with zipfile.ZipFile(archive, "a") as zf:
                zf.writestr("engagements.json", b"tampered")

            with self.assertRaises(ValueError):
                verify_workspace_backup(archive)

    def test_manifest_with_authority_effect_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "bad.nrwb"
            manifest = {
                "schema_version": 1,
                "authorization_effect": "grant",
                "files": [],
            }
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr(
                    MANIFEST_NAME,
                    json.dumps(manifest).encode("utf-8"),
                )
            with self.assertRaisesRegex(ValueError, "cannot grant authorization"):
                verify_workspace_backup(archive)

    def test_restore_requires_new_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "workspace"
            source.mkdir()
            (source / "engagements.json").write_text("{}", encoding="utf-8")
            archive = root / "backup.nrwb"
            create_workspace_backup(source, archive)
            destination = root / "existing"
            destination.mkdir()

            with self.assertRaisesRegex(ValueError, "must not already exist"):
                restore_workspace_backup(archive, destination)

    def test_symlink_source_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "workspace"
            source.mkdir()
            target = root / "target.txt"
            target.write_text("secret", encoding="utf-8")
            link = source / "link.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this platform")

            with self.assertRaisesRegex(ValueError, "refuses symlink"):
                create_workspace_backup(source, root / "backup.nrwb")


if __name__ == "__main__":
    unittest.main()
