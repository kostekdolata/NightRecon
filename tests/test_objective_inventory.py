"""Read-only collectors tested against disposable local Git repositories."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.task_automation.controller import Rejected
from tools.task_automation.inventory import read_base, read_working


@unittest.skipUnless(os.name == "posix", "descriptor-safe inventory collection runs on the POSIX controller host")
class ObjectiveInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.git("init", "-q")
        (self.root / "tracked.txt").write_bytes(b"original")
        self.git("add", "tracked.txt")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                 "-c", "commit.gpgSign=false", "-c", "core.hooksPath=" + os.devnull,
                 "commit", "-qm", "disposable baseline fixture")
        self.sha = self.git("rev-parse", "HEAD").decode().strip()
        self.base = read_base(self.root, self.sha)

    def git(self, *args):
        result = subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_pinned_base_is_collected_without_index_or_worktree_changes(self):
        self.assertEqual(self.base["tracked.txt"].content, b"original")
        self.assertEqual(self.base["tracked.txt"].mode, "100644")
        self.assertEqual(self.git("status", "--porcelain"), b"")

    def test_working_inventory_includes_modifications_and_untracked_additions(self):
        (self.root / "tracked.txt").write_bytes(b"changed")
        (self.root / "new.txt").write_bytes(b"new")
        inventory = read_working(self.root, self.base)
        self.assertEqual(inventory["tracked.txt"].content, b"changed")
        self.assertEqual(inventory["new.txt"].content, b"new")

    def test_deletion_is_not_replaced_by_baseline_bytes(self):
        (self.root / "tracked.txt").unlink()
        self.assertNotIn("tracked.txt", read_working(self.root, self.base))

    def test_candidate_gitignore_cannot_hide_untracked_out_of_scope_file(self):
        (self.root / ".gitignore").write_text("hidden.txt\n")
        (self.root / "hidden.txt").write_bytes(b"not hidden from controller")
        self.assertIn("hidden.txt", read_working(self.root, self.base))

    def test_transient_runtime_root_is_excluded_only_for_untracked_content(self):
        (self.root / "work").mkdir()
        (self.root / "work/untracked").write_bytes(b"scratch")
        (self.root / "work/tracked").write_bytes(b"tracked")
        self.git("add", "-f", "work/tracked")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                 "-c", "commit.gpgSign=false", "commit", "-qm", "tracked transient fixture")
        base = read_base(self.root, self.git("rev-parse", "HEAD").decode().strip())
        inventory = read_working(self.root, base)
        self.assertIn("work/tracked", inventory)
        self.assertNotIn("work/untracked", inventory)

    def test_symlink_contents_are_recorded_without_reading_target(self):
        outside = Path(self.temp.name) / "secret"
        outside.write_bytes(b"must not be read")
        (self.root / "link").symlink_to(outside)
        entry = read_working(self.root, self.base)["link"]
        self.assertEqual(entry.mode, "120000")
        self.assertEqual(entry.content, os.fsencode(str(outside)))
        self.assertNotIn(b"must not be read", entry.content)

    def test_symlink_parent_is_not_followed_for_tracked_paths(self):
        outside = Path(self.temp.name) / "outside"
        outside.mkdir()
        (outside / "file").write_bytes(b"secret")
        (self.root / "parent").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(Rejected):
            read_working(self.root, {"parent/file": self.base["tracked.txt"]})

    def test_hardlink_to_external_content_fails_closed(self):
        outside = Path(self.temp.name) / "outside"
        outside.write_bytes(b"external")
        os.link(outside, self.root / "hardlink")
        with self.assertRaises(Rejected):
            read_working(self.root, self.base)

    def test_special_file_does_not_block_collector(self):
        os.mkfifo(self.root / "pipe")
        with self.assertRaises(Rejected):
            read_working(self.root, self.base)

    def test_executable_mode_is_preserved_for_scope_rejection(self):
        (self.root / "tracked.txt").chmod(0o755)
        self.assertEqual(read_working(self.root, self.base)["tracked.txt"].mode, "100755")

    def test_oversized_file_fails_without_partial_inventory(self):
        (self.root / "large").write_bytes(b"x" * 1048577)
        with self.assertRaises(Rejected):
            read_working(self.root, self.base)

    def test_untrusted_revision_syntax_is_not_passed_to_git(self):
        for revision in ("HEAD", "--help", "master;touch file", "f" * 39):
            with self.subTest(revision=revision), self.assertRaises(Rejected):
                read_base(self.root, revision)

    def test_symlink_repository_is_rejected(self):
        alias = Path(self.temp.name) / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(Rejected):
            read_base(alias, self.sha)

    def test_local_fsmonitor_helper_is_not_executed(self):
        marker = Path(self.temp.name) / "fsmonitor-executed"
        helper = Path(self.temp.name) / "helper.sh"
        helper.write_text("#!/bin/sh\ntouch '" + str(marker) + "'\n")
        helper.chmod(0o755)
        self.git("config", "core.fsmonitor", str(helper))
        read_base(self.root, self.sha)
        read_working(self.root, self.base)
        self.assertFalse(marker.exists())


class CollectorPlatformBoundaryTests(unittest.TestCase):
    def test_nonposix_collection_fails_closed(self):
        path = Path("unused")
        with patch("tools.task_automation.inventory.os.name", "nt"):
            with self.assertRaises(Rejected):
                read_base(path, "f" * 40)


if __name__ == "__main__":
    unittest.main()
