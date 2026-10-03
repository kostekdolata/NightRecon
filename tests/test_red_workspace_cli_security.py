"""Security tests for Red workspace passphrase-file handling."""

import os
from pathlib import Path
import tempfile
import unittest

from nightrecon_red_engine.red_workspace_cli import _read_passphrase_file


class WorkspacePassphraseFileTests(unittest.TestCase):
    def test_reads_one_line_without_persisting_value_elsewhere(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "passphrase.txt"
            path.write_bytes(b"correct horse battery staple\n")
            if os.name != "nt":
                path.chmod(0o600)

            self.assertEqual(
                _read_passphrase_file(str(path)),
                b"correct horse battery staple",
            )

    def test_rejects_multiline_passphrase_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "passphrase.txt"
            path.write_bytes(b"first line\nsecond line\n")
            if os.name != "nt":
                path.chmod(0o600)

            with self.assertRaisesRegex(ValueError, "exactly one line"):
                _read_passphrase_file(str(path))

    def test_rejects_group_or_other_access_on_posix(self):
        if os.name == "nt":
            self.skipTest("POSIX permission bits are not authoritative on Windows")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "passphrase.txt"
            path.write_bytes(b"correct horse battery staple\n")
            path.chmod(0o644)

            with self.assertRaisesRegex(ValueError, "group or other"):
                _read_passphrase_file(str(path))

    def test_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.txt"
            target.write_bytes(b"correct horse battery staple\n")
            if os.name != "nt":
                target.chmod(0o600)
            link = root / "passphrase.txt"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks unavailable on this platform")

            with self.assertRaisesRegex(ValueError, "non-symlink"):
                _read_passphrase_file(str(link))


if __name__ == "__main__":
    unittest.main()
