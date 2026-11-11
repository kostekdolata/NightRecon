"""Offline contracts for explicit Qt read-only engagement loading."""
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "packages" / "red-night"))
from red_night_app.operations_read_model import OperationsSnapshot
from red_night_app.qt_explicit_snapshot import load_explicit_snapshot


class QtExplicitSnapshotTests(TestCase):
    def test_default_remains_disconnected(self):
        self.assertIsNone(load_explicit_snapshot([]))

    def test_partial_arguments_fail_closed(self):
        with self.assertRaises(SystemExit) as raised:
            load_explicit_snapshot(["--engagement-id", "test"])
        self.assertEqual(raised.exception.code, 2)

    def test_unknown_options_fail_closed(self):
        with self.assertRaises(SystemExit):
            load_explicit_snapshot(["--run-scan"])

    def test_missing_files_never_call_reader_or_create_files(self):
        with TemporaryDirectory() as temp:
            missing = str(Path(temp) / "missing.db")
            with patch("red_night_app.qt_explicit_snapshot.read_operations_snapshot") as reader:
                with self.assertRaises(SystemExit):
                    load_explicit_snapshot([
                        "--engagement-id", "eng",
                        "--authority-db", missing,
                        "--audit-path", missing,
                        "--review-db", missing,
                    ])
                reader.assert_not_called()
                self.assertFalse(Path(missing).exists())

    def test_explicit_paths_forward_to_existing_read_only_model(self):
        with TemporaryDirectory() as temp:
            files = [Path(temp) / name for name in ("authority.db", "audit.jsonl", "review.db")]
            for path in files:
                path.touch()
            expected = OperationsSnapshot("eng", "UNAVAILABLE", None, (), (), ())
            with patch("red_night_app.qt_explicit_snapshot.read_operations_snapshot", return_value=expected) as reader:
                actual = load_explicit_snapshot([
                    "--engagement-id", "eng",
                    "--authority-db", str(files[0]),
                    "--audit-path", str(files[1]),
                    "--review-db", str(files[2]),
                ])
            self.assertIs(actual, expected)
            reader.assert_called_once_with(
                engagement_id="eng", authority_db=files[0],
                audit_path=files[1], review_db=files[2],
            )

    def test_overlong_identifier_rejected(self):
        with self.assertRaises(SystemExit):
            load_explicit_snapshot([
                "--engagement-id", "x" * 129,
                "--authority-db", "a", "--audit-path", "b", "--review-db", "c",
            ])

    def test_entrypoint_does_not_import_operational_launcher(self):
        source = (Path(__file__).resolve().parents[1] /
                  "installer/windows/qt_preview_entrypoint.py").read_text(encoding="utf-8")
        self.assertIn("load_explicit_snapshot(sys.argv[1:])", source)
        self.assertIn("build_window(operations_snapshot=snapshot)", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("windows_launcher", source)
