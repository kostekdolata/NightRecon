"""Red Night's directory import should expose safe summary defaults."""

import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nightrecon.edition_gateway import EditionRouteError, run_edition_cli
from nightrecon.red_night import main as red_main


USER_DN = "CN=Alice,DC=example,DC=test"
GROUP_DN = "CN=Operators,DC=example,DC=test"


class RedDirectoryCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "directory.json"
        self.path.write_text(json.dumps({
            "schema_version": 1,
            "entries": [
                {"dn": USER_DN, "kind": "user", "name": "Alice"},
                {"dn": GROUP_DN, "kind": "group", "name": "Operators",
                 "members": [USER_DN, "CN=Unknown,DC=example,DC=test"]},
            ],
        }), encoding="utf-8")

    def command(self, *flags):
        result = io.StringIO()
        with contextlib.redirect_stdout(result):
            red_main(("identity", "import", str(self.path), "--source-id", "lab-1", *flags))
        return json.loads(result.getvalue())

    def test_default_returns_non_identifying_summary_and_missing_reference_count(self):
        output = self.command()
        self.assertEqual(output["identities"], 1)
        self.assertEqual(output["groups"], 1)
        self.assertEqual(output["observed_memberships"], 1)
        self.assertEqual(output["unresolved_members"], 1)
        self.assertEqual(len(output["graph_sha256"]), 64)
        self.assertNotIn("graph", output)
        self.assertNotIn("Alice", json.dumps(output))
        self.assertNotIn(USER_DN, json.dumps(output))

    def test_explicit_graph_includes_observed_evidence_and_same_fingerprint(self):
        summary = self.command()
        detailed = self.command("--include-graph")
        self.assertEqual(summary["graph_sha256"], detailed["graph_sha256"])
        self.assertEqual(detailed["graph"]["summary"]["observed_edges"], 1)
        self.assertEqual(detailed["graph"]["summary"]["inferred_edges"], 0)
        self.assertIn("Alice", json.dumps(detailed["graph"]))
        self.assertNotIn("CN=Unknown", json.dumps(detailed["graph"]))

    def test_bad_or_oversized_file_fails_without_emitting_graph(self):
        for payload in (b'{"schema_version":1,"entries":[],"password":"secret"}',
                        b"x" * 1_000_001):
            with self.subTest(size=len(payload)):
                self.path.write_bytes(payload)
                output, error = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                    with self.assertRaises(SystemExit) as exit_status:
                        red_main(("identity", "import", str(self.path),
                                  "--source-id", "lab-1", "--include-graph"))
                self.assertEqual(exit_status.exception.code, 2)
                self.assertEqual(output.getvalue(), "")
                self.assertNotIn("secret", error.getvalue())

    def test_only_red_can_dispatch_identity_import(self):
        with patch("nightrecon.edition_gateway.legacy_main") as legacy:
            for edition in ("white", "blue", "purple", "black"):
                with self.subTest(edition=edition):
                    with self.assertRaises(EditionRouteError):
                        run_edition_cli(edition, ("identity", "import", str(self.path)))
            legacy.assert_not_called()


if __name__ == "__main__":
    unittest.main()
