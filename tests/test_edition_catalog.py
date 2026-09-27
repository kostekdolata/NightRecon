"""Edition boundaries are explicit without claiming separate executables exist."""

import contextlib
import io
import json
import sys
import unittest
from unittest.mock import patch

from nightrecon.cli import main
from nightrecon.edition_catalog import EDITIONS


class EditionCatalogTests(unittest.TestCase):
    def test_five_unique_editions_in_expected_order(self):
        self.assertEqual(
            tuple(edition.slug for edition in EDITIONS),
            ("white", "blue", "red", "purple", "black"),
        )
        self.assertEqual(len({edition.slug for edition in EDITIONS}), 5)

    def test_no_unshipped_standalone_edition_claim(self):
        self.assertTrue(all(not edition.standalone_available for edition in EDITIONS))

    def test_json_cli_catalog_is_machine_readable(self):
        output = io.StringIO()
        with patch.object(sys, "argv", ["nightrecon", "editions", "--json"]):
            with contextlib.redirect_stdout(output):
                main()

        records = json.loads(output.getvalue())
        self.assertEqual([record["slug"] for record in records], [
            "white", "blue", "red", "purple", "black",
        ])
        self.assertTrue(all(not record["standalone_available"] for record in records))


if __name__ == "__main__":
    unittest.main()
