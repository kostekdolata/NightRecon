"""CLI tests for signed declarative assessment check packs."""

import base64
import contextlib
import io
import sys
import unittest
from unittest.mock import patch

from nightrecon.check_catalog import CheckCatalogResult
from nightrecon.check_packs import load_check_pack_json
from nightrecon.cli import main


class CliCheckPackTests(unittest.TestCase):
    def setUp(self):
        self.key_bytes = b"k" * 32
        self.key_spec = (
            "test-key="
            + base64.b64encode(
                self.key_bytes
            ).decode("ascii")
        )
        self.pack = load_check_pack_json(
            """{
                "schema_version": 1,
                "pack_id": "nightrecon.test.cli",
                "name": "CLI Test Pack",
                "version": "1.0.0",
                "checks": [
                    {
                        "check_id": "pack.cli.test",
                        "name": "CLI Pack Check",
                        "family": "test",
                        "description": "CLI pack integration.",
                        "intrusiveness": "passive",
                        "conditions": [],
                        "finding": {
                            "title": "Matched",
                            "summary": "Matched."
                        }
                    }
                ]
            }"""
        )

    def test_checks_list_includes_signed_pack_checks(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        def catalog_loader(*, additional_checks=()):
            return CheckCatalogResult(
                checks=additional_checks,
            )

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "checks",
                "list",
                "--check-pack",
                "pack.json",
                "--check-pack-key",
                self.key_spec,
            ],
        ):
            with patch(
                "nightrecon.cli.load_signed_check_pack_file",
                return_value=self.pack,
            ) as pack_loader:
                with patch(
                    "nightrecon.cli.load_check_catalog",
                    side_effect=catalog_loader,
                ):
                    with contextlib.redirect_stdout(stdout):
                        with contextlib.redirect_stderr(stderr):
                            main()

        self.assertEqual(stderr.getvalue(), "")
        self.assertIn(
            "pack.cli.test",
            stdout.getvalue(),
        )
        pack_loader.assert_called_once_with(
            "pack.json",
            trusted_keys={
                "test-key": self.key_bytes,
            },
        )

    def test_checks_list_includes_active_installed_pack_checks(self):
        stdout = io.StringIO()
        stderr = io.StringIO()

        def catalog_loader(*, additional_checks=()):
            return CheckCatalogResult(
                checks=additional_checks,
            )

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "checks",
                "list",
                "--installed-check-packs",
                "--check-pack-key",
                self.key_spec,
                "--check-store-dir",
                "pack-store",
            ],
        ):
            with patch(
                "nightrecon.cli.CheckPackStore"
            ) as store_class:
                store = store_class.return_value
                store.list_pack_ids.return_value = (
                    "nightrecon.test.cli",
                )
                store.load_active.return_value = self.pack

                with patch(
                    "nightrecon.cli.load_check_catalog",
                    side_effect=catalog_loader,
                ):
                    with contextlib.redirect_stdout(stdout):
                        with contextlib.redirect_stderr(stderr):
                            main()

        self.assertEqual(stderr.getvalue(), "")
        self.assertIn(
            "pack.cli.test",
            stdout.getvalue(),
        )
        store_class.assert_called_once_with(
            "pack-store"
        )
        store.load_active.assert_called_once_with(
            "nightrecon.test.cli",
            trusted_keys={
                "test-key": self.key_bytes,
            },
        )

    def test_installed_scan_packs_require_assessment(self):
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "scan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--installed-check-packs",
                "--check-pack-key",
                self.key_spec,
            ],
        ):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exc:
                    main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "--installed-check-packs requires --assessment",
            stderr.getvalue(),
        )

    def test_scan_check_pack_requires_assessment(self):
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "scan",
                "127.0.0.1",
                "--scope",
                "127.0.0.1",
                "--check-pack",
                "pack.json",
            ],
        ):
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as exc:
                    main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "--check-pack/--check-pack-key require --assessment",
            stderr.getvalue(),
        )

    def test_invalid_signed_pack_fails_closed(self):
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            [
                "nightrecon",
                "checks",
                "list",
                "--check-pack",
                "pack.json",
                "--check-pack-key",
                self.key_spec,
            ],
        ):
            with patch(
                "nightrecon.cli.load_signed_check_pack_file",
                side_effect=ValueError(
                    "Invalid check-pack signature."
                ),
            ):
                with contextlib.redirect_stderr(stderr):
                    with self.assertRaises(SystemExit) as exc:
                        main()

        self.assertEqual(exc.exception.code, 2)
        self.assertIn(
            "Invalid check-pack signature.",
            stderr.getvalue(),
        )


if __name__ == "__main__":
    unittest.main()
