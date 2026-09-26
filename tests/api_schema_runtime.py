"""Runtime integration tests for optional NightRecon YAML API support."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from nightrecon.api_openapi import load_api_description


class ApiSchemaRuntimeTests(unittest.TestCase):
    def test_yaml_openapi_loads_with_redacted_external_reference(self):
        document = """
openapi: 3.1.0
info:
  title: YAML API
  version: "1"
servers:
  - url: https://user:secret@example.test/api?token=hidden
components:
  schemas:
    External:
      $ref: https://user:secret@schemas.example.test/model.yaml?token=hidden#Thing
paths:
  /status:
    get:
      operationId: status
      responses:
        "200": {}
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "openapi.yaml"
            path.write_text(
                document,
                encoding="utf-8",
            )

            inventory = load_api_description(
                path,
                max_bytes=4096,
            )

        self.assertEqual(
            inventory.title,
            "YAML API",
        )
        self.assertEqual(
            inventory.servers[0].url,
            "https://example.test/api",
        )
        self.assertEqual(
            inventory.external_references_observed,
            (
                "https://schemas.example.test/model.yaml",
            ),
        )
        self.assertEqual(
            inventory.operations[0].method,
            "GET",
        )

        serialized = repr(inventory)
        self.assertNotIn(
            "user:secret",
            serialized,
        )
        self.assertNotIn(
            "token=hidden",
            serialized,
        )


if __name__ == "__main__":
    unittest.main()
