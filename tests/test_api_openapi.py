"""Tests for NightRecon passive OpenAPI/Swagger normalization."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from nightrecon.api_openapi import (
    load_api_description_json,
    normalize_api_description,
)


class ApiOpenApiTests(unittest.TestCase):
    def test_openapi3_normalization_is_non_secret_and_deterministic(self):
        document = {
            "openapi": "3.1.0",
            "info": {
                "title": "Example API",
                "version": "2026-09",
            },
            "servers": [
                {
                    "url": (
                        "https://user:secret@example.test"
                        "/api?token=hidden#fragment"
                    )
                }
            ],
            "security": [
                {
                    "bearerAuth": [],
                }
            ],
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                    }
                },
                "schemas": {
                    "External": {
                        "$ref": (
                            "https://schemas.example.test"
                            "/external.json"
                        )
                    }
                },
            },
            "paths": {
                "/users/{user_id}": {
                    "parameters": [
                        {
                            "name": "user_id",
                            "in": "path",
                            "required": True,
                            "schema": {
                                "type": "string",
                            },
                        }
                    ],
                    "get": {
                        "operationId": "getUser",
                        "summary": "Get one user",
                        "parameters": [
                            {
                                "name": "verbose",
                                "in": "query",
                                "required": False,
                                "schema": {
                                    "type": "boolean",
                                },
                            }
                        ],
                        "responses": {
                            "200": {},
                            "404": {},
                        },
                    },
                    "post": {
                        "operationId": "updateUser",
                        "requestBody": {
                            "content": {
                                "application/json": {},
                            }
                        },
                        "responses": {
                            "200": {},
                        },
                    },
                }
            },
        }

        inventory = normalize_api_description(
            document
        )

        self.assertEqual(
            inventory.specification,
            "openapi",
        )
        self.assertEqual(
            inventory.specification_version,
            "3.1.0",
        )
        self.assertEqual(
            inventory.title,
            "Example API",
        )
        self.assertEqual(
            inventory.api_version,
            "2026-09",
        )
        self.assertEqual(
            inventory.servers[0].url,
            "https://example.test/api",
        )
        self.assertEqual(
            inventory.security_scheme_names,
            ("bearerAuth",),
        )
        self.assertEqual(
            inventory.external_references_observed,
            (
                "https://schemas.example.test/external.json",
            ),
        )
        self.assertEqual(
            inventory.operation_count,
            2,
        )

        get_operation = inventory.operations[0]
        self.assertEqual(
            get_operation.method,
            "GET",
        )
        self.assertEqual(
            get_operation.path,
            "/users/{user_id}",
        )
        self.assertEqual(
            get_operation.operation_id,
            "getUser",
        )
        self.assertEqual(
            tuple(
                (
                    item.location,
                    item.name,
                    item.schema_type,
                )
                for item in get_operation.parameters
            ),
            (
                (
                    "path",
                    "user_id",
                    "string",
                ),
                (
                    "query",
                    "verbose",
                    "boolean",
                ),
            ),
        )
        self.assertEqual(
            get_operation.response_statuses,
            ("200", "404"),
        )
        self.assertEqual(
            get_operation.security_schemes,
            ("bearerAuth",),
        )

        post_operation = inventory.operations[1]
        self.assertEqual(
            post_operation.method,
            "POST",
        )
        self.assertEqual(
            post_operation.request_content_types,
            ("application/json",),
        )

        serialized = repr(
            inventory
        )
        self.assertNotIn(
            "user:secret",
            serialized,
        )
        self.assertNotIn(
            "token=hidden",
            serialized,
        )

    def test_operation_parameter_overrides_path_parameter(self):
        document = {
            "openapi": "3.0.3",
            "info": {},
            "paths": {
                "/items": {
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "schema": {
                                "type": "integer",
                                "format": "int32",
                            },
                        }
                    ],
                    "get": {
                        "parameters": [
                            {
                                "name": "limit",
                                "in": "query",
                                "required": True,
                                "schema": {
                                    "type": "integer",
                                    "format": "int64",
                                },
                            }
                        ],
                        "responses": {},
                    },
                }
            },
        }

        inventory = normalize_api_description(
            document
        )
        parameter = (
            inventory.operations[0]
            .parameters[0]
        )

        self.assertTrue(
            parameter.required
        )
        self.assertEqual(
            parameter.schema_format,
            "int64",
        )

    def test_swagger2_normalization_builds_declared_servers(self):
        document = {
            "swagger": "2.0",
            "info": {
                "title": "Legacy",
                "version": "2",
            },
            "schemes": [
                "https",
                "http",
            ],
            "host": "api.example.test:8443",
            "basePath": "/v1",
            "securityDefinitions": {
                "apiKey": {
                    "type": "apiKey",
                    "name": "X-Key",
                    "in": "header",
                }
            },
            "paths": {
                "/status": {
                    "get": {
                        "operationId": "status",
                        "produces": [
                            "application/json",
                        ],
                        "responses": {
                            "200": {},
                        },
                    },
                    "put": {
                        "operationId": "mutate",
                        "consumes": [
                            "application/json",
                        ],
                        "responses": {
                            "204": {},
                        },
                    },
                }
            },
        }

        inventory = normalize_api_description(
            document
        )

        self.assertEqual(
            inventory.specification,
            "swagger",
        )
        self.assertEqual(
            tuple(
                server.url
                for server in inventory.servers
            ),
            (
                "https://api.example.test:8443/v1",
                "http://api.example.test:8443/v1",
            ),
        )
        self.assertEqual(
            inventory.security_scheme_names,
            ("apiKey",),
        )
        self.assertEqual(
            tuple(
                operation.method
                for operation in inventory.operations
            ),
            (
                "GET",
                "PUT",
            ),
        )
        self.assertEqual(
            inventory.operations[1].request_content_types,
            ("application/json",),
        )

    def test_unsupported_specification_fails_closed(self):
        with self.assertRaises(ValueError):
            normalize_api_description(
                {
                    "openapi": "2.5.0",
                    "paths": {},
                }
            )

        with self.assertRaises(ValueError):
            normalize_api_description(
                {
                    "paths": {},
                }
            )

    def test_invalid_paths_shape_fails_closed(self):
        with self.assertRaises(ValueError):
            normalize_api_description(
                {
                    "openapi": "3.1.0",
                    "paths": [],
                }
            )

    def test_local_json_loader_is_bounded_and_never_fetches_refs(self):
        document = {
            "openapi": "3.1.0",
            "info": {
                "title": "Local",
                "version": "1",
            },
            "paths": {},
            "components": {
                "schemas": {
                    "Remote": {
                        "$ref": (
                            "https://outside.test/schema.json"
                        )
                    }
                }
            },
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(
                temp_dir
            ) / "openapi.json"
            path.write_text(
                json.dumps(document),
                encoding="utf-8",
            )

            inventory = load_api_description_json(
                path,
                max_bytes=4096,
            )

            self.assertEqual(
                inventory.title,
                "Local",
            )
            self.assertEqual(
                inventory.external_references_observed,
                (
                    "https://outside.test/schema.json",
                ),
            )

            with self.assertRaises(ValueError):
                load_api_description_json(
                    path,
                    max_bytes=8,
                )

    def test_invalid_local_json_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(
                temp_dir
            ) / "openapi.json"
            path.write_text(
                "{bad json",
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                load_api_description_json(
                    path
                )


if __name__ == "__main__":
    unittest.main()
