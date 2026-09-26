"""Tests for bounded NightRecon GraphQL schema intelligence."""

import json
import tempfile
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from nightrecon.api_graphql import (
    execute_graphql_introspection,
    load_graphql_introspection_json,
    parse_graphql_introspection,
)


def _document():
    return {
        "data": {
            "__schema": {
                "queryType": {
                    "name": "Query",
                },
                "mutationType": {
                    "name": "Mutation",
                },
                "subscriptionType": None,
                "types": [
                    {
                        "kind": "OBJECT",
                        "name": "Query",
                        "fields": [
                            {
                                "name": "user",
                                "args": [
                                    {
                                        "name": "id",
                                        "type": {
                                            "kind": "NON_NULL",
                                            "name": None,
                                            "ofType": {
                                                "kind": "SCALAR",
                                                "name": "ID",
                                            },
                                        },
                                    }
                                ],
                                "type": {
                                    "kind": "OBJECT",
                                    "name": "User",
                                },
                            }
                        ],
                    },
                    {
                        "kind": "OBJECT",
                        "name": "Mutation",
                        "fields": [
                            {
                                "name": "updateUser",
                                "args": [],
                                "type": {
                                    "kind": "OBJECT",
                                    "name": "User",
                                },
                            }
                        ],
                    },
                ],
            }
        }
    }


class _FakeResponse:
    def __init__(
        self,
        body,
        *,
        status=200,
    ):
        self.status = status
        self._body = body
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"

    def __enter__(self):
        return self

    def __exit__(
        self,
        exc_type,
        exc,
        tb,
    ):
        return False

    def read(
        self,
        limit,
    ):
        return self._body[:limit]


class _FakeOpener:
    def __init__(
        self,
        response,
    ):
        self.response = response
        self.requests = []

    def open(
        self,
        request,
        timeout,
    ):
        self.requests.append(
            (
                request,
                timeout,
            )
        )
        return self.response


class GraphQLIntelligenceTests(unittest.TestCase):
    def test_parser_normalizes_schema_without_values(self):
        schema = parse_graphql_introspection(
            _document()
        )

        self.assertEqual(
            schema.query_type,
            "Query",
        )
        self.assertEqual(
            schema.mutation_type,
            "Mutation",
        )
        self.assertEqual(
            schema.subscription_type,
            "",
        )
        self.assertEqual(
            schema.field_count,
            2,
        )

        query_type = next(
            item
            for item in schema.types
            if item.name == "Query"
        )
        field = query_type.fields[0]
        argument = field.arguments[0]

        self.assertEqual(
            field.name,
            "user",
        )
        self.assertEqual(
            field.return_type_name,
            "User",
        )
        self.assertEqual(
            argument.name,
            "id",
        )
        self.assertEqual(
            argument.type_name,
            "ID",
        )
        self.assertTrue(
            argument.required
        )
        self.assertNotIn(
            "defaultValue",
            repr(schema),
        )

    def test_saved_introspection_loader_is_bounded(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(
                temp_dir
            ) / "introspection.json"
            path.write_text(
                json.dumps(
                    _document()
                ),
                encoding="utf-8",
            )

            schema = load_graphql_introspection_json(
                path,
                max_bytes=8192,
            )

            self.assertEqual(
                schema.query_type,
                "Query",
            )

            with self.assertRaises(
                ValueError
            ):
                load_graphql_introspection_json(
                    path,
                    max_bytes=8,
                )

    def test_active_executor_sends_only_fixed_introspection_operation(self):
        payload = json.dumps(
            _document()
        ).encode(
            "utf-8"
        )
        opener = _FakeOpener(
            _FakeResponse(
                payload
            )
        )
        secret = (
            "Bearer graphql-secret"
        )

        with patch(
            "nightrecon.api_graphql.build_opener",
            return_value=opener,
        ):
            result = execute_graphql_introspection(
                endpoint_url="https://example.test/graphql",
                origin="https://example.test",
                authorized=True,
                timeout=2.0,
                max_response_bytes=8192,
                authorization=secret,
            )

        self.assertTrue(
            result.success
        )
        self.assertEqual(
            result.reason,
            "completed",
        )
        self.assertIsNotNone(
            result.schema
        )
        request, timeout = (
            opener.requests[0]
        )
        self.assertEqual(
            timeout,
            2.0,
        )
        self.assertEqual(
            request.get_method(),
            "POST",
        )
        self.assertEqual(
            request.headers["Authorization"],
            secret,
        )
        request_json = json.loads(
            request.data.decode(
                "utf-8"
            )
        )
        self.assertEqual(
            request_json[
                "operationName"
            ],
            "NightReconIntrospection",
        )
        self.assertIn(
            "__schema",
            request_json["query"],
        )
        self.assertNotIn(
            "graphql-secret",
            repr(result),
        )

    def test_endpoint_credentials_query_and_cross_origin_fail_before_network(self):
        with patch(
            "nightrecon.api_graphql.build_opener"
        ) as build:
            with self.assertRaises(
                ValueError
            ):
                execute_graphql_introspection(
                    endpoint_url=(
                        "https://user:secret@example.test/graphql"
                    ),
                    origin="https://example.test",
                    authorized=True,
                )

            with self.assertRaises(
                ValueError
            ):
                execute_graphql_introspection(
                    endpoint_url=(
                        "https://example.test/graphql?token=secret"
                    ),
                    origin="https://example.test",
                    authorized=True,
                )

            with self.assertRaises(
                PermissionError
            ):
                execute_graphql_introspection(
                    endpoint_url="https://outside.test/graphql",
                    origin="https://example.test",
                    authorized=True,
                )

        build.assert_not_called()

    def test_invalid_introspection_response_fails_without_raw_error_retention(self):
        opener = _FakeOpener(
            _FakeResponse(
                b'{"errors":[{"message":"sensitive backend detail"}]}'
            )
        )

        with patch(
            "nightrecon.api_graphql.build_opener",
            return_value=opener,
        ):
            result = execute_graphql_introspection(
                endpoint_url="https://example.test/graphql",
                origin="https://example.test",
                authorized=True,
            )

        self.assertFalse(
            result.success
        )
        self.assertEqual(
            result.reason,
            "invalid_introspection_response",
        )
        self.assertIsNone(
            result.schema
        )
        self.assertNotIn(
            "sensitive backend detail",
            repr(result),
        )


if __name__ == "__main__":
    unittest.main()
