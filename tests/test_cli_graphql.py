"""CLI tests for NightRecon GraphQL schema intelligence."""

import contextlib
import io
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from nightrecon.api_graphql import (
    GraphQLArgument,
    GraphQLField,
    GraphQLIntrospectionResult,
    GraphQLSchema,
    GraphQLType,
)
from nightrecon.cli import main


def _schema():
    return GraphQLSchema(
        query_type="Query",
        mutation_type="Mutation",
        subscription_type="",
        types=(
            GraphQLType(
                name="Query",
                kind="OBJECT",
                fields=(
                    GraphQLField(
                        name="user",
                        return_type_name="User",
                        return_type_kind="OBJECT",
                        arguments=(
                            GraphQLArgument(
                                name="id",
                                type_name="ID",
                                type_kind="SCALAR",
                                required=True,
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )


class CliGraphQLTests(unittest.TestCase):
    def run_cli(self, *args):
        stdout = io.StringIO()
        stderr = io.StringIO()

        with patch.object(
            sys,
            "argv",
            ["nightrecon", *args],
        ):
            with contextlib.redirect_stdout(stdout):
                with contextlib.redirect_stderr(stderr):
                    try:
                        main()
                        code = 0
                    except SystemExit as exc:
                        code = exc.code

        return code, stdout.getvalue(), stderr.getvalue()

    def test_saved_introspection_is_offline_and_persisted(self):
        with patch(
            "nightrecon.cli.load_graphql_introspection_json",
            return_value=_schema(),
        ) as loader:
            with patch(
                "nightrecon.cli.execute_graphql_introspection"
            ) as execute:
                with patch(
                    "nightrecon.cli.ResultStore"
                ) as store_class:
                    store_class.return_value.save_graphql_schema_report.return_value = (
                        Path("results/session-graphql.json")
                    )

                    with patch(
                        "nightrecon.cli.NightReconLogger"
                    ):
                        code, stdout, stderr = self.run_cli(
                            "api",
                            "graphql-inspect",
                            "introspection.json",
                            "--endpoint-url",
                            "https://example.test/graphql",
                            "--scope",
                            "example.test",
                        )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "GraphQL Schema Summary: source=saved-introspection",
            stdout,
        )
        self.assertIn(
            "GRAPHQL FIELD user returns=User args=id:ID!",
            stdout,
        )
        loader.assert_called_once_with(
            "introspection.json",
            max_bytes=2_097_152,
        )
        execute.assert_not_called()
        (
            store_class.return_value
            .save_graphql_schema_report
            .assert_called_once()
        )

    def test_live_introspection_uses_ephemeral_authorization(self):
        secret = (
            "Bearer graphql-cli-secret"
        )
        result = GraphQLIntrospectionResult(
            success=True,
            reason="completed",
            endpoint_url="https://example.test/graphql",
            status=200,
            byte_count=256,
            schema=_schema(),
        )

        with patch.dict(
            os.environ,
            {
                "NIGHTRECON_GRAPHQL_AUTH": secret,
            },
            clear=False,
        ):
            with patch(
                "nightrecon.cli.execute_graphql_introspection",
                return_value=result,
            ) as execute:
                with patch(
                    "nightrecon.cli.ResultStore"
                ) as store_class:
                    store_class.return_value.save_graphql_schema_report.return_value = (
                        Path("results/session-graphql.json")
                    )

                    with patch(
                        "nightrecon.cli.NightReconLogger"
                    ):
                        code, stdout, stderr = self.run_cli(
                            "api",
                            "graphql-introspect",
                            "--endpoint-url",
                            "https://example.test/graphql",
                            "--scope",
                            "example.test",
                            "--authorization-env",
                            "NIGHTRECON_GRAPHQL_AUTH",
                        )

        self.assertEqual(code, 0)
        self.assertEqual(stderr, "")
        self.assertIn(
            "source=live-introspection",
            stdout,
        )
        self.assertNotIn(
            "graphql-cli-secret",
            stdout,
        )
        self.assertEqual(
            execute.call_args.kwargs["authorization"],
            secret,
        )
        report = (
            store_class.return_value
            .save_graphql_schema_report
            .call_args.args[0]
        )
        self.assertNotIn(
            "graphql-cli-secret",
            repr(report),
        )

    def test_out_of_scope_live_introspection_never_executes(self):
        with patch(
            "nightrecon.cli.execute_graphql_introspection"
        ) as execute:
            with patch(
                "nightrecon.cli.NightReconLogger"
            ):
                code, stdout, stderr = self.run_cli(
                    "api",
                    "graphql-introspect",
                    "--endpoint-url",
                    "https://example.test/graphql",
                    "--scope",
                    "other.test",
                )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "outside the authorized scope",
            stderr,
        )
        execute.assert_not_called()

    def test_endpoint_query_and_credentials_fail_before_execution(self):
        with patch(
            "nightrecon.cli.execute_graphql_introspection"
        ) as execute:
            code, stdout, stderr = self.run_cli(
                "api",
                "graphql-introspect",
                "--endpoint-url",
                "https://example.test/graphql?token=secret",
                "--scope",
                "example.test",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertIn(
                "must not contain credentials, query data, or a fragment",
                stderr,
            )
            self.assertNotIn(
                "token=secret",
                stderr,
            )

            code, stdout, stderr = self.run_cli(
                "api",
                "graphql-introspect",
                "--endpoint-url",
                "https://user:secret@example.test/graphql",
                "--scope",
                "example.test",
            )

            self.assertEqual(code, 2)
            self.assertEqual(stdout, "")
            self.assertNotIn(
                "user:secret",
                stderr,
            )

        execute.assert_not_called()

    def test_live_introspection_failure_reports_generic_reason(self):
        result = GraphQLIntrospectionResult(
            success=False,
            reason="invalid_introspection_response",
            endpoint_url="https://example.test/graphql",
            status=200,
            byte_count=64,
            schema=None,
        )

        with patch(
            "nightrecon.cli.execute_graphql_introspection",
            return_value=result,
        ):
            with patch(
                "nightrecon.cli.NightReconLogger"
            ):
                code, stdout, stderr = self.run_cli(
                    "api",
                    "graphql-introspect",
                    "--endpoint-url",
                    "https://example.test/graphql",
                    "--scope",
                    "example.test",
                )

        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn(
            "invalid_introspection_response",
            stderr,
        )


if __name__ == "__main__":
    unittest.main()
