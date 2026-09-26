"""Tests for NightRecon GraphQL schema reporting and storage."""

import json
import tempfile
import unittest

from nightrecon.api_graphql import (
    GraphQLArgument,
    GraphQLField,
    GraphQLSchema,
    GraphQLType,
)
from nightrecon.graphql_report import GraphQLSchemaReport
from nightrecon.session import ScanSession
from nightrecon.storage import ResultStore
from nightrecon.targets import parse_target


class GraphQLReportStorageTests(unittest.TestCase):
    def test_report_contains_schema_metadata_only_and_saves_separately(self):
        session = ScanSession.create(
            target=parse_target("example.test"),
            scope_rules=("example.test",),
        )
        schema = GraphQLSchema(
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
        report = GraphQLSchemaReport.create(
            session=session,
            endpoint_url="https://example.test/graphql",
            source="saved-introspection",
            schema=schema,
        )
        data = report.to_dict()

        self.assertEqual(
            data["summary"]["types"],
            1,
        )
        self.assertEqual(
            data["summary"]["fields"],
            1,
        )
        self.assertEqual(
            data["summary"]["query_type"],
            "Query",
        )
        self.assertEqual(
            data["summary"]["mutation_type"],
            "Mutation",
        )
        self.assertNotIn(
            "Authorization",
            repr(data),
        )
        self.assertNotIn(
            "secret",
            repr(data),
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            path = ResultStore(
                temp_dir
            ).save_graphql_schema_report(
                report
            )

            self.assertEqual(
                path.name,
                f"{session.session_id}-graphql.json",
            )

            with path.open(
                "r",
                encoding="utf-8",
            ) as file:
                persisted = json.load(
                    file
                )

        self.assertEqual(
            persisted["endpoint_url"],
            "https://example.test/graphql",
        )
        self.assertEqual(
            persisted["types"][0]["fields"][0]["arguments"][0]["name"],
            "id",
        )


if __name__ == "__main__":
    unittest.main()
