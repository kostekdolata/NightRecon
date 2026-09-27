"""Tests for NightRecon read-only database evidence contract."""

import unittest
from dataclasses import fields

from nightrecon.infrastructure_database import (
    DatabaseConnectionProfile,
    DatabaseEngine,
    DatabaseSchemaObservation,
    DatabaseServerObservation,
    build_database_schema_inventory_facts,
    build_database_server_identity_facts,
    supported_database_actions,
    validate_database_action,
)


class InfrastructureDatabaseTests(unittest.TestCase):
    def test_profile_requires_supported_engine_tls_and_certificate_validation(self):
        profile = DatabaseConnectionProfile(
            engine=DatabaseEngine.POSTGRESQL,
            username="audit-user",
            database_name="postgres",
            port=5432,
        )

        self.assertEqual(
            profile.engine,
            DatabaseEngine.POSTGRESQL,
        )
        self.assertTrue(
            profile.use_tls
        )
        self.assertTrue(
            profile.validate_server_certificate
        )

        with self.assertRaisesRegex(
            ValueError,
            "engine",
        ):
            DatabaseConnectionProfile(
                engine="postgresql",
                username="audit-user",
                database_name="postgres",
                port=5432,
            )

        with self.assertRaisesRegex(
            ValueError,
            "requires TLS",
        ):
            DatabaseConnectionProfile(
                engine=DatabaseEngine.POSTGRESQL,
                username="audit-user",
                database_name="postgres",
                port=5432,
                use_tls=False,
            )

        with self.assertRaisesRegex(
            ValueError,
            "certificate validation",
        ):
            DatabaseConnectionProfile(
                engine=DatabaseEngine.MYSQL,
                username="audit-user",
                database_name="mysql",
                port=3306,
                validate_server_certificate=False,
            )

    def test_profile_bounds_and_text_validation_are_enforced(self):
        cases = (
            {
                "username": "bad\nuser",
            },
            {
                "database_name": "bad\ndb",
            },
            {
                "port": 0,
            },
            {
                "connect_timeout": 0,
            },
            {
                "operation_timeout": 0,
            },
            {
                "max_schemas": 0,
            },
            {
                "max_schemas": 4097,
            },
        )

        for overrides in cases:
            with self.subTest(
                overrides=overrides
            ):
                values = {
                    "engine": DatabaseEngine.POSTGRESQL,
                    "username": "audit-user",
                    "database_name": "postgres",
                    "port": 5432,
                }
                values.update(
                    overrides
                )

                with self.assertRaises(
                    ValueError
                ):
                    DatabaseConnectionProfile(
                        **values
                    )

    def test_contract_has_no_query_or_sql_surface(self):
        profile_fields = {
            item.name
            for item in fields(
                DatabaseConnectionProfile
            )
        }
        server_fields = {
            item.name
            for item in fields(
                DatabaseServerObservation
            )
        }
        schema_fields = {
            item.name
            for item in fields(
                DatabaseSchemaObservation
            )
        }

        for names in (
            profile_fields,
            server_fields,
            schema_fields,
        ):
            self.assertNotIn(
                "query",
                names,
            )
            self.assertNotIn(
                "sql",
                names,
            )
            self.assertNotIn(
                "command",
                names,
            )
            self.assertNotIn(
                "password",
                names,
            )

    def test_only_fixed_read_only_database_actions_are_supported(self):
        self.assertEqual(
            supported_database_actions(),
            (
                "database.server_identity",
                "database.schema_inventory",
            ),
        )

        self.assertEqual(
            validate_database_action(
                "database.server_identity"
            ),
            "database.server_identity",
        )

        with self.assertRaises(
            ValueError
        ):
            validate_database_action(
                "database.execute_query"
            )

    def test_server_identity_normalizes_postgresql_and_mysql_facts(self):
        postgres = (
            build_database_server_identity_facts(
                DatabaseServerObservation(
                    engine=DatabaseEngine.POSTGRESQL,
                    product="PostgreSQL",
                    version="17.6",
                )
            )
        )
        mysql = (
            build_database_server_identity_facts(
                DatabaseServerObservation(
                    engine=DatabaseEngine.MYSQL,
                    product="MySQL",
                    version="8.4.6",
                )
            )
        )

        self.assertEqual(
            tuple(
                (
                    fact.key,
                    fact.value,
                )
                for fact in postgres
            ),
            (
                (
                    "database.engine",
                    "postgresql",
                ),
                (
                    "database.product",
                    "PostgreSQL",
                ),
                (
                    "database.version",
                    "17.6",
                ),
            ),
        )
        self.assertEqual(
            tuple(
                (
                    fact.key,
                    fact.value,
                )
                for fact in mysql
            ),
            (
                (
                    "database.engine",
                    "mysql",
                ),
                (
                    "database.product",
                    "MySQL",
                ),
                (
                    "database.version",
                    "8.4.6",
                ),
            ),
        )

    def test_server_identity_rejects_invalid_engine_and_control_characters(self):
        with self.assertRaises(
            ValueError
        ):
            build_database_server_identity_facts(
                DatabaseServerObservation(
                    engine="postgresql",
                    product="PostgreSQL",
                    version="17.6",
                )
            )

        with self.assertRaises(
            ValueError
        ):
            build_database_server_identity_facts(
                DatabaseServerObservation(
                    engine=DatabaseEngine.POSTGRESQL,
                    product="PostgreSQL\nInjected",
                    version="17.6",
                )
            )

    def test_schema_inventory_is_bounded_and_deterministic(self):
        facts = (
            build_database_schema_inventory_facts(
                (
                    DatabaseSchemaObservation(
                        name="zeta"
                    ),
                    DatabaseSchemaObservation(
                        name="Public"
                    ),
                    DatabaseSchemaObservation(
                        name="alpha"
                    ),
                ),
                max_schemas=10,
            )
        )

        self.assertEqual(
            tuple(
                (
                    fact.key,
                    fact.value,
                )
                for fact in facts
            ),
            (
                (
                    "database.schema_count",
                    "3",
                ),
                (
                    "database.schema_0001.name",
                    "alpha",
                ),
                (
                    "database.schema_0002.name",
                    "Public",
                ),
                (
                    "database.schema_0003.name",
                    "zeta",
                ),
            ),
        )

    def test_schema_inventory_rejects_duplicates_invalid_names_and_overflow(self):
        with self.assertRaisesRegex(
            ValueError,
            "Duplicate",
        ):
            build_database_schema_inventory_facts(
                (
                    DatabaseSchemaObservation(
                        name="public"
                    ),
                    DatabaseSchemaObservation(
                        name="public"
                    ),
                ),
                max_schemas=10,
            )

        with self.assertRaises(
            ValueError
        ):
            build_database_schema_inventory_facts(
                (
                    DatabaseSchemaObservation(
                        name="bad\nname"
                    ),
                ),
                max_schemas=10,
            )

        with self.assertRaisesRegex(
            ValueError,
            "exceed max_schemas",
        ):
            build_database_schema_inventory_facts(
                (
                    DatabaseSchemaObservation(
                        name="one"
                    ),
                    DatabaseSchemaObservation(
                        name="two"
                    ),
                ),
                max_schemas=1,
            )

        with self.assertRaises(
            ValueError
        ):
            build_database_schema_inventory_facts(
                (),
                max_schemas=0,
            )


if __name__ == "__main__":
    unittest.main()
