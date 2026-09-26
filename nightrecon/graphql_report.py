"""Structured non-secret GraphQL schema reporting."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from nightrecon.api_graphql import (
    GraphQLSchema,
)
from nightrecon.session import ScanSession


@dataclass(frozen=True)
class GraphQLSchemaReport:
    session_id: str
    created_at: str
    target: str
    target_type: str
    scope: tuple[str, ...]
    status: str
    endpoint_url: str
    source: str
    query_type: str
    mutation_type: str
    subscription_type: str
    types: tuple[dict, ...]

    @classmethod
    def create(
        cls,
        *,
        session: ScanSession,
        endpoint_url: str,
        source: str,
        schema: GraphQLSchema,
    ) -> "GraphQLSchemaReport":
        types = tuple(
            {
                "name": gql_type.name,
                "kind": gql_type.kind,
                "fields": tuple(
                    {
                        "name": field.name,
                        "return_type_name": field.return_type_name,
                        "return_type_kind": field.return_type_kind,
                        "arguments": tuple(
                            {
                                "name": argument.name,
                                "type_name": argument.type_name,
                                "type_kind": argument.type_kind,
                                "required": argument.required,
                            }
                            for argument in field.arguments
                        ),
                    }
                    for field in gql_type.fields
                ),
            }
            for gql_type in schema.types
        )

        return cls(
            session_id=session.session_id,
            created_at=datetime.now(
                timezone.utc
            ).isoformat(),
            target=session.target,
            target_type=session.target_type,
            scope=session.scope,
            status="completed",
            endpoint_url=endpoint_url,
            source=source,
            query_type=schema.query_type,
            mutation_type=schema.mutation_type,
            subscription_type=schema.subscription_type,
            types=types,
        )

    @property
    def field_count(self) -> int:
        return sum(
            len(item["fields"])
            for item in self.types
        )

    def to_dict(self) -> dict:
        data = asdict(
            self
        )
        data["summary"] = {
            "types": len(
                self.types
            ),
            "fields": self.field_count,
            "query_type": (
                self.query_type
                or None
            ),
            "mutation_type": (
                self.mutation_type
                or None
            ),
            "subscription_type": (
                self.subscription_type
                or None
            ),
        }
        return data
