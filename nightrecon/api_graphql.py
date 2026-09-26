"""Bounded GraphQL schema intelligence for NightRecon.

NightRecon can normalize saved introspection JSON or execute one fixed
introspection operation against an explicitly authorized same-origin endpoint.
Arbitrary GraphQL query text, variables, mutations, and subscriptions are not
accepted by this module.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

from nightrecon.web_crawl import (
    normalize_http_url,
    url_origin,
)


_INTROSPECTION_QUERY = """
query NightReconIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      fields(includeDeprecated: true) {
        name
        args {
          name
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
""".strip()

_DEFAULT_USER_AGENT = "NightRecon/0.27 graphql-introspection"


@dataclass(frozen=True)
class GraphQLArgument:
    name: str
    type_name: str
    type_kind: str
    required: bool


@dataclass(frozen=True)
class GraphQLField:
    name: str
    return_type_name: str
    return_type_kind: str
    arguments: tuple[GraphQLArgument, ...]


@dataclass(frozen=True)
class GraphQLType:
    name: str
    kind: str
    fields: tuple[GraphQLField, ...]


@dataclass(frozen=True)
class GraphQLSchema:
    query_type: str
    mutation_type: str
    subscription_type: str
    types: tuple[GraphQLType, ...]

    @property
    def field_count(self) -> int:
        return sum(
            len(item.fields)
            for item in self.types
        )


@dataclass(frozen=True)
class GraphQLIntrospectionResult:
    success: bool
    reason: str
    endpoint_url: str
    status: int | None
    byte_count: int
    schema: GraphQLSchema | None


class _NoRedirectHandler(
    HTTPRedirectHandler
):
    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        return None


def _safe_text(
    value: Any,
    *,
    limit: int = 512,
) -> str:
    if not isinstance(
        value,
        str,
    ):
        return ""

    return value.strip()[
        :limit
    ]


def _type_reference(
    value: Any,
) -> tuple[str, str, bool]:
    if not isinstance(
        value,
        Mapping,
    ):
        return "", "", False

    outer_kind = _safe_text(
        value.get("kind"),
        limit=64,
    )
    required = (
        outer_kind == "NON_NULL"
    )
    current: Any = value

    for _ in range(8):
        if not isinstance(
            current,
            Mapping,
        ):
            break

        name = _safe_text(
            current.get("name"),
            limit=256,
        )
        kind = _safe_text(
            current.get("kind"),
            limit=64,
        )

        if name:
            return (
                name,
                kind,
                required,
            )

        current = current.get(
            "ofType"
        )

    return "", outer_kind, required


def parse_graphql_introspection(
    document: Mapping[str, Any],
) -> GraphQLSchema:
    """Normalize GraphQL introspection metadata without retaining values."""

    if not isinstance(
        document,
        Mapping,
    ):
        raise ValueError(
            "GraphQL introspection document must be an object."
        )

    root: Any = document

    if isinstance(
        document.get("data"),
        Mapping,
    ):
        root = document[
            "data"
        ]

    if not isinstance(
        root,
        Mapping,
    ):
        raise ValueError(
            "GraphQL introspection data must be an object."
        )

    schema = root.get(
        "__schema"
    )

    if not isinstance(
        schema,
        Mapping,
    ):
        raise ValueError(
            "GraphQL introspection response does not contain __schema."
        )

    def root_type(
        key: str,
    ) -> str:
        value = schema.get(
            key
        )

        if not isinstance(
            value,
            Mapping,
        ):
            return ""

        return _safe_text(
            value.get("name"),
            limit=256,
        )

    normalized_types: list[
        GraphQLType
    ] = []

    raw_types = schema.get(
        "types",
        (),
    )

    if not isinstance(
        raw_types,
        list,
    ):
        raise ValueError(
            "GraphQL introspection types must be a list."
        )

    for raw_type in raw_types:
        if not isinstance(
            raw_type,
            Mapping,
        ):
            continue

        name = _safe_text(
            raw_type.get("name"),
            limit=256,
        )
        kind = _safe_text(
            raw_type.get("kind"),
            limit=64,
        )

        if not name or not kind:
            continue

        fields: list[
            GraphQLField
        ] = []
        raw_fields = raw_type.get(
            "fields",
            (),
        )

        if isinstance(
            raw_fields,
            list,
        ):
            for raw_field in raw_fields:
                if not isinstance(
                    raw_field,
                    Mapping,
                ):
                    continue

                field_name = _safe_text(
                    raw_field.get("name"),
                    limit=256,
                )

                if not field_name:
                    continue

                return_name, return_kind, _ = (
                    _type_reference(
                        raw_field.get(
                            "type"
                        )
                    )
                )
                arguments: list[
                    GraphQLArgument
                ] = []
                raw_arguments = raw_field.get(
                    "args",
                    (),
                )

                if isinstance(
                    raw_arguments,
                    list,
                ):
                    for raw_argument in raw_arguments:
                        if not isinstance(
                            raw_argument,
                            Mapping,
                        ):
                            continue

                        argument_name = _safe_text(
                            raw_argument.get(
                                "name"
                            ),
                            limit=256,
                        )

                        if not argument_name:
                            continue

                        (
                            argument_type_name,
                            argument_type_kind,
                            argument_required,
                        ) = _type_reference(
                            raw_argument.get(
                                "type"
                            )
                        )
                        arguments.append(
                            GraphQLArgument(
                                name=argument_name,
                                type_name=argument_type_name,
                                type_kind=argument_type_kind,
                                required=argument_required,
                            )
                        )

                fields.append(
                    GraphQLField(
                        name=field_name,
                        return_type_name=return_name,
                        return_type_kind=return_kind,
                        arguments=tuple(
                            sorted(
                                arguments,
                                key=lambda item: item.name,
                            )
                        ),
                    )
                )

        normalized_types.append(
            GraphQLType(
                name=name,
                kind=kind,
                fields=tuple(
                    sorted(
                        fields,
                        key=lambda item: item.name,
                    )
                ),
            )
        )

    return GraphQLSchema(
        query_type=root_type(
            "queryType"
        ),
        mutation_type=root_type(
            "mutationType"
        ),
        subscription_type=root_type(
            "subscriptionType"
        ),
        types=tuple(
            sorted(
                normalized_types,
                key=lambda item: item.name,
            )
        ),
    )


def load_graphql_introspection_json(
    path: str | Path,
    *,
    max_bytes: int = 2_097_152,
) -> GraphQLSchema:
    if max_bytes < 1:
        raise ValueError(
            "max_bytes must be at least 1."
        )

    file_path = Path(
        path
    )
    payload = file_path.read_bytes()

    if len(payload) > max_bytes:
        raise ValueError(
            "GraphQL introspection document exceeds max_bytes."
        )

    try:
        document = json.loads(
            payload.decode(
                "utf-8"
            )
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as exc:
        raise ValueError(
            "GraphQL introspection document must be valid UTF-8 JSON."
        ) from exc

    if not isinstance(
        document,
        Mapping,
    ):
        raise ValueError(
            "GraphQL introspection document root must be an object."
        )

    return parse_graphql_introspection(
        document
    )


def execute_graphql_introspection(
    *,
    endpoint_url: str,
    origin: str,
    authorized: bool,
    timeout: float = 5.0,
    max_response_bytes: int = 1_048_576,
    authorization: str | None = None,
    user_agent: str = _DEFAULT_USER_AGENT,
) -> GraphQLIntrospectionResult:
    """Execute exactly one fixed GraphQL introspection operation."""

    if not authorized:
        raise PermissionError(
            "GraphQL introspection requires explicit authorization."
        )

    if timeout <= 0:
        raise ValueError(
            "timeout must be greater than 0."
        )

    if max_response_bytes < 1:
        raise ValueError(
            "max_response_bytes must be at least 1."
        )

    if (
        not isinstance(
            user_agent,
            str,
        )
        or not user_agent.strip()
    ):
        raise ValueError(
            "user_agent must be a non-empty string."
        )

    if authorization is not None and (
        not isinstance(
            authorization,
            str,
        )
        or not authorization.strip()
    ):
        raise ValueError(
            "authorization must be a non-empty string when provided."
        )

    raw_parts = urlsplit(
        endpoint_url
    )

    if (
        raw_parts.username is not None
        or raw_parts.password is not None
        or raw_parts.query
        or raw_parts.fragment
    ):
        raise ValueError(
            "GraphQL endpoint URL must not contain credentials, "
            "query data, or a fragment."
        )

    endpoint = normalize_http_url(
        endpoint_url
    )
    normalized_origin = url_origin(
        origin
    )

    if url_origin(
        endpoint
    ) != normalized_origin:
        raise PermissionError(
            "GraphQL endpoint is outside the authorized origin."
        )

    body = json.dumps(
        {
            "query": _INTROSPECTION_QUERY,
            "operationName": "NightReconIntrospection",
        },
        separators=(
            ",",
            ":",
        ),
    ).encode(
        "utf-8"
    )
    headers = {
        "User-Agent": user_agent.strip(),
        "Accept": "application/json",
        "Content-Type": "application/json",
    }

    if authorization is not None:
        headers[
            "Authorization"
        ] = authorization.strip()

    request = Request(
        endpoint,
        data=body,
        headers=headers,
        method="POST",
    )
    opener = build_opener(
        _NoRedirectHandler()
    )

    try:
        with opener.open(
            request,
            timeout=timeout,
        ) as response:
            status = getattr(
                response,
                "status",
                None,
            )
            payload = response.read(
                max_response_bytes + 1
            )
    except HTTPError as exc:
        return GraphQLIntrospectionResult(
            success=False,
            reason="http_error",
            endpoint_url=endpoint,
            status=exc.code,
            byte_count=0,
            schema=None,
        )
    except (
        URLError,
        OSError,
        ValueError,
    ):
        return GraphQLIntrospectionResult(
            success=False,
            reason="request_failed",
            endpoint_url=endpoint,
            status=None,
            byte_count=0,
            schema=None,
        )

    if (
        len(payload)
        > max_response_bytes
    ):
        return GraphQLIntrospectionResult(
            success=False,
            reason="response_byte_limit_exceeded",
            endpoint_url=endpoint,
            status=status,
            byte_count=max_response_bytes,
            schema=None,
        )

    try:
        document = json.loads(
            payload.decode(
                "utf-8"
            )
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
    ):
        return GraphQLIntrospectionResult(
            success=False,
            reason="invalid_json_response",
            endpoint_url=endpoint,
            status=status,
            byte_count=len(
                payload
            ),
            schema=None,
        )

    try:
        schema = parse_graphql_introspection(
            document
        )
    except ValueError:
        return GraphQLIntrospectionResult(
            success=False,
            reason="invalid_introspection_response",
            endpoint_url=endpoint,
            status=status,
            byte_count=len(
                payload
            ),
            schema=None,
        )

    success = (
        status is not None
        and 200 <= status < 300
    )

    return GraphQLIntrospectionResult(
        success=success,
        reason=(
            "completed"
            if success
            else "non_success_status"
        ),
        endpoint_url=endpoint,
        status=status,
        byte_count=len(
            payload
        ),
        schema=(
            schema
            if success
            else None
        ),
    )
