"""Bounded read-only Microsoft Entra identity provider.

The provider uses a fixed Microsoft Graph v1.0 collection plan for users,
groups, service principals, and direct group memberships. It exposes no
operator-supplied Graph URL or OData query surface. The concrete transport
accepts only approved graph.microsoft.com v1.0 paths and validated @odata.nextLink
paging URLs.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import json
from time import monotonic
from typing import Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

from nightrecon_red_engine.graph_identity_evidence import (
    IdentityEvidenceBundle,
    IdentityRelationshipEvidence,
    RoleEvidence,
)
from nightrecon_red_engine.graph_models import GraphNodeKind
from nightrecon_red_engine.identity_collection import (
    DirectoryEntry,
    IdentityCollectionRequest,
    IdentityProviderCollection,
)
from nightrecon_red_engine.red_directory_import import directory_natural_key


GRAPH_HOST = "graph.microsoft.com"
GRAPH_BASE_URL = "https://graph.microsoft.com"
GRAPH_USERS_PATH = (
    "/v1.0/users?$select=id,displayName,userPrincipalName&$top=100"
)
GRAPH_GROUPS_PATH = "/v1.0/groups?$select=id,displayName&$top=100"
GRAPH_APPLICATIONS_PATH = "/v1.0/applications?$select=id,displayName,appId&$top=100"
GRAPH_SERVICE_PRINCIPALS_PATH = (
    "/v1.0/servicePrincipals?$select=id,displayName,appId&$top=100"
)
GRAPH_ROLE_DEFINITIONS_PATH = "/v1.0/roleManagement/directory/roleDefinitions"
GRAPH_ROLE_ASSIGNMENTS_PATH = (
    "/v1.0/roleManagement/directory/roleAssignments"
    "?$select=id,principalId,roleDefinitionId,directoryScopeId"
)

_ALLOWED_QUERY_KEYS = frozenset({"$select", "$top", "$skiptoken"})
_ALLOWED_COLLECTION_PATHS = frozenset({
    "/v1.0/users",
    "/v1.0/groups",
    "/v1.0/applications",
    "/v1.0/servicePrincipals",
    "/v1.0/roleManagement/directory/roleDefinitions",
    "/v1.0/roleManagement/directory/roleAssignments",
})


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


def _object_id(value: object) -> str:
    result = _required_text(value, "Microsoft Graph object id")
    if len(result) > 256 or any(char in result for char in "/?#"):
        raise ValueError("Microsoft Graph object id contains unsupported characters")
    return result


def _group_members_path(group_id: str) -> str:
    encoded = quote(_object_id(group_id), safe="._-")
    return (
        f"/v1.0/groups/{encoded}/members"
        "?$select=id,displayName,userPrincipalName,appId&$top=100"
    )


def _owners_path(resource: str, object_id: str) -> str:
    if resource not in {"applications", "servicePrincipals"}:
        raise ValueError("Microsoft Graph ownership resource is unsupported")
    encoded = quote(_object_id(object_id), safe="._-")
    return (
        f"/v1.0/{resource}/{encoded}/owners"
        "?$select=id,displayName,userPrincipalName,appId&$top=100"
    )


def _validate_graph_url(url: str) -> str:
    _required_text(url, "Microsoft Graph URL")
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("Microsoft Graph transport requires HTTPS")
    if parsed.hostname != GRAPH_HOST or parsed.username or parsed.password:
        raise ValueError("Microsoft Graph URL must target graph.microsoft.com")
    if parsed.port not in (None, 443):
        raise ValueError("Microsoft Graph URL uses an unsupported port")
    if parsed.fragment:
        raise ValueError("Microsoft Graph URL fragments are not supported")

    path = parsed.path
    relationship_kind = ""
    allowed = path in _ALLOWED_COLLECTION_PATHS
    if not allowed:
        pieces = path.split("/")
        allowed = (
            len(pieces) == 5
            and pieces[:3] == ["", "v1.0", "groups"]
            and pieces[4] == "members"
            and bool(pieces[3])
            and len(pieces[3]) <= 256
            and not any(char in pieces[3] for char in "?#")
        )
        if allowed:
            relationship_kind = "members"
        else:
            allowed = (
                len(pieces) == 5
                and pieces[1] == "v1.0"
                and pieces[2] in {"applications", "servicePrincipals"}
                and pieces[4] == "owners"
                and bool(pieces[3])
                and len(pieces[3]) <= 256
                and not any(char in pieces[3] for char in "?#")
            )
            if allowed:
                relationship_kind = "owners"
    if not allowed:
        raise ValueError("Microsoft Graph URL is outside the fixed Entra collection plan")

    query = parse_qs(parsed.query, keep_blank_values=True)
    if set(query) - _ALLOWED_QUERY_KEYS:
        raise ValueError("Microsoft Graph query is outside the fixed Entra collection plan")
    if any(len(values) != 1 for values in query.values()):
        raise ValueError("Microsoft Graph query contains repeated parameters")

    expected_select = {
        "/v1.0/users": "id,displayName,userPrincipalName",
        "/v1.0/groups": "id,displayName",
        "/v1.0/applications": "id,displayName,appId",
        "/v1.0/servicePrincipals": "id,displayName,appId",
        "/v1.0/roleManagement/directory/roleAssignments":
            "id,principalId,roleDefinitionId,directoryScopeId",
    }.get(path)
    if relationship_kind in {"members", "owners"}:
        expected_select = "id,displayName,userPrincipalName,appId"

    if expected_select is None:
        if path != "/v1.0/roleManagement/directory/roleDefinitions":
            raise ValueError(
                "Microsoft Graph projection is outside the fixed Entra collection plan"
            )
        if "$select" in query or "$top" in query:
            raise ValueError(
                "Microsoft Graph role-definition query is outside the fixed plan"
            )
    else:
        if query.get("$select") != [expected_select]:
            raise ValueError(
                "Microsoft Graph $select is outside the fixed Entra collection plan"
            )
        if path != "/v1.0/roleManagement/directory/roleAssignments":
            if query.get("$top") != ["100"]:
                raise ValueError(
                    "Microsoft Graph $top is outside the fixed Entra collection plan"
                )
        elif "$top" in query:
            raise ValueError(
                "Microsoft Graph role-assignment query is outside the fixed plan"
            )

    if "$skiptoken" in query and not query["$skiptoken"][0]:
        raise ValueError("Microsoft Graph $skiptoken must not be blank")
    return url


def _absolute_graph_url(path_or_url: str) -> str:
    if path_or_url.startswith("/"):
        return _validate_graph_url(GRAPH_BASE_URL + path_or_url)
    return _validate_graph_url(path_or_url)


@dataclass(frozen=True)
class GraphPage:
    items: tuple[Mapping[str, object], ...]
    next_link: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.items, tuple) or any(
            not isinstance(item, Mapping) for item in self.items
        ):
            raise ValueError("Microsoft Graph page items must be a tuple of mappings")
        if self.next_link is not None:
            _validate_graph_url(self.next_link)


class EntraGraphTransport(Protocol):
    def get_page(self, path_or_url: str) -> GraphPage: ...

    def close(self) -> None: ...


class _NoGraphRedirects(HTTPRedirectHandler):
    """Reject redirects so bearer credentials never leave the fixed Graph host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class MicrosoftGraphTransport:
    """Fixed-host Graph v1.0 transport with ephemeral bearer-token resolution."""

    def __init__(
        self,
        *,
        access_token_resolver: Callable[[], str],
        timeout_seconds: float = 10.0,
        max_response_bytes: int = 1_000_000,
    ) -> None:
        if not callable(access_token_resolver):
            raise ValueError("access_token_resolver must be callable")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be greater than zero")
        if type(max_response_bytes) is not int or max_response_bytes < 1:
            raise ValueError("max_response_bytes must be a positive integer")
        self._access_token_resolver = access_token_resolver
        self._timeout_seconds = float(timeout_seconds)
        self._max_response_bytes = max_response_bytes
        self._opener = build_opener(_NoGraphRedirects())

    def __repr__(self) -> str:
        return (
            "MicrosoftGraphTransport("
            f"host={GRAPH_HOST!r}, timeout_seconds={self._timeout_seconds!r}, "
            f"max_response_bytes={self._max_response_bytes})"
        )

    def get_page(self, path_or_url: str) -> GraphPage:
        url = _absolute_graph_url(path_or_url)
        try:
            token = self._access_token_resolver()
        except Exception:
            raise LookupError(
                "Microsoft Graph access token could not be resolved"
            ) from None
        response = None
        try:
            _required_text(token, "resolved Microsoft Graph access token")
            request = Request(
                url,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {token}",
                },
                method="GET",
            )
            try:
                response = self._opener.open(request, timeout=self._timeout_seconds)
                payload = response.read(self._max_response_bytes + 1)
            except HTTPError as exc:
                raise RuntimeError(
                    f"Microsoft Graph read-only request failed with HTTP {exc.code}"
                ) from exc
            except URLError as exc:
                raise RuntimeError("Microsoft Graph read-only request failed") from exc
        finally:
            token = ""
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass

        if len(payload) > self._max_response_bytes:
            raise ValueError("Microsoft Graph response exceeds max_response_bytes")
        try:
            data = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise ValueError("Microsoft Graph response is not valid UTF-8 JSON") from exc
        if not isinstance(data, dict) or not isinstance(data.get("value"), list):
            raise ValueError("Microsoft Graph response has an unsupported shape")
        if set(data) - {"@odata.context", "@odata.nextLink", "value"}:
            raise ValueError("Microsoft Graph response contains unsupported top-level fields")

        items = tuple(
            dict(item)
            for item in data["value"]
            if isinstance(item, Mapping)
        )
        if len(items) != len(data["value"]):
            raise ValueError("Microsoft Graph response contains a non-object collection item")

        next_link = data.get("@odata.nextLink")
        if next_link is not None:
            if not isinstance(next_link, str):
                raise ValueError("Microsoft Graph @odata.nextLink must be a string")
            next_link = _validate_graph_url(next_link)
        return GraphPage(items=items, next_link=next_link)

    def close(self) -> None:
        return None


@dataclass(frozen=True)
class EntraProviderLimits:
    max_requests: int = 96
    max_pages_per_collection: int = 10
    max_groups_with_membership_reads: int = 32
    max_owner_objects: int = 64
    max_role_definitions: int = 256
    max_relationships: int = 5_000
    max_runtime_seconds: float = 30.0

    def __post_init__(self) -> None:
        if type(self.max_requests) is not int or self.max_requests < 1:
            raise ValueError("max_requests must be a positive integer")
        if (
            type(self.max_pages_per_collection) is not int
            or self.max_pages_per_collection < 1
        ):
            raise ValueError("max_pages_per_collection must be a positive integer")
        if (
            type(self.max_groups_with_membership_reads) is not int
            or self.max_groups_with_membership_reads < 1
        ):
            raise ValueError(
                "max_groups_with_membership_reads must be a positive integer"
            )
        if type(self.max_owner_objects) is not int or self.max_owner_objects < 1:
            raise ValueError("max_owner_objects must be a positive integer")
        if type(self.max_role_definitions) is not int or self.max_role_definitions < 1:
            raise ValueError("max_role_definitions must be a positive integer")
        if type(self.max_relationships) is not int or self.max_relationships < 1:
            raise ValueError("max_relationships must be a positive integer")
        if (
            isinstance(self.max_runtime_seconds, bool)
            or not isinstance(self.max_runtime_seconds, (int, float))
            or self.max_runtime_seconds <= 0
        ):
            raise ValueError("max_runtime_seconds must be greater than zero")


def _display_name(item: Mapping[str, object], *fallbacks: str) -> str:
    value = item.get("displayName")
    if isinstance(value, str) and value.strip():
        return value.strip()
    for field in fallbacks:
        value = item.get(field)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return _object_id(item.get("id"))


def _member_kind(item: Mapping[str, object]) -> str | None:
    raw = item.get("@odata.type")
    if not isinstance(raw, str):
        return None
    normalized = raw.casefold()
    if normalized == "#microsoft.graph.user":
        return "user"
    if normalized == "#microsoft.graph.group":
        return "group"
    if normalized == "#microsoft.graph.serviceprincipal":
        return "service"
    return None


class EntraIdentityProvider:
    """Fixed-plan, bounded, read-only Microsoft Entra provider."""

    def __init__(
        self,
        *,
        transport: EntraGraphTransport,
        tenant_id: str,
        limits: EntraProviderLimits = EntraProviderLimits(),
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._transport = transport
        self._tenant_id = _required_text(tenant_id, "tenant_id")
        if not isinstance(limits, EntraProviderLimits):
            raise ValueError("limits must be EntraProviderLimits")
        if not callable(clock):
            raise ValueError("clock must be callable")
        self._limits = limits
        self._clock = clock

    def collect(self, request: IdentityCollectionRequest) -> IdentityProviderCollection:
        if request.source_type != "entra-id":
            raise ValueError("Entra provider requires source_type entra-id")
        if request.target.casefold() != self._tenant_id.casefold():
            raise ValueError("Entra request target does not match configured tenant")

        started = self._clock()
        request_count = 0
        truncated = False
        limitations: list[str] = []
        identities: dict[str, DirectoryEntry] = {}
        groups: dict[str, tuple[str, set[str]]] = {}

        def mark_truncated(reason: str) -> None:
            nonlocal truncated
            truncated = True
            if reason not in limitations:
                limitations.append(reason)

        def budget_available() -> bool:
            if request_count >= self._limits.max_requests:
                mark_truncated("Microsoft Graph request ceiling reached.")
                return False
            if self._clock() - started >= self._limits.max_runtime_seconds:
                mark_truncated("Microsoft Graph runtime ceiling reached.")
                return False
            return True

        def read_collection(
            initial_path: str,
            handler: Callable[[Mapping[str, object]], None],
        ) -> None:
            nonlocal request_count
            page_ref: str | None = initial_path
            pages = 0
            while page_ref is not None:
                if not budget_available():
                    return
                if pages >= self._limits.max_pages_per_collection:
                    mark_truncated("Microsoft Graph page ceiling reached.")
                    return
                page = self._transport.get_page(page_ref)
                if not isinstance(page, GraphPage):
                    raise ValueError("Microsoft Graph transport returned an invalid page")
                request_count += 1
                pages += 1
                for item in page.items:
                    handler(item)
                    if len(identities) + len(groups) >= request.limits.max_entries:
                        mark_truncated("Microsoft Graph entry ceiling reached.")
                        return
                page_ref = page.next_link

        def add_identity(item: Mapping[str, object], kind: str) -> None:
            object_id = _object_id(item.get("id"))
            if object_id in groups:
                raise ValueError("Microsoft Graph object id appears as both group and identity")
            name = (
                _display_name(item, "userPrincipalName")
                if kind == "user"
                else _display_name(item, "appId")
            )
            existing = identities.get(object_id)
            entry = DirectoryEntry(object_id, kind, name)
            if existing is not None and existing != entry:
                raise ValueError("Microsoft Graph object id has conflicting identity data")
            identities[object_id] = entry

        def add_group(item: Mapping[str, object]) -> None:
            object_id = _object_id(item.get("id"))
            if object_id in identities:
                raise ValueError("Microsoft Graph object id appears as both identity and group")
            name = _display_name(item)
            existing = groups.get(object_id)
            if existing is not None and existing[0] != name:
                raise ValueError("Microsoft Graph group id has conflicting display data")
            groups.setdefault(object_id, (name, set()))

        def add_member(group_id: str, item: Mapping[str, object]) -> None:
            kind = _member_kind(item)
            if kind is None:
                mark_truncated(
                    "Microsoft Graph returned an unsupported group member type; "
                    "that relationship was omitted."
                )
                return
            member_id = _object_id(item.get("id"))
            group = groups.get(group_id)
            if group is None:
                raise ValueError("Microsoft Graph membership references an unknown group")
            members = group[1]
            if member_id in members:
                return
            membership_count = sum(len(value[1]) for value in groups.values())
            if membership_count >= request.limits.max_memberships:
                mark_truncated("Microsoft Graph membership ceiling reached.")
                return
            members.add(member_id)

        try:
            read_collection(
                GRAPH_USERS_PATH,
                lambda item: add_identity(item, "user"),
            )
            if len(identities) + len(groups) < request.limits.max_entries:
                read_collection(GRAPH_GROUPS_PATH, add_group)
            if len(identities) + len(groups) < request.limits.max_entries:
                read_collection(
                    GRAPH_SERVICE_PRINCIPALS_PATH,
                    lambda item: add_identity(item, "service"),
                )

            group_ids = tuple(sorted(groups))
            if len(group_ids) > self._limits.max_groups_with_membership_reads:
                mark_truncated("Microsoft Graph group-membership read ceiling reached.")
                group_ids = group_ids[:self._limits.max_groups_with_membership_reads]

            for group_id in group_ids:
                if not budget_available():
                    break
                before_requests = request_count
                read_collection(
                    _group_members_path(group_id),
                    lambda item, gid=group_id: add_member(gid, item),
                )
                if request_count == before_requests and truncated:
                    break

            if group_ids:
                mark_truncated(
                    "Microsoft Graph v1.0 group-member listing may omit service "
                    "principals; service-principal group membership can be incomplete."
                )
        finally:
            self._transport.close()

        entries: list[DirectoryEntry] = list(identities.values())
        for group_id, (name, members) in groups.items():
            entries.append(
                DirectoryEntry(
                    group_id,
                    "group",
                    name,
                    tuple(sorted(members)),
                )
            )

        duration_ms = max(0, int(round((self._clock() - started) * 1_000)))
        return IdentityProviderCollection(
            entries=tuple(
                sorted(
                    entries,
                    key=lambda item: (
                        item.kind,
                        item.distinguished_name.casefold(),
                    ),
                )
            ),
            truncated=truncated,
            request_count=request_count,
            duration_ms=duration_ms,
            limitations=tuple(limitations),
        )
