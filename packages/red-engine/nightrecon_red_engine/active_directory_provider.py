"""Bounded read-only Active Directory identity provider.

The provider has a fixed collection plan for users, groups, and observed group
memberships. It never accepts an operator-supplied LDAP filter or attribute
list. The concrete ldap3 transport supports encrypted LDAPS or LDAP+StartTLS,
validates server certificates, disables referrals, and resolves bind secrets
only when the authorized collection is actually executed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import ssl
from time import monotonic
from typing import Protocol

from nightrecon_red_engine.identity_collection import (
    DirectoryEntry,
    IdentityCollectionRequest,
    IdentityProviderCollection,
)


AD_USER_FILTER = (
    "(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))"
)
AD_GROUP_FILTER = "(objectClass=group)"
AD_USER_ATTRIBUTES = (
    "distinguishedName",
    "displayName",
    "sAMAccountName",
    "name",
)
AD_GROUP_ATTRIBUTES = (
    "distinguishedName",
    "cn",
    "name",
    "member",
)


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


@dataclass(frozen=True)
class ActiveDirectoryProviderLimits:
    """Hard provider-side ceilings in addition to request-level limits."""

    page_size: int = 250
    max_pages: int = 16
    search_time_limit_seconds: int = 10
    max_runtime_seconds: float = 30.0

    def __post_init__(self) -> None:
        if type(self.page_size) is not int or self.page_size < 1:
            raise ValueError("page_size must be a positive integer")
        if type(self.max_pages) is not int or self.max_pages < 1:
            raise ValueError("max_pages must be a positive integer")
        if (
            type(self.search_time_limit_seconds) is not int
            or self.search_time_limit_seconds < 1
        ):
            raise ValueError("search_time_limit_seconds must be a positive integer")
        if (
            isinstance(self.max_runtime_seconds, bool)
            or not isinstance(self.max_runtime_seconds, (int, float))
            or self.max_runtime_seconds <= 0
        ):
            raise ValueError("max_runtime_seconds must be greater than zero")


@dataclass(frozen=True)
class LdapSearchPage:
    """One bounded LDAP search response page."""

    entries: tuple[Mapping[str, object], ...]
    cookie: bytes | str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple) or any(
            not isinstance(item, Mapping) for item in self.entries
        ):
            raise ValueError("LDAP page entries must be a tuple of mappings")
        if not isinstance(self.cookie, (bytes, str, type(None))):
            raise ValueError("LDAP page cookie has an unsupported type")


class ActiveDirectorySearchTransport(Protocol):
    """Narrow internal transport used only by the fixed AD collection plan."""

    @property
    def target(self) -> str: ...

    def search_page(
        self,
        *,
        base_dn: str,
        search_filter: str,
        attributes: tuple[str, ...],
        page_size: int,
        page_cookie: bytes | str | None,
        time_limit_seconds: int,
    ) -> LdapSearchPage: ...

    def close(self) -> None: ...


class Ldap3ActiveDirectoryTransport:
    """Encrypted ldap3 transport with ephemeral bind-secret resolution."""

    def __init__(
        self,
        *,
        host: str,
        bind_username: str,
        secret_resolver: Callable[[], str],
        mode: str = "ldaps",
        port: int | None = None,
        ca_certs_file: str | None = None,
        connect_timeout_seconds: float = 5.0,
        receive_timeout_seconds: float = 10.0,
    ) -> None:
        self._host = _required_text(host, "host")
        self._bind_username = _required_text(bind_username, "bind_username")
        if not callable(secret_resolver):
            raise ValueError("secret_resolver must be callable")
        if mode not in {"ldaps", "starttls"}:
            raise ValueError("mode must be ldaps or starttls")
        selected_port = 636 if mode == "ldaps" else 389
        if port is not None:
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("port must be between 1 and 65535")
            selected_port = port
        if (
            isinstance(connect_timeout_seconds, bool)
            or not isinstance(connect_timeout_seconds, (int, float))
            or connect_timeout_seconds <= 0
        ):
            raise ValueError("connect_timeout_seconds must be greater than zero")
        if (
            isinstance(receive_timeout_seconds, bool)
            or not isinstance(receive_timeout_seconds, (int, float))
            or receive_timeout_seconds <= 0
        ):
            raise ValueError("receive_timeout_seconds must be greater than zero")
        if ca_certs_file is not None:
            _required_text(ca_certs_file, "ca_certs_file")

        self._secret_resolver = secret_resolver
        self._mode = mode
        self._port = selected_port
        self._ca_certs_file = ca_certs_file
        self._connect_timeout_seconds = float(connect_timeout_seconds)
        self._receive_timeout_seconds = float(receive_timeout_seconds)
        self._connection = None

    @property
    def target(self) -> str:
        return self._host

    def __repr__(self) -> str:
        return (
            "Ldap3ActiveDirectoryTransport("
            f"host={self._host!r}, mode={self._mode!r}, port={self._port})"
        )

    def _open_connection(self):
        if self._connection is not None:
            return self._connection

        try:
            from ldap3 import Connection, Server, Tls
        except ImportError as exc:
            raise RuntimeError(
                "Active Directory collection requires the optional "
                "'nightrecon-red-engine[ad]' dependency."
            ) from exc

        tls = Tls(
            validate=ssl.CERT_REQUIRED,
            ca_certs_file=self._ca_certs_file,
        )
        server = Server(
            self._host,
            port=self._port,
            use_ssl=self._mode == "ldaps",
            tls=tls,
            connect_timeout=self._connect_timeout_seconds,
        )
        secret = self._secret_resolver()
        try:
            _required_text(secret, "resolved bind secret")
            connection = Connection(
                server,
                user=self._bind_username,
                password=secret,
                receive_timeout=self._receive_timeout_seconds,
                auto_referrals=False,
                raise_exceptions=True,
            )
            if self._mode == "starttls":
                connection.open()
                if not connection.start_tls():
                    raise RuntimeError("LDAP StartTLS negotiation failed")
            if not connection.bind():
                raise RuntimeError("LDAP bind failed")
        finally:
            secret = ""

        self._connection = connection
        return connection

    @staticmethod
    def _page_cookie(result: object) -> bytes | str | None:
        if not isinstance(result, Mapping):
            return None
        controls = result.get("controls")
        if not isinstance(controls, Mapping):
            return None
        paging = controls.get("1.2.840.113556.1.4.319")
        if not isinstance(paging, Mapping):
            return None
        value = paging.get("value")
        if not isinstance(value, Mapping):
            return None
        cookie = value.get("cookie")
        if isinstance(cookie, (bytes, str)):
            return cookie or None
        return None

    def search_page(
        self,
        *,
        base_dn: str,
        search_filter: str,
        attributes: tuple[str, ...],
        page_size: int,
        page_cookie: bytes | str | None,
        time_limit_seconds: int,
    ) -> LdapSearchPage:
        _required_text(base_dn, "base_dn")
        if search_filter not in {AD_USER_FILTER, AD_GROUP_FILTER}:
            raise ValueError("LDAP search filter is outside the fixed AD collection plan")
        allowed_attributes = {
            AD_USER_FILTER: AD_USER_ATTRIBUTES,
            AD_GROUP_FILTER: AD_GROUP_ATTRIBUTES,
        }
        if attributes != allowed_attributes[search_filter]:
            raise ValueError("LDAP attributes are outside the fixed AD collection plan")
        if type(page_size) is not int or page_size < 1:
            raise ValueError("page_size must be positive")
        if type(time_limit_seconds) is not int or time_limit_seconds < 1:
            raise ValueError("time_limit_seconds must be positive")

        try:
            from ldap3 import SUBTREE
        except ImportError as exc:
            raise RuntimeError(
                "Active Directory collection requires the optional "
                "'nightrecon-red-engine[ad]' dependency."
            ) from exc

        connection = self._open_connection()
        succeeded = connection.search(
            search_base=base_dn,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=list(attributes),
            size_limit=0,
            time_limit=time_limit_seconds,
            paged_size=page_size,
            paged_criticality=True,
            paged_cookie=page_cookie,
        )
        if not succeeded:
            result = connection.result
            description = (
                result.get("description", "unknown")
                if isinstance(result, Mapping)
                else "unknown"
            )
            raise RuntimeError(f"LDAP read-only search failed: {description}")

        response = tuple(
            dict(item)
            for item in connection.response
            if isinstance(item, Mapping) and item.get("type") == "searchResEntry"
        )
        return LdapSearchPage(
            entries=response,
            cookie=self._page_cookie(connection.result),
        )

    def close(self) -> None:
        connection = self._connection
        self._connection = None
        if connection is not None:
            try:
                connection.unbind()
            except Exception:
                pass


def _attribute_text(attributes: Mapping[str, object], *names: str) -> str:
    for name in names:
        value = attributes.get(name)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (list, tuple)) and value:
            first = value[0]
            if isinstance(first, str) and first.strip():
                return first.strip()
    return ""


def _attribute_members(
    attributes: Mapping[str, object],
) -> tuple[tuple[str, ...], bool]:
    values: list[object] = []
    ranged = False

    for key, value in attributes.items():
        if not isinstance(key, str):
            continue
        normalized = key.casefold()
        if normalized == "member":
            pass
        elif normalized.startswith("member;range="):
            ranged = True
        else:
            continue

        if value in (None, ""):
            continue
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, (list, tuple)):
            values.extend(value)
        else:
            raise ValueError("LDAP group member attribute has an unsupported type")

    members: set[str] = set()
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise ValueError("LDAP group member values must be nonblank strings")
        members.add(item.strip())
    return tuple(sorted(members, key=str.casefold)), ranged


def _directory_entry(
    raw: Mapping[str, object],
    *,
    kind: str,
) -> tuple[DirectoryEntry, bool]:
    dn = _required_text(raw.get("dn"), "LDAP entry DN")
    attributes = raw.get("attributes")
    if not isinstance(attributes, Mapping):
        raise ValueError("LDAP entry attributes must be a mapping")

    if kind == "user":
        name = _attribute_text(
            attributes,
            "displayName",
            "sAMAccountName",
            "name",
        ) or dn
        return DirectoryEntry(dn, "user", name), False

    if kind == "group":
        name = _attribute_text(attributes, "cn", "name") or dn
        members, ranged = _attribute_members(attributes)
        return DirectoryEntry(
            dn,
            "group",
            name,
            members,
        ), ranged

    raise ValueError("unsupported Active Directory entry kind")


class ActiveDirectoryIdentityProvider:
    """Fixed-plan, bounded, read-only Active Directory provider."""

    def __init__(
        self,
        *,
        transport: ActiveDirectorySearchTransport,
        base_dn: str,
        limits: ActiveDirectoryProviderLimits = ActiveDirectoryProviderLimits(),
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._transport = transport
        self._base_dn = _required_text(base_dn, "base_dn")
        if not isinstance(limits, ActiveDirectoryProviderLimits):
            raise ValueError("limits must be ActiveDirectoryProviderLimits")
        if not callable(clock):
            raise ValueError("clock must be callable")
        self._limits = limits
        self._clock = clock

    def collect(self, request: IdentityCollectionRequest) -> IdentityProviderCollection:
        if request.source_type != "active-directory":
            raise ValueError("Active Directory provider requires source_type active-directory")
        if request.target.casefold() != self._transport.target.casefold():
            raise ValueError("Active Directory request target does not match provider target")

        started = self._clock()
        entries: list[DirectoryEntry] = []
        seen_dns: set[str] = set()
        membership_count = 0
        page_count = 0
        truncated = False
        limitations: list[str] = []

        def mark_truncated(reason: str) -> None:
            nonlocal truncated
            truncated = True
            if reason not in limitations:
                limitations.append(reason)

        try:
            for kind, search_filter, attributes in (
                ("user", AD_USER_FILTER, AD_USER_ATTRIBUTES),
                ("group", AD_GROUP_FILTER, AD_GROUP_ATTRIBUTES),
            ):
                cookie: bytes | str | None = None
                while True:
                    if len(entries) >= request.limits.max_entries:
                        mark_truncated("Active Directory entry ceiling reached.")
                        break
                    if page_count >= self._limits.max_pages:
                        mark_truncated("Active Directory page ceiling reached.")
                        break
                    if self._clock() - started >= self._limits.max_runtime_seconds:
                        mark_truncated("Active Directory runtime ceiling reached.")
                        break

                    page = self._transport.search_page(
                        base_dn=self._base_dn,
                        search_filter=search_filter,
                        attributes=attributes,
                        page_size=min(
                            self._limits.page_size,
                            request.limits.max_entries,
                        ),
                        page_cookie=cookie,
                        time_limit_seconds=self._limits.search_time_limit_seconds,
                    )
                    if not isinstance(page, LdapSearchPage):
                        raise ValueError("Active Directory transport returned an invalid page")
                    page_count += 1

                    for raw in page.entries:
                        entry, ranged_membership = _directory_entry(raw, kind=kind)
                        if ranged_membership:
                            mark_truncated(
                                "Active Directory returned ranged group membership; "
                                "additional members may be omitted."
                            )
                        normalized_dn = entry.distinguished_name.casefold()
                        if normalized_dn in seen_dns:
                            continue

                        if len(entries) >= request.limits.max_entries:
                            mark_truncated("Active Directory entry ceiling reached.")
                            break

                        if entry.kind == "group" and entry.members:
                            remaining = (
                                request.limits.max_memberships - membership_count
                            )
                            if remaining <= 0:
                                mark_truncated(
                                    "Active Directory membership ceiling reached."
                                )
                                break
                            if len(entry.members) > remaining:
                                entry = DirectoryEntry(
                                    entry.distinguished_name,
                                    entry.kind,
                                    entry.name,
                                    entry.members[:remaining],
                                )
                                mark_truncated(
                                    "Active Directory membership ceiling reached."
                                )

                        entries.append(entry)
                        seen_dns.add(normalized_dn)
                        membership_count += len(entry.members)

                        if truncated and (
                            len(entries) >= request.limits.max_entries
                            or membership_count >= request.limits.max_memberships
                        ):
                            break

                    if truncated and (
                        len(entries) >= request.limits.max_entries
                        or membership_count >= request.limits.max_memberships
                        or page_count >= self._limits.max_pages
                    ):
                        break

                    if self._clock() - started >= self._limits.max_runtime_seconds:
                        if page.cookie:
                            mark_truncated("Active Directory runtime ceiling reached.")
                        break

                    cookie = page.cookie
                    if not cookie:
                        break

                if truncated and (
                    len(entries) >= request.limits.max_entries
                    or membership_count >= request.limits.max_memberships
                    or page_count >= self._limits.max_pages
                    or self._clock() - started >= self._limits.max_runtime_seconds
                ):
                    break
        finally:
            self._transport.close()

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
            request_count=page_count,
            limitations=tuple(limitations),
        )
