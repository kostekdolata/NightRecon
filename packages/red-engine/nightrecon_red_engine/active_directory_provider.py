"""Bounded read-only Active Directory identity and relationship provider.

The provider has a fixed collection plan for directory identities, groups,
membership, selected privilege/delegation relationships, and domain trust
configuration. It never accepts an operator-supplied LDAP filter or attribute
list. The concrete ldap3 transport supports encrypted LDAPS or LDAP+StartTLS,
validates server certificates, disables referrals, and resolves bind secrets
only when an authorized collection is actually executed.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
import ssl
from time import monotonic
from typing import Protocol

from nightrecon_red_engine.graph_identity_evidence import (
    GroupMembershipEvidence,
    IdentityEvidence,
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


AD_USER_FILTER = (
    "(|(&(objectClass=user)(!(objectClass=computer)))"
    "(&(objectCategory=computer)(objectClass=computer)))"
)
AD_GROUP_FILTER = "(|(objectClass=group)(objectClass=trustedDomain))"
AD_USER_ATTRIBUTES = (
    "distinguishedName",
    "displayName",
    "sAMAccountName",
    "name",
    "objectClass",
    "objectSid",
    "primaryGroupID",
    "servicePrincipalName",
    "msDS-AllowedToDelegateTo",
    "dNSHostName",
)
AD_GROUP_ATTRIBUTES = (
    "distinguishedName",
    "cn",
    "name",
    "member",
    "objectClass",
    "objectSid",
    "managedBy",
    "trustPartner",
    "flatName",
    "trustDirection",
    "trustType",
    "trustAttributes",
)

_PRIVILEGED_DOMAIN_RIDS: dict[int, str] = {
    512: "Domain Admins",
    518: "Schema Admins",
    519: "Enterprise Admins",
    520: "Group Policy Creator Owners",
    526: "Key Admins",
    527: "Enterprise Key Admins",
}
_PRIVILEGED_BUILTIN_RIDS: dict[int, str] = {
    544: "Administrators",
    548: "Account Operators",
    549: "Server Operators",
    550: "Print Operators",
    551: "Backup Operators",
}


def _required_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{field} must be a nonblank, trimmed string")
    return value


@dataclass(frozen=True)
class ActiveDirectoryProviderLimits:
    """Hard provider-side ceilings in addition to request-level limits."""

    page_size: int = 250
    max_pages: int = 16
    max_relationships: int = 5_000
    max_trusts: int = 64
    search_time_limit_seconds: int = 10
    max_runtime_seconds: float = 30.0

    def __post_init__(self) -> None:
        if type(self.page_size) is not int or self.page_size < 1:
            raise ValueError("page_size must be a positive integer")
        if type(self.max_pages) is not int or self.max_pages < 1:
            raise ValueError("max_pages must be a positive integer")
        if type(self.max_relationships) is not int or self.max_relationships < 1:
            raise ValueError("max_relationships must be a positive integer")
        if type(self.max_trusts) is not int or self.max_trusts < 1:
            raise ValueError("max_trusts must be a positive integer")
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
    referral_count: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.entries, tuple) or any(
            not isinstance(item, Mapping) for item in self.entries
        ):
            raise ValueError("LDAP page entries must be a tuple of mappings")
        if not isinstance(self.cookie, (bytes, str, type(None))):
            raise ValueError("LDAP page cookie has an unsupported type")
        if type(self.referral_count) is not int or self.referral_count < 0:
            raise ValueError("LDAP page referral_count must be a nonnegative integer")


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
        connection = None
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
        except Exception:
            if connection is not None:
                try:
                    connection.unbind()
                except Exception:
                    pass
            raise
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

        response_items = connection.response
        if not isinstance(response_items, (list, tuple)):
            raise RuntimeError("LDAP search response has an unsupported shape")
        response = tuple(
            dict(item)
            for item in response_items
            if isinstance(item, Mapping) and item.get("type") == "searchResEntry"
        )
        referral_count = sum(
            1
            for item in response_items
            if isinstance(item, Mapping) and item.get("type") == "searchResRef"
        )
        return LdapSearchPage(
            entries=response,
            cookie=self._page_cookie(connection.result),
            referral_count=referral_count,
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


def _attribute_values(
    attributes: Mapping[str, object],
    name: str,
) -> tuple[str, ...]:
    value = attributes.get(name)
    if value in (None, ""):
        return ()
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, (list, tuple)):
        values = tuple(value)
    else:
        raise ValueError(f"LDAP {name} attribute has an unsupported type")

    normalized: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"LDAP {name} values must be nonblank strings")
        normalized.append(item.strip())
    return tuple(normalized)


def _attribute_int(attributes: Mapping[str, object], name: str) -> int | None:
    value = attributes.get(name)
    if value in (None, ""):
        return None
    if isinstance(value, (list, tuple)):
        if len(value) != 1:
            raise ValueError(f"LDAP {name} must contain one integer value")
        value = value[0]
    if isinstance(value, bool):
        raise ValueError(f"LDAP {name} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise ValueError(f"LDAP {name} must be an integer")


def _sid_text(value: object) -> str:
    if isinstance(value, (list, tuple)):
        if len(value) != 1:
            raise ValueError("LDAP objectSid must contain one value")
        value = value[0]
    if isinstance(value, str):
        result = value.strip()
        if result.startswith("S-") and result:
            return result
        raise ValueError("LDAP objectSid string is invalid")
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        if len(raw) < 8:
            raise ValueError("LDAP objectSid binary value is too short")
        revision = raw[0]
        count = raw[1]
        expected = 8 + count * 4
        if len(raw) != expected:
            raise ValueError("LDAP objectSid binary value has invalid length")
        authority = int.from_bytes(raw[2:8], "big")
        subs = [
            int.from_bytes(raw[8 + offset:12 + offset], "little")
            for offset in range(0, count * 4, 4)
        ]
        return "S-" + "-".join(
            [str(revision), str(authority), *(str(item) for item in subs)]
        )
    raise ValueError("LDAP objectSid has an unsupported type")


def _optional_sid(attributes: Mapping[str, object]) -> str | None:
    value = attributes.get("objectSid")
    if value in (None, ""):
        return None
    return _sid_text(value)


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
        object_class_values = _attribute_values(attributes, "objectClass")
        if not object_class_values:
            raise ValueError("LDAP identity entry requires objectClass")
        object_classes = {value.casefold() for value in object_class_values}
        service_principals = _attribute_values(
            attributes,
            "servicePrincipalName",
        )

        if "computer" in object_classes:
            identity_kind = "computer"
            name = _attribute_text(
                attributes,
                "dNSHostName",
                "sAMAccountName",
                "name",
            ) or dn
        elif service_principals:
            identity_kind = "service"
            name = _attribute_text(
                attributes,
                "displayName",
                "sAMAccountName",
                "name",
            ) or dn
        else:
            identity_kind = "user"
            name = _attribute_text(
                attributes,
                "displayName",
                "sAMAccountName",
                "name",
            ) or dn

        return DirectoryEntry(dn, identity_kind, name), False

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


def _raw_attributes(raw: Mapping[str, object]) -> Mapping[str, object]:
    attributes = raw.get("attributes")
    if not isinstance(attributes, Mapping):
        raise ValueError("LDAP entry attributes must be a mapping")
    return attributes


def _is_trusted_domain(raw: Mapping[str, object]) -> bool:
    attributes = _raw_attributes(raw)
    if _attribute_text(attributes, "trustPartner"):
        return True
    try:
        classes = {
            value.casefold()
            for value in _attribute_values(attributes, "objectClass")
        }
    except ValueError:
        return False
    return "trusteddomain" in classes


def _privileged_group_semantic(sid: str) -> tuple[str, str] | None:
    try:
        rid = int(sid.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return None
    if sid.startswith("S-1-5-32-") and rid in _PRIVILEGED_BUILTIN_RIDS:
        return _PRIVILEGED_BUILTIN_RIDS[rid], str(rid)
    if not sid.startswith("S-1-5-32-") and rid in _PRIVILEGED_DOMAIN_RIDS:
        return _PRIVILEGED_DOMAIN_RIDS[rid], str(rid)
    return None


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
        entry_by_dn: dict[str, DirectoryEntry] = {}
        identity_metadata: dict[str, dict[str, object]] = {}
        group_metadata: dict[str, dict[str, object]] = {}
        trusts: list[dict[str, object]] = []
        membership_count = 0
        page_count = 0
        truncated = False
        limitations: list[str] = []

        def mark_truncated(reason: str) -> None:
            nonlocal truncated
            truncated = True
            if reason not in limitations:
                limitations.append(reason)

        def safe_sid(attributes: Mapping[str, object], description: str) -> str | None:
            try:
                return _optional_sid(attributes)
            except ValueError:
                mark_truncated(
                    f"Active Directory {description} objectSid could not be normalized; "
                    "related privilege evidence may be incomplete."
                )
                return None

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
                    if page.referral_count:
                        mark_truncated(
                            "Active Directory returned LDAP referrals; referrals were "
                            "not followed outside the configured target."
                        )

                    for raw in page.entries:
                        if kind == "group" and _is_trusted_domain(raw):
                            if len(trusts) >= self._limits.max_trusts:
                                mark_truncated(
                                    "Active Directory trusted-domain ceiling reached."
                                )
                                continue
                            attributes_map = _raw_attributes(raw)
                            partner = _attribute_text(
                                attributes_map,
                                "trustPartner",
                                "flatName",
                            )
                            if not partner:
                                mark_truncated(
                                    "Active Directory trusted-domain object lacked a "
                                    "usable trust partner; relationship omitted."
                                )
                                continue
                            try:
                                direction = _attribute_int(attributes_map, "trustDirection")
                                trust_type = _attribute_int(attributes_map, "trustType")
                                trust_attributes = _attribute_int(
                                    attributes_map,
                                    "trustAttributes",
                                )
                            except ValueError:
                                mark_truncated(
                                    "Active Directory trust attributes could not be "
                                    "normalized; trust relationship omitted."
                                )
                                continue
                            trusts.append({
                                "partner": partner,
                                "direction": direction,
                                "trust_type": trust_type,
                                "trust_attributes": trust_attributes,
                            })
                            continue

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
                        entry_by_dn[normalized_dn] = entry
                        membership_count += len(entry.members)

                        attributes_map = _raw_attributes(raw)
                        if entry.kind == "group":
                            group_metadata[normalized_dn] = {
                                "sid": safe_sid(attributes_map, "group"),
                                "managed_by": _attribute_text(
                                    attributes_map,
                                    "managedBy",
                                ),
                            }
                        else:
                            try:
                                primary_group_id = _attribute_int(
                                    attributes_map,
                                    "primaryGroupID",
                                )
                            except ValueError:
                                primary_group_id = None
                                mark_truncated(
                                    "Active Directory primaryGroupID could not be "
                                    "normalized; primary-group evidence may be incomplete."
                                )
                            identity_metadata[normalized_dn] = {
                                "sid": safe_sid(attributes_map, "identity"),
                                "primary_group_id": primary_group_id,
                                "spns": _attribute_values(
                                    attributes_map,
                                    "servicePrincipalName",
                                ),
                                "delegates": _attribute_values(
                                    attributes_map,
                                    "msDS-AllowedToDelegateTo",
                                ),
                            }

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

        relationships: dict[
            tuple[GraphNodeKind, str, GraphNodeKind, str, str],
            IdentityRelationshipEvidence,
        ] = {}
        supplemental_memberships: dict[
            tuple[GraphNodeKind, str, str],
            GroupMembershipEvidence,
        ] = {}
        roles: dict[str, RoleEvidence] = {}
        domain_identities: dict[str, IdentityEvidence] = {}

        def principal_reference(dn: str) -> tuple[GraphNodeKind, str] | None:
            entry = entry_by_dn.get(dn.casefold())
            if entry is None:
                return None
            if entry.kind == "group":
                return (
                    GraphNodeKind.GROUP,
                    directory_natural_key(
                        "group",
                        entry.distinguished_name,
                        namespace="ad",
                    ),
                )
            return (
                GraphNodeKind.IDENTITY,
                directory_natural_key(
                    entry.kind,
                    entry.distinguished_name,
                    namespace="ad",
                ),
            )

        def add_relationship(item: IdentityRelationshipEvidence) -> None:
            key = (
                item.source_kind,
                item.source_key,
                item.target_kind,
                item.target_key,
                item.relationship,
            )
            if key in relationships:
                return
            if len(relationships) >= self._limits.max_relationships:
                mark_truncated("Active Directory relationship ceiling reached.")
                return
            relationships[key] = item

        group_by_sid: dict[str, DirectoryEntry] = {}
        for dn, metadata in group_metadata.items():
            group = entry_by_dn[dn]
            sid = metadata.get("sid")
            if isinstance(sid, str):
                group_by_sid[sid] = group
                semantic = _privileged_group_semantic(sid)
                if semantic is not None:
                    label, rid = semantic
                    role_key = directory_natural_key(
                        "role",
                        f"privileged-group:{sid}",
                        namespace="ad",
                    )
                    roles.setdefault(
                        role_key,
                        RoleEvidence(
                            natural_key=role_key,
                            label=label,
                            source_id=f"{request.source_id}#privileged-group",
                            properties=(
                                ("category", "well-known-ad-privileged-group"),
                                ("rid", rid),
                            ),
                        ),
                    )
                    add_relationship(IdentityRelationshipEvidence(
                        source_kind=GraphNodeKind.GROUP,
                        source_key=directory_natural_key(
                            "group",
                            group.distinguished_name,
                            namespace="ad",
                        ),
                        target_kind=GraphNodeKind.PERMISSION,
                        target_key=role_key,
                        relationship="assigned-role",
                        source_id=f"{request.source_id}#privileged-group",
                        properties=(("rid", rid),),
                    ))

            managed_by = metadata.get("managed_by")
            if isinstance(managed_by, str) and managed_by:
                manager = principal_reference(managed_by)
                if manager is None:
                    mark_truncated(
                        "Active Directory managedBy referenced a principal absent "
                        "from the bounded identity collection; relationship omitted."
                    )
                else:
                    source_kind, source_key = manager
                    target_key = directory_natural_key(
                        "group",
                        group.distinguished_name,
                        namespace="ad",
                    )
                    if (
                        source_kind is GraphNodeKind.GROUP
                        and source_key == target_key
                    ):
                        mark_truncated(
                            "Active Directory managedBy resolved to the same group; "
                            "self-management relationship omitted."
                        )
                    else:
                        add_relationship(IdentityRelationshipEvidence(
                            source_kind=source_kind,
                            source_key=source_key,
                            target_kind=GraphNodeKind.GROUP,
                            target_key=target_key,
                            relationship="manages",
                            source_id=f"{request.source_id}#managed-by",
                        ))

        explicit_memberships = {
            (member.casefold(), group.distinguished_name.casefold())
            for group in entries
            if group.kind == "group"
            for member in group.members
        }
        supplemental_membership_count = 0
        for dn, metadata in identity_metadata.items():
            entry = entry_by_dn[dn]
            sid = metadata.get("sid")
            primary_group_id = metadata.get("primary_group_id")
            if not isinstance(sid, str) or not isinstance(primary_group_id, int):
                continue
            try:
                domain_sid = sid.rsplit("-", 1)[0]
            except (AttributeError, IndexError):
                continue
            group = group_by_sid.get(f"{domain_sid}-{primary_group_id}")
            if group is None:
                mark_truncated(
                    "Active Directory primary group was absent from the bounded "
                    "group collection; primary-group relationship omitted."
                )
                continue
            pair = (dn, group.distinguished_name.casefold())
            if pair in explicit_memberships:
                continue
            if (
                membership_count + supplemental_membership_count
                >= request.limits.max_memberships
            ):
                mark_truncated("Active Directory membership ceiling reached.")
                break
            item = GroupMembershipEvidence(
                member_kind=GraphNodeKind.IDENTITY,
                member_key=directory_natural_key(
                    entry.kind,
                    entry.distinguished_name,
                    namespace="ad",
                ),
                group_key=directory_natural_key(
                    "group",
                    group.distinguished_name,
                    namespace="ad",
                ),
                source_id=f"{request.source_id}#primary-group",
            )
            supplemental_memberships[
                (item.member_kind, item.member_key, item.group_key)
            ] = item
            supplemental_membership_count += 1

        spn_targets: dict[str, list[DirectoryEntry]] = {}
        for dn, metadata in identity_metadata.items():
            entry = entry_by_dn[dn]
            for spn in metadata.get("spns", ()):
                if isinstance(spn, str):
                    spn_targets.setdefault(spn.casefold(), []).append(entry)

        for dn, metadata in identity_metadata.items():
            source = entry_by_dn[dn]
            source_key = directory_natural_key(
                source.kind,
                source.distinguished_name,
                namespace="ad",
            )
            for delegated_spn in metadata.get("delegates", ()):
                if not isinstance(delegated_spn, str):
                    continue
                matches = spn_targets.get(delegated_spn.casefold(), [])
                if len(matches) != 1:
                    mark_truncated(
                        "Active Directory constrained-delegation target was absent "
                        "or ambiguous in the bounded identity collection; "
                        "relationship omitted."
                    )
                    continue
                target = matches[0]
                target_key = directory_natural_key(
                    target.kind,
                    target.distinguished_name,
                    namespace="ad",
                )
                if target_key == source_key:
                    mark_truncated(
                        "Active Directory constrained-delegation target resolved "
                        "to the same identity; self-relationship omitted."
                    )
                    continue
                add_relationship(IdentityRelationshipEvidence(
                    source_kind=GraphNodeKind.IDENTITY,
                    source_key=source_key,
                    target_kind=GraphNodeKind.IDENTITY,
                    target_key=target_key,
                    relationship="delegates-to",
                    source_id=f"{request.source_id}#constrained-delegation",
                ))

        if trusts:
            current_domain_key = directory_natural_key(
                "domain",
                self._base_dn,
                namespace="ad",
            )
            domain_identities[current_domain_key] = IdentityEvidence(
                natural_key=current_domain_key,
                label=self._base_dn,
                source_id=f"{request.source_id}#domain",
                identity_type="ad-domain",
            )
            for trust in trusts:
                partner = str(trust["partner"])
                partner_key = directory_natural_key(
                    "domain",
                    partner,
                    namespace="ad",
                )
                domain_identities.setdefault(
                    partner_key,
                    IdentityEvidence(
                        natural_key=partner_key,
                        label=partner,
                        source_id=f"{request.source_id}#trusted-domain",
                        identity_type="ad-domain",
                    ),
                )
                if partner_key == current_domain_key:
                    mark_truncated(
                        "Active Directory trusted-domain object resolved to the "
                        "current domain; self-trust relationship omitted."
                    )
                    continue
                properties = tuple(
                    (name, str(value))
                    for name, value in (
                        ("trust_direction", trust.get("direction")),
                        ("trust_type", trust.get("trust_type")),
                        ("trust_attributes", trust.get("trust_attributes")),
                    )
                    if value is not None
                )
                add_relationship(IdentityRelationshipEvidence(
                    source_kind=GraphNodeKind.IDENTITY,
                    source_key=current_domain_key,
                    target_kind=GraphNodeKind.IDENTITY,
                    target_key=partner_key,
                    relationship="domain-trust",
                    source_id=f"{request.source_id}#domain-trust",
                    properties=properties,
                ))

        duration_ms = max(
            0,
            int(round((self._clock() - started) * 1_000)),
        )
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
            duration_ms=duration_ms,
            limitations=tuple(limitations),
            supplemental_evidence=IdentityEvidenceBundle(
                identities=tuple(sorted(
                    domain_identities.values(),
                    key=lambda item: item.natural_key,
                )),
                memberships=tuple(sorted(
                    supplemental_memberships.values(),
                    key=lambda item: (
                        item.group_key,
                        item.member_kind.value,
                        item.member_key,
                    ),
                )),
                roles=tuple(sorted(
                    roles.values(),
                    key=lambda item: item.natural_key,
                )),
                relationships=tuple(sorted(
                    relationships.values(),
                    key=lambda item: (
                        item.relationship,
                        item.source_kind.value,
                        item.source_key,
                        item.target_kind.value,
                        item.target_key,
                    ),
                )),
            ),
        )
