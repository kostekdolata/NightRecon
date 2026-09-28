"""Runtime compatibility smoke for the optional ldap3 Active Directory extra."""

from __future__ import annotations

import importlib.metadata

from nightrecon_red_engine.active_directory_provider import (
    AD_GROUP_ATTRIBUTES,
    AD_GROUP_FILTER,
    AD_USER_ATTRIBUTES,
    AD_USER_FILTER,
    Ldap3ActiveDirectoryTransport,
)


def main() -> None:
    import ldap3
    from ldap3 import Connection, Server, SUBTREE, Tls

    version = importlib.metadata.version("ldap3")
    assert version
    assert ldap3.__name__ == "ldap3"
    assert Connection is not None
    assert Server is not None
    assert Tls is not None
    assert SUBTREE is not None

    transport = Ldap3ActiveDirectoryTransport(
        host="dc.example.test",
        bind_username="EXAMPLE\\reader",
        secret_resolver=lambda: "runtime-only-secret",
    )
    assert transport.target == "dc.example.test"
    assert "runtime-only-secret" not in repr(transport)
    assert AD_USER_FILTER.startswith("(|")
    assert AD_GROUP_FILTER == "(objectClass=group)"
    assert "distinguishedName" in AD_USER_ATTRIBUTES
    assert "objectClass" in AD_USER_ATTRIBUTES
    assert "servicePrincipalName" in AD_USER_ATTRIBUTES
    assert "dNSHostName" in AD_USER_ATTRIBUTES
    assert "member" in AD_GROUP_ATTRIBUTES

    print(f"ldap3 Active Directory runtime compatibility: passed ({version})")


if __name__ == "__main__":
    main()
