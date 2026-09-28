# v0.34.0 Live Identity Intelligence

Red Night v0.34 introduces the authorization-first identity collection runtime.

The runtime is read-only by contract. A provider adapter receives a bounded
IdentityCollectionRequest only after the engagement workspace authorizes the
`identity.collect` capability for the requested target. Denied requests never
call the provider. Returned users, groups, and memberships are normalized
through the existing directory evidence bridge, retaining provenance and
unresolved-reference accounting.

This milestone intentionally does not implement credential harvesting,
directory writes, persistence, lateral movement, password operations, or an
unrestricted LDAP/Graph client.

v0.41 development now adds the first concrete adapter behind this boundary: a
bounded read-only Active Directory provider using encrypted LDAP transport,
fixed filters and attributes, explicit truncation metadata, and zero provider
calls when engagement authorization fails. See
[V041_ACTIVE_DIRECTORY_PROVIDER.md](V041_ACTIVE_DIRECTORY_PROVIDER.md).
The Entra adapter remains a later v0.41 batch.
