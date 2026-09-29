# v0.34.0 Live Identity Intelligence

Red Night v0.34 introduces the authorization-first identity collection runtime.

The runtime is read-only by contract. A provider adapter receives a bounded
IdentityCollectionRequest only after the engagement workspace authorizes the
`identity.collect` capability for the requested target. Denied requests never
call the provider. Returned identities, groups, and memberships are normalized
through the existing directory evidence bridge, retaining provenance and
unresolved-reference accounting.

This milestone intentionally does not implement credential harvesting,
directory writes, persistence, lateral movement, password operations, or an
unrestricted LDAP/Graph client.

v0.41 development now adds the first concrete adapter behind this boundary: a
bounded read-only Active Directory provider using encrypted LDAP transport,
fixed filters and attributes, explicit truncation metadata, user/computer/
service identity classification, and zero provider calls when engagement
authorization fails. See
[V041_ACTIVE_DIRECTORY_PROVIDER.md](V041_ACTIVE_DIRECTORY_PROVIDER.md).

v0.41 also adds a bounded read-only Microsoft Entra provider using fixed
Microsoft Graph v1.0 identity endpoints, dedicated Entra evidence namespacing,
strict next-link validation, explicit request/runtime ceilings, and zero Graph
calls when engagement authorization fails. See
[V041_ENTRA_PROVIDER.md](V041_ENTRA_PROVIDER.md).
