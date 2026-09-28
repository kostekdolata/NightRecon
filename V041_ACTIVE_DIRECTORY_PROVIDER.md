# v0.41.0 Active Directory Provider

Red Night v0.41 development now includes a concrete, authorization-first,
read-only Active Directory provider behind the existing v0.34 identity
collection contract.

## Current provider scope

The provider performs a fixed collection plan for:

- regular directory users
- computer identities
- SPN-bearing user-derived service identities
- directory groups
- observed direct and nested group-membership evidence returned by Active Directory

It does not accept an operator-supplied LDAP filter or arbitrary attribute
list. The fixed identity query includes non-computer `user` objects plus
computer objects. Returned object classes are used locally to identify
computers; a non-computer user-derived object with one or more
`servicePrincipalName` values is classified as a service identity. SPN values
are used only for classification and are not copied into normalized identity
evidence.

The provider normalizes observations through the existing identity collection
and graph evidence pipeline as `ad-user`, `ad-computer`, or `ad-service`
identities.

## Authorization boundary

The shared engagement workspace authorizes the `identity.collect` capability
for the requested directory target before the provider is called. Denied,
expired, revoked, out-of-scope, or otherwise unauthorized requests therefore
make zero LDAP page requests.

The provider also requires its configured directory-controller target to match
the authorized request target.

## Transport safety

The optional `ad` package extra installs ldap3. The concrete transport supports
only:

- LDAPS
- LDAP upgraded with StartTLS

TLS server certificates are required to validate. LDAP referrals are disabled,
so a directory response cannot silently redirect collection to another host.
Bind secrets are obtained from a caller-supplied resolver only when an
authorized collection executes; secret values are not added to evidence,
reports, provider metadata, or object representations.

## Hard ceilings

Provider defaults are deliberately finite:

- page size: 250 entries
- maximum LDAP pages: 16
- server search time limit: 10 seconds per page
- total provider runtime ceiling: 30 seconds

The existing identity request additionally limits:

- entries: 1,000
- observed memberships: 5,000
- normalized serialized evidence: 1 MB

Ceilings can be lowered by the caller. Results record provider request counts
and explicitly set `truncated` when page, runtime, entry, or membership budgets
prevent a complete result.

Active Directory ranged membership attributes are preserved when returned but
are also marked incomplete, preventing a large group from being misreported as
having no additional members.

## Current non-goals

This provider does not implement:

- password spraying, guessing, or password changes
- credential harvesting or secret persistence
- arbitrary LDAP query execution
- directory writes or privilege changes
- DCSync or replication abuse
- persistence or lateral movement
- autonomous exploitation

The deterministic provider-quality benchmark is documented in
[V041_AD_BENCHMARK_LAB.md](V041_AD_BENCHMARK_LAB.md).

Broader privilege/trust relationships, live external comparison measurements,
and the Entra provider remain later v0.41 batches.
