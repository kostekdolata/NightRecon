# v0.41.0 Active Directory Provider

Red Night v0.41 includes a concrete, authorization-first, read-only Active
Directory provider behind the existing v0.34 identity collection contract.

## Current provider scope

The provider performs a fixed collection plan for:

- regular directory users
- computer identities
- SPN-bearing user-derived service identities
- directory groups
- direct and nested group membership returned by Active Directory
- primary-group membership derived from `primaryGroupID` + observed SIDs
- `managedBy` relationships where both endpoints are observed
- constrained-delegation targets from `msDS-AllowedToDelegateTo` when the target SPN maps unambiguously to an observed identity
- selected well-known privileged-group semantics derived from documented SIDs/RIDs
- `trustedDomain` configuration with trust direction, type, and attributes preserved as observed evidence

It does not accept an operator-supplied LDAP filter or arbitrary attribute
list. The fixed identity query includes non-computer `user` objects plus
computer objects. The second fixed query covers groups and `trustedDomain`
objects in the same bounded LDAP page plan.

Returned object classes are used locally to distinguish users, computers, and
SPN-bearing service identities. SPN values and raw SIDs are used only for
normalization and relationship resolution; they are not copied into ordinary
identity-safe summaries.

The provider normalizes ordinary principals as `ad-user`, `ad-computer`, or
`ad-service` identities. Domain trust endpoints are normalized as opaque
`ad-domain` identities.

## Relationship semantics

The selected v0.41 AD relationships are deliberately descriptive:

- `member-of` — direct/nested or primary-group membership
- `manages` — observed `managedBy` relationship
- `delegates-to` — configured constrained-delegation target resolved through an observed SPN
- `assigned-role` — a group mapped to a selected well-known privileged-group semantic
- `domain-trust` — observed trusted-domain configuration

These edges describe directory configuration only. They do **not** establish
that a relationship is exploitable, that a privilege path is reachable in the
current environment, or that compromise is possible.

For domain trust objects, the graph retains the numeric `trustDirection`,
`trustType`, and `trustAttributes` values as evidence. The neutral
`domain-trust` edge does not reinterpret those values as an attack direction.

The selected privileged-group semantic set is intentionally narrow and based on
well-known Microsoft SID/RID definitions, including Domain Admins, Schema
Admins, Enterprise Admins, Group Policy Creator Owners, Key Admins, Enterprise
Key Admins, and selected built-in operator/administrator groups. The provider
does not infer privilege from a localized group display name.

Microsoft reference material used for this boundary includes:

- https://learn.microsoft.com/windows-server/identity/ad-ds/manage/understand-security-groups
- https://learn.microsoft.com/windows/win32/secauthz/well-known-sids
- https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/5026a939-44ba-47b2-99cf-386a9e674b04
- https://learn.microsoft.com/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c

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
- maximum supplemental privilege/trust relationships: 5,000
- maximum trusted-domain objects: 64
- server search time limit: 10 seconds per page
- total provider runtime ceiling: 30 seconds

The existing identity request additionally limits:

- entries: 1,000
- observed memberships: 5,000
- normalized serialized base evidence: 1 MB

Ceilings can be lowered by the caller. Results record provider request counts
and explicitly set `truncated` when page, runtime, entry, membership,
relationship, trust, or endpoint-resolution budgets prevent complete evidence.

Active Directory ranged membership attributes are preserved when returned but
are also marked incomplete, preventing a large group from being misreported as
having no additional members.

Missing or ambiguous `managedBy`, primary-group, SPN delegation, trust, or
relationship endpoints are never invented. The relationship is omitted and the
collection reports an explicit limitation.

## Current non-goals

This provider does not implement:

- password spraying, guessing, or password changes
- credential harvesting or secret persistence
- arbitrary LDAP query execution
- directory writes or privilege changes
- DCSync or replication abuse
- ACL abuse or security-descriptor mutation
- Kerberos ticket theft or forging
- persistence or lateral movement
- autonomous exploitation

The deterministic provider-quality benchmark is documented in
[V041_AD_BENCHMARK_LAB.md](V041_AD_BENCHMARK_LAB.md).

The read-only Microsoft Entra provider is documented separately in
[V041_ENTRA_PROVIDER.md](V041_ENTRA_PROVIDER.md).

The authorization-first CLI integration is documented in
[V041_IDENTITY_OPERATOR_SURFACE.md](V041_IDENTITY_OPERATOR_SURFACE.md).
