# v0.41.0 Microsoft Entra Identity Provider

Red Night v0.41 development now includes a concrete, authorization-first,
read-only Microsoft Entra provider behind the existing v0.34 identity
collection contract.

## Current provider scope

The provider performs a fixed Microsoft Graph v1.0 collection plan for:

- Entra users
- Entra groups
- service principals
- direct group-membership relationships returned by Microsoft Graph

The provider does not expose an operator-supplied Graph URL, OData filter,
search expression, arbitrary projection, or Graph version selector.

The fixed Graph projections are:

- `/v1.0/users?$select=id,displayName,userPrincipalName&$top=100`
- `/v1.0/groups?$select=id,displayName&$top=100`
- `/v1.0/servicePrincipals?$select=id,displayName,appId&$top=100`
- `/v1.0/groups/{id}/members?$select=id,displayName,userPrincipalName,appId&$top=100`

Only validated `@odata.nextLink` paging URLs on
`https://graph.microsoft.com/v1.0/` are accepted. Redirecting paging to
another host, switching to `/beta`, adding arbitrary fields, or adding
arbitrary query parameters is rejected before access-token resolution.

## Authorization boundary

The shared engagement workspace authorizes the `identity.collect` capability
for the configured Entra tenant before the provider is called. Denied,
expired, revoked, or out-of-scope requests therefore make zero Microsoft Graph
page calls.

The provider also requires the request target to match the configured tenant ID
or tenant identifier exactly.

## Credential boundary

The concrete Microsoft Graph transport receives an access-token resolver rather
than a persisted token.

The token is resolved only when an authorized Graph page request executes. The
token value is used only in the HTTP Authorization header and is not copied into
evidence, reports, benchmark output, object representations, or error text.

## Graph transport boundary

The concrete transport is restricted to:

- HTTPS
- `graph.microsoft.com`
- Microsoft Graph `v1.0`
- the fixed identity collection paths above
- fixed `$select` projections
- `$top=100`
- Graph-provided `$skiptoken` paging only

The transport rejects:

- HTTP
- alternate hosts
- alternate ports
- `/beta`
- arbitrary Graph resources
- arbitrary `$filter`, `$search`, `$expand`, or other OData controls
- arbitrary field projections
- scope-escaping `@odata.nextLink` URLs

## Hard ceilings

Provider defaults are deliberately finite:

- maximum Graph requests: 64
- maximum pages per collection: 10
- maximum groups receiving membership reads: 32
- total provider runtime ceiling: 30 seconds

The shared identity request additionally limits:

- normalized entries: 1,000
- observed memberships: 5,000
- normalized serialized evidence: 1 MB

Results retain provider request count, runtime, truncation state, unresolved
references, and explicit limitations.

## Evidence normalization

Provider-native object IDs are transformed into opaque normalized natural keys
under a dedicated Entra namespace.

Current identity mappings are:

- user -> `entra-user`
- service principal -> `entra-service`
- group -> Entra group evidence

This namespace is intentionally distinct from the on-premises Active Directory
`ad-*` namespace, so the same textual identifier cannot silently collide
across identity sources.

## Microsoft Graph v1.0 membership limitation

Microsoft documents a current v1.0 limitation where the group-members endpoint
can omit service principals. Red Night therefore records an explicit
completeness limitation whenever group memberships are collected rather than
claiming exhaustive service-principal membership coverage.

The provider can normalize service-principal membership if Graph returns it, but
it does not infer missing relationships.

## Deterministic benchmark

`tests/entra_identity_benchmark_runtime.py` exercises the complete no-network
pipeline:

1. authorized tenant engagement
2. concrete Entra provider
3. fixed fake Graph transport
4. Entra namespace normalization
5. graph projection
6. deterministic benchmark comparison

The fixture currently models:

- 1 user
- 1 service principal
- 1 group
- 2 direct memberships
- 4 Graph page requests

It runs in CI on Python 3.11 and Python 3.14 without Microsoft credentials or
network access.

## Current non-goals

This batch does not implement:

- directory writes
- password operations
- credential harvesting
- arbitrary Graph queries
- application ownership relationships
- directory-role assignment relationships
- OAuth consent or permission modification
- persistence
- lateral movement
- autonomous exploitation

Application ownership, selected role relationships, and broader hybrid identity
correlation remain subsequent v0.41 work.
