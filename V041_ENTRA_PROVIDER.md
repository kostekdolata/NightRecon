# v0.41.0 Microsoft Entra Identity Provider

Red Night v0.41 includes a concrete, authorization-first, read-only Microsoft
Entra provider behind the existing v0.34 identity collection contract.

## Current provider scope

The provider performs a fixed Microsoft Graph v1.0 collection plan for:

- Entra users
- Entra groups
- application registrations
- service principals
- direct group memberships returned by Microsoft Graph
- owners of application registrations
- owners of service principals
- directory role definitions
- active directory role assignments

The provider does not expose an operator-supplied Graph URL, OData filter,
search expression, arbitrary projection, or Graph version selector.

The fixed Graph surfaces are:

- `/v1.0/users?$select=id,displayName,userPrincipalName&$top=100`
- `/v1.0/groups?$select=id,displayName&$top=100`
- `/v1.0/applications?$select=id,displayName,appId&$top=100`
- `/v1.0/servicePrincipals?$select=id,displayName,appId&$top=100`
- `/v1.0/groups/{id}/members?$select=id,displayName,userPrincipalName,appId&$top=100`
- `/v1.0/applications/{id}/owners`
- `/v1.0/servicePrincipals/{id}/owners`
- `/v1.0/roleManagement/directory/roleDefinitions`
- `/v1.0/roleManagement/directory/roleAssignments?$select=id,principalId,roleDefinitionId,directoryScopeId`

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
HTTP redirects are disabled so a bearer credential cannot be redirected away
from the fixed Graph host.

## Graph transport boundary

The concrete transport is restricted to:

- HTTPS
- `graph.microsoft.com`
- Microsoft Graph `v1.0`
- the fixed identity/ownership/RBAC paths above
- fixed field projections
- fixed `$top=100` where used by the approved collection plan
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

- maximum Graph requests: 96
- maximum pages per collection: 10
- maximum groups receiving membership reads: 32
- maximum application/service-principal objects receiving owner reads: 64
- maximum observed role definitions retained for assignment resolution: 256
- maximum ownership + role-assignment relationships: 5,000
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
- application registration -> `entra-application`
- service principal -> `entra-service`
- group -> Entra group evidence

Ownership is represented as an observed `owns` edge from an observed user,
group, or service identity to an observed application/service identity.

Directory role assignments are represented as observed `assigned-role` edges
to permission nodes. A permission node is keyed by both the role definition and
`directoryScopeId`, so the same principal holding the same role at two scopes
does not collapse into one graph edge.

Red Night does not infer ownership, role assignments, privilege, or
exploitability when an endpoint is absent from the bounded evidence set.

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
5. ownership and scoped role evidence
6. graph projection
7. deterministic benchmark comparison

The fixture currently models:

- 1 user
- 1 service principal
- 1 application registration
- 1 group
- 1 scoped directory role
- 2 direct group memberships
- 2 ownership relationships
- 1 directory-role assignment
- 9 Graph page requests

It runs in CI on Python 3.11 and Python 3.14 without Microsoft credentials or
network access.

## Current non-goals

This provider does not implement:

- directory writes
- password operations
- credential harvesting
- arbitrary Graph queries
- ownership modification
- directory-role assignment or removal
- OAuth consent or permission modification
- persistence
- lateral movement
- autonomous exploitation

Broader hybrid identity correlation, additional read-only relationship types,
and live external comparison measurements remain later work.

The authorization-first CLI integration is documented in
[V041_IDENTITY_OPERATOR_SURFACE.md](V041_IDENTITY_OPERATOR_SURFACE.md).
