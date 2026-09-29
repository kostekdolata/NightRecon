# Red Night v0.41.0 Release Notes

Red Night v0.41.0 is the Live Identity Intelligence release.

It builds on the stable v0.40 product boundary and turns the previous
authorization-first identity contract into concrete, separately packaged
Active Directory and Microsoft Entra workflows.

## Delivered

### Concrete Active Directory intelligence

- certificate-validating LDAPS or LDAP+StartTLS transport
- fixed read-only LDAP collection plan with no arbitrary filter/attribute shell
- regular user, computer, service, and group identities
- direct/nested and primary-group membership evidence
- bounded membership-path review
- selected well-known privileged-group semantics derived from SID/RID evidence
- observed `managedBy` relationships
- constrained-delegation target relationships resolved through observed SPNs
- neutral domain-trust relationships retaining trust direction/type/attributes
- explicit incomplete-evidence handling for ranged, missing, ambiguous,
  redirected, self-referential, or over-budget observations

### Concrete Microsoft Entra intelligence

- fixed Microsoft Graph v1.0 read-only collection plan
- HTTPS-only fixed Graph host with redirects disabled
- users, groups, application registrations, and service principals
- direct group membership evidence
- application/service-principal ownership
- directory role definitions and scoped role assignments
- distinct permission nodes for identical roles assigned at different scopes
- validated Graph paging and hard request/page/object/runtime ceilings
- explicit Graph v1.0 service-principal-membership completeness limitation

### Operator workflow

- `red-night-app identity collect ad`
- `red-night-app identity collect entra`
- existing shared-core engagement authorization remains authoritative
- denied/out-of-scope collections make zero provider calls
- allowed live collection consumes the engagement action budget exactly once
- credentials are resolved lazily from named environment variables
- default stdout/report output is identity-label/secret safe
- detailed graph labels require an explicit graph export
- deterministic graph SHA-256 fingerprints are exposed in the safe summary

### Evidence and graph

- separate `ad:*` and `entra:*` natural-key namespaces
- user, service, computer, application, group, role/permission, and domain nodes
- observed membership, ownership, management, delegation, role, and trust edges
- provenance and observed-vs-inferred semantics preserved
- missing relationship endpoints remain missing instead of being invented
- relationship evidence never becomes an automatic exploitability verdict

### Deterministic benchmark coverage

The CI identity labs are network-free and credential-free while exercising the
production authorization, provider, normalization, graph, and benchmark
boundaries.

The Active Directory fixture covers users, service/computer identities, groups,
primary-group evidence, a selected privileged-group semantic, management,
constrained delegation, and one domain trust.

The Entra fixture covers a user, service principal, application registration,
group memberships, application/service-principal ownership, and a scoped
directory-role assignment.

Both benchmark paths run under Python 3.11 and Python 3.14.

## Versioning and compatibility

The stable Red distributions are:

- `nightrecon-red-night==0.41.0`
- `nightrecon-red-engine==0.41.0`
- `nightrecon-shared-core==0.41.0`

The legacy `nightrecon` compatibility package remains at 0.31.0 by design
while the migration window is open. It pins the matching 0.41 Red engine and
shared core.

Legacy `nightrecon.<module>` compatibility aliases remain for migrated Red
engine modules. The standalone Red application itself does not require the
legacy package.

## Safety boundary

v0.41 is a read-only identity-intelligence release.

It does not add:

- arbitrary LDAP or Microsoft Graph query execution
- password spraying or guessing
- credential harvesting
- DCSync or replication abuse
- Kerberos ticket theft/forging
- directory or cloud writes
- ownership or role mutation
- ACL/security-descriptor mutation
- persistence
- lateral movement
- autonomous exploitation

All live collection remains subject to explicit engagement scope, validity
windows, capability allowlists, action budgets, approvals where configured,
revocation, and audit.

## Known open completion gates

v0.41 does not claim universal parity with BloodHound or another specialist
identity product.

Open Red completion work includes:

- live authorized identity comparison labs with measured coverage, false
  positives, runtime, operator steps, and incomplete-evidence behavior
- broader read-only ACL/security-descriptor relationship coverage where it can
  remain bounded and evidence-honest
- broader discovery/performance comparison baselines
- professional reporting/collaboration workflows
- reviewed controlled-validation technique coverage
- continued reduction of legacy compatibility seams

See `RED_ACCEPTANCE.md` for the broader measurable completion standard and
`V041_RELEASE_ACCEPTANCE.md` for the v0.41 release-specific verification
record.
