# Red Night v0.41.0 Release Acceptance

This document records the release-specific acceptance boundary for Red Night
v0.41.0.

The broader Red product completion standard remains in `RED_ACCEPTANCE.md`.
Passing this release gate means the v0.41 Live Identity Intelligence milestone
is stable and internally coherent; it does not mean every Red acceptance
category or specialist comparison is complete.

## Release target

The coordinated v0.41 release consists of:

- `nightrecon-red-night==0.41.0`
- `nightrecon-red-engine==0.41.0`
- `nightrecon-shared-core==0.41.0`

The legacy `nightrecon==0.31.0` package remains a compatibility bridge and
pins the matching Red engine/shared core.

## Integrated v0.41 development train

The release incorporates the verified v0.41 identity batches:

- bounded identity membership-path review
- concrete read-only Active Directory provider
- deterministic Active Directory benchmark lab
- Active Directory computer/service identity enrichment
- concrete read-only Microsoft Entra provider
- Entra application/service-principal ownership and scoped directory-role
  relationships
- authorization-first live identity operator surface
- selected Active Directory privilege, management, constrained-delegation, and
  domain-trust relationships

Each batch was merged only after exact-head CI passed, followed by a clean
post-merge master verification before the next batch began.

## Authorization and credential acceptance

The live identity path preserves the shared engagement policy:

- target/tenant must be explicitly in engagement scope
- engagement must be active and inside its validity window
- `identity.collect` must be permitted
- action budget must remain
- explicit approval is required when configured by policy
- denied requests make zero AD/Graph provider calls
- denied requests do not consume an action
- allowed collection consumes one action

AD passwords and Entra bearer tokens are resolved lazily from named environment
variables only after authorization reaches the concrete transport.

Secret values and credential environment-variable names are excluded from
ordinary output, reports, evidence, graph fingerprints, and sanitized errors.

## Active Directory acceptance

The AD path verifies:

- LDAPS or LDAP+StartTLS only
- certificate validation required
- LDAP referrals disabled
- fixed user/computer and group/trusted-domain queries
- hard entry, membership, page, relationship, trust, response, and runtime
  ceilings
- regular user, service, computer, and group normalization
- direct/nested and primary-group membership evidence
- selected well-known privileged-group semantics
- observed `managedBy` relationships
- constrained-delegation targets resolved only through observed unambiguous SPNs
- domain-trust observations with numeric trust metadata
- missing/ambiguous/ranged/self-referential relationship evidence omitted and
  reported as incomplete

The deterministic AD benchmark requires zero missed/invented expected
relationships for its fixture and verifies label/DN-safe benchmark output.

## Microsoft Entra acceptance

The Entra path verifies:

- HTTPS only
- fixed `graph.microsoft.com` v1.0 surfaces
- redirects disabled
- no arbitrary OData filter/search/expand/projection surface
- bounded validated `@odata.nextLink` paging
- hard request, page, object, relationship, and runtime ceilings
- users, groups, applications, and service principals
- group memberships
- application/service-principal owners
- role definitions and scoped role assignments
- identical roles at different directory scopes remain distinct
- missing principals/roles are not invented
- the documented Graph v1.0 service-principal group-membership limitation is
  surfaced as a completeness limitation

The deterministic Entra benchmark verifies the full
authorization -> provider -> normalization -> graph -> benchmark path without
Microsoft credentials or external network access.

## Operator/output acceptance

The standalone Red command surface exposes:

- `identity collect ad`
- `identity collect entra`

Default live collection output contains counts, limitations, provider request
and runtime metadata, graph counts, and a deterministic graph SHA-256.

Default output does not disclose:

- identity/group/application/role labels
- raw Active Directory DNs
- Entra object IDs
- passwords or tokens
- credential environment-variable names

A detailed graph containing labels requires an explicit `--export-graph`
action.

## Distribution and quality gate

Before the stable v0.41 tag may be created:

1. coordinated 0.41 package metadata and dependency pins must pass release
   consistency tests;
2. isolated and combined Red Night wheel installations must pass on Ubuntu and
   Windows for Python 3.11 and 3.14;
3. both AD benchmark/runtime CI jobs must pass;
4. both Entra benchmark/runtime CI jobs must pass;
5. the complete NightRecon cross-platform/integration CI matrix must pass on the
   exact release-finalization head;
6. the finalization PR must merge to `master`;
7. the exact merge commit must pass the complete CI matrix again;
8. the guarded release-tag allowlist must bind `v0.41.0` to that verified
   immutable release commit;
9. the Release Tag Guard must create the annotated tag without moving any
   existing tag.

## Explicit limitations

v0.41 CI uses deterministic fake AD/Graph transports for repeatability and
secret-free testing. This does not substitute for live authorized comparison
labs.

The release does not claim that Red Night matches or exceeds BloodHound or any
other specialist product.

Broader ACL/security-descriptor modeling, live product-comparison evidence,
cross-category performance baselines, professional multi-operator reporting,
and additional controlled-validation coverage remain open acceptance work.

A graph relationship or path remains descriptive evidence and never becomes an
automatic exploitability verdict.
