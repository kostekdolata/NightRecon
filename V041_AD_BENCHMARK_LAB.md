# v0.41.0 Active Directory Benchmark Lab

Red Night's v0.41 identity work includes a deterministic, no-network benchmark
for the read-only Active Directory provider.

The benchmark measures evidence collection quality. It does **not** score risk,
exploitability, operator skill, or overall product superiority.

## What is measured

For one explicit expected identity topology, the benchmark records:

- expected identities discovered
- expected groups discovered
- expected membership relationships discovered
- expected role/privilege semantics discovered
- expected management, delegation, and trust relationships discovered
- missed identities, groups, memberships, roles, and relationships
- unexpected/invented identities, groups, memberships, roles, and relationships
- unresolved membership references
- provider request/page count
- provider runtime in milliseconds
- provider truncation state and limitations
- deterministic normalized graph SHA-256
- deterministic benchmark SHA-256

The benchmark fingerprint excludes provider runtime because runtime varies across
machines and runs. It includes the expected and observed opaque natural keys,
relationship topology, request count, completeness metadata, and normalized
graph fingerprint.

## Privacy boundary

Benchmark output is label-free. It contains counts, booleans, limitations, and
hashes only. Raw Active Directory DNs and human-readable user/group labels are
not emitted by the benchmark result.

## Deterministic CI fixture

`tests/ad_identity_benchmark_runtime.py` exercises the complete pipeline:

1. an active authorized engagement with `identity.collect`
2. the concrete Active Directory provider
3. a no-network fixed LDAP transport fixture
4. identity normalization
5. graph projection
6. benchmark comparison

The fixture models:

- 1 regular user identity
- 1 service identity
- 1 computer identity
- 2 directory groups
- 2 domain identities used by one trust observation
- 4 observed memberships, including 3 primary-group relationships
- 1 selected privileged-group role semantic
- 1 group-management relationship
- 1 constrained-delegation relationship
- 1 domain-trust relationship
- 2 LDAP page requests

Its acceptance conditions are:

- 0 missed identities
- 0 missed groups
- 0 missed memberships
- 0 missed roles
- 0 missed management/delegation/trust relationships
- 0 invented memberships
- 0 invented relationships
- no unexpected evidence
- no unresolved references
- no truncation
- 64-character graph and benchmark SHA-256 fingerprints
- no user/service/computer label or raw DN in serialized benchmark output

The same fixture runs in CI on Python 3.11 and Python 3.14 through the existing
optional Active Directory dependency job.

## Incomplete collection cases

Unit coverage also verifies that benchmark results preserve and explain:

- provider page/runtime/entry/membership truncation
- unresolved directory references
- missed expected topology
- unexpected/invented topology

When expected evidence is missing and the provider supplies no explicit
limitation, the benchmark records that the expected evidence was absent without
a provider-reported truncation reason rather than inventing an explanation.

## Current limitation

This is a deterministic provider-quality baseline, not yet a live-domain
comparison against external specialist products. Live authorized lab work will
be added separately once reproducible test infrastructure is available.

The deterministic fixture now covers user, service, computer, group, primary
group, selected privileged-group semantics, management, constrained delegation,
and domain-trust normalization.

This remains a deterministic provider-quality baseline rather than a live
specialist-tool comparison. Broader ACL/security-descriptor relationship
coverage and external lab comparisons remain open work.
