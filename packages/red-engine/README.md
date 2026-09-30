# NightRecon Red Engine

`nightrecon-red-engine` is the canonical engine distribution for Red Night.

The stable v0.43.0 package owns the `nightrecon_red_engine` namespace and is
used directly by the standalone Red Night application. The legacy
`nightrecon` package keeps thin compatibility aliases during the migration
window; canonical Red implementations live in this package.

The engine includes Red-owned discovery, web/API, credentialed-infrastructure,
assessment/check, identity, graph, validation, planning, remediation/retest,
cloud/hybrid, and operator components.

v0.43 retains the v0.42 cross-domain exposure foundation and adds:

- reviewed metadata-only controlled-validation technique registry
- exact candidate-to-technique eligibility and immutable adapter contracts
- explicit operator-selected isolated revocable workers for bounded read-only proofs
- durable validation and explicit no-op cleanup evidence with deterministic retest linkage
- reviewed ATT&CK relationship metadata with explicit non-equivalence semantics
- deterministic controlled-validation comparison/runtime gates with explicit non-parity interpretation

The engine does not depend on the legacy `nightrecon` distribution. Its
mandatory application-level dependency direction is:

`Red Night application -> nightrecon-red-engine -> nightrecon-shared-core`

Optional extras expose existing bounded runtime integrations such as browser,
API/YAML, Active Directory/ldap3, SSH, SMB, WinRM, PostgreSQL, and MySQL.

Red Night remains authorization-first. v0.43 permits only the reviewed bounded
TCP, TLS-fingerprint, and HTTP HEAD proof adapters behind explicit selection,
scope, capability, budget, approval, revocation, worker-isolation, evidence, and
cleanup controls. It does not add arbitrary command execution, credential
harvesting, directory/cloud writes, persistence, privilege changes, exploit
payloads, or autonomous exploitation.
