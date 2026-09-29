# NightRecon Red Engine

`nightrecon-red-engine` is the canonical engine distribution for Red Night.

The stable v0.42.0 package owns the `nightrecon_red_engine` namespace and is
used directly by the standalone Red Night application. The legacy
`nightrecon` package keeps thin compatibility aliases during the migration
window; canonical Red implementations live in this package.

The engine includes Red-owned discovery, web/API, credentialed-infrastructure,
assessment/check, identity, graph, validation, planning, remediation/retest,
cloud/hybrid, and operator components.

v0.42 retains the concrete authorization-first identity layer and adds:

- bounded deterministic cross-domain attack-path atlas
- exact AD/network, web/API/network, cloud/network, and Azure/Entra correlation
- proposal-only validation candidate compilation
- unified evidence-gap and remediation/retest exposure review
- descriptive structural concentration and path-set comparison
- reproducible comparison/runtime gates with explicit non-parity interpretation

The engine does not depend on the legacy `nightrecon` distribution. Its
mandatory application-level dependency direction is:

`Red Night application -> nightrecon-red-engine -> nightrecon-shared-core`

Optional extras expose existing bounded runtime integrations such as browser,
API/YAML, Active Directory/ldap3, SSH, SMB, WinRM, PostgreSQL, and MySQL.

Red Night remains authorization-first. v0.42 does not add arbitrary command
execution, credential harvesting, directory/cloud writes, persistence,
privilege changes, or autonomous exploitation.
