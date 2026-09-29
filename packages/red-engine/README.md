# NightRecon Red Engine

`nightrecon-red-engine` is the canonical engine distribution for Red Night.

The stable v0.41.0 package owns the `nightrecon_red_engine` namespace and is
used directly by the standalone Red Night application. The legacy
`nightrecon` package keeps thin compatibility aliases during the migration
window; canonical Red implementations live in this package.

The engine includes Red-owned discovery, web/API, credentialed-infrastructure,
assessment/check, identity, graph, validation, planning, remediation/retest,
cloud/hybrid, and operator components.

v0.41 adds the concrete authorization-first identity layer:

- bounded read-only Active Directory collection over LDAPS/StartTLS
- bounded read-only Microsoft Entra collection over fixed Microsoft Graph v1.0 surfaces
- identity-safe live operator commands
- deterministic AD/Entra benchmark fixtures
- user, service, computer, application, group, role, and domain evidence
- group membership and primary-group relationships
- Entra ownership and scoped directory-role relationships
- selected AD privilege, management, constrained-delegation, and domain-trust evidence

The engine does not depend on the legacy `nightrecon` distribution. Its
mandatory application-level dependency direction is:

`Red Night application -> nightrecon-red-engine -> nightrecon-shared-core`

Optional extras expose existing bounded runtime integrations such as browser,
API/YAML, Active Directory/ldap3, SSH, SMB, WinRM, PostgreSQL, and MySQL.

Red Night remains authorization-first. v0.41 does not add arbitrary command
execution, credential harvesting, directory/cloud writes, persistence,
privilege changes, or autonomous exploitation.
