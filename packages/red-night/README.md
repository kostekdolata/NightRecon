# Red Night application distribution

`nightrecon-red-night` is the independently installable Red Night application.

The stable v0.43.0 package supplies the `red-night-app` command and depends on
the matching `nightrecon-red-engine==0.43.0` and
`nightrecon-shared-core==0.43.0` distributions. It does not require the
legacy `nightrecon==0.31.0` package and it does not install future White,
Blue, Purple, or Black Night applications.

The application entry point calls `nightrecon_red_engine.red_cli` directly.
The CI distribution matrix verifies:

- isolated Red Night installation with no legacy NightRecon package
- combined Red Night + legacy compatibility installation
- independent `red-night-app` / `red-night` scripts
- Python 3.11 and 3.14 on Ubuntu and Windows

Optional extras expose the existing bounded integrations:

- `browser`
- `api`
- `ad`
- `ssh`
- `smb`
- `winrm`
- `postgres`
- `mysql`
- `all`

v0.41 includes authorization-first live Active Directory and Microsoft Entra
identity collection through `red-night-app identity collect ad` and
`red-night-app identity collect entra`. Default live identity output is
label/secret-safe; detailed graph labels require an explicit graph export.

All active operations remain subject to shared-core scope, authorization
windows, action budgets, approval requirements, revocation, and audit controls.

Red Night v0.43 adds explicitly selected Controlled Validation Intelligence for the reviewed bounded read-only proof techniques. Execution remains subject to the shared-core authorization boundary and the isolated revocable worker, durable evidence, cleanup, and retest contracts documented in `V043_CONTROLLED_VALIDATION_INTELLIGENCE.md`.
