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


## v0.44 deployment foundation

Red Night is being extended toward three deployment profiles using the same
application and engine packages:

- standalone installation;
- composed NightRecon stack;
- Red Night Live USB.

The declarative profile contract lives in `red_night_app.deployment`. It does
not create boot media and does not import any other Night runtime. See
`RED_LIVE_ARCHITECTURE.md` for the Live development gates.


### v0.44 Batch 3 appliance session

The development package also exposes `red-night-appliance` for the Live
deployment layer. The appliance controller requires an explicit workspace mode
selection and does not grant target authorization.

Current Batch 3 behavior:

- Secure Workspace is listed but refuses to start until Batch 4 provides LUKS2
  persistence;
- Ephemeral Session provides a constrained Red command prompt that invokes only
  the existing `red-night-app` command boundary, never an operating-system
  shell, from temporary runtime storage;
- Recovery & Integrity Check validates the Red deployment contract without
  launching assessment commands.

The appliance layer does not change Red engine scope, approvals, budgets,
revocation, evidence, cleanup, or worker-isolation behavior.
