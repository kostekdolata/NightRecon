# Red Night application distribution (development preview)

This separately built package supplies the `red-night-app` command. It uses
the dedicated Red engine package for the existing Red assessment engines and the
separate shared-core package for common authorization and cross-Night
foundations. It does not install future White, Blue, Purple, or
Black Night applications.

Run `red-night-app --help` to see the commands supported by the existing
fail-closed Red gateway.

The existing NightRecon assessment modules are treated as Red-owned
capabilities. Separation work must package or move those proven implementations,
not copy or rebuild them. See `RED_OWNERSHIP.md` for ownership and
`RED_PACKAGE_PLAN.md` for the dependency-removal sequence.

## Standalone runtime boundary

The Red app no longer depends on `nightrecon==0.31.0`. Its runtime boundary is
`nightrecon-red-engine` plus shared core and the declared base/optional
dependencies. The legacy root package remains compatible but optional.

The Red package now declares the existing direct runtime requirement
`cryptography` and mirrors the established optional extras:

- `browser`
- `api`
- `ssh`
- `smb`
- `winrm`
- `postgres`
- `mysql`
- `all`

These extras expose existing functionality; they do not add new assessment
features.

Dedicated package separation and compatibility migration remain development
work. This preview is not a completed Red Night release.


## Red engine namespace skeleton

The separate `nightrecon-red-engine` distribution owns the
`nightrecon_red_engine` namespace. The Red app depends directly on that engine
package. Existing engine modules were moved in dependency-coherent batches; they
were not copied or rebuilt. See `RED_PACKAGE_NAMESPACE.md`.


## Direct Red engine runtime

The application entrypoint calls `nightrecon_red_engine.red_cli` directly.
The isolated distribution matrix verifies that the app runs with no legacy
`nightrecon` package installed, while combined installs preserve compatibility
aliases and legacy console behavior.
