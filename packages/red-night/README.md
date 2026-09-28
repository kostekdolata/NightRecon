# Red Night application distribution (development preview)

This separately built package supplies the `red-night-app` command. It currently
uses the existing NightRecon runtime for the already implemented Red assessment
engines and the separate shared-core package for common authorization and
cross-Night foundations. It does not install future White, Blue, Purple, or
Black Night applications.

Run `red-night-app --help` to see the commands supported by the existing
fail-closed Red gateway.

The existing NightRecon assessment modules are treated as Red-owned
capabilities. Separation work must package or move those proven implementations,
not copy or rebuild them. See `RED_OWNERSHIP.md` for ownership and
`RED_PACKAGE_PLAN.md` for the dependency-removal sequence.

## Current dependency bridge

The preview still depends on `nightrecon==0.31.0`. That dependency remains only
because the Red wheel is currently launcher-only and the established Red
engines/CLI still live in the root distribution.

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

The separate `nightrecon-red-engine` distribution now owns the
`nightrecon_red_engine` namespace. The Red app depends on that engine package
and temporarily on the legacy root package for the existing CLI bridge. Engine
modules are moved into the engine distribution in dependency-coherent batches;
they are not copied or rebuilt. See `RED_PACKAGE_NAMESPACE.md`.


## Direct Red engine runtime

The application entrypoint now calls `nightrecon_red_engine.red_cli` directly.
The legacy `nightrecon==0.31.0` dependency remains declared temporarily until
the isolated distribution matrix verifies that the app runs without that
package installed. Removal of that metadata bridge is the final packaging step.
