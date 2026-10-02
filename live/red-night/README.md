# Red Night Live deployment

This directory is the source-controlled Red Night v0.44 Live USB deployment
layer. It builds a Debian 13 (trixie) amd64 hybrid ISO around the same
`nightrecon-shared-core`, `nightrecon-red-engine`, and
`nightrecon-red-night` wheel artifacts used by normal Red installations.

Red Night Live does not fork Red assessment, authorization, evidence,
validation, reporting, cleanup, or retest logic.

## Current verified architecture

- x86-64 / amd64 UEFI hybrid ISO built with source-controlled `live-build`
  inputs;
- VM UEFI userspace boot smoke with networking disabled;
- privileged Red appliance with explicit Secure Workspace, Ephemeral Session,
  and Recovery & Integrity modes;
- no workspace mode grants target authorization;
- explicit LUKS2 Secure Workspace selection and guarded first-use provisioning;
- encrypted workspace reopen/reboot continuity;
- Ephemeral Session cleanup and proof that encrypted workspace state is not
  modified;
- safe removal/reattach, interrupted-session recovery, and read-only ext4
  integrity evidence;
- no automatic host-disk discovery or target selection.

## Release integrity

The build stages exactly one wheel for each mandatory Red distribution and
creates immutable release metadata before image construction:

- `/opt/nightrecon/release/artifacts/` — exact shared-core, Red engine, and
  Red application wheels;
- `/opt/nightrecon/release/package-manifest.json` — wheel identities, versions,
  sizes, roles, and SHA-256 digests;
- `/opt/nightrecon/release/SBOM.json` — deterministic secret-free Red package
  SBOM.

The image installation hook verifies this metadata after installing the wheels.
The UEFI boot smoke verifies the immutable release directory again before
emitting `RED_NIGHT_LIVE_BOOT_OK`.

The build also emits external sidecars beside the ISO:

- `<image>.sha256`;
- `<image>.package-manifest.json`;
- `<image>.SBOM.json`;
- `<image>.manifest.json`.

The outer image manifest binds the ISO digest and size, package-manifest digest,
SBOM digest, release version, source revision, OS/architecture, and an explicit
Secure Boot status. CI records Secure Boot as `not-verified`; UEFI boot under
OVMF is not presented as Secure Boot evidence.

## Build inputs

Prepare exactly one matching-version wheel for each required Red distribution:

```bash
mkdir -p live/red-night/.wheelhouse
python -m pip wheel --no-deps \
  --wheel-dir live/red-night/.wheelhouse \
  ./packages/shared-core ./packages/red-engine ./packages/red-night
```

Mixed Red package versions fail closed during release metadata staging.

## Build the image

```bash
sudo env \
  NIGHTRECON_SOURCE_REVISION="$(git rev-parse HEAD)" \
  NIGHTRECON_RELEASE_VERSION="0.44.0-dev" \
  ./live/red-night/build-image.sh \
  --wheel-dir "$PWD/live/red-night/.wheelhouse" \
  --output "$PWD/RedNight-Live-v0.44.0-dev-amd64.iso"
```

The release version identifies the deployment train; the three coordinated Red
Python distribution versions remain the stable functional baseline until
release finalization deliberately changes them.

## UEFI VM boot smoke

```bash
./live/red-night/ci/uefi_boot_smoke.sh \
  ./RedNight-Live-v0.44.0-dev-amd64.iso
```

The smoke boots with UEFI firmware, TCG emulation, and no virtual NIC. It proves
the image reaches userspace, the privileged appliance is active, deployment
contracts are valid, and embedded release artifacts are intact.

## Updates and recovery

Signed offline update verification, package/schema compatibility, and bounded
rollback planning are application contracts. An update plan cannot be created
unless the signed bundle, compatibility, locked encrypted workspace, and
rollback artifact have all been verified. Planning has
`authorization_effect: none` and does not itself mutate the system.

## Gates that remain physical/manual

CI does not claim the following:

- Secure Boot on the intended production signing chain;
- representative physical hardware compatibility;
- USB/media endurance;
- Red+White Live composition before White Live has independently passed its own
  deployment/persistence acceptance.

Those results must be recorded from real qualification evidence rather than
inferred from VM CI.
