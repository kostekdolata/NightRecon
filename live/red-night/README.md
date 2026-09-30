# Red Night Live build skeleton

This directory contains the source-controlled Debian `live-build`
configuration for Red Night v0.44 Batch 2.

It builds an amd64 UEFI ISO from the same versioned Python distributions used by
the normal standalone product:

- `nightrecon-shared-core`
- `nightrecon-red-engine`
- `nightrecon-red-night`

The builder creates those wheels from the repository, stages them into the Live
image, and installs them into `/opt/nightrecon/venv` from the embedded
wheelhouse with `--no-index`. The Live image does not copy Red Python source
directly into the runtime.

## Development image boundary

Batch 2 intentionally provides:

- Debian Trixie amd64 base;
- GRUB EFI boot path;
- ISO-hybrid output;
- Secure Boot disabled for the development gate;
- immutable Live root filesystem;
- same Red/shared-core application package artifacts as normal installation;
- a boot-time package/import smoke marker;
- no persistent engagement workspace;
- no automatic host-disk mounting;
- no application appliance UI yet;
- no automatic target authorization;
- no peer-Night runtime dependency.

Secure Boot, encrypted persistence, recovery/update signing, hardware matrix,
and full-stack Live composition are later v0.44 batches.

## Build prerequisites

The CI build runs `live-build` inside a privileged `debian:trixie`
container so the build toolchain matches the target Debian release. This avoids
the obsolete `live-build` package currently shipped by the Ubuntu hosted-runner
base image.

The Debian build environment installs:

- `live-build`
- `python3`, `python3-pip`, `python3-setuptools`, and `python3-wheel`
- `xorriso`
- `squashfs-tools`
- `dosfstools`
- `mtools`

The host independently installs `qemu-system-x86`, `ovmf`, and `xorriso`
for the UEFI boot check.

A native Debian Trixie build host can run `build.sh` directly as root or
through `sudo`.

## Build

From the repository root:

```sh
bash live/red-night/build.sh
```

Default output:

```
artifacts/live/red-night/RedNight-Live-v0.44.0-dev-amd64.iso
artifacts/live/red-night/RedNight-Live-v0.44.0-dev-amd64.iso.sha256
artifacts/live/red-night/RedNight-Live-v0.44.0-dev-amd64.manifest.json
```

The source-controlled `auto/config` pins the initial Live target to Debian
Trixie, amd64, ISO-hybrid, GRUB EFI, and development Secure Boot disabled.

## UEFI VM smoke

```sh
bash live/red-night/tests/uefi_boot_smoke.sh \
  artifacts/live/red-night/RedNight-Live-v0.44.0-dev-amd64.iso
```

The smoke boots the ISO with QEMU + OVMF and passes only after the guest emits
`RED_NIGHT_LIVE_BOOT_OK` from a hardened one-shot systemd service after
validating the installed Red deployment contract and launching
`red-night-app --help`.

The VM is started with no virtual NIC for this boot gate; boot success therefore
does not depend on network access or authorize any assessment activity.
