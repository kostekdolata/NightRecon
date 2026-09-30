# Red Night Live build skeleton

This directory is the source-controlled Red Night v0.44 Live USB build layer.

It builds a Debian 13 (trixie) amd64 hybrid ISO around the same versioned
`nightrecon-shared-core`, `nightrecon-red-engine`, and
`nightrecon-red-night` wheel artifacts used by normal Red installations.

Batch 2 is intentionally limited to image construction and boot proof:

- x86-64 / amd64 only;
- UEFI boot through GRUB EFI;
- no persistent engagement workspace yet;
- no LUKS provisioning yet;
- no automatic host-disk mounting or modification;
- no target authorization or automatic assessment activity;
- no dependency on White, Blue, Purple, or Black Night runtimes;
- runtime boot smoke is performed with VM networking disabled.

The build may use Internet access while constructing the image to resolve the
existing Red Python runtime dependencies. The resulting image must boot and
validate the installed Red deployment contract without Internet access.
Signed/offline update bundles and fully reproducible dependency mirroring are
later v0.44 production-hardening work.

## Build inputs

Prepare exactly one wheel for each required Red distribution:

- `nightrecon-shared-core`
- `nightrecon-red-engine`
- `nightrecon-red-night`

```bash
mkdir -p live/red-night/.wheelhouse
python -m pip wheel --no-deps \
  --wheel-dir live/red-night/.wheelhouse \
  ./packages/shared-core ./packages/red-engine ./packages/red-night
```

## Build the image

```bash
sudo ./live/red-night/build-image.sh \
  --wheel-dir "$PWD/live/red-night/.wheelhouse" \
  --output "$PWD/RedNight-Live-v0.44.0-dev-amd64.iso"
```

The script stages only the three required Red wheels, builds the ISO, copies it
to the requested output path, writes a SHA-256 sidecar, and removes temporary
wheel staging.

## UEFI VM boot smoke

```bash
./live/red-night/ci/uefi_boot_smoke.sh ./RedNight-Live-v0.44.0-dev-amd64.iso
```

The smoke test boots with UEFI firmware, TCG emulation, and no virtual NIC. A
one-shot systemd unit validates the installed Red deployment contract and emits
`RED_NIGHT_LIVE_BOOT_OK` to the serial console.

This marker proves the Batch 2 image reached userspace and loaded the installed
Red package contract. It is not a claim that persistence, Secure Boot, hardware
compatibility, update recovery, or later Live acceptance gates are complete.
