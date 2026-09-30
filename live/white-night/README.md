# White Night Live — Batch 1 build skeleton

This directory contains the first source-controlled White Night Live deployment
skeleton. It is a deployment layer for the same White Night product packages,
not a fork of White-owned application or engine behavior.

Batch 1 proves only:

- Debian live-build configuration is source controlled;
- the target is x86-64 UEFI boot;
- built nightrecon-shared-core, nightrecon-white-engine, and
  nightrecon-white-night wheel artifacts are staged into the immutable image;
- the image can boot in an offline QEMU/OVMF VM and emit a deterministic
  readiness marker.

Batch 1 deliberately does not install or auto-launch White Night, create
persistent engagement state, configure LUKS2, mount host disks, enable Secure
Boot claims, or add any target/network execution capability. Those belong to
later Live batches and remain separately gated.

## Local build

Install Debian `live-build`, QEMU x86 system emulation, and OVMF. Build the
three required wheels into a directory, then run the build script as root:

```sh
python -m pip wheel --no-deps --no-build-isolation --wheel-dir /tmp/white-wheels \
  ./packages/shared-core ./packages/white-engine ./packages/white-night

sudo env WHEEL_DIR=/tmp/white-wheels ./live/white-night/build.sh
```

The default output is:

```text
artifacts/live/white-night/WhiteNight-Live-0.1.0a6-amd64.iso
artifacts/live/white-night/WhiteNight-Live-0.1.0a6-amd64.iso.sha256
```

Verify UEFI boot without a VM network interface:

```sh
./tests/white_live_vm_smoke.sh \
  artifacts/live/white-night/WhiteNight-Live-0.1.0a6-amd64.iso
```

A passing smoke test observes `WHITE_NIGHT_LIVE_BOOT_OK` on the serial
console. That marker means the immutable image booted and the expected wheel
artifacts were present. It does not mean later White Live acceptance gates have
passed.
