# White Night Live — Batch 2 application runtime

This directory contains the source-controlled White Night Live deployment layer.
It uses the same versioned White Night and shared-core package artifacts as a
normal standalone installation. It is not a fork of White-owned application or
engine behavior.

## Verified Batch 1 foundation

Batch 1 established:

- Debian trixie `live-build` configuration;
- x86-64 UEFI boot;
- exact `nightrecon-shared-core`, `nightrecon-white-engine`, and
  `nightrecon-white-night` wheel staging;
- checksum verification and retained ISO artifacts;
- offline QEMU/OVMF userspace boot verification.

## Batch 2 initial slice

Batch 2 now adds the installed White application boundary:

- `python3-venv` provides an isolated immutable-image runtime;
- the three exact staged wheels are installed into `/opt/nightrecon/venv`;
- installation uses `--no-index --no-deps`, so image construction does not
  replace the staged White packages with repository packages from elsewhere;
- `/usr/local/bin/white-night-app` points to the packaged application entry
  point;
- boot readiness verifies exact installed package versions;
- readiness executes `white-night-app editions --json`;
- the offline UEFI VM must emit `WHITE_NIGHT_LIVE_APP_OK`.

Batch 2 now also enables a systemd-managed White application bootstrap at boot.
The bootstrap runs the packaged `/usr/local/bin/white-night-app`, validates its
startup output, writes a transient runtime record under `/run`, and emits
`WHITE_NIGHT_LIVE_AUTO_START_OK`. The final readiness service is ordered after
that bootstrap and the VM smoke requires both the auto-start and application
readiness markers.

This is the alpha appliance-start contract, not the final graphical/operator UI.
The bootstrap is intentionally nonpersistent and does not create engagement
state.

Persistence remains disabled. This batch does not configure LUKS2, mount or
modify host disks, add target execution, add another Night runtime, or claim
production Secure Boot acceptance.

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

Verify the installed White application after UEFI boot without a VM network
interface:

```sh
./tests/white_live_vm_smoke.sh \
  artifacts/live/white-night/WhiteNight-Live-0.1.0a6-amd64.iso
```

A passing smoke test observes `WHITE_NIGHT_LIVE_APP_OK` on the serial console.

## UEFI signing note

The alpha builder uses Debian live-build's automatic UEFI Secure Boot mode so
Debian signed shim/GRUB artifacts may be used when available. This is not a claim
that White Night has completed production Secure Boot acceptance. Hardware
compatibility, project signing policy, recovery, and full Secure Boot testing
remain later hardening gates.

## Headless CI boot selection

The Live image deliberately keeps an interactive GRUB boot menu because later
White Live batches will expose Secure Workspace, Ephemeral Session, and Recovery
modes. Headless CI selects the default entry through QEMU's local UNIX monitor
before waiting for the serial readiness marker. The guest still runs with
`-nic none`.
