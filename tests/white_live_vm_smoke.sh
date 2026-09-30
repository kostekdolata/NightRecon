#!/bin/sh
set -eu

marker=WHITE_NIGHT_LIVE_APP_OK
timeout_seconds=${WHITE_LIVE_VM_TIMEOUT:-240}

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <WhiteNight-Live-*.iso>" >&2
    exit 2
fi

iso=$1
if [ ! -f "$iso" ]; then
    echo "ISO image not found: $iso" >&2
    exit 2
fi

if ! command -v qemu-system-x86_64 >/dev/null 2>&1; then
    echo "qemu-system-x86_64 is required" >&2
    exit 2
fi

ovmf_code=
ovmf_vars=
for pair in \
    "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd"
do
    code=${pair%%:*}
    vars=${pair#*:}
    if [ -f "$code" ] && [ -f "$vars" ]; then
        ovmf_code=$code
        ovmf_vars=$vars
        break
    fi
done

if [ -z "$ovmf_code" ]; then
    echo "OVMF UEFI firmware files were not found" >&2
    exit 2
fi

tmp=$(mktemp -d -t white-night-live-vm.XXXXXX)
log="$tmp/serial.log"
monitor="$tmp/qemu-monitor.sock"
vars_copy="$tmp/OVMF_VARS.fd"
cp "$ovmf_vars" "$vars_copy"

pid=
cleanup() {
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
        wait "$pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM HUP

qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -m 1024 \
    -smp 2 \
    -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
    -drive "if=pflash,format=raw,file=$vars_copy" \
    -cdrom "$iso" \
    -boot order=d \
    -nic none \
    -display none \
    -monitor "unix:$monitor,server=on,wait=off" \
    -serial stdio \
    -no-reboot \
    >"$log" 2>&1 &
pid=$!

# Debian Live presents an interactive GRUB entry before the kernel starts.
# CI is headless, so select the default Live entry through QEMU's host-side
# monitor. The guest still has no NIC and the image itself keeps its normal
# interactive boot menu for real operators.
python3 - "$monitor" <<'PY'
import socket
import sys
import time

path = sys.argv[1]
for _ in range(40):
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(path)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.25)
else:
    raise SystemExit("QEMU monitor socket did not become ready")

with client:
    for _ in range(5):
        time.sleep(2)
        client.sendall(b"sendkey ret\n")
PY

elapsed=0
while [ "$elapsed" -lt "$timeout_seconds" ]; do
    if grep -Fq "$marker" "$log"; then
        printf 'White Night Live UEFI VM smoke: passed (%s)\n' "$marker"
        exit 0
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        pid=
        echo "White Night Live VM exited before readiness marker." >&2
        tail -n 120 "$log" >&2 || true
        exit 1
    fi

    sleep 1
    elapsed=$((elapsed + 1))
done

echo "White Night Live VM did not emit readiness marker within ${timeout_seconds}s." >&2
tail -n 120 "$log" >&2 || true
exit 1
