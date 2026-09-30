#!/bin/sh
set -eu

timeout_seconds=${WHITE_LIVE_VM_TIMEOUT:-240}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    echo "usage: $0 <WhiteNight-Live-*.iso> [ephemeral|recovery|secure-workspace]" >&2
    exit 2
fi

iso=$1
mode=${2:-ephemeral}

case "$mode" in
    ephemeral)
        menu_down=0
        expected_one=WHITE_NIGHT_LIVE_MODE_OK=ephemeral
        expected_two=WHITE_NIGHT_LIVE_AUTO_START_OK
        expected_three=WHITE_NIGHT_LIVE_APP_OK
        ;;
    recovery)
        menu_down=1
        expected_one=WHITE_NIGHT_LIVE_MODE_OK=recovery
        expected_two=WHITE_NIGHT_LIVE_RECOVERY_READY
        expected_three=WHITE_NIGHT_LIVE_RECOVERY_OK
        ;;
    secure-workspace)
        menu_down=2
        expected_one=WHITE_NIGHT_LIVE_MODE=secure-workspace
        expected_two=WHITE_NIGHT_LIVE_SECURE_WORKSPACE_BLOCKED
        expected_three=
        ;;
    *)
        echo "unsupported White Night Live VM mode: $mode" >&2
        exit 2
        ;;
esac

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

# Wait until the White Night GRUB menu is visible, then select by position.
# Positional arrow-key selection avoids collisions with GRUB's built-in edit
# shortcuts (notably the "e" key).
python3 - "$monitor" "$log" "$menu_down" <<'PY'
import os
import socket
import sys
import time

path = sys.argv[1]
log_path = sys.argv[2]
down_count = int(sys.argv[3])

for _ in range(80):
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(path)
        break
    except (FileNotFoundError, ConnectionRefusedError):
        time.sleep(0.25)
else:
    raise SystemExit("QEMU monitor socket did not become ready")

menu_text = "White Night — Ephemeral Session"
for _ in range(120):
    try:
        if menu_text in open(log_path, encoding="utf-8", errors="ignore").read():
            break
    except FileNotFoundError:
        pass
    time.sleep(0.25)
else:
    raise SystemExit("White Night GRUB menu did not become visible")

with client:
    time.sleep(0.3)
    for _ in range(down_count):
        client.sendall(b"sendkey down\n")
        time.sleep(0.35)
    # Give GRUB time to commit the highlighted entry before Enter. Without
    # this pause the serial UI can visibly move while the following Enter is
    # still lost by the firmware/GRUB input transition.
    time.sleep(0.75)
    client.sendall(b"sendkey ret\n")
    time.sleep(0.5)
PY

elapsed=0
while [ "$elapsed" -lt "$timeout_seconds" ]; do
    if grep -Fq "$expected_one" "$log" && grep -Fq "$expected_two" "$log"; then
        if [ -z "$expected_three" ] || grep -Fq "$expected_three" "$log"; then
            printf 'White Night Live UEFI VM smoke: passed mode=%s\n' "$mode"
            exit 0
        fi
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
        wait "$pid" 2>/dev/null || true
        pid=
        echo "White Night Live VM exited before expected mode markers ($mode)." >&2
        tail -n 160 "$log" >&2 || true
        exit 1
    fi

    sleep 1
    elapsed=$((elapsed + 1))
done

echo "White Night Live VM did not emit expected mode markers within ${timeout_seconds}s ($mode)." >&2
tail -n 160 "$log" >&2 || true
exit 1
