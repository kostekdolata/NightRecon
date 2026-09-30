#!/bin/sh
set -eu

[ "$#" -eq 1 ] || {
    echo "usage: $0 ISO" >&2
    exit 2
}

ISO="$1"
[ -f "$ISO" ] || {
    echo "ISO not found: $ISO" >&2
    exit 2
}

command -v qemu-system-x86_64 >/dev/null 2>&1 || {
    echo "qemu-system-x86_64 is required" >&2
    exit 2
}
command -v timeout >/dev/null 2>&1 || {
    echo "timeout is required" >&2
    exit 2
}

OVMF=
for candidate in \
    /usr/share/OVMF/OVMF_CODE_4M.fd \
    /usr/share/OVMF/OVMF_CODE.fd
do
    if [ -f "$candidate" ]; then
        OVMF="$candidate"
        break
    fi
done

[ -n "$OVMF" ] || {
    echo "OVMF UEFI firmware was not found" >&2
    exit 2
}

LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT INT TERM

set +e
timeout 240s qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -m 1536 \
    -smp 2 \
    -bios "$OVMF" \
    -cdrom "$ISO" \
    -boot d \
    -display none \
    -serial "file:$LOG" \
    -monitor none \
    -nic none \
    -no-reboot
QEMU_STATUS=$?
set -e

if grep -Fq "RED_NIGHT_LIVE_BOOT_OK" "$LOG"; then
    echo "Red Night Live UEFI boot smoke passed."
    exit 0
fi

echo "Red Night Live UEFI boot smoke failed (qemu status $QEMU_STATUS)." >&2
tail -n 200 "$LOG" >&2 || true
exit 1
