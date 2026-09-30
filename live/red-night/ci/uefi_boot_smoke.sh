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

OVMF_CODE=
OVMF_VARS_TEMPLATE=

if [ -f /usr/share/OVMF/OVMF_CODE_4M.fd ] &&
   [ -f /usr/share/OVMF/OVMF_VARS_4M.fd ]; then
    OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
    OVMF_VARS_TEMPLATE=/usr/share/OVMF/OVMF_VARS_4M.fd
elif [ -f /usr/share/OVMF/OVMF_CODE.fd ] &&
     [ -f /usr/share/OVMF/OVMF_VARS.fd ]; then
    OVMF_CODE=/usr/share/OVMF/OVMF_CODE.fd
    OVMF_VARS_TEMPLATE=/usr/share/OVMF/OVMF_VARS.fd
else
    echo "matching OVMF UEFI CODE/VARS firmware was not found" >&2
    exit 2
fi

WORK_DIR=$(mktemp -d)
LOG="$WORK_DIR/serial.log"
OVMF_VARS="$WORK_DIR/OVMF_VARS.fd"
cp "$OVMF_VARS_TEMPLATE" "$OVMF_VARS"
trap 'rm -rf "$WORK_DIR"' EXIT INT TERM

set +e
timeout 240s qemu-system-x86_64 \
    -machine q35,accel=tcg \
    -m 1536 \
    -smp 2 \
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE" \
    -drive "if=pflash,format=raw,unit=1,file=$OVMF_VARS" \
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
