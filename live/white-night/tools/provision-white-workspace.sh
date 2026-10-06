#!/bin/sh
set -eu

CONFIRMATION="PROVISION-WHITE-NIGHT-LUKS2"

usage() {
    echo "usage: $0 --target <regular-file> --key-file <0600-file> --confirm PROVISION-WHITE-NIGHT-LUKS2" >&2
    exit 2
}

target=
key_file=
confirm=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --target)
            [ "$#" -ge 2 ] || usage
            target=$2
            shift 2
            ;;
        --key-file)
            [ "$#" -ge 2 ] || usage
            key_file=$2
            shift 2
            ;;
        --confirm)
            [ "$#" -ge 2 ] || usage
            confirm=$2
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

[ -n "$target" ] && [ -n "$key_file" ] && [ -n "$confirm" ] || usage

if [ "$(id -u)" -ne 0 ]; then
    echo "White Night provisioning requires root" >&2
    exit 2
fi

for command in cryptsetup mkfs.ext4 stat readlink; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required command not found: $command" >&2
        exit 2
    }
done

if [ "$confirm" != "$CONFIRMATION" ]; then
    echo "destructive confirmation token mismatch" >&2
    exit 3
fi

case "$target" in
    /dev/*)
        echo "block-device paths are not accepted by this provisioning slice" >&2
        exit 3
        ;;
esac

if [ -L "$target" ]; then
    echo "symlink targets are not accepted" >&2
    exit 3
fi

if [ ! -f "$target" ]; then
    echo "target must be an existing regular file" >&2
    exit 3
fi

resolved=$(readlink -f -- "$target")
case "$resolved" in
    /dev/*)
        echo "resolved block-device paths are not accepted" >&2
        exit 3
        ;;
esac

size=$(stat -c %s -- "$target")
if [ "$size" -lt 67108864 ]; then
    echo "target file is too small; minimum is 64 MiB" >&2
    exit 3
fi

if [ ! -f "$key_file" ] || [ -L "$key_file" ]; then
    echo "key file must be an existing regular file" >&2
    exit 3
fi

key_mode=$(stat -c %a -- "$key_file")
if [ "$key_mode" != "600" ]; then
    echo "key file permissions must be exactly 0600" >&2
    exit 3
fi

if cryptsetup isLuks "$target" >/dev/null 2>&1; then
    echo "target is already a LUKS container; refusing to overwrite" >&2
    exit 3
fi

# This is the only destructive boundary in this helper. It never discovers a
# target and never accepts /dev paths in this initial slice.
cryptsetup luksFormat \
    --batch-mode \
    --type luks2 \
    --key-file "$key_file" \
    "$target"

cryptsetup isLuks --type luks2 "$target" >/dev/null
echo "WHITE_NIGHT_LUKS2_PROVISIONED"
