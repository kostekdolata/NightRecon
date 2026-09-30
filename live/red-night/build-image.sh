#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WHEEL_DIR=
OUTPUT=

usage() {
    echo "usage: $0 --wheel-dir DIR --output ISO" >&2
    exit 2
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --wheel-dir)
            [ "$#" -ge 2 ] || usage
            WHEEL_DIR="$2"
            shift 2
            ;;
        --output)
            [ "$#" -ge 2 ] || usage
            OUTPUT="$2"
            shift 2
            ;;
        *)
            usage
            ;;
    esac
done

[ -n "$WHEEL_DIR" ] || usage
[ -n "$OUTPUT" ] || usage
[ "$(id -u)" -eq 0 ] || {
    echo "live-build image construction must run as root" >&2
    exit 2
}

WHEEL_DIR=$(realpath "$WHEEL_DIR")
OUTPUT_DIR=$(dirname "$OUTPUT")
mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR=$(realpath "$OUTPUT_DIR")
OUTPUT="$OUTPUT_DIR/$(basename "$OUTPUT")"

command -v lb >/dev/null 2>&1 || {
    echo "live-build (lb) is required" >&2
    exit 1
}

find_one_wheel() {
    pattern="$1"
    set -- "$WHEEL_DIR"/$pattern
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
        echo "expected exactly one wheel matching $pattern in $WHEEL_DIR" >&2
        exit 1
    fi
    printf '%s\n' "$1"
}

SHARED_WHEEL=$(find_one_wheel "nightrecon_shared_core-*.whl")
ENGINE_WHEEL=$(find_one_wheel "nightrecon_red_engine-*.whl")
APP_WHEEL=$(find_one_wheel "nightrecon_red_night-*.whl")

STAGE_DIR="$SCRIPT_DIR/config/includes.chroot/opt/nightrecon/wheels"
cleanup() {
    rm -rf "$STAGE_DIR"
}
trap cleanup EXIT INT TERM

rm -rf "$STAGE_DIR"
mkdir -p "$STAGE_DIR"
cp "$SHARED_WHEEL" "$ENGINE_WHEEL" "$APP_WHEEL" "$STAGE_DIR/"

cd "$SCRIPT_DIR"
lb clean --purge >/dev/null 2>&1 || true
rm -f live-image-*.iso

lb config
lb build

ISO_PATH=$(find "$SCRIPT_DIR" -maxdepth 1 -type f -name 'live-image-*.iso' -print | head -n 1)
[ -n "$ISO_PATH" ] && [ -f "$ISO_PATH" ] || {
    echo "live-build did not produce an ISO image" >&2
    exit 1
}

cp "$ISO_PATH" "$OUTPUT"
sha256sum "$OUTPUT" > "$OUTPUT.sha256"

echo "Red Night Live image: $OUTPUT"
echo "SHA-256 sidecar: $OUTPUT.sha256"
