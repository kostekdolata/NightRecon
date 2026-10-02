#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPOSITORY=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
WHEEL_DIR=
OUTPUT=
RELEASE_VERSION=${NIGHTRECON_RELEASE_VERSION:-0.44.0-dev}

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
command -v python3 >/dev/null 2>&1 || {
    echo "python3 is required" >&2
    exit 1
}

RELEASE_STAGE="$SCRIPT_DIR/config/includes.chroot/opt/nightrecon/release"
cleanup() {
    rm -rf "$RELEASE_STAGE"
}
trap cleanup EXIT INT TERM

python3 "$SCRIPT_DIR/create_release_metadata.py" stage \
    --wheel-dir "$WHEEL_DIR" \
    --output-dir "$RELEASE_STAGE" \
    --release-version "$RELEASE_VERSION"

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

PACKAGE_MANIFEST="$OUTPUT.package-manifest.json"
SBOM="$OUTPUT.SBOM.json"
IMAGE_MANIFEST="$OUTPUT.manifest.json"
cp "$RELEASE_STAGE/package-manifest.json" "$PACKAGE_MANIFEST"
cp "$RELEASE_STAGE/SBOM.json" "$SBOM"

SOURCE_REVISION=${NIGHTRECON_SOURCE_REVISION:-}
if [ -z "$SOURCE_REVISION" ]; then
    SOURCE_REVISION=$(git -C "$REPOSITORY" rev-parse HEAD)
fi

python3 "$SCRIPT_DIR/create_release_metadata.py" finalize \
    --release-dir "$RELEASE_STAGE" \
    --image "$OUTPUT" \
    --source-revision "$SOURCE_REVISION" \
    --release-version "$RELEASE_VERSION" \
    --output-manifest "$IMAGE_MANIFEST"

echo "Red Night Live image: $OUTPUT"
echo "SHA-256 sidecar: $OUTPUT.sha256"
echo "Image manifest: $IMAGE_MANIFEST"
echo "Package manifest: $PACKAGE_MANIFEST"
echo "SBOM: $SBOM"
