#!/bin/sh
set -eu

WHITE_VERSION=0.1.0a6
SHARED_CORE_VERSION=0.43.0

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)
wheel_dir=${WHEEL_DIR:-}
output_dir=${OUTPUT_DIR:-"$repo_root/artifacts/live/white-night"}

if [ "$(id -u)" -ne 0 ]; then
    echo "White Night Live build must run as root (for live-build)." >&2
    exit 2
fi

if [ -z "$wheel_dir" ] || [ ! -d "$wheel_dir" ]; then
    echo "WHEEL_DIR must point to built White/shared-core wheel artifacts." >&2
    exit 2
fi

for command_name in lb sha256sum mktemp; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Required build command is missing: $command_name" >&2
        exit 2
    fi
done

build_dir=$(mktemp -d -t white-night-live-build.XXXXXX)
cleanup() {
    rm -rf "$build_dir"
}
trap cleanup EXIT INT TERM HUP

cp -a "$script_dir/auto" "$build_dir/"
cp -a "$script_dir/config" "$build_dir/"

image_wheels="$build_dir/config/includes.chroot/opt/nightrecon/wheels"
mkdir -p "$image_wheels"

stage_exactly_one() {
    pattern=$1
    set -- "$wheel_dir"/$pattern
    if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
        echo "Expected exactly one build artifact matching: $pattern" >&2
        exit 2
    fi
    cp "$1" "$image_wheels/"
}

stage_exactly_one "nightrecon_shared_core-${SHARED_CORE_VERSION}-*.whl"
stage_exactly_one "nightrecon_white_engine-${WHITE_VERSION}-*.whl"
stage_exactly_one "nightrecon_white_night-${WHITE_VERSION}-*.whl"

cd "$build_dir"
./auto/config
lb build

set -- ./*.iso
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "Expected live-build to produce exactly one ISO image." >&2
    exit 1
fi

mkdir -p "$output_dir"
artifact="$output_dir/WhiteNight-Live-${WHITE_VERSION}-amd64.iso"
cp "$1" "$artifact"
(
    cd "$output_dir"
    sha256sum "$(basename "$artifact")" > "$(basename "$artifact").sha256"
)

printf 'White Night Live Batch 1 image: %s\n' "$artifact"
printf 'SHA-256 manifest: %s.sha256\n' "$artifact"
