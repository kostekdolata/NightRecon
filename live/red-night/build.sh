#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_VERSION="${RED_LIVE_IMAGE_VERSION:-v0.44.0-dev}"
ARTIFACT_DIR="${RED_LIVE_ARTIFACT_DIR:-${REPO_ROOT}/artifacts/live/red-night}"
PYTHON_BUILD="${PYTHON_BUILD:-python3}"
KEEP_WORK="${RED_LIVE_KEEP_WORK:-0}"

for command in lb git sha256sum "${PYTHON_BUILD}"; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "Missing required command: ${command}" >&2
    exit 2
  fi
done

if [[ "${EUID}" -eq 0 ]]; then
  ROOT_CMD=()
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "Red Live build requires root or sudo for live-build" >&2
    exit 2
  fi
  ROOT_CMD=(sudo)
fi

if [[ -n "${RED_LIVE_WORK_DIR:-}" ]]; then
  WORK_DIR="${RED_LIVE_WORK_DIR}"
  rm -rf -- "${WORK_DIR}"
  mkdir -p -- "${WORK_DIR}"
  CLEANUP_WORK=0
else
  WORK_DIR="$(mktemp -d -t red-night-live.XXXXXX)"
  CLEANUP_WORK=1
fi

cleanup() {
  if [[ "${CLEANUP_WORK}" == "1" && "${KEEP_WORK}" != "1" ]]; then
    "${ROOT_CMD[@]}" rm -rf -- "${WORK_DIR}" || true
  fi
}
trap cleanup EXIT

cp -a "${SCRIPT_DIR}/auto" "${SCRIPT_DIR}/config" "${WORK_DIR}/"
mkdir -p "${WORK_DIR}/config/includes.chroot/opt/nightrecon/wheels"
mkdir -p "${WORK_DIR}/config/includes.chroot/etc"
mkdir -p "${ARTIFACT_DIR}"

version_from_pyproject() {
  "${PYTHON_BUILD}" -c '
import pathlib, sys, tomllib
path = pathlib.Path(sys.argv[1])
with path.open("rb") as handle:
    print(tomllib.load(handle)["project"]["version"])
' "$1"
}

SHARED_VERSION="$(version_from_pyproject "${REPO_ROOT}/packages/shared-core/pyproject.toml")"
ENGINE_VERSION="$(version_from_pyproject "${REPO_ROOT}/packages/red-engine/pyproject.toml")"
APP_VERSION="$(version_from_pyproject "${REPO_ROOT}/packages/red-night/pyproject.toml")"

if [[ "${SHARED_VERSION}" != "${ENGINE_VERSION}" || "${ENGINE_VERSION}" != "${APP_VERSION}" ]]; then
  echo "Red Live requires coordinated shared-core/engine/app versions" >&2
  exit 3
fi

WHEELHOUSE="${WORK_DIR}/config/includes.chroot/opt/nightrecon/wheels"

"${PYTHON_BUILD}" -m pip wheel \
  --no-deps \
  --no-build-isolation \
  --wheel-dir "${WHEELHOUSE}" \
  "${REPO_ROOT}/packages/shared-core" \
  "${REPO_ROOT}/packages/red-engine" \
  "${REPO_ROOT}/packages/red-night"

"${PYTHON_BUILD}" -m pip download \
  --dest "${WHEELHOUSE}" \
  --only-binary=:all: \
  --implementation cp \
  --python-version 3.13 \
  --platform manylinux_2_17_x86_64 \
  --platform manylinux_2_28_x86_64 \
  --platform manylinux_2_34_x86_64 \
  "cryptography>=50.0.1,<51"

(
  cd "${WHEELHOUSE}"
  sha256sum ./*.whl | LC_ALL=C sort > WHEELHOUSE.sha256
)

cat > "${WORK_DIR}/config/includes.chroot/etc/nightrecon-live-build.env" <<EOF
NIGHTRECON_SHARED_CORE_VERSION=${SHARED_VERSION}
NIGHTRECON_RED_ENGINE_VERSION=${ENGINE_VERSION}
NIGHTRECON_RED_NIGHT_VERSION=${APP_VERSION}
NIGHTRECON_LIVE_RELEASE=trixie
NIGHTRECON_LIVE_ARCHITECTURE=amd64
NIGHTRECON_LIVE_IMAGE_VERSION=${IMAGE_VERSION}
EOF

SOURCE_REVISION="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
SOURCE_DATE_EPOCH="$(git -C "${REPO_ROOT}" show -s --format=%ct HEAD)"
export SOURCE_DATE_EPOCH

"${PYTHON_BUILD}" - <<PY > "${WORK_DIR}/config/includes.chroot/etc/nightrecon-live-build.json"
import json
print(json.dumps({
    "schema_version": 1,
    "image_version": "${IMAGE_VERSION}",
    "base_distribution": "debian-trixie",
    "architecture": "amd64",
    "firmware_boot": "uefi",
    "secure_boot": "disabled-development",
    "source_revision": "${SOURCE_REVISION}",
    "packages": {
        "nightrecon-shared-core": "${SHARED_VERSION}",
        "nightrecon-red-engine": "${ENGINE_VERSION}",
        "nightrecon-red-night": "${APP_VERSION}",
    },
    "persistent_workspace": False,
    "host_disk_policy": "no-automatic-mount",
}, sort_keys=True, indent=2))
PY

pushd "${WORK_DIR}" >/dev/null
./auto/config
"${ROOT_CMD[@]}" lb build
ISO_SOURCE="$(find . -maxdepth 1 -type f -name '*.iso' -print | LC_ALL=C sort | head -n 1)"
if [[ -z "${ISO_SOURCE}" || ! -s "${ISO_SOURCE}" ]]; then
  echo "live-build did not produce an ISO" >&2
  exit 4
fi
popd >/dev/null

ISO_NAME="RedNight-Live-${IMAGE_VERSION}-amd64.iso"
ISO_OUTPUT="${ARTIFACT_DIR}/${ISO_NAME}"
cp "${WORK_DIR}/${ISO_SOURCE#./}" "${ISO_OUTPUT}"
ISO_SHA256="$(sha256sum "${ISO_OUTPUT}" | awk '{print $1}')"
printf '%s  %s\n' "${ISO_SHA256}" "${ISO_NAME}" > "${ISO_OUTPUT}.sha256"

LIVE_BUILD_VERSION="$(lb --version 2>/dev/null | head -n 1 || true)"
"${PYTHON_BUILD}" - <<PY > "${ARTIFACT_DIR}/RedNight-Live-${IMAGE_VERSION}-amd64.manifest.json"
import json
print(json.dumps({
    "schema_version": 1,
    "image": "${ISO_NAME}",
    "sha256": "${ISO_SHA256}",
    "image_version": "${IMAGE_VERSION}",
    "base_distribution": "debian-trixie",
    "architecture": "amd64",
    "firmware_boot": "uefi",
    "secure_boot": "disabled-development",
    "source_revision": "${SOURCE_REVISION}",
    "source_date_epoch": int("${SOURCE_DATE_EPOCH}"),
    "live_build_version": "${LIVE_BUILD_VERSION}",
    "packages": {
        "nightrecon-shared-core": "${SHARED_VERSION}",
        "nightrecon-red-engine": "${ENGINE_VERSION}",
        "nightrecon-red-night": "${APP_VERSION}",
    },
    "package_install_source": "embedded-wheelhouse",
    "persistent_workspace": False,
    "host_disk_policy": "no-automatic-mount",
}, sort_keys=True, indent=2))
PY

echo "Built ${ISO_OUTPUT}"
echo "SHA-256 ${ISO_SHA256}"
