#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
  echo "Usage: $0 <RedNight-Live.iso>" >&2
  exit 2
fi

ISO="$(realpath "$1")"
if [[ ! -s "${ISO}" ]]; then
  echo "ISO not found or empty: ${ISO}" >&2
  exit 2
fi

for command in qemu-system-x86_64 xorriso timeout grep; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    echo "Missing required command: ${command}" >&2
    exit 2
  fi
done

EL_TORITO="$(xorriso -indev "${ISO}" -report_el_torito plain 2>&1 || true)"
if ! grep -Eiq 'UEFI|EFI' <<<"${EL_TORITO}"; then
  echo "ISO does not expose an EFI/UEFI El Torito boot entry" >&2
  echo "${EL_TORITO}" >&2
  exit 3
fi

OVMF_CODE=""
OVMF_VARS=""
for pair in   "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd"   "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd"
do
  code="${pair%%:*}"
  vars="${pair#*:}"
  if [[ -f "${code}" && -f "${vars}" ]]; then
    OVMF_CODE="${code}"
    OVMF_VARS="${vars}"
    break
  fi
done

if [[ -z "${OVMF_CODE}" ]]; then
  echo "OVMF firmware files were not found" >&2
  exit 4
fi

TMP="$(mktemp -d -t red-night-uefi-smoke.XXXXXX)"
trap 'rm -rf -- "${TMP}"' EXIT
cp "${OVMF_VARS}" "${TMP}/OVMF_VARS.fd"
LOG="${TMP}/qemu.log"

timeout 240s qemu-system-x86_64 \
  -machine q35,accel=tcg \
  -cpu max \
  -m 1536 \
  -smp 2 \
  -drive if=pflash,format=raw,readonly=on,file="${OVMF_CODE}" \
  -drive if=pflash,format=raw,file="${TMP}/OVMF_VARS.fd" \
  -cdrom "${ISO}" \
  -boot order=d \
  -display none \
  -serial stdio \
  -monitor none \
  -nic none \
  -no-reboot \
  >"${LOG}" 2>&1 &
RUNNER_PID=$!

for _ in $(seq 1 120); do
  if grep -q "RED_NIGHT_LIVE_BOOT_OK" "${LOG}"; then
    kill "${RUNNER_PID}" >/dev/null 2>&1 || true
    wait "${RUNNER_PID}" >/dev/null 2>&1 || true
    echo "Red Night Live UEFI VM boot smoke: passed"
    exit 0
  fi
  if ! kill -0 "${RUNNER_PID}" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

kill "${RUNNER_PID}" >/dev/null 2>&1 || true
wait "${RUNNER_PID}" >/dev/null 2>&1 || true
echo "Red Night Live did not emit its boot-ready marker" >&2
tail -n 240 "${LOG}" >&2 || true
exit 5
