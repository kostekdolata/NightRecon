#!/bin/sh
set -eu

# Disposable CI-only LUKS2 acceptance fixture.
# This script must never be used as a field-media provisioning path.

if [ "$(id -u)" -ne 0 ]; then
    echo "white_live_luks_fixture.sh must run as root" >&2
    exit 2
fi

for command in cryptsetup mkfs.ext4 mount umount findmnt sha256sum python3; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "required command not found: $command" >&2
        exit 2
    }
done

tmp=$(mktemp -d -t white-night-luks-fixture.XXXXXX)
image="$tmp/workspace.img"
key_file="$tmp/workspace.key"
wrong_key="$tmp/wrong.key"
malformed="$tmp/not-luks.img"
mountpoint="$tmp/mnt"
ephemeral="$tmp/ephemeral"
mapper="nightrecon-white-ci-$$"
mapper_path="/dev/mapper/$mapper"
metadata_rel=".nightrecon-workspace.json"
state_rel="engagements/ci-fixture-state.json"
before_mounts="$tmp/mounts.before"
after_mounts="$tmp/mounts.after"

cleanup() {
    set +e
    if mountpoint -q "$mountpoint" 2>/dev/null; then
        umount "$mountpoint"
    fi
    if [ -e "$mapper_path" ]; then
        cryptsetup close "$mapper"
    fi
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM HUP

mkdir -p "$mountpoint" "$ephemeral"
findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS | sort > "$before_mounts"

# Regular-file backing storage is intentionally used instead of a host block
# device. The fixture owns this file and deletes it on exit.
truncate -s 96M "$image"
python3 - "$key_file" "$wrong_key" <<'PY'
import os
from pathlib import Path
import sys

for path in map(Path, sys.argv[1:]):
    path.write_bytes(os.urandom(64))
    path.chmod(0o600)
PY

# Provisioning exists only inside this disposable fixture. Runtime White Live
# code remains prohibited from calling luksFormat.
cryptsetup luksFormat \
    --batch-mode \
    --type luks2 \
    --key-file "$key_file" \
    "$image"

cryptsetup isLuks --type luks2 "$image"
cryptsetup open \
    --type luks2 \
    --key-file "$key_file" \
    "$image" \
    "$mapper"

mkfs.ext4 -q -F "$mapper_path"
mount "$mapper_path" "$mountpoint"
chmod 0700 "$mountpoint"
mkdir -p "$mountpoint/engagements"

cat > "$mountpoint/$metadata_rel" <<'JSON'
{"authorization_effect":"none","compatible_shared_core":"0.43.x","compatible_white":"0.1.0a6","creation_format_version":1,"product":"White Night","schema_version":1,"workspace_uuid":"00000000-0000-4000-8000-000000000001"}
JSON

cat > "$mountpoint/$state_rel" <<'JSON'
{"fixture":"white-live-luks2","sequence":1,"state":"persisted"}
JSON

metadata_hash=$(sha256sum "$mountpoint/$metadata_rel" | awk '{print $1}')
state_hash=$(sha256sum "$mountpoint/$state_rel" | awk '{print $1}')

sync
umount "$mountpoint"
cryptsetup close "$mapper"

# Second phase: reopen the exact same encrypted container and prove state
# survives closure/reopen.
cryptsetup open \
    --type luks2 \
    --key-file "$key_file" \
    "$image" \
    "$mapper"
mount "$mapper_path" "$mountpoint"

test "$(sha256sum "$mountpoint/$metadata_rel" | awk '{print $1}')" = "$metadata_hash"
test "$(sha256sum "$mountpoint/$state_rel" | awk '{print $1}')" = "$state_hash"
grep -Fq '"authorization_effect":"none"' "$mountpoint/$metadata_rel"
grep -Fq '"state":"persisted"' "$mountpoint/$state_rel"

sync
umount "$mountpoint"
cryptsetup close "$mapper"

# Simulated Ephemeral phase: write only to disposable nonpersistent scratch and
# prove the encrypted workspace image itself is byte-for-byte unchanged.
image_hash_before_ephemeral=$(sha256sum "$image" | awk '{print $1}')
cat > "$ephemeral/session-state.json" <<'JSON'
{"fixture":"white-live-ephemeral","state":"temporary"}
JSON
test -s "$ephemeral/session-state.json"
image_hash_after_ephemeral=$(sha256sum "$image" | awk '{print $1}')
test "$image_hash_before_ephemeral" = "$image_hash_after_ephemeral"

# Wrong-secret unlock must fail closed and must not create the mapper.
if cryptsetup open \
    --type luks2 \
    --key-file "$wrong_key" \
    "$image" \
    "$mapper" >/dev/null 2>&1
then
    echo "wrong-key unlock unexpectedly succeeded" >&2
    exit 1
fi
test ! -e "$mapper_path"

# A malformed target must never be accepted as LUKS2.
truncate -s 4M "$malformed"
if cryptsetup isLuks --type luks2 "$malformed" >/dev/null 2>&1; then
    echo "malformed target unexpectedly identified as LUKS2" >&2
    exit 1
fi

# With all fixture resources closed, the host mount table must exactly match
# its pre-test state.
findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS | sort > "$after_mounts"
cmp -s "$before_mounts" "$after_mounts"

echo "WHITE_NIGHT_LUKS2_FIXTURE_OK"
