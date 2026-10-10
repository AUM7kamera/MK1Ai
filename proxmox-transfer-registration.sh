#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 || ! $1 =~ ^[0-9]+$ || ! $2 =~ ^[0-9]+$ || $1 == "$2" ]]; then
    printf 'Usage: %s REGISTRATION_CTID PRODUCTION_CTID\n' "$0" >&2
    exit 64
fi

registration_ctid=$1
production_ctid=$2
profile_source=/var/lib/mk1ai/owner_profile.dat
profile_destination=/etc/mk1ai/owner_profile.dat
profile_stage=/etc/mk1ai/.owner_profile.dat.pending
workdir=$(mktemp -d)
profile_copy=$workdir/owner_profile.dat
trap 'rm -f -- "$profile_copy"; rmdir -- "$workdir"' EXIT

if [[ $(pct status "$registration_ctid") != *running* ]]; then
    printf 'Registration container %s must be running.\n' "$registration_ctid" >&2
    exit 1
fi
if [[ $(pct status "$production_ctid") != *stopped* ]]; then
    printf 'Stop production container %s before profile migration.\n' "$production_ctid" >&2
    exit 1
fi

pct pull "$registration_ctid" "$profile_source" "$profile_copy"
[[ -f $profile_copy && ! -L $profile_copy ]] || {
    printf 'Pulled profile is not a regular file.\n' >&2
    exit 1
}

credential_fingerprints=$(python3 - "$profile_copy" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if path.stat().st_size > 65536:
    raise SystemExit("Profile exceeds the allowed size")
profile = json.loads(path.read_text(encoding="ascii"))
if (
    not isinstance(profile, dict)
    or set(profile) != {"version", "user_id", "credentials"}
    or type(profile["version"]) is not int
    or profile["version"] != 1
    or not isinstance(profile["user_id"], str)
    or not isinstance(profile["credentials"], list)
    or not 1 <= len(profile["credentials"]) <= 10
):
    raise SystemExit("Invalid profile structure")

def decode(value, minimum, maximum):
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise ValueError("Invalid encoded field")
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
    )
    if not minimum <= len(decoded) <= maximum:
        raise ValueError("Invalid decoded field length")
    return decoded

decode(profile["user_id"], 1, 128)
seen = set()
for credential in profile["credentials"]:
    if (
        not isinstance(credential, dict)
        or set(credential) != {"credential_id", "public_key", "sign_count"}
        or type(credential["sign_count"]) is not int
        or not 0 <= credential["sign_count"] <= 2**32 - 1
    ):
        raise SystemExit("Invalid credential entry")
    credential_id = decode(credential["credential_id"], 1, 1024)
    decode(credential["public_key"], 1, 4096)
    if credential_id in seen:
        raise SystemExit("Duplicate credential ID")
    seen.add(credential_id)
    print(hashlib.sha256(credential_id).hexdigest())
PY
)

if [[ ! -t 0 ]]; then
    printf 'Interactive out-of-band fingerprint confirmation is required.\n' >&2
    exit 1
fi
mapfile -t credential_fingerprint_list <<< "$credential_fingerprints"
for fingerprint in "${credential_fingerprint_list[@]}"; do
    [[ $fingerprint =~ ^[0-9a-f]{64}$ ]] || {
        printf 'Invalid credential fingerprint generated from profile.\n' >&2
        exit 1
    }
    printf 'Credential ID SHA-256: %s\n' "$fingerprint"
    printf 'Compare with the enrollment result through an independent channel, then type the full fingerprint: '
    if ! IFS= read -r confirmation; then
        printf 'Could not read credential fingerprint confirmation.\n' >&2
        exit 1
    fi
    [[ $confirmation == "$fingerprint" ]] || {
        printf 'Credential fingerprint confirmation failed; refusing transfer.\n' >&2
        exit 1
    }
done

chmod 0400 "$profile_copy"
profile_sha256=$(sha256sum "$profile_copy")
profile_sha256=${profile_sha256%% *}
pct exec "$production_ctid" -- test -d /etc/mk1ai
pct exec "$production_ctid" -- test ! -e "$profile_destination"
pct exec "$production_ctid" -- test ! -L "$profile_destination"
pct exec "$production_ctid" -- test ! -e "$profile_stage"
pct exec "$production_ctid" -- test ! -L "$profile_stage"
pct push "$production_ctid" "$profile_copy" "$profile_stage"
pct exec "$production_ctid" -- chown mk1ai:mk1ai "$profile_stage"
pct exec "$production_ctid" -- chmod 0400 "$profile_stage"
pct exec "$production_ctid" -- mv -n -- "$profile_stage" "$profile_destination"
pct exec "$production_ctid" -- test -f "$profile_destination"
[[ $(pct exec "$production_ctid" -- stat -c %a "$profile_destination") == 400 ]] || {
    printf 'Production profile permissions are not mode 0400.\n' >&2
    exit 1
}
production_sha256=$(pct exec "$production_ctid" -- sha256sum -- "$profile_destination")
production_sha256=${production_sha256%% *}
[[ $production_sha256 == "$profile_sha256" ]] || {
    printf 'Production profile hash does not match the validated source.\n' >&2
    exit 1
}
pct start "$production_ctid"
pct exec "$production_ctid" -- systemctl is-active --quiet mk1-remote-dashboard.service

pct set "$registration_ctid" --onboot 0
pct stop "$registration_ctid"
printf 'Profile transferred. Production container started; enrollment container stopped and disabled at boot.\n'
