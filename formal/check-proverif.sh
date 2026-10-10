#!/bin/sh
set -eu

formal_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
output_dir=$(mktemp -d)
trap 'rm -rf "$output_dir"' EXIT HUP INT TERM

proverif "$formal_dir/proverif/hardware_compromise.pv" >"$output_dir/hardware.out"
grep -Fqx 'RESULT not attacker(payload[]) is true.' "$output_dir/hardware.out"
grep -Fqx 'RESULT inj-event(server_accepted(nonce_2,ciphertext_2)) ==> inj-event(client_sent(nonce_2,ciphertext_2)) is true.' "$output_dir/hardware.out"
grep -Fqx 'RESULT inj-event(client_accepted(nonce_2,ciphertext_2)) ==> inj-event(server_responded(nonce_2,ciphertext_2)) is true.' "$output_dir/hardware.out"

proverif "$formal_dir/proverif/user_only.pv" >"$output_dir/user-only.out"
grep -Fqx 'RESULT not attacker(payload[]) is true.' "$output_dir/user-only.out"

proverif "$formal_dir/proverif/no_user_factor.pv" >"$output_dir/no-user-factor.out"
grep -Fqx 'RESULT not attacker(payload[]) is false.' "$output_dir/no-user-factor.out"

printf '%s\n' 'ProVerif checks matched the expected results.'
