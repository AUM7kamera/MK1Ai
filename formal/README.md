# Symbolic hardware-compromise models

These ProVerif files are symbolic models, not evidence that the current
implementation satisfies the modeled properties.

- `proverif/hardware_compromise.pv` exposes hardware and FIDO factors from the
  start, keeps the user factor private, authenticates the server's ephemeral
  KEM parameters with a symbolic signature, separates request and response
  authenticators, and asks payload-secrecy plus injective request/response
  correspondence queries.
- `proverif/user_only.pv` models the same root derivation with public empty
  optional factors; it asks whether the user-only mode keeps the payload secret.
- `proverif/no_user_factor.pv` is a negative-control model in which the
  mandatory user factor is replaced by a public value; payload disclosure is
  expected because hardware and FIDO factors are public to the attacker.

## Verification run

```sh
opam exec -- sh formal/check-proverif.sh
```

Executed with ProVerif 2.05 from OPAM. The model checks returned:

- Hardware/FIDO factors disclosed; user factor retained as a secret: payload
  secrecy and both injective request/response correspondences hold.
- User-only model: payload secrecy holds.
- No-user-factor negative control: payload secrecy fails with an attacker
  trace, as expected.

The same checks run in CI using the digest-pinned OCaml/OPAM image and pinned
ProVerif package version. This verification has not yet been observed on a
hosted CI run.

The encapsulation, KDF, MAC, and authenticated-encryption constructors are
ideal symbolic abstractions. The model assumes a trusted server verification
key and does not compromise the user factor during or after a session; it
therefore does not establish post-compromise security or forward secrecy
against later user-factor disclosure. It does not prove the ML-KEM-1024 +
X25519 combiner, HKDF transcript binding, real implementation constant-time
behavior, entropy quality, downgrade resistance, or correspondence with
Python/C/WireGuard code. The results are proofs only within this symbolic model
and are not a certification or an implementation assurance claim. Independent
model and implementation review remain required.
