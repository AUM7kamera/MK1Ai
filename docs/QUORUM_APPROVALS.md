# Quarantine release quorum (prototype)

**Status:** partial implementation guidance. This procedure is not an
independent evaluation or proof of organizational/node independence.

Quarantine release requires valid Ed25519 signatures from at least two
distinct identities in the enrolled roster of two or three public keys. The
target checks each signature against the same generation-bound, random
challenge and remains quarantined on every parse, signature, state, or
firewall-removal failure. A single approver key cannot release quarantine.

## Provisioning

1. Generate each Ed25519 private key on its independently administered
   approver node, and keep the private key there. Do not copy private keys to
   the protected endpoint. For example, using OpenSSL:

   ```sh
   umask 077
   openssl genpkey -algorithm ED25519 -out node-1-private.pem
   openssl pkey -in node-1-private.pem -pubout -out node-1.pub
   ```

2. Provision two or three public keys out of band as root-owned, non-group- or
   world-writable PEM files:
   `/etc/mk1ai/quorum/node-1.pub`, `node-2.pub`, and optionally `node-3.pub`.
   The installer creates the protected directory but does not generate or
   enroll keys. The public key fingerprints must be compared by an operator
   over a separate authenticated channel before enrollment.
3. Record each signer's identity and failure domain independently. The code
   checks distinct Ed25519 key material and labels, but does not attest the
   signer's OS, architecture, administration, or physical independence.

## Release procedure

1. While the target is quarantined, issue a one-use challenge:

   ```sh
   sudo /usr/bin/python3 /opt/mk1ai/mk1_quarantine.py issue-release-challenge \
     > release-challenge.json
   ```

2. Transfer the challenge to each required approver. Each approver reviews the
   operation out of band and signs only on their own node:

   ```sh
   python3 mk1_quorum_cli.py approve \
     --signer-id node-1 \
     --release-challenge release-challenge.json \
     --private-key /secure/path/node-1-private.pem \
     > node-1-approval.json
   ```

   Repeat independently for a second signer and, when selected, a third.
   The signer rejects challenge fields whose embedded message does not match
   the generation and random challenge.
3. Combine two or three distinct signer records:

   ```sh
   python3 mk1_quorum_cli.py combine \
     --record node-1-approval.json \
     --record node-2-approval.json \
     > release-approvals.json
   ```

4. Return the bundle to the target and supply the challenge token shown in
   `release-challenge.json`:

   ```sh
   sudo /usr/bin/python3 /opt/mk1ai/mk1_quarantine.py release \
     --challenge '<64 lowercase hexadecimal challenge>' \
     --approval-bundle /path/to/release-approvals.json
   ```

The release command accepts signatures only for the current persisted
generation/challenge. A changed or reissued challenge invalidates previously
collected signatures. The bundle carries no private signing material.

## Limits and residual risks

- The target enforces 2-of-2 or 2-of-3 public-key signatures. It does not
  enforce a 3-of-3 S2 policy, operator identity, FIDO2 presence, signed audit
  records, or organizational separation. Do not claim S2 based on this
  mechanism.
- Local quorum configuration can be falsified by a fully compromised target.
  Key enrollment and node independence require external review; a local
  signature verifier cannot establish either.
- Signer private-key file handling is a prototype. It requires a file owned by
  the signing user with mode 0600-equivalent and does not provide HSM/FIDO2
  integration or prove private-key erasure in Python/OpenSSL libraries.
- The current systemd network gate uses existing quarantine state, but this
  quorum check is scoped to quarantine release only. Configuration changes,
  key rotation, audit export, independent monitoring, quorum-loss drills, and
  real multi-node recovery testing remain unimplemented.
