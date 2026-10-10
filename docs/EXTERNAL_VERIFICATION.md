# External fresh-nonce measurement (prototype)

**Status:** standalone verifier tooling; not a deployed attestation service or
an assurance claim.

The verifier must run on a separate, independently administered host. It
measures files from a target image mounted read-only on that host; it does not
accept file hashes or attestation claims reported by the target endpoint. The
expected build manifest must be produced by a reviewed reproducible-build
process and signed by an independently provisioned Ed25519 builder key. The
verifier signs a successful measurement with its own Ed25519 key.

## Provision trust material

- Provision the build-authority public key and verifier public key out of band
  to the report consumer.
- Keep the verifier signing key on the independent verifier only, with
  owner-only file permissions. Do not copy it to the target.
- The signed manifest is canonical UTF-8 JSON with `version: 1`, a bounded
  `build_id`, and a sorted `files` array of normalized relative paths and
  lowercase SHA-256 digests. Its Ed25519 signature covers the exact canonical
  manifest bytes.

## Measure and verify

Create a fresh 256-bit nonce on the external verifier:

```sh
python3 mk1_external_verifier_cli.py challenge --target-id target-a \
  > measurement-challenge.json
```

Mount the target filesystem read-only on the verifier. The verifier opens files
relative to that mount using no-follow file descriptors and checks that files
remain stable while reading:

```sh
python3 mk1_external_verifier_cli.py measure \
  --target-root /mnt/mk1ai-target \
  --challenge measurement-challenge.json \
  --manifest signed-build-manifest.json \
  --manifest-signature signed-build-manifest.sig \
  --builder-public-key build-authority.pub \
  --verifier-private-key /secure/path/verifier-private.pem \
  > signed-measurement.json
```

The verifier refuses writable mounts, path traversal, symlinks in measured
paths, oversized files/manifests, malformed signatures, stale/mismatched
challenge fields, and any target digest mismatch. Verify the result against
the same challenge and signed manifest using the verifier's public key:

```sh
python3 mk1_external_verifier_cli.py verify \
  --report signed-measurement.json \
  --challenge measurement-challenge.json \
  --manifest signed-build-manifest.json \
  --manifest-signature signed-build-manifest.sig \
  --builder-public-key build-authority.pub \
  --verifier-public-key verifier.pub
```

Any failure exits nonzero; a successful report binds the target label, nonce,
manifest digest and exact measured file/digest set to the external verifier
signature. A consumer must compare the report nonce to the outstanding nonce
it issued and must not reuse a challenge. The target currently has no mechanism
to consume a report as a prerequisite for network activation.

## Limits and residual risk

- No current build pipeline emits reproducible signed manifests, and no
  independent host, read-only media path, persistent nonce ledger, report
  consumer, or network gate is deployed. The CLI and Python APIs are a
  prototype to support those future integrations.
- Measuring a filesystem does not verify running memory, the boot chain,
  firmware, hypervisor, the measurement device/controller, or files omitted
  from the manifest. A compromised target or storage controller may deceive
  I/O or alter live state after measurement.
- A verifier signature only identifies the configured signing key; it does
  not prove that the verifier host is independent or uncompromised. Trust
  anchors and verifier independence require out-of-band operational evidence.
- Nonces are cryptographically fresh, but durable single-use/replay state is
  not implemented. Challenge issuance, report acceptance, quorum integration,
  audit witnessing and key custody remain unverified.
