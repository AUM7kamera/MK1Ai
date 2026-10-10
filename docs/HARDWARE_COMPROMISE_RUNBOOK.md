# Hardware-compromise and disposable-operation runbook

**Status:** operational guidance only. The repository does not yet provide a
tested signed-image release and reprovisioning pipeline, independent
credential authority, or recovery automation. Do not treat following this
document as proof that a host is clean.

## Suspected endpoint or hardware compromise

1. Stop sensitive operations. If safe to do so, put the endpoint in quarantine
   and prevent it from rejoining trusted networks. Do not rely on its local
   status, attestation, logs, or self-integrity result.
2. Record the asset, time, operator, observed symptoms, and externally
   witnessed log-head hashes. Preserve evidence through an independently
   controlled process; do not copy packet payloads or secrets into ordinary
   incident notes.
3. From an independent authority, revoke the endpoint identity, short-lived
   credentials, and any operator or service credentials that may have been
   exposed. Record the revocation generation and distribute it to peers.
4. Rotate affected purpose-specific keys and any shared credentials from
   systems not exposed to the suspected endpoint. Do not restore long-term
   secrets from the endpoint or combine all backup shares on one device.
5. Retire or physically isolate the endpoint pending hardware/vendor
   investigation. If firmware, controller, or supply-chain compromise is
   plausible, replacing storage alone is not a trusted recovery.
6. Reprovision from an independently verified, signed offline image and
   configuration. Verify signatures and hashes on a separate trusted system
   using an out-of-band trust anchor before connecting the medium. Reject
   unsigned, stale, or unverifiable media. Never use an affected endpoint's
   self-measurement as the sole acceptance decision.
7. Restore only reviewed configuration and non-secret data. Enroll a new
   endpoint identity, obtain independent verification, and require the
   configured quorum before permitting sensitive operations.
8. Document failed or unavailable verification steps as unresolved. Keep the
   endpoint quarantined until independent operators authorize recovery.

## Disposable USB scan environment

Use an isolated, disposable scan environment. After each scan batch, power it
off, discard its writable state, and rebuild from a separately verified
offline image before reuse. Treat every scan verdict as advisory; a ClamAV
`clean` verdict is not proof that content is safe. Do not attach the scanner
to a trusted network or place long-term credentials in it.

The signed image production, external trust-anchor distribution, and
automated disposable rebuild are not currently implemented or hardware
verified. Until they exist, this procedure is a manual operational objective,
not an enforced property.

## One-way media transfer preference

Where practical, use a physically one-way transfer process: export from the
source side to controlled removable media, disconnect it, inspect/import it
on the receiving side, and never reconnect the receiving system to the
source-side interface. Use separate media for inbound and outbound transfer.
Record custody and hashes on both sides; do not rely on a device's firmware or
write-protect switch as a data diode. For stronger boundaries use an evaluated
hardware data diode and independent inspection.

This operating pattern reduces return-channel risk but does not prove
unidirectionality. USB controllers and media firmware are within the hostile
hardware model. Payload encryption does not hide traffic timing, volume,
endpoints, or other network metadata.
