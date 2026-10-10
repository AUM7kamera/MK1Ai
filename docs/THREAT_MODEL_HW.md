# Hardware-compromise threat model

**Status:** design artifact; not an evaluation result. No hardware security
feature is a prerequisite for the software security design or a basis for
raising an assurance/profile claim.

## 1. Threat T.HW_COMPROMISE

The attacker may have physical access; DMA capability; malicious supply-chain
components or implants; compromised UEFI, BMC, ME/PSP, NIC, SSD, USB-controller,
or microcode firmware; extracted TPM, secure-enclave, or FIDO2-held secrets;
side-channel or fault-injection capability (including Spectre-class, Rowhammer,
cache, power, and timing attacks); or control of the host, hypervisor, VM,
Crostini, or cloud runtime.

The defensive objectives are to limit the blast radius, detect compromise
where independent evidence permits, and support recovery. A fully compromised
endpoint cannot provide reliable confidentiality or integrity for data
available to that endpoint. Hardware-rooted evidence reported by the endpoint
itself is not independent evidence.

## 2. Trust rules

- TPM, secure enclave, Secure Boot, IOMMU, dm-verity, IMA/EVM, HVCI, and FIDO2
  may be used only as optional additional layers. Their presence, absence, or
  self-reported status does not raise the software assurance profile.
- Do not accept local attestation or self-integrity reports as proof of a
  trustworthy endpoint. Independent verification must use a separate verifier
  and a fresh challenge; its own independence and compromise risks must be
  assessed.
- Do not keep a complete long-term secret on one endpoint. A hardware-held
  factor is not a substitute for the mandatory user factor and is assumed
  readable by the attacker in the formal model.
- Software controls must remain defined when hardware factors are absent. A
  hardware factor may be combined with user and optional authenticator
  material, but its absence must not prevent the user-only design from
  operating. The lower strength of that mode must be made visible.
- A compromised endpoint may lie about quarantine, policy, measurements, and
  audit state. External witnesses and independently operated nodes are
  needed to constrain this risk; they do not guarantee endpoint integrity.

## 3. Inventory of current hardware-related behavior

This is a source/document inventory, not a runtime or hardware test.

| Area | Observed state | Evidence and boundary |
|---|---|---|
| TPM2, Secure Boot, IOMMU, dm-verity, IMA/EVM, HVCI | No enforcing implementation found in the inspected source. They appear as proposed environment requirements in the ST draft. | `docs/ST.md` previously listed TPM2, Secure Boot, and IOMMU as required platform controls. No measured-boot verifier, quote verifier, verity setup, or IMA policy implementation was located. |
| WebAuthn / FIDO2 | Passkey registration and authentication are implemented for the remote dashboard. They do not establish authenticator hardware type, attestation trust, quorum approval, or resistance to a compromised endpoint. | `mk1_remote_dashboard.py` uses the `webauthn` registration/authentication APIs. Dashboard login must not be treated as a hardware trust assertion. |
| Quarantine release | A partial 2-of-2 or 2-of-3 Ed25519 signature check is implemented for a persisted challenge. It does not verify node architecture/OS diversity, custody, operator identity, or a three-of-three S2 quorum. | `mk1_quarantine.py`, `mk1_quorum.py`, `mk1_quorum_cli.py`, `docs/QUORUM_APPROVALS.md`. Signer independence and out-of-band public-key enrollment remain operational requirements, not machine-verified facts. |
| Application secure transport and user-rooted derivation | The Python RSI transport derives AES-256-GCM keys with HKDF-SHA256 from ML-KEM-768 shared secret material. The C tunnel is also identified as ML-KEM-768. Standalone Argon2id user-rooted derivation, SLIP-39 Shamir backup, an ML-KEM-1024/X25519/WireGuard-PSK combiner, a bounded message-ratchet helper, and device/purpose key-derivation and signed-revocation validation helpers are present, but none is integrated with existing transport or operator flows. | `mk1_secure_transport.py`, `mk1_tunnel.c`, `mk1_key_derivation.py`, `mk1_key_backup.py`, `mk1_hybrid_kem.py`, `mk1_session_ratchet.py`, `mk1_key_registry.py`. WireGuard integration is not proof that the application protocol has the requested three-layer construction. |
| Secret memory controls | `mk1_memory_guard.py` includes process core/ptrace controls, a `TracerPid` polling thread, `mlock`, `MADV_DONTDUMP`, and `explicit_bzero` support for mutable buffers. These are process-local best-effort controls, not hardware protection. | Polling can miss short-lived attachment and cannot defeat a compromised kernel/hypervisor or physical side channels. Whole-system swap policy is not established by these helpers. |
| External verification, quorum, and witness | Quarantine release has partial 2-of-2/2-of-3 signature verification. A standalone external verifier prototype can measure a read-only filesystem against a signed manifest with a fresh nonce. Neither feature provides independent state/policy/log comparison, profile computation, durable nonce replay state, network gating, or an audit-head witness. | Targeted signatures do not establish signer/verifier independence or endpoint integrity. Filesystem measurement does not verify live memory or firmware. Self-reported status and local hashes are not independent verification. |
| Formal hardware-compromise model | No ProVerif/Tamarin model or verified correspondence to implementation was found before this change. | A restricted ProVerif 2.05 model now executes in the pinned CI container; its symbolic scope and lack of implementation correspondence are documented in `formal/README.md`. |

The inventory is scoped to the repository source and checked-in documentation;
it does not establish what may be configured on a deployed host.

## 4. Assurance profiles

Profiles are based on software controls and independent-node properties only.
Optional hardware features are shown separately and never increase the profile.

| Profile | Definition |
|---|---|
| S0 | Single node. No independent mutual verification. A complete endpoint compromise defeats endpoint-local confidentiality and integrity. |
| S1 | At least two nodes mutually verify fresh state. Independence and quorum are limited; a shared failure domain can defeat both. |
| S2 | At least three nodes with independent architectures and operating systems participate in quorum verification/approval. Independence is an operational claim requiring evidence, not a device self-report. |

No profile is currently claimed or automatically computed by the product.

## 5. Recovery and residual risk

On suspected hardware or endpoint compromise, treat local reports as
untrusted; suspend sensitive operations; revoke affected endpoint credentials
from an independent authority; rotate affected keys; preserve externally
witnessed evidence; and rebuild from an independently verified offline
provisioning source. The manual recovery guidance is in
`HARDWARE_COMPROMISE_RUNBOOK.md`; signed-image production, independent
revocation authority, and tested recovery flow are not yet implemented.

Hardware compromise can defeat protections implemented solely on the affected
endpoint. Side-channel resistance, malicious firmware detection, physical
tamper detection, and independent-verifier security require separate
evaluation. Metadata such as traffic timing and volume may remain exposed even
when payloads are encrypted. Where feasible, prefer controlled one-way media
transfer; this operational practice is not a hardware data diode and does not
prove unidirectionality.

## 6. Current change record

| Purpose | Changed files | Tests/evidence | Residual risk |
|---|---|---|---|
| Record hardware threat assumptions and distinguish source-level presence from deployed assurance. | `docs/THREAT_MODEL_HW.md`, `docs/ST.md`, `docs/ASSURANCE_GAPS.md` | Source/document inventory only; no hardware or deployment test. | Inventory may not reflect locally modified or deployed systems; independent verification, implementation, and recovery remain gaps. |
