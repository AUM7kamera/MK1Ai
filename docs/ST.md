# MK1Ai Security Target (Draft)

**Status:** working draft for requirements/evidence planning; not an evaluated or
approved Security Target. **No Common Criteria certification, EAL claim, or
achievement is asserted.**

## 1. TOE identification and scope

The target platform, operating-system image, hardware configuration, supported
interfaces, and evaluated configuration have not been baselined. These remain
open decisions. This draft records the intended security objective, not a
verified product boundary.

The intended TOE is a small security-function (SF) core that applies
authorization, quarantine, cryptographic-key, and audit policy. Python,
PyTorch, packet/DPI parsing, AI models, cloud/Colab/RSI integrations, and
visualization are intended to remain outside the TOE and advisory-only. That
separation does not yet exist: the current Python application can invoke
privileged network operations. Until privilege and policy enforcement are
separated, the intended boundary below must not be treated as the implemented
boundary.

```text
                    Outside the proposed TOE
  Management workstation / two operators / optional authenticators
  Remote peer / WireGuard endpoint / external services
  AI, Python, PyTorch, DPI, AF_PACKET observation, dashboard
  Hardware and firmware (untrusted; optional controls are not trust roots)
  Kernel, nftables, USBGuard, hypervisor, boot/update infrastructure
                              |
                              | authenticated, constrained IPC
                              v
  +----------------------------------------------------------+
  | Proposed TOE: minimal C/Rust SF core                    |
  | policy/state machine | authorization | key interface    |
  | nftables/USB policy controller | audit/update verifier  |
  +----------------------------------------------------------+
```

The diagram is aspirational. It does not imply that the listed controls are
implemented, trusted, or verified. In particular, no end-to-end correspondence
between the proposed SF core and current source has been established.

## 2. Security problem definition

### Threats

- **T.NETWORK_BYPASS:** an unauthorized interface, route, service, or firewall
  change sends or receives traffic while the system is intended to be isolated.
- **T.UNAUTHORIZED_DEVICE:** an unauthorized USB interface or other peripheral
  becomes a data path or injects input.
- **T.STATE_LOSS:** reboot, crash, partial write, or power loss clears quarantine
  or leaves a network-start path open.
- **T.UNAUTHORIZED_ADMIN:** one operator or an unauthenticated local process
  changes policy, releases quarantine, rotates keys, or modifies configuration.
- **T.REPLAY_OR_FORGERY:** stale messages, unsigned updates, configuration, or
  audit data are accepted as current and authentic.
- **T.COMPROMISED_ADVISOR:** AI/DPI/model errors or compromised advisory
  components cause unsafe enforcement.
- **T.SUPPLY_CHAIN:** compromised dependencies, build tools, actions, signing
  keys, or release artifacts alter the evaluated configuration.
- **T.PLATFORM_FAILURE:** kernel, firmware, hypervisor, physical access, or
  hardware faults bypass software controls.
- **T.HW_COMPROMISE:** an attacker extracts hardware-held secrets or controls
  firmware, DMA-capable devices, side channels, the endpoint, or its host/
  hypervisor. Endpoint-local confidentiality and integrity cannot be assured
  after complete endpoint compromise. Payload encryption does not conceal
  traffic timing, volume, destination, or other network metadata. Prefer
  controlled one-way media transfer where practical; this is operational
  guidance, not a verified data diode. See the
  [hardware-compromise runbook](./HARDWARE_COMPROMISE_RUNBOOK.md).

### Assumptions and unresolved environment requirements

- The supported software, kernel, nftables, WireGuard, USBGuard, OpenSSL, and
  hypervisor versions are not baselined.
- Hardware, firmware, boot measurements, attestation, and hardware-held
  secrets are not trusted prerequisites. They may be used only as optional
  additional layers and cannot raise an assurance profile.
- Local self-attestation and self-integrity reports are not independent
  evidence. Independent verification requires a separately operated verifier
  and fresh challenge; that verifier remains within the threat model.
- An endpoint under complete physical, firmware, hypervisor, or side-channel
  control cannot provide endpoint-local confidentiality or integrity for data
  available to it. External verification can limit or detect some effects but
  cannot establish that the endpoint is uncompromised.
- Network peer identity, management-address ownership, allowed management
  protocols, and recovery paths are not yet specified.
- An external-verifier measurement prototype reads files from a read-only
  target tree against a signed build manifest, but neither reproducible
  manifests nor a deployed verifier, durable challenge ledger, report
  consumer, or network-activation gate exists.
- Remote user-factor and WireGuard-PSK provisioning for the RSI/Colab protocol
  is not specified. The live transport migration is blocked until a reviewed
  provisioning protocol is approved; no legacy-algorithm fallback is implied.
- Physical isolation, firmware, side-channel, and hardware fault resistance
  require evaluation-lab evidence; source tests cannot establish these
  properties.
- The current cryptographic transport does not implement the requested
  three-layer profile end to end. Traffic metadata remains exposed even when
  payload encryption is used; the software-only objective cannot claim
  metadata confidentiality.

### Security Problem Definition (SPD)

The TOE shall prevent unauthorized network and device paths; preserve
quarantine through restart and failure; enforce authenticated multi-operator
administration; protect keys and security state; reject replayed or
unauthenticated configuration and updates; create privacy-minimized,
tamper-evident audit records; and ensure advisory AI cannot independently
authorize or bypass enforcement.

## 3. Security objectives

### Objectives for the TOE

- **O.QUARANTINE:** deny all unapproved ingress, egress, forwarding, and device
  paths; report isolation complete only after required controls are verified.
- **O.PERSIST:** retain root-protected quarantine state across restart and make
  network activation depend on its validated state.
- **O.AUTHORIZE:** require fresh, generation-bound approvals from distinct
  enrolled operator/node keys for quarantine release, key rotation, and
  security-sensitive configuration; reject operations below the configured
  quorum threshold.
- **O.DEVICE:** default-deny USB interfaces and other non-network device paths.
- **O.CRYPTO:** use approved, authenticated cryptographic protocols, enforce
  freshness/replay protection, and protect and erase secrets.
- **O.AUDIT:** record security decisions in tamper-evident, privacy-minimized
  audit data and detect audit failure.
- **O.UPDATE:** accept only authenticated updates and prevent unauthorized
  rollback.
- **O.MINIMIZE:** keep security enforcement in a small, privilege-separated SF
  core; treat Python/AI/DPI as untrusted advice.
- **O.ADVISORY_ONLY:** AI, model, and composite anomaly scores shall not
  independently cause packet blocking, quarantine, or a privileged action.
  Enforcement rules must be deterministic, bounded, and separately reviewed.
- **O.FAIL_CLOSED:** on missing evidence, failed checks, or loss of the SF
  watchdog, deny network and device access.

### Objectives for the operational environment

- **OE.SOFTWARE_BASELINE:** define and independently verify the supported
  software versions and deployment configuration. Hardware security features
  are optional and are not a prerequisite for the software security design.
- **OE.OPERATORS:** maintain distinct operator identities and independent
  approval credentials, and verify recovery procedures. FIDO2 authenticators
  may be used as an optional factor but their hardware properties are not
  assumed.
- **OE.PHYSICAL:** apply the documented physical air-gap and tamper procedures.
- **OE.SUPPLY_CHAIN:** protect offline signing keys, build inputs, release
  provenance, and out-of-band trust-anchor distribution.
  HSMs may be an optional additional layer but are not trusted prerequisites.
- **OE.EVALUATION:** independently verify the target platform, TOE boundary,
  implementation correspondence, tests, and vulnerability analysis.

### Software-only assurance profiles

These intended profile definitions do not claim that any profile has been
implemented or achieved. Optional hardware features are reported separately
and do not raise a profile.

| Profile | Basis |
|---|---|
| S0 | Single node; no independent mutual verification. Complete endpoint compromise defeats endpoint-local confidentiality and integrity. |
| S1 | At least two independently operated nodes mutually verify fresh state and approve protected operations. Shared failure domains remain a material risk. |
| S2 | At least three independently administered nodes with distinct architectures and operating systems participate in a three-node quorum for protected operations. Independence requires external evidence and cannot be asserted by a node about itself. |

The current product does not compute or claim S0/S1/S2. Its partial quarantine
release implementation checks two distinct signatures from a roster of two or
three Ed25519 keys; it does not establish the independence properties required
for S1 or enforce three-of-three S2 approval. See
[`THREAT_MODEL_HW.md`](./THREAT_MODEL_HW.md) for the threat inventory and
residual-risk statement.

## 4. Security Functional Requirements (provisional)

The following are requirement statements for a future ST baseline, not claims
that the implementation currently satisfies them.

| ID | Requirement |
|---|---|
| SFR-ACCESS | Identify and authenticate operators and local IPC peers; authorize each security-sensitive action. |
| SFR-QUARANTINE | Apply default-deny ingress, egress, forwarding, and peripheral policy; verify effective state before reporting completion. |
| SFR-PERSIST | Store quarantine and monotonic freshness state in protected persistent storage; network startup must fail closed on absent/invalid state. |
| SFR-APPROVAL | Require fresh quorum approvals from distinct enrolled node/operator keys for release, key rotation, and protected configuration changes. Optional FIDO2 factors do not establish hardware trust. |
| SFR-KEY-ROOT | Derive protected root material from a mandatory user factor using Argon2id and bind optional hardware/authenticator factors without making them sole trust roots. |
| SFR-HYBRID-KEM | Combine ML-KEM-1024, X25519, WireGuard PSK material, and the complete protocol transcript using the finalized HKDF profile; reject incomplete or downgraded exchanges. |
| SFR-SESSION-LIFETIME | Use per-session ephemeral inputs and bounded directional ratchets with strict sequence/replay checks, message/time limits, and key destruction. |
| SFR-KEY-SEPARATION | Derive distinct per-device, per-purpose keys by generation; verify signed revocation manifests and reject stale generations. |
| SFR-CRYPTO | Provide authenticated encryption, key separation, key lifecycle and erasure, and two-sided replay rejection using the finalized cryptographic profile. |
| SFR-CONFIG | Strictly validate signed configuration against a closed schema; reject unknown fields and invalid values. |
| SFR-AUDIT | Produce append-only, hash-chained and periodically signed audit records; detect tampering and export safely. |
| SFR-UPDATE | Verify update signatures and prevent rollback using protected monotonic state. |
| SFR-FAILSAFE | Loss of the SF heartbeat or a required platform check shall cause bounded, fail-closed quarantine. |
| SFR-ADVISORY | AI, DPI, and packet-observation results may inform operators but shall not independently grant access or initiate destructive action. |

The Common Criteria component mapping, dependencies, refinement rationale, and
final SFR wording are not established. A certifier/evaluation authority must
review the final ST.

The current Python packet pipeline makes model/composite scores advisory;
they do not independently trigger a block or kill switch. The limited fixed
rules include a frame-size ceiling, a small payload-marker list, parser
failure handling, source blacklist, and explicit ONI mode. This is not a
complete evaluated enforcement policy: staged responses, operator approval
for disruptive actions, rate-policy coverage, and implementation
correspondence remain open.

## 5. Formal policy properties to verify

The policy state machine and implementation correspondence are not yet
available. A restricted hardware-compromise model is maintained in
[`formal/proverif/hardware_compromise.pv`](../formal/proverif/hardware_compromise.pv)
and was run with ProVerif 2.05. The symbolic results and assumptions are listed
in [`formal/README.md`](../formal/README.md). They cover payload secrecy while
the user factor remains secret, hardware/FIDO factor disclosure, user-only
operation, and two injective message correspondences. They do not establish
the implementation properties below; the policy state machine, its
implementation mapping, and independent review are still missing. At minimum,
formal models and tests shall address:

1. In `QUARANTINED`, no external packet is transmitted.
2. An unauthorized USB device/interface never enters the data path.
3. A destroyed/revoked key cannot be used for later operations.
4. Every accepted application message traverses all finalized cryptographic
   layers and passes freshness checks at both endpoints.
5. `RELEASED` is unreachable without the configured quorum of distinct,
   valid approvals.
6. Any invalid/missing persistent state, failed verification, or expired SF
   heartbeat denies network activation.
7. The current symbolic model supports only the narrow case where hardware and
   FIDO factors are disclosed and the user factor remains secret; it does not
   model user-factor compromise.
8. Later compromise of long-term factors does not reveal completed session
   keys, and replayed handshakes are rejected. This remains unmodeled and
   unverified.

## 6. Assurance status

This document is a draft requirements artifact only. The restricted symbolic
model result is not a formal verification of the TOE or implementation. There
is no validated TOE boundary, independent penetration test, laboratory report,
or Common Criteria evaluation result. See
[`ASSURANCE_GAPS.md`](./ASSURANCE_GAPS.md) for implementation status, evidence
needed, and unresolved decisions.
