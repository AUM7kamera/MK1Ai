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
  Management workstation / two operators / FIDO2 keys
  Remote peer / WireGuard endpoint / external services
  AI, Python, PyTorch, DPI, AF_PACKET observation, dashboard
  Hardware, UEFI/Secure Boot, TPM2, NIC/USB controllers
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

### Assumptions and unresolved environment requirements

- Administrators provision the evaluated hardware and maintain physical
  control; the precise physical-isolation procedure is not yet defined.
- Required kernel, nftables, WireGuard, USBGuard, TPM2, Secure Boot, FIDO2,
  OpenSSL, and hypervisor versions are not baselined.
- Network peer identity, management-address ownership, allowed management
  protocols, and recovery paths are not yet specified.
- Physical, firmware, side-channel, and hardware fault resistance require
  evaluation-lab evidence; source tests cannot establish these properties.

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
- **O.AUTHORIZE:** require the defined two-operator authentication for
  quarantine release, key rotation, and security-sensitive configuration.
- **O.DEVICE:** default-deny USB interfaces and other non-network device paths.
- **O.CRYPTO:** use approved, authenticated cryptographic protocols, enforce
  freshness/replay protection, and protect and erase secrets.
- **O.AUDIT:** record security decisions in tamper-evident, privacy-minimized
  audit data and detect audit failure.
- **O.UPDATE:** accept only authenticated updates and prevent unauthorized
  rollback.
- **O.MINIMIZE:** keep security enforcement in a small, privilege-separated SF
  core; treat Python/AI/DPI as untrusted advice.
- **O.FAIL_CLOSED:** on missing evidence, failed checks, or loss of the SF
  watchdog, deny network and device access.

### Objectives for the operational environment

- **OE.PLATFORM:** provision and verify Secure Boot, TPM2, IOMMU, hardened
  kernel, immutable root filesystem, mandatory access control, and resource
  confinement.
- **OE.OPERATORS:** enroll and safeguard two distinct FIDO2 authenticators and
  verify recovery procedures.
- **OE.PHYSICAL:** apply the documented physical air-gap and tamper procedures.
- **OE.SUPPLY_CHAIN:** protect offline/HSM signing keys, build inputs, release
  provenance, and out-of-band trust-anchor distribution.
- **OE.EVALUATION:** independently verify the target platform, TOE boundary,
  implementation correspondence, tests, and vulnerability analysis.

## 4. Security Functional Requirements (provisional)

The following are requirement statements for a future ST baseline, not claims
that the implementation currently satisfies them.

| ID | Requirement |
|---|---|
| SFR-ACCESS | Identify and authenticate operators and local IPC peers; authorize each security-sensitive action. |
| SFR-QUARANTINE | Apply default-deny ingress, egress, forwarding, and peripheral policy; verify effective state before reporting completion. |
| SFR-PERSIST | Store quarantine and monotonic freshness state in protected persistent storage; network startup must fail closed on absent/invalid state. |
| SFR-APPROVAL | Require two distinct enrolled FIDO2 credentials for release, key rotation, and protected configuration changes. |
| SFR-CRYPTO | Provide authenticated encryption, key separation, key lifecycle and erasure, and two-sided replay rejection using the finalized cryptographic profile. |
| SFR-CONFIG | Strictly validate signed configuration against a closed schema; reject unknown fields and invalid values. |
| SFR-AUDIT | Produce append-only, hash-chained and periodically signed audit records; detect tampering and export safely. |
| SFR-UPDATE | Verify update signatures and prevent rollback using protected monotonic state. |
| SFR-FAILSAFE | Loss of the SF heartbeat or a required platform check shall cause bounded, fail-closed quarantine. |
| SFR-ADVISORY | AI, DPI, and packet-observation results may inform operators but shall not independently grant access or initiate destructive action. |

The Common Criteria component mapping, dependencies, refinement rationale, and
final SFR wording are not established. A certifier/evaluation authority must
review the final ST.

## 5. Formal policy properties to verify

The policy state machine and implementation correspondence are not yet
available. At minimum, the formal model and test suite shall address:

1. In `QUARANTINED`, no external packet is transmitted.
2. An unauthorized USB device/interface never enters the data path.
3. A destroyed/revoked key cannot be used for later operations.
4. Every accepted application message traverses all finalized cryptographic
   layers and passes freshness checks at both endpoints.
5. `RELEASED` is unreachable without two distinct, valid approvals.
6. Any invalid/missing persistent state, failed verification, or expired SF
   heartbeat denies network activation.

## 6. Assurance status

This document is a draft requirements artifact only. There is no validated TOE
boundary, formal verification result, independent penetration test, laboratory
report, or Common Criteria evaluation result. See
[`ASSURANCE_GAPS.md`](./ASSURANCE_GAPS.md) for implementation status, evidence
needed, and unresolved decisions.
