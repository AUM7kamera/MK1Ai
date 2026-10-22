# Provisional requirement-to-evidence traceability

**Status date:** 2026-10-22  
**Status:** repository-source mapping for review; not an approved requirements
baseline, implementation verification, or certification evidence.

The SFR identifiers below are the provisional requirements in
[`ST.md`](./ST.md). A source file or passing unit test establishes only that
the repository contains the referenced code or test. It does not show that
the requirement is complete, correct, integrated into a TOE, or effective in
deployment. `Gap` means no adequate implementation evidence was identified;
`Partial` means a limited mechanism or test exists but the stated requirement
is materially broader.

| Requirement | Source / test evidence | Status | Remaining correspondence and assurance work |
|---|---|---|---|
| SFR-ACCESS | [`mk1_quorum.py`](../mk1_quorum.py), [`mk1_secure_transport.py`](../mk1_secure_transport.py); `tests/test_quorum.py`, `tests/test_secure_transport.py` | Partial | No single SF authorization boundary covers every privileged/security-sensitive action. OS-independent peer identity, full action matrix, role review, and deployment validation are absent. |
| SFR-QUARANTINE | [`mk1_firewall.py`](../mk1_firewall.py), [`mk1_quarantine.py`](../mk1_quarantine.py), `tests/test_firewall_nft.py`, `tests/test_quarantine.py` | Partial | Local tests cover selected nftables rendering, failures, and release paths. Effective state across target kernels, all ingress/egress/device paths, reboot and hardware interfaces needs privileged namespace and target-hardware testing. |
| SFR-PERSIST | [`mk1_quarantine.py`](../mk1_quarantine.py), `tests/test_quarantine.py`, `tests/test_config_templates.py` | Partial | No protected monotonic freshness counter or demonstrated root-of-trust storage. Startup ordering and power-loss/replay behavior need target configuration evidence. |
| SFR-APPROVAL | [`mk1_quarantine.py`](../mk1_quarantine.py), [`mk1_quorum.py`](../mk1_quorum.py), `tests/test_quarantine.py`, `tests/test_quorum.py`, `tests/test_airgap_ai_defender.py` | Partial / enforcement gated | Selected quarantine-release signatures are checked; there is no per-event operator review queue or comprehensive integration for key rotation/configuration. Operator threshold, roles, recovery, independence, and audit custody are undecided. Active isolation remains disabled. |
| SFR-KEY-ROOT | [`mk1_key_derivation.py`](../mk1_key_derivation.py), `tests/test_key_derivation.py`, `tests/test_compromised_hardware.py` | Partial | The user-factor derivation helper has tests, but application-wide use, enrollment/recovery, factor lifecycle, zeroization coverage, and independent review are not established. |
| SFR-HYBRID-KEM | [`mk1_hybrid_kem.py`](../mk1_hybrid_kem.py), `tests/test_hybrid_kem.py` | Partial / live migration blocked | A helper exists; it is not shown to be integrated end-to-end across the live application transport. Provisioning, peer authentication, transcript binding, downgrade behavior, interoperability, and protocol review remain open. |
| SFR-SESSION-LIFETIME | [`mk1_session_ratchet.py`](../mk1_session_ratchet.py), `tests/test_session_ratchet.py` | Partial | Unit tests cover selected sequence, replay, expiry, and key-destruction behavior. The ratchet is not demonstrated as the required transport for every application path; concurrency, process restart, long-run limits, and independent protocol review remain. |
| SFR-KEY-SEPARATION | [`mk1_key_registry.py`](../mk1_key_registry.py), [`mk1_key_backup.py`](../mk1_key_backup.py), `tests/test_key_registry.py`, `tests/test_key_backup.py` | Partial | Helpers cover selected key-generation, backup, and revocation operations. Mandatory cross-application integration, durable monotonic generations, recovery, and compromise/revocation drills are not established. |
| SFR-CRYPTO | [`mk1_secure_transport.py`](../mk1_secure_transport.py), [`mk1_hybrid_kem.py`](../mk1_hybrid_kem.py), `tests/test_secure_transport.py`, `tests/test_hybrid_kem.py` | Partial / profile unresolved | Existing mechanisms do not establish the requested complete, reviewed, interoperable cryptographic profile across every network path. Key provisioning, endpoint identity, two-sided replay, rotation, and downgrade tests remain incomplete. |
| SFR-CONFIG | [`airgap_ai_defender.py`](../airgap_ai_defender.py), `tests/test_airgap_ai_defender.py`, `tests/test_scripts.py` | Partial | Runtime configuration is strictly allowlisted and bounded, but no signed closed-schema configuration with key lifecycle, provenance binding, and audit linkage is implemented. |
| SFR-AUDIT | No complete append-only, hash-chained, periodically signed audit implementation identified. | Gap | Define privacy/retention and witness policy; implement tamper evidence, durable storage, export, failure behavior, access control, and independent verification tests. |
| SFR-UPDATE | [`scripts/sign_release.py`](../scripts/sign_release.py), [`scripts/verify_release.py`](../scripts/verify_release.py), `tests/test_release_verification.py` | Partial | Bundle authenticity/inventory checks are not an installed signed-update workflow. Protected anti-rollback state, atomic activation, recovery, power-loss, and target-platform tests are missing. |
| SFR-FAILSAFE | [`airgap_ai_defender.py`](../airgap_ai_defender.py), [`mk1_firewall.py`](../mk1_firewall.py), `tests/test_airgap_ai_defender.py`, `tests/test_firewall_nft.py` | Partial | Selected failure paths refuse active actions or avoid reporting isolation on firewall failure. A separate SF heartbeat, bounded failure detection, complete platform-check list, and verified fail-closed enforcement are absent. |
| SFR-ADVISORY | [`airgap_ai_defender.py`](../airgap_ai_defender.py), `tests/test_airgap_ai_defender.py` | Partial / guarded | Tests cover selected paths where AI/USB signals cannot directly initiate isolation. A complete dataflow review is needed to show all AI/DPI outputs are advisory and no alternate privileged path bypasses per-event approval. |

## Required next evidence

1. Approve the TOE boundary, target configuration, terminology, and final SFR
   wording with the product owner and evaluator.
2. Link each refined SFR to design components, source functions, positive and
   negative tests, build artifacts, and deployment procedures. Review these
   mappings independently.
3. Add missing tests only after the underlying security policy and operator
   authority are approved. In particular, do not implement a quorum threshold,
   crypto protocol, signed-configuration trust root, or update anti-rollback
   mechanism by guessing at policy.
4. Preserve failed/skipped tests and unresolved mappings in the evidence
   package; do not convert a source reference into a satisfied requirement.
