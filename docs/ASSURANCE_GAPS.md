# Assurance gaps and verification status

**Status date:** 2026-10-10
**Assurance statement:** No Common Criteria certification, EAL7 conformance,
evaluation, or achievement is claimed. This inventory is not a substitute for
an independent evaluation.

## Current change record

| Item | Purpose | Changed files | Tests/evidence | Residual risk |
|---|---|---|---|---|
| Part 1.1 | Remove whole-ruleset nftables flushes; apply a dedicated `inet mk1ai_quarantine` table as one `nft -f -` transaction without deleting `mk1ai_egress`. | `airgap_ai_defender.py`, `airgap_ai_defender_6.py`, `mk1_firewall.py`, `tests/test_airgap_ai_defender.py`, `tests/test_airgap_ai_defender_6.py`, `tests/integration/test_firewall_netns.py`, `.github/workflows/build-release.yml`, `Makefile` | Full Python suite: 253 passed, 2 skipped, 51 subtests passed. Both privileged namespace integration tests passed with `sudo`; they cover egress-table preservation, safe-harbor-only TCP reachability, idempotency, and failed-batch rollback. `make check` passed. CI builds pinned liboqs and `make check-ci` refuses to run without it. | Local native runner skipped liboqs/ML-KEM because liboqs is not installed here; `make check-ci` therefore failed at its deliberate dependency gate. CI execution has not been observed. Target nftables versions, distribution firewall-manager interactions, boot ordering, and production traffic remain unverified. |
| Part 1.5 | Validate IP addresses with `ipaddress`, ports as bounded integers, and pass the safe-harbor plan into policy generation without shell interpolation. | `mk1_firewall.py`, `airgap_ai_defender.py`, `tests/test_airgap_ai_defender.py`, `tests/integration/test_firewall_netns.py`, `README.md` | The full Python suite passed as above; namespace tests verified permitted TCP reaches only the configured safe-harbor endpoint and non-permitted TCP/UDP is dropped. The management path is **TCP only** by decision. | A deployment must independently confirm that the selected TCP endpoints suffice. No production host or management application was tested. |
| Part 1.2 | Persist quarantine in a root-owned atomic state file, apply a drop policy before recording a new quarantine transition, disable all verified logical paths at boot, and order network units after the gate. Release requires two distinct public-key signatures. | `mk1_quarantine.py`, `mk1_airgap.py`, `airgap_ai_defender.py`, `security/systemd/`, `security/install-quarantine-guard.sh`, `tests/test_quarantine.py`, `tests/test_airgap_ai_defender.py` | Included in the full Python suite. `systemd-analyze verify` passed for the service unit; shell syntax passed. Tests cover root-owned mode, restart persistence, invalid state, failed policy, approval failure and network-unit dependencies. | FIDO2 ceremonies, enrollment/revocation, signed audit records, crash/power-loss behavior on target storage, installer execution, and effective startup ordering on each supported network manager are not hardware/deployment verified. |
| Part 1.3 | Enumerate interfaces, rfkill Wi-Fi/BT radios, modem sysfs devices, Thunderbolt devices, and prohibited modules; block/remove them and install a verified modprobe blacklist. Thunderbolt domains are required to verify `dpon`; built-in compressed module entries are recognized. Failure to enumerate or verify any applicable path prevents completion. | `mk1_airgap.py`, `mk1_quarantine.py`, `security/systemd/mk1ai-quarantine.service`, `security/install-quarantine-guard.sh`, `tests/test_airgap_paths.py` | Included in the full Python suite; mocked tests cover interface/radio failures, missing Bluetooth rfkill, built-in module refusal (including `.ko.xz`), Thunderbolt `dpon`, blacklist contents, and successful enumeration flow. Logical isolation is explicitly distinguished from physical isolation in `README.md` and `docs/PHYSICAL_ISOLATION.md`. | No Wi-Fi/BT, modem, USB-network, Thunderbolt, built-in-driver, or real kernel-module hardware test was performed. This is not physical isolation; follow and record the separate physical procedure. |
| Part 1.4 | Set USB default authorization to zero, configure USBGuard default deny, deny every HID interface, and allow only an exact storage-only interface set (rejecting composite devices). | `security/usbguard/`, `security/install-usb-guard.sh`, `security/verify-usb-guard.sh`, `mk1_usb_guard.py`, `tests/test_usb_guard.py`, `README.md` | Unit tests exercise USB classification and check the exact USBGuard policy shape. Installer/verifier shell syntax and post-boot verification branches are checked; live USBGuard parser/service and reboot behavior remain target checks. | USBGuard package/version support, bootloader integration, controller behavior, and physical USB devices were not tested. Installation requires an approved package and Debian/Ubuntu `update-grub`; execute the verifier and test actual USB device outcomes after reboot. |
| Part 1.6 | Remove the scan nonce from guest kernel arguments and bind a scan response to a per-run, owner-only host UNIX socket channel. Accept only a local socket peer whose PID and UID match the launched QEMU process. | `mk1_usb_guard.py`, `security/usb-scan-guest/usb-scan-init`, `tests/test_usb_guard.py`, `README.md` | Included in the full Python suite. Tests assert no nonce appears in guest kernel arguments, the per-run host channel, QEMU peer credential binding, strict verdict syntax, duplicate rejection, and bounded channel output. | A guest necessarily controls its own verdict output; peer credentials identify the local QEMU process but do not attest that ClamAV reported honestly. ClamAV `clean` is a low-confidence signal, not proof of benign content. Real QEMU/KVM/USB pass-through was not tested. |

## Required remediation/evidence backlog

“Gap” means the requested claim is not yet established by integrated,
reproducible evidence. Some files contain partial prototypes; a source-level
prototype is not equivalent to an enforced or verified system property.

| # | Status | Missing implementation/evidence required |
|---:|---|---|
| 1 | Partial; namespace integration tested | Verify target-host nftables versions, distribution firewall-manager interactions, boot ordering, and production packet behavior. |
| 2 | Partial; unit-tested, deployment unverified | Execute installer on each supported target, verify durable storage and actual systemd ordering/failure behavior, and complete FIDO2-based two-person enrollment, revocation, audit, and recovery. The current release prototype verifies two distinct public-key signatures; it does not implement FIDO2 ceremonies. |
| 3 | Partial; mocked only | Test radios, USB-network drivers, modems, Thunderbolt security-level changes and module unload/block behavior on supported physical hardware. Confirm the service can write required sysfs controls and that each target kernel reports every path. No result is physical isolation. |
| 4 | Partial; mocked/source-tested only | Install USBGuard and reboot supported systems; validate daemon configuration and rules with the target USBGuard parser; verify boot-time authorization default and actual HID/composite-device rejection on hardware. |
| 5 | Partial; generation tested, runtime unverified | Confirm nftables rules on actual target hosts and decide whether TCP-only safe-harbor rules cover required operations. |
| 6 | Partial; unit-tested only | Exercise the per-run host UNIX socket with the signed QEMU guest and real USB pass-through. The host-side channel token is not sent in guest-readable state; guest verdict remains untrusted. ClamAV “clean” is a low-confidence signal only. |
| 7 | Gap | Separate advisory AI from enforcement. Implement and test deterministic rate/frame-length/signature rules, staged responses, and operator approval. AI-selected privileged actions are not acceptable as the security policy. |
| 8 | Gap | Disable local adaptation by default. Before enabling, require signed checkpoints, robust outlier exclusion, rate limits, and rollback. A `.sha256` sidecar alone is not an authenticity mechanism. |
| 9 | Gap | Display SHA-256 fingerprint of the Proxmox credential ID and require a documented out-of-band operator confirmation before registration. |
| 10 | Gap | Finalize and migrate every application crypto path to the requested WireGuard + ML-KEM-1024 + AES-256-GCM/HKDF-SHA-384-or-stronger profile; require WireGuard preshared keys/Rosenpass and keepalive; test interoperability. Current source/report indicates ML-KEM-768 and SHA-256 remain. Cryptographic profile and compatibility are not approved. |
| 11 | Gap | Add client signatures (ML-DSA-87, or explicitly evaluated hybrid if immature), and implement replay rejection on both client and server with tests. |
| 12 | Gap | Install a systemd egress/input default-drop policy before WireGuard and prove ordering, fail-closed startup, and the only permitted `oifname`/endpoint paths. Existing template alone is not an installed unit. |
| 13 | Gap | Restrict control IPC with `SO_PEERCRED`, enforce root ownership of parent directories, remove weakening operations, and test peer credentials and path replacement races. |
| 14 | Gap | Set the requested nginx TLS 1.3 groups and run a pre-start OpenSSL 3.5+ capability/version check; test startup refusal on unsupported builds. |
| 15 | Gap | Make air-gap builds exclude RSI/Colab/cloudflared/Drive/SMTP/SMS code and dependencies; inspect resulting artifacts and test feature exclusion. |
| 16 | Gap | Provide signed offline ClamAV database import, verification, atomic rollback, and failure tests. |
| 17 | Gap | Move AF_PACKET/Python to observation-only outside the TOE; provide a separate XDP/eBPF enforcement plan and state clearly that the datapath is unimplemented. |
| 18 | Gap | Pin every GitHub Action by commit SHA; make unit/C tests, fuzzing, and static analysis mandatory; set Bandit to medium-or-higher and test CI gate behavior. The current workflow is not SHA-pinned. |
| 19 | Gap | Add reviewed lockfiles and hash-enforced installation, pin `cryptography`, and document/complete the pqcrypto-to-liboqs/OpenSSL 3.5 ML-KEM migration evaluation. |
| 20 | Gap | Move release signing to offline/HSM/Sigstore controls, distribute public trust anchors out-of-band, and produce reproducible builds and signed SBOMs with retained provenance. |
| 21 | Gap | Audit panel process launch and replace `execlp` lookup of `sudo`/`ip` with validated absolute paths; add tests. |
| 22 | Partial prototype; assurance gap | Document `TracerPid` limitations and implement/test encrypted or disabled swap. Existing memory guarding does not prove whole-system secret confidentiality. |
| 23 | Gap | Provision Secure Boot and TPM2 measured boot, seal keys to approved PCRs, verify TPM quotes locally, and test network refusal on tamper. No hardware-backed evidence is present. |
| 24 | Gap | Build read-only dm-verity root, separate and harden state/log mounts (`noexec,nosuid,nodev`), and verify IMA/EVM policy against deployed files. |
| 25 | Gap | Baseline and verify requested kernel hardening, module signature enforcement, delayed `modules_disabled`, IOMMU/DMA protection and sysrq policy on supported hardware. |
| 26 | Gap | Build/enforce MAC, seccomp-bpf, Landlock, namespace and cgroup-v2 boundaries around a minimal SF core and separately privileged workers. Python is currently privileged in security-sensitive flows. |
| 27 | Gap | Enroll at least two distinct FIDO2 keys, enforce quorum for each listed operation, and create signed audit entries with recovery/revocation tests. |
| 28 | Gap | Implement SF heartbeat watchdog with defined stages/timeouts and fail-closed quarantine; test crash, stall, restart and avoid unsafe automatic release. |
| 29 | Gap | Define strict JSON Schema, reject unknown fields, authenticate configuration signatures and bind accepted configuration to audit records. |
| 30 | Gap | Implement append-only hash-chain audit, periodic signatures, tamper detection, signed export, and tests proving secrets/packet payloads are omitted. |
| 31 | Gap | Deploy canary credentials/files and alerting; add exponential backoff and alert tests for dashboard authentication failures. |
| 32 | Gap | Approve root-to-purpose key hierarchy, TPM/HSM sealing, rotation/revocation/backup, and verify `mlock`, `MADV_DONTDUMP`, and explicit zeroization across all key buffers. |
| 33 | Gap | Add constant-time comparisons, startup KATs, entropy-source health checks, and monotonic-counter replay protection independent of NTP in air-gap mode. |
| 34 | Gap | Implement signed A/B updates, protected anti-rollback counter, power-loss recovery, and downgrade tests. |
| 35 | Partial; broad gap | Inventory all parser boundaries; bound length, depth, time and resource use; establish libFuzzer/AFL++ targets and CI corpus. Evaluate a memory-safe-language rewrite for the SF core. |
| 36 | Gap | Add property/state-machine tests and fault-injection for partial writes, power loss, concurrency and restart recovery. |

## EAL evidence not yet available

- **ASE:** this draft ST is not an approved Security Target; TOE boundary,
  assumptions, SPD, and component-level SFR mapping require baselining.
- **ADV_SPM/FSP/TDS/ARC:** no complete formal policy model, TLA+/Isabelle/Coq
  proof, verified tool/version record, or formal-to-code correspondence exists.
- **ADV_IMP/ATE:** no bounded SF-core complexity report or complete real-device
  test evidence for USB, NIC, WireGuard, TPM2, power loss, and concurrency.
- **AVA_VAN.5:** no independent vulnerability analysis, penetration-test
  results, or side-channel evaluation plan/results from an evaluation body.
- **ALC:** configuration-management, controlled build/release, developer
  environment, delivery, and defect-correction evidence is incomplete.
- No evaluator submission package, laboratory findings, or certification
  decision is available.

## Decisions recorded as unresolved

1. Supported Linux distribution/kernel, nftables, systemd, OpenSSL, WireGuard,
   hardware, and hypervisor versions.
2. Management safe-harbor protocols, ports, address ownership and recovery
   behavior; current implementation emits TCP-only scoped rules.
3. Physical isolation steps and which indicators can truthfully establish
   logical versus physical isolation.
4. Final post-quantum algorithms, OpenSSL/provider deployment, WireGuard
   preshared-key/Rosenpass policy, and backward-compatibility window.
5. Operator enrollment, two-person separation, loss/revocation recovery, and
   FIDO2 key custody.
6. Which external services and feature flags are excluded from an air-gap
   build, and how artifact exclusion is independently checked.

Until these gaps are closed and independently evaluated, the implementation
must be described as a prototype with unverified controls, not an EAL7 TOE.
