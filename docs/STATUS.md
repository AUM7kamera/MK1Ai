# STATUS

This file records implementation state only. Nothing here is a certification,
conformance claim, or statement that a goal is "achieved".

## Safety analysis and profile safety states (2026-10-22)

| Item | State | Evidence / remaining work |
|---|---|---|
| S1: hazard scenarios | 実装あり未検証 | Initial hazard analysis is recorded in `docs/SAFETY_ANALYSIS.md`. It is a repository-based design artifact only; deployment hazards, likelihood, impact, and control effectiveness require asset-specific review and tests. |
| S2: profile safety states | 実装あり未検証 | Proposed IT/data-center, factory/OT, and government/high-control states are in `docs/SAFETY_STATES.md`. They are not operationally enforced or finally approved; review checklist and representative recovery/non-interference tests remain open. |
| S3: active-isolation impact preview | 部分実装・未検証 | A preview helper remains for tests/reference but is not exposed in the live path. Active enforcement is disabled because startup-only consent is not per-event approval. No profile or deployment is authorized by this change. |
| S4: operator-approved response | 未実装・fail-closed | The proposal and evidence gate are in `docs/OPERATOR_APPROVAL_DESIGN.md`; approval threshold and profile authority remain undecided. Standard CLI/panel monitoring is Dry-Run; if the internal threat evaluator receives active intent it sets `APPROVAL_REQUIRED` without dispatching isolation. `--no-dry-run`, panel `[3]`, and direct non-dry-run kill-switch/generated-payload calls are refused; the USB threat callback does not change network/tunnel state. Per-event approval, an actionable review queue, audit custody, and an operator action to resolve pending state remain unimplemented. |
| H5: packet payload persistence | 修正・ローカルテスト済み | Full packet inspection log writes now require `FULL_PACKET_INSPECTION=1`; suspicious findings alone do not persist packet bytes. Focused regression test confirms no log file is created with the flag disabled. Retention, deletion, encryption-at-rest, and access audit remain undecided/unverified. |
| H5: DPI finding token minimization | 修正・ローカルテスト済み | Signature `token` fields are omitted from persisted detailed inspection records and console warnings, even when full inspection is explicitly enabled. Regression test verifies both sinks and that the original DPI result remains unchanged. |
| Map WebSocket Origin allowlist | 修正・ローカルテスト済み | Chrome extension Origin must exactly match a configured `MK1_MAP_EXTENSION_ORIGIN`; an unset/empty allowlist rejects all extension connections. Focused handshake test covers the empty allowlist. |
| AI data file permissions | 部分修正・ローカル確認済み | Removed executable bits from tracked JSON data; runtime config, curated data, and local adaptation checkpoint are no longer tracked, while local files are preserved. Current `ai_data` directories/files are owner-only. `run.sh` creates the directory as `0700`, writes config atomically as `0600`, and has a regression assertion for that mode. Prior repository history is unchanged. |
| Runtime config schema | 修正・ローカルテスト済み | Configuration must be a regular file owned by the effective/operator UID and not group/world writable; symlinks are rejected. Reads are capped at 64 KiB; unknown keys, invalid values, malformed/deep JSON, and read errors are rejected. Invalid live panel updates preserve the last applied settings. |
| CI workflow integrity | ローカル検証済み・GitHub再実行待ち | Removed stray Markdown fences and pinned all eight remaining `uses:` references to full commit SHAs. Corrected the legacy netns jobs to use distro Python/pytest rather than a Python 3.12 build incompatible with Debian 12/Ubuntu 22.04 glibc, and made the privileged integration step use the explicit setup-python interpreter. YAML and both distro-container test matrices pass locally. The corrected workflow has not yet run on GitHub because this worktree is unpublished and GitHub CLI is unauthenticated. |
| Tunnel control IPC | 部分修正・ローカルテスト済み | The UNIX socket now requires Linux `SO_PEERCRED` UID match and a parent directory owned by the service/operator with no group/world write permission. Unauthorized peer and writable-parent regression tests pass. |
| Panel data directory permissions | 修正・ネイティブテスト済み | C panel now creates/opens `ai_data` without following a final symlink, requires the effective-user owner, and enforces mode `0700` before reading or writing configuration/log data. Native tests cover creation, restrictive repair, symlink refusal, and non-directory refusal. |
| Remote dashboard rate-limit capacity | 修正・ローカルテスト済み | The in-memory per-client/per-route rate-limit table now rejects new keys at capacity instead of evicting an existing client's active bucket. Existing buckets remain effective under key churn; entries are reclaimed after the configured window. Focused dashboard tests pass. The bound is process-local and does not coordinate across workers/restarts. |
| Remote dashboard stale-status indication | 修正・ローカルテスト済み | The producer now writes a source snapshot timestamp; the dashboard rejects missing timestamps, snapshots older than 10 seconds, or timestamps over 5 seconds in the future. Failed/non-success/malformed refreshes raise a visible warning; malformed recognized fields invalidate freshness even when the timestamp was written first. Focused dashboard suite: 21 passed. The producer clock and status source are not independently validated. |
| Python dependency lockfiles | 修正・ローカルテスト済み | Added Python 3.12 pip-compile locks with artifact hashes for runtime, CPU-only model, CI, and release-build dependencies; pinned `cryptography`, `requests`, PyTorch, NumPy, and psutil; documented refresh/install procedures in `docs/DEPENDENCY_LOCKS.md`; and switched workflow Python installs to `--require-hashes`. Clean Python 3.12 model+CI lock installation and `pip check` passed; full Python suite with model dependencies: 340 passed, 6 skipped, 58 subtests; Bandit medium+ scan passed locally. GitHub CI execution and dependency provenance review remain outstanding. |
| Runtime dependency installation | 修正・ローカルテスト済み | Startup now checks for optional Python modules and reports missing dependencies but never invokes pip or downloads packages. Regression test asserts no subprocess install occurs; full Python suite with model dependencies passes (340 passed, 6 skipped, 58 subtests). CPU-only model dependencies are available through a dedicated hash-locked feature set; they must be installed before startup. |
| GUI / remote-dashboard audit | 部分完了・ソース確認のみ | `docs/GUI_AUDIT.md` records the current browser dashboard's roles, routes, observed security controls, usability/safety gaps, and required owner decisions. It is an inventory, not an approved UX specification or deployment assessment. No product GUI work or control action was enabled. |
| Commercial readiness procedures | 下書き・未承認 | `docs/COMMERCIAL_READINESS.md` supplies PSIRT intake, release QA, support/lifecycle, legal/export-control, and OSS-review worksheets. No owner, channel, SLA, legal conclusion, or operational process is assigned or approved. |
| Provisional ST traceability | 部分完了・文書草案 | `docs/REQUIREMENTS_TRACEABILITY.md` maps each provisional SFR to located source/test evidence and explicitly records gaps. It is source inventory only, not an approved SFR baseline, implementation correspondence, independent review, or evaluation evidence. |
 codespace-laughing-journey-96qwxx6659vq2x4qg
| 超大容量通信目標 (1.6 Tbps/device, 5 Pbps aggregate) | 未達成・未検証 | `docs/THROUGHPUT_DESIGN.md` specifies one-way authenticated application-payload goodput, candidate crypto/inspection/AI boundary, and design analysis. `docs/performance-capacity.json` is deterministically generated by `scripts/performance_capacity.py` and includes exact-rational node counts, node-only cost/power assumptions, conditional fabric-link sensitivity, and joint node/fabric post-failure capacity bounds; Mode A (post-failure utilization <=80%) is adopted and Mode B (capacity 1.2x target) is a separate comparison. The joint model is a scalar `min(node, fabric)` arithmetic bound, not topology simulation or physical availability evidence. Physical capacity, full-fabric costs, and power remain unverified. Local loopback reports and three-repeat diagnostics remain synthetic and are not production throughput evidence. Detailed assumptions, failure cases, benchmark procedures, and validation status are in `docs/PERFORMANCE_ASSUMPTIONS.md`, `docs/NETWORK_FAILURE_ANALYSIS.md`, `docs/PERFORMANCE_BENCHMARK_PLAN.md`, and `docs/PERFORMANCE_VALIDATION_RESULTS.md`. Neither target is achieved or verified; no scale-out extrapolation is claimed. |

 main

## A. nftables compatibility
- `destroy table` removed from `mk1_firewall.py` / `mk1_quarantine.py`.
  Apply = `add table` → `delete table` → `add table` … in one `nft -f -` batch;
  release = `add table` → `delete table` in one batch (`remove_nft_policy`).
- Startup/apply-time check: `nft --version` must parse and be >= 0.9.0;
  otherwise apply/remove return False (fail-closed; caller treats as not
  isolated) and the reason is logged and stored in `mk1_firewall.last_nft_failure`.
  Minimum 0.9.0 is a conservative choice, not verified against 0.8.x. (未検証)
- Tests: tests/test_firewall_nft.py (unit), tests/integration/test_firewall_netns.py
  (idempotence, atomic failure, removal keeps `mk1ai_egress`).
- CI: new `nft-legacy-netns` job (Debian 12, Ubuntu 22.04 containers, `--privileged`).
  The job has NOT yet run on GitHub: 未検証.
- Local sandbox (nft 1.0.9): unit tests pass; the existing traffic-policy
  netns test fails in this sandbox before and after this change (環境依存、原因未調査).

## Historical status note

The preceding nftables and pending-work notes were recorded before 2026-10-22
and have not been revalidated as part of the S1/S2 document change. The prior
ML-DSA availability question is superseded by the confirmed decision: refuse
sensitive operations when ML-DSA-87 is unavailable, maintain quarantine, and
allow observation-only operation. Ed25519-only fallback requires explicit
two-person opt-in and must remain visibly identified. Other historical test
and CI statements must not be treated as current results until refreshed.

## Current safety-gate validation (2026-10-22)

- `python3 -m pytest -q`: 329 passed, 17 skipped, 58 subtests passed in the
  current environment. The focused hardware-compromise simulation, firewall,
  threat-gate, and quarantine tests: 168 passed, 14 skipped, 13 subtests.
- The clean Python 3.12 environment with hash-locked CI and CPU model
  dependencies previously passed: 340 passed, 6 skipped, 58 subtests;
  `pip check` passed.
- `python3 -m pytest -q tests/test_map_visualization.py`: 8 passed.
- The pinned liboqs 0.15.0 commit `97f6b86b1b6d109cfd43cf276ae39c2e776aed80`
  built locally. `make check-ci` passed with liboqs required, including
  ML-KEM-768 availability and the C ML-KEM-768/AES-256-GCM round trip;
  OpenSSL, libsodium, libbpf, ptrace, tunnel, memory-guard, path-trust, and
  Clang static-analysis checks also passed. `make -B panel` rebuilt the
  native panel against liboqs with `-Wall -Wextra -Werror`.
- The nftables namespace unit/integration tests passed inside disposable,
  read-only-source Debian 12 and Ubuntu 22.04 containers with only
  `NET_ADMIN`/`SYS_ADMIN` capabilities: 5 unit and 3 integration tests per
  image. The host-level gated test was not run because this Codespace is
  non-root; no host network rules were changed.
- The latest available GitHub run for the earlier published snapshot
  (`38aad95a1675e3a772d7d7caa6e2b892b761eaf4`) completed with failures:
  the standard-runner netns step selected `/usr/bin/python3` under `sudo`
  and could not import pytest; the Debian 12 and Ubuntu 22.04 jobs tried to
  start setup-python's glibc 2.38-dependent Python inside older-glibc
  containers. The workflow was corrected and the two matrix environments
  now pass locally, but GitHub has not run this corrected worktree: the
  branch is not published and `gh auth status` reports no login.
- Hardware and OT validation remains limited to offline/mock simulations.
  This Codespace exposes `/dev/kvm` but has no QEMU executable, USB devices,
  or serial-device nodes; no target hardware, control network, plant process,
  or site-specific recovery path was accessed or tested. The KVM device node
  alone is not hardware or OT validation.
- `.github/workflows/build-release.yml`: YAML parse passed; all eight
  remaining `uses:` references are pinned to full commit SHAs.
- `python3 -m py_compile airgap_ai_defender.py mk1_map.py mk1_firewall.py mk1_quarantine.py`:
  passed.
- `python3 airgap_ai_defender.py --no-dry-run`: refused with the expected
  per-event approval-not-implemented error.
- `git diff --check`: passed.
- `tests/test_remote_dashboard.py`: 21 passed for snapshot timestamp freshness
  and stale-warning behavior. `tests/test_airgap_ai_defender.py -k panel_status`:
  2 passed.
