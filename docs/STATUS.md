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
| Runtime config schema | 修正・ローカルテスト済み | Configuration reads are capped at 64 KiB; unknown keys, invalid values, malformed/deep JSON, and read errors are rejected rather than partially ignored at startup. Invalid live panel updates are logged and do not replace the last applied tunnel, memory-guard, or map settings. |
| CI workflow integrity | 部分修正・静的確認済み | Removed stray Markdown fences from the workflow and pinned all seven `uses:` references to verified action commit SHAs. YAML parses locally; GitHub Actions execution remains unverified. |
| Tunnel control IPC | 部分修正・ローカルテスト済み | The UNIX socket now requires Linux `SO_PEERCRED` UID match and a parent directory owned by the service/operator with no group/world write permission. Unauthorized peer and writable-parent regression tests pass. |

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

- `python3 -m pytest -q tests/test_airgap_ai_defender.py tests/test_firewall_nft.py`:
  145 passed, 20 skipped, 4 subtests passed after adding direct-path and
  recovery-failure regression checks.
- `python3 -m pytest -q`: 325 passed, 17 skipped, 58 subtests passed.
- `python3 -m pytest -q tests/test_map_visualization.py`: 8 passed.
- `.github/workflows/build-release.yml`: YAML parse passed; every `uses:` reference is SHA-pinned. CI has not been run.
- `python3 -m py_compile airgap_ai_defender.py mk1_map.py mk1_firewall.py mk1_quarantine.py`:
  passed.
- `make panel`: fresh rebuild passed with `-Wall -Wextra -Werror`.
- `make test`: native runner and unit tests passed; liboqs and C ML-KEM-768
  were skipped because liboqs is not installed.
- `python3 airgap_ai_defender.py --no-dry-run`: refused with the expected
  per-event approval-not-implemented error.
- `git diff --check`: passed.
- CI, privileged netns tests, hardware, and OT/non-interference tests have not
  been run for this change.
