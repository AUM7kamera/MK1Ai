# STATUS

This file records implementation state only. Nothing here is a certification,
conformance claim, or statement that a goal is "achieved".

## Safety analysis and profile safety states (2026-10-22)

| Item | State | Evidence / remaining work |
|---|---|---|
| S1: hazard scenarios | 実装あり未検証 | Initial hazard analysis is recorded in `docs/SAFETY_ANALYSIS.md`. It is a repository-based design artifact only; deployment hazards, likelihood, impact, and control effectiveness require asset-specific review and tests. |
| S2: profile safety states | 実装あり未検証 | Proposed IT/data-center, factory/OT, and government/high-control states are in `docs/SAFETY_STATES.md`. They are not operationally enforced or finally approved; review checklist and representative recovery/non-interference tests remain open. |

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
