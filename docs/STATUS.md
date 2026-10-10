# STATUS

This file records implementation state only. Nothing here is a certification,
conformance claim, or statement that a goal is "achieved".

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

## Not started (pending approval / decisions)
B, C (awaiting confirmation), D, E, F, G. Undecided: item 10 loopback/local TCP
mode, item 17 fail-visible vs fail-closed when ML-DSA is unavailable.
