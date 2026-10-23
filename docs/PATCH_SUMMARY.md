# Throughput design verification patch summary

## Scope

This patch only adds throughput-capacity arithmetic, design/evidence documents,
and related tests. It does not change MK1Ai's production packet processing,
encryption, authentication, AI detection, isolation, offline behavior, or
security policy.

## Changes

* `scripts/performance_capacity.py`: exact rational arithmetic, validated
  positive input, deterministic JSON generation, per-mode cost/power ranges,
  conditional fabric-cut link-count sensitivity scenarios, and a generic
  post-failure `min(node, fabric)` evaluator for arbitrary installed counts.
* `docs/performance-capacity.json`: generated node-count scenarios for
  0.4/0.8/1.2/1.6 Tbps/node and fabric-link sensitivity cases, including
  generator source hash.
* `tests/test_performance_capacity.py`: formula/ceiling/failure/monotonicity,
  invalid-input, target sensitivity, fabric-link failure invariants, all four
  insufficient/sufficient node/fabric outcomes and tied bottlenecks,
  per-node link-budget invariants, deterministic JSON and Markdown parity.
* `docs/THROUGHPUT_DESIGN.md`: one-way goodput boundary, AI/crypto placement
  acceptance boundary, separate headroom definitions, updated capacity table.
* `docs/PERFORMANCE_ASSUMPTIONS.md`: assumptions, fabric sensitivity,
  cost/power scope and exclusions.
* `docs/NETWORK_FAILURE_ANALYSIS.md`: node/rack/ToR/spine/link/power/cooling/
  control-plane/common-mode failure model and undefined inputs.
* `docs/PERFORMANCE_BENCHMARK_PLAN.md`: isolated physical test stages, metrics,
  manifests, evidence and acceptance gate.
* `docs/PERFORMANCE_VALIDATION_RESULTS.md`: evidence classification and
  unmeasured items, including the latest Codespaces hardware/tool readiness
  inventory.
* `docs/STATUS.md`: updated the performance-target evidence pointer and
  retained the unachieved/unverified state.

No remote synchronization, commit, push, merge, rebase, or release operation was
performed. Pre-existing unrelated modified and untracked worktree files were
preserved.

## Verification status

The arithmetic has independent expected-value tests and generated JSON is
compared with node, fabric, joint-capacity, and component-measurement Markdown
tables. The capacity suite passed 15 tests/97 subtests; the complete Python
suite passed 351 tests, skipped 17, and passed 159 subtests. JSON syntax,
generator determinism and `git diff --check` passed. See
[`PERFORMANCE_VALIDATION_RESULTS.md`](./PERFORMANCE_VALIDATION_RESULTS.md) for
the tested commands and evidence limitations.
