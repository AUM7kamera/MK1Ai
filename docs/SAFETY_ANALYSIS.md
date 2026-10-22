# MK1Ai safety analysis

**Status date:** 2026-10-22
**Status:** Initial hazard analysis for review. This document is a design
artifact, not evidence of safe operation, a certification, or a functional
safety claim. MK1Ai does not provide or claim SIL capability.

## Scope and method

This analysis considers operators, administrators, users, people represented
in telemetry or logs, and people affected by equipment or operational
networks. It is based on repository documentation and source inspection. No
production deployment, hardware, OT network, recovery drill, or safety
validation was performed.

Priority is a triage order, not a measured risk score. Likelihood and impact
cannot be quantified without the target asset, environment, and operating
procedures. Unknown, stale, or unverified status must not be treated as
normal. Controls described as present below are repository-level observations;
they are not evidence that a control is effective in a deployed environment.
`Critical` identifies plausible immediate physical harm or loss of the only
recovery path; `High` identifies potentially severe availability, integrity,
privacy, or security impact; `Medium` identifies misleading status that can
contribute to unsafe decisions.

## Hazard scenarios

| ID | Priority | Scenario | Causes and potential impact | Current safeguards observed | Residual risk and required evidence |
|---|---|---|---|---|---|
| H1 | Critical | Automatic isolation interferes with factory control or safety-instrumented communications | A detection, watchdog, USB response, or administrator action disables a control-network interface or route. This can interrupt process control, alarms, interlocks, or operator visibility and may cause injury or equipment damage. | Repository guidance describes logical isolation and notes deployment limitations. No approved OT-specific exclusion/approval boundary was confirmed in the inspected implementation. | Do not auto-block or disable OT control/safety paths. Require asset-specific hazard analysis and authorized on-site operator approval before any change. Verify non-interference on representative equipment; this repository provides no functional-safety assurance. |
| H2 | Critical | Administrator lockout during isolation or recovery | `--no-dry-run`, all-interface isolation, a USB/HID deny policy, bad safe-harbor configuration, quorum loss, or an update can remove the only usable management path. | README warns that active isolation can cut SSH and advises disposable Linux VMs. Safe-harbor policy, persisted quarantine, quorum release, and USB recovery guidance exist in code/tests/docs. | No end-to-end, out-of-band recovery drill on target hardware was confirmed. Require an independently usable console/serial path, tested break-glass with strong authentication, full audit/notification, and a recovery runbook before enabling disruptive controls. |
| H3 | High | Self-denial-of-service from false positive or faulty automation | A false detection, untrained AI output, parser error, watchdog, or faulty policy causes a broad block or interface shutdown. Operations and recovery may be interrupted. | Dry-run is documented; local adaptation is documented as disabled; some network-policy and quarantine tests exist. | The whole detection-to-action path, false-positive impact, external watchdog behavior, approval gates, and OT behavior remain unverified. AI must remain advisory; use notification → observation → operator approval → scoped rule-based action. |
| H4 | High | User data corruption or loss during update, quarantine, or recovery | Partial writes, power loss, failed update/rollback, key loss, or restoring corrupted state can destroy configuration, audit records, or user data. | Release signing/verification helpers and atomic quarantine-state handling are documented; backup and recovery guidance exists. | A/B update, power-loss consistency, rollback, backup restoration, key-recovery, and end-to-end data integrity are not established. Require tested atomic updates, verified backups, rollback, and fault-injection evidence before deployment. |
| H5 | High | Excessive collection or exposure of packet contents and personal data | DPI logs can include packet details and a payload hex sample; IP addresses and remote-view telemetry may identify people or reveal network activity. | Full packet inspection is disabled by default as an environment option; packet-log creation uses restrictive modes in inspected code; some map events omit non-global addresses. | Suspicious packets can still be logged when the inspection option is off. Retention, deletion, encryption-at-rest, access audit, disclosure/consent, and IP retention have not been established. Keep payload inspection off by default and do not enable logging until purpose, scope, access, encryption, and retention are approved. |
| H6 | High | Remote viewing exposes sensitive status or persists without operator awareness | A remote session, compromised browser/client, weak origin/session controls, or lack of revocation/visibility may expose status and personal/network data. | The dashboard has authentication and session expiry described in README; inspected POST routing limits the login role to authentication/logout endpoints and status is served through an authorized GET. | Session inventory/revocation, trusted-source enforcement, idle expiry under all conditions, login notification, dedicated audit, and always-visible local indicator were not confirmed end to end. Server-side read-only enforcement and local visibility must be tested. |
| H7 | High | Spoofed, suppressed, or misleading security notification | An attacker forges a notice, a mail/SMS destination is changed, or delivery fails silently. Operators may take unsafe actions or miss an intrusion. | Dashboard authentication uses Passkey and email/SMS OTP according to README. | Success-login notification, reauthentication for destination changes, notification to the old destination, anti-phishing content, delivery-failure handling, and air-gap behavior are not fully confirmed. Notifications must contain no OTP, token, session identifier, or link; delivery failure must be visible and not silently reported as success. |
| H8 | High | Update failure weakens isolation or leaves inconsistent state | A failed, interrupted, malicious, or stale update changes enforcement, breaks management access, or leaves data/configuration partially updated. | Release signing and verification scripts exist. | A/B rollout, anti-rollback, canary deployment, atomic activation, and tests proving that enforcement and recovery survive update failure were not confirmed. Treat update safety as unverified until those tests pass on target profiles. |
| H9 | High | USB control causes local lockout or admits unsafe media | HID denial can remove keyboard/mouse access; composite-device classification, guest verdicts, scanner integrity, or USB policy failure can block a legitimate device or trust malicious media. | USBGuard installer/verifier and USB policy tests exist; README and runbook describe recovery limitations and treat clean scan results as low confidence. | Live hardware, boot behavior, allow-list recovery, and the scanner trust boundary are unverified. Provide a tested local recovery path; do not treat a clean scan as proof of safety. |
| H10 | High | Quorum or key failure prevents legitimate recovery or permits unauthorized release | Lost approver keys, compromised signer independence, stale/replayed challenges, or unavailable ML-DSA can deny sensitive operations or weaken approval. | Quarantine release has a documented two-signature prototype; helper modules and tests exist. | Organizational independence, break-glass, key lifecycle, ML-DSA dual-signature integration, and recovery drills are not established. Sensitive operations must fail closed on missing required cryptography while preserving observation and a separately governed recovery route. |
| H11 | Medium | False status creates unsafe confidence | A stale sensor, partial path verification, failed check, or local compromise is displayed as healthy or fully isolated. | Existing documentation distinguishes logical from physical isolation and notes unverified controls. | Consistent `unknown`/stale/failure states and end-to-end panel behavior were not confirmed. Do not show “normal” or “isolation complete” unless the required checks are fresh and complete; identify the checks and time behind the status. |

## Required safeguards before operational enablement

1. Keep disruptive features disabled by default. Present the impact scope and a
   dry-run result before any destructive or broad action; require an explicit
   confirmation and, where policy requires, two-person approval.
2. Do not use AI output as an isolation authority. Any automatic block must be
   deterministic, narrowly scoped, policy-authorized, and tested for false
   positives.
3. Never apply IT/DC assumptions to OT. Control and safety-instrumented
   communications are excluded from automatic blocking; site operators decide
   whether and how to change them.
4. Preserve a tested management/recovery path. Quorum loss or cryptographic
   capability loss may deny sensitive operations, but must not remove the
   operator's separately governed recovery route.
5. Keep packet-content inspection and retention off unless explicitly
   authorized with a stated purpose, minimal collection, approved retention,
   access control, encryption, and audit.
6. Distinguish logical isolation from physical isolation. Incomplete,
   unavailable, stale, or failed path checks produce `unknown` or `partial`,
   never “safe” or “isolation complete.”
7. Updates and recovery must be atomic or rollback-capable and must preserve
   the last known enforcement state until a verified replacement is active.

## Evidence still required

- Asset- and profile-specific hazard/risk assessment, including OT process
  hazards and management-path dependencies.
- Lab and target tests for false positives, lockout, power loss, partial
  writes, update rollback, USB/HID recovery, and quorum loss.
- Independently operated break-glass and out-of-band recovery drills.
- Privacy review specifying packet/IP collection, retention, deletion,
  encryption, access, audit, and user disclosure.
- Verified dashboard read-only behavior, session revocation, authentication
  notification, and persistent local remote-view indicator.
- Evidence that all relevant logical paths are checked before declaring
  logical isolation, plus a separate physical inspection record where needed.
