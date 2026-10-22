# Safety-state design by operating profile

**Status date:** 2026-10-22
**Status:** Proposed design for review. This is not an approved operational
profile or evidence that a running system enforces these states. No safety
integrity level or functional-safety capability is claimed.

## State vocabulary

The interface and logs should distinguish these states by text and timestamp,
not color alone:

| State | Meaning |
|---|---|
| `NORMAL` | Required status sources are fresh and report no active incident. This does not mean “safe” or guarantee protection. |
| `WARNING` | A rule or operator reported a concern. No disruptive response has yet been applied. |
| `OBSERVING` | Evidence is being collected under the approved, minimal-collection policy. AI may advise but cannot authorize blocking. |
| `ACTION_PENDING` | A scoped response is proposed. Show targets, excluded paths, expected impact, dry-run result, and required approvers. |
| `ISOLATION_PARTIAL` | Some policy was applied, but one or more required routes or controls are unverified, unavailable, or failed. |
| `LOGICAL_ISOLATION_VERIFIED` | The profile's applicable software-controlled paths have fresh positive verification. This is logical isolation only, not physical isolation. |
| `PHYSICAL_ISOLATION_VERIFIED` | An authorized human completed the asset-specific physical procedure and recorded the inspection. Software alone cannot set this state. |
| `RECOVERY_PENDING` | Recovery or release was requested and awaits the profile's approvals and checks. Existing enforcement remains in place unless an authorized recovery procedure changes it. |
| `UNKNOWN` | A required source is unavailable, stale, inconsistent, or cannot be verified. Never present this as `NORMAL` or “isolation complete.” |

Every status transition must include a timestamp, source, and reason that do
not expose credentials or packet contents. A failed verification must be
visible. Notifications supplement, but do not replace, enforced controls.

## Profile-specific safe states

| Profile | Failure or suspected compromise | Isolation behavior | Recovery and approval |
|---|---|---|---|
| IT / data center | Show `WARNING`, `OBSERVING`, or `UNKNOWN` according to evidence freshness. Preserve a tested administrative/break-glass path. | A pre-approved, tested profile may apply narrowly scoped rule-based egress isolation while retaining its management safe-harbor and out-of-band path. Broad all-interface shutdown is not the default. If path ownership, impact, or policy application is unknown, require operator review and do not claim isolation. | Require scope preview and explicit operator approval for disruptive actions; require two-person approval where the site's policy classifies the action as sensitive. Keep quarantine on failed release and provide an independently tested console/serial recovery path. |
| Factory / OT | The safe state is site- and process-specific; an application-level network block is not presumed safe. Notify the responsible operator and show `UNKNOWN` if the process state cannot be verified. | Automatic blocking, interface shutdown, USB-network disablement, or alteration of control/safety-instrumented communications is prohibited by this design. Default behavior is observation and notification. A site operator follows the approved plant emergency/change procedure and assesses hazards before action. | Only authorized on-site operations personnel approve changes to control paths. Recovery follows the plant procedure and verifies control, safety, alarms, and operator visibility before resumption. MK1Ai does not replace safety instrumented functions or provide SIL assurance. |
| Government / high-control environment | Until the authority, classification, data-handling rules, and approved operating profile are documented, status is `UNKNOWN`; external notifications and remote viewing remain disabled by default. | Do not infer that internet isolation, whole-network blocking, or any particular fail-open/fail-closed policy is safe. Apply only a formally approved, asset-specific profile; otherwise remain in observation and require the designated authority to decide. | Define and test named approval roles, out-of-band recovery, evidence custody, and notification channels before enablement. Legal, classification, export-control, and accreditation decisions require the responsible experts/authority. |

## Cross-profile invariants

1. Assess people, equipment, data, and management access affected by an
   automatic action before enabling it. A notification is not a mitigation.
2. Default disruptive modes to dry-run/off. Display impact scope before
   execution; use explicit confirmation and two-person approval as required
   by the profile.
3. Never let a failed or stale check become a healthy result. If path
   enumeration or policy verification is incomplete, use `UNKNOWN` or
   `ISOLATION_PARTIAL`.
4. Do not call logical isolation physical isolation. `PHYSICAL_ISOLATION_VERIFIED`
   requires a separate, authorized inspection record using
   [the physical isolation procedure](./PHYSICAL_ISOLATION.md).
5. Do not automatically remove active quarantine after an update failure,
   failed signature check, quorum loss, or incomplete recovery.
6. Provide an independently usable recovery route before enabling controls
   that can interrupt networking, USB/HID, or administrator access. Break-glass
   use requires strong authentication, complete audit, and notification.
7. The remote console is not a recovery path. If local status cannot be
   determined, display `UNKNOWN`; do not conceal the condition.

## Review and acceptance checklist

- [ ] Operations owners approve the IT/data-center profile and identify its
  safe-harbor and out-of-band recovery paths.
- [ ] OT owners approve an asset-specific hazard assessment and confirm that
  control and safety-instrumented paths are excluded from automatic action.
- [ ] The government/high-control authority defines its profile, or that
  profile remains disabled and unavailable.
- [ ] Each profile defines action authority, two-person approval thresholds,
  data retention, notification behavior, and recovery ownership.
- [ ] Fault-injection and recovery drills verify the state transitions,
  operator visibility, and lockout protections on representative systems.

Until these items are reviewed and tested, this design remains proposed and
operational enablement must not imply that the product is “safe.”
