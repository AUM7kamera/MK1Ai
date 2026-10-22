# Operator approval for disruptive actions

**Status:** design proposal only. No approval workflow is implemented by this
document, and active isolation remains disabled.

## Current behavior

Standard CLI and panel monitoring is Dry-Run: detections are logged/previewed
without network changes and are not currently presented as an actionable
approval queue. If the internal threat evaluator is called with active intent,
it sets `APPROVAL_REQUIRED` and refuses enforcement. The CLI rejects
`--no-dry-run`, the panel's active-isolation action is disabled, the
privileged kill-switch and generated-payload helpers refuse non-dry-run calls,
and the USB threat callback does not stop interfaces or disable the tunnel.
`APPROVAL_REQUIRED` is not evidence that isolation occurred or that a threat
was confirmed.

## Approval invariants

Any future implementation must satisfy all of the following:

1. **No startup consent as action approval.** Consent to start monitoring is
   not approval for a later event or for a different action/scope.
2. **Advisory detection.** AI, anomaly scores, watchdogs, USB scan verdicts,
   and parser results may create a reviewable event, but cannot authorize a
   disruptive action. The action must be deterministic and policy-defined.
3. **Bound approval.** Approval must identify one event, one action, one
   target profile, and the exact previewed scope. Any policy, profile,
   interface, safe-harbor, or action change invalidates the approval.
4. **Fresh, single-use authorization.** An approval must expire, be
   non-replayable, and be consumed atomically before enforcement. Missing,
   stale, malformed, or unverifiable approval means refusal.
5. **Independent authorization boundary.** A compromised monitoring process,
   model, status file, or remote dashboard must not be able to manufacture
   approval. The approval authority and its credentials must be defined and
   tested independently of those components.
6. **No scope broadening on failure.** Failed or partial policy application
   must not trigger a wider fallback such as disabling all interfaces.
   Report `UNKNOWN` or `ISOLATION_PARTIAL`; never report successful isolation
   without fresh positive verification of each required control.
7. **Recovery is separate.** Approval to isolate does not authorize release.
   Release requires its own authorization, audit, and verified recovery path.
8. **Privacy-minimal audit.** Record the event identifier, timestamp, policy
   version, action/scope, approver identity reference, decision, and
   enforcement result. Do not record packet payloads, credentials, OTPs,
   tokens, or unnecessary personal/network data. Retention and deletion
   periods require an explicit owner decision before persistent audit is
   implemented.

## Profile constraints

- **IT/data center:** a future profile may define narrow, pre-approved
  deterministic actions and a tested management safe-harbor. The profile,
  approver roles, quorum, allowed targets, and recovery path must be approved
  by the asset owner. Broad all-interface shutdown is not the default.
- **Factory/OT:** automatic changes to control or safety-instrumented paths
  are prohibited by the current safety design. A site-authorized operator
  follows the plant's hazard/change procedure; this application must not
  present generic operator approval as a substitute.
- **Government/high-control:** remain `UNKNOWN` and observation-only until
  the responsible authority defines the profile, authorization roles,
  evidence custody, and permitted communications.

The approval threshold is intentionally undecided. This design does not
select one-person approval, two-person approval, or a k-of-n quorum. FIDO2
ceremonies, key enrollment/revocation, recovery from lost credentials, and
organizational independence also require policy decisions and review.

## Required state flow

`OBSERVING` → `APPROVAL_REQUIRED` → `APPROVED` or `REJECTED` → (for an
approved event only) `ENFORCING` → `LOGICAL_ISOLATION_VERIFIED`,
`ISOLATION_PARTIAL`, or `UNKNOWN`.

An expired or invalid approval returns to `APPROVAL_REQUIRED` or `UNKNOWN`;
it must never be treated as approved. A failed enforcement must not retry with
a broader action. Recovery uses a separate state transition and authorization.
Status must include a timestamp, source category, and reason while omitting
packet content and other unnecessary sensitive data.

## Implementation and evidence gate

Do not re-enable active isolation until the asset owner has decided the
profile, action scope, approver roles and threshold, approval channel,
retention, and recovery authority. Then require, at minimum:

- tests proving every detection source is advisory and cannot bypass approval;
- tests for event/action/scope binding, expiry, replay, duplicate submission,
  concurrent approval, and policy changes between approval and execution;
- authorization tests for role separation and compromised dashboard/monitor
  boundaries;
- policy-application, partial-failure, state-verification, and no-broadening
  tests in a network namespace;
- an end-to-end recovery drill on each supported target profile, including
  independent console/serial access;
- independent review of the implementation and deployment-specific evidence.

Until these decisions and gates are complete, keep active isolation disabled.
