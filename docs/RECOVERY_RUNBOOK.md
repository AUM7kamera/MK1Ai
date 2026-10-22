# Network isolation and administrator recovery runbook

**Status:** operational guidance. Recovery procedures and break-glass controls
are not independently validated on target hardware. This document does not
authorize a specific network or OT action.

## Current active-isolation limitation

Active isolation is disabled in this version. `--no-dry-run` is rejected, the
panel's active-isolation action does not start a monitor, and detections marked
`APPROVAL_REQUIRED` do not alter firewall or network state. A pending approval
is not isolation and does not confirm that a threat was contained. Do not
attempt to enable active isolation by changing configuration or calling
internal functions.

Before any future release enables it, the asset owner must identify the system
role and paths, approve the scoped policy, test local/serial recovery, test
management safe-harbor where applicable, and complete the site's OT hazard
assessment. Dry-run testing must happen in a disposable environment first.

## If an isolation attempt fails or management access is lost

1. Treat a failed, partial, stale, or unavailable verification as `UNKNOWN`,
   not as proof of successful isolation. Do not repeat the action blindly or
   broaden it by disabling additional interfaces.
2. Use the approved local console or serial path. If there is no usable
   independent path, dispatch an authorized on-site operator; do not assume a
   remote recovery is possible.
3. Record the asset, time, operator, requested action, visible state, and
   failure reason in the controlled incident record. Do not include passwords,
   OTPs, tokens, session identifiers, private keys, or packet payloads.
4. Preserve the existing firewall/quarantine state while an authorized
   operator assesses it. Do not flush firewall rules or remove a quarantine
   policy as a troubleshooting shortcut.
5. In an OT environment, consult the site's control-room/emergency procedure
   before restoring, stopping, or changing any control path. Verify alarms,
   control, safety functions, and operator visibility under that procedure.
6. For a quarantine release that is supported by the installed version, use
   the enrolled approvers and the procedure in
   [QUORUM_APPROVALS.md](./QUORUM_APPROVALS.md). Confirm signer identity and
   the change out of band. If required cryptography, quorum, or state
   verification is unavailable, do not bypass it; keep sensitive operations
   refused and use the separately approved recovery authority.
7. After recovery, verify the intended routes and policy from an independent
   management point, confirm the operator can reach the system, and record
   which checks passed or remain unknown. Do not report physical isolation
   unless the separate physical inspection was completed.

## Break-glass requirements

Break-glass must be separately provisioned and tested before deployment. It
requires strong authentication, narrowly assigned authority, complete audit
without secrets or payloads, and notification through an approved channel.
Keep the recovery credential and path independent from the protected
endpoint. A break-glass procedure that has not been exercised is an
unverified recovery path, not a safeguard.

This repository does not yet enforce every requirement in this runbook. In
particular, target-specific console/serial availability, break-glass
authentication and notification, power-loss recovery, and end-to-end
lockout drills remain deployment evidence gaps.
