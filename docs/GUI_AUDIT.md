# GUI and remote-dashboard audit

**Status date:** 2026-10-22  
**Status:** source-level inventory and risk review only. This is not an
approved product UX specification, accessibility assessment, penetration
test, or deployment validation.

## Scope and observed interfaces

The repository currently has a C `ncurses` panel and a Python remote dashboard.
This audit covers the browser dashboard in `mk1_remote_dashboard.py`; it does
not assess every terminal panel interaction or claim a product GUI boundary.
The Common Criteria TOE draft intends visualization to remain outside the TOE,
but that separation is not implemented or demonstrated.

The browser UI is a single-page status and authentication interface. The login
role displays a dashboard of monitoring state, packet counts, threat and
backdoor scores, mode, model/RSI state, training and adaptation state, network
interface, memory use, and last sample time. The enrollment role has a
separate passkey registration page. The authenticated dashboard offers logout
but no enforcement controls. The backend restricts login-role POST routes to
authentication, OTP verification, and logout; `POST /api/start-monitor` is
rejected, and status reads require an authenticated session.

## Controls observed in source/tests

- The backend requires a loopback bind address and checks WireGuard state and
  bind address at startup. Browser Origin is configured as HTTPS and checked
  against Host/Origin headers. The HTTP server itself is not TLS-wrapped in
  this module; deployment must provide and validate the TLS-terminating
  boundary. Its identity, configuration, and security are not established by
  the source tests.
- Authentication combines a registered WebAuthn passkey and two OTP channels.
  Enrollment uses a one-time bootstrap token. The session cookie is Secure,
  HttpOnly, SameSite=Strict and uses the `__Host-` prefix; session/CSRF
  rotation and idle/absolute expiry are implemented.
- Responses set no-store, frame, content-type, referrer, transport, resource,
  permissions, and content-security headers. The server returns only an
  allowlist of bounded status values.
- Server-side authorization, read-only route restrictions, private
  credential/bootstrap files, request size limits, and per-client/per-route
  rate limits have regression tests.
- The page always states that effective assurance is unclaimed/S0 and warns
  that the endpoint has no hardware trust and loses local confidentiality and
  integrity under complete compromise.

These are repository observations and test results, not proof of a deployed
control's effectiveness.

## Usability and safety gaps

- No approved persona, task analysis, navigation model, information hierarchy,
  language/RTL requirement, multi-tenant model, or product-level visual design
  exists. Do not infer these requirements from the current prototype.
- No accessibility audit or assistive-technology, browser-compatibility,
  keyboard-only, zoom/reflow, E2E, visual-regression, load, or chaos test was
  found. Numeric status and severity are not independently validated against
  operational meaning or a site-specific safety case.
- The dashboard polls every three seconds. The producer now places the
  observation snapshot time in the status file, and the dashboard rejects
  missing timestamps, snapshots more than ten seconds old, or timestamps more
  than five seconds in the future. Failed, non-success, or malformed responses
  raise a visible stale-data warning; it clears only after a valid, recent
  snapshot time is received. This bounded-age check does not prove sensor
  correctness or that the producer clock is trustworthy. Any malformed
  recognized field invalidates the timestamp so a partially parsed status
  file cannot clear the warning.
- Session inventory/revocation, a durable access audit, login notification,
  data-retention policy, and an always-visible local operator indicator remain
  unresolved.
- No API authorization model for future control actions exists. Do not add
  enforcement controls to this dashboard; any future control plane needs
  separately approved roles, quorum integration, audit custody, and a reviewed
  API boundary.
- No product deployment or reverse-proxy/TLS termination configuration was
  validated. The HTTPS Origin setting and browser security headers alone do
  not establish end-to-end TLS.

## Required owner decisions before product UX work

The product owner and operational stakeholders must specify:

1. Intended users, roles, critical tasks, and whether the product is
   single-tenant.
2. Supported languages, localization, accessibility target, browsers, and
   operating environments.
3. Status freshness semantics, severity vocabulary, stale/unknown behavior,
   notification/acknowledgement policy, and required operator visibility.
4. Data displayed, personal/network data classification, retention, access
   logging, and disclosure expectations.
5. API ownership, role boundaries, approval/quorum workflow, and whether the
   dashboard remains read-only.

Only after those decisions should personas, information architecture,
wireframes, and a design system be proposed for approval. Implementation,
product support claims, and safety-control enablement remain out of scope for
this audit.
