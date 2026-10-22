# Commercial and organizational readiness pack

**Status date:** 2026-10-22  
**Status:** draft templates for organizational completion and specialist review.
Nothing in this document establishes an operating PSIRT, support commitment,
legal conclusion, export classification, regulatory applicability, or
certification.

Do not publish this as a customer policy or claim the listed processes are
operational until an authorized organization assigns owners, approves the
decisions, supplies contact channels, and exercises the procedures.

## 1. Accountable owners and decision record

Complete before external release:

| Decision | Assigned owner | Approver | Decision / evidence | Due date |
|---|---|---|---|---|
| Product owner and supported configuration | TBD | TBD | TBD | TBD |
| Security response / PSIRT lead and backup | TBD | TBD | TBD | TBD |
| Security report intake channel and access custodians | TBD | TBD | TBD | TBD |
| Vulnerability response authority and disclosure coordinator | TBD | TBD | TBD | TBD |
| Release manager and independent release approver | TBD | TBD | TBD | TBD |
| Customer support owner and escalation path | TBD | TBD | TBD | TBD |
| Product lifecycle / end-of-support authority | TBD | TBD | TBD | TBD |
| Privacy/data-protection reviewer | TBD | TBD | TBD | TBD |
| Legal and export-control counsel | TBD | TBD | TBD | TBD |
| OSS license/compliance owner | TBD | TBD | TBD | TBD |

No individual should be represented as an assigned contact solely because a
repository comment or commit names them.

## 2. Draft security-report intake and response workflow

This is a workflow template, not an active incident-response commitment. The
organization must fill in the channels, service levels, authorities, and
retention rules below before accepting reports as a supported product.

### Intake record

Create a restricted case record with:

- Unique case identifier, received timestamp, intake channel, and assigned
  responder.
- Reporter contact and requested disclosure/credit preference, stored only
  where needed and access controlled.
- Affected product/version/configuration, impact description, reproduction
  evidence, and whether the report is suspected to be public or actively
  exploited.
- Data classification, access history, evidence integrity/hash, and retention
  or deletion date according to an approved policy.
- Any conflict of interest, third-party coordination need, and legal/privacy
  escalation.

Do not request real customer secrets, credentials, personal data, or
production packet captures when a sanitized reproduction will suffice. Provide
an organization-approved encrypted transfer method before requesting sensitive
evidence.

### Proposed states

`received -> acknowledged -> triage -> confirmed | not_reproducible |
duplicate | not_applicable -> remediation -> verification -> coordinated
disclosure -> closed`

Every transition should record the decision owner, timestamp, evidence, and
next action. A reporter's allegation is not itself proof; a lack of local
reproduction is not proof that the report is invalid.

### Triage and containment checklist

1. Restrict case access and preserve the original report and evidence.
2. Identify affected assets, versions, configurations, trust boundaries, and
   potentially exposed data without probing systems outside authorization.
3. Assess confidentiality, integrity, availability, privacy, and physical/
   operational safety impact; record uncertainty and assumptions.
4. Check for signs of exploitation using authorized telemetry. Preserve
   relevant evidence without enabling disruptive containment on OT or other
   safety-critical systems.
5. Escalate suspected active exploitation, safety impact, personal-data
   exposure, cryptographic/key compromise, or legal reporting obligations to
   the designated authorities.
6. Decide whether a mitigation, advisory, affected-version list, or coordinated
   disclosure is appropriate. Do not promise a fix date before an owner has
   approved one.
7. Independently verify the remediation and release artifact; notify affected
   parties under the approved policy and applicable law.
8. Close with root cause, affected versions, disclosure record, lessons
   learned, evidence-retention disposition, and follow-up actions.

### Organizational decisions still required

- Public/private intake address and out-of-band backup channel: **TBD**
- Acknowledgement, triage, update, and disclosure targets: **TBD**
- Severity rubric and safety/escalation thresholds: **TBD**
- Coordinated disclosure policy and embargo authority: **TBD**
- Customer notification and regulatory-reporting decision owners: **TBD**
- Evidence access, encryption, retention, deletion, and privacy policy: **TBD**
- Emergency release authority and independent approval: **TBD**

Until these are approved and exercised, do not publish a security contact, SLA,
coordinated-disclosure guarantee, or claim that MK1Ai operates a PSIRT.

## 3. Draft release and quality gate

For each candidate release, record:

| Gate | Evidence to attach | Owner / approval |
|---|---|---|
| Product scope and configuration fixed | Version, source revision, OS/kernel/architecture, configuration manifest | TBD |
| Change and risk review complete | Change list, threat/safety/privacy impact, unresolved risks | TBD |
| Build inputs reviewed | Lockfiles, native toolchain/OS package list, source revisions, licenses | TBD |
| Automated checks complete | CI run links, test results, static analysis, model checks, known skips | TBD |
| Target-environment validation complete | Hardware, networking, recovery, update/rollback, accessibility and performance results | TBD |
| Security review complete | Reviewer, scope, findings, dispositions, exceptions | TBD |
| Artifact integrity and trust established | Signed manifest, signing key custody/approval evidence, public-key distribution method | TBD |
| SBOM and license review complete | Format/version, artifact linkage, completeness limitations, license decisions | TBD |
| Deployment, recovery, and support materials reviewed | Approved configuration, limitations, recovery and contact information | TBD |
| Release authorization | Independent approver and immutable record | TBD |

An empty, skipped, unavailable, or unrun check must be reported as such; it is
not a pass. A signature proves possession of a signing key over the signed
bytes, not that the build was reproducible, reviewed, safe, or produced by an
independent authority.

## 4. Support and lifecycle policy worksheet

The product owner must approve these before making support claims:

- Supported product editions, OS images, architectures, kernels, and
  deployment topologies: **TBD**
- Security-update and maintenance channels, update authenticity and rollback
  policy: **TBD**
- Supported versions, maintenance window, end-of-support notice, and migration
  guidance: **TBD**
- Support hours, response targets, severity definitions, and escalation
  contacts: **TBD**
- Customer responsibilities, prerequisites, known limitations, backup and
  recovery expectations: **TBD**
- Data collected for support, consent, minimization, transfer, retention, and
  deletion: **TBD**
- Incident communication, outage status, and vulnerability-advisory channels:
  **TBD**

No SLA, product lifetime, update availability, or customer support level is
implied by this worksheet.

## 5. Legal, regulatory, privacy, and OSS review checklist

Obtain qualified counsel and compliance review for each intended market and
customer category. This repository does not determine applicability or
compliance.

- Export-control classification, encryption reporting/licensing, destinations,
  end users, and distribution restrictions: **TBD by export-control counsel**
- Applicable product cybersecurity, privacy, safety, procurement, and sector
  rules (including whether CRA, NIS2, or sector-specific obligations apply):
  **TBD by counsel**
- Contract/EULA, warranty, liability, indemnity, privacy notices, and data
  processing terms: **TBD by counsel**
- OSS component inventory, license obligations, attribution/source-offer
  duties, notices, and distribution obligations: **TBD by qualified reviewer**
- Trademark, product naming, third-party service terms, and customer claims:
  **TBD**
- Required records, retention, incident notification, and jurisdictional
  deadlines: **TBD by counsel**

Record the reviewer, date, markets/configurations assessed, assumptions,
evidence, open questions, and decision authority. Do not infer a legal
classification or compliance status from the presence of a technical feature
or a document checklist.
