# Application onboarding intake

| | |
|---|---|
| Scope | Every new application, or a material change to an existing one (new data class, auth method or integration). Contoso Health (fictional 5,000-user hospital, lab scenario) |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering runs the intake. The app's business owner is accountable ([raci.md](raci.md), "SSO / SCIM app onboarding") |

An app goes live only when every field has an answer and every rule is met,
or the gap is on the [exception register](exception-process.md) with an end
date.

## Intake form

| # | Field | Allowed answers | Rule |
|---|---|---|---|
| 1 | Business owner | A named person | Accountable for who gets access and for the review. **No owner, no onboarding** |
| 2 | Technical owner | Two people, or one plus a team group | Owns SSO configuration, certificates, provisioning and the app's NHIs (NHI standard N1) |
| 3 | Data classification | PHI · PCI · PII · internal · public | Drives fields 6, 8 and 9. "Don't know" counts as PHI |
| 4 | Sign-in protocol | OIDC (preferred) · SAML 2.0 · **exception** | No SSO means an exception with an end date, MFA inside the app and a quarterly review of local accounts. PHI apps never use password-based SSO |
| 5 | Local accounts | None, or a list | At most one local emergency admin, vaulted in PAM. Any other is an exception |
| 6 | Provisioning | SCIM · API · manual with a ticket | SCIM by default. Manual only below 50 users, with a monthly reconciliation. **The leaver path is tested before go-live.** PHI apps deprovision on demand |
| 7 | Roles → groups → packages | One `App-<Application>-<Role>` group per app role | Access only by group, each fed by an access package: automatic (birthright) if HR attributes decide it, otherwise requestable with approval and expiry. SoD pairs declared up front. In-app admin roles go through PIM for Groups |
| 8 | Review tier ([ADR 0012](../adr/0012-access-review-no-response-and-clinical-lockout.md)) | T1 privileged · T2 requestable · T3 birthright clinical | Every role in field 7 has a tier. Clinical PHI apps that clinicians need on shift are T3 for their core roles, so they are never removed on reviewer silence |
| 9 | Conditional Access | Baseline · targeted policy | Never excluded from CA001 or CA008 without an exception. PHI apps reached from shared devices fall under CA060 |
| 10 | NHIs created | Service principal, credential type, API permissions, secrets outside Entra (SCIM token, API key) | Federated credential, then certificate (12 months or less, in Key Vault). A client secret is an exception (N2); Tier-0 permissions need a risk acceptance (N6). **Each credential has an owner and an expiry** in the NHI inventory or the secrets register. Admin consent through the workflow only |
| 11 | Logging | Sign-in logs plus app audit logs to the SIEM | Required for PHI and PCI apps, or the gap goes on the exception register |
| 12 | Rollback | How to revert sign-in and provisioning | Written before go-live |

## Go-live checklist

Each item has evidence on the change ticket: a screenshot, a query result or
a plan link.

- [ ] Fields 1–12 complete; exceptions approved with end dates.
- [ ] SSO tested by a non-admin test user; the CA report-only result shows
      the app in scope of CA001 and CA008.
- [ ] Joiner, mover and leaver tested through provisioning; the leaver ends
      disabled or deleted in the app, with timestamps.
- [ ] Access packages published with approver, expiry and review tier; no
      direct user assignments.
- [ ] NHI rows exist with owners and credential expiry dates; certificate
      expiry alerts go to a group.
- [ ] Logs arrive in the SIEM.
- [ ] Any local emergency account is vaulted and its check-out tested.

## Worked example: AWS IAM Identity Center (lab)

- **Fields 4 and 6:** SAML SSO and SCIM provisioning, BUILT as code
  (`modules/apps`; the SCIM job is created stopped). What stays human:
  activating the signing certificate, the AWS identity-source switch, the
  SCIM token into Key Vault and one local seeding apply
  (`lab/terraform/README.md`, human step 7).
- **Field 7:** `App-AWS-IdentityCenter-Users` maps to the `ViewOnlyAccess`
  permission set (`lab/terraform/aws/`).
- **Field 8:** T2.
- **Field 10:** the SCIM token is a long-lived secret outside Entra, so it
  is in the secrets register (`aws-scim-token`) with an owner and a rotation
  date.
