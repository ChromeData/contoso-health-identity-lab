# Application onboarding intake

| | |
|---|---|
| Scope | Every new application, or a material change to an existing one (new data class, new auth method, new integration). Contoso Health (fictional 5,000-user hospital, lab scenario) |
| Status | Draft v0.1, 2026-10-20 |
| Owner | IAM Engineering runs the intake. The app's business owner is accountable ([raci.md](raci.md), "SSO / SCIM app onboarding") |

An app goes live only when every field has an answer and every rule is met,
or the gap is on the [exception register](exception-process.md) with an end
date.

## Intake form

| # | Field | Allowed answers | Rule |
|---|---|---|---|
| 1 | Business owner | A named person | Accountable for who gets access and for the review. **No owner, no onboarding** |
| 2 | Technical owner | Two named people, or one person plus a team group | Owns SSO configuration, certificates, provisioning and the app's non-human identities (NHI standard N1) |
| 3 | Data classification | PHI · PCI · PII · internal · public | Drives fields 6, 8 and 9. "Don't know" counts as PHI |
| 4 | Sign-in protocol | OIDC (preferred for new or custom apps) · SAML 2.0 · **exception** | No SSO means an exception with an end date, MFA inside the app, and a quarterly review of local accounts. PHI apps don't use password-based SSO |
| 5 | Local accounts | None, or a list | At most one local emergency admin account, vaulted in PAM. Any other local account is an exception |
| 6 | Provisioning | SCIM · API (connector or script) · manual with a ticket | SCIM by default. Manual is allowed only for fewer than 50 users, with a monthly reconciliation. **The leaver path must be tested before go-live.** PHI apps deprovision on demand (`iam-standard.md` §3) |
| 7 | Roles → groups → packages | One `App-<Application>-<Role>` group per app role | Access is granted only by group, and each group is fed by an access package. If HR attributes decide who gets it, it's an automatic (birthright) assignment. Otherwise it's requestable, with approval and expiry. Separation-of-duties pairs are declared up front. In-app admin roles go through PIM for Groups |
| 8 | Review tier ([ADR 0012](../adr/0012-access-review-no-response-and-clinical-lockout.md)) | T1 privileged · T2 requestable · T3 birthright clinical | Every role in field 7 has a tier. Clinical apps carrying PHI that clinicians need on shift are T3 for their core roles, so they are never removed on reviewer silence |
| 9 | Conditional Access | Covered by the baseline · needs a targeted policy | The app must not be excluded from CA001 or CA008. Any exclusion goes through the exception process (CA design principles §3). PHI apps reached from shared devices fall under CA060 (ADR 0014) |
| 10 | NHIs created | Service principal; credential type; API permissions; secrets outside Entra (SCIM token, API key) | Federated credential, then certificate (12 months or less, in Key Vault). A client secret is an exception (N2). Every permission is listed with a reason, and Tier-0 permissions need a risk acceptance (N6). **Each credential has an owner and an expiry date** in the NHI inventory (`06-NHI-Inventory.ps1`). Admin consent goes through the admin-consent workflow; user consent is never used |
| 11 | Logging | Sign-in logs, plus app audit logs to the SIEM | Required for PHI and PCI apps. The app's own admin actions reach the SIEM, or the gap goes on the exception register |
| 12 | Rollback | How to revert the sign-in and provisioning change | Written before go-live |

## Go-live checklist

Every item needs evidence attached to the change ticket: a screenshot, a log
query result or a plan link.

- [ ] Fields 1–12 complete. Exceptions approved, each with an end date.
- [ ] SSO tested by a non-admin test user. The CA report-only result shows
      the app in scope of CA001 and CA008.
- [ ] Joiner, mover and leaver tested through provisioning. The leaver ends
      disabled or deleted in the app, with timestamps.
- [ ] Access packages published with approver, expiry and review tier. No
      direct user assignments to the app.
- [ ] NHI inventory rows exist, with owners and credential expiry dates.
      Signing-certificate expiry alerts go to a group, not to a single
      person.
- [ ] Logs are arriving in the SIEM.
- [ ] Any local emergency account is vaulted, and the vault check-out has
      been tested.

## Worked example: AWS IAM Identity Center (lab)

- **Fields 4 and 6:** SAML and SCIM. They are still to be built (human step
  7 in `lab/terraform/README.md`).
- **Field 7:** `App-AWS-IdentityCenter-Users` maps to the `ViewOnlyAccess`
  permission set (`lab/terraform/aws/`).
- **Field 8:** T2.
- **Field 10:** the SCIM token is a long-lived secret outside Entra, so it
  goes in the NHI inventory with an owner and a rotation date.

verify: SCIM token lifetime and rotation in IAM Identity Center.
