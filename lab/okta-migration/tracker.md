# Okta -> Entra app migration tracker

Generated 2026-11-07T03:11:39Z by `node lab/okta-migration/inventory.mjs` from the Okta API and Microsoft Graph. Do not edit by hand: re-run the script.

| app | owner | protocol | users | wave | status | test_result |
|---|---|---|---|---|---|---|
| Clinic Lab Results | Clinic lab manager (business) / Clinic IT lead (technical) | OIDC | 1 | 1 | inventoried | PASS okta 2026-11-07T03:11:15Z |
| Clinic Billing | Clinic revenue-cycle manager | SAML 2.0 | 0 | 2 | inventoried | not tested |
| Clinic Scheduling (legacy) | Clinic operations manager | Bookmark | 1 | 2 | inventoried | not tested |

## Detail per app

### Clinic Lab Results

- Okta: app `0oa19mje0oyLEHh1U698`, groups Clinic-Staff, authentication policy *Clinic clinical apps*, SSO events in the last 7 days: 3
- Entra: not built yet
- Next: pre-stage the Entra app (PR), owner sign-off

### Clinic Billing

- Okta: app `0oa19mjdqjb0WxeAZ698`, groups Clinic-Billing, authentication policy *Clinic clinical apps*, SSO events in the last 7 days: 0
- Entra: not built yet
- Next: pre-stage the Entra app (PR), owner sign-off - blocker: no billing service provider exists in the lab; its users arrive with an HR department (runbook Phase 3)

### Clinic Scheduling (legacy)

- Okta: app `0oa196auv2sxeVRfe698`, groups Clinic-Staff, authentication policy *Any two factors*, SSO events in the last 7 days: 0
- Entra: not built yet
- Next: pre-stage the Entra app (PR), owner sign-off - blocker: bookmark app: the vendor offers no SSO yet - becomes an Entra linked sign-on tile

## Group rules: Okta to Entra

| Okta rule | Okta expression | Entra dynamic rule | Decision |
|---|---|---|---|
| Clinic staff by login domain | `String.substringAfter(user.login, "@") == "contosohealthlab.com"` | `(user.userPrincipalName -endsWith "@contosohealthlab.com")` | Not copied: a login-domain rule means every hospital user after the acquisition. Assigned app group + access package instead. |
| Clinic billing by department | `user.department == "Clinic Billing"` | `(user.department -eq "Clinic Billing")` | Copy as a dynamic group when the app moves (HR owns the attribute). |

## Phishing-resistant posture (Okta)

| Admin | Roles | Active factors | Phishing-resistant factor enrolled |
|---|---|---|---|
| okta@ContosoHealthLab.onmicrosoft.com | SUPER_ADMIN | signed_nonce, token:software:totp | yes |

| Policy | Rule | Factors | Demands phishing-resistant |
|---|---|---|---|
| Any two factors | Catch-all Rule | 2FA | yes |
| Okta Admin Console | Admin App Policy | 2FA | no |
| Okta Admin Console | Catch-all Rule | 2FA | no |
| Okta Dashboard | Catch-all Rule | 2FA | no |
| Okta Browser Plugin | Catch-all Rule | 2FA | no |
| Okta Account Management Policy | Password Expiry Rule | 1FA | no |
| Okta Account Management Policy | Catch-all Rule | 2FA_If_Possible | no |
| Okta OIN Submission Tester | Catch-all Rule | 1FA | no |
| Clinic clinical apps | Clinic staff: two factors, re-auth every 8h | 2FA | no |
| Clinic clinical apps | Catch-all Rule | deny | no |

## Sources

- Okta API on integrator-8288815.okta.com: /api/v1/apps, /apps/{id}/groups, /apps/{id}/users, /policies/{id}/rules, /groups/rules, /logs (7 days), /users/{id}/roles, /users/{id}/factors
- Microsoft Graph as the lab operator: applications, servicePrincipals, appRoleAssignedTo, groups/{id}/members, identity/conditionalAccess/policies, auditLogs/signIns (7 days)
- Decisions (owner, wave, pilot, cut-over switch): lab/okta-migration/waves.json
- Test results: lab/okta-migration/results/*.json (cutover.mjs test)
