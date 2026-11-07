# Runbook: identity downtime (Entra ID degraded or down)

Status: DESIGNED. Not drilled. The lab has no clinical stations or EHR.

Goal: clinicians keep caring for patients when Microsoft Entra ID, or the
link to it, fails. Security rules relax only as far as this page says.

## 1. Confirm the outage (L1, 5 minutes)

1. Check Service health in the Microsoft 365 admin center and the Azure status page (https://azure.status.microsoft).
2. Check a sign-in from a second network (a phone hotspot). If it works there, the fault is the hospital network, not Entra. Go to the network runbook.
3. Open a P1 incident in ServiceNow. Tell the Clinical Operations on-call lead.

## 2. What still works

- **Users already signed in.** Existing sessions and tokens keep working until they expire.
- **Entra's backup authentication system** signs users in again, automatically, when:
  - they used the same app on the same device in the last 3 days;
  - no interactive sign-in is needed;
  - they are members of the tenant (not B2B guests);
  - no revocation (for example a password change) happened since.
  It covers Microsoft 365 apps, many gallery apps (AWS, Workday and others with IdP-initiated SAML) and managed identities.
- **Windows sign-in on the shared stations** with a key or a cached credential already used on that device. verify: on target hardware, for FIDO2 keys while offline (ADR 0014).
- **On-premises AD** sign-in (Kerberos) to file shares and on-premises apps, if the domain controllers are up.

## 3. What does NOT work

- **New MFA registration**, TAP issue and passkey registration.
- **First sign-in** to an app or device not used in the last 3 days.
- **B2B guests** (vendors, visiting physicians).
- Apps that use **SP-initiated SAML** (for example ServiceNow) or OIDC with access tokens. Microsoft's list: "Backup Authentication System for Microsoft Entra ID", appendix.
- Policies that use **sign-in frequency** or an **authentication strength** reduce what the backup system can do (CA060 and CA008 both do).
- **Service principals** that are not managed identities (the lab operator, HR-SYNC, the pipeline).
- PIM activation, access package requests and new joiners.

## 4. Clinical fallback

1. Clinical Operations declares **EHR downtime** if the EHR sign-in fails. Units switch to the EHR's read-only downtime mode (downtime PCs with a local copy of the census and medication lists) and paper forms.
2. Do NOT share accounts. Do NOT turn off Conditional Access policies to "let people in". A switched-off policy is often forgotten after the outage.
3. If admins cannot sign in and must change the tenant, use the **admin break-glass** accounts ([break-glass-drill.md](break-glass-drill.md), ADR 0003). Every break-glass sign-in raises a High alert by design. Tell the SOC first.
4. Record the downtime start and end time on the incident.

## 5. After recovery

1. Check that every break-glass sign-in has an incident and a reason.
2. Re-check the CA policies against the code (`config-drift.yml`, ADR 0021). Nothing must have changed during the outage.
3. Have the EHR team reconcile paper downtime records into the EHR.
4. Write the post-incident report ([post-incident-report-template.md](post-incident-report-template.md)).

## Sources

- verify: Microsoft Learn, "Backup Authentication System for Microsoft Entra ID" (checked 2026-11-07: 3-day same app and device rule, home-tenant members only, no fresh interactive sign-in, sign-in frequency and authentication strength reduce resilience, service principals that are not managed identities are not protected).
