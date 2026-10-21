# Runbook: compromised identity (L1 / L2)

**Scenario:** Contoso Health lab, a fictional 5,000-user hospital. **Status:** written against the lab code, not yet exercised. No tenant has been deployed (`lab/terraform/README.md`, *Validate / fmt status*).

**Use when:** a workforce account is believed to be used by someone other than its owner. Typical triggers:

- A Sentinel incident from `blocked-country-signin.kql` with `Outcome == "SUCCEEDED - CA gap"`.
- A `failed-signin-spike.kql` incident, followed by a success from the same IP.
- An ITDR incident naming the account: `identity-risk.kql` (open high risk, or confirmed compromised), or `auth-method-changed-by-admin.kql` (someone else changed its methods).
- A user reporting MFA prompts they did not start.
- The service desk receiving a report of a phished password.

**Break-glass accounts (`bg-admin-NN`) are out of scope here.** Any sign-in by one is already a High incident (`break-glass-signin.kql`). Use [break-glass-drill.md](break-glass-drill.md) only for planned drills. Treat an unplanned break-glass sign-in as Sev 1 and escalate to L2 immediately.

## Who does what

| Step | L1 (SOC tier 1 / service desk) | L2 (IAM engineer) |
|---|---|---|
| 1 Triage | Owns | Consulted |
| 2 Revoke sessions | Does it if delegated; otherwise asks L2 | Owns |
| 3 Disable, reset, clean methods | n/a | Owns (needs an active PIM elevation, see below) |
| 4 Investigate | Collects the sign-in export | Owns |
| 5 Notify | Updates the ticket | Owns stakeholder calls |
| 6 Recover and close | n/a | Owns |

In this lab, L2's rights come from PIM ([pim-activation-support.md](pim-activation-support.md)):

- **Privileged-IAM-Admins** (User Administrator): disable a cloud-only user, reset a non-admin's password. It needs approval, so request it at the start of the incident, not at step 3.
- **PIM-Tier1-Helpdesk** (Authentication Administrator; a tier group, `enable_pim_tiers`, scoped to an administrative unit when that is on): delete methods and issue a TAP. For an admin, Privileged Authentication Administrator (Tier 0). verify: Learn's role table for authentication methods.
- **Azure rights on the DC01 VM**: the AD disable, because `Invoke-AdContainment.ps1` uses `az vm run-command`.

**Response targets.** These are a lab standard, not measured values: revoke within 15 minutes of triage confirming the compromise, and disable within 30 minutes.

## 1. Triage (L1)

1. Open or adopt the ticket. A Sentinel incident has already opened a ServiceNow incident through `lab/monitoring/playbook-notify.json`, and the INC number is commented on the Sentinel incident. Record the start time in UTC.
2. Establish four facts:
   - **Account type.** Is the account synced (`onPremisesSyncEnabled = true`, the lab default for workers) or cloud-only?
   - **Privilege.** Does the user hold, or is the user eligible for, a privileged role? Check membership and eligibility of Privileged-IAM-Admins. If the user does, the incident is **Sev 1** and L2 takes over now.
   - **Successful sign-in.** Is there a successful sign-in (`ResultType == "0"`) from an unexpected IP or country?
   - **MFA.** Was MFA satisfied on that sign-in?
3. Pull the last 7 days of sign-ins for the account. The `LocationDetails` normalisation is the same trap documented in `lab/kql/break-glass-signin.kql`:

```kql
let Upn = "user@<domain>";
union
  (SigninLogs | extend SignInType = "interactive"),
  (AADNonInteractiveUserSignInLogs | extend SignInType = "non-interactive"
     | extend LocationDetails = todynamic(tostring(LocationDetails)))
| where TimeGenerated > ago(7d) and UserPrincipalName =~ Upn
| extend Country = tostring(LocationDetails.countryOrRegion)
| project TimeGenerated, SignInType, IPAddress, Country, AppDisplayName,
          ClientAppUsed, ResultType, ConditionalAccessStatus,
          AuthenticationRequirement, RiskLevelDuringSignIn, CorrelationId
| sort by TimeGenerated desc
```

4. **Decision.** If any of the following is true, proceed to step 2: a success from an unexpected location, MFA fatigue the user did not start, or a credential the user confirms was disclosed. If it was only failures and the user is in control, close as "attempted, no compromise" and record the IPs.

## 2. Contain: revoke sessions (L1 if delegated, else L2)

Revoking kills refresh tokens and session cookies. Access tokens already issued stay valid until they expire (verify: the current default access-token lifetime, and which apps honour Continuous Access Evaluation).

- **Containment playbook (High ITDR incidents, Sentinel path):** `pb-identity-contain` (`lab/monitoring/playbook-contain.json`) posts a Teams card with *Contain*, *Revoke sessions only* and *Reject*. Only a member of `ITDR-Containment-Approvers` who is not the subject can answer; no answer in 4 hours means no action, and break-glass accounts are refused outright. *Contain* revokes sessions and marks the user confirmed compromised in Identity Protection. It disables a cloud-only account only if the opt-in directory role was granted at deploy time (`-GrantDisableRole`; otherwise the disable returns 403, and admins stay out of its reach). For a synced account it only flags the AD disable: run `lab/scripts/monitoring/Invoke-AdContainment.ps1`, which disables the account on DC01 through `az vm run-command` (step 3). Every outcome is commented on the incident and noted on the ServiceNow ticket. Built and tested offline; never run in a tenant (`lab/scripts/monitoring/README.md`; design in [ADR 0017](../adr/0017-approval-gated-identity-containment.md)).
- **VIP in a restricted-management AU (RMAU-VIP):** the playbook sends no approval card, because Graph application permissions don't apply to RMAU members. It records *ESCALATED, NOT CONTAINED* on the incident; page the RMAU-scoped responder (the VIP-support PIM group, holding roles scoped to that AU), who revokes sessions and disables the account by hand. For a synced VIP the disable happens in AD (`Invoke-AdContainment.ps1`, step 3). verify: which calls the RMAU blocks.
- **Portal:** Entra admin center → Users → *user* → **Revoke sessions**.
- **PowerShell:** `Revoke-MgUserSignInSession -UserId <objectId>`, using the `User.RevokeSessions.All` scope. `lab/scripts/powershell/04-Leaver.ps1` uses the same call.
- **Graph:** `POST /users/{id}/revokeSignInSessions`.

**Don't count on CA006 to evict the attacker.** *Contain* marks the user
confirmed compromised, so user risk becomes High and CA006 (MFA plus a
secure password change, once enforced) applies at the next sign-in. That is
self-remediation, and an attacker who registered a method of their own
passes it: they set a new password (written back to AD when writeback is
on), lock the real user out and clear the risk (verify: self-remediation
after `confirmCompromised`). So after a confirmed compromise, step 3 isn't
optional: disable first (in AD for a synced account), then clean the
methods, then reset. *Revoke sessions only* leaves the account enabled,
so whoever holds a working password and method can sign straight back in.

## 3. Disable, reset, clean auth methods (L2)

**Disable.** Who can write `accountEnabled` depends on the account type:

| Account | How to disable | Why |
|---|---|---|
| Cloud-only | `Update-MgUser -UserId <id> -AccountEnabled:$false`, or the portal *Edit properties → Account enabled* | Entra owns the attribute |
| Synced (lab default) | `Disable-ADAccount <sam>` on DC01, or `Invoke-AdContainment.ps1` (run-command on DC01, writes an evidence record). Then run Cloud Sync **Provision on demand** for the user so the disable reaches Entra now, not on the next 10–20 minute cycle | Entra rejects a cloud write to `accountEnabled` on a synced user, as `04-Leaver.ps1` documents |

**Place an HR hold.** The mock HR feed drives `active`/disabled through the provisioning job mapping (`lab/scripts/mock-hr/Invoke-InboundProvisioning.ps1`). Until the incident closes, do not re-run inbound provisioning for this worker's `active` row. Verify: whether the job's mapping re-enables an AD account that security disabled by hand. Until that is confirmed, assume it does.

**Reset the password.**

- Synced: `Set-ADAccountPassword -Reset` and `Set-ADUser -ChangePasswordAtLogon $true` on DC01.
- Cloud-only: the portal's *Reset password*.

Then **revoke sessions again**, because a token minted between the containment step and the reset survives the first revoke. Verify: which roles may reset this user's password in Microsoft's privileged-role password-reset table. User Administrator cannot reset every admin.

**Clean the authentication methods.**

1. List the methods: `GET /users/{id}/authentication/methods`.
2. In AuditLogs, find "User registered security info" events from the attacker's IPs.
3. Delete every method the user did not register.
4. Re-onboard the user with a Temporary Access Pass, the same mechanism the joiner Lifecycle Workflow uses (`lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1`).

## 4. Investigate (L2)

| Question | Where to look |
|---|---|
| What else did the attacker IP touch? | Re-run the step 1 query, filtered on `IPAddress`, without the UPN filter |
| What did the account change? | `AuditLogs` where `InitiatedBy.user.userPrincipalName =~ Upn`: app consents, method registration, group changes, access-package requests |
| Consented apps | `GET /users/{id}/oauth2PermissionGrants` and the app-role assignments. Revoke any unknown grants |
| Did it elevate? | `lab/kql/pim-activation.kql`, with a longer lookback |
| Which CA policy should have stopped it? | `ConditionalAccessPolicies` on the successful sign-in. A policy still report-only (every policy ships that way, see `ca_policy_states` in `lab/terraform/envs/dev/lab.tfvars`) becomes a finding for [graduate-a-ca-policy.md](graduate-a-ca-policy.md) |
| Risk signal | `GET /identityProtection/riskyUsers/{id}` and `riskDetections`. After confirmation, `POST /identityProtection/riskyUsers/confirmCompromised` (Entra ID P2). The playbook's *Contain* does this for you |
| Mailbox rules and forwarding | Out of the lab's scope. Hand it to the Exchange / M365 admin |

**Lab gap, stated plainly:** the risk-based policies (CA006 user risk, CA007 sign-in risk) and `identity-risk.kql` exist as code but sit behind staging flags, report-only, and have never run in a tenant.

## 5. Notify

| Who | When | What |
|---|---|---|
| SOC lead | At Sev 1, immediately; otherwise at containment | Timeline so far, IPs, containment status |
| The user's manager (the HR `manager` attribute) | At containment | Account disabled, expected restore path |
| Privacy / compliance officer | When the account held clinical-app access (`App-*` groups, the Nurse, ICU or Pharmacy packages) | Apps and window. **The breach-risk assessment is theirs, not IAM's** |
| App owners (ServiceNow, AWS) | When the account was provisioned there | Request an app-side session kill. The provisioning cycle takes about 40 minutes (`04-Leaver.ps1`) |
| Ticket | At every step | Update the ServiceNow INC. The Sentinel incident links to it |

## 6. Recover and close (L2)

1. Confirm the methods are clean and the password is reset.
2. Re-enable the account through the owner of the attribute: AD for synced users, Entra for cloud-only users.
3. Remove the HR hold.
4. Issue a TAP and watch the first sign-in.
5. Close the ticket with:
   - the timeline (UTC);
   - the root cause;
   - the control that failed or was missing;
   - a backlog item for that control.
6. Keep any exported CSVs under the gitignored `lab/evidence/out/`. They contain tenant data and never go in a commit.

**Not built:**

- Containment without a human: the playbook always waits for an approver's answer in Teams, by design.
- Containment on incidents outside the ITDR rules (`blocked-country-signin.kql` and `failed-signin-spike.kql` only notify).
- Mailbox investigation.
