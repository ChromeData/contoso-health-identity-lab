# 09 · Privileged access, live

**What you show:** admin power checked out for real. A Tier-0 activation with
a reason, a ticket and someone else's approval; the help desk refused when it
reaches for an admin; the break-glass keys proven one by one; and on the AD
side, a domain admin account checked out of the vault against an approved
change and used in a recorded session.

**Whisperglass:** *Contoso 06 · Privileged access*, all of it this time: the
PIM part, then the vault and Guacamole.

**Starts from:** `turn where` says `dc` (or a later stage), and:

- the joiner stage has run, so the admin accounts exist and are eligible:
  `adm-ava.lin` for PIM-Tier0-CA-Admins, `adm-raj.patel` for
  PIM-Tier1-Helpdesk. Mei Tanaka's workforce account is in PIM-Approvers-Tier0;
- two browsers or browser profiles, one for the person asking and one for the
  approver (a private window works);
- for part C: both break-glass accounts with two FIDO2 security keys each
  (four keys), a change ticket opened **before** the drill, and a second admin
  to review;
- for part D: Docker with 4 CPUs and 8 GiB, DC01 running, and your IP in
  `operator_ip_ranges`. For the vault alarm (steps 33 and 34), the DC01 rules
  are released (run sheet 10, part A) and `lab/scripts/monitoring/ingest-vault-audit.sh --follow 60`
  is running.

**Heads-up:** this is a draft. Nothing in it has run in the tenant yet, so
correct any step the first time you do it. In part D, operators sign in to
Guacamole through Entra only once `enable_pim_oidc_app` is on (it needs
`enable_sso_apps`). Until then they use local Guacamole users, and you say so.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| | **Part A: a Tier-0 activation (E17, E17b, E36b)** | | |
| 1 | Read the Map part of *Contoso 06*. | the lab map | the privileged station |
| 2 | Requester's browser, as `adm-ava.lin`: Entra admin center, **ID Governance**, **Privileged Identity Management**, **My roles**, **Groups**, **Eligible assignments** | PIM | PIM-Tier0-CA-Admins, with an end date: the eligibility itself expires after 180 days |
| 3 | **Activate** on PIM-Tier0-CA-Admins: up to 4 hours, a justification, and a ticket number and system. Click **Activate** | the activation form | an MFA prompt (or, once run sheet 08 step 33 has run, a fresh phishing-resistant sign-in), then "pending approval" |
| 4 | Same browser: PIM, **Approve requests** | the list | your own request is **not** offered to you |
| 5 | Approver's browser, as Mei (workforce account): PIM, **Approve requests**, **Groups**. Open the request, read the justification and the ticket, then **Approve** with a reason | the request | Approved |
| 6 | Requester: **My roles**, **Groups**, **Active assignments**. Refresh; sign out and back in if the rights don't show | the assignment | Activated, ending at most 4 hours from now |
| 7 | The security mailbox | the inbox | the activation email |
| 8 | `turn open sentinel`, **Logs**: `AuditLogs \| where LoggedByService == "PIM" \| where TimeGenerated > ago(1h) \| project TimeGenerated, ActivityDisplayName, Result` | the results | the request, the approval and the activation. Copy the exact `ActivityDisplayName` strings into the capture note: `pim-activation.kql` and the preview rule depend on them |
| 9 | Sentinel **Incidents**, within about 15 minutes | the incident list | **Contoso - PIM activation (just-in-time elevation)**, Medium, naming the requester. If the notify playbook is deployed, the Teams card and the ServiceNow number too |
| 10 | As `adm-ava.lin`, sign in to the Entra admin center. Then **Sign-in logs**, that sign-in, the **Report-only** tab (or **Conditional Access**, once CA020 has graduated) | the sign-in details | CA020's result and its 4-hour sign-in frequency, exactly as shown (E17b) |
| 11 | Only if run sheet 08 step 33 has run: activate PIM-Tier0-CA-Admins again | the sign-in log, **Authentication details** and **Conditional Access** tabs | a fresh phishing-resistant sign-in that carries `c1`. Once run sheet 10 releases the preview rule *Tier-0 PIM activation without the authentication context*, it stays quiet. An alert means its field mapping needs fixing: record it |
| | **Part B: the help desk's reach (E46b)** | | |
| 12 | As `adm-raj.patel`: activate PIM-Tier1-Helpdesk (a justification and MFA, no approval, up to 8 hours) | PIM | Activated |
| 13 | **Users**, a standard workforce user, **Authentication methods**: reset or remove a method | the user | allowed |
| 14 | The same on a Tier-1 admin's `adm-` account | the admin | refused: an error in the portal, and the denial in the audit log |
| 15 | **Roles & admins**, **Helpdesk Administrator**, **Assignments** | the assignment | its scope is `AU-Workforce-Standard`, not the whole directory |
| 16 | Sentinel **Incidents** | the incident list | **Authentication method changed by an admin for another user** for the allowed change, with its severity |
| | **Part C: the break-glass drill (E49)** | | |
| 17 | `pwsh`: `Connect-MgGraph -TenantId <tenant id> -Scopes User.Read.All,GroupMember.Read.All,Policy.Read.All,UserAuthenticationMethod.Read.All`, with `az login` done too. Then `./lab/scripts/powershell/Invoke-BreakGlassDrill.ps1 -Phase Preflight -OnMicrosoftDomain <tenant>.onmicrosoft.com -ChangeTicket <CHG>` | the terminal | every check PASS, and the drill start time. Any FAIL stops the drill |
| 18 | A private window to the Entra admin center: `bg-admin-01` with **key 1**. Look, don't change anything. Note the time in UTC, sign out, close the window | the portal | signed in |
| 19 | The same for `bg-admin-01` key 2, `bg-admin-02` key 1 and `bg-admin-02` key 2 | the portal | four sign-ins: every key tested, not just every account |
| 20 | Sentinel **Incidents**, 5 to 15 minutes after each sign-in | the incident list | **Contoso - Break-glass account sign-in (any)**, High, for each one. The Teams card, and the ServiceNow number commented back on the incident |
| 21 | `./lab/scripts/powershell/Invoke-BreakGlassDrill.ps1 -Phase Verify -DrillStartUtc <start> -DeclaredSignIns 'bg-admin-01:key 1','bg-admin-01:key 2','bg-admin-02:key 1','bg-admin-02:key 2' -ChangeTicket <CHG>` | the terminal | each sign-in seen and alerted, no audit operation by either break-glass account, result **Pass**, and a record in `lab/evidence/drills/` |
| 22 | Keys back in their safes. The second admin reviews the result. Link the incidents and the ServiceNow numbers to the change and close them as "drill". Add the Teams, ServiceNow and Splunk results by hand in `lab/evidence/drills/README.md` | the drill log | four rows, one per key |
| | **Part D: the vault and the recorded session (E51a, E51)** | | |
| 23 | Read the Build part. `cd lab/pam && ./pam-up.sh` | the terminal | Vault unsealed; Guacamole and the ITSM mock up |
| 24 | `./vault-onboard-ad.sh -k <key-vault> -d corp.<domain>` | the terminal | the LDAP engine and the Tier-0 library set up |
| 25 | **Not available: retired.** Discovery to reconciliation against DC01 (`lab/pam/README.md` sections 1 to 4) ended with the Vault stand-in (ADR 0036): `svc-pam-discovery` and its secret were deleted on 2026-11-07. Skip this step in the live run. Do NOT run the Samba harness (`test/e2e.sh`) here: it refuses a real DC, and its `--force` bypass deletes Vault's `ldap/` mount. The Samba exercise is a separate, offline one (`lab/pam/README.md`). Previously: the dependency scan on DC01 (`Get-AccountDependencies.ps1` through `az vm run-command`), `./onboard.sh --dry-run`, `./onboard.sh`, then `./reconcile.sh --verify --strict` | the terminal | the reconciliation report: GAP 0, with the held accounts named |
| 26 | Raise the change. In the lab: `./itsm-ticket.sh add "$(./itsm-ticket.sh next)" --operator ops-alice --approver ops-carol --approver ops-dana`. At tenant time: in the ServiceNow PDI, assigned to the operator and approved by two other people | the terminal, or the PDI | a CHG number, approved, in Implement |
| 27 | `./psm-session.sh checkout --operator ops-alice --ticket <CHG>` | the terminal | the Tier-0 account checked out, the two approvers who counted, and an audit line |
| 28 | Browser: `http://127.0.0.1:8081/guacamole` as the operator. In the lab, the local password is in `.secrets/operators/ops-alice-password`. With `enable_pim_oidc_app`, sign in through Entra instead. Connect **DC01 - tier0-admin-01 (recorded)** | the RDP session | a session on DC01. The operator never sees the password |
| 29 | Do the admin task, then disconnect. `./psm-session.sh checkin` | the terminal | checked in: Vault rotates the password |
| 30 | Guacamole as `guacadmin`: **Settings**, **History** | the session row | the operator's name. Play the recording back |
| 31 | `out/pam-audit.jsonl`, and the check-out in Vault's own audit log | the audit lines | the operator, the change number and the approvers, by name |
| 32 | With Entra sign-in on: **Sign-in logs**, the operator's Guacamole sign-in, **Report-only** tab | the sign-in details | CA022's report-only result, exactly as shown |
| 33 | Log on to DC01 as a Tier-0 admin **without** a check-out | Sentinel **Incidents** | **Tier-0 logon on DC01 without a Vault check-out**, High, Class Vaulted. Containment does not act on it: the playbook comments "AD disable required", because AD is the authority |
| 34 | Log on again, this time with a check-out (steps 26 to 29) | Sentinel **Incidents** | no incident. The absence is the proof |
| 35 | Read the Proof part. | | |

## Say this, in your own words

- Nobody owns admin power. You ask for it, give a reason and a ticket, someone
  else approves, and it expires.
- The approver can never be the person asking: PIM doesn't even offer the
  request to them.
- The help desk can reset ordinary staff, never an admin, so a convincing
  caller can't talk them into resetting one.
- Two break-glass accounts, two keys each, every key tested, and the alarm
  fires every time. The script does the checking; the sign-ins stay human.
- On the AD side, a local HashiCorp Vault and Guacamole harness shows the
  ideas. The lab's target is Microsoft-native (ADR 0036): Azure Key Vault,
  Azure Bastion session recording and Windows LAPS. Check-out needs an approved change and, for Tier 0, two
  approvers, neither of them the person asking. The session is recorded, and
  the password is rotated at check-in.
- A Tier-0 logon the vault can't account for is an alarm. No evidence means an
  alert, never silence.

## If something goes wrong

| What you see | Do this |
|---|---|
| The group isn't under **My roles** | The eligibility is missing or has expired. Eligibility is granted by `Set-PimGroupEligibility.ps1` in the joiner stage. Never fix it by adding a standing member. |
| The request stays "pending approval" | The approver must be in PIM-Approvers-Tier0 and must not be the person asking. |
| Activated, but no admin rights | Sign out and back in; the old token predates the activation. |
| Tier-0 activation asks for a fresh sign-in, then fails | The account has no method the admin strength accepts. Register an issued security key. Never switch Tier 0 back to MFA as a fix: that is a reviewed PR. |
| The help desk **can** reset the admin in step 14 | The scoping is broken: that is a finding, so stop. Check the role assignment's scope is the admin unit, check the unit's rule (`turn au-rule`), and check the admin is not in the unit. |
| The preflight shows a FAIL | Stop the drill and fix it first: break-glass excluded from every policy, two usable keys per account, the rule enabled. |
| No break-glass incident after 15 minutes | Verify polls for 30 minutes, so let it finish. If none fired, that is a Sev 2 defect: the tenant's most powerful accounts are unmonitored. Don't close the change. |
| `psm-session.sh` refuses the ticket | It names the reason: not approved, not in Implement, outside its window, assigned to someone else, or too few distinct approvers. |
| `no Tier-0 account available` | Both accounts are checked out. `./psm-session.sh status`, then check one in. |
| The session wasn't recorded | The recordings volume lost its permissions. `docker compose down` (without `-v`), then `./pam-up.sh`. |
| Every Tier-0 logon alerts, even with a check-out | The vault feed is down: the incident shows `VaultFeedHealthy = false`. Restart `ingest-vault-audit.sh --follow 60`. |

## Do it again

- **PIM:** **My roles**, **Active assignments**, **Deactivate** (or let it
  expire), then start again from step 3.
- **Break-glass:** a new change ticket every time, and new rows in the drill
  log. The next drill is due within 90 days.
- **Vault:** check in anything still out (`./psm-session.sh status`), take a
  new number with `./itsm-ticket.sh next`, and start again from step 26. After
  a laptop restart, run `./pam-up.sh`. Once DC01 is onboarded, use
  `docker compose down` **without** `-v`: `-v` deletes the only copies of the
  onboarded passwords.
- A re-take is a new capture, logged as `re-run of Exx`.
