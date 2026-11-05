# Runbook: quarterly break-glass drill (L2)

**Scenario:** Contoso Health lab (fictional 5,000-user hospital).

> **Status: RAN · tenant once, 2026-11-05, in the lab form** (one software
> passkey per account, app-only checks; see [Lab deviation](#lab-deviation-software-passkeys-in-the-operators-keychain)).
> Preflight passed; both accounts signed in to My Account with the passkey
> only; Sentinel raised High incident #42 for both, 10.2 minutes after the
> sign-ins reached the workspace; no audit operation by either account.
> Result Pass. Not done: Teams card and ServiceNow INC (the notify playbook
> is not triggered by any automation rule yet), Splunk leg, a change ticket
> and a second reviewer. Record: [`../../evidence/drills/`](../../evidence/drills/README.md)
> (`2026-11-05T1041Z-break-glass-drill.json`), capture log E49.

## Tooling

`Invoke-BreakGlassDrill.ps1` automates the checking parts of this runbook.
In production the sign-ins stay manual: a script that could sign in as a
standing Global Administrator would be the most dangerous file in the repo.
The lab is the exception, and says so: its keys are software passkeys in the
operator Mac's Keychain, signed in with by `passkey.mjs prove` (see
[Lab deviation](#lab-deviation-software-passkeys-in-the-operators-keychain)).

- `-Phase Preflight` is read-only and refuses to start the drill on any
  FAIL: both accounts exist, are enabled and are in Break-Glass-Admins;
  every CA policy excludes the group; each account has the expected number
  of FIDO2 keys and the passkey policy targets the group; the break-glass
  rule is deployed and enabled; sign-in data reached the workspace in the
  last 24 hours.
- `-Phase Verify` reads back from Log Analytics the sign-ins since the drill
  start, the alerts and incidents the rule raised, and any audit operation
  the accounts initiated. It re-runs the preflight and writes the drill
  record.
- It does **not** check the Teams card, the ServiceNow INC or the Splunk
  alert. Confirm those by hand and add them to the record.
- It needs Global Reader and Authentication Administrator (to read FIDO2
  methods), read-only Graph scopes, and Reader plus Log Analytics Reader
  (plus Microsoft Sentinel Reader on the Sentinel path) through `az`.
- `-UseAzureCliToken` runs it **app-only**, with the Graph token of the app
  the Azure CLI is signed in as. In the lab that is the lab operator
  (`lab/scripts/operator/op pwsh ...`), whose application roles cover the
  read scopes above. App-only refuses `-Phase All` (it prompts a person
  through each sign-in): run Preflight, the sign-ins, then Verify. Pass the
  sign-in list through `pwsh -Command`, not `-File` (with `-File` the comma
  list arrives as one string and fails validation).

## Lab deviation: software passkeys in the operator's Keychain

| | Production standard | This lab (since 2026-11-05) |
|---|---|---|
| Keys per account | Two FIDO2 hardware keys, attested, in separate safes | One software passkey (Chromium's virtual authenticator), `notAttested` |
| Where the key lives | The safe; only the key holder opens it | The operator Mac's login Keychain, `contoso-lab-passkey-bg-admin-NN` |
| How it was registered | In person at Security info, never with a TAP | The operator provisioned it through Graph (`fido2Methods/creationOptions` + `POST fido2Methods`, beta): the TAP policy excludes Break-Glass-Admins (ADR 0016) |
| Who signs in during the drill | The key holder, by hand, watched by a second admin | `node lab/scripts/demo/signin/passkey.mjs prove bg-admin-NN@... --break-glass` (My Account, look only) |
| Drill preflight | `-ExpectedKeysPerAccount 2` (default) | `-ExpectedKeysPerAccount 1` |

Why: the lab has no hardware keys, and the break-glass accounts had no
working method at all (password only, never signed in), so in a real
lockout they could not have reached the admin portals, where Microsoft
enforces MFA. A software passkey is still phishing-resistant and satisfies
that MFA.

What it costs: **the Keychain item is the key.** Anyone who can read
`contoso-lab-passkey-bg-admin-01` from the operator's login Keychain can sign
in as a Global Administrator, with no Conditional Access in the way. It is
never printed, logged or committed, and every `prove` raises the Sentinel
break-glass incident. Entra accepts the key only because the `all_users`
passkey target still carries the unattested Default profile (ADR 0016,
Consequences): enforcing an AAGUID allow-list on the admin profile without
the virtual authenticator's AAGUID would lock both accounts out (the
preflight fails first). Re-key with `passkey.mjs register ... --replace`.

Lab drill, in order:

```bash
op=lab/scripts/operator/op
$op pwsh -NoProfile -File lab/scripts/powershell/Invoke-BreakGlassDrill.ps1 -Phase Preflight -UseAzureCliToken -ExpectedKeysPerAccount 1 -OnMicrosoftDomain contosohealthlab.onmicrosoft.com
node lab/scripts/demo/signin/passkey.mjs prove bg-admin-01@ContosoHealthLab.onmicrosoft.com --break-glass
node lab/scripts/demo/signin/passkey.mjs prove bg-admin-02@ContosoHealthLab.onmicrosoft.com --break-glass
$op pwsh -NoProfile -Command "& ./lab/scripts/powershell/Invoke-BreakGlassDrill.ps1 -Phase Verify -UseAzureCliToken -ExpectedKeysPerAccount 1 -OnMicrosoftDomain contosohealthlab.onmicrosoft.com -DrillStartUtc '<start printed by Preflight>' -DeclaredSignIns 'bg-admin-01:key 1','bg-admin-02:key 1' -Operator lab-operator"
```

## Why

The two emergency-access accounts (`bg-admin-01`, `bg-admin-02`) hold standing
Global Administrator, are cloud-only on `*.onmicrosoft.com`, and are excluded
from every Conditional Access policy (`lab/terraform/modules/groups`,
`modules/conditional-access`). A drill proves three things a config review
can't: each key still signs in, the alert path still fires end to end, and the
people who hold the keys still know the procedure. Cadence: at least every 90
days (`lab/terraform/README.md`, human step 6).

## Prerequisites

- [ ] Human step 6 done: Passkey (FIDO2) method enabled for Break-Glass-Admins,
      two keys registered per account, stored in separate safes.
- [ ] Detections deployed: Sentinel rule "Contoso - Break-glass account sign-in
      (any)" (High, every 5 min, 1 h lookback), or after the Sentinel trial the
      Log Analytics alert to `ag-identity-secops` (`modules/monitoring`).
- [ ] Splunk running (`lab/splunk/splunk-up.sh`) inside its 60-day trial. On
      Splunk Free, alerts don't trigger (`lab/splunk/README.md`), so skip that
      leg and record why.
- [ ] A change ticket opened **before** the drill. The rule is never muted;
      the ticket is how the incident is recognised as the drill
      (`lab/kql/break-glass-signin.kql`, false-positive notes).
- [ ] Two people: the key holder and a second admin who reviews.

## Procedure

Record every time in UTC.

1. **Baseline.** Run `Invoke-BreakGlassDrill.ps1 -Phase Preflight
   -OnMicrosoftDomain <tenant>.onmicrosoft.com -ChangeTicket <CHG>` and note
   the drill start time it prints. Also run
   `lab/scripts/powershell/01-Verify-Baseline.ps1 -OnMicrosoftDomain
   <tenant>.onmicrosoft.com`, which adds the check that the group holds
   Global Administrator. Both must pass. Stop on any FAIL.
2. **Sign in with bg-admin-01, key 1.** Use a private browser window to the
   Entra admin center. Look, don't change: open the sign-in log and sign out.
   Note the sign-in time.
3. **Repeat for bg-admin-01 key 2, then bg-admin-02 keys 1 and 2.** Four
   sign-ins: each key is tested, not just each account.
4. **Sentinel.** Within about 5 min of each sign-in reaching Log Analytics
   (allow 5–15 min ingestion lag), confirm:
   - an incident from the break-glass rule, High, with the account entity;
   - the Teams card in the Identity-SecOps channel;
   - a ServiceNow incident, with its INC number commented back on the
     Sentinel incident (`lab/monitoring/playbook-notify.json`).
   After the Sentinel trial: confirm the action-group email instead.
5. **Splunk.** Within the 1 h lookback, run
   `lab/splunk/ingest-from-loganalytics.sh`, then Splunk Web → Activity →
   Triggered Alerts. Confirm the break-glass alert fired. (The replay sets
   `_time` from `TimeGenerated`, so a replay later than 1 h after the
   sign-in won't trigger the scheduled search.)
6. **No changes made.** Run `Invoke-BreakGlassDrill.ps1 -Phase Verify
   -DrillStartUtc <start> -DeclaredSignIns 'bg-admin-01:key 1',... -ChangeTicket
   <CHG>`. It counts any `AuditLogs` operation initiated by
   `bg-admin-01`/`02` in the drill window; expect none. The second admin
   reviews that result.
7. **Close out.** Keys back in their safes. The Verify phase re-runs the
   preflight; re-run `01-Verify-Baseline.ps1` too. Link the Sentinel
   incident(s) and INC number(s) to the change ticket and close them as
   "drill".
8. **Record** one row per key in the drill log. The Verify phase writes the
   public record to `lab/evidence/drills/` (short account names, key
   labels, times and ticket numbers only) and the full observation to the
   gitignored `lab/evidence/out/drills/`. Add the Teams, ServiceNow and
   Splunk results by hand. Fill only what you observed.

## Pass / fail

| Result | Meaning | Action |
|---|---|---|
| Pass | All four keys signed in; Sentinel (or LA) alerted for each; Splunk alerted, or its leg was skipped with a reason | Log it; next drill in ≤ 90 days |
| Partial | A key failed, or one alert path didn't fire | Log it; open a defect ticket the same day; re-drill that leg after the fix |
| Fail | No alert fired for a break-glass sign-in | Sev 2 defect: the tenant's most powerful accounts are unmonitored. Fix before closing the change |

## Timing to capture (once real)

Sign-in → incident created; incident → Teams card; incident → INC number.
These become the measured alerting latency. Until a drill runs there's no
number to quote.
