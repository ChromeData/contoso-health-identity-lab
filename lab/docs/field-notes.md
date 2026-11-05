# Field notes: what broke, how I found it, what I changed

These are the real failures from building and running this lab in a live
Microsoft Entra tenant, oldest first. Each entry says what happened, how I
found out, the root cause, the fix, the control I added so it cannot happen
quietly again (or, where there is none yet, what it would be), and where the
evidence is. E-numbers are rows in
[`lab/evidence/capture-log.csv`](../evidence/capture-log.csv); `#` numbers are
pull requests.

| # | Date (UTC) | In one line |
|---|---|---|
| 1 | 2026-10-27 | Detection rules ran for nine hours on empty tables |
| 2 | 2026-10-28 | Security defaults blocked the first Conditional Access policy |
| 3 | 2026-10-28 | The leaver script said FAILED after AWS had already disabled her |
| 4 | 2026-10-28 to 11-05 | A nightly VM shutdown paused directory sync for six days |
| 5 | 2026-10-30 to 11-05 | The drift check could not sign in for six nights, then caught a real Microsoft change |
| 6 | 2026-11-04 | A scanner update broke the nightly Kubernetes pipeline |
| 7 | 2026-11-05 | Every plan showed six changes nobody made |
| 8 | 2026-11-05 | The admin robot could escape its own AWS guardrails |
| 9 | 2026-11-05 | Two checks that could pass without checking |
| 10 | 2026-11-05 | The audit evidence pack was one record short, and a KPI never counted the leaver |

---

## 1. Detection rules ran for nine hours on empty tables

**What happened.** Sentinel went live with 11 detection rules at 04:59 UTC
(E15). None of them could fire: no Entra sign-in or audit log had ever reached
the Log Analytics workspace.

**How I found it.** The workspace had no Entra rows to show, hours after the
rules were switched on.

**Root cause.** The Entra log export is part of the bootstrap root, which a
person applies in two passes: the second pass needs the id of the workspace
that the pipeline creates in between. I had skipped the second pass.

**Fix.** Applied it (1 resource added): 11 log categories now stream to the
workspace, including sign-ins, audits, provisioning and the Identity
Protection risk tables (E07, 14:17 UTC). The first audit rows arrived after
that.

**Control added.** `lab/setup/after-signup.sh` now looks the workspace up and
keeps `log_analytics_workspace_id` on every re-run, because an empty value
would delete the export again. The Sentinel run sheet's troubleshooting table
starts with "check that Entra's logs reach the workspace"
(`lab/docs/your-turn/04-sentinel-detection.md`).

**Evidence.** E07, E15; commit `9332d34`, `lab/setup/after-signup.sh`.

## 2. Security defaults blocked the first Conditional Access policy

**What happened.** The first policy to graduate from report-only to On
(CA003, block legacy authentication) failed to apply.

**How I found it.** The apply run failed with `400 BadRequest: Security
defaults`.

**Root cause.** A new tenant ships with security defaults on, and Entra
refuses to turn on any Conditional Access policy while they are on.

**Fix.** Security defaults off at 22:12 UTC (E30a), then CA001 (MFA for all
users) graduated first, so the gap without forced MFA lasted about an hour,
not days. Nine of eleven policies are now on (E30, then #88 to #93).

**Control added.** The graduation run sheet now starts with "security
defaults are off", the exact command to do it, and the rule to graduate
CA001 first and keep the window short (#55).

**Evidence.** E30, E30a; #50, #55.

## 3. The leaver script said FAILED after AWS had already disabled her

**What happened.** On the first live leaver, `04-Leaver.ps1` reported the
AWS step as FAILED. In AWS, the account was already disabled. The evidence
pack run that night also filed one record as an error (E56).

**How I found it.** The script's result did not match the AWS provisioning
log, which showed the disable at 23:50 UTC (E52). For the pack, the
manifest records each failed record and why.

**Root cause.** Two parsing mistakes against real responses that the mocks
had not modelled. The provision-on-demand response puts the outcome in
`value`, not `key` (which is a type name). And Graph allows only one
`$expand` per query; the privileged-role record expanded two and got a 400.

**Fix.** #95: read the outcome from `value`; look role names up once instead
of expanding them.

**Control added.** Not yet. No mocked test pins the real on-demand response
shape, so this could regress. The next step is a fixture taken from the live
response.

**Evidence.** E52 (HR to AWS disable in 9 minutes), E56; #95.

## 4. A nightly VM shutdown paused directory sync for six days

**What happened.** Changes made in on-site Active Directory stopped reaching
Entra. This happened first on the evening of the leaver run (E52), and then
again from 2026-10-29 until 2026-11-05 08:40 UTC.

**How I found it.** The first time, the mover's Entra update waited for the
next cycle after DC01 came back (E52). The second time, the pre-recording
readiness check found the Cloud Sync job in quarantine.

**Root cause.** DC01 shuts down every night to save money. When the sync
agent cannot be reached, Microsoft quarantines the sync job, and it stays
paused after the VM comes back until someone clears it.

**Fix.** Cleared the quarantine. Then I wrote `lab/scripts/demo/preflight.sh`
(#128): it starts DC01, waits for the agent, clears the quarantine (a Graph
restart with `QuarantineState`), and checks the HR, Cloud Sync and AWS jobs.

**Control added.** One command before every recording or demo, run as the
lab operator; it prints READY or what is wrong. In production the fix is
simpler: domain controllers do not shut down at night.

**Evidence.** E52; #128.

## 5. The drift check could not sign in for six nights, then caught a real Microsoft change

**What happened.** The nightly check that compares the tenant's identity
configuration with the code failed every night from 2026-10-30 to
2026-11-04. On 2026-11-05 it finally ran, and failed again, this time with
two High findings.

**How I found it.** The red runs in the Actions list (first:
[run 41043783607](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/41043783607)).
Each one had stopped at sign-in with `AADSTS700213 No matching federated
identity record`. The High findings opened issue #112 by themselves.

**Root cause.** Two separate things.
- *Sign-in:* the read-only PLAN identity trusts this repository's `main`
  branch only through a second federated credential added in #101 on
  2026-10-29. That credential exists only after the bootstrap root is
  applied, and the directory audit log shows it was first written at
  2026-11-05 02:16 UTC. For six nights the code said one thing and the
  tenant another. A failed sign-in turned the run red but opened no issue,
  so nobody looked.
- *Findings:* Microsoft added a new property, `telecomProviderSettings`, to
  the SMS and voice sign-in method settings. I checked before accepting it:
  both methods are disabled, the new value is null, and the directory audit
  log shows no policy change since the baseline. So this was a schema
  change, not a configuration change.

**Fix.** Bootstrap applied (the credential now exists). Baseline refreshed
through a reviewed PR (#113); the next run was clean
([run 41957460762](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/41957460762))
(#113 closed #112). The check never reverts anything by itself: the way back
is always a PR.

**Control added.** `config-drift.yml` now opens an issue when a night
produces no comparison at all (sign-in, token or export failure), comments
on it every night it stays broken, and closes it on the next good run. A
broken check is now as loud as real drift.

**Evidence.** #101, #112, #113; `lab/evidence/config-snapshots/20261105T021841Z.json`.

## 6. A scanner update broke the nightly Kubernetes pipeline

**What happened.** The nightly Kubernetes pipeline started failing on
2026-11-04 with no change on my side
([run 41776291310](https://github.com/ChromeData/contoso-health-identity-lab/actions/runs/41776291310)).

**How I found it.** The failed scheduled run: Checkov reported CKV2_K8S_6
on the `nightly-report` pod.

**Root cause.** A Checkov update started enforcing a rule that every pod
has a NetworkPolicy. The pod had none, so anything in the cluster could
connect to it.

**Fix.** #114: a deny-all-inbound NetworkPolicy. It is a batch job: its
credential arrives from the Vault Agent sidecar on an in-pod volume and its
probes are exec probes, so nothing needs to reach it. Local Checkov: 88
passed, 0 failed.

**Control added.** None was needed. The control that caught it is Checkov
in the pipeline, and it worked. The production step still open is an
egress allow-list per destination.

**Evidence.** #114.

## 7. Every plan showed six changes nobody made

**What happened.** Every pull request's Terraform plan said six SSO apps
would "update their owners". Nobody had changed them.

**How I found it.** Reading plan comments before merging. A plan that always
shows noise trains reviewers to skim, and then a real change hides in it.

**Root cause.** The apps module set the owner to whoever ran Terraform. PR
plans run as the read-only PLAN identity, applies as APPLY, and local runs
as a person, so each one proposed a different owner.

**Fix.** #117: the owner is a fixed identity, the APPLY app, named by client
id; the caller is only a fallback.

**Control added.** A mocked test: the owners are APPLY plus the named human,
never the caller. #117's own plan showed no owner changes.

**Evidence.** #117, #119.

## 8. The admin robot could escape its own AWS guardrails

**What happened.** The lab operator (the certificate-only workload identity
that does unattended admin work, ADR 0024) gets AWS administrator rights
minus guardrails. The guardrails could be bypassed.

**How I found it.** Code review on #110: the operator could create a second
role, attach AdministratorAccess to it and assume it. That session would
carry none of the operator's Deny rules, and it could create users and
access keys that would survive the Entra kill switch.

**Root cause.** The Deny statements protected only the operator's own role.
Least privilege written against one resource, when the risk is a whole class
of actions.

**Fix.** An account-wide explicit Deny on every IAM write, plus PassRole and
IAM Roles Anywhere (`d10d3b7`). IAM changes stay human-applied, like the
GitHub role. Live check: `CreateAccessKey` and `UpdateAssumeRolePolicy` are
refused with "explicit deny".

**Control added.** The Deny itself, in Terraform. And a question I now ask
on every grant: can this identity reach the same thing by another route,
such as creating a new role?

**Evidence.** #110.

## 9. Two checks that could pass without checking

**What happened.** Code review of #111 found two fail-open paths before it
merged.
- The evidence pack downloads every stored file again and compares hashes.
  But a download that timed out was recorded as an error that the final
  check never counted, so the run still said "filed".
- The HR feed workflow sends only what changed since the last push. When
  no successful push was on record, or the run history could not be read,
  it fell back to the previous commit, as if the earlier change had been
  sent. A failed hire could be skipped forever.

**How I found it.** Code review (two P1 findings).

**Root cause.** In both, "I could not check" was treated the same as
"nothing to report".

**Fix.** `825e621`, `763c26f`: a read-back that does not finish fails the
run as "could not be checked", never "filed". The HR feed's starting point
is the last push Microsoft accepted, and if the run history cannot be read
the run stops instead of guessing. A failed run's summary states only the
retention lock the store actually reported. New tests fail against the old
code.

**Control added.** The rule I review for now: when a lookup fails, stop.
"Not found" and "could not read" are different answers.

**Evidence.** #111; `lab/evidence/README.md` (evidence pack section).

## 10. The audit evidence pack was one record short, and a KPI never counted the leaver

**What happened.** The evidence pack from GitHub Actions filed 6 of 7
records, twice. The PIM activation history (who elevated, when, why) was
refused. Separately, the KPI "minutes from HR leaver to account disabled"
had said "not measured" since the leaver ran.

**How I found it.** The pack's summary says "6 of 7 records" and the
manifest names the failure (`PermissionScopeNotGranted`). For the KPI, I read
the raw provisioning log for the leaver event.

**Root cause.**
- *Pack:* the first fix (#120) gave the evidence identity a read permission,
  but Microsoft's documentation lists a ReadWrite permission as the least
  privileged one for that list API. No read-only grant could ever work, and
  the filter it used was itself rejected (`InvalidFilter`).
- *KPI:* the script counted only `disable` events. Provisioning from HR to
  on-site AD logs a leaver as `update` with `accountDisabled -> True`.

**Fix.** #129: the activation history comes from the directory audit log,
which the identity can already read, matched to the request ids so nothing
is counted twice. The evidence identity stays read-only. #139: the KPI
accepts the update form, once per person.

**Control added.** Tests for both, written to fail against the old code. A
written rule as well: check Microsoft's permission table before adding a
permission, and prefer a different read path over a write permission.

**Evidence.** #120, #129, #139; E72 (the leaver now measures 2.7 minutes
from HR to Entra disable).

---

**What these have in common.** Most of these are not bugs in what the
controls do. They are gaps between what the code says and what the tenant
actually has: a pass that was skipped, a credential that was never applied,
a schema Microsoft changed, a response shape the mocks did not model. That
is why the lab has a nightly drift check, evidence that is read back after
it is filed, and a capture log that records only what I saw.
