# CyberArk safes as code (psPAS), tested against a stub vault

Most CyberArk work is clicking through the web console, which leaves no
record of what anyone meant to set up. Here the intended safes, who is a
member of each (as one of three roles) and which accounts live in them are
one reviewed file, [`intended-state.json`](intended-state.json).
[`Invoke-SafeReconcile.ps1`](Invoke-SafeReconcile.ps1) finds every
difference between that file and the vault, through
[psPAS](https://github.com/pspete/psPAS) (the community PowerShell module for
CyberArk's REST API), and with `-Apply` fixes what it safely can.

> **Status: BUILT (tested offline against a stub vault). It has never run
> against CyberArk.** The lab has no CyberArk licence or tenant. The 53
> Pester tests run every script unmodified against
> [`tests/stubs/psPAS`](tests/stubs/psPAS/psPAS.psm1), a scripted vault in a
> JSON file with psPAS 8.2.0's parameter names, types and error shape. They
> run on every pull request in `lab-tests.yml`. That proves the drift logic,
> the fail-closed reads and exactly what `-Apply` writes. It does not prove
> that a real vault answers the way the stub does.

The safes mirror the lab's Vault stand-in: the `tier0-admins` and
`tier1-admins` library sets in [`../pam-policy.json`](../pam-policy.json)
become `CH-Tier0-Admins` and `CH-Tier1-Admins`. The day-to-day PAM demo
still runs on the Vault stand-in ([`../README.md`](../README.md)). This folder
is the same model written for CyberArk itself.

## The three roles

A safe membership is 22 separate yes/no permissions. The state file uses three
roles, and [`RoleMap.psm1`](RoleMap.psm1) is the only place they are turned
into permissions:

| Role | Can | Cannot |
|---|---|---|
| `audit` | list accounts, read the log, see members | retrieve a credential |
| `use` | retrieve, connect, ask the CPM to change a password | manage the safe or its members, delete |
| `full` | administer the safe and its members | approve access requests, or skip dual control |

## What it reports, and what `-Apply` does

| Drift | Means | `-Apply` |
|---|---|---|
| `UNEXPECTED` | a member nobody declared | reported only, never removed |
| `EXTRA_PERM` | a member holding more than their role | resets the member to exactly their role |
| `DUPLICATE` | the same account twice in a safe | reported only |
| `WRONG_PLATFORM` | an account under another platform | reported only |
| `MISSING` | a declared safe, member or account is not there | creates it (accounts with no secret: the CPM sets one) |
| `MISSING_PERM` | a member below their role | resets the member to exactly their role |

It **never deletes** a safe, member or account. A reconciler that can delete
will, the first time the file is wrong, revoke someone's access in the middle
of an incident. The stub has no `Remove-*` command at all, so a deletion
added later fails the tests.

Every read finishes before `-Apply` writes anything, so a failed read never
leaves a half-applied run. The report (console and `-JsonPath`) lists drift
in the order of the table above, most worrying first.

Exit codes: **0** in sync, **1** drift found (also after `-Apply`, so CI
shows it), **2** could not run: a bad state file (including a safe or
account declared twice), no session, any failed read other than "safe not
found", or a write the vault rejects.

## Run it

Against the stub (what CI runs):

```powershell
Invoke-Pester ./lab/pam/cyberark/tests -Output Detailed   # Pester 5.5+, PowerShell 7
```

Against a real self-hosted PVWA (**not run**: no tenant):

```powershell
Install-Module psPAS -RequiredVersion 8.2.0 -Scope CurrentUser
./lab/pam/cyberark/Connect-Lab.ps1 -BaseUri https://pvwa.example.org   # prompts; nothing stored
./lab/pam/cyberark/Invoke-SafeReconcile.ps1                            # report only
./lab/pam/cyberark/Invoke-SafeReconcile.ps1 -Apply -WhatIf             # what would change
./lab/pam/cyberark/Invoke-SafeReconcile.ps1 -Apply
./lab/pam/cyberark/Disconnect-Lab.ps1
```

[`New-LabSafe.ps1`](New-LabSafe.ps1) is a first-time setup helper: it
creates the safes and adds missing members only, with the same permissions
the reconciler uses.

To check on a first live run (open questions the stub cannot answer):
- Does the vault answer a missing safe with HTTP 404? The scripts treat only
  a 404 as "missing" and stop on anything else, so a different answer stops
  the run. It is never read as "missing".
- A real safe has members nobody adds by hand (built-in vault users, and
  the CPM's own user when `managingCPM` is set). psPAS's `Get-PASSafeMember`
  has an `-includePredefinedUsers` filter, and the script does not set it.
  Whether that keeps all of them out is unchecked. Any member it returns that
  the file does not declare shows as `UNEXPECTED`.
- Paging, and the exact objects psPAS returns for members and accounts.

## What was fixed while porting

Ported from the author's earlier psPAS-PAM-Automation lab (MIT, same
author). Each fix has a test that fails against the earlier code:

1. **`New-LabSafe.ps1` had its own role map, and it disagreed with
   `RoleMap.psm1`.** Its `audit` lacked ViewSafeMembers, and its `use` and
   `full` were short of 3 and 11 permissions, so every member it added was
   drift on the reconciler's first run. It also passed the permissions as
   `@($roleMap[...])`, an array rather than a splat, which fails to bind
   against psPAS's real `[boolean]` parameters. It now uses
   `Get-LabRolePermissionSet`, like the reconciler. A test builds the vault
   `New-LabSafe.ps1` leaves and checks the reconciler finds no drift in it.
2. **The stub hid bugs.** It accepted any parameter (a catch-all), so wrong
   names and the array-for-splat passed silently. It also returned nothing
   for a missing safe, where psPAS throws. It now copies psPAS 8.2.0's
   parameters exactly and throws like psPAS (`[404] ...`).
3. **A missing safe stopped the old reconciler.** `-ErrorAction
   SilentlyContinue` cannot catch psPAS's terminating errors. Against the
   corrected stub, the old reconciler died at the first missing safe, so
   `-Apply` could never create one. Any failed read also ended it with exit
   1, the "drift" code. Now a 404 is `MISSING`, and anything else is exit 2.
4. **`full` could skip dual control.** It held AccessWithoutConfirmation,
   which made "cannot approve its own request" meaningless. Removed. The
   lab's Tier-0 flow depends on two approvers.
5. **A reset relied on an unchecked API behaviour.** It sent only the true
   permissions and assumed the API clears the rest. Every add and reset now
   sends all 22, true or false.
6. Also: the state file is JSON (no `powershell-yaml`, and no
   `Install-Module` at run time), and it is validated before the vault is
   touched (unknown roles, missing fields, accounts in undeclared safes,
   duplicate members). The same account twice in a safe is reported as
   `DUPLICATE`.

Not ported: `Import-Accounts.ps1`. Onboarding accounts is the reconciler's
`-Apply`, which matches on user name and address exactly. The old script
skipped an account whenever a loose search found anything. The old
`findings/` files and status badge are not ported either, because they
describe the earlier repo's runs.
