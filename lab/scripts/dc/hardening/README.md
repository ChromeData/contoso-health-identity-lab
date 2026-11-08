# AD hardening on DC01: tiers, Protected Users, Windows LAPS

Status: **RAN · tenant** on DC01, 2026-11-07. Evidence: `lab/evidence/ad-hardening/20261107T0057Z`
(capture log E116 to E118).

Each script runs on DC01 as SYSTEM through `lab/scripts/dc/run-on-dc.py`. Without `Apply=yes`, each one
only prints what it would do. Each one is safe to run again. All files here are ASCII only, because
Windows PowerShell 5.1 reads a file without a BOM as ANSI.

| Script | What it does |
|---|---|
| `Invoke-PingCastle.ps1` | The free PingCastle health check, pinned by SHA-256 and signature. It reads only and prints the scores. |
| `Set-AdTiering.ps1` | Creates the Tier 0/1/2 OUs and groups and the accounts `t0-adm-01`, `t1-adm-01` and `t2-adm-01`. It adds those three accounts (and only those) to Protected Users. It creates the GPO `Tier0 - Deny logon to Tier1 and Tier2`. |
| `Enable-WindowsLaps.ps1` | Extends the schema for Windows LAPS and sets the permissions. It creates two GPOs that back up to AD with encryption: DC01's DSRM password, and the local admin password on Tier 1 servers. `Rotate=yes` proves one rotation. |
| `Test-AdHardening.ps1` | Reads back every setting above and prints PASS or FAIL. `SignIn=yes` adds the sign-in proof (see below). |

## Review fixes after the live run (PR #225, Greptile)

These four changes came after the 2026-11-07 run. They are tested offline (Pester) and have **not run on DC01 yet**,
because DC01 was deallocated after the job. The live results above came from the earlier version.

- `Set-AdTiering.ps1`: a dry run no longer needs the three passwords. Only an apply that creates an account needs them.
- `Test-AdHardening.ps1`: each LAPS GPO must be linked, enabled, to exactly its OU (Domain Controllers, or
  Tier1\Servers). The server policy's decryptor must be `<NETBIOS>\Tier1-Admins`. The deny-logon GPO check now
  also fails on a disabled link.
- `Test-AdHardening.ps1`: `SignIn=yes` without `T2Password` now stops before it creates anything, instead of
  skipping the Protected Users half.
- `Invoke-PingCastle.ps1`: on every run, it deletes the extracted folder and extracts again from the hash-checked
  zip. A cached exe is never reused.

## Run it

```bash
OP=lab/scripts/operator/op
$OP python3 lab/scripts/dc/run-on-dc.py lab/scripts/dc/hardening/Set-AdTiering.ps1 --param Apply=yes \
  --secret T0Password=keychain:contoso-lab-ad-t0-adm-01 \
  --secret T1Password=keychain:contoso-lab-ad-t1-adm-01 \
  --secret T2Password=keychain:contoso-lab-ad-t2-adm-01
$OP python3 lab/scripts/dc/run-on-dc.py lab/scripts/dc/hardening/Enable-WindowsLaps.ps1 --param Apply=yes --param Rotate=yes
$OP python3 lab/scripts/dc/run-on-dc.py lab/scripts/dc/hardening/Test-AdHardening.ps1 --param SignIn=yes \
  --secret T2Password=keychain:contoso-lab-ad-t2-adm-01
$OP python3 lab/scripts/dc/run-on-dc.py lab/scripts/dc/hardening/Invoke-PingCastle.ps1 --param Label=after
```

The three admin passwords were generated on the Mac straight into the login Keychain
(`contoso-lab-ad-<account>`) with `security -i` over stdin. They were never printed and never put in argv.

## What is true and what is not

- **True:** the tiers, groups and accounts exist. The three new admins are in Protected Users and
  "cannot be delegated". `tier0-admin-01`, `tier0-admin-02` and `contosoadmin` are **not** in
  Protected Users (see the next section).
- **True:** the deny-logon GPO holds all five Deny rights for Domain Admins, Enterprise Admins,
  Schema Admins and Tier0-Admins. It is linked only to `Tier1\Servers` and `Tier2\Devices`.
- **Not in effect yet:** no computer is in those OUs today. DC01 is the only computer in AD, and
  `vm-win11-01` is not domain-joined. The GPO denies nothing until a server or PC joins those OUs.
- **True:** Windows LAPS manages DC01's DSRM password. The password is encrypted in AD (only
  Domain Admins can decrypt it) and rotates every 30 days. One forced rotation ran at
  2026-11-07T01:02:04Z (event 10018).
- **Built, not running:** the Tier 1 server LAPS policy is linked, but there are no member servers.
- **Key Vault is now out of date:** the `dc01-dsrm-password` secret holds the FIRST DSRM password,
  from `01-Install-ADDSForest.ps1`. The current one is in AD. A Domain Admin reads it with
  `Get-LapsADPassword -Identity DC01 -AsPlainText`.

## Why the old admins stay out of Protected Users

Protected Users turns off NTLM, DES/RC4 Kerberos and credential delegation for its members
(Microsoft Learn, "Protected Users security group"). The lab's current remote-session path into
DC01 signs in with NTLM. If `tier0-admin-01`, `tier0-admin-02` or `contosoadmin` joined the group,
that path would stop working. The new accounts show the target state. `Test-AdHardening.ps1`
proves the effect: `t2-adm-01` signs in with Kerberos, and NTLM refuses it. The fix is to move the
remote-session path to Kerberos and then add the old accounts. Until then, PingCastle keeps
`P-ProtectedUsers` (3 admins outside the group).

## The sign-in proof

`SignIn=yes` creates a temporary plain domain user in `CN=Users`, which is outside the Cloud Sync
scope, so the user never reaches Entra. Its random password exists only in memory. The user binds
to LDAP with Kerberos and with NTLM, and the script then deletes it. This proves that a normal user
still signs in after the hardening. Cloud Sync health is a separate Graph read of the
synchronization jobs (evidence file 09).
