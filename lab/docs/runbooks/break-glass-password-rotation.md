# Runbook: rotate a break-glass password

**Scenario:** Contoso Health lab (fictional 5,000-user hospital).

> **Status: BUILT, not run.** On 2026-11-07 a read-only check showed that
> neither break-glass password was ever rotated (capture log E11f). The
> seeded value still sits in Terraform state and still works.

## Why

`modules/groups` creates bg-admin-01 and bg-admin-02 with a generated
password (`random_password`). That value is in Terraform state. The PLAN
identity can read state (ADR 0003). So until a person rotates it, anyone who
can read state can read a working Global Administrator password.

## Who

The lab **owner**, as a human Global Administrator or Privileged
Authentication Administrator. Only those roles can reset a Global
Administrator's password. The lab operator must never hold them, so it
cannot do this. The script refuses a service-principal sign-in.

## When

- Once now (it was never done).
- After every break-glass use or drill that used the password.
- When a custodian leaves.
- At least once a year, with the quarterly drill in the same quarter.

## Steps

1. Open a terminal on the owner's Mac. Sign in to Azure CLI as yourself:
   `az login --tenant 86a2e327-4951-4348-a3c4-6f4b79ffd8f2`.
2. Dry run (changes nothing):
   `lab/scripts/break-glass/rotate-password.sh bg-admin-01`
   Check the account, the "Password set" date and the Keychain item name.
3. Rotate: `lab/scripts/break-glass/rotate-password.sh bg-admin-01 --apply`.
   - The new password goes straight into the login Keychain
     (`contoso-breakglass-bg-admin-01-password`). It is never shown.
   - The script reads back `lastPasswordChangeDateTime`.
4. Do steps 2 and 3 again for `bg-admin-02`.
5. Commit the two records the script wrote in `lab/evidence/break-glass/`.
   Append the two capture-log rows it printed (give each a new id).
   The record and the row say "the lab owner". They do not name your login,
   because this repo is public. Do not add your login to them.
6. Check the passkey still signs in (the next drill, `break-glass-drill.md`).
   The password is the backup. The passkey is the sign-in.
7. Check Sentinel for an incident on the reset. If one opened, close it
   with this runbook as the reason.

## What this does not fix

- Both break-glass passkeys and the new passwords are still in the same
  Mac Keychain as the operator key (review finding B2). Production keeps
  each credential on a hardware key or in a sealed envelope, in two
  separate safes, with two custodians.
- A cloud user's password method cannot be deleted, so the password stays
  as a backup credential.

## If it fails

The script keeps a new password under a `-pending` Keychain name until
Entra accepts it. It never deletes that item when it cannot prove the item is
unused.

- **The reset call failed (outcome unknown):** a failed call does not prove
  that the reset did not happen. The connection can drop after Entra changed
  the password. So the `-pending` item can hold the only copy of the working
  password. Do not delete it. Run:
  `lab/scripts/break-glass/rotate-password.sh bg-admin-01 --resume`.
  Resume sends the same pending value again. When Entra accepts it, the
  script promotes the item to the real name. Now the account and the
  Keychain hold the same value.
- **`--apply` refuses because a `-pending` item exists:** an earlier run did
  not finish. Do not delete the item. Run `--resume`, as above.
- **`--resume` fails too:** keep the item. Check the error (for example: no
  role, or Entra is down). Fix the cause, then run `--resume` again. The
  passkey still signs in while you do this.
- **Keychain read-back did not match:** nothing was sent to Entra. The
  script stops before the reset. Run `--resume` (it sends the saved
  value), or ask a second admin to check the item first.
