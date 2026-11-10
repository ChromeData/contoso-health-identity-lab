# Intune compliance baseline + CA005 (compliant device for admin portals)

**Hardware stand-in only.** Microsoft Intune, Entra join and Conditional Access
are the real products. The only substitution is the hardware: the "corporate
laptop / privileged-access workstation" is a Windows 11 Enterprise **Azure VM**
(`lab/terraform/modules/intune-vm`), listed in
[`STAND-INS.md`](../../docs/STAND-INS.md) and named on camera in §4.

The story: *admin portals only from a managed, healthy device* - rolled out
**report-only first** and to a **pilot group first**, exactly like every other
Conditional Access policy in this lab.

| Piece | Where | Owns |
|---|---|---|
| CA005 policy | `lab/terraform/modules/conditional-access` (`CA005`) | *Require compliant device* for **Microsoft Admin Portals** + **Windows Azure Service Management API**, pilot group only, break-glass excluded, report-only by default |
| Pilot group | `lab/terraform/modules/groups` → `CA005-Pilot-CompliantDevice` (`ca005-pilot-compliantdevice`) | Scope of CA005, target of the compliance policy, *VM Administrator Login* on the VM |
| Compliant device | `lab/terraform/modules/intune-vm` (`enable_intune_vm`) | Windows 11 Enterprise VM, Trusted Launch, Entra joined + Intune auto-enrolled by the `AADLoginForWindows` extension (`mdmId`) |
| What "compliant" means | `New-IntuneComplianceBaseline.ps1` (this folder) | Windows 10/11 compliance policy: Secure Boot, code integrity, min OS 10.0.26100 (BitLocker opt-in); assigned to the pilot group |

### Why a pilot group and not "all admins"

The operator administers this lab from a **personal Mac** that is not, and will
never be, Intune-enrolled. CA005 scoped to every admin role would - the moment
it is enforced - lock the operator out of the Azure portal **and** break `az` /
Azure PowerShell (both ride the Windows Azure Service Management API). So CA005
includes only `CA005-Pilot-CompliantDevice`. Never add your everyday admin
account to it. Production widens the include to the admin roles once every
admin has a compliant privileged-access workstation.

---

## Prerequisites (human, once)

1. **Licences.** The pilot user holds a **Microsoft 365 E5 (trial)** licence:
   Entra ID P1/P2 (Conditional Access, automatic MDM enrollment) + Intune
   Plan 1. The tenant must have Intune active, or the Graph Intune APIs fail.
   The pilot user is an IT test account, never a clinical persona. The
   cloud-only `adm-` admin accounts carry no licence by design
   (`New-AdminAccounts.ps1` warns on one), so decide before the trial which
   licensed account pilots CA005 (verify: whether Intune evaluates
   compliance for an unlicensed user signing in to an enrolled device).
2. **Windows 11 licensing on Azure.** The VM sets `license_type =
   "Windows_Client"` (multitenant hosting rights). Microsoft lists
   Microsoft 365 E3/E5 as a qualifying entitlement - here that is the E5
   **trial**, so treat the VM as dev/test only and deallocate/destroy it when
   the trial ends. *(verify: whether a trial licence confers hosting rights is
   a licensing question for your Microsoft contact.)*
3. **CI may grant the VM login role.** `envs/bootstrap/main.tf` now lists
   *Virtual Machine Administrator Login* (`1c0163c0-47e6-4577-8991-ea5c82e286e4`)
   in `delegable_role_ids`. **Re-apply `envs/bootstrap` locally** before the
   pipeline applies `enable_intune_vm = true`, or the role assignment is
   refused by the ABAC condition.
4. **MDM user scope** (tenant-wide - no Terraform resource) - **before** the
   VM is created. The extension attempts the Intune enrollment *during the
   join*, when it installs at apply time, before anyone signs in to the VM.
   Intune admin center → **Devices → Device onboarding → Enrollment → Windows
   → Automatic Enrollment** → **MDM user scope = Some →
   `CA005-Pilot-CompliantDevice`** (or *All* - the simplest choice in a
   throwaway lab tenant); **WIP user scope = None** → Save. (Older
   docs/portal: Entra → *Mobility (MDM and WIP)* → *Microsoft Intune* - same
   setting.) *(verify: Microsoft doesn't document whether scope "Some" is
   honoured for this no-user-at-join enrollment - see step 3a if the VM never
   appears in Intune.)*
5. **Recommended:** Intune → **Devices → Compliance → Compliance policy
   settings → "Mark devices with no compliance policy assigned as" = Not
   compliant**, so "Compliant" in the demo always means "passed a policy".

---

## Demo flow

### 1 · Pilot membership + the compliance policy

```powershell
Connect-MgGraph -Scopes 'DeviceManagementConfiguration.ReadWrite.All','Group.Read.All','User.Read.All','GroupMember.ReadWrite.All','DeviceManagementManagedDevices.Read.All'

# Dry run first - reads everything, changes nothing.
./New-IntuneComplianceBaseline.ps1 -PilotMemberUserPrincipalNames '<pilot-user>@<your-domain>' -WhatIf
./New-IntuneComplianceBaseline.ps1 -PilotMemberUserPrincipalNames '<pilot-user>@<your-domain>'
```

Re-running is a no-op. Changing a setting (e.g. `-MinimumOsVersion`) PATCHes
only the drifted property; settings you add in the portal are never removed.

> **BitLocker is opt-in.** The default policy requires Secure Boot + code
> integrity + min OS - nothing to do inside the VM. Azure VMs don't ship with
> BitLocker on (Azure encrypts disks server-side), and Microsoft's Windows 365
> known-issues page (Cloud PCs are Azure VMs) says *Require BitLocker* may
> report **Not Compliant** there. To show it anyway: turn it on inside the VM
> (step 3b), then re-run with
> `-HealthChecks SecureBoot,CodeIntegrity,BitLocker` - the script PATCHes only
> `bitLockerEnabled`.

Defender antimalware / real-time protection / firewall / TPM checks exist in
Intune but **not** in the Graph **v1.0** `windows10CompliancePolicy` schema
(only `/beta`). Add them in the portal if you want them (policy → Properties →
System Security).

### 2 · The VM: Entra join + Intune auto-enrollment

PR flipping `enable_intune_vm = true` in `envs/dev/lab.tfvars` (with
`enable_premium = true` already on) → approve `prod`. Terraform creates
`vm-win11-01` (hostname **`CH-WIN11-01`**), the `AADLoginForWindows`
extension Entra-joins it and (with `mdmId`) enrolls it into Intune, and the
pilot group gets *Virtual Machine Administrator Login* on the VM.

### 3 · Sign in to the VM (Azure Bastion only, since 2026-11-08)

The PC has **no public IP and no inbound NSG rule**: the only admin path is
Azure Bastion from inside the VNet, which `lab/bastion/capture.sh` brings up
for a session and deletes afterwards (cost). In the Azure portal: **vm-win11-01
> Connect > Bastion**.

- With session recording on (the capture's Premium Bastion), Learn says Entra
  ID RDP in the portal "can't be used concurrently with graphical session
  recording", so sign in with a local account's password.
- For an Entra sign-in, use a Bastion without recording: Authentication type
  **Microsoft Entra ID**; the user needs *Virtual Machine User Login* (or
  Administrator Login) on the VM.

The older path (RDP straight to the PC's public IP from the Mac, with an
`/etc/hosts` entry and the `.rdp` output) no longer works: there is no public
IP. The `.rdp` output stays for a client with a private path to the PC.

- *verify:* Microsoft documents `enablerdsaadauth` for *Remote PC connections*
  (and says the client needs no domain/Entra join for the web-account option)
  but doesn't list Windows App for macOS on that path by name; community
  guidance says it works. **Last-resort fallback, not Microsoft-documented
  for a standalone VM:** add `targetisaadjoined:i:1` to the `.rdp` and sign in
  with a password as `AzureAD\<upn>`. Microsoft documents that property for
  Azure Virtual Desktop host pools only, and the password path to a
  standalone Entra-joined VM only from Windows PCs registered/joined to the
  same tenant. It is password-only, so it stops working once **CA001 (MFA)**
  is enforced.
- The Mac never has to be enrolled for RDP: CA005 targets the admin portals,
  not the *Microsoft Remote Desktop* / *Azure Windows VM Sign-In* resources.
- Local break-glass into the VM, off camera and only if Entra sign-in fails
  (user `contosolocal`): copy the password straight to the clipboard so it is
  never printed,
  `terraform -chdir=lab/terraform/envs/dev output -raw intune_vm_admin_password | pbcopy`
  (macOS; `clip.exe` on Windows, `xclip -selection clipboard` on Linux).

**3a · Confirm join + enrollment** (inside the VM, PowerShell):

```powershell
dsregcmd /status | Select-String 'AzureAdJoined|AzureAdPrt|MDMUrl'   # AzureAdJoined : YES
```

Settings → Accounts → Access work or school shows the tenant with an **Info**
button (= MDM-managed). In Intune admin center → Devices → Windows,
`CH-WIN11-01` appears. Enrollment was attempted when the extension joined the
VM at apply time, not when you signed in. If the device is missing after
~15 min and a reboot: the MDM user scope / licence (prereqs 1 + 4) was most
likely not in place at apply time, or scope *Some* isn't honoured for this
no-user enrollment. Set the scope to **All**, delete `CH-WIN11-01` from Entra
(Devices → All devices), then re-create the VM - two PRs
(`enable_intune_vm = false`, then `true`), or locally
`terraform apply -replace='module.intune_vm[0].azurerm_windows_virtual_machine.vm'`.
*(verify: community-reported, not in Microsoft docs - a device that joined
before auto-enrollment was set up doesn't enroll on its own later.)*

**3b · BitLocker (optional - only if you add the BitLocker check)** - inside
the VM, elevated Windows PowerShell 5.1 (the VM's built-in shell):

```powershell
# vTPM protector + encryption first, then a recovery password escrowed to Entra.
Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector
Add-BitLockerKeyProtector -MountPoint 'C:' -RecoveryPasswordProtector
$kp = (Get-BitLockerVolume -MountPoint 'C:').KeyProtector |
    Where-Object KeyProtectorType -eq 'RecoveryPassword' | Select-Object -Last 1
BackupToAAD-BitLockerKeyProtector -MountPoint 'C:' -KeyProtectorId $kp.KeyProtectorId
Restart-Computer
```

Then, from your workstation:
`./New-IntuneComplianceBaseline.ps1 -HealthChecks SecureBoot,CodeIntegrity,BitLocker`.

*(verify: in-guest BitLocker on a Trusted Launch VM uses its vTPM; Azure's own
supported disk-encryption options are SSE / encryption at host. The
production-grade alternative is an Intune **Endpoint security → Disk
encryption** policy that enables BitLocker silently.)*

### 4 · Compliant in Intune

Device health checks (Secure Boot, code integrity - and BitLocker if you added
it) are **measured at boot** - restart the VM once after enrollment (and after
BitLocker), then
Settings → Accounts → Access work or school → Info → **Sync**.

```powershell
./New-IntuneComplianceBaseline.ps1 -ShowDeviceCompliance      # CH-WIN11-01  compliant
```

Intune admin center → Devices → Compliance → *Contoso Health - Windows
compliance baseline* → **Device status** = Compliant.

### 5 · CA005 report-only result (the on-camera moment)

1. **Inside the VM**, Edge (signed in with the Windows/Entra account - Edge
   passes the device identity automatically) → `portal.azure.com` as the pilot
   user.
2. **On the Mac**, a browser → `portal.azure.com` as the same pilot user.
3. Entra → Sign-in logs → each sign-in → **Report-only** tab → **CA005**:
   - VM sign-in: **Report-only: Success** (device compliant).
   - Mac sign-in: **Report-only: Failure** (device not compliant / unknown).

Microsoft documents that a report-only compliant-device policy can make macOS
/ iOS / Android **prompt the user to pick a device certificate**. Only the
pilot account is in scope, so the prompt can only ever reach the pilot account.

Optional KQL (Log Analytics `loga-idlab`, once Entra logs flow):

```kusto
SigninLogs
| where TimeGenerated > ago(1d)
| mv-expand cap = ConditionalAccessPolicies
| where tostring(cap.displayName) startswith "CA005"
| project TimeGenerated, UserPrincipalName, AppDisplayName,
          os = tostring(DeviceDetail.operatingSystem),
          compliant = tostring(DeviceDetail.isCompliant),
          result = tostring(cap.result)        // reportOnlySuccess / reportOnlyFailure / success / failure
```

### 6 · Enforce for the pilot

One-line PR in `envs/dev/lab.tfvars`:

```hcl
CA005 = "enabled" # compliant device, admin portals (pilot group)
```

After apply: the pilot user on the **Mac** is blocked from the Azure portal
with a "device must be managed/compliant" error (*verify: the exact AADSTS
code in the sign-in log - expected in the 53000 / 530003 family*); the same
user in the **VM** gets in. Your own admin account is untouched (not in the
pilot group), break-glass is excluded, CI's workload identities are outside
user CA.

**Rollback:** flip CA005 back to `enabledForReportingButNotEnforced` (one-line
PR) or remove the user from the pilot group.

### 7 · Teardown

`enable_intune_vm = false` (PR). Then delete the device object from **Intune**
(Devices → Windows → CH-WIN11-01 → Delete) **and Entra** (Devices → All
devices). Terraform doesn't own those objects, and Microsoft documents that a
re-join **fails** if a device with the same hostname still exists.

---

## Verify checklist

- [ ] `terraform output conditional_access_policy_ids` lists 5 ids; CA005 shows
      **Report-only** in the portal, *Users → Include* = `CA005-Pilot-CompliantDevice`,
      *Exclude* = `Break-Glass-Admins`, *Target resources* = Microsoft Admin
      Portals + Windows Azure Service Management API, *Grant* = Require device
      to be marked as compliant.
- [ ] `terraform output ca005_pilot_group_object_id` resolves to
      `CA005-Pilot-CompliantDevice` (assigned, security, not role-assignable).
- [ ] VM: Trusted Launch on, `licenseType = Windows_Client`, extension
      `AADLoginForWindows` provisioning *Succeeded*, NSG has only the operator
      RDP rule.
- [ ] `dsregcmd /status` in the VM → `AzureAdJoined : YES`, `AzureAdPrt : YES`.
- [ ] Intune → Devices → Windows lists `CH-WIN11-01`, ownership Corporate.
- [ ] Compliance policy exists once (re-run of the script reports `unchanged`)
      and is assigned to the pilot group.
- [ ] `-ShowDeviceCompliance` → `CH-WIN11-01 compliant` (after a restart).
- [ ] Sign-in logs: CA005 *Report-only: Success* from the VM, *Report-only:
      Failure* from the Mac (same pilot user).
- [ ] After enforcement: Mac blocked, VM allowed; operator's admin account
      unaffected; `bg-admin-01` shows *Conditional Access: Not applied*.

## What remains unverified (no tenant was available when this was written)

- `win11-25h2-ent` availability in `eastus2`. The SKU is listed by Microsoft
  (Azure Local "Azure Marketplace images" table: offer `windows-11`, SKUs
  `win11-23h2-ent` / `win11-24h2-ent` / `win11-25h2-ent`), but no region
  listing was run; run
  `az vm image list-skus -l eastus2 -p MicrosoftWindowsDesktop -f windows-11`.
- Windows App for **macOS** honouring `enablerdsaadauth` on a direct (non-AVD)
  connection, and the `targetisaadjoined` fallback from a Mac (Microsoft
  documents it for AVD only).
- Whether MDM user scope *Some* (pilot group) is enough for the extension's
  no-user-at-join enrollment, or *All* is needed (step 3a has the recovery).
- Device-health-attestation results (Secure Boot / code integrity, and
  BitLocker if added) on a Trusted Launch VM - expected to attest via the
  vTPM after a reboot; BitLocker is opt-in because Microsoft lists *Require
  BitLocker* as possibly Not Compliant on Windows 365 Cloud PCs.
  Microsoft has announced moving Windows health attestation to Microsoft Azure
  Attestation (Message Center; ~Q1 2027) - outbound HTTPS from the VM is
  required (the NSG allows outbound by default).
- Whether a compliance policy assigned to a **user** group evaluates on a VM
  whose enrollment was started by the extension rather than a user. If the
  device stays *Not evaluated*, also assign the policy to *All devices* in the
  portal for the lab.
- Exact AADSTS error code on the enforced Mac block.
- Every Graph call in the script ran only against an offline fake of the
  documented v1.0 endpoints, never a real tenant.

---

## EPM and LAPS proof (Intune PC) - `New-IntuneEpmAndLaps.ps1`

**Status: BUILT, not run.** The script creates three Intune policies. It has
not run, because the lab operator holds `DeviceManagementConfiguration.Read.All`
only, and creating a policy needs `DeviceManagementConfiguration.ReadWrite.All`.
A human Intune admin runs it once (delegated Graph). Nothing is bought.

**Licence (checked 2026-11-07, `subscribedSkus` as the operator).** The tenant's
Microsoft 365 E5 trial (`SPE_E5`, 25 seats, ends 2026-11-26) carries the
`Intune-EPM` service plan, provisioning status *Success*. Microsoft Learn
(*Intune advanced capabilities*): EPM comes with "Microsoft Intune Plan 2, the
Microsoft Intune Suite, and select Microsoft 365 bundles". This tenant's E5
SKU lists it, so no add-on and no trial is needed.

**The PC.** `CH-WIN11-01` (Azure VM `vm-win11-01`) is Entra joined and
Intune enrolled (`azureAdJoinUsingAzureVmExtension`, 2026-10-29). It is
deallocated when not in use.

| Policy | What it does |
|---|---|
| EPM - Settings (lab) | EPM on. Default response **Deny all requests**: only a file named by a rule can be elevated. Reports all elevations. |
| EPM - Rules (lab) | One rule: `procexp64.exe` by SHA-256 hash, **Support approved**, child processes denied. |
| LAPS - Intune PC (lab) | Windows LAPS on the built-in Administrator. Backup to **Microsoft Entra ID**, 7 days, 20 characters, all character types. One hour after someone uses the password, it is reset and the account is logged off. |

**The proof, when it runs (in this order):**

1. An Intune admin runs the script (`-WhatIf` first), then syncs CH-WIN11-01.
2. A **standard** user who holds the E5 licence signs in to the PC. She
   right-clicks `procexp64.exe`, chooses *Run with elevated access*, and types
   a business reason. The request appears in the Intune admin center:
   *Endpoint security > Endpoint Privilege Management > Elevation requests*.
3. An admin activates PIM-Tier1-Intune-Admins and approves, with a reason.
   The admin needs the Intune permission *Endpoint Privilege Management
   Elevation Requests* (view + modify).
4. The user gets a toast notification and runs the file elevated. Learn: the
   approval lasts **24 hours** from approval, and "there's no current support
   for a custom time period or cancellation". Say "for 24 hours", never "for
   a few minutes".
5. LAPS read-back: the device's *Local admin password* page shows a backup
   time. Reading the password itself needs `DeviceLocalCredential.Read.All` and
   an Entra role such as Cloud Device Administrator. The operator has neither.

To let the operator do steps 1 and 5 unattended, grant its app
`DeviceManagementConfiguration.ReadWrite.All` (and `DeviceLocalCredential.Read.All`
for the read-back). That is an owner decision: both are Tier-1 device rights.
