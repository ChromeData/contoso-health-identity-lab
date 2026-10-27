# 05 · Directory (stage `dc`)

Draft: written before this stage first ran in the lab tenant. Steps marked (verify) are checked during the first build.

**What you build:** the on-premises side. One Azure VM becomes `DC01`, the
forest root for `corp.<your domain>`, with one drawer (OU) per department and
one for leavers. The Cloud Sync agent copies people up to Entra, and the HR
provisioning app is ready to write workers into AD.

**Whisperglass:** *Contoso 02 · Directory*.

**Starts from:** `turn where` says `sentinel`.

**Heads-up:** a tenant younger than 48 hours is capped at 600 directory
objects, and the VM's managed identity counts as one: sign up two days before
this stage. The VM costs Azure compute and shuts itself down every evening.

## Steps

| # | You do | Look at | You should see |
|---|---|---|---|
| 1 | Read the Map part of *Contoso 02*. | the lab map | the directory station: AD DS, Cloud Sync, Entra ID |
| 2 | `turn pr dc` | the terminal | one flag `false -> true`: `enable_dc`, then `Success! 13 passed`, then the steps after the apply: 01 forest, reboot, 02 configure, 04 Cloud Sync agent, then `New-InboundProvisioningApp.ps1` |
| 3 | Press **Enter**, wait for green checks, show the **Terraform plan** comment | the PR | the VM `vm-dc01` with its network rule, its data disk and its nightly shutdown in the plan |
| 4 | **Merge pull request**, **Confirm merge** | the PR | "Merged" |
| 5 | `turn approve`, comment **approve** in the issue, then `turn watch` | the approval issue, then the terminal | the issue closes as approved; the apply ends in a green tick |
| 6 | `turn outputs` (this also connects Terraform to the state, which the next step reads) | the terminal | `saved (... bytes)` |
| 7 | Set the names: `RG=rg-identity-lab VM=vm-dc01 DOMAIN=<your domain>`, then `KV=$(terraform -chdir=lab/terraform/envs/dev output -raw key_vault_uri \| sed -E 's#https://([^.]+).*#\1#')` | the terminal | `echo $KV` prints the vault's name |
| 8 | Build the forest (about 10 minutes): `az vm run-command invoke -g $RG -n $VM --command-id RunPowerShellScript --scripts @lab/scripts/dc/01-Install-ADDSForest.ps1 --parameters "DomainName=corp.$DOMAIN" "NetbiosName=CORP" "KeyVaultName=$KV"` | the terminal | `DSRM password stored (value not displayed).`, then `Promotion staged. Restart the VM now (az vm restart), then run 02-Configure-Domain.ps1.` |
| 9 | `az vm restart -g $RG -n $VM` | the terminal | the command returns once the VM is back |
| 10 | Configure the domain (about 5 minutes): `az vm run-command invoke -g $RG -n $VM --command-id RunPowerShellScript --scripts @lab/scripts/dc/02-Configure-Domain.ps1 --parameters "KeyVaultName=$KV" "UpnSuffix=$DOMAIN"` | the terminal | `+ OU` lines (Workforce and its six departments, Disabled, ServiceAccounts, PrivilegedAccounts), `KDS root key created`, `Enterprise Root CA installed`, then under `Paste into the provisioning app -> Mappings -> parentDistinguishedName` an expression starting `IIF([active]="False"`. Copy it somewhere private. |
| 11 | Wait two minutes, then run the command under *Verify* in `lab/scripts/dc/README.md` | the terminal | the domain, the OUs, your UPN suffix, the five accounts `svc-vault-rotator`, `svc-pam-discovery`, `svc-backup`, `tier0-admin-01`, `tier0-admin-02`, and `TcpTestSucceeded : True` (LDAPS on 636) |
| 12 | `az keyvault secret list --vault-name $KV -o table` | the terminal | names only: `dc01-dsrm-password`, `svc-vault-rotator`, `svc-pam-discovery`. No value is ever shown. |
| 13 | Optional, for the vault stage later: `az vm run-command invoke -g $RG -n $VM --command-id RunPowerShellScript --scripts @lab/scripts/dc/03-Get-LdapsCaCert.ps1` | the terminal | a `-----BEGIN CERTIFICATE-----` block: the lab root CA, public only. `lab/pam/vault-onboard-ad.sh` fetches it itself when the vault is built. |
| 14 | Off camera: RDP to the DC (address: `terraform -chdir=lab/terraform/envs/dev output -raw dc_public_ip`; password to the clipboard: `terraform -chdir=lab/terraform/envs/dev output -raw dc_admin_password \| pbcopy`). Change the password at once and store the new one in Key Vault as `dc01-admin-password` | Remote Desktop | signed in as `contosoadmin`; the new password is in the vault |
| 15 | Entra admin center: **Entra Connect → Cloud sync → Agents → Download on-premises agent**. Copy the installer's link, not the file | the Entra admin center (verify: how the page offers the link) | an `https://` link |
| 16 | Fill in the agent's inputs without printing secrets: `URL='<installer link>' UPN='<your Hybrid Identity Administrator account>'`, then `read -rs HPW` (that account's password) and `read -rs DPW` (the `contosoadmin` password from step 14) | the terminal | nothing echoed |
| 17 | Install the agent: `az vm run-command invoke -g $RG -n $VM --command-id RunPowerShellScript --scripts @lab/scripts/dc/04-Install-CloudSyncAgent.ps1 --parameters "InstallerUrl=$URL" "HybridAdminUpn=$UPN" "DomainName=corp.$DOMAIN" "DomainAdminUser=CORP\\contosoadmin" --protected-parameters "HybridAdminPassword=$HPW" "DomainAdminPassword=$DPW"` | the terminal | `Signature OK:` naming Microsoft Corporation, then `Agent service is Running.` |
| 18 | Refresh **Cloud sync → Agents** | the Entra admin center | the agent on DC01 is **Healthy** |
| 19 | The HR provisioning app: `pwsh`, then `Connect-MgGraph -TenantId <tenant id> -Scopes Application.ReadWrite.All,Synchronization.ReadWrite.All`, then `./lab/scripts/mock-hr/New-InboundProvisioningApp.ps1 -Target AD -WhatIf`, then the same without `-WhatIf` | the terminal | the dry run: `WhatIf: would instantiate 'API-driven provisioning to on-premises Active Directory' as 'Contoso HR Inbound Provisioning'`; the real run: `ServicePrincipalId` and `JobId`. Keep both somewhere private: they are `<spId>` and `<jobId>` in the next run sheets. |
| 20 | **Enterprise applications → Contoso HR Inbound Provisioning → Provisioning**: assign the DC01 agent and `corp.<your domain>` to the job | the provisioning app (verify: where the page offers this) | the agent assigned to the job |
| 21 | Under **Mappings**, set `parentDistinguishedName` to the expression from step 10, *Apply this mapping: Always*. Map the extension's `hireDate` into `msDS-cloudExtensionAttribute1` with `FormatDateTime` (verify: the exact expression) | the attribute mappings (verify: the click path) | the expression's source attribute reads `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department` (verify) |
| 22 | **Entra Connect → Cloud sync → + New configuration → AD to Microsoft Entra ID sync**, select `corp.<your domain>`, **Scoping filters → Selected organizational units**: `OU=Workforce` and `OU=Disabled`. Map `msDS-cloudExtensionAttribute1` to `employeeHireDate`. Enable the configuration | the Entra admin center (verify: where the hire-date mapping is) | the configuration enabled, scoped to those two OUs only. Never `OU=ServiceAccounts` or `OU=PrivilegedAccounts`. |
| 23 | Read the Proof part | | |

## Say this, in your own words

- Active Directory is the filing cabinet: one drawer per department, and one
  drawer for leavers.
- Cloud Sync, not Connect Sync: a small agent, no SQL server, no second server
  to patch. It copies people up to Entra, never down. Decision record 0001 says
  what we gave up.
- Tier 0 stays at home: service and admin accounts are never copied to the
  cloud.
- No password crosses a person or the pipeline. The DC makes them and writes
  them straight into Key Vault; the agent's two passwords travel encrypted.
- Nothing unsigned runs on the DC: the agent installer is refused unless
  Microsoft signed it.
- People arrive in the next run sheet, from HR. Nobody is typed in by hand.

## If something goes wrong

| What you see | Do this |
|---|---|
| The apply fails with `FailedIdentityOperation ... directory object quota limit` | The tenant is younger than 48 hours. Wait for the cap to lift, then **Re-run failed jobs**. |
| A run-command step hangs or says the VM is not running | The nightly shutdown stopped it: `az vm start -g $RG -n $VM`, then run the step again. Every script is safe to run twice. |
| Step 8 says `Key Vault not writable yet ... retrying in 30s` | Normal for a few minutes. It gives up after ten. |
| Step 10 stops with `AD CS: CertSvc is not running` | Setting up the CA as SYSTEM may need an Enterprise Admin credential (verify, `lab/scripts/dc/README.md`). |
| `TcpTestSucceeded : False` on 636 | The DC certificate has not landed. Run `certutil -pulse` on the DC through run-command, wait two minutes, check again. |
| Step 17 fails at registering the agent with an `AADSTS` error | That account had to do MFA, and the agent sign-in is password-only. Use an account scoped to Hybrid Identity Administrator. |
| `Refusing to run the installer` | The link was not the Microsoft-signed agent. Copy it again (step 15). |

## Do it again

`lab/scripts/demo/rewind-lab.sh sentinel --open-pr`, merge, do the cleanup it
prints (the Cloud Sync configuration, then the agent; the **Contoso HR Inbound
Provisioning** app; the HR users), then start from step 2.
