# DC build — AD DS + AD CS on the Azure VM

The VM itself comes from `lab/terraform/modules/dc-vm` (`enable_dc = true`).
These scripts turn it into `DC01`, the forest root for `corp.<your-domain>`:
the on-premises side of HR → **AD** → Cloud Sync → Entra.

They run **inside the VM as SYSTEM** through `az vm run-command invoke`, so you
never need to RDP for the build. Windows PowerShell 5.1 runs them. Promotion
needs a reboot between the two phases, which is why this isn't a Terraform VM
extension.

| Script | What it does |
|---|---|
| `01-Install-ADDSForest.ps1` | NTDS data disk → `F:`, DSRM password generated **straight into Key Vault**, AD DS + DNS, new forest (no reboot) |
| `02-Configure-Domain.ps1` | DNS forwarder to Azure DNS, UPN suffix, OUs, KDS root key, AD CS (LDAPS), PAM-managed accounts + delegation, prints the provisioning OU expression |
| `03-Get-LdapsCaCert.ps1` | Prints the lab root CA certificate (PEM) for Vault's LDAPS trust |

## Run it

Before the VM exists: `enable_dc` creates a system-assigned managed identity,
which is a directory object. A tenant younger than 48 hours is capped at 600
objects and the apply fails with `FailedIdentityOperation ... directory object
quota limit`; wait for the cap to lift (see `lab/setup/SIGNUP-KIT.md`) and
re-run the apply.

```bash
RG=rg-identity-lab VM=vm-dc01
KV=$(terraform -chdir=lab/terraform/envs/dev output -raw key_vault_uri | sed -E 's#https://([^.]+).*#\1#')
DOMAIN=contosohealthlab.com            # your verified custom domain (handback.env CUSTOM_DOMAIN)

# 1) Forest (about 10 min)
az vm run-command invoke -g $RG -n $VM --command-id RunPowerShellScript \
  --scripts @lab/scripts/dc/01-Install-ADDSForest.ps1 \
  --parameters "DomainName=corp.$DOMAIN" "NetbiosName=CORP" "KeyVaultName=$KV"

# 2) Reboot to finish promotion
az vm restart -g $RG -n $VM

# 3) Domain configuration (about 5 min). Copy the OU expression it prints.
az vm run-command invoke -g $RG -n $VM --command-id RunPowerShellScript \
  --scripts @lab/scripts/dc/02-Configure-Domain.ps1 \
  --parameters "KeyVaultName=$KV" "UpnSuffix=$DOMAIN"
```

Step 3 now stops the script if AD CS cannot be configured (step 5 inside it:
no CA means no DC certificate and no LDAPS), and it fails loudly if the
`svc-vault-rotator` Reset Password ACE is missing on the ServiceAccounts OU or
on AdminSDHolder after `dsacls`. verify: Enterprise CA setup as SYSTEM via
run-command (it writes to the Configuration partition) may need `-Credential`
for an Enterprise Admin.

4. **By hand**, off camera: RDP to the DC's public IP
   (`terraform -chdir=lab/terraform/envs/dev output -raw dc_public_ip`; the NSG
   only admits `operator_ip_ranges`). Copy the admin password straight to the
   clipboard so it is never printed:
   `terraform -chdir=lab/terraform/envs/dev output -raw dc_admin_password | pbcopy`
   (macOS; `clip.exe` on Windows, `xclip -selection clipboard` on Linux).
   **Change it immediately** and store the new one in Key Vault as
   `dc01-admin-password`. Then, in the Entra admin center: *Entra Connect →
   Cloud sync → Agents → Download on-premises agent*. Install it and sign in
   with your admin account. The same agent serves Cloud Sync **and**
   API-driven provisioning to AD. It creates its gMSA, which the KDS root key
   from step 3 makes possible.
5. Paste the printed `parentDistinguishedName` expression into the
   provisioning app's attribute mapping (*Apply this mapping: Always*). That's
   what places each worker in their department OU and moves leavers to
   `OU=Disabled`. **Verify** the source-attribute name shown in your mapping
   UI matches `urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department`.
6. **Cloud Sync configuration**, by hand, after the agent from step 4 shows
   *Healthy*: Entra admin center → *Entra Connect → Cloud sync → + New
   configuration → AD to Microsoft Entra ID sync* → select `corp.<DOMAIN>` →
   *Scoping filters → Selected organizational units*: `OU=Workforce` (its
   department OUs come with it) **and** `OU=Disabled`. Do **not** add
   `OU=ServiceAccounts` or `OU=PrivilegedAccounts`: Tier-0 and service
   accounts stay on-premises only. Then enable the configuration.
   Without `OU=Disabled` in scope, a leaver moved there by provisioning falls
   out of sync scope and is **soft-deleted** in Entra instead of showing as
   disabled.

## Verify

```bash
az vm run-command invoke -g $RG -n $VM --command-id RunPowerShellScript --scripts \
  "Get-ADDomain | Select DNSRoot,NetBIOSName; Get-ADOrganizationalUnit -Filter * | Select -Expand DistinguishedName; \
   (Get-ADForest).UPNSuffixes; Get-ADUser -Filter 'SamAccountName -like \"tier0-*\" -or SamAccountName -like \"svc-*\"' | Select -Expand SamAccountName; \
   Test-NetConnection localhost -Port 636 | Select TcpTestSucceeded"
```

- [ ] Domain, OUs, UPN suffix and the five accounts (`svc-vault-rotator`, `svc-pam-discovery`, `svc-backup`, `tier0-admin-01`/`02`) are listed
- [ ] `TcpTestSucceeded : True` on 636 (LDAPS needs the DC certificate; re-run `certutil -pulse` if not)
- [ ] Key Vault holds `dc01-dsrm-password`, `svc-vault-rotator` and `svc-pam-discovery` (names only: `az keyvault secret list --vault-name $KV -o table`)

## Why it's built this way

- **No secret ever crosses a human or the pipeline.** DSRM and the Vault
  reconcile-account passwords are generated on the DC and written to Key Vault
  by the VM's managed identity over the private endpoint. The run-command
  parameters carry names only.
- **AD database on a no-cache data disk.** That's Microsoft's guidance for DCs
  on Azure, because write-back caching can corrupt NTDS.
- **The reconcile-account trade-off is explicit.** Vault must rotate Domain
  Admin passwords, and AdminSDHolder overwrites OU delegation on protected
  accounts, so `svc-vault-rotator` is granted on AdminSDHolder. That makes it
  Tier 0, the same position as a CyberArk CPM reconcile account. Its password
  lives only in Key Vault and should be rotated by Vault (`ldap/rotate-root`).
- **The DC's identity can write only its three build secrets.** An ABAC
  condition on its Key Vault Secrets Officer grant
  (`lab/terraform/modules/dc-vm/main.tf`) limits it to `dc01-dsrm-password`,
  `svc-vault-rotator` and `svc-pam-discovery` (the read-only discovery bind for
  `lab/pam/discover.sh`); it cannot read or change any other secret's value
  in the vault (secret names stay visible through ARM).
- **Single-DC lab shortcut.** The DC points DNS at itself and forwards to
  168.63.129.16. Add the DC IP to the VNet's DNS servers once member servers
  join.
