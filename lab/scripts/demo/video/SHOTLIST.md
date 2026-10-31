# Walkthrough shot list (stations 7 to 16)

Rule for every station: **code first, result second.** Open the Terraform or script in VS Code, then show the platform it changed. Every platform the lab uses appears at least once. Narration is in your voice (pending Higgsfield credits), matched to the tone of the lab-map lines.

Screens are recorded with the Playwright recorder (`rec.mjs`) where a browser page exists, and with a VS Code window capture for code. The old fake terminal page (`pages/term.html`) is retired.

| # | Station | VS Code (what to open) | Platform result (what the viewer sees) | Capture |
|---|---------|------------------------|-----------------------------------------|---------|
| 7 | Source of truth | `lab/hr/hr_feed.csv` with Dana's row, then `lab/scripts/powershell/02-Joiner.ps1` | Entra: HR front-door provisioning app, provisioning log showing Dana's row arriving | VS Code window; Entra blade (already in `scenes.mjs` 05-hr-app) |
| 8 | Directory | `lab/terraform/modules/dc-vm/main.tf` (the VM) and the promote script under `lab/scripts/dc/` | Azure portal: DC01 VM overview. Entra: Cloud Sync job healthy. AD Users and Computers via `run-on-dc.py` screenshot of the Workforce OU | Azure + Entra blades; DC screenshot via run-on-dc |
| 9 | Joiner and mover | `lab/terraform/modules/entitlement/` (access packages) and `modules/groups/` (dynamic groups) | Entra: Dana's profile, groups, the four access packages, SoD incompatible pair | Entra blades (08-joiner) |
| 10 | Apps | `lab/terraform/modules/apps/` (AWS gallery app, ServiceNow SAML app, Okta IdP) and `lab/terraform/aws/main.tf` | **AWS** IAM Identity Center: identity source = external, Users list with Dana (SCIM). **ServiceNow**: login page redirecting to Microsoft, then landing in the instance. **Okta**: Identity Providers page with Entra as IdP and the routing rule. **GitHub**: the apps-stage PR and its Actions run | AWS console (root-login.mjs), ServiceNow (sn/login.mjs), Okta admin, GitHub PR page |
| 11 | Sign-in rules | `lab/terraform/modules/conditional-access/` and `lab/terraform/envs/dev/lab.tfvars` (the nine `enabled` flags) | Entra: Conditional Access policies list showing 9 On, 2 Report-only. Sign-in log entry showing a policy applied | Entra blades (09-signin, update narration: no longer "all report-only") |
| 12 | Privileged access | `lab/terraform/modules/pim/` | Entra PIM: eligible group, an activation with reason and 4-hour expiry. Azure Key Vault secrets list (names only) | Entra PIM blades (10-pim, 11-pim-live); Key Vault blade |
| 13 | Detect and respond | `lab/sentinel/` rules as YAML or Terraform (`modules/monitoring/`) | Sentinel: analytics rules list, one incident open, the Teams approval card if the team exists | security.microsoft.com (12-detect) |
| 14 | Leaver and robot accounts | `lab/scripts/powershell/04-Leaver.ps1` and `06-NHI-Inventory.ps1` | Entra: Priya disabled, no groups. **AWS**: Users list with Priya gone, timestamp. NHI inventory table | Entra blade (13-leaver) + AWS console users page |
| 15 | Proof | `lab/scripts/powershell/Export-EvidencePack.ps1`, `Compare-IdentityConfig.ps1` | Azure: WORM storage container with the pack and immutability policy. Entra: access review. GitHub: the nightly drift workflow run, green | Azure blades (14-worm, 15-evidence); GitHub Actions run |
| 16 | Delivery | `lab/terraform/modules/pipeline-identity/main.tf` (PLAN and APPLY, federated credentials) and `.github/workflows/` | **GitHub**: PR list, one PR with the plan comment, the approve comment, the Actions run. Entra: the two app registrations with federated credentials, no secrets | GitHub pages (03-delivery) + Entra app registration blade |

## Platforms covered
- Microsoft Entra: 7, 9, 10, 11, 12, 14, 15, 16
- Azure: 8, 12, 15
- AWS: 10, 14
- ServiceNow: 10
- Okta: 10
- GitHub: 10, 15, 16
- Sentinel / Defender portal: 13

## Narration fixes needed in the existing walkthrough
- `09-signin` beat 1 says every policy is report-only "for now". Nine are enforced. Rewrite.
- `03-delivery` beat 0 lists day one to three then "then the scripts". Add the apps, SCIM, Okta and ServiceNow stages that followed.
- `16-next` was removed (stale). Replace with a short "what's left" in your voice: passkeys for the last two rules, the containment playbook in Teams, a break-glass drill.
- `17-close` in your voice with results: 25 changes, 9 enforced sign-in rules, a leaver gone from AWS in 9 minutes, repo link in the description.

## Access needed to capture the platform screens
- AWS console: root session via `aws/root-login.mjs` (Keychain `contoso-lab-aws-root`), or an IdC user once SSO works.
- ServiceNow: `sn/login.mjs` (Keychain `contoso-lab-servicenow-admin`).
- Okta admin: Keychain `contoso-lab-okta-admin` (confirm name in handback.env).
- GitHub: `gh` CLI session, repo is private.
- Entra / Azure / Sentinel: the admin session, which needs the current admin password (Keychain `contoso-lab-admin` is wrong; CA020 forces re-auth every 4 hours).
