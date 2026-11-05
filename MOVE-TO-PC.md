# Moving the lab to another machine (Windows PC)

What lives where, what to copy, what to re-create. Nothing secret is in this repo; every secret is in the Mac's Keychain and has to be re-entered on the PC, never copied through chat or a file.

## 1. Clone and tools

```powershell
git clone https://github.com/ChromeData/contoso-health-identity-lab
winget install Git.Git Microsoft.PowerShell HashiCorp.Terraform OpenJS.NodeJS.LTS Microsoft.AzureCLI Amazon.AWSCLI GitHub.cli Python.Python.3.12 Docker.DockerDesktop jqlang.jq
```

- Terraform **1.16.5** (the lock files were made with it).
- PowerShell 7 with the Microsoft.Graph modules: `Install-Module Microsoft.Graph -Scope CurrentUser`.
- Node 20 or later. The video and map tooling runs `npm install` inside `lab/setup/signup-assist` (Playwright) and `lab/scripts/demo/video`.
- Docker Desktop with WSL 2. The Splunk and Kusto emulator images are amd64, which is native on a PC, so no Rosetta step.
- Pester 5: `Install-Module Pester -Scope CurrentUser -Force`.

## 2. Secrets: re-enter, do not copy

On the Mac they are Keychain items. On Windows use Credential Manager (`cmdkey`) or the SecretManagement module with the Windows vault. Same names, so the scripts' lookups keep working:

| Name | What it is |
|---|---|
| `contoso-lab-admin` | Tenant admin password (<your-admin-upn>) |
| `contoso-lab-aws-root`, `contoso-lab-aws-idlab-admin` | AWS root and the SSO admin profile |
| `contoso-lab-servicenow-admin`, `contoso-lab-servicenow` | ServiceNow developer instance |
| `contoso-lab-okta-token` | Okta API token |
| `contoso-lab-dc01-admin`, `contoso-lab-cloudsync` | DC01 local admin, Cloud Sync agent account |
| `contoso-lab-porkbun`, `contoso-lab-porkbun-api` | Registrar login and API |
| `contoso-lab-test-user-a/b/c`, `contoso-lab-tap-adm-raj`, `contoso-lab-totp-adm-raj` | Test users and the adm-raj MFA seed |
| `contoso-lab-totp-<user>`, `contoso-lab-pw-<user>` | Authenticator seeds and passwords written by `lab/scripts/demo/signin/enroll.mjs` (account = UPN); re-run `enroll.mjs --force` on a new machine instead of copying |
| `greptile-api` | Greptile API key (MCP server in `.mcp.json`) |

Not every helper reads a vault, though: `lab/scripts/dc/run-on-dc.py` and a few others call the macOS `security` command directly (`keychain:<service>`), so on Windows they need a `security`-shim or a rewrite to read the Windows vault. Creating the Credential Manager entries is necessary but not sufficient; treat those scripts as Mac-only until ported.

PowerShell equivalent of the Mac lookups: `Get-Secret -Name contoso-lab-admin -AsPlainText` with the SecretManagement module. Set `GREPTILE_API_KEY` from the vault in your PowerShell profile the same way `~/.zshrc` does on the Mac.

## 3. Files that are not in git and must be carried by hand

- `lab/setup/handback.env` (tenant ids, app ids, domain). Not secret, but gitignored because it is tenant-specific. Copy it over a secure channel, or regenerate from the portal values.
- `lab/setup/signup-assist/profile.json` (the browser profile used for sign-ups). Optional; a fresh profile works.
- `lab/terraform/**/terraform.tfvars` where present (the AWS and Okta roots). Gitignored; copy or recreate from `terraform.tfvars.example`.
- `lab/splunk/.env` is generated per machine by `splunk-up.sh`; do not copy it.
- `lab/evidence/out/` (video renders, raw captures). Large and regenerable; copy only `out/video/clips/*.mp3` and `out/video/clips/face.mp4` (the presenter voice lines and the intro clip the 00-face scene uses) and `out/video/build/*.png` (the sign-up screenshots the maps embed).

## 4. Machine-specific pieces in the Mac scratchpad, now in the repo

`lab/scripts/demo/video/tools/combine-map.py` (the interactive map), `tools/dump-lines.mjs` (script page lines), `lab/splunk/replay-synthetic.py`. The Graph sign-in helper that bounced through Brave is Mac-only and not needed on a PC: `Connect-MgGraph` opens the default browser normally there.

## 5. Terraform state

Mixed, so read this carefully:
- `lab/terraform/envs/dev` uses a **remote** Azure storage backend (`backend.tf`). Nothing to copy; `terraform init` reconnects to it, and the CI pipeline keeps applying from GitHub regardless of which laptop you use.
- `lab/terraform/aws` and `lab/terraform/okta` use **local** state (no backend block), so their `terraform.tfstate` lives only on this Mac. If you move machines, either copy `lab/terraform/{aws,okta}/terraform.tfstate*` over a secure channel, or migrate each to a remote backend first. The Okta root's state holds the API token value; treat the file as a secret. Skipping this leaves the new machine blind to those resources, so the next apply tries to recreate what already exists.

## 6. First run on the PC, in order

1. `pwsh lab/scripts/powershell/00-Preflight.ps1` (checks tools, modules and the handback file).
2. `Invoke-Pester lab/scripts/powershell/tests` (offline, about a thousand checks).
3. `terraform -chdir=lab/terraform/envs/dev init && terraform -chdir=lab/terraform/envs/dev test -var-file=lab.tfvars` (mocked plan, no tenant).
4. `lab/monitoring/kusto-harness/run.sh --accept-eula` under WSL, or the Splunk path: `lab/splunk/splunk-up.sh` then `python lab/splunk/replay-synthetic.py`.
5. Only then anything against the tenant.
