# CI/CD pipeline — Contoso Health Identity Platform

Identity-as-code for Entra ID, delivered through GitHub Actions with **no stored
credentials**. Every change to the tenant is planned, scanned, AI-reviewed, and
human-approved before it applies. This folder documents how the pipeline is
wired and exactly what a human must configure for it to run.

> Terraform lives in [`../terraform/envs/dev`](../terraform/envs/dev)
> (`azuread ~> 3.10`, `azurerm ~> 4.0`). Detections live in
> [`../kql`](../kql). The workflows live in
> [`../../.github/workflows`](../../.github/workflows).

Protagonist of the walkthrough: **Dana Okafor** (joiner → mover → leaver). This
pipeline is the "change control" layer behind everything Dana's story touches —
Conditional Access, access packages, PIM, the lot.

---

## 1. Architecture

```
          Pull request  (feature branch -> main)
          ───────────────────────────────────────────────────────────
          every PR (plan, Checkov + AI review only if lab/terraform/** changed)
                │
    ┌───────────┼───────────────────────────────┬──────────────────────┐
    ▼           ▼                                 ▼                      ▼
 terraform-plan.yml                          ai-review.yml         (branch
   • fmt -check                                • OIDC login          protection
   • init / validate                             (PLAN app)          requires
   • plan  ──► PR comment                       • az get-access-      the 5 checks
   • Checkov  ──► code scanning (SARIF)           token (Entra)       green; 0
   • TruffleHog ──► fail on verified secret      • diff -> Azure       approvals on
        (PLAN app, READ-ONLY, OIDC)               OpenAI -> PR        a solo repo,
                                                  comment (advisory)  see §5 F)
                │
                ▼
          Review + approve, merge to main
                │
                ▼
          Push to main
          ───────────────────────────────────────────────────────────
 terraform-apply.yml
   • environment: prod   ⟵ REQUIRED REVIEWER GATE (run pauses here)
   • OIDC login (APPLY app, WRITE)
   • init / plan -out / apply
   • step summary
                │
                ▼
          Entra ID + Azure tenant changed
                │
                ▼
          Detections (lab/kql) fire in Log Analytics / Sentinel
          ──► notify Logic App ──► Teams card + ServiceNow ticket
          ──► (High ITDR incident, enable_itdr_containment) containment
              Logic App ──► Teams approval ──► revoke / confirm compromised / disable
```

Not drawn: `lab-tests.yml` runs on every PR and push to `main` with **no
credentials** (fmt, validate and every mocked `terraform test`, the Pester
suites, the shell tests and the Splunk drift check). Its two checks are the
4th and 5th required checks (§5 F).

Also not drawn: `config-drift.yml`, the **nightly reconcile**. The
detections at the bottom of the diagram fire when a change is made; the
reconcile catches what they missed. Every night (and on demand) it signs in
as the read-only PLAN app over OIDC, exports the tenant's Conditional
Access, named locations, authentication strengths and methods, PIM policies,
consent / app-management / cross-tenant policies and break-glass exclusion
facts as one normalised snapshot with every id hashed
(`Export-IdentityConfig.ps1 -Public`), compares it with the committed
baseline (`lab/config-baseline/identity-config.json`) and with the states
declared in `lab.tfvars` (`Compare-IdentityConfig.ps1`), uploads the
snapshot as a run artifact (never commits it), and on High or Medium drift
opens or updates one issue labelled `identity-drift`. Accepted differences
live in `lab/config-baseline/drift-exceptions.json` with an owner and an
expiry (90 days High, 180 Medium / Low): when the exception expires, the
finding comes back by itself. Until the first tenant export is committed the
baseline is a placeholder and the job succeeds with "no baseline yet". The
loop is described in
[`../scripts/powershell/README.md`](../scripts/powershell/README.md#configuration-drift-export-compare-nightly-reconcile).
BUILT; no workflow has run yet.

The reviewer approves the run before it re-plans. The applied plan is the fresh
one on `main`, not the PR comment's; drift since the PR (portal edits, other
merges) is applied without a second look and is visible in the plan step's log.

**Two identities, two triggers, least privilege:**

| App registration | Permissions | Runs on | Workflow |
|---|---|---|---|
| **PLAN app** | read-only (Graph read, Reader, Storage Blob Data Reader on state: it can read state, which holds the generated passwords) | `pull_request` | `terraform-plan.yml`, `ai-review.yml` |
| **APPLY app** | write (Graph write, Contributor/role mgmt) | `push` to `main` (or manual dispatch of `main`), via `prod` env, which only `main` may deploy to | `terraform-apply.yml` |

Only a same-repo PR can assume the **read-only** PLAN identity. A fork PR gets
a read-only `GITHUB_TOKEN` and no OIDC token at all (GitHub downgrades write
permissions, `id-token: write` included, on fork `pull_request` runs), so it
reaches neither identity: if it touches `lab/terraform/**`, its `terraform
plan` check fails by design until a maintainer pushes the branch to this repo
(verify: on the first fork PR). The APPLY app's federated credential is scoped
to the `prod` environment, which only the `push`/apply job references.

---

## 2. OIDC trust (workload identity federation)

No client secret, no certificate, no PAT. GitHub mints a short-lived OIDC token
per job (`permissions: id-token: write`); Entra trusts it because a **federated
credential** on the app registration matches the token's `sub` (subject) and
`iss` (`https://token.actions.githubusercontent.com`), `aud`
(`api://AzureADTokenExchange`).

These **federated credentials** are created by Terraform in
[`../terraform/envs/bootstrap`](../terraform/envs/bootstrap) from
`github_owner` / `github_repo` (the public lab repo, default name
`contoso-health-identity-lab`). The subjects must match the repo exactly:

| App | Credential subject (`sub`) | Why |
|---|---|---|
| PLAN app | `repo:OWNER@OWNER_ID/REPO@REPO_ID:pull_request` | same-repo PRs can plan (read-only); fork PRs get no OIDC token |
| APPLY app | `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:prod` | only the `prod` deploy can apply |

Why the numeric ids: GitHub.com emits this immutable form by default for repos
created (or renamed / transferred) after 2026-07-15, and because the ids are
never reused it also blocks subject recycling (a deleted, re-registered owner
or repo name cannot mint a matching token). verify: confirm both subjects with
GitHub's OIDC subject preview before the first PR.

Optional extra PLAN subject if you also want plan on branch pushes:
`repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/heads/main`.

Issuer / audience for all of them:

```
Issuer:   https://token.actions.githubusercontent.com
Audience: api://AzureADTokenExchange
```

The `environment:prod` subject is the keystone: GitHub only puts
`environment:prod` in the token's `sub` when a job declares
`environment: prod`, and that job is the one gated by a required reviewer. So
the write identity is unreachable without passing the human gate, and `prod`
accepts deployments from `main` only (§5E).

---

## 3. Why a public repo

The repo is **public on purpose**, and the pipeline depends on it:

- **Environments + required reviewers are free on public repos.** On private
  repos, protected Environments (the `prod` reviewer gate) need GitHub
  Team/Enterprise. Public = the reviewer gate costs nothing. **While the repo
  is private** the gate is the `approval` job in `terraform-apply.yml`
  (`.github/scripts/apply-approval-gate.sh`): it opens an "Approve: apply
  <sha> to prod" issue and the apply waits for an approver's `approve` or
  `deny` comment (repo Variable `APPLY_APPROVERS`, default the owner; 30
  minutes, then cancel). Difference: removing that job takes a merged PR,
  while an Environment reviewer cannot be removed by code. Restore required
  reviewers (5E) and delete the job when the repo goes public.
- **Branch protection / rulesets** (require PR, require status checks, require
  review) are free on public repos.
- **Code scanning (SARIF upload)** — the Checkov results under the *Security &
  quality* tab (labelled *Security* before 2026-04-02) —
  is free for public repos; on private repos it needs GitHub Advanced Security.
- It doubles as a **portfolio artifact**: hiring managers can read the actual
  OIDC wiring. Because there are no secrets in the repo, public is safe — the
  worst an attacker can do with the config is read how good it is.

---

## 4. SHA-pinning rationale (supply chain)

Every third-party action is pinned to a **full 40-char commit SHA**, with the
human-readable version in a trailing comment:

```yaml
uses: azure/login@7ddb5af1ef8758cf1353cf3b42f940aee27ba21c # v3.0.2
```

A tag like `@v2` or `@v2.3.0` is a *mutable pointer* the action's owner (or
anyone who compromises them) can re-point at new code. In **2026 the Trivy /
aquasecurity GitHub Actions were compromised** by exactly this — a tag
re-pointed to malicious code that exfiltrated CI secrets: **CVE-2026-33634**
(2026-03-19, 76 of 77 `aquasecurity/trivy-action` tags and all
`aquasecurity/setup-trivy` tags force-pushed to an infostealer; NVD /
GitHub advisory, CVSS-B 9.4, checked 2026-10-20). A commit SHA is
immutable, so a pinned SHA cannot be swapped under you. We pin **everything**,
including GitHub's own `actions/*`, not just vendor actions.

One caveat: a SHA pins the action's own code, not a container image it pulls.
TruffleHog's action runs `ghcr.io/trufflesecurity/trufflehog:<version>`
(default `latest`), so `terraform-plan.yml` pins `version:
"3.97.9@sha256:52e67fef4d054ecff5c2ce4b4ae376626d1ef54aa0898b53cac19c25e92e14db"`
and bumps it by hand with the SHA, because Dependabot does not touch that
input. `checkov-action`'s pinned `action.yml` hard-codes
`ghcr.io/bridgecrewio/checkov:3.3.3`, a tag the workflow cannot override
(verify: accepted residual risk, re-check on each bump).

Pinned set in this pipeline, exactly as in the workflow files (bump
deliberately via Dependabot, never blind-retag):

| Action | Version | Commit SHA |
|---|---|---|
| `actions/checkout` | v5.0.0 | `08c6903cd8c0fde910a37f88322edcfb5dd907a8` |
| `azure/login` | v3.0.2 | `7ddb5af1ef8758cf1353cf3b42f940aee27ba21c` |
| `hashicorp/setup-terraform` | v4.0.1 | `dfe3c3f87815947d99a8997f908cb6525fc44e9e` |
| `actions/setup-python` | v7.0.0 | `5fda3b95a4ea91299a34e894583c3862153e4b97` (`k8s-identity.yml` only: Python 3.12 for Checkov) |
| `actions/github-script` | v8.0.0 | `ed597411d8f924073f98dfc5c65a23a2325f34cd` |
| `bridgecrewio/checkov-action` | v12.3109.0 | `a59d390da81ed70dbf0bced4d76d0c2b3a5dbf6e` |
| `trufflesecurity/trufflehog` | v3.97.9 | `4dd8831c5f12599465d4d45c3c447b4018a34c85` (scanner image pinned by digest: `version:` input, bumped by hand) |
| `github/codeql-action/upload-sarif` | v4.38.2 | `2892aa5e19bbd11bc0cff5427e3b750a04d9e3c2` |

`setup-terraform` installs **Terraform 1.16.5** in all four Terraform
workflows (`terraform-plan.yml`, `terraform-apply.yml`, `k8s-identity.yml`,
`lab-tests.yml`),
the same CLI that generated the committed `.terraform.lock.hcl` files.
`k8s-identity.yml` installs Checkov from PyPI as `checkov==3.3.20`, on a
`setup-python`-pinned Python 3.12, instead of using the action (§7);
Dependabot has no pip entry, so bump that pin by hand.

> To re-verify a SHA for a tag:
> `curl -s https://api.github.com/repos/<owner>/<repo>/git/refs/tags/<tag>`
> (dereference annotated tags via `.../git/tags/<sha>` → `.object.sha`).

**Dependabot** is configured in [`../../.github/dependabot.yml`](../../.github/dependabot.yml):
weekly, grouped `github-actions` bumps (SHA and the `# vX.Y.Z` comment
together) plus Terraform provider bumps for `envs/dev`, `envs/bootstrap`,
`aws` and the three `k8s` roots (`platform`, `identity`, `aks-mapping`). Pin
bumps arrive as reviewable PRs, without reintroducing floating tags. The image
digests in the Kubernetes segment (kind node, busybox, Vault Agent) are bumped
by hand.
Dependabot's own PR runs see only Dependabot secrets, so mirror the two
repository secrets there too (§5 D).

---

## 5. Setup checklist (what a human must configure)

Do these once. Nothing in the repo contains a secret; all of this is config on
the GitHub and Entra sides.

### A–C. Entra apps, Graph roles, Azure RBAC — one local bootstrap apply
The pipeline cannot create its own identities (chicken-and-egg), and no PR may
be able to widen its own permissions. So all of A–C lives in
[`../terraform/envs/bootstrap`](../terraform/envs/bootstrap), applied **locally
by a human admin**, in a separate state container CI cannot reach:

- [ ] `cd lab/terraform/envs/bootstrap && cp terraform.tfvars.example terraform.tfvars`
      → set `github_owner`, `github_repo`, `github_owner_id`, `github_repo_id`
      (after the public repo exists: `gh api repos/OWNER/REPO --jq '.owner.id, .id'`),
      `tfstate_storage_account_name`.
- [ ] `terraform init -backend-config="storage_account_name=<sa>" && terraform apply`.
      This creates:
  - **PLAN** app + federated credential `repo:OWNER@OWNER_ID/REPO@REPO_ID:pull_request`, Graph
    roles `User.Read.All`, `Group.Read.All`, `Policy.Read.All`,
    `EntitlementManagement.Read.All`, `RoleManagement.Read.Directory`,
    `RoleManagementPolicy.Read.AzureADGroup`; Azure **Reader** (subscription).
  - **APPLY** app + federated credential `repo:OWNER@OWNER_ID/REPO@REPO_ID:environment:prod`,
    Graph roles `User.ReadWrite.All`, `Group.ReadWrite.All`, `Policy.Read.All`,
    `Policy.ReadWrite.ConditionalAccess`, `EntitlementManagement.ReadWrite.All`,
    `RoleManagement.ReadWrite.Directory`,
    `RoleManagementPolicy.ReadWrite.AzureADGroup`; Azure **Contributor** +
    **Role Based Access Control Administrator constrained by an ABAC condition**
    to the Key Vault Secrets User/Officer roles and *Virtual Machine
    Administrator Login* for the Intune VM (Contributor alone cannot create
    role assignments; the condition stops CI granting Owner to anything). The VM
    login role was added later: **re-apply bootstrap** before the pipeline
    applies `enable_intune_vm = true`, or the condition refuses the grant.
  - APPLY: **Storage Blob Data Contributor** on the `tfstate` container only
    (apply takes the blob lease). PLAN: **Storage Blob Data Reader** on the
    same container (PR plans run with `-lock=false`). State holds the
    generated break-glass, DC and Intune VM local-admin passwords, so any
    same-repo PR run can read them.
  - PLAN: **Cognitive Services OpenAI User** on the Azure OpenAI account once
    `azure_openai_resource_id` is set.
- [ ] Click **Grant admin consent** for the tenant on BOTH apps (Entra → App
      registrations → API permissions) and confirm every row says *Granted*.
- [ ] Seed the envs/dev state blob once, as yourself:
      `terraform -chdir=lab/terraform/envs/dev init -input=false -backend-config=resource_group_name=<rg> -backend-config=storage_account_name=<sa>`.
      When the key is missing, the azurerm backend writes an empty state
      (under a lease) during init. The Reader-only PLAN identity cannot do
      that, so without this the first PR plan fails.
- [ ] Register resource providers once, as yourself — `envs/dev` sets
      `resource_provider_registrations = "none"` because the Reader-only PLAN
      identity cannot register them:
      ```bash
      for rp in Microsoft.KeyVault Microsoft.Network Microsoft.Compute Microsoft.ManagedIdentity \
                Microsoft.OperationalInsights Microsoft.OperationsManagement Microsoft.SecurityInsights \
                Microsoft.Insights Microsoft.DevTestLab Microsoft.Logic Microsoft.Web \
                Microsoft.CognitiveServices Microsoft.Storage; do az provider register -n $rp; done
      ```
- [ ] **Second bootstrap apply** once `envs/dev` has created Log Analytics (and
      the E5 trial is on): set `log_analytics_workspace_id` → the tenant's
      Entra diagnostic setting streams sign-in/audit/provisioning logs. It is
      human-owned on purpose: a pipeline PR can't remove it.

> `RoleManagement.ReadWrite.Directory` on APPLY is effectively Tier 0. The
> mitigations are the `prod` reviewer gate, the environment-scoped subject,
> and that its own identity, federation and grants are not in the root it
> applies (bootstrap is human-only); it could still escalate out of band, so
> this is change control, not a privilege boundary.

### D. GitHub — repo variables (Settings → Secrets and variables → Actions → Variables)
These are **identifiers, not secrets** — use *Variables*, not Secrets (the two
privacy-only exceptions follow the list):
- [ ] `AZURE_TENANT_ID`
- [ ] `AZURE_SUBSCRIPTION_ID`
- [ ] `AZURE_PLAN_CLIENT_ID`  (PLAN app client ID)
- [ ] `AZURE_APPLY_CLIENT_ID` (APPLY app client ID)
- [ ] `AZURE_OPENAI_ENDPOINT`    e.g. `https://contoso-health-aoai.openai.azure.com`
- [ ] `AZURE_OPENAI_DEPLOYMENT`  e.g. `gpt-5.4-mini` (**verify:** a current GA
      chat model in your region at deploy time; gpt-4o is Deprecated/Legacy per
      the Foundry retirement schedule). `review.py` calls the v1 endpoint, so
      there is no `AZURE_OPENAI_API_VERSION` to set. It sends
      `max_completion_tokens` and no temperature, so it works with both GPT-5.x
      reasoning models and gpt-4o (verify: on the first real PR run).
- [ ] (optional) `AZURE_OPENAI_MAX_COMPLETION_TOKENS` (default 4000) and
      `AZURE_OPENAI_REASONING_EFFORT` (unset = model default; values are
      model-dependent)
- [ ] `TFSTATE_RG`, `TFSTATE_STORAGE_ACCOUNT`  (backend `-backend-config` values)
- [ ] `TF_ONMICROSOFT_DOMAIN`      e.g. `contosohealthlab.onmicrosoft.com`
- [ ] `TF_KEY_VAULT_NAME`          e.g. `kv-idlab-7f3a`
- [ ] `TF_PIM_APPROVER_OBJECT_IDS` JSON list, e.g. `["<admin object id>"]`
- [ ] `TF_SENTINEL_PLAYBOOK_ID`    printed by `lab/scripts/monitoring/Deploy-Playbook.ps1`
- [ ] `TF_KV_SECRETS_OFFICER_IDS`  JSON list of custodian object ids
- [ ] `TF_ENTITLEMENT_APPROVER_GROUP_OBJECT_ID` (optional) group object id
      whose members approve access-package requests. Unset = approval goes
      to the requestor's manager. Set it here, not only in a local
      `terraform.tfvars`, or the next CI apply moves approval back to the
      manager. It is also the review fallback below when that one is unset.
- [ ] `TF_ACCESS_REVIEW_FALLBACK_GROUP_OBJECT_ID` (optional) group object id
      whose members review users with no manager. Once access reviews are
      on, the plan fails if neither this nor
      `TF_ENTITLEMENT_APPROVER_GROUP_OBJECT_ID` is set.
- [ ] `TF_CA010_EXCEPTION_GROUP_OBJECT_IDS` (optional) JSON list of
      `CA010-Exclusion-<reason>` group ids, excluded from the device-code
      block next to break-glass. Unset = `[]`. Set here, or the next CI apply
      removes the exception.
- [ ] `TF_SERVICENOW_INSTANCE_URL`, `TF_SERVICENOW_SSO_SYS_ID` (optional) for
      the ServiceNow SAML app (`enable_servicenow_sso` in `lab.tfvars`): the
      instance URL and, once the identity provider record exists in
      ServiceNow, its sys_id (a second apply). Unset = `''`; the plan
      refuses the flag without the URL.
- [ ] `TF_INTUNE_VM_ADMIN_LOGIN_OBJECT_IDS` (optional) JSON list of user object
      ids that get *Virtual Machine Administrator Login* on the Intune VM (the
      CA005 pilot group gets it anyway). Unset = `[]`.
- [ ] Senior-scope identifiers (all optional until their staging flag is on;
      unset = empty / `[]`):
      `TF_PIM_TIER0_APPROVER_OBJECT_IDS` (JSON list; empty = the PIM approvers),
      `TF_PRIVILEGED_REVIEW_REVIEWER_GROUP_OBJECT_ID` (governance group that
      reviews PIM-eligible access), `TF_B2B_CONNECTED_ORGANIZATION_ID`
      (printed by `New-B2BConnectedOrganization.ps1`),
      `TF_CA008_PILOT_GROUP_OBJECT_ID` (only to reuse an existing pilot group),
      `TF_AWS_SAML_ENTITY_ID`, `TF_AWS_SAML_ACS_URLS` (JSON list),
      `TF_AWS_ACCESS_PORTAL_URL`, `TF_AWS_SCIM_TEMPLATE_ID` (from the AWS
      Identity Center console / `aws_scim_template_lookup_command`),
      `TF_CONTAINMENT_PLAYBOOK_ID` (printed by
      `Deploy-ContainmentPlaybook.ps1`), `TF_EVIDENCE_STORAGE_ACCOUNT_NAME`
      (globally unique), and for the ITDR rules `TF_IAC_PRINCIPAL_IDS` (JSON
      list of the APPLY identity's immutable ids: the `envs/bootstrap` output
      `iac_principal_ids`; empty = nothing counts as IaC, so every pipeline
      change alerts, which fails closed) and `TF_PRIVILEGED_USER_OBJECT_IDS`
      (JSON list of extra privileged user object ids, e.g. from
      `Find-ShadowAdmins.ps1 -PrivilegedIdsPath`). Set both in the
      `enable_itdr_detections` PR. The AWS SCIM token is **never** a CI value: one local
      seeding apply writes it from Key Vault, and `terraform-apply.yml` sets
      `TF_VAR_require_scim_credentials=true` so a CI apply that would create
      it empty fails instead.

**Repository *secrets* (Settings → Secrets and variables → Actions →
Secrets).** Not credentials: both workflows read them as `secrets.*` only
because GitHub masks secrets in run logs but prints variables in every step's
env header, and the repo is public.
- [ ] `TF_OPERATOR_IP_RANGES`  JSON list, e.g. `["203.0.113.7/32"]` — Key Vault
      firewall, the DC and Intune VM NSGs, the evidence store firewall and,
      with `enable_dc`, the Sentinel `operator_ips` watchlist. Each entry a
      single IPv4 host as /32: required when `enable_dc = true` (DC01 NSG and
      the `operator_ips` watchlist), and never wider than /24 otherwise;
      `0.0.0.0/0` fails validation. Unset = `[]` (no public vault access, no
      inbound to the VMs). The Terraform variable is also `sensitive`, so the
      plan comment hides it.
- [ ] `TF_ALERT_EMAIL`         post-trial alert address (also `sensitive` in
      Terraform). Unset = no notifications.
- [ ] `TF_PIM_ALERT_MAILBOX`   one security mailbox for PIM notifications
      (`pim_alert_mailbox`, `sensitive`). Both workflows map it to
      `TF_VAR_pim_alert_mailbox`. Unset = no PIM mailbox (tenant default
      notifications only).
- [ ] `TF_APP_OWNER_OBJECT_IDS` (JSON list) and
      `TF_SAML_CERT_NOTIFICATION_EMAILS` (JSON list) for `modules/apps`:
      secrets only so the public logs mask a person's object id and mailbox.
- [ ] If you set any of these, also create it as a **Dependabot** secret
      (Settings → Secrets and variables → Dependabot) with the same name and
      value. Dependabot-triggered PR runs see only Dependabot secrets, so
      without them the weekly Dependabot plan falls back to `[]`/'' and shows
      false Key Vault firewall / NSG / action-group removals.
      `terraform-plan.yml` flags this with a warning banner in the plan
      comment. (verify: `id-token: write` and repo Variables are honoured in
      Dependabot-triggered `pull_request` runs; if not, azure/login fails and
      the plan check is red on Dependabot PRs.)

Policy knobs (staging flags, CA states, blocked countries) are **not**
variables: they live in the committed `lab/terraform/envs/dev/lab.tfvars`, so
every change is a reviewable diff — the CA flip PR in the demo edits that file.
That includes `itdr_exclude_rules` and the `evidence_immutability_*` trio:
they reach CI only through `-var-file=lab.tfvars`. `-var-file` outranks
`TF_VAR_`, so a `TF_VAR_itdr_exclude_rules` would be silently ignored, and a
repo Variable for the immutability settings would let a settings change,
with no PR and no review, lock the WORM store irreversibly.

> **Public-repo caution:** the plan comment is public. Anything not marked
> `sensitive` (object ids, UPNs, the onmicrosoft domain) is visible to anyone.
> None of it is a credential, but keep that in mind before adding variables.

### E. GitHub — the `prod` Environment with a required reviewer
- [ ] Settings → **Environments** → **New environment** → name it **`prod`**
      (the name MUST match `environment: prod` in `terraform-apply.yml`).
- [ ] Add **Required reviewers** (yourself / a second admin). This is the human
      gate; the apply run pauses until approved.
- [ ] **Deployment branches and tags → Selected branches and tags → add
      `main`.** Required. The APPLY subject `environment:prod` carries no
      branch ref, so this setting is the only thing that ties the write
      identity to merged code. Without it, any branch can reach the APPLY app
      after the reviewer approves, for example a `workflow_dispatch` of an
      unmerged branch or a workflow added on a branch. (The job's `if:
      github.ref == refs/heads/main` in `terraform-apply.yml` is defence in
      depth only.) Do not use "Protected branches only": per GitHub's docs,
      when no branch protection rule exists in the repository, that option
      lets every branch deploy, and `main` here is protected by a ruleset,
      not a classic rule (verify: whether rulesets count for this option; the
      docs do not say).

### F. GitHub — branch protection / ruleset on `main`
- [ ] Require a pull request before merging. **Solo repo: 0 required
      approvals** — GitHub never lets you approve your own PR, so ≥ 1 would
      deadlock. The real human gate is the `prod` environment reviewer (you
      *can* approve your own deployment unless "Prevent self-review" is on).
      With a second maintainer, raise this to 1.
- [ ] Require status checks to pass: `terraform plan`, `checkov (IaC scan)`,
      `trufflehog (secret scan)`, `terraform validate + test (mocked)` and
      `Pester + PSScriptAnalyzer + shell tests` (`lab-tests.yml`, no path
      filter for the same reason as below). (AI review is advisory — do **not** make it a
      required check.) `terraform-plan.yml` has no workflow-level `paths:`
      filter on purpose: GitHub leaves a path-skipped required check *Pending*
      and blocks the merge. It runs on every PR; TruffleHog always scans, and
      plan + Checkov skip at job level when nothing under `lab/terraform/**`
      changed (a job skipped by `if:` reports Success). If change detection
      itself fails, they run anyway (fail closed).
- [ ] Outside contributors: a fork PR cannot plan (no OIDC token, §2). Review
      the diff, push the branch into this repo, and merge from a same-repo PR.
- [ ] (Optional) require branches up to date; block force-push.
- [ ] Private vulnerability reporting enabled (`SECURITY.md` sends reporters
      to the *Report a vulnerability* button, which only appears once it is
      on). The publish script does it; verify in Settings.

### G. Smoke test
- [ ] Open a trivial PR under `lab/terraform/**` → confirm the plan comment, the
      Checkov/TruffleHog checks, and the AI-review comment appear.
- [ ] Open a docs-only PR (e.g. edit `lab/docs/*.md`) → confirm `terraform plan`
      and `checkov (IaC scan)` show *Skipped*, `trufflehog (secret scan)` runs,
      and the PR is mergeable (not stuck on *Pending*).
- [ ] Merge → confirm `terraform-apply` pauses on the `prod` reviewer gate →
      approve → confirm apply runs with no secret in the logs.

---

## 6. Files in / driving this pipeline

| Path | Purpose |
|---|---|
| `../../.github/workflows/terraform-plan.yml` | every PR: TruffleHog; if `lab/terraform/**` changed, also fmt/init/validate/plan + Checkov |
| `../../.github/workflows/terraform-apply.yml` | main: reviewer-gated OIDC apply (a push that touches only `lab/terraform/aws/**` or `lab/terraform/k8s/**` doesn't start it) |
| `../../.github/workflows/ai-review.yml` | same-repo PR touching `lab/terraform/**`: Azure OpenAI (Entra-auth) security review |
| `./ai-review/review.py` | stdlib script that calls Azure OpenAI with the Entra bearer token |
| `../../.github/workflows/k8s-identity.yml` | PR touching `lab/k8s/**` or `lab/terraform/k8s/**` (or manual): runs `../k8s/ci/pipeline.sh` on an ephemeral kind cluster, no cloud credentials (§7) |
| `../../.github/workflows/lab-tests.yml` | every PR and main, **no credentials**: `terraform fmt`, `init -backend=false` + `validate` in every root and module, every mocked `terraform test`; PSScriptAnalyzer + the Pester suites (`lab/scripts/powershell/tests`, ITDR, PAM dependency scan) with pinned modules; the vault-ingest shell test and the Splunk savedsearches drift check |
| `../../.github/workflows/pam-harness.yml` | manual and nightly, **no credentials**: `lab/pam/test/run-all.sh` (default suites) from a fresh clone on a fresh runner: no `.env`, no `.secrets/`, no Docker volumes. Its console output and per-suite job summary are the third-party-timestamped run of the PAM harness. BUILT, not run (no workflow has run yet) |
| `../../.github/workflows/config-drift.yml` | nightly and manual, **PLAN app (read-only, OIDC), no secrets**: `Export-IdentityConfig.ps1 -Public` then `Compare-IdentityConfig.ps1` against `lab/config-baseline/`; snapshot + findings as a run artifact, Markdown in the job summary, one `identity-drift` issue on drift (closed by the next clean run). Needs `issues: write` on the job. Succeeds with a notice while the baseline is the placeholder. BUILT, not run |

**Not planned or applied by CI: `lab/terraform/aws/`.** The AWS IAM Identity
Center root is applied by a human from a short-lived `aws sso login` session.
CI still runs `fmt -check -recursive` and Checkov over it, because both cover
all of `lab/terraform/**`. The GitHub OIDC → AWS IAM role pattern for a team
setup is built but off (`enable_github_oidc = false`, human-applied, plan
runs only) in `../terraform/aws/github-oidc.tf`; see `../terraform/aws/README.md`.

**AI review provider note:** GitHub Models was retired **2026-07-30**, so the
review model runs on **Azure OpenAI**, authenticated with the same Entra OIDC
identity (no api-key). An **Anthropic-API fallback** is included as commented
config in `ai-review.yml` — it is key-based, so it is left disabled to preserve
the "no stored credentials" property.

---

## 7. Kubernetes workload identity pipeline (`k8s-identity.yml`)

A separate, self-contained workflow for the Kubernetes segment
([`../k8s/README.md`](../k8s/README.md)). It holds **no identity at all**:
`contents: read`, no `id-token: write`, no secrets, no variables. The job
installs pinned Terraform and Checkov and runs
[`../k8s/ci/pipeline.sh`](../k8s/ci/pipeline.sh), the same script a human
runs locally. The script builds a kind cluster on the runner (the AKS
stand-in, see [`../docs/STAND-INS.md`](../docs/STAND-INS.md)), applies the
`platform` and `identity` roots under `lab/terraform/k8s`, seeds one secret
into Vault, deploys the workload, runs the end-to-end tests and tears
everything down. Every stage prints PASS/FAIL with its timing, and a summary
table ends the run (stage list: [`../k8s/README.md`](../k8s/README.md) §5).
Two of the checks guard the cluster's configuration rather than the workload.
**Admission:** a ValidatingAdmissionPolicy in the `identity` root
(`clinical-apps-workload-identity`) denies images not pinned by digest,
unapproved images under the `nightly-report` service account, token
automount, and any creation of or change to a `nightly-report` workload by
anyone but the pipeline's identity; server-side dry runs prove each denial. **Drift detection:** a
stage edits the deployers' RoleBinding out of band as the kind admin (it adds
a user, `mallory`). `terraform plan -detailed-exitcode` must then exit 2
(`DRIFT DETECTED`), an apply heals the change, and the next plan must exit 0.

- **Not a required check.** It is path-filtered (`lab/k8s/**`,
  `lab/terraform/k8s/**`, the workflow itself), and a path-filtered required
  check stays *Pending* on PRs it skips (§5 F). So the ruleset on `main`
  keeps its three required checks. To require it, drop
  `paths:` and add job-level change detection as `terraform-plan.yml` does.
- **Fork PRs** run this workflow in full: with no credentials in the job,
  there is nothing to exfiltrate. (A fork PR that also touches
  `lab/terraform/k8s/**` is still blocked by the required `terraform plan`
  check, as any `lab/terraform` change from a fork is: see the next bullet.)
- **Checkov** is the PyPI package pinned to `3.3.20` in its own venv on
  Python 3.12 (`actions/setup-python`, so the ubuntu-latest move to 26.04 and
  its Python 3.14 does not change the interpreter), not `checkov-action`. The pipeline hard-fails on any failed check without an
  inline skip justification. `terraform-plan.yml`'s Checkov job also
  hard-fails (`soft_fail: false`, every accepted finding skipped inline with
  a reason) and also scans `lab/terraform/k8s` (it covers all of
  `lab/terraform/**`).
- **The Entra workflows and the k8s roots.** A PR touching
  `lab/terraform/k8s/**` also counts as a Terraform change for
  `terraform-plan.yml`'s `changes` job (its regex matches all of
  `lab/terraform/`), so its fmt check, Checkov and the `envs/dev` plan run.
  From a same-repo branch that costs one OIDC Entra plan that shows no
  changes. From a fork it fails the required `terraform plan` check by design
  (fork PRs get no OIDC token), so a fork PR touching the k8s roots cannot
  merge until a maintainer re-pushes it as a same-repo branch, exactly like
  any other `lab/terraform` change. Excluding `lab/terraform/k8s/` from that
  regex would avoid both, at the price of also skipping the required Checkov
  job for those files; it is left as is. `terraform-apply.yml` excludes
  `lab/terraform/k8s/**`, so merging k8s-only changes does not start a
  reviewer-gated no-op apply.
- **`aks-mapping` is never applied, by anything.** The third root under
  `lab/terraform/k8s` holds the Entra Workload ID federated credential that
  replaces the Vault role on AKS. `pipeline.sh` runs only fmt, validate and
  the mocked `terraform test` on it, in its Terraform stage. It holds no
  credential and runs no plan against a tenant. `terraform-apply.yml`'s
  `!lab/terraform/k8s/**` keeps it out of the Entra apply. It can't be applied
  here at all: Entra must fetch the cluster's OIDC keys, and kind's issuer
  isn't public.
