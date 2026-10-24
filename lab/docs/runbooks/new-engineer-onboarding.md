# New engineer onboarding

**Scenario:** Contoso Health lab (fictional 5,000-user hospital). For an
engineer joining the identity team that owns the lab. What has run and what
hasn't is in [`../../evidence/README.md`](../../evidence/README.md); treat
anything without a record there as unproven, and never present it as
working.

## House rules

1. **One owner per object.** Terraform owns groups, CA, PIM policy and
   packages. HR owns workers. Scripts verify and fill the Graph gaps.
2. **No secrets in the repo.** It is public. Identifiers go in GitHub
   Variables; the operator IP and alert email are repo secrets only so the
   logs mask them.
3. **CA ships report-only,** and one policy graduates per PR
   ([graduate-a-ca-policy.md](graduate-a-ca-policy.md)).
4. **Name every stand-in.** A new one needs a row in
   [`../STAND-INS.md`](../STAND-INS.md).
5. **Write `verify:` when you aren't sure.** Never guess a fact or a result.

## Run what runs without a tenant

Terraform 1.16.5 (the lock files' version), PowerShell 7 with the Graph
modules, Docker (Colima on Apple Silicon), `jq`, `openssl`, `curl`.

```bash
terraform -chdir=lab/terraform fmt -recursive -check
terraform -chdir=lab/terraform/envs/dev init -backend=false
terraform -chdir=lab/terraform/envs/dev validate
terraform -chdir=lab/terraform/envs/dev test -var-file=lab.tfvars
cd lab/pam && ./test/run-all.sh          # PAM default suites on local Docker
lab/k8s/ci/pipeline.sh                   # kind cluster, built and destroyed
lab/splunk/render-savedsearches.sh --check
```

Tenant work follows the Terraform README's *Apply order*, and it starts
trial licences that run on a clock. Ask before you touch
`terraform/envs/bootstrap` (human-applied, Tier-0 grants).

## First week

| Day | Do | Done when |
|---|---|---|
| 1 | Read [`../architecture.md`](../architecture.md), [`../STAND-INS.md`](../STAND-INS.md), and the Terraform and pipelines READMEs | You can explain why APPLY is effectively Tier 0, and what limits it |
| 2 | Run the offline checks above | Every check passes, or an issue is filed with the output |
| 3 | Read the core KQL rules beside their SPL twins, then the runbooks in this folder | You can say what each rule catches and what it misses |
| 4 | Pick one `verify:` item in `lab/` and close it with a primary source, or record why you can't | A PR with the source linked |
| 5 | Tabletop [compromised-identity.md](compromised-identity.md) with a teammate, then review a CA PR with the checklist in [graduate-a-ca-policy.md](graduate-a-ca-policy.md) §7 | Gaps found are filed as issues |
