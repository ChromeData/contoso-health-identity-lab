# IAM / PAM RACI

| | |
|---|---|
| Scope | Contoso Health (fictional 5,000-user hospital, lab scenario) |
| Status | Draft v0.1, 2026-10-20 |

**Key:** R = Responsible, A = Accountable (one per row), C = Consulted,
I = Informed. **Roles:** HR (People Operations and HRIS), Clin Ops (nursing
leadership and department managers), IAM Eng, SOC, Audit (internal audit and
compliance), App Owner (each application's business owner), Svc Desk, CISO.

| Activity | HR | Clin Ops | IAM Eng | SOC | Audit | App Owner | Svc Desk | CISO | Lab artifact |
|---|---|---|---|---|---|---|---|---|---|
| Worker record (joiner, mover, leaver) | **A/R** | C | I | | | | I | | `lab/scripts/mock-hr/hr_feed.csv` |
| Provisioning pipeline (HR → AD → Entra) | C | | **A/R** | | | | | | `Invoke-InboundProvisioning.ps1` |
| Birthright and access-package design | C | C | **A/R** | | C | C | | | `modules/groups`, `modules/entitlement` |
| Access request approval | | R (manager) | | | | **A** | | | Entitlement approval stage |
| Separation-of-duties rules | | C | R | | C | **A** | | | `lab/iga/sod-rules.json`, `09-SoD-Report.ps1` |
| Access review (risk-tiered, ADR 0012) | | R (manager) | R (runs campaign) | | I | **A** | | | `modules/entitlement`, `10-Review-KPIs.ps1` |
| Urgent leaver (involuntary) | **A** (request) | I | R | R (if security-driven) | I | | I | I | `04-Leaver.ps1` |
| Day-1 credential (TAP) | | R (manager receives it) | **A** | | | | R (fallback) | | Joiner workflow |
| CA policy change (report-only) | | I | **A/R** | C | | | I | | `modules/conditional-access` PR |
| CA policy graduation to enforced | | **C (sign-off)** | R | C | I | C | I | **A** | `lab.tfvars` PR |
| PIM eligibility grant | | | R | I | I | | | **A** | `Set-PimGroupEligibility.ps1` |
| PIM activation approval | | | R (approver group) | I (alert) | | | | **A** | `modules/pim`, `pim-activation.kql` |
| Break-glass custody and 90-day drill | | | R | R (confirms alert) | I | | | **A** | [break-glass-drill.md](../runbooks/break-glass-drill.md) (not yet run) |
| Vault onboarding and rotation policy | | | **A/R** | I | C | C (dependencies) | | | `lab/pam/` |
| NHI ownership and attestation | | | **A** (process) | | I | R (owner attests) | | | [nhi-standard.md](nhi-standard.md) |
| Detection rule lifecycle | | | C | **A/R** | I | | | | `lab/kql/`, `modules/monitoring` |
| Identity incident containment | | I | R | **A** | I | I | I | I | `playbook-contain.json` (Teams-approved) |
| Evidence pack for audit | | | R | C | **A** (consumer) | | | | `Export-EvidencePack.ps1` |
| Standards and exceptions | | C | R | C | C | C | | **A** | [exception-process.md](exception-process.md) |
| SSO / SCIM app onboarding | | | R | | | **A** | I | | `modules/apps`, `lab/terraform/aws/` ([app-onboarding-intake.md](app-onboarding-intake.md)) |
| Password, MFA and TAP support | | | C | | | | **A/R** | | [help-desk-identity-verification.md](../runbooks/help-desk-identity-verification.md) (not yet exercised) |

**Lab gaps.** A requester can't approve their own elevation, but this is a
solo repo, so the `prod` reviewer can approve their own deployment until a
second maintainer exists (exception E5). Containment never acts without a
human answer; the SOC stays Responsible.
