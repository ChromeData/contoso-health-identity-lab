# IAM / PAM RACI

| | |
|---|---|
| Scope | Contoso Health (fictional 5,000-user hospital, lab scenario) |
| Status | Draft v0.1, 2026-10-20 |

**Key:** R = Responsible, A = Accountable (one per row), C = Consulted,
I = Informed.

**Roles:**
- **HR**: People Operations and the HRIS team.
- **Clin Ops**: Clinical Operations (nursing leadership, department managers).
- **IAM Eng**: IAM Engineering.
- **SOC**: Security Operations.
- **Audit**: Internal Audit and Compliance.
- **App Owner**: the business owner of each application.
- **Svc Desk**: Service Desk.
- **CISO**.

| Activity | HR | Clin Ops | IAM Eng | SOC | Audit | App Owner | Svc Desk | CISO | Lab artifact |
|---|---|---|---|---|---|---|---|---|---|
| Worker record (joiner, mover, leaver) | **A/R** | C | I | | | | I | | `lab/scripts/mock-hr/hr_feed.csv` |
| Provisioning pipeline (HR → AD → Entra) | C | | **A/R** | | | | | | `Invoke-InboundProvisioning.ps1` |
| Birthright and access-package design | C | C | **A/R** | | C | C | | | `modules/groups`, `modules/entitlement` |
| Access request approval | | R (manager) | | | | **A** | | | Entitlement approval stage |
| Separation-of-duties (SoD) rules | | C | R | | C | **A** | | | `lab/iga/sod-rules.json`, `Set-IncompatibleAccessPackages.ps1`, `09-SoD-Report.ps1` |
| Access review (risk-tiered, ADR 0012) | | R (manager) | R (runs campaign) | | I | **A** | | | `modules/entitlement` (per-tier review flags), `reviews.tf`, `10-Review-KPIs.ps1` |
| Urgent leaver (involuntary) | **A** (request) | I | R | R (if security-driven) | I | | I | I | `04-Leaver.ps1`, leaver Lifecycle Workflow |
| Day-1 credential (TAP) | | R (manager receives it) | **A** | | | | R (fallback issue) | | Joiner workflow, TAP task |
| CA policy change (report-only) | | I | **A/R** | C | | | I | | `modules/conditional-access` PR |
| CA policy graduation to enforced | | **C (sign-off)** | R | C | I | C | I | **A** | `lab.tfvars` PR |
| PIM eligibility grant | | | R | I | I | | | **A** | `Set-PimGroupEligibility.ps1` |
| PIM activation approval | | | R (approver group) | I (alert) | | | | **A** | `modules/pim`, `kql/pim-activation.kql` |
| Break-glass custody and 90-day drill | | | R | R (confirms alert) | I | | | **A** | Human step 6; `kql/break-glass-signin.kql`; [break-glass-drill.md](../runbooks/break-glass-drill.md) and `Invoke-BreakGlassDrill.ps1` (not yet run) |
| Vault onboarding and rotation policy | | | **A/R** | I | C | C (dependencies) | | | `lab/pam/vault-onboard-ad.sh` |
| NHI ownership and attestation | | | **A** (process) | | I | R (owner attests) | | | [nhi-standard.md](nhi-standard.md) |
| Detection rule lifecycle | | | C | **A/R** | I | | | | `lab/kql/`, `modules/monitoring` |
| Identity incident containment | | I | R | **A** | I | I | I | I | `monitoring/playbook-notify.json` (notify), `monitoring/playbook-contain.json` (Teams-approved containment) |
| Evidence pack for audit | | | R | C | **A** (consumer) | | | | `Export-EvidencePack.ps1` |
| Standards and exceptions | | C | R | C | C | C | | **A** | [exception-process.md](exception-process.md) |
| SSO / SCIM app onboarding | | | R | | | **A** | I | | `lab/terraform/aws/`; others are portal steps (human step 7) |
| Password, MFA and TAP support | | | C | | | | **A/R** | | [help-desk-identity-verification.md](../runbooks/help-desk-identity-verification.md) (not yet exercised) |

## Notes and lab gaps

- **Approver separation.** Whoever requests an elevation can't approve it. The
  lab is a solo repo, so the `prod` reviewer can approve their own deployment
  unless "Prevent self-review" is on (`lab/pipelines/README.md` §5F). This
  needs an exception.
- **Containment.** The notify playbook sends a Teams card and opens a
  ServiceNow ticket for every incident. For High ITDR incidents a second
  playbook asks the containment approver group in Teams, then revokes
  sessions, marks the user confirmed compromised and, with an opt-in role,
  disables a cloud-only account. AD accounts are disabled with
  `Invoke-AdContainment.ps1`. The SOC stays Responsible; nothing acts without
  a human answer. Built and tested offline, never run in a tenant.
- **Escalation for clinical lock-out.** The service desk issues a TAP after
  verifying identity, and Clinical Operations is informed. The procedure is
  level V2-C in
  [help-desk-identity-verification.md](../runbooks/help-desk-identity-verification.md)
  (written, not yet exercised).
- **Runbooks** for the operational rows are in [`../runbooks/`](../runbooks/).
