# Architecture Decision Records

The design decisions behind the Contoso Health identity platform (a
fictional 5,000-user hospital). Each record says what was decided, which
options were rejected, what it costs and what would change it. The code
READMEs say *how*; these say *why*. Start with 0012, 0002 and 0019 (about
15 minutes for all three).

## Index

| ADR | Decision | Area |
|---|---|---|
| [0001](0001-cloud-sync-vs-connect-sync.md) | Cloud Sync over Connect Sync: one agent serves sync and HR provisioning | Hybrid identity |
| [0002](0002-pim-for-groups-vs-direct-role-eligibility.md) | PIM design: role-holding groups, Tier-0/1 map, approver groups, caps, expiring eligibility, `c1` step-up, direct GA eligibility, AU-scoped help desk | Privileged access |
| [0003](0003-ca-exclusions-and-break-glass.md) | One break-glass group, excluded from every CA policy and alerted on every sign-in | Access policy |
| [0004](0004-pipeline-workload-identity-federation.md) | Pipeline on OIDC federation, PLAN and APPLY split by token subject | Delivery / NHI |
| [0005](0005-risk-acceptance-apply-identity-tier0.md) | Risk acceptance: the APPLY identity is Tier 0 (time-boxed, lab only) | Risk |
| [0006](0006-api-driven-inbound-provisioning-vs-workday-connector.md) | API-driven inbound provisioning in the lab; native Workday connector plus API sources in production | Lifecycle (JML) |
| [0007](0007-pam-stand-ins-vault-guacamole-conjur-vs-cyberark.md) | PAM stand-ins (Vault, Guacamole, Conjur), mapped term by term to CyberArk | PAM |
| [0008](0008-iga-entra-id-governance-midpoint-vs-sailpoint-saviynt.md) | Entra ID Governance as IGA of record; midPoint stands in for SailPoint / Saviynt | Governance |
| [0009](0009-adfs-to-entra-id-retirement-path.md) | AD FS retirement: staged rollout with password hash sync, app by app | Federation |
| [0010](0010-kubernetes-workload-identity-scope.md) | Merged into 0011 | — |
| [0011](0011-out-of-scope-global-secure-access-verified-id-ciem.md) | Scope boundaries: Kubernetes kept to one workload; GSA, Verified ID and CIEM left out | Scope |
| [0012](0012-access-review-no-response-and-clinical-lockout.md) | Risk-tiered certification: silence removes privileged access but never a nurse's clinical access | Governance |
| [0013](0013-tier0-domain-controller-exposure.md) | Risk acceptance: DC01's operator-only public IP, lab only | Risk / Tier 0 |
| [0014](0014-shared-clinical-workstation-authentication.md) | Shared clinical stations: a FIDO2 key per clinician, a device-filtered CA policy, a 5-minute lock | Authentication |
| [0015](0015-risk-based-conditional-access-thresholds.md) | Risk-based CA at High only; Medium goes to the SOC | Access policy |
| [0016](0016-passkey-profiles-and-phone-method-retirement.md) | Two passkey profiles, protected registration, SMS and voice retired before Microsoft's date | Authentication |
| [0017](0017-approval-gated-identity-containment.md) | Containment runs only after a person approves in Teams; a confirmed compromise gets a block | Detection and response |
| [0018](0018-nhi-ownership-and-agent-identity-sponsorship.md) | Two owners per non-human identity; agents get Agent ID with a named sponsor | NHI / governance |
| [0019](0019-pam-vault-high-availability-and-dr.md) | Vault HA and DR: Raft, auto-unseal, a timed restore drill (RAN · harness, hashed) | PAM / resilience |
| [0020](0020-pim-activation-design.md) | Merged into 0002 | — |

## Format

Title, Status, Date · Context · Options considered · Decision ·
Consequences (risks and compensating controls) · How it is measured (from
0012) · Revisit trigger · Evidence · Sources (Microsoft facts with URL and
check date). A risk acceptance names an owner and a review date: 0005 and
0013 in full, and one each inside 0015 and 0017.

## Rules

1. **Evidence means file paths in this repo.** An ADR never claims a tenant
   result, drill or metric that hasn't happened; the result cell says "fill
   after running" until it has.
2. **Status uses the repository's four words:** RAN · tenant (nothing yet),
   RAN · harness, BUILT, DESIGNED.
3. **External facts that could change are marked `verify:`** until checked
   against a primary source.
4. **Decisions are superseded, not edited.** A changed decision gets a new
   ADR and the old one says "Superseded by 00NN". One consolidation was made
   on 2026-10-21, before any tenant run: 0020 merged into 0002 and 0010 into
   0011, each leaving a pointer at its old number.
5. **Revisit triggers are reviewed whenever the lab moves a phase forward.**
