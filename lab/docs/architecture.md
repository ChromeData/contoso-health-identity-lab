# Architecture — Contoso Health Identity Platform

Microsoft Entra ID sits in the middle, inside the thick blue border. What
feeds it is above: HR, on-prem AD, the delivery pipeline and the managed
device. What it drives is below: applications, identity threat detection and
response, and audit evidence. The PAM stand-ins sit below it on the left.
Solid boxes are **real products**. A dashed box is, or holds, a
**stand-in**: its "stand-in:" line names what it replaces, as does
[`STAND-INS.md`](STAND-INS.md).

![Contoso Health Identity Platform architecture](architecture.svg)

Source: [`architecture.mmd`](architecture.mmd); re-render with
`./render-architecture.sh`.

## Status labels

Each box's bold status says how far it has actually been exercised, and the
fill repeats it, so the map can't claim more than the repository proves:

| Label | Fill | Means | Boxes |
|---|---|---|---|
| **RAN · harness** | green | Executed end to end on a local harness, with a hashed run record in [`../evidence/`](../evidence/README.md), except the Vault audit feed box, whose count is self-reported in its README ("log not in repo") | Vault lifecycle, Guacamole, Vault HA/DR, dynamic database credentials, Conjur, the midPoint campaign, the Vault audit feed, the Kubernetes segment |
| **BUILT** | amber | Code plus offline tests (mocked `terraform test`, Pester, fixture runs); **never applied to a tenant**. Boxes marked "untested" (the DC01 build scripts behind AD DS and AD CS, Intune's compliance script) have no tests | Everything in Entra; AD DS and AD CS; Intune; the pipeline; Key Vault; detections; both playbooks; the evidence pack, KPIs and WORM store; SSO + SCIM; ServiceNow tickets and SAML SSO (flag off) |
| **DESIGNED** | white | Documented steps or a runbook only | The provisioning agent and Cloud Sync configuration, ServiceNow provisioning, the Okta cut-over |
| **RAN · tenant** | — | Run in the Entra tenant, with captured evidence | **None yet: no tenant exists** |

A box moves up only when its capture exists
([`evidence-capture-plan.md`](evidence-capture-plan.md)); then the map is
re-rendered. One note on this rendering: the harness now also records an RDP
session to a Linux xrdp container standing in for DC01, which the map
doesn't draw. Guacamole's Entra sign-in (OIDC, behind CA022) is BUILT, not
run.

## Owners

From [`standards/raci.md`](standards/raci.md): **HR** owns the worker record;
**IAM Engineering** owns the platform, the pipeline and the vault; **App
Owners** are accountable for their apps, reviews and SoD exceptions, and
attest the NHIs they own; the **SOC** owns detection and containment;
**Audit** consumes the evidence pack; the **CISO** approves PIM eligibility
and each Conditional Access graduation.

## What the map shows, band by band

**Lifecycle.** HR posts a worker; API-driven inbound provisioning places
them in the right AD OU with a mass-change guard
([ADR 0006](adr/0006-api-driven-inbound-provisioning-vs-workday-connector.md)),
and Cloud Sync brings them into Entra
([ADR 0001](adr/0001-cloud-sync-vs-connect-sync.md)). One HR change disables
a leaver in AD and Entra; `04-Leaver.ps1` revokes sessions, removes packages
and app assignments, and flags the non-human identities the leaver owns.
The acquired clinic's Okta trusts Entra while its apps move across one at a
time ([`okta-migration-runbook.md`](okta-migration-runbook.md)).

**Governance.** Birthright access needs no approval: automatic assignment
from HR attributes. Anything else is an access package with approval and a
180-day expiry; guests come only through a sponsor, for 90 days. Nine SoD
rules are preventive where an incompatibility link can enforce them and
detective on existing access. Reviews are tiered by risk, and birthright
clinical access is never removed on silence, so an ignored review can't lock
a nurse out
([ADR 0012](adr/0012-access-review-no-response-and-clinical-lockout.md)).
midPoint runs the same campaign headless as the SailPoint / Saviynt stand-in
([ADR 0008](adr/0008-iga-entra-id-governance-midpoint-vs-sailpoint-saviynt.md)).

**Apps.** The packages' `App-*` groups drive SSO and provisioning as code:
AWS IAM Identity Center over SAML and SCIM, ServiceNow over SAML (flag off;
provisioning DESIGNED), and the Clinical Portal and the PAM broker over OIDC.

**Access.** Conditional Access is code, report-only first, one policy
graduated per PR, with break-glass excluded from every policy and alerted on
([ADR 0003](adr/0003-ca-exclusions-and-break-glass.md)). Four groups:
baseline (CA001–CA005), risk-based (CA006–CA007,
[ADR 0015](adr/0015-risk-based-conditional-access-thresholds.md)),
phishing-resistant sign-in and protected registration (CA008–CA010,
[ADR 0016](adr/0016-passkey-profiles-and-phone-method-retirement.md)), and
admin and clinical sessions (CA011, CA020–CA023, CA060,
[ADR 0014](adr/0014-shared-clinical-workstation-authentication.md)). The full
list is in the [CA design principles](standards/conditional-access-design-principles.md) §1.

**Privilege.** No human holds a standing admin role except the two
break-glass accounts. Elevation goes through PIM for Groups in Tier-0 and
Tier-1 groups with approver groups, expiring eligibility and a
phishing-resistant step-up for Tier 0; Global Administrator is a direct,
expiring eligibility per named person; the help desk is scoped to an
administrative unit of ordinary workforce accounts
([ADR 0002](adr/0002-pim-for-groups-vs-direct-role-eligibility.md)). Tier-0
AD credentials live in Vault: discovered, onboarded, rotated after a
dependency check, reconciled, and checked out against an approved change
(two approvers for Tier 0) into a per-person recorded session
([ADR 0007](adr/0007-pam-stand-ins-vault-guacamole-conjur-vs-cyberark.md)).
HA and DR are rehearsed on a separate three-node cluster with a timed drill
([ADR 0019](adr/0019-pam-vault-high-availability-and-dr.md)); database access
is a one-hour login created on request.

**Non-human identities.** An inventory with owners, credential expiry and a
register of secrets outside Entra, an app management policy, admin consent
only through a workflow, a leaver hand-off, and an identity-only Entra Agent
ID ([ADR 0018](adr/0018-nhi-ownership-and-agent-identity-sponsorship.md)).

**Identity threat detection and response.** Entra sign-in, audit and risk
logs, DC01's security events and the vault's check-out feed reach Sentinel:
22 rules, from consent and credential changes on apps through roles granted
outside PIM to Kerberoasting, DCSync and vault misuse
([threat-model.md](threat-model.md)). The domain-controller rules stand in
for Defender for Identity's detections. On a High incident the containment
playbook asks a listed approver in Teams, then revokes sessions and confirms
the user compromised; a synced account is flagged for an AD disable
([ADR 0017](adr/0017-approval-gated-identity-containment.md)). Splunk
receives a replay of the same events.

**Delivery and evidence.** Changes ship as Terraform through a PR with
checks and a human gate, applied over OIDC with no stored credentials
([ADR 0004](adr/0004-pipeline-workload-identity-federation.md)); the APPLY
identity's Tier-0 reach is a formal risk acceptance
([ADR 0005](adr/0005-risk-acceptance-apply-identity-tier0.md)). Post-apply
scripts handle what the provider can't express. One command exports a
hashed evidence pack mapped to SOX and HIPAA controls into a WORM store
whose writers can add but never delete.

**Workloads on Kubernetes** (optional, the dashed box under the pipeline).
A throwaway kind cluster, the AKS stand-in, is built and destroyed on every
run; a clinical job proves who it is with a ten-minute, audience-bound
token and gets one secret as a file, with no Kubernetes Secret. The AKS
mapping is written, never applied
([ADR 0011](adr/0011-out-of-scope-global-secure-access-verified-id-ciem.md),
[`../k8s/README.md`](../k8s/README.md)).

**Not on the map:** the AD FS retirement path
([ADR 0009](adr/0009-adfs-to-entra-id-retirement-path.md)), the CA restore
drill (`Invoke-CaRestoreDrill.ps1`, BUILT), and what ADR 0011 leaves out of
scope.

The design documents behind the map, and the order to read them in, are in
[`README.md`](README.md).
