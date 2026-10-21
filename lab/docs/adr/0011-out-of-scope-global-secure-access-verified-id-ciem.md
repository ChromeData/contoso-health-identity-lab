# ADR 0011: Out of scope: Global Secure Access, Verified ID, CIEM

- **Status:** Accepted
- **Date:** 2026-10-20
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

Three Microsoft capabilities were considered for the lab and left out.
Saying what isn't covered, and why, is part of the design. Each one below
has a reason it doesn't fit Contoso Health's current priorities and a
trigger that would bring it back. The priorities are:

- HR-driven JML
- Conditional Access
- zero standing admin through PIM
- vaulted Tier-0 credentials
- detection and response

## Options considered

1. **Build a small demo of each.** Adds breadth but no depth. Each one needs
   its own licence or trial and isn't backed by a scenario requirement.
2. **Out of scope, recorded here,** with a revisit trigger for each.
3. **Say nothing.** A reviewer can't tell whether something was left out on
   purpose or just missed. Rejected.

## Decision

Option 2.

| Capability | Why it is out | What covers the need today | Revisit trigger |
|---|---|---|---|
| **Global Secure Access** (Entra Private Access / Internet Access, Microsoft's ZTNA) | The scenario's only on-prem admin path is RDP to DC01. In the lab that path is restricted by NSG to `operator_ip_ranges` and brokered through recorded Guacamole sessions. There are no published on-prem apps for remote clinicians. verify: licensing (Entra Suite or standalone). | CA on every cloud app. Tier-0 access only through vaulted, recorded sessions (ADR 0007). | A VPN replacement project, or on-prem clinical apps that need remote access without the network being exposed |
| **Microsoft Entra Verified ID** (verifiable credentials, Face Check) | No scenario requirement for portable credentials or remote identity proofing. Joiners are vouched for by HR, and day-1 sign-in uses a manager-delivered Temporary Access Pass from the joiner Lifecycle Workflow. verify: Face Check pricing and licensing. | HR as the source of truth (ADR 0006) and the TAP-based joiner workflow | Fully remote hiring that needs identity proofing, or credential exchange with affiliated hospitals or agencies (for example agency-nurse credentials) |
| **CIEM** (Microsoft Entra Permissions Management and similar) | Microsoft retired Entra Permissions Management in 2025 (verify: exact end-of-sale and retirement dates and the recommended successor). The scenario's cloud permissions are small and already code. AWS is IAM Identity Center with one `ViewOnlyAccess` permission set in Terraform, and Entra admin roles go through PIM for Groups. PIM for Azure resource roles exists as code (`modules/pim/azure.tf`, off by default, never applied). | Permission sets and PIM for Groups as reviewed code. Access reviews (ADR 0008). | Multi-account AWS or multi-subscription Azure growth beyond what PR review can reason about, or a finding of unused high-privilege cloud permissions |

## Consequences

**Positive**
- Trial time and build time go to the controls the scenario depends on.
- A reviewer can see each omission was a decision, and what would reverse
  it.

**Risks and compensating controls**

| Risk | Control |
|---|---|
| Remote on-prem access is solved ad hoc later | The trigger above names the project that reopens it. Until then, no on-prem app is published to the internet. |
| Unused cloud permissions build up without CIEM | Keep cloud permissions as code with PR review. Turn on PIM for Azure resource roles (`enable_pim_azure_resources`) when there are any to protect. |
| Product names and licensing in this area change often | Every external fact here is marked verify: and must be re-checked before it's quoted. |

## Revisit trigger

Any trigger in the table above, or a scenario change: an acquisition, a new
cloud, or a regulatory requirement for identity proofing.

## Evidence

- `lab/terraform/aws/main.tf`: `aws_ssoadmin_permission_set.view_only`
  (`ViewOnlyAccess`)
- `lab/terraform/modules/dc-vm/main.tf`: NSG allows RDP and LDAPS from the
  operator's IPs only
- `lab/pam/README.md`: recorded Tier-0 sessions
- `lab/scripts/powershell/post-apply/New-LifecycleWorkflows.ps1`: joiner
  TAP task
- `lab/terraform/modules/pim/` (including `azure.tf`), `lab/terraform/modules/conditional-access/`
