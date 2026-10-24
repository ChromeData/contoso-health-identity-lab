# ADR 0013: Tier-0 domain controller exposure (lab public IP vs. production)

- **Status:** Accepted, as a time-boxed risk acceptance for the lab. Not acceptable for production. BUILT: code validated offline; `enable_dc = false`, so no DC has been deployed.
- **Date:** 2026-10-20
- **Risk owner:** PAM Lead (in the lab, the repository maintainer)
- **Next review:** 2027-01-20, or earlier on any revisit trigger
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

When `enable_dc = true`, `modules/dc-vm` gives DC01 a private address in
`snet-identity` and a **Standard static public IP**. The subnet NSG allows
inbound RDP (3389) and LDAPS (636) to the DC from `operator_ip_ranges` only,
and nothing else; an empty list, the default, creates no inbound rule. The
module accepts only single `/32` IPv4 entries (a range, a bare address or
IPv6 fails the plan, tested in `operator_ip.tftest.hcl`), and the variable
is sensitive, so the PR's plan comment never shows it. The VM is
deallocated nightly, uses Trusted Launch, is built through
`az vm run-command`, and its managed identity can read only its own three
Key Vault secrets.

**Why the public IP exists.** The PAM stand-in runs in Docker on the
operator's laptop: Guacamole brokers recorded RDP to DC01 and Vault rotates
AD passwords over LDAPS, so both need a path from the laptop. The same IP
gives the provisioning agent its outbound access.

**The consequence.** A Tier-0 asset has an internet-facing address. Two
services answer on it to anyone sending from an allowlisted IP, and the admin
path starts on a laptop that also hosts the PAM vault and is not a
privileged access workstation (PAW).

## Options considered

1. **No public IP; Azure Bastion into the VNet.** Removes the listener for
   operator RDP, but doesn't serve the laptop's Vault or Guacamole, so the
   PAM stack would have to move into the VNet.
2. **No public IP; a private Tier-0 admin host** running the PAM stack,
   reached over Bastion or a point-to-site VPN, outbound through a NAT
   gateway. The shape of the production design; the cost is an always-on VM.
3. **Keep the public IP and add just-in-time VM access** (Defender for
   Cloud). Shortens the exposure but keeps the listener, and needs Defender
   for Servers Plan 2.
4. **Public IP with the NSG locked to one operator address, time-boxed
   (chosen for the lab).**

## Decision

**Lab: option 4,** under these conditions:

- `operator_ip_ranges` holds a single `/32`, the operator's current egress
  IP; `modules/dc-vm` enforces it, and `envs/dev` refuses anything wider
  once `enable_dc` is on.
- The DC exists only while the lab is being exercised, and is deallocated
  nightly.
- The built-in administrator password is rotated at first sign-in and held
  only in Key Vault. Day-to-day Tier-0 logons use the vaulted
  `tier0-admin-NN` accounts through a check-out.
- The acceptance ends on the review date.

**Production:** no domain controller has an internet-facing interface.
Administration runs from a PAW, through a PAM-brokered session in a Tier-0
admin subnet, to the DC's private IP. The broker is reached through Bastion
or private connectivity, with JIT access on the broker host. The agent's
outbound goes through a NAT gateway or Azure Firewall. At least two DCs
(R09).

## Consequences

- **The allowlist is the only barrier** between the internet and RDP/LDAPS
  on a DC. A reassigned home IP or carrier-grade NAT behind one address can
  still widen it unnoticed.
- **The operator laptop is effectively Tier 0:** compromising it gives the
  PAM stack and a network path to the DC. Accepted for the lab; option 2
  removes it.
- **Detection.** `tier0-logon-without-checkout.kql` catches a Tier-0 logon
  with no vault check-out. `dc-logon-outside-operator-allowlist.kql` (with an
  SPL twin) flags a DC01 logon from outside the allowlist, read from a
  Sentinel watchlist (`operator_ips`) so the IP never sits in the public
  repo. Each watchlist entry expires on this ADR's review date, after which
  the rule ignores it and the plan warns. Neither rule has run in a
  workspace.
- ADR 0011 relies on this path to keep Global Secure Access out of scope;
  re-check it if the path changes.
- **Residual risk:** risk register R13.

## Revisit trigger

- The review date: 2027-01-20.
- A second operator, or a DC that stays running.
- The PAM stack moves off the laptop: implement option 2.
- Any RDP or LDAPS connection to DC01 from an unexpected source.

## Evidence

- `lab/terraform/modules/dc-vm/main.tf`, `variables.tf`,
  `tests/operator_ip.tftest.hcl`
- `lab/terraform/envs/dev/variables.tf` (`operator_ip_ranges`, sensitive,
  `/32` only with `enable_dc`), `tests/mock_plan.tftest.hcl`, `lab.tfvars`
- `lab/terraform/modules/monitoring/itdr_v2.tf` (`operator_ips` watchlist);
  `lab/splunk/detections/dc-logon-outside-operator-allowlist.spl`
- `lab/kql/tier0-logon-without-checkout.kql`,
  `dc-logon-outside-operator-allowlist.kql`
- `lab/scripts/dc/README.md`; `lab/pam/README.md` (prerequisites)

## Sources (Microsoft Learn, checked 2026-10-20)

- https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-usage
  (JIT VM access needs Defender for Servers Plan 2)
- https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/default-outbound-access
  (explicit outbound options; new virtual networks default to private
  subnets)
