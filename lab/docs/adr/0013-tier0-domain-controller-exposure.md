# ADR 0013: Tier-0 domain controller exposure (lab public IP vs. production)

- **Status:** Accepted, as a time-boxed risk acceptance for the lab. Not acceptable for production. Code validated offline. `enable_dc = false` in `lab.tfvars`, so no DC has been deployed.
- **Date:** 2026-10-20
- **Risk owner:** PAM Lead (in the lab, the repository maintainer)
- **Next review:** 2027-01-20, or earlier on any revisit trigger
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

When `enable_dc = true`, `modules/dc-vm` builds the following:

- **The VM and its addresses.** DC01 (`vm-dc01`) sits in `snet-identity`
  (10.42.2.0/24) with the static private IP 10.42.2.4. Its NIC also has a
  **Standard static public IP**, `pip-vm-dc01`. `snet-identity` is not a
  private subnet: `modules/dc-vm` leaves `default_outbound_access_enabled`
  unset, and the azurerm default is `true` (the unset value is pinned in
  `operator_ip.tftest.hcl`). The public IP is the explicit egress either
  way.
- **Inbound rules.** The subnet NSG allows inbound TCP **3389 (RDP)** and
  **636 (LDAPS)** to 10.42.2.4, from `operator_ip_ranges` only. There is no
  other inbound allow rule. An empty list, which is the default, creates no
  inbound rules at all.
- **The allowlist.** `modules/dc-vm` accepts only single IPv4 addresses
  written as /32; a /24, a /31, `0.0.0.0/0`, a bare address and IPv6 are all
  rejected (tested in `modules/dc-vm/tests/operator_ip.tftest.hcl`).
  `envs/dev` passes it `operator_ip_ranges`, which accepts up to /24 while
  `enable_dc = false`, because the same variable feeds the Key Vault
  firewall, the Intune VM and the evidence store; with `enable_dc = true`
  the `envs/dev` root refuses anything but /32 before the module does. The
  variable is marked sensitive, so the plan comment on the PR never shows
  it.
- **Other controls.** The VM is deallocated every night at 19:00 Eastern. It
  uses Trusted Launch. The forest is built through `az vm run-command`; RDP
  is used by hand only to rotate the admin password and install the
  provisioning agent. Its managed identity can read and write only its own
  two Key Vault secrets (`dc01-dsrm-password`, `svc-vault-rotator`; ABAC).
  A third, `svc-pam-discovery`, was retired on 2026-11-07 with the Vault
  stand-in (ADR 0036).

**Why the public IP exists.** The PAM stand-in runs in Docker on the
operator's laptop. Guacamole brokers recorded RDP sessions to DC01, and
Vault rotates AD passwords over LDAPS, so both need a path from the laptop
to the DC (`lab/pam/README.md`). The same IP gives the DC explicit outbound
access for the Entra provisioning agent.

**The consequence.** A Tier-0 asset has an internet-facing address. Two
services answer on it to anyone sending from an allowlisted IP. The admin
path starts on a laptop that also hosts the PAM vault, and that laptop is
not a privileged access workstation (PAW).

## Options considered

1. **No public IP; Azure Bastion into the VNet.** This removes the public
   listener for operator RDP. It doesn't serve the laptop's Vault (LDAPS) or
   Guacamole, so the PAM stack would have to move into the VNet. verify:
   Bastion SKU and hourly cost.
2. **No public IP; a private Tier-0 admin host.** The PAM stack runs on a
   jump host in a Tier-0 admin subnet, reached over Bastion or a
   point-to-site VPN, with outbound through a NAT gateway. This is the shape
   of the production design. The cost is an always-on VM.
3. **Keep the public IP and add just-in-time (JIT) VM access** (Defender for
   Cloud). The ports stay closed until someone requests them for a time window
   and a source IP. It shortens the exposure but keeps the public listener,
   and it needs Defender for Servers Plan 2.
4. **Public IP with the NSG locked to the operator, time-boxed (chosen for
   the lab).**

## Decision

**Lab: option 4,** under these conditions:

- `operator_ip_ranges` holds a single /32, the operator's current egress IP.
  `modules/dc-vm` enforces the /32.
- The DC exists only while the lab is being exercised. `enable_dc` is turned
  on for a session and off afterwards, and the VM is deallocated nightly.
- The built-in administrator password is rotated at first sign-in and held
  only in Key Vault. That account is used only for the build steps.
  Day-to-day Tier-0 logons use the vaulted `tier0-admin-NN` accounts,
  through a check-out.
- The acceptance ends on the review date.

**Production:** no domain controller has an internet-facing interface,
whether it runs on premises or in Azure IaaS.

- Administration runs from a PAW, through a PAM-brokered session, to the
  DC's private IP. The session manager sits in a Tier-0 admin subnet,
  injects the credential and records the session. There is no direct RDP
  from any workstation.
- The broker is reached through Azure Bastion or private connectivity. JIT
  VM access applies to the broker host. Neither the broker nor the DC has a
  public IP.
- The provisioning agent's outbound traffic goes through a NAT gateway or
  Azure Firewall, limited to the endpoints the agent needs.
- At least two DCs (risk register R09).

## Consequences

- **The allowlist is the only barrier between the internet and RDP/LDAPS on
  a DC.** Two things can still widen it without anyone noticing: a
  reassigned home IP, or carrier-grade NAT behind one address. A /24
  entered by mistake now fails the plan. Because the variable is sensitive,
  the plan doesn't show the value.
- **The operator laptop is effectively Tier 0.** Compromising it gives an
  attacker the PAM stack and a network path to the DC. That is accepted for
  the lab, and it is the defect option 2 removes.
- **Detection.** `tier0-logon-without-checkout.kql` catches a Tier-0 logon
  with no vault check-out, once DC security events reach the workspace
  (`modules/monitoring`). `dc-logon-outside-operator-allowlist.kql`, with
  an SPL twin, flags a DC01 logon from a source outside the allowlist: High
  on a successful logon, Medium on failures only. It reads the allowlist
  from a Sentinel watchlist, `operator_ips` (columns `IpRange`, `Owner`,
  `ExpiresOn`), so the IP never sits in the public repo. `modules/monitoring`
  builds the watchlist from `operator_ip_ranges`, with `ExpiresOn` set to
  this ADR's review date (`operator_ips_expires_on`): the rule ignores an
  expired entry and the plan warns once the date has passed. While the
  watchlist is empty every source alerts. The rule and the watchlist sit
  behind `enable_itdr_detections_v2` on the Sentinel path. Neither rule has
  run in a tenant.
- ADR 0011 relies on this NSG path to keep Global Secure Access out of
  scope. If the path changes, re-check ADR 0011.
- **Residual risk:** risk register **R13**.

## Revisit trigger

- The review date: 2027-01-20.
- A second operator, or a DC that stays running.
- The PAM stack moves off the laptop. Implement option 2 then.
- Any RDP or LDAPS connection to DC01 from an unexpected source.

## Evidence

- `lab/terraform/modules/dc-vm/main.tf`: header, NSG, `azurerm_public_ip.dc`,
  auto-shutdown, ABAC condition
- `lab/terraform/modules/dc-vm/variables.tf`: `allowed_ip_ranges`
  validation (single /32 entries), `auto_shutdown_time`
- `lab/terraform/modules/dc-vm/tests/operator_ip.tftest.hcl`: accepted and
  rejected allowlists
- `lab/terraform/envs/dev/variables.tf`: `operator_ip_ranges`, sensitive:
  IPv4 no wider than /24 in general (shared with the Key Vault firewall, the
  Intune VM and the evidence store), and single /32 entries only when
  `enable_dc = true` (a second validation)
- `lab/terraform/envs/dev/tests/mock_plan.tftest.hcl`: runs
  `dc_refuses_wider_than_single_host` and
  `no_dc_keeps_slash24_out_of_the_watchlist`
- `lab/terraform/envs/dev/main.tf`: `module "dc_vm"`
- `lab/terraform/modules/monitoring/itdr_v2.tf`:
  `azurerm_sentinel_watchlist.operator_ips`
- `lab/splunk/detections/dc-logon-outside-operator-allowlist.spl` and
  `transforms.conf` `[contoso_operator_ips]`: the SPL twin and its lookup
- `lab/terraform/envs/dev/lab.tfvars`: `enable_dc = false`
- `lab/scripts/dc/README.md`: build by run-command; RDP by hand, off camera
- `lab/pam/README.md`: prerequisites, RDP 3389 and LDAPS 636 from the
  operator's IP
- `lab/kql/tier0-logon-without-checkout.kql`,
  `lab/kql/dc-logon-outside-operator-allowlist.kql`

## Sources (Microsoft Learn, checked 2026-10-20)

- JIT VM access needs Defender for Servers Plan 2 and an NSG or Azure
  Firewall:
  https://learn.microsoft.com/en-us/azure/defender-for-cloud/just-in-time-access-usage
- The explicit outbound options (NAT gateway, public IP, load balancer, or
  firewall with a UDR), and the change to private subnets by default: from
  the Microsoft.Network API version released after 2026-03-31, subnets in
  *new* virtual networks default to private (`defaultOutboundAccess =
  false`); existing virtual networks and earlier API versions keep the old
  default:
  https://learn.microsoft.com/en-us/azure/virtual-network/ip-services/default-outbound-access
