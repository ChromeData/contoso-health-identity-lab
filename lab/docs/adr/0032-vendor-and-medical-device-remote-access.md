# ADR 0032: Vendor and medical-device remote access

- **Status:** DESIGNED. Nothing here is built. B2B guest code exists but has never been applied (`modules/entitlement/b2b.tf`). The lab has no imaging network and no vendor.
- **Date:** 2026-11-07
- **Risk owner:** Identity platform owner, with Clinical Engineering (biomed)
- **Next review:** 2027-02-07
- **Scope:** Contoso Health lab scenario (fictional 5,000-user hospital). Not a real employer.

## Context

- Device vendors support their own equipment remotely. Examples: GE
  HealthCare and Philips field engineers on CT and MRI scanners, the PACS
  (image archive) and patient monitoring servers.
- These devices sit on a separate **imaging and biomed network segment**
  (for example VLAN 30, `10.30.0.0/16`). Many run old operating systems
  that cannot be patched quickly.
- Third-party remote access is a common way in for attackers. The 2024
  Change Healthcare attack started with a stolen remote-access credential
  that had no MFA.
- Today a vendor often has a shared VPN account or an always-on remote
  tool. Nobody knows which engineer used it.

## Options considered

1. **A shared vendor VPN account.** Rejected: no named person, no MFA
   policy we own, always on.
2. **The vendor's own always-on remote tool on the device.** Rejected as
   the default: the hospital cannot see or stop the session. Kept only
   where the device contract requires it, behind a firewall rule that is
   opened per session.
3. **Named B2B guests, just-in-time, recorded (chosen).**

## Decision

1. **Identity.** Each vendor engineer is a named **Entra B2B guest** from
   the vendor's own tenant (a connected organization). Every guest has a
   **sponsor** in Clinical Engineering.
2. **Access package** `Vendor - <Vendor> - <System>` (for example
   `Vendor - GE - CT Suite`):
   - requested by the engineer, approved by the sponsor;
   - **expires after 30 days**; renewal needs a new approval;
   - adds the guest to an eligible group only, never to an active role.
3. **Just in time.** The guest activates a **PIM for Groups** group (for
   example `PIM-Vendor-GE-CT`) for at most 4 hours. Each activation needs
   the sponsor's approval and a ServiceNow change or incident number.
4. **Conditional Access** (a new policy, CA091):
   - phishing-resistant MFA, or MFA trusted from the vendor tenant through
     cross-tenant access settings;
   - only during the agreed maintenance window, enforced by the PIM
     approval and the activation length (Conditional Access has no
     time-of-day condition). verify: CA conditions list;
   - no access from countries outside the contract.
5. **The session.** The engineer reaches the device only through a brokered
   path: **Entra Private Access** (per-app access to the device's address
   and port) or **Azure Bastion** to a jump host on the imaging segment.
   Sessions through Bastion Premium are recorded. Private Access sessions
   are logged, not recorded as video. verify: Global Secure Access logging.
6. **Network.** The imaging segment allows inbound support traffic only
   from the broker. No direct internet path to the devices.
7. **Detection.** Alert on a vendor sign-in outside an active PIM
   activation, and on a vendor session to a device outside its access
   package.

## Consequences

- **Cost.** Entra Private Access and Bastion Premium are paid. The lab
  does not build them (cost rule: about $5 a day). ADR 0011 keeps Global
  Secure Access out of the lab's scope.
- **Vendor friction.** Engineers must request, wait for approval and use
  the broker. The sponsor must answer quickly during an outage of a
  scanner. Fallback: the sponsor can approve from the phone app.
- **Old devices.** Some devices need a vendor tool that only works with
  its own cloud service. Those are exceptions with an end date.

## Revisit trigger

- A device contract that forbids brokered access.
- A vendor that cannot use B2B (no Entra tenant). Then use a hospital
  issued guest account with a passkey, still sponsored and time-boxed.
