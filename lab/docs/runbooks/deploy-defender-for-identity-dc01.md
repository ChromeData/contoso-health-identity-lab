# Runbook: deploy Defender for Identity on DC01 (L2)

**Scenario:** Contoso Health lab (fictional 5,000-user hospital).

> **Status: this has NOT been run.** Microsoft Defender for Identity (MDI) is
> staged in code behind `enable_defender_for_identity` (ADR 0023), which is
> `false` in `lab/terraform/envs/dev/lab.tfvars`. No sensor is installed, no
> trial has started, and the Defender XDR connector is not created. Don't cite
> an MDI result anywhere until this runbook has run and left evidence.

## Why

MDI is the native on-prem AD-attack detector (ADR 0023). It runs a sensor on
the domain controller and ships Microsoft-maintained detections for
Kerberoasting, DCSync, lateral movement and reconnaissance. In this lab it is
the **primary** detector for those signatures; the four SecurityEvent KQL rules
(`lab/kql/kerberoast-rc4-service-ticket.kql`,
`dcsync-replication-request.kql`, `ad-privileged-group-change.kql`, and the
recon half of `tier0-logon-without-checkout.kql`) are kept as its portable,
offline-testable twins. `tier0-logon-without-checkout.kql` and
`dc-logon-outside-operator-allowlist.kql` stay custom: they correlate against
the Vault check-out feed and the operator allowlist, which MDI cannot see.

Terraform can express only one piece of MDI: the Microsoft Defender XDR data
connector that lands MDI alerts in the lab's Log Analytics workspace
(`lab/terraform/modules/monitoring/mdi.tf`). Everything else on this page is a
human step, because the `azurerm` / `azuread` providers cannot create an MDI
workspace or install a sensor.

## What the flag does, and what it does not

`enable_defender_for_identity = true` (with `enable_sentinel = true`) adds
`azurerm_sentinel_data_connector_microsoft_threat_protection`: MDI alerts then
arrive in `SecurityAlert`, beside the twin rules' incidents. It does **not**
start the trial, provision MDI, or install the sensor. Turn the flag on only
**after** steps 1-5 below, so the connector has alerts to carry.

## Prerequisites

- `enable_dc = true` and DC01 built and promoted (`lab/scripts/dc`,
  `lab/terraform/modules/dc-vm`). The DC is reached by `az vm run-command`
  (build) and by hand through Azure Bastion (no public IP since the ADR 0013
  amendment of 2026-11-08); see
  `lab/scripts/dc/README.md`.
- `enable_sentinel = true` and Entra logs flowing (the connector is a Sentinel
  feature).
- A **Microsoft Security Administrator** (or Global Administrator) to start the
  trial and provision MDI. Marked `[tenant admin]` below.

## Steps

1. **[tenant admin] Start the Defender for Identity trial.** In the Microsoft
   Defender portal, start the free 90-day Defender for Identity trial.
   `verify:` the trial entry point and that it needs no credit card
   (Microsoft Learn, "Defender for Identity licensing").

2. **[tenant admin] Create / confirm the MDI workspace.** MDI auto-creates its
   workspace on first use; confirm it exists in the Defender portal under
   *Settings -> Identities*. Note the geography it picks.

3. **[tenant admin] Create the directory service account (DSA).** MDI reads the
   directory with a DSA. For the lab a **gMSA** is the documented choice (the
   KDS root key already exists from `lab/scripts/dc/02-Configure-Domain.ps1`).
   Create the gMSA, allow DC01 to retrieve its password, and register it in
   *Settings -> Identities -> Directory service accounts*. `verify:` the
   current gMSA steps and the exact permissions (Microsoft Learn,
   "Directory Service Accounts").

4. **Download and install the sensor on DC01.** Download the sensor package and
   access key from *Settings -> Identities -> Sensors* in the Defender portal.
   Install it on DC01. Reach DC01 the same way the build does: either run the
   silent installer through `az vm run-command invoke` / `run-on-dc.py` (no
   RDP; pass the access key as a protected parameter, the way
   `04-Install-CloudSyncAgent.ps1` passes secrets), or by hand through an Azure
   Bastion session (off camera; DC01 has no public IP, ADR 0013 amendment).
   Prefer run-command so no secret
   reaches a command line. `verify:` the silent-install flags and that the
   sensor service starts (Microsoft Learn, "Install the sensor").

5. **Verify sensor health.** In *Settings -> Identities -> Sensors* the DC01
   sensor shows **Healthy** (give it a few minutes to report). Resolve any
   health alert (NNR, event forwarding, connectivity) before going on.
   `verify:` the health page lists no open sensor issue.

6. **Turn on the connector (code).** Set `enable_defender_for_identity = true`
   in `lab/terraform/envs/dev/lab.tfvars` in its own PR and apply. This creates
   the Defender XDR connector, so MDI alerts reach `SecurityAlert`. If the
   workspace is already onboarded to the unified Defender portal, the
   connection may be managed there automatically and the resource can conflict;
   if the apply reports that, drop the resource and keep the flag as the record
   that MDI is in the design (`mdi.tf` header, `verify:`).

7. **Confirm alerts reach Sentinel.** Generate a benign MDI test alert
   (Microsoft documents a safe reconnaissance test), and confirm it appears in
   `SecurityAlert` and as a Defender XDR incident. The lab's `notify`
   automation rule filters to lab analytic-rule ids, so an MDI incident is not
   double-notified: MDI has its own response actions (that is expected).

## Verify

- [ ] DC01 sensor **Healthy** in the Defender portal
- [ ] An MDI detection (e.g. Kerberoasting or DCSync) raises an alert in
      `SecurityAlert`
- [ ] The twin KQL rule fires on the same event (so the twin and MDI agree)
- [ ] `terraform -chdir=lab/terraform/envs/dev output
      defender_for_identity_connector_id` is non-null
- [ ] Record the run in `lab/evidence/` (not committed here) and fill the ADR
      0023 "How it is measured" placeholders

## After

- The trial is 90 days. On expiry, either license MDI or set
  `enable_defender_for_identity = false` and fall back to the twin KQL rules
  (they keep running with no licence). This is ADR 0023's revisit trigger.
- A second DC needs its own sensor. One sensor per DC.

## What this runbook carries that code cannot

The trial, the MDI workspace, the directory service account, the sensor
install and sensor health are all portal / on-DC steps. The `azurerm` /
`azuread` providers cannot express any of them. Terraform owns only the
Defender XDR connector (step 6); the rest lives here.
