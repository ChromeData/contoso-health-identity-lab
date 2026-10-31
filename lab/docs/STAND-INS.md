# Stand-ins — what replaces what, and what I say on camera

This lab runs on **real products** wherever an individual can get them. Where
the enterprise product has no individual trial, a named stand-in does the same
job. Each one is listed here, in the code that runs it, and **out loud** in
any video that shows it.

**Status words** (the same on screen and in this file):
**RAN · harness** = ran on a laptop against local containers, never against a
tenant; **BUILT** = code tested offline, never applied; **DESIGNED** =
documented steps, no code; **RAN · tenant** = ran in the lab tenant (since
2026-10-27; rows in `lab/evidence/capture-log.csv`).

**Filmed in** names the video chapter where the stand-in appears: the
walkthrough (§1–§9), the PAM cut (§1–§12), the Kubernetes companion clip, or
"not filmed yet", when the line is ready but no current cut shows the
stand-in. "§1 (map)" means it appears only as a box on the walkthrough's lab
map, whose caption names what it replaces.

## Stand-ins

| Stand-in (what actually runs) | Replaces | Why | Where in the repo | Status · filmed in | On-camera line |
|---|---|---|---|---|---|
| `hr_feed.csv` + `Invoke-InboundProvisioning.ps1` (mock HR) | **Workday / SAP SuccessFactors** | No free HR SaaS sandbox for an individual. Entra's Workday and SuccessFactors apps pull from the HR system; the mock pushes through API-driven `/bulkUpload`. Both feed the same Entra provisioning service | `lab/scripts/mock-hr/` | BUILT · walkthrough §2 | "The HR system here is a mock I wrote. Entra's Workday and SuccessFactors connectors feed the same provisioning service, so everything from that service down is the same." |
| HashiCorp Vault Community: LDAP secrets engine, static role + library | **CyberArk Digital Vault + CPM** | CyberArk is enterprise-only | `lab/pam/vault-onboard-ad.sh` | RAN · harness (Samba AD; DC01 not yet) · walkthrough §5, PAM cut §3 | "This layer stands in for CyberArk: Vault for the Digital Vault, and its rotation of real AD accounts for CyberArk's CPM." |
| Apache Guacamole session recording | **CyberArk PSM** | Same | `lab/pam/psm-session.sh` | RAN · harness (recorded SSH, and a recorded RDP session to the Linux xrdp stand-in below; a Windows RDP session needs DC01) · walkthrough §5, PAM cut §6 | "Guacamole stands in for PSM: brokered, recorded sessions where the operator never sees the password." (The PAM cut adds: "Its sign-in page acts as PVWA.") |
| CyberArk **Conjur OSS** | Conjur Enterprise / CyberArk Secrets Manager | Same | `lab/pam/conjur-demo.sh` | RAN · harness · walkthrough §1 | "And Conjur is CyberArk's own open-source project, here for workload secrets." |
| Evolveum **midPoint**: a certification campaign run headless over its REST API | **SailPoint IdentityNow / Saviynt** | No individual trial. The campaign certifies users built from the mock-HR personas, not Entra users. midPoint's REST API has no decision endpoint, so a script records each decision through the same service call the GUI uses, inside the assigned reviewer's own security context: midPoint applies that reviewer's authorizations, and no reviewer signs in. Reading Entra users through the Microsoft Graph connector is a tenant-time step and hasn't run | `lab/pam/midpoint/` (campaign; hashed evidence in `lab/evidence/midpoint/`), `lab/pam/README.md` (midPoint section) | RAN · harness · walkthrough §9 | "midPoint stands in for SailPoint or Saviynt. This campaign ran against users built from the mock HR feed, and a script entered each reviewer's decision under that reviewer's own permissions; nobody clicked through it. When certification has to cover SAP, Epic and mainframe, not just Entra apps, this is where SailPoint or Saviynt goes." Only if the Entra aggregation has run and is on screen, add: "These users come from Entra, through Graph." |
| **Okta Integrator Free** org | The acquired clinic's enterprise Okta tenant | Free plan of the real product | `lab/terraform/okta/` (the Okta side: IdP, routing rule, Clinic-Staff, one legacy app; human-applied), `lab/terraform/modules/apps/okta.tf` (the Entra side, `enable_okta_federation`), `lab/docs/okta-migration-runbook.md` (Phases 0–4; ADR 0022) | RAN · tenant (E58: applied against an Okta Integrator Free org) · walkthrough §1 (map) | "Okta, the acquired clinic's reception, is built as code and applied (E58): Entra as its identity provider, one routing rule, one legacy app." (Nothing of Okta is on screen, so nothing is claimed to run. If a cut ever shows the Integrator Free org working, say: "Okta here is the real product, its free Integrator plan, standing in for an enterprise Okta tenant.") |
| **ServiceNow Personal Developer Instance** | Production ServiceNow | Free developer instance of the real product | `lab/monitoring/playbook-notify.json` (incidents); `lab/pam/lib.sh` `itsm_validate` (change tickets and their approvals, including Tier-0 dual control, before a PAM check-out, tenant time) | RAN · tenant (E57: SAML SSO) · walkthrough §5, §6; PAM cut §5 | "ServiceNow is a free developer instance: same platform, same Table API." |
| AWS IAM Identity Center (and the ServiceNow PDI's SAML app) as a nurse's apps | **Clinical apps** (the EHR) | No EHR sandbox for an individual; the SSO + provisioning pattern (package → app group → SAML + SCIM) is the same for any app | `lab/terraform/modules/apps` (`servicenow.tf` for ServiceNow), `lab/terraform/aws` | RAN · tenant (AWS SAML + SCIM, E22/E23; ServiceNow SAML, E57); DESIGNED (ServiceNow provisioning) · walkthrough §3 (AWS only) | "A real nurse gets the health-record system, not AWS. AWS stands in for clinical apps, and the pattern, package to app group to SAML and SCIM, is the same." |
| **Splunk Enterprise 60-day trial** (RAN · harness 2026-10-31: 215 synthetic events replayed, 15 of 22 saved searches fired after the replay learned the harness row contract, `lab/evidence/splunk/20261031T053010Z`) + `lab/splunk/ingest-from-loganalytics.sh` (replay from Log Analytics into HEC via `az login`) | Production Splunk; **Entra → Event Hub → Splunk Add-on for Microsoft Cloud Services** | Time-limited trial; zero new secrets for the feed: no app registration, no Event Hub, no Splunkbase account | `lab/splunk/` (`docker-compose.yml`, `splunk-up.sh`, `ingest-from-loganalytics.sh`) | BUILT, never run · walkthrough §6 (with a caption naming the production path: Entra → Event Hub → Splunk Add-on for Microsoft Cloud Services) | "Splunk is a trial fed by replay, not an Event Hub, running the same rules. Two SIEMs is a migration state; Microsoft-first shops keep Sentinel." |
| **Microsoft Sentinel 31-day trial** → Log Analytics scheduled queries | Production Sentinel | Time-limited trial. LA alerts mute repeat notifications for one window (Sentinel groups per entity instead) | `lab/terraform/modules/monitoring` (`enable_sentinel` / `enable_la_alerts`) | RAN · tenant (E15, E15b) · walkthrough §6 | "I'm on Sentinel's trial for the recording. After it, the identical KQL runs as Log Analytics alerts, and that path is in the same module." |
| Microsoft **trial licenses** (M365 E5, Entra ID Governance; Teams if the E5 trial comes without it) | Purchased licenses | 30-day trials | `lab/terraform/envs/dev/README.md` (Staging flags) | DESIGNED (no tenant yet) · walkthrough §1, PAM cut §1 | "Licensing is trial; nothing I configure depends on that." |
| Windows 11 Enterprise **Azure VM**, Entra joined + Intune enrolled | The corporate laptop / privileged-access workstation | No managed hardware in a lab, and the operator's personal Mac shouldn't be enrolled in a lab tenant. Intune, Entra join and Conditional Access are the real products; only the hardware is substituted | `lab/terraform/modules/intune-vm`, `lab/scripts/intune/` | BUILT · walkthrough §4 | "The managed laptop here is a Windows 11 VM in Azure, Entra-joined and enrolled in Intune, and a script in the repo defines what compliant means: things like Secure Boot and code integrity." |
| **Samba AD DC** container `dc01.corp.test.local` + a stub `az` CLI, seeded with one account per finding | **Windows Server AD DS (DC01)** and its Key Vault reads, for the PAM scripts | The real DC01 needs the trial window; the same scripts run against Samba first. Samba has no RDP, so the harness's RDP session goes to the Linux stand-in below, and a Windows RDP session needs DC01 | `lab/pam/test/` (`e2e.sh`, `docker-compose.samba.yml`, `samba-ad/`, `stub-az`) | RAN · harness · PAM cut §2 (and §3–§4 when the harness state is on screen) | "This part runs on a Samba AD test domain controller in Docker, seeded with one account per finding. The same scripts will run against DC01." |
| `rdp-target` container: Debian xrdp + xorgxrdp, logon only with the AD password (Kerberos against the Samba DC), session = one xterm | **An RDP session to DC01** (Windows Server), for the recorded-RDP path through Guacamole | Samba AD has no RDP; this gives the brokered RDP path something real to connect to. It is Linux, not Windows: it shows the protocol path, the injected credential and the recording, not a Windows logon | `lab/pam/rdp-target/`, `psm-session.sh --target rdp-target` | RAN · harness (`lab/evidence/pam/20261020T220031Z/rdp-recording.json`) · not filmed yet | "This RDP target is a Linux xrdp container standing in for the domain controller. The check-out, the injected password and the recording are the real path; the Windows session comes with DC01." |
| **kind** cluster `contoso-k8s` (Kubernetes in Docker), built and destroyed per run by one script, in CI and on a laptop | **Azure Kubernetes Service (AKS)** | No cloud cost or cloud credentials in CI. RBAC, Pod Security Admission, ValidatingAdmissionPolicy, projected service-account tokens and TokenReview are upstream Kubernetes, the same on AKS. The API-server audit log exists on AKS too, but there its policy is AKS-managed and it is read through diagnostic settings, not a file in the node, so the lab's audit-policy choices (Secrets at Metadata only, RBAC and admission-policy changes at RequestResponse) are not a setting you get on AKS (verify: AKS audit categories) | `lab/k8s/` (`kind/cluster.yaml`, `kind/audit-policy.yaml`, `ci/pipeline.sh`), `.github/workflows/k8s-identity.yml` | RAN · harness (not yet in GitHub Actions) · companion clip (the PAM cut §11 names it on screen) | "This cluster is kind, Kubernetes running in Docker, built and torn down by one script. On AKS the Kubernetes side is the same; what changes is where the identities come from." |
| Vault **Kubernetes auth method + Agent Injector** (in-cluster Vault, dev mode: in-memory, lives one run) | **CyberArk Secrets Manager: Conjur JWT authenticator (`authn-jwt`) + Secrets Provider for Kubernetes**; Azure-native on AKS: **Microsoft Entra Workload ID + Key Vault CSI driver** | Conjur OSS has an authn-k8s authenticator too (verify: docs.conjur.org), but it needs a Conjur server or follower reachable from the cluster plus certificate injection into pods over the exec API; Vault's chart installs server and injector in one Helm release, so the segment stays one self-contained script, and Vault is already the lab's CyberArk stand-in. The pattern carries over: the pod proves who it is with a short-lived, audience-bound service-account token, and no Kubernetes Secret exists | `lab/terraform/k8s/identity`, `lab/k8s/manifests/`; the Entra Workload ID equivalent of the Vault role is `lab/terraform/k8s/aks-mapping` (plan-only, see below) | RAN · harness · companion clip, PAM cut §11 | "The pod logs in to Vault with a ten-minute service-account token whose audience is Vault, and gets exactly one secret. That's the pattern of Conjur's JWT authenticator for Kubernetes; on AKS it's Entra Workload ID and the Key Vault CSI driver." |
| **Impersonated** Kubernetes groups (`kubectl --as-group k8s-clinical-deployers` / `k8s-clinical-auditors`) | **Entra security groups via AKS Microsoft Entra integration** (RoleBinding subject = the group's object ID, or Azure RBAC for Kubernetes) | kind has no Entra sign-in; impersonation drives the same RBAC evaluation an Entra-authenticated user would hit | `lab/terraform/k8s/identity` (Roles + RoleBindings), `lab/k8s/test/k8s-e2e.sh` | RAN · harness · companion clip | "These two human groups are impersonated, because kind has no Entra sign-in. On AKS with Entra integration the RoleBinding names the Entra group's object ID, and the rules are identical." |
| **Lab shortcuts:** a single DC that's also the CA; one Vault unseal key (the main stack; the HA row below shows the production shape); Vault on a laptop over IP-locked public endpoints (DC and Key Vault firewall); local PAM sign-ins (until the Entra OIDC mode is on); guacadmin can read a checked-out password until check-in | At least two DCs per site and a separate Tier-0 CA; split unseal custody, HA; a vault on the private network; PAM behind Entra SSO + Conditional Access; PSM fetching the password at launch | Budget, and a laptop lab | `lab/terraform/modules/dc-vm`, `lab/pam/pam-up.sh` | n/a (shortcuts, not products) · walkthrough §5 | "Lab shortcuts, each on screen with its production fix: one DC, which is also the certificate authority; one unseal key; Vault on my laptop, over IP-locked public endpoints; local PAM sign-ins; and guacadmin can read a checked-out password until check-in." |
| 3-node Vault Raft cluster auto-unsealed by a local **transit unsealer** Vault (`vault-ha.sh`, `dr-drill.sh`), a separate rehearsal cluster: the PAM scripts themselves use the one-node vault | **CyberArk Vault DR / HA**; for Vault in production, **Azure Key Vault (HSM) auto-unseal** | No HSM or second region in a laptop lab; transit auto-unseal exercises the same unseal-on-restart and snapshot-restore path the drill measures (RTO/RPO) | `lab/pam/vault-ha.sh`, `lab/pam/dr-drill.sh`, `lab/pam/ha/` | RAN · harness · walkthrough §1 (map); PAM cut §9 | "The unsealer here is a second local Vault. In production that's Azure Key Vault or an HSM, and the failover and restore steps you see are the same." |
| `lab/scripts/monitoring/ingest-vault-audit.sh` (Vault file audit log → Logs Ingestion API → `VaultCheckout_CL`) | **CyberArk Digital Vault / PTA syslog → Azure Monitor Agent (CEF) → Sentinel** | The stand-in Vault has no CEF/syslog forwarder; the Logs Ingestion API with an `az login` token adds no secret and lands the same "who checked out which Tier-0 account, when" rows the ITDR rule joins against | `lab/scripts/monitoring/ingest-vault-audit.sh`, `lab/terraform/modules/monitoring/telemetry.tf` | RAN · harness (rows built from real Vault audit events; never sent to a real workspace) · walkthrough §1 (map); PAM cut §8 | "Vault's check-out log reaches Sentinel through a small ingestion script. With CyberArk it's the Digital Vault and PTA syslog through the Azure Monitor Agent; the detection joining it to DC logons is the same." |
| `lab/scripts/monitoring/Invoke-AdContainment.ps1` (`az vm run-command` disables the on-prem account after the approved containment) | **Microsoft Defender for Identity response actions** ("Disable user in AD" through the sensor's action account) | MDI needs its own licence and sensor on the DC; the run-command keeps the approval-gated disable on the real DC01 | `lab/scripts/monitoring/Invoke-AdContainment.ps1`, `lab/monitoring/playbook-contain.json` | BUILT · walkthrough §1 (map) | "For a synced account the cloud side can't disable it, so the playbook flags it and this script disables it on the DC. With Defender for Identity that's a built-in response action." |
| Vault **SSH secrets engine as a user CA** (10-minute certificates) + `ssh-target` container, session recorded by Guacamole (`psm-ssh.sh`) | **CyberArk Secure Infrastructure Access** (short-lived certificates); **PSMP** for the recorded session; a real Linux server | Same as the PSM row; a container is the cheapest Linux target that trusts only the CA | `lab/pam/psm-ssh.sh`, `lab/pam/ssh-target/` | RAN · harness · walkthrough §1 (map); PAM cut §7 | "The Linux box is a container that trusts only Vault's SSH certificate authority, so every login is a ten-minute certificate tied to a person: the zero-standing-privilege model of CyberArk's Secure Infrastructure Access." |
| `discover.sh` → `onboard.sh` → `rotate.sh` → `reconcile.sh` (LDAP discovery, bulk onboarding over the Vault API, dependency-gated rotation, reconciliation report) + `Get-AccountDependencies.ps1` | **CyberArk Accounts Discovery / Pending Accounts, onboarding rules, CPM change / verify / reconcile and account usages** | Vault has no discovery or onboarding UI, and it can't push a new password into a Windows service, so rotation is refused until every usage is resolved instead of being updated by the CPM | `lab/pam/discover.sh`, `onboard.sh`, `rotate.sh`, `reconcile.sh`, `accounts-dependencies.json`, `dependency-scan/` (CyberArk vocabulary map: `lab/pam/README.md`) | RAN · harness (Samba AD; DC01 not yet) · walkthrough §5; PAM cut §2–§4 | "Discovery, onboarding and reconciliation here are scripts over Vault's API. In CyberArk that's Accounts Discovery, onboarding rules and the CPM's verify and reconcile; the questions they answer are the same." |
| Vault **database secrets engine** + PostgreSQL `clinical-db` (synthetic data), in their own compose project `contoso-dyndb` with **their own Vault** (`127.0.0.1:8220`), never the AD-backed one; a token minted by the script for the requester | **CyberArk zero-standing-privilege database access / dynamic secrets**, and a real clinical reporting database; the minted token stands in for Vault sign-in through Entra OIDC with an Entra group mapped to the policy | No database estate in a lab; a container with synthetic rows is enough to prove a one-hour login created per request and dropped at expiry. A separate Vault keeps the demo from touching the AD-backed one. verify: CyberArk SIA database support (`lab/pam/dynamic-db/README.md`) | `lab/pam/dynamic-db/`, `lab/pam/docker-compose.dynamic-db.yml`, `lab/pam/test/e2e-dynamic-db.sh` | RAN · harness · walkthrough §5 | "Nobody holds a password to this database. Vault creates a login for one person for one hour and drops it after; the database is a container with synthetic data, behind a lab Vault of its own." |
| DC01 Security events (4624/4672, 4728/4732/4756, 4769 RC4, 4662) through the Azure Monitor Agent, read by the lab's own KQL rules | **Microsoft Defender for Identity** detections (Kerberoasting, DCSync, sensitive-group changes) | MDI needs its own licence and a sensor on the DC; the rules show the detection logic in the open. The MDI sensor stays an optional tenant-time add-on. verify: `SecurityEvent` via AMA needs Sentinel and its connector | `lab/kql/kerberoast-rc4-service-ticket.kql`, `dcsync-replication-request.kql`, `ad-privileged-group-change.kql`, `lab/terraform/modules/monitoring/telemetry.tf` | BUILT · walkthrough §1 (map) | "These AD attack detections are my own queries over the DC's security log. Defender for Identity ships the same detections built in, and its sensor is the production path." |
| `Invoke-CaRestoreDrill.ps1` (Graph snapshot → compare → restore, SHA-256 verified) | **Microsoft Entra Backup and Recovery** (preview) | The product is preview and may not be in the trial tenant (verify: availability); the script runs the same drill, timed, either way. Restore needs the snapshot's `.sha256` sidecar and a break-glass exclusion in the body; re-creating a deleted policy as enforced needs `-AllowEnabledRecreate`; the restore record goes to the gitignored `lab/evidence/out/ca-restore/` | `lab/scripts/powershell/Invoke-CaRestoreDrill.ps1` | BUILT · not filmed yet | Only if the product isn't available: "The restore here uses a snapshot the lab takes through Graph. Entra Backup and Recovery does the same from the portal; the drill and its timing are what matter." |
| "Fabrikam Affiliated Clinic" connected organization: a second Entra tenant or a domain the operator controls (the committed default, `fabrikam-clinic.example`, is a reserved name that never resolves) | **An affiliated practice's own Entra tenant** | No partner organisation exists for a lab; a second free tenant gives a real home tenant for the guest | `lab/terraform/modules/entitlement/b2b.tf`, `lab/scripts/powershell/post-apply/New-B2BConnectedOrganization.ps1`, `Set-ExternalCollaboration.ps1` | BUILT · walkthrough §1 (named, not filmed working) | "The partner clinic here is a second test tenant I control, standing in for an affiliated practice. The guest still arrives only through a sponsor-approved access package that expires in ninety days." |

**The Kubernetes rows are filmed in the companion clip**, which says each of
their lines word for word. The PAM cut §11 says the Vault Kubernetes auth line
word for word and names kind on screen. In the main walkthrough the only
Kubernetes thing on screen is the architecture diagram's dashed box, which
carries its own stand-in label. As with every other stand-in, these lines are
never cut.

**Written, never applied (not stand-ins):**

- `lab/terraform/k8s/aks-mapping` holds the real `azuread` federated identity
  credential that Entra Workload ID would use for
  `system:serviceaccount:clinical-apps:nightly-report` on AKS. It is checked
  offline only (fmt, validate, `terraform test` with a mocked provider), never
  against a tenant. It can't be applied, because Entra has to fetch the
  cluster's OIDC discovery document and keys, and kind's issuer isn't publicly
  reachable. Whenever it's shown, say "never applied".
- CA060 (shared clinical workstations, ADR 0014) targets devices enrolled with
  the `CH-SharedClinical` Autopilot profile. No such device exists in the lab,
  so the policy matches nothing; that is recorded as "not exercised", and the
  device filter is never pointed at another device to get a result.

### Off camera only (rehearsal fixtures, never in the video)

These replace something too, but only for rehearsing without Azure. They never
appear on screen, so they need no spoken line. If one is ever filmed, give it a
row above.

| Fixture | Replaces | Where |
|---|---|---|
| `Reset-DemoState.ps1` | Nothing in the design: puts Dana and Marcus back before a re-take | `lab/scripts/demo/` |
| `itsm-mock` (mock ServiceNow Table API v2 `change_request` and `sysapproval_approver`) | A ServiceNow Personal Developer Instance change and its approvals, for rehearsing the ticket check and Tier-0 dual control before a PAM check-out. Never filmed; the PAM cut names it once as "a mock ServiceNow" when it describes the test harness | `lab/pam/itsm-ticket.sh`, `lab/pam/tools/mock_servicenow.py` |
| Stub `az` / `curl` + sample Vault audit log | The Logs Ingestion API and a live Vault, for testing `ingest-vault-audit.sh` offline | `lab/scripts/monitoring/tests/` |
| Vault-anomaly harness: its own Vault 2.1.1 and Samba AD DC (compose project `contoso-vaultanom`) | DC01 and the shared PAM vault, for producing real Vault audit events (ticketed and unticketed reads, a 403, failed logins, a rotation failure) that the anomaly rule's rows are checked against. Its Splunk step is skipped unless a local Splunk trial is running | `lab/pam/test/e2e-vault-anomaly.sh`, `lab/pam/test/docker-compose.vault-anomaly.yml`, `lab/pam/test/vault-anomaly/` |
| Synthetic IGA fixtures (`sod-tenant.json`, `review-decisions.json`) | Tenant reads, for the offline runs of `09-SoD-Report.ps1` and `10-Review-KPIs.ps1` (a fixture run is refused in the public evidence tree) | `lab/iga/fixtures/` |
| CISA's published ScubaGear sample report (SHA-256 pinned, fetched by the test fixture script) | A ScubaGear run against the tenant, for the offline tests of `Invoke-BaselineAssessment.ps1` | `lab/scripts/powershell/tests/fixtures/Get-ScubaSample.ps1` |
| Azure Data Explorer Kusto emulator in a local container, with synthetic tables and stubbed Sentinel functions | A Log Analytics / Sentinel workspace, for running the 22 KQL rules on a real KQL engine against synthetic positive and negative events. **RAN · harness** on 2026-10-21, after the operator accepted Microsoft's emulator licence: 22/22 rules, 223/223 cases PASS (`lab/evidence/kusto/20261021T001217Z/`). It is a local engine with synthetic data and a shimmed `_GetWatchlist`: not a Log Analytics workspace, not Sentinel, not a tenant, so no rule was scheduled and nothing fired | `lab/monitoring/kusto-harness/` |

## Real products (no stand-in, say so once)

Microsoft Entra ID P2 · Entra ID Governance (access packages and automatic
assignment policies, Lifecycle Workflows, access reviews, B2B connected
organizations and external collaboration settings) · PIM for Groups, for
directory roles and for Azure resources · administrative units, including
restricted management · Conditional Access, including authentication context
and Token Protection (pilot) · Entra ID Protection (risk-based CA) ·
authentication methods policy (passkey profiles, TAP) · app management policy
and admin consent workflow · Entra Agent ID (preview, identity only) · Intune
· Active Directory Domain Services + AD Certificate Services · Entra Cloud Sync
and API-driven inbound provisioning · Azure Key Vault (private endpoint) · Log
Analytics · Microsoft Sentinel, its watchlists and automation rules · Logic
Apps · AWS IAM Identity Center (SAML + SCIM, permission set as code in
`lab/terraform/aws/`) · Microsoft Teams Workflows · GitHub Actions (OIDC,
environments) · Checkov · TruffleHog · Azure OpenAI · Terraform · Microsoft
Graph PowerShell · Azure Blob immutable storage (WORM evidence) · Azure
Monitor Logs Ingestion API · CISA ScubaGear · Microsoft Zero Trust Assessment
· Purple Knight or PingCastle (free AD assessments).

> On camera, once, early: *"Everything you'll see is the real Microsoft, AWS
> and ServiceNow product. Where an enterprise tool has no individual trial,
> I'll name the stand-in and what it replaces when we get there."* (Okta
> isn't in it: it's applied (E58), but nothing of it runs on screen.)

## Rules for keeping this honest

1. A new stand-in isn't merged without a row here, and every video that
   shows it working says the line in its row, word for word. A stand-in that
   appears only as a box on the lab map is covered by the box's caption,
   which names what it replaces. If no video shows it, the row says "not
   filmed yet" and its line waits until one does; if it is only ever a
   rehearsal fixture, it moves to "Off camera only". When a video's line
   changes, this file changes in the same edit.
2. The code or doc that runs a stand-in names what it replaces in its first
   lines.
3. Every number on a slide is MEASURED (`08-Measure-KPIs.ps1`, hashed
   snapshot) and labelled "lab tenant" on the slide itself. No illustrative
   numbers. (The walkthrough has no metrics slide: §9 closes on numbers
   measured in this lab, each already on screen earlier.)
4. The status column uses only the four status words above, and a result is
   described in the present tense only once it has run.

## CyberArk vocabulary, mapped to the lab's stand-ins

Postings say CyberArk. The lab does the same jobs with HashiCorp Vault and Apache Guacamole. Same control, different product names.

| CyberArk term | What it does | Lab equivalent |
|---|---|---|
| Vault / Safe | The locked store, partitioned by team or system | Vault KV secrets engine, one mount per tier |
| CPM (Central Policy Manager) | Rotates passwords on a schedule or after use | Vault AD secrets engine rotation and check-in |
| PSM (Privileged Session Manager) | Opens the session for the admin and records it; the admin never sees the password | Guacamole recorded RDP and SSH sessions, credential injected |
| PVWA (Password Vault Web Access) | The web console where people request and check out access | Vault UI plus the approved-change check on check-out |
| Dual control | A second person approves a check-out | Approved change ticket required before check-out (`FEED` detection matches check-outs to logons) |
| Discovery | Finds privileged accounts nobody knew about | `Find-ShadowAdmins.ps1`, `06-NHI-Inventory.ps1` |
| Conjur | Secrets for programs, not people | Conjur OSS, in the lab under the same name |
