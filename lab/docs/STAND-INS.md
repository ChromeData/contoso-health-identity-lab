# Stand-ins: what replaces what

This lab runs on **real products** wherever an individual can get them.
Where the enterprise product has no individual trial, a named stand-in does
the same job. Each one is listed here and named in the code that runs it.

**Status words:** **RAN · harness** = ran on a laptop against local
containers, never against a tenant; **BUILT** = code tested offline, never
applied; **DESIGNED** = documented steps, no code; **RAN · tenant** = ran in
the lab tenant. Nothing has the last status yet: no tenant exists. The hashed
run records behind every RAN · harness row are indexed in
[`lab/evidence/README.md`](../evidence/README.md).

## Stand-ins

| Stand-in (what actually runs) | Replaces | Why | Where in the repo | Status |
|---|---|---|---|---|
| `hr_feed.csv` + `Invoke-InboundProvisioning.ps1` (mock HR) | **Workday / SAP SuccessFactors** | No free HR SaaS sandbox for an individual. Entra's Workday and SuccessFactors apps pull from the HR system; the mock pushes through API-driven `/bulkUpload`. Both feed the same Entra provisioning service | `lab/scripts/mock-hr/` | BUILT |
| HashiCorp Vault Community: LDAP secrets engine, static role + library | **CyberArk Digital Vault + CPM** | CyberArk is enterprise-only | `lab/pam/vault-onboard-ad.sh` | RAN · harness (Samba AD; DC01 not yet) |
| Apache Guacamole session recording | **CyberArk PSM** | Same | `lab/pam/psm-session.sh` | RAN · harness (recorded SSH, and a recorded RDP session to the Linux xrdp stand-in below; a Windows RDP session needs DC01) |
| CyberArk **Conjur OSS** | Conjur Enterprise / CyberArk Secrets Manager | Same | `lab/pam/conjur-demo.sh` | RAN · harness |
| Evolveum **midPoint**: a certification campaign run headless over its REST API | **SailPoint IdentityNow / Saviynt** | No individual trial. The campaign certifies users built from the mock-HR personas, not Entra users. midPoint's REST API has no decision endpoint, so a script records each decision inside the assigned reviewer's own security context; no reviewer signs in. Reading Entra users through the Graph connector hasn't run | `lab/pam/midpoint/` (campaign; hashed evidence in `lab/evidence/midpoint/`), `lab/pam/README.md` (midPoint section) | RAN · harness |
| **Okta Integrator Free** org | The acquired clinic's enterprise Okta tenant | Free plan of the real product | `lab/docs/okta-migration-runbook.md` | DESIGNED |
| **ServiceNow Personal Developer Instance** | Production ServiceNow | Free developer instance of the real product | `lab/monitoring/playbook-notify.json` (incidents); `lab/pam/lib.sh` `itsm_validate` (change tickets and their approvals, including Tier-0 dual control, before a PAM check-out, tenant time) | BUILT |
| AWS IAM Identity Center (and the ServiceNow PDI's SAML app) as a nurse's apps | **Clinical apps** (the EHR) | No EHR sandbox for an individual; the SSO + provisioning pattern (package → app group → SAML + SCIM) is the same for any app | `lab/terraform/modules/apps` (`servicenow.tf` for ServiceNow), `lab/terraform/aws` | BUILT (AWS SAML + SCIM as code; ServiceNow SAML as code, `enable_servicenow_sso`); DESIGNED (ServiceNow provisioning) |
| **Splunk Enterprise 60-day trial** + `lab/splunk/ingest-from-loganalytics.sh` (replay from Log Analytics into HEC via `az login`) | Production Splunk; **Entra → Event Hub → Splunk Add-on for Microsoft Cloud Services** | Time-limited trial; zero new secrets for the feed: no app registration, no Event Hub, no Splunkbase account | `lab/splunk/` (`docker-compose.yml`, `splunk-up.sh`, `ingest-from-loganalytics.sh`) | BUILT (never started: no SPL search has run) |
| **Microsoft Sentinel 31-day trial** → Log Analytics scheduled queries | Production Sentinel | Time-limited trial. LA alerts mute repeat notifications for one window (Sentinel groups per entity instead) | `lab/terraform/modules/monitoring` (`enable_sentinel` / `enable_la_alerts`) | BUILT |
| Microsoft **trial licenses** (M365 E5, Entra ID Governance; Teams if the E5 trial comes without it) | Purchased licenses | 30-day trials | `lab/terraform/envs/dev/README.md` (Staging flags) | DESIGNED (no tenant yet) |
| Windows 11 Enterprise **Azure VM**, Entra joined + Intune enrolled | The corporate laptop / privileged-access workstation | No managed hardware in a lab, and the operator's personal Mac shouldn't be enrolled in a lab tenant. Intune, Entra join and Conditional Access are the real products; only the hardware is substituted | `lab/terraform/modules/intune-vm`, `lab/scripts/intune/` | BUILT |
| **Samba AD DC** container `dc01.corp.test.local` + a stub `az` CLI, seeded with one account per finding | **Windows Server AD DS (DC01)** and its Key Vault reads, for the PAM scripts | The real DC01 needs the trial window; the same scripts run against Samba first. Samba has no RDP, so the harness's RDP session goes to the Linux stand-in below, and a Windows RDP session needs DC01 | `lab/pam/test/` (`e2e.sh`, `docker-compose.samba.yml`, `samba-ad/`, `stub-az`) | RAN · harness |
| `rdp-target` container: Debian xrdp + xorgxrdp, logon only with the AD password (Kerberos against the Samba DC), session = one xterm | **An RDP session to DC01** (Windows Server), for the recorded-RDP path through Guacamole | Samba AD has no RDP; this gives the brokered RDP path something real to connect to. It is Linux, not Windows: it shows the protocol path, the injected credential and the recording, not a Windows logon | `lab/pam/rdp-target/`, `psm-session.sh --target rdp-target` | RAN · harness (`lab/evidence/pam/20261020T220031Z/rdp-recording.json`) |
| **kind** cluster `contoso-k8s` (Kubernetes in Docker), built and destroyed per run by one script, in CI and on a laptop | **Azure Kubernetes Service (AKS)** | No cloud cost or credentials in CI. RBAC, Pod Security Admission, ValidatingAdmissionPolicy, projected service-account tokens and TokenReview are upstream Kubernetes, the same on AKS. The audit-policy choices are not an AKS setting: AKS manages its own audit policy | `lab/k8s/` (`kind/cluster.yaml`, `kind/audit-policy.yaml`, `ci/pipeline.sh`), `.github/workflows/k8s-identity.yml` | RAN · harness (not yet passed in GitHub Actions) |
| Vault **Kubernetes auth method + Agent Injector** (in-cluster Vault, dev mode: in-memory, lives one run) | **CyberArk Secrets Manager: Conjur JWT authenticator (`authn-jwt`) + Secrets Provider for Kubernetes**; Azure-native on AKS: **Microsoft Entra Workload ID + Key Vault CSI driver** | Vault is already the lab's CyberArk stand-in, and its chart installs server and injector in one Helm release, so the segment stays one script. The pattern carries over: the pod proves who it is with a short-lived, audience-bound token, and no Kubernetes Secret exists | `lab/terraform/k8s/identity`, `lab/k8s/manifests/`; the Entra Workload ID equivalent of the Vault role is `lab/terraform/k8s/aks-mapping` (plan-only, see below) | RAN · harness |
| **Impersonated** Kubernetes groups (`kubectl --as-group k8s-clinical-deployers` / `k8s-clinical-auditors`) | **Entra security groups via AKS Microsoft Entra integration** (RoleBinding subject = the group's object ID, or Azure RBAC for Kubernetes) | kind has no Entra sign-in; impersonation drives the same RBAC evaluation an Entra-authenticated user would hit | `lab/terraform/k8s/identity` (Roles + RoleBindings), `lab/k8s/test/k8s-e2e.sh` | RAN · harness |
| **Lab shortcuts:** a single DC that's also the CA; one Vault unseal key (the main stack; the HA row below shows the production shape); Vault on a laptop over IP-locked public endpoints (DC and Key Vault firewall); local PAM sign-ins (until the Entra OIDC mode is on); guacadmin can read a checked-out password until check-in | At least two DCs per site and a separate Tier-0 CA; split unseal custody, HA; a vault on the private network; PAM behind Entra SSO + Conditional Access; PSM fetching the password at launch | Budget, and a laptop lab | `lab/terraform/modules/dc-vm`, `lab/pam/pam-up.sh` | n/a (shortcuts, not products) |
| 3-node Vault Raft cluster auto-unsealed by a local **transit unsealer** Vault (`vault-ha.sh`, `dr-drill.sh`), a separate rehearsal cluster: the PAM scripts themselves use the one-node vault | **CyberArk Vault DR / HA**; for Vault in production, **Azure Key Vault (HSM) auto-unseal** | No HSM or second region in a laptop lab; transit auto-unseal exercises the same unseal-on-restart and snapshot-restore path the drill measures (RTO/RPO) | `lab/pam/vault-ha.sh`, `lab/pam/dr-drill.sh`, `lab/pam/ha/` | RAN · harness |
| `lab/scripts/monitoring/ingest-vault-audit.sh` (Vault file audit log → Logs Ingestion API → `VaultCheckout_CL`) | **CyberArk Digital Vault / PTA syslog → Azure Monitor Agent (CEF) → Sentinel** | The stand-in Vault has no CEF/syslog forwarder; the Logs Ingestion API with an `az login` token adds no secret and lands the same "who checked out which Tier-0 account, when" rows the ITDR rule joins against | `lab/scripts/monitoring/ingest-vault-audit.sh`, `lab/terraform/modules/monitoring/telemetry.tf` | RAN · harness (rows built from real Vault audit events; never sent to a real workspace) |
| `lab/scripts/monitoring/Invoke-AdContainment.ps1` (`az vm run-command` disables the on-prem account after the approved containment) | **Microsoft Defender for Identity response actions** ("Disable user in AD" through the sensor's action account) | MDI needs its own licence and sensor on the DC; the run-command keeps the approval-gated disable on the real DC01 | `lab/scripts/monitoring/Invoke-AdContainment.ps1`, `lab/monitoring/playbook-contain.json` | BUILT |
| Vault **SSH secrets engine as a user CA** (10-minute certificates) + `ssh-target` container, session recorded by Guacamole (`psm-ssh.sh`) | **CyberArk Secure Infrastructure Access** (short-lived certificates); **PSMP** for the recorded session; a real Linux server | Same as the PSM row; a container is the cheapest Linux target that trusts only the CA | `lab/pam/psm-ssh.sh`, `lab/pam/ssh-target/` | RAN · harness |
| `discover.sh` → `onboard.sh` → `rotate.sh` → `reconcile.sh` (LDAP discovery, bulk onboarding over the Vault API, dependency-gated rotation, reconciliation report) + `Get-AccountDependencies.ps1` | **CyberArk Accounts Discovery / Pending Accounts, onboarding rules, CPM change / verify / reconcile and account usages** | Vault has no discovery or onboarding UI, and it can't push a new password into a Windows service, so rotation is refused until every usage is resolved instead of being updated by the CPM | `lab/pam/discover.sh`, `onboard.sh`, `rotate.sh`, `reconcile.sh`, `accounts-dependencies.json`, `dependency-scan/` (CyberArk vocabulary map: `lab/pam/README.md`) | RAN · harness (Samba AD; DC01 not yet); `Get-AccountDependencies.ps1` BUILT (never run on Windows) |
| Vault **database secrets engine** + PostgreSQL `clinical-db` (synthetic data), in their own compose project `contoso-dyndb` with **their own Vault** (`127.0.0.1:8220`), never the AD-backed one; a token minted by the script for the requester | **CyberArk zero-standing-privilege database access / dynamic secrets**, and a real clinical reporting database; the minted token stands in for Vault sign-in through Entra OIDC with an Entra group mapped to the policy | No database estate in a lab; synthetic rows are enough to prove a one-hour login created per request and dropped at expiry. A separate Vault keeps the demo away from the AD-backed one | `lab/pam/dynamic-db/`, `lab/pam/docker-compose.dynamic-db.yml`, `lab/pam/test/e2e-dynamic-db.sh` | RAN · harness |
| DC01 Security events (4624/4672, 4728/4732/4756, 4769 RC4, 4662) through the Azure Monitor Agent, read by the lab's own KQL rules | **Microsoft Defender for Identity** detections (Kerberoasting, DCSync, sensitive-group changes) | MDI needs its own licence and a sensor on the DC; the rules show the detection logic in the open. The MDI sensor stays an optional tenant-time add-on. verify: `SecurityEvent` via AMA needs Sentinel and its connector | `lab/kql/kerberoast-rc4-service-ticket.kql`, `dcsync-replication-request.kql`, `ad-privileged-group-change.kql`, `lab/terraform/modules/monitoring/telemetry.tf` | BUILT |
| `Invoke-CaRestoreDrill.ps1` (Graph snapshot → compare → restore, SHA-256 verified) | **Microsoft Entra Backup and Recovery** (preview) | The product is preview and may not be in the trial tenant; the script runs the same drill, timed, either way. Restore needs the snapshot's `.sha256` sidecar and a break-glass exclusion in the body | `lab/scripts/powershell/Invoke-CaRestoreDrill.ps1` | BUILT |
| "Fabrikam Affiliated Clinic" connected organization: a second Entra tenant or a domain the operator controls (the committed default, `fabrikam-clinic.example`, is a reserved name that never resolves) | **An affiliated practice's own Entra tenant** | No partner organization exists for a lab; a second free tenant gives a real home tenant for the guest | `lab/terraform/modules/entitlement/b2b.tf`, `lab/scripts/powershell/post-apply/New-B2BConnectedOrganization.ps1`, `Set-ExternalCollaboration.ps1` | BUILT |

**Written, never applied (not stand-ins):**

- `lab/terraform/k8s/aks-mapping` holds the real `azuread` federated identity
  credential that Entra Workload ID would use for
  `system:serviceaccount:clinical-apps:nightly-report` on AKS. It is checked
  offline only (fmt, validate, `terraform test` with a mocked provider). It
  can't be applied, because Entra has to fetch the cluster's OIDC discovery
  document and keys, and kind's issuer isn't publicly reachable.
- CA060 (shared clinical workstations, ADR 0014) targets devices enrolled
  with the `CH-SharedClinical` Autopilot profile. No such device exists in
  the lab, so the policy matches nothing; that is recorded as "not
  exercised", and the device filter is never pointed at another device to
  get a result.

### Test fixtures (for testing without Azure; not product stand-ins)

| Fixture | Replaces | Where |
|---|---|---|
| `Reset-DemoState.ps1` | Nothing in the design: resets the demo personas between rehearsal runs | `lab/scripts/demo/` |
| `itsm-mock` (mock ServiceNow Table API v2 `change_request` and `sysapproval_approver`) | A ServiceNow Personal Developer Instance change and its approvals, for rehearsing the ticket check and Tier-0 dual control before a PAM check-out. | `lab/pam/itsm-ticket.sh`, `lab/pam/tools/mock_servicenow.py` |
| Stub `az` / `curl` + sample Vault audit log | The Logs Ingestion API and a live Vault, for testing `ingest-vault-audit.sh` offline | `lab/scripts/monitoring/tests/` |
| Vault-anomaly harness: its own Vault 2.1.1 and Samba AD DC (compose project `contoso-vaultanom`) | DC01 and the shared PAM vault, for producing real Vault audit events (ticketed and unticketed reads, a 403, failed logins, a rotation failure) that the anomaly rule's rows are checked against. Its Splunk step is skipped unless a local Splunk trial is running | `lab/pam/test/e2e-vault-anomaly.sh`, `lab/pam/test/docker-compose.vault-anomaly.yml`, `lab/pam/test/vault-anomaly/` |
| Synthetic IGA fixtures (`sod-tenant.json`, `review-decisions.json`) | Tenant reads, for the offline runs of `09-SoD-Report.ps1` and `10-Review-KPIs.ps1` (a fixture run is refused in the public evidence tree) | `lab/iga/fixtures/` |
| CISA's published ScubaGear sample report (SHA-256 pinned, fetched by the test fixture script) | A ScubaGear run against the tenant, for the offline tests of `Invoke-BaselineAssessment.ps1` | `lab/scripts/powershell/tests/fixtures/Get-ScubaSample.ps1` |
| Azure Data Explorer Kusto emulator in a local container, with synthetic tables and stubbed Sentinel functions | A Log Analytics / Sentinel workspace, for running the 22 KQL rules on a real KQL engine against synthetic positive and negative events. **RAN · harness** on 2026-10-21, after the operator accepted Microsoft's emulator licence: 22/22 rules, 223/223 cases PASS (`lab/evidence/kusto/20261021T001217Z/`). It is a local engine with synthetic data and a shimmed `_GetWatchlist`: not a Log Analytics workspace, not Sentinel, not a tenant, so no rule was scheduled and nothing fired | `lab/monitoring/kusto-harness/` |


## Real products (no stand-in)

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

## Rules for keeping this honest

1. A new stand-in isn't merged without a row here.
2. The code or doc that runs a stand-in names what it replaces in its first
   lines.
3. The status column uses only the four status words above, and a result is
   described in the present tense only once it has run.
