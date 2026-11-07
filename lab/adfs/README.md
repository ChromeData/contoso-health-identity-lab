# AD FS → Entra: move one real app, with its claim rules

**Status: BUILT.** The code and tests are in this folder and in
`modules/apps/claims_viewer.tf`. Local checks ran (capture log L10). **Nothing has
run on DC01 or in the tenant.** Two owner decisions come first (see "Blocked on").
ADR 0009 stays a design record until step 9 below has run.

## What this does, in plain words

- **AD FS** (Active Directory Federation Services) is a Windows Server role. It
  lets people use their company (AD) password to sign in to web apps. The app
  trusts AD FS, and AD FS vouches for the user.
- **A claim** is one fact about the user inside the sign-in token that AD FS
  sends to the app. Examples: "email = sam@…", "role = Clinician". The app
  decides what the user can do from its claims.
- **A claim rule** is the AD FS recipe that makes those claims. For example:
  "if the user is in group X, issue role = Clinician".
- **Why companies leave AD FS:** the servers need patching, certificates and
  an internet-facing proxy. Its signing key can forge a sign-in for anyone
  ("Golden SAML"). Entra can do the same job with no servers, and Conditional
  Access then sees every sign-in.
- **The migration:** rebuild the app in Entra with the same claims, point the
  app at Entra, prove the claims did not change, keep a way back, then remove
  AD FS.

## The pieces

| Piece | Where | What it is |
|---|---|---|
| AD FS | DC01 (`scripts/10-Install-Adfs.ps1`) | One-server farm, gMSA `gmsa-adfs`, `sts.corp.contosohealthlab.com` |
| The app | `claims-viewer/` | **Contoso Claims Viewer**: SimpleSAMLphp 2.4.10, a real SAML app on `https://localhost:8443`. It shows every claim it gets. |
| Relying party + rules | `scripts/11-Add-ClaimsViewerRp.ps1`, `claims-viewer.rules.txt` | `urn:contoso:claims-viewer`: LDAP attributes, a transform (UPN → Name ID), group → role (2 rules), one custom regex rule |
| Readiness report feed | `scripts/12-Install-ConnectHealthAgent.ps1` | Microsoft Entra Connect Health agent for AD FS |
| Entra app (as code) | `lab/terraform/modules/apps/claims_viewer.tf` | Same identifier and reply URL. Claim rules converted to a claims-mapping policy plus two app roles. |
| Proof | `compare/` | `capture.mjs` (browser sign-in, saves the app's claims), `compare_claims.py` (before vs after; passes only if equal), `claims-contract.json` |
| Cutover / roll-back | `claims-viewer/cutover.sh entra` / `adfs` | Swaps the one IdP metadata file the app trusts |
| Decommission | `scripts/19-Remove-Adfs.ps1` | Refuses while AD FS still issues tokens for the app; then removes the role, the DKM container (the signing key's protector), the gMSA, DNS and certificates |

### The rule conversion

| AD FS rule | Entra equivalent | Migration report flag (expected) |
|---|---|---|
| 1 LDAP: UPN, mail, givenName, sn, department, employeeID | Claims-mapping policy, `Source = user` | Ready |
| 2 Transform: UPN → Name ID (unspecified) | Name ID = `userprincipalname`; the app asks for format unspecified | Ready |
| 3a/3b `groupsid == <SID>` → `role` | App roles `ClaimsViewer.Clinician` / `.Admin`, assigned to the same AD groups (synced by Cloud Sync) | Needs review (verify) |
| 4 `RegExReplace(upn, "@.*$", "")` | `ExtractMailPrefix(userprincipalname)` | `UNSUPPORTED_ISSUANCE_TRANSFORMATION` (regex), per Microsoft's rule table |
| Access policy "Permit specific group" | Assignment required + one assignment per group | Ready |

## Where AD FS runs, and why

**DC01.** A separate temporary VM is not possible on this subscription:

- The subscription is an **Azure Free Trial** (`quotaId FreeTrial_2014-09-01`).
- Its regional vCPU quota in eastus2 is **4**, and DC01 plus the Intune VM use
  all 4 (2 × Standard_D2als_v7; `az vm list-usage`, read 2026-11-07).
- A Free Trial cannot raise the quota. eastus2 offers no B-series to it. Another
  region would need VNet peering to reach the DC.

AD FS on a domain controller is a supported install since Windows Server 2012
R2. It keeps Tier 0 with Tier 0: the AD FS signing key is as powerful as a DC.
Production puts AD FS on its own servers behind a Web Application Proxy.

## Cost (eastus2 retail prices, read 2026-11-07)

| Item | Cost |
|---|---|
| AD FS on DC01 | $0 extra while DC01 keeps its normal hours (it already runs by day and stops at 19:00 New York). Each extra hour on is $0.172. |
| NSG rule for 443 | $0 |
| Connect Health | $0: part of Entra ID P1, which the E5 trial has (SPE_E5, 25 seats) |
| Entra app, claims policy | $0 |
| Claims Viewer | $0: local Docker |
| For reference: the VM that cannot be made | Standard_D2als_v7 Windows $0.172/h = $4.13/day if left on, plus disk |

Total: **$0 to about $4 a day**, under the program's $5/day rule. Nothing to delete except AD FS itself (step 10).

## Blocked on (owner decisions)

1. **AD FS on DC01: yes or no.** DC01 is Tier 0 and runs Cloud Sync for the
   recording. AD FS adds a service on 443 and does not touch AD DS or Cloud
   Sync. Do it outside recording days.
2. **Connect Health registration needs a person.** `Register-MicrosoftEntraConnectHealthAgent`
   signs in as a Global or Hybrid Identity Administrator. Unattended, it needs
   an account "which does *not* have multifactor authentication enabled"
   (Learn). CA001 requires MFA for everyone except break-glass. So: RDP to
   DC01, run it, and sign in with MFA (about 5 minutes). The alternative is a
   CA001 exclusion for a registration account, which is the lead's call and
   not recommended.
3. **Optional:** to read the report as code (`GET /beta/reports/getRelyingPartyDetailedSummary`),
   the operator needs `Reports.Read.All` (envs/operator, human-applied). Today the call
   returns `Authentication_MSGraphPermissionMissing`. Without it, use the
   portal page.
4. **Colima:** the default Colima VM forwards no ports to the Mac right now (a
   plain test container on 127.0.0.1:18080 was unreachable, while the same
   request inside the VM worked). Restart Colima before step 7.

## Run order (STE)

The E5 trial ends about 2026-11-26. Steps 2 to 6 feed the readiness report, so do them first.

1. Get decision 1. Start DC01 with `lab/scripts/demo/preflight.sh`.
2. Make the pilot password, straight into the Keychain (the toolkit writes over stdin, never argv):
   `node --input-type=module -e "import {keychainWrite, randomPassword} from './lab/scripts/demo/signin/lib.mjs'; keychainWrite('contoso-lab-pw-adfs-pilot', 'adfs-pilot@contosohealthlab.com', 'AD FS pilot (lab/adfs)', randomPassword())"`
3. Install AD FS:
   `lab/scripts/dc/run-on-dc.py lab/adfs/scripts/10-Install-Adfs.ps1 --param DomainName=corp.contosohealthlab.com --param 'DomainAdminUser=CORP\contosoadmin' --secret DomainAdminPassword=keychain:contoso-lab-dc01-admin`
   - 3b. If it prints `gmsaHasSeAudit: false`: add `CORP\gmsa-adfs$` to "Generate security audits" in the Default Domain Controllers Policy (owner's call: a Tier-0 GPO change), then `gpupdate /force`. Write down the change. Undo it in step 10.
4. Add the relying party, rules, groups and pilot user:
   `lab/scripts/dc/run-on-dc.py lab/adfs/scripts/11-Add-ClaimsViewerRp.ps1 --param DomainName=corp.contosohealthlab.com --param UpnSuffix=contosohealthlab.com --param "RulesText=$(cat lab/adfs/claims-viewer.rules.txt)" --secret PilotPassword=keychain:contoso-lab-pw-adfs-pilot`
5. Install the Connect Health agent: `lab/scripts/dc/run-on-dc.py lab/adfs/scripts/12-Install-ConnectHealthAgent.ps1`. Then decision 2: the person registers it.
6. Make sign-in traffic and the "before" claims:
   `lab/scripts/dc/run-on-dc.py lab/adfs/scripts/13-Get-AdfsClaims.ps1 --param FederationServiceName=sts.corp.contosohealthlab.com --param UserName=adfs-pilot@contosohealthlab.com --param Count=5 --secret UserPassword=keychain:contoso-lab-pw-adfs-pilot > before-adfs.json`
   Open Entra > Enterprise apps > Usage & insights > **AD FS application migration**. Record the status and the claim-rule findings. Microsoft notes that changes can take up to 24 hours to show.
7. PR: `enable_adfs_https = true`. After its apply: `claims-viewer/fetch-metadata.sh pin` (ADFS_IP = DC01's public IP), then `fetch-metadata.sh adfs`, `cutover.sh adfs`, and `node lab/adfs/compare/capture.mjs adfs-pilot@contosohealthlab.com before.json` (browser, through the app).
8. PR: `enable_claims_viewer_app = true` with the two group object ids. After its apply: run the output `claims_viewer_saml_signing_cert_activation_command`, then `enroll.mjs adfs-pilot@contosohealthlab.com` (authenticator for Entra MFA).
9. **Cutover and proof:** `fetch-metadata.sh entra` (TENANT_ID, CLIENT_ID), `cutover.sh entra`, `capture.mjs … after.json`, `python3 lab/adfs/compare/compare_claims.py before.json after.json`. It must print `"same": true`. **Roll-back** at any point: `cutover.sh adfs` (the AD FS relying party is still there).
10. **Decommission** after the quiet period: `19-Remove-Adfs.ps1 -DomainName … -QuietHours 24` (report), then `-Apply yes`. Undo step 3b. PR: `enable_adfs_https = false`. The Entra app stays: it is now the app's only IdP.

## Safety notes

- The tenant domain is **not** federated. Only this one app ever trusts AD FS, so no user can be locked out of Microsoft 365.
- Secrets: only protected run-command parameters and the Keychain. `13-Get-AdfsClaims.ps1` prints claims, never the token.
- The pilot user has no HR record on purpose. The HR reconciliation report will flag it until `-RemoveTestObjects yes`.
