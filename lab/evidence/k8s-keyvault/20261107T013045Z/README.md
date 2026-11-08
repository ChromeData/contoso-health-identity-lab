# Kubernetes workload identity with Azure Key Vault: live run 2026-11-07

**Status: RAN · tenant.** One unmodified run of
`lab/scripts/operator/op lab/k8s/ci/pipeline.sh` on the lab Mac, as the lab
operator, against tenant ContosoHealthLab and a throwaway resource group
(`rg-k8skv-test-864b1cef`, eastus2). Exit 0. Full output: [`run.log`](run.log).

| Stage | Seconds | Result | Evidence |
|---|---|---|---|
| 1 preflight | 12 | PASS | kind v0.33.0 + kubectl v1.37.1 hash-verified; az = the operator service principal |
| 2 terraform fmt / validate / test | 6 | PASS | 3 roots, 17 tftest runs |
| 3 checkov | 12 | PASS | 11 terraform + 88 k8s checks, 0 failed |
| 4 azure: vault, issuer, trust | 127 | PASS | storage static website, Key Vault (RBAC), clinical-db + decoy, app + federated credential + Key Vault Secrets User on clinical-db |
| 5 kind cluster + public issuer | 54 | PASS | API server discovery document + JWKS published, read back anonymously, same SHA-256 |
| 6 platform apply | 21 | PASS | CSI driver + Azure provider; CSIDriver tokenRequests = ["api://AzureADTokenExchange"] |
| 7 identity apply | 3 | PASS | 9 added; live VAP [Deny], 4 rules |
| 8 deploy workload | 34 | PASS | pod Ready = Entra exchange + Key Vault read worked |
| 9 rotate secret | 7 | PASS | new version live in ~5 s, same pod, 0 restarts |
| 10 drift | 3 | PASS | plan exit 2 on the tampered RoleBinding, healed, plan exit 0 |
| 11 e2e | 35 | PASS | `K8S E2E PASSED (66/66)` |
| 12 secrets out of state | 9 | PASS | 2 versions of clinical-db + decoy, plain + base64: 0 hits in 3 states + audit log |
| teardown | 184 | PASS | 3 destroys, kind deleted, resource group deleted, vault purged; read back: group exists=false, app registrations=0, vault gone |
| **total** | **507** | **PASS** | |

What Entra and Key Vault answered (from the e2e lines):

- nightly-report's token (iss = the website, aud `api://AzureADTokenExchange`,
  600 s) → HTTP 200, a Key Vault token: `aud` = `cfa8b339-…` (the Azure Key
  Vault app id, a v2 token), `idtyp=app`, lifetime 3900 s (`expires_in` 3599).
- that token: GET clinical-db 200; GET clinical-other 403
  `Forbidden/ForbiddenByRbac`; PUT clinical-db 403; list 403.
- unapproved-job's token → 401 `AADSTS700213` (no matching subject);
  nightly-report's default-audience token → 401 `AADSTS700212` (no matching
  audience); other-team/nightly-report → 401 `AADSTS700213`.
- a real pod as unapproved-job naming the same SecretProviderClass: Pending,
  never started, FailedMount with `AADSTS700213`.

Earlier attempts the same night, not counted: run a91c4820 stopped in stage
5 (Colima's port forwarder did not forward the kind API port; fixed by
pinning the port to 127.0.0.1:16443 and forwarding it with a separate ssh
connection, `lab/k8s/README.md` section 5); run 167e6a1b passed 65 of 66
(the test expected the v1 `aud` URL; the tenant issues v2 tokens with the
app id) and its teardown timed out deleting `clinical-apps` (fixed: the
namespace now depends on the CSI driver release, so it is destroyed first).
Both earlier runs' teardowns deleted and purged everything (read back).

`run.log` holds Entra object ids of the throwaway apps (all deleted), the
tenant and subscription ids, and no secret value or token (searched: no
JWT-shaped string).
