# k8s/aks-mapping — the Entra Workload ID side of the same trust (plan-only)

**Never applied here, said up front.** This root is checked with `fmt`,
`validate` and a mocked `terraform test`, and nothing more. There is no AKS
cluster and no Entra app registration behind it. It exists so the mapping
from the lab's Vault role to **Microsoft Entra Workload ID** is real, typed,
tested code rather than a slide.

It is the Entra equivalent of the Vault role `nightly-report` built in
[`../identity`](../identity/README.md): one **federated identity credential
(FIC)** on an app registration that trusts the AKS cluster's projected
service-account tokens for exactly `clinical-apps/nightly-report`.

| Object | Terraform | Value |
|---|---|---|
| Federated identity credential | `azuread_application_federated_identity_credential.nightly_report` | issuer = `var.aks_oidc_issuer_url` (HTTPS, not an obviously private host); subject = `system:serviceaccount:clinical-apps:nightly-report`; audiences = `["api://AzureADTokenExchange"]`; on application `/applications/<var.application_object_id>` |
| Output `entra_trust` | | issuer + subject + audiences Entra will accept |
| Output `kubernetes_side` | | SA annotation `azure.workload.identity/client-id=<var.application_client_id>`, pod label `azure.workload.identity/use: "true"`, projected token audience |

Provider: `hashicorp/azuread ~> 3.10` (the lab's constraint), locked at
**3.10.0** for `linux_amd64` + `darwin_arm64`.

## Why it is never applied

Entra does not call the cluster. It validates the projected token on its
own: it reads `<issuer>/.well-known/openid-configuration`, follows `jwks_uri`,
and checks the token's signature with those keys. So the issuer must be a
public HTTPS URL. The kind cluster's issuer is
`https://kubernetes.default.svc.cluster.local`, which nothing outside the
cluster can resolve, so a FIC pointing at it would be accepted by Entra and
then fail every token exchange. The issuer variable rejects that (and
loopback, private or link-local IPv4 literals, `*.local`, `*.internal`,
plain HTTP). That is a denylist, not proof the issuer is public: a DNS name
that resolves to a private address still passes.

(It can be made to work with kind by publishing the cluster's discovery
document and JWKS on a public HTTPS host and setting the API server's
`--service-account-issuer` to it. That is a real technique, not done here.)

## Vault role ↔ Entra FIC

| Vault role `nightly-report` (built and tested in this lab) | Entra FIC (this root, plan-only) |
|---|---|
| `bound_service_account_names` + `bound_service_account_namespaces` = one SA in one namespace | `subject = system:serviceaccount:clinical-apps:nightly-report`, matched as an exact string |
| `audience = "vault"` | `audiences = ["api://AzureADTokenExchange"]` |
| Vault asks the API server (`TokenReview`) at every login: live. A projected token whose SA was deleted cannot log in any more (a Vault token already issued still lives out its ≤ 15 min TTL) | Entra checks the signature against the issuer's public JWKS: offline. A projected token stays exchangeable until its own `exp`, SA deleted or not (verify: current Entra behaviour) |
| `kubernetes_host` = the in-cluster API server | `issuer` = the cluster's public OIDC issuer URL |
| policy `nightly-report-read` (read on one path) | Key Vault RBAC: *Key Vault Secrets User* on the one secret, assigned to this app's service principal (not built here) |
| Vault token TTL 15 min | Entra access token; lifetime set by Entra, not per FIC (verify: about an hour) |
| Vault Agent renders the file; the app never holds a login-capable token | The workload identity webhook projects the Entra-audience token into the pod and sets `AZURE_*` env vars; or the Key Vault CSI driver does the exchange and mounts the secret as a file |

**Both trust namespace + name, not the SA's UID.** Vault's
`alias_name_source = serviceaccount_uid` keeps a recreated SA's Vault
*entity* separate, but `bound_service_account_names` still authorises by
name; the FIC does the same with `sub`. Deleting and recreating
`nightly-report` gets the same access on both.

## Decisions

| Decision | Why | Alternative not taken |
|---|---|---|
| App registration + `azuread_application_federated_identity_credential` | Same provider and resource the lab already uses for GitHub OIDC (`modules/pipeline-identity`) | User-assigned managed identity + `azurerm_federated_identity_credential`: the more common AKS carrier, and a managed identity cannot have a client secret at all. On an app registration, "no password credentials" must be reviewed separately: a FIC does not stop someone adding a secret to the same app |
| Subject and namespace are `locals`, not variables | They must equal what `../identity` binds; the test checks `../identity/main.tf` statically | Variables: one typo and the FIC trusts a different SA |
| No defaults on the three variables | There is no real cluster or app here; a plausible-looking default would read like one | Defaults: misleading |
| Issuer validated: HTTPS, and not loopback / private or link-local IPv4 / `kubernetes.default.svc` / `*.local` / `*.internal` | Entra must fetch the JWKS; a private issuer is a silent, permanent failure. A denylist only: a name resolving to a private address passes | No validation |
| Object id validated as a bare GUID | `main.tf` adds `/applications/`, so a resource id here is caught. A client id is not: it is a GUID too, and nothing offline can tell the two apart (against a real tenant the apply would fail: no application has that object id; verify) | Taking the resource id as input: one more string to get wrong |

## Offline checks

```bash
terraform -chdir=lab/terraform/k8s/aks-mapping init -backend=false
terraform -chdir=lab/terraform/k8s/aks-mapping validate
terraform -chdir=lab/terraform/k8s/aks-mapping test     # mocked azuread provider
```

`tests/aks_mapping.tftest.hcl` pins: subject exactly
`system:serviceaccount:clinical-apps:nightly-report`; exactly one audience,
`api://AzureADTokenExchange`; issuer HTTPS and passed through verbatim;
`application_id` in the `/applications/<object id>` form; the Kubernetes half
(SA annotation, pod label); `../identity` still binds
`clinical-apps/nightly-report`; plain-HTTP, kind, loopback and private-IP
issuers and a resource id where the object id belongs are rejected. The
placeholder GUIDs are one digit repeated, the only made-up GUIDs the
public-repo release gate accepts. The core assertions
were checked to fail against broken copies (namespace changed, audience
`vault`, a second audience, client id passed as `application_id`).

A real `terraform plan` would need an Entra sign-in from the environment
(`ARM_TENANT_ID` + OIDC from CI, like `envs/dev`). Nothing in this lab runs
one.

## Sources

- Resource schema: `terraform providers schema -json` for `hashicorp/azuread`
  3.10.0 (`application_id`, `audiences`, `display_name`, `issuer`, `subject`).
- Microsoft Learn: *Use Microsoft Entra Workload ID with AKS*;
  *Workload identity federation*; *Create an OIDC issuer for AKS*.
  verify: re-read before recording; the issuer URL shape and token lifetimes
  are Microsoft's to change.
