#!/usr/bin/env bash
# shellcheck disable=SC2034  # constants below are read by the scripts that source this file
# =============================================================================
# lab/k8s/ci/lib.sh - shared constants + helpers for ci/pipeline.sh and
# test/k8s-e2e.sh. Sourced, never executed.
#
# Portable on purpose: macOS ships bash 3.2 (no mapfile, no associative
# arrays, no ${x,,}), GitHub's ubuntu-latest has bash 5 + GNU coreutils. So:
# plain indexed arrays only, sha256 via whichever of sha256sum / shasum exists,
# no `sed -i`, no `grep -P`.
#
# Unlike lab/pam/lib.sh this does NOT cd: both scripts work from any cwd and
# use the absolute paths below.
# =============================================================================
set -euo pipefail
umask 077   # every temp file (token header, Entra / Key Vault responses) is 0600

K8S_CI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
K8S_DIR="$(cd "$K8S_CI_DIR/.." && pwd -P)"
LAB_DIR="$(cd "$K8S_DIR/.." && pwd -P)"
REPO_ROOT="$(cd "$LAB_DIR/.." && pwd -P)"

# --- names fixed by the lab contract (kind config, Terraform, manifests and
# the tests all agree on these; change them in one place = change them all) --
KIND_CLUSTER_NAME=contoso-k8s
KUBE_CONTEXT="kind-$KIND_CLUSTER_NAME"
# kind names the node container <cluster>-control-plane; the API-server audit
# log is read from inside it (docker exec), it is not exposed on the host.
CP_CONTAINER="$KIND_CLUSTER_NAME-control-plane"
AUDIT_LOG_IN_NODE=/var/log/kubernetes/audit/audit.log
APP_NS=clinical-apps
# The Secrets Store CSI Driver + Azure Key Vault provider (lab/terraform/k8s/platform).
CSI_NS=secrets-store
APP_DEPLOYMENT=nightly-report
# The one Key Vault secret the workload may read, the decoy in the same vault
# it must NOT read, the SecretProviderClass that serves it and where it lands.
SECRET_NAME=clinical-db
DECOY_SECRET=clinical-other
SPC_NAME=nightly-report-db
MOUNTED_FILE=/mnt/secrets-store/db
# Entra Workload ID: the audience the CSI driver requests, the Key Vault
# token scope, and the data-plane API version (Microsoft Learn, Key Vault
# REST API reference).
EXCHANGE_AUDIENCE=api://AzureADTokenExchange
KV_SCOPE=https://vault.azure.net/.default
KV_API_VERSION=7.5
# Throwaway Azure objects live here (one resource group per run, deleted at
# teardown). Same region as the lab (rg-identity-lab).
AZ_LOCATION=eastus2
# The ValidatingAdmissionPolicy (and its binding) the identity root installs:
# digest-pinned images, an image allowlist for the nightly-report identity,
# no automounted API token. The e2e test matches denials by this name.
VAP_NAME=clinical-apps-workload-identity
# Drift drill (pipeline stage 10; audit check in the e2e test): the kind admin
# adds this User to this Terraform-owned RoleBinding out of band, Terraform
# must notice (plan exit 2) and put it back (plan exit 0). "mallory" is a
# made-up name; nothing authenticates as it, the binding is the evidence.
DRIFT_RB=app-deployer--k8s-clinical-deployers
DRIFT_ADDR='kubernetes_role_binding_v1.human["app-deployer"]'
DRIFT_USER=mallory
# Paths owned by the other parts of this segment.
KIND_CONFIG_TEMPLATE="$K8S_DIR/kind/cluster.yaml"
AUDIT_POLICY="$K8S_DIR/kind/audit-policy.yaml"
MANIFESTS_DIR="$K8S_DIR/manifests"
NEGATIVE_POD="$MANIFESTS_DIR/negative/privileged-pod.yaml"
TF_K8S_DIR="$LAB_DIR/terraform/k8s"
TF_PLATFORM="$TF_K8S_DIR/platform"
TF_IDENTITY="$TF_K8S_DIR/identity"
# The Entra + Key Vault side: app registration, federated credential, and
# Key Vault Secrets User on the one secret. Applied as the lab operator in
# stage 4, destroyed at teardown.
TF_KEYVAULT_TRUST="$TF_K8S_DIR/keyvault-trust"
E2E_TEST="$K8S_DIR/test/k8s-e2e.sh"

# Run state, 0600, gitignored by ci/.gitignore: run.env (this run's id and
# the names of its throwaway Azure objects, so teardown can always find them,
# and a standalone e2e run on a kept cluster knows where to look) and
# seed.sha256 (the sha256 of the CURRENT clinical-db value; rewritten after
# the stage-9 rotation). Removed again by a full teardown.
STATE_DIR="$K8S_CI_DIR/.state"
RUN_ENV="$STATE_DIR/run.env"

# kubeconfig: kind, kubectl and the Terraform kubernetes/helm providers must
# all use the SAME file. $KUBECONFIG may be a colon-separated list; kind
# writes to the first entry, so that is the one we hand Terraform too.
KUBECONFIG_PATH="${KUBECONFIG:-$HOME/.kube/config}"
KUBECONFIG_PATH="${KUBECONFIG_PATH%%:*}"

# --- helpers ------------------------------------------------------------------
log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1${2:+ ($2)}"; }
indent() { sed 's/^/      /'; }

k() { kubectl --context "$KUBE_CONTEXT" "$@"; }

sha256_stdin() { # sha256_stdin < data -> lowercase hex digest only
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | cut -d' ' -f1
  else
    shasum -a 256 | cut -d' ' -f1   # macOS
  fi
}

sha256_file() { sha256_stdin < "$1"; }

cluster_exists() { kind get clusters 2>/dev/null | grep -qx "$KIND_CLUSTER_NAME"; }

# https_status METHOD URL OUT [HEADER_FILE] [BODY_FILE|-] [CONTENT_TYPE]
#   -> prints the HTTP status ("000" = no answer); body in OUT.
# Tokens travel in a 0600 header file (curl -H @file), bodies as a file or
# stdin (--data-binary @-): neither ever appears in curl's argument list,
# which any local user can read with `ps`.
https_status() {
  local method="$1" url="$2" out="$3" hdr="${4:-}" body="${5:-}" ctype="${6:-application/json}"
  local -a args
  args=(-sS --max-time 30 -o "$out" -w '%{http_code}' -X "$method")
  if [[ -n "$hdr" ]]; then args+=(-H "@$hdr"); fi
  if [[ -n "$body" ]]; then args+=(-H "Content-Type: $ctype" --data-binary "@$body"); fi
  curl "${args[@]}" "$url" 2>/dev/null || true
}

# load_run_env: this run's ids (RUN_ID, AZ_RG, AZ_STORAGE, KV_NAME, KV_ID,
# SA_ISSUER, AZ_TENANT_ID, WORKLOAD_CLIENT_ID) from $RUN_ENV. Identifiers
# only, never a secret.
load_run_env() {
  [[ -s "$RUN_ENV" ]] || return 1
  # shellcheck disable=SC1090  # written by azure.sh write_run_env
  . "$RUN_ENV"
}

# wait_until SECONDS CMD... : retry CMD every 2s until it succeeds or time runs out
wait_until() {
  local deadline=$((SECONDS + $1)); shift
  until "$@"; do
    [[ $SECONDS -lt $deadline ]] || return 1
    sleep 2
  done
}
