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
umask 077   # every temp file (token header, Vault responses) is 0600

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
VAULT_NS=vault
APP_DEPLOYMENT=nightly-report
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
# NodePort 30820 in the cluster -> 127.0.0.1:18200 on the host (kind
# extraPortMappings). Overridable so a human can point the test elsewhere.
VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:18200}"

# Paths owned by the other parts of this segment.
KIND_CONFIG_TEMPLATE="$K8S_DIR/kind/cluster.yaml"
AUDIT_POLICY="$K8S_DIR/kind/audit-policy.yaml"
MANIFESTS_DIR="$K8S_DIR/manifests"
NEGATIVE_POD="$MANIFESTS_DIR/negative/privileged-pod.yaml"
TF_K8S_DIR="$LAB_DIR/terraform/k8s"
TF_PLATFORM="$TF_K8S_DIR/platform"
TF_IDENTITY="$TF_K8S_DIR/identity"
# Plan-only: the Entra Workload ID equivalent of the Vault role (a federated
# identity credential). The pipeline runs fmt / validate / test on it and
# NEVER plans it against Azure or applies it (kind's OIDC issuer is not
# reachable from Entra, which must fetch the issuer's JWKS).
TF_AKS_MAPPING="$TF_K8S_DIR/aks-mapping"
E2E_TEST="$K8S_DIR/test/k8s-e2e.sh"

# Only used with KEEP_CLUSTER=1: the kept cluster's dev root token + the
# sha256 of the CURRENT clinical/data/db value (seed.sha256: rewritten after
# the stage-9 rotation), so a later run (or a standalone test run) can reuse
# the cluster.
# Gitignored by ci/.gitignore; removed again on the next full teardown.
STATE_DIR="$K8S_CI_DIR/.state"

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

# vault_http METHOD PATH OUT [HEADER_FILE] [BODY_FILE|-]
#   -> prints the HTTP status ("000" = Vault did not answer); body in OUT.
# The token travels in a 0600 header file (curl -H @file), the body as a file
# or stdin (--data-binary @-): neither ever appears in curl's argument list,
# which any local user can read with `ps`.
vault_http() {
  local method="$1" path="$2" out="$3" hdr="${4:-}" body="${5:-}"
  local -a args
  args=(-sS --max-time 20 -o "$out" -w '%{http_code}' -X "$method")
  if [[ -n "$hdr" ]]; then args+=(-H "@$hdr"); fi
  if [[ -n "$body" ]]; then args+=(-H 'Content-Type: application/json' --data-binary "@$body"); fi
  curl "${args[@]}" "$VAULT_ADDR/v1/$path" 2>/dev/null || true
}

vault_errors() { # vault_errors RESPONSE_FILE -> Vault's error strings (never secret), one line
  jq -r '(.errors // []) | join("; ")' "$1" 2>/dev/null || echo "(no JSON body)"
}

# wait_until SECONDS CMD... : retry CMD every 2s until it succeeds or time runs out
wait_until() {
  local deadline=$((SECONDS + $1)); shift
  until "$@"; do
    [[ $SECONDS -lt $deadline ]] || return 1
    sleep 2
  done
}
