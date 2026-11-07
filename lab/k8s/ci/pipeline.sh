#!/usr/bin/env bash
# shellcheck disable=SC2329  # stage functions are called indirectly (stage N FUNC) or from the EXIT trap
# =============================================================================
# lab/k8s/ci/pipeline.sh - the ONE script for the Kubernetes workload-identity
# segment. A human runs it on the lab Mac AS THE LAB OPERATOR:
#
#   lab/scripts/operator/op lab/k8s/ci/pipeline.sh
#
# The products are real: Azure Key Vault holds the secret, Microsoft Entra
# Workload ID trusts the cluster's service-account tokens, and the Secrets
# Store CSI Driver with the Azure provider mounts the value into the pod.
# Stand-ins (lab/docs/STAND-INS.md): the kind cluster replaces AKS; the
# impersonated k8s-clinical-* groups replace Entra groups. ADR 0027 replaced
# the earlier HashiCorp Vault stand-in.
#
#   [1/12]  preflight          tool versions; kind + kubectl on PATH must match
#                              the pinned version AND sha256 (else the pinned
#                              build is downloaded + verified); from stage 4 on,
#                              az must be the operator service principal
#   [2/12]  terraform static   fmt -check, init (lockfile read-only), validate,
#                              terraform test (mock providers, no cluster, no
#                              Azure) for platform, identity and keyvault-trust
#   [3/12]  checkov            terraform + kubernetes frameworks; every skip
#                              must carry an inline justification
#   [4/12]  azure (throwaway)  one resource group: a storage static website (the
#                              public issuer) and a Key Vault (RBAC) holding
#                              clinical-db (seeded here) + a decoy; then
#                              keyvault-trust: app registration, federated
#                              credential, Key Vault Secrets User on clinical-db
#   [5/12]  kind cluster       contoso-k8s, issuer = that website; the API
#                              server's discovery document + JWKS are copied
#                              there and read back anonymously
#   [6/12]  platform apply     namespaces + PSA labels; CSI driver + Azure provider
#   [7/12]  identity apply     SAs, SecretProviderClass, human RBAC,
#                              ValidatingAdmissionPolicy (read back live:
#                              binding exactly [Deny], pods + deployments)
#   [8/12]  deploy workload    kubectl apply lab/k8s/manifests + rollout status
#                              (the pod starts only if Entra and Key Vault said yes)
#   [9/12]  rotate secret      a NEW version in Key Vault; the driver must
#                              rewrite the file in the SAME pod, no restart
#   [10/12] drift              out-of-band RoleBinding edit as the kind admin
#                              -> terraform plan exit 2 -> apply -> exit 0
#   [11/12] e2e tests          lab/k8s/test/k8s-e2e.sh
#   [12/12] secrets out of     every version of clinical-db and the decoy:
#           state              0 hits in the three Terraform states + the audit log
#   teardown (EXIT trap)       terraform destroy x3, kind delete cluster, resource
#                              group deleted, vault purged, all read back as gone
#
# Secrets: a Key Vault value (the seed in stage 4, the rotated one in stage
# 9, the decoy) exists in a shell variable only for the moment it is sent
# (to az through a 0600 file); the test gets its SHA-256, not the value.
# Stage 12 reads every version back (as the operator) into a subshell's
# environment, only to COUNT them; it prints counts, never a value. No
# client secret exists anywhere: the workload signs in with its
# federated service-account token only. Terraform and diagnostic output pass
# through mask_out, which redacts anything shaped like a JWT.
#
# Usage:  lab/scripts/operator/op lab/k8s/ci/pipeline.sh          full run, all deleted at the end
#         KEEP_CLUSTER=1 lab/scripts/operator/op lab/k8s/ci/pipeline.sh
#                                                 keep the cluster AND the Azure objects
#         lab/scripts/operator/op lab/k8s/ci/pipeline.sh --teardown
#                                                 delete what a kept run left
#         STOP_AFTER=3 lab/k8s/ci/pipeline.sh     static checks only (no cluster,
#                                                 no Azure, no operator needed)
# Exit:   0 only if every stage that ran passed and none was cut short (and,
#         on a full run, teardown worked and read back clean).
# =============================================================================
# shellcheck source-path=SCRIPTDIR
# shellcheck source=lib.sh disable=SC1091  # followed with shellcheck -x
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
# shellcheck source=azure.sh disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/azure.sh"

NSTAGES=12
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
STOP_AFTER="${STOP_AFTER:-$NSTAGES}"
[[ "$STOP_AFTER" =~ ^([1-9]|1[0-2])$ ]] || die "STOP_AFTER must be 1-$NSTAGES"
TEARDOWN_ONLY=0
case "${1:-}" in
  -h|--help) awk '/^# ====/ { n++; next } n == 1' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
  --teardown) TEARDOWN_ONLY=1 ;;
  "") ;;
  *) die "usage: [KEEP_CLUSTER=1] lab/scripts/operator/op $0 [--teardown]" ;;
esac

# --- pinned tool versions -------------------------------------------------------
# Whatever kind / kubectl is on PATH is hashed and must match the sha256
# pinned HERE (not a .sha256 file fetched from the same server, which would
# only prove a download was not truncated). If it is missing, the wrong
# version or the wrong bytes (a preinstalled runner-image copy built
# differently, say), the pinned release build is downloaded, verified and put
# first on PATH. So CI, where ubuntu-latest preinstalls both tools, also runs
# hash-verified binaries.
# Values from the kind v0.33.0 release assets and dl.k8s.io v1.37.1, fetched
# 2026-10-19; the darwin-arm64 ones also match the binaries already installed
# on the lab Mac. Bump version + hashes together.
KIND_VERSION=v0.33.0
KUBECTL_VERSION=v1.37.1
TERRAFORM_VERSION=1.16.5   # CI installs it with hashicorp/setup-terraform
pinned_sha256() { # pinned_sha256 TOOL PLATFORM
  case "$1/$2" in
    kind/linux-amd64)     echo aee6151561422756b764a4ae28e7f44cda5af5a9eead3cc9985112b1de8d8e0d ;;
    kind/darwin-arm64)    echo 0c8c7dbe5e23594a198b786c4bc13dacc101fa6196b0cb0b23a1ca44e61f4b4f ;;
    kubectl/linux-amd64)  echo 65691ff77eb6fa44c908b77a1082c9f092c3b9733b5cefabec0d1104890e21a8 ;;
    kubectl/darwin-arm64) echo fd65982c97ddad3106754b69ffa196d0e543aa591930ae52aed1adfb92f8c77f ;;
    *) return 1 ;;
  esac
}

# --- run state ------------------------------------------------------------------
STAGE_NAMES=("" "preflight" "terraform fmt / validate / test" "checkov" "azure: vault, issuer, trust"
  "kind cluster + public issuer" "terraform apply platform" "terraform apply identity" "deploy workload"
  "rotate secret (no restart)" "drift: detect + heal" "e2e tests" "secrets out of state")
STAGE_RESULT=("" SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP SKIP)
STAGE_SECS=(0 0 0 0 0 0 0 0 0 0 0 0 0)
# One short line per stage for the summary table (the evidence a viewer of
# the run should take away), set by the stage itself when it passes.
STAGE_NOTE=("" "" "" "" "" "" "" "" "" "" "" "" "")
CURRENT_STAGE=0
STAGE_T0=0
TEARDOWN_RESULT=SKIP
TEARDOWN_SECS=0
# Set once THIS run has created or adopted the cluster. Teardown only ever
# deletes a cluster the run touched: a run that dies in preflight must not
# delete a cluster somebody kept with KEEP_CLUSTER=1.
CLUSTER_TOUCHED=0
# Set once THIS run has created Azure objects (or, with --teardown, adopted a
# kept run's). Teardown deletes only those.
AZURE_TOUCHED=0
WORK="$(mktemp -d "${TMPDIR:-/tmp}/k8s-pipeline.XXXXXX")"
SEED_SHA_FILE="$STATE_DIR/seed.sha256"

export TF_IN_AUTOMATION=1             # no "run terraform apply next" hints
export TF_INPUT=0
export TF_VAR_kube_context="$KUBE_CONTEXT"
export TF_VAR_kubeconfig_path="$KUBECONFIG_PATH"

on_ci() { [[ "${GITHUB_ACTIONS:-}" == true ]]; }

# mask_out: redact anything shaped like a JWT (header.payload.signature,
# base64url, the header always starts eyJ). Nothing we run should print a
# token; this catches the case where something does.
mask_out() { sed -E 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/<jwt redacted>/g'; }

tf() { terraform -chdir="$1" "${@:2}"; }

tf_has_state() { # tf_has_state DIR -> 0 if the local state lists any resource
  [[ -s "$1/terraform.tfstate" ]] && jq -e '(.resources // []) | length > 0' "$1/terraform.tfstate" >/dev/null 2>&1
}

discard_stale_state() {
  # Local state of an ephemeral cluster (contract: no backend). Once that
  # cluster is gone the state describes nothing that exists.
  local d
  for d in "$TF_PLATFORM" "$TF_IDENTITY"; do
    if [[ -e "$d/terraform.tfstate" || -e "$d/terraform.tfstate.backup" ]]; then
      rm -f "$d/terraform.tfstate" "$d/terraform.tfstate.backup" "$d/.terraform.tfstate.lock.info"
      log "discarded local Terraform state of a deleted cluster: ${d#"$REPO_ROOT"/}"
    fi
  done
}

new_secret_hex() { openssl rand -hex "$1"; }   # N random bytes -> 2N hex chars

# Assertions made by the pipeline itself (stages 9, 10, 12) print the same
# PASS / FAIL lines as the e2e test. A FAIL ends the stage (and the run).
stage_pass() { printf 'PASS  %s\n' "$*"; }
stage_fail() { printf 'FAIL  %s\n' "$*"; exit 1; }

# --- stages -------------------------------------------------------------------------
stage() { # stage N FUNC   (plain call, never in an if/||: set -e must stay live inside)
  local n="$1" fn="$2"
  [[ $n -le $STOP_AFTER ]] || return 0
  CURRENT_STAGE=$n
  STAGE_T0=$SECONDS
  STAGE_RESULT[n]=FAIL     # until FUNC returns: set -e exits the script mid-stage
  printf '\n==> [%d/%d] %s\n' "$n" "$NSTAGES" "${STAGE_NAMES[n]}"
  "$fn"
  STAGE_SECS[n]=$((SECONDS - STAGE_T0))
  STAGE_RESULT[n]=PASS
  CURRENT_STAGE=0
}

tool_version() { # tool_version kind|kubectl -> e.g. v0.33.0 ("" if missing)
  case "$1" in
    kind)    kind version 2>/dev/null | awk '{print $2}' || true ;;
    kubectl) kubectl version --client -o json 2>/dev/null | jq -r '.clientVersion.gitVersion // empty' || true ;;
  esac
}

tool_pinned() { # tool_pinned TOOL VERSION PLATFORM : the TOOL on PATH is VERSION and, if PLATFORM has a pin, has its sha256
  local tool="$1" ver="$2" plat="$3" path want got
  [[ "$(tool_version "$tool")" == "$ver" ]] || return 1
  path=$(command -v "$tool") || return 1
  if ! want=$(pinned_sha256 "$tool" "$plat"); then
    log "$tool $ver at $path: version OK, no sha256 pin for platform '${plat:-unknown}' (not hash-verified)"
    return 0
  fi
  got=$(sha256_file "$path")
  if [[ "$got" != "$want" ]]; then
    log "$tool $ver at $path: sha256 $got is not the pinned $want"
    return 1
  fi
  log "$tool $ver at $path: sha256 matches the pin"
}

install_pinned() { # install_pinned TOOL VERSION PLATFORM URL
  local tool="$1" ver="$2" plat="$3" url="$4" want got
  want=$(pinned_sha256 "$tool" "$plat") || die "no pinned sha256 for $tool on $plat - install $tool $ver yourself"
  mkdir -p "$WORK/bin"
  log "installing $tool $ver ($plat) from $url"
  curl -fsSL --retry 3 --max-time 120 -o "$WORK/bin/$tool.part" "$url"
  got=$(sha256_file "$WORK/bin/$tool.part")
  if [[ "$got" != "$want" ]]; then
    rm -f "$WORK/bin/$tool.part"
    die "$tool download sha256 mismatch: got $got, pinned $want"
  fi
  chmod 755 "$WORK/bin/$tool.part"
  mv "$WORK/bin/$tool.part" "$WORK/bin/$tool"
  log "$tool sha256 verified ($got)"
}

preflight() {
  # The lab Mac keeps kind/kubectl/terraform in ~/.local/bin, which
  # non-login shells may not have on PATH. Appended, so an explicit PATH wins.
  if [[ -d "$HOME/.local/bin" && ":$PATH:" != *":$HOME/.local/bin:"* ]]; then
    PATH="$PATH:$HOME/.local/bin"
  fi
  local t
  for t in docker terraform checkov jq curl openssl awk; do need "$t"; done
  docker info >/dev/null 2>&1 || die "docker daemon not reachable (macOS: colima start)"

  local plat=""
  case "$(uname -s)/$(uname -m)" in
    Linux/x86_64)  plat=linux-amd64 ;;
    Darwin/arm64)  plat=darwin-arm64 ;;
  esac
  if ! tool_pinned kind "$KIND_VERSION" "$plat"; then
    [[ -n "$plat" ]] || die "kind $KIND_VERSION missing and no pinned build for $(uname -s)/$(uname -m)"
    install_pinned kind "$KIND_VERSION" "$plat" \
      "https://github.com/kubernetes-sigs/kind/releases/download/$KIND_VERSION/kind-$plat"
  fi
  if ! tool_pinned kubectl "$KUBECTL_VERSION" "$plat"; then
    [[ -n "$plat" ]] || die "kubectl $KUBECTL_VERSION missing and no pinned build for $(uname -s)/$(uname -m)"
    install_pinned kubectl "$KUBECTL_VERSION" "$plat" \
      "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/${plat%-*}/${plat#*-}/kubectl"
  fi
  # The pinned copies go FIRST on PATH so they beat a different version, and
  # what PATH then resolves to is checked again (version AND hash).
  if [[ -d "$WORK/bin" ]]; then
    PATH="$WORK/bin:$PATH"
    tool_pinned kind "$KIND_VERSION" "$plat" || die "kind on PATH is not the pinned $KIND_VERSION after install"
    tool_pinned kubectl "$KUBECTL_VERSION" "$plat" || die "kubectl on PATH is not the pinned $KUBECTL_VERSION after install"
  fi
  export PATH
  local tfv
  tfv=$(terraform version -json | jq -r .terraform_version)
  [[ "$tfv" == "$TERRAFORM_VERSION" ]] || die "terraform $tfv found, $TERRAFORM_VERSION required (the lock files were generated with it)"

  log "bash      $BASH_VERSION"
  log "docker    $(docker version --format '{{.Server.Version}} ({{.Server.Os}}/{{.Server.Arch}})')"
  log "kind      $(tool_version kind)   ($(command -v kind))"
  log "kubectl   $(tool_version kubectl)   ($(command -v kubectl))"
  log "terraform $tfv"
  log "checkov   $(checkov --version 2>/dev/null)"
  log "jq        $(jq --version)"

  local f
  for f in "$KIND_CONFIG_TEMPLATE" "$AUDIT_POLICY" "$NEGATIVE_POD" "$E2E_TEST" \
           "$TF_PLATFORM/main.tf" "$TF_IDENTITY/main.tf" "$TF_IDENTITY/tests/identity.tftest.hcl" \
           "$TF_KEYVAULT_TRUST/.terraform.lock.hcl" "$TF_KEYVAULT_TRUST/tests/keyvault_trust.tftest.hcl"; do
    [[ -s "$f" ]] || die "missing ${f#"$REPO_ROOT"/}"
  done
  # Azure is needed from stage 4 on. A static-only run (STOP_AFTER<=3) needs
  # no operator and no cloud.
  if [[ $STOP_AFTER -ge 4 ]]; then
    az_preflight
    if [[ -s "$RUN_ENV" ]]; then
      die "a kept run's Azure objects are still recorded in ${RUN_ENV#"$REPO_ROOT"/}: delete them first (lab/scripts/operator/op $0 --teardown)"
    fi
  fi
  log "KEEP_CLUSTER=$KEEP_CLUSTER  kube context=$KUBE_CONTEXT  kubeconfig=$KUBECONFIG_PATH"
}

terraform_static() {
  log "terraform fmt -check -recursive lab/terraform/k8s"
  tf "$TF_K8S_DIR" fmt -check -recursive -diff
  local d
  for d in "$TF_PLATFORM" "$TF_IDENTITY" "$TF_KEYVAULT_TRUST"; do
    log "init + validate ${d#"$REPO_ROOT"/}"
    # -lockfile=readonly: the committed .terraform.lock.hcl (linux_amd64 +
    # darwin_arm64 hashes) is the supply-chain pin. Init fails instead of
    # quietly rewriting it if a provider would resolve to anything else.
    tf "$d" init -backend=false -input=false -lockfile=readonly -no-color | indent
    tf "$d" validate -no-color | indent
  done
  # identity's and keyvault-trust's tests are mandatory (preflight checks the
  # files exist); platform's run too. Mock providers: no cluster, no token,
  # no Azure credentials.
  local runs=0 n
  for d in "$TF_PLATFORM" "$TF_IDENTITY" "$TF_KEYVAULT_TRUST"; do
    if ls "$d"/tests/*.tftest.hcl >/dev/null 2>&1; then
      log "terraform test ${d#"$REPO_ROOT"/}"
      tf "$d" test -no-color | tee "$WORK/tftest.log" | indent
      # Terraform's own summary line: "Success! N passed, 0 failed."
      n=$(sed -n 's/^Success! \([0-9][0-9]*\) passed.*/\1/p' "$WORK/tftest.log")
      runs=$((runs + ${n:-0}))
    fi
  done
  STAGE_NOTE[2]="3 roots, $runs tftest runs passed"
}

checkov_skips_justified() {
  # Checkov honours `#checkov:skip=CKV_X_1:reason` comments (Terraform) and
  # `checkov.io/skipN: CKV_X_1=reason` annotations (Kubernetes), and the
  # reason is optional to Checkov. Not here: a skip without a reason fails.
  local all bad
  all=$(grep -rnIE --include='*.tf' --include='*.yaml' --include='*.yml' --exclude-dir=.terraform \
    'checkov:skip=|checkov\.io/skip' "$TF_K8S_DIR" "$MANIFESTS_DIR" || true)
  if [[ -z "$all" ]]; then
    log "inline Checkov skips: none"
    return 0
  fi
  log "inline Checkov skips (each must give a reason):"
  printf '%s\n' "${all//"$REPO_ROOT"\//}" | indent
  bad=$(printf '%s\n' "$all" | grep -vE \
    "checkov:skip=[A-Z0-9_]+:[[:space:]]*[^[:space:]]|checkov\\.io/skip[0-9]*:[[:space:]]*[\"']?[A-Z0-9_]+=[^[:space:]\"']" || true)
  if [[ -n "$bad" ]]; then
    printf '%s\n' "$bad" | indent
    die "Checkov skip(s) without a justification (above)"
  fi
}

run_checkov() {
  checkov_skips_justified
  local rc=0
  log "checkov --framework terraform  lab/terraform/k8s"
  # --skip-download: no calls to the Prisma Cloud API (no key, no network
  # dependency, same result on a laptop and on the runner).
  checkov -d "$TF_K8S_DIR" --framework terraform --quiet --compact --skip-download \
    | tee "$WORK/checkov-tf.log" || rc=1
  log "checkov --framework kubernetes lab/k8s/manifests (except negative/)"
  # negative/ holds the deliberately privileged pod the e2e test feeds to Pod
  # Security Admission. Scanning it could only report the violations it exists
  # to demonstrate, so it is skipped HERE, by path, and nowhere else.
  # (--skip-path is a regex on the file path; '/negative/' matches whether
  # Checkov reports it relative to -d or absolute - both verified.)
  checkov -d "$MANIFESTS_DIR" --framework kubernetes --skip-path '/negative/' \
    --quiet --compact --skip-download | tee "$WORK/checkov-k8s.log" || rc=1
  # Run both scans before failing, so one CI run shows every finding.
  [[ $rc -eq 0 ]] || die "Checkov reported failed checks (above)"
  local ptf pk8s
  ptf=$(sed -n 's/^Passed checks: \([0-9][0-9]*\), Failed checks: 0.*/\1/p' "$WORK/checkov-tf.log")
  pk8s=$(sed -n 's/^Passed checks: \([0-9][0-9]*\), Failed checks: 0.*/\1/p' "$WORK/checkov-k8s.log")
  STAGE_NOTE[3]="${ptf:-?} terraform + ${pk8s:-?} k8s passed, 0 failed"
}

KIND_CONFIG="$WORK/kind-cluster.yaml"
render_kind_config() { # template -> $KIND_CONFIG (a plain call, not $(...): set -e stays live)
  local out="$KIND_CONFIG"
  grep -q '__AUDIT_POLICY_PATH__' "$KIND_CONFIG_TEMPLATE" \
    || die "kind/cluster.yaml has no __AUDIT_POLICY_PATH__ placeholder"
  # sed replacement metacharacters in the path would corrupt the YAML.
  case "$AUDIT_POLICY" in *'|'*|*'&'*|*\\*) die "unsupported characters in $AUDIT_POLICY" ;; esac
  grep -q '__SA_ISSUER__' "$KIND_CONFIG_TEMPLATE" \
    || die "kind/cluster.yaml has no __SA_ISSUER__ placeholder"
  [[ "$SA_ISSUER" =~ ^https://[a-z0-9.]+$ ]] || die "unexpected issuer URL: $SA_ISSUER"
  sed -e "s|__AUDIT_POLICY_PATH__|$AUDIT_POLICY|g" -e "s|__SA_ISSUER__|$SA_ISSUER|g" "$KIND_CONFIG_TEMPLATE" > "$out"
  # Supply chain: the node image must be pinned by digest, not a moving tag.
  grep -qE 'image:[[:space:]]*kindest/node:v[0-9.]+@sha256:[0-9a-f]{64}' "$out" \
    || die "kind/cluster.yaml must pin the node image by digest"
}

port_in_use() { (: <"/dev/tcp/127.0.0.1/$1") 2>/dev/null; }

kind_cluster() {
  # Always a fresh cluster: its issuer is this run's website, and a cluster
  # from another run signs for another issuer.
  render_kind_config
  if cluster_exists; then
    log "deleting leftover cluster $KIND_CLUSTER_NAME (its issuer belongs to another run)"
    kind delete cluster --name "$KIND_CLUSTER_NAME" --kubeconfig "$KUBECONFIG_PATH"
  fi
  discard_stale_state
  CLUSTER_TOUCHED=1
  log "creating cluster $KIND_CLUSTER_NAME (issuer $SA_ISSUER, audit policy ${AUDIT_POLICY#"$REPO_ROOT"/})"
  kind create cluster --name "$KIND_CLUSTER_NAME" --config "$KIND_CONFIG" \
    --kubeconfig "$KUBECONFIG_PATH" --wait 180s
  k wait --for=condition=Ready node --all --timeout=180s
  k get nodes -o wide | indent
  publish_issuer
  STAGE_NOTE[5]="issuer published: discovery doc + JWKS"
}

platform_apply() {
  tf "$TF_PLATFORM" init -input=false -lockfile=readonly -no-color | indent
  tf "$TF_PLATFORM" apply -input=false -auto-approve -no-color 2>&1 | mask_out | sed '/^Outputs:$/,$d' | indent
  # Read back live: the CSIDriver object must request tokens for exactly the
  # Entra exchange audience, and both DaemonSets must be Ready.
  local aud
  aud=$(k get csidriver secrets-store.csi.k8s.io -o json | jq -c '[.spec.tokenRequests[]?.audience]')
  printf '      live: CSIDriver secrets-store.csi.k8s.io tokenRequests audiences=%s\n' "$aud"
  [[ "$aud" == "[\"$EXCHANGE_AUDIENCE\"]" ]] || stage_fail "CSIDriver tokenRequests $aud, exactly [\"$EXCHANGE_AUDIENCE\"] expected"
  k -n "$CSI_NS" get daemonsets -o wide | indent
  STAGE_NOTE[6]="CSI driver + Azure provider Ready; 1 token audience"
}

identity_apply() {
  tf "$TF_IDENTITY" init -input=false -lockfile=readonly -no-color | indent
  tf "$TF_IDENTITY" apply -input=false -auto-approve -no-color 2>&1 | mask_out | tee "$WORK/identity-apply.log" | sed '/^Outputs:$/,$d' | indent
  local n acts rules nval
  n=$(sed -n 's/^Apply complete! Resources: \([0-9][0-9]*\) added.*/\1/p' "$WORK/identity-apply.log")
  # The summary line is evidence, so it is read back from the API server, not
  # restated from the .tf: the binding must say exactly [Deny] and the policy
  # must match CREATE + UPDATE of pods and deployments (the e2e test then
  # proves the denials; this stops a weakened guardrail at the stage that
  # installed it).
  acts=$(k get validatingadmissionpolicybinding "$VAP_NAME" -o json | jq -c '.spec.validationActions')
  rules=$(k get validatingadmissionpolicy "$VAP_NAME" -o json | jq -r '
    def covers($g; $r): any(.spec.matchConstraints.resourceRules[]?;
      (.apiGroups | index($g)) and (.resources | index($r))
      and (.operations | index("CREATE") and index("UPDATE")));
    if covers(""; "pods") and covers("apps"; "deployments")
    then "\(.spec.validations | length) \([.spec.matchConstraints.resourceRules[].resources[]] | join(","))"
    else "" end')
  printf '      live: binding %s validationActions=%s\n' "$VAP_NAME" "$acts"
  printf '      live: policy matches CREATE+UPDATE of %s\n' "${rules#* }"
  [[ "$acts" == '["Deny"]' ]] || stage_fail "binding $VAP_NAME: validationActions $acts, exactly [\"Deny\"] expected"
  [[ -n "$rules" ]] || stage_fail "policy $VAP_NAME does not match CREATE+UPDATE of pods and deployments"
  nval="${rules%% *}"
  stage_pass "admission policy live: Deny, $nval rules, pods + deployments matched"
  STAGE_NOTE[7]="${n:-?} added; live VAP: [Deny], $nval rules"
}

DB_VERSION=""   # Key Vault version id of clinical-db this run last wrote

write_db_value() { # write_db_value WHAT : a NEW random value -> clinical-db (operator); its sha256 -> SEED_SHA_FILE
  # The value is NOT in Terraform (it would sit in state in plain text): it is
  # generated and written here, to Key Vault through az, and lives in this
  # function's variable only until it is sent and hashed.
  local value sha
  value=$(new_secret_hex 16)    # 32 chars, 128 bits
  kv_put_retry "$SECRET_NAME" value || die "$1 $SECRET_NAME failed: $(head -3 "$WORK/kv-put.err" 2>/dev/null)"
  sha=$(printf '%s' "$value" | sha256_stdin)
  value=""
  # Only now (the write succeeded) does the hash every later check compares
  # against change.
  mkdir -p "$STATE_DIR"
  printf '%s\n' "$sha" > "$SEED_SHA_FILE"
  DB_VERSION=$(sed 's|.*/||' "$WORK/kv-put.out")
  log "$1 $KV_NAME/$SECRET_NAME: version ${DB_VERSION:0:8}... (sha256 ${sha:0:12}..., value not printed)"
}

deploy_workload() {
  # The pod starts only after its CSI volume mounted, i.e. after Entra
  # accepted the federated token AND Key Vault RBAC allowed the read. A new
  # role assignment can take minutes to reach Key Vault (Azure RBAC
  # propagation), so the rollout gets 10 minutes; the kubelet retries the
  # mount on its own.
  local existed
  existed=$(k -n "$APP_NS" get deployment "$APP_DEPLOYMENT" --ignore-not-found -o name)
  if [[ -s "$MANIFESTS_DIR/kustomization.yaml" ]]; then
    k apply -k "$MANIFESTS_DIR"
  else
    # NOT -R: manifests/negative/ (the PSA-rejected pod) must never be applied.
    k apply -f "$MANIFESTS_DIR"
  fi
  if [[ -n "$existed" ]]; then
    # Kept cluster re-applied: a fresh pod, so the mount itself is exercised again.
    k -n "$APP_NS" rollout restart deployment "$APP_DEPLOYMENT"
  fi
  # Captured first: a failing `get` inside a for-list would not trip set -e,
  # and an empty list would skip rollout status and still "pass".
  local d deps
  deps=$(k -n "$APP_NS" get deployments -o name)
  [[ "$deps" == *"deployment.apps/$APP_DEPLOYMENT"* ]] \
    || die "deployment $APP_DEPLOYMENT not found in $APP_NS after apply (got: ${deps:-nothing})"
  for d in $deps; do
    k -n "$APP_NS" rollout status "$d" --timeout=600s
  done
  k -n "$APP_NS" get pods -o wide | indent
  STAGE_NOTE[8]="pod Ready after $((SECONDS - STAGE_T0))s (mount = Entra + Key Vault yes)"
}

# --- stage 9: rotation without a restart ---------------------------------------------
app_pod() { # newest Ready, not-terminating nightly-report pod -> stdout ("" if none)
  k -n "$APP_NS" get pods -l "app.kubernetes.io/name=$APP_DEPLOYMENT" -o json | jq -r '
    [.items[] | select(.metadata.deletionTimestamp == null)
              | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
    | sort_by(.metadata.creationTimestamp) | last | .metadata.name // empty'
}

pod_fingerprint() { # pod_fingerprint POD -> "UID name=restarts,..." over every container, init containers included
  k -n "$APP_NS" get pod "$1" -o json | jq -r '"\(.metadata.uid) \([(.status.initContainerStatuses // [])[], (.status.containerStatuses // [])[]
    | "\(.name)=\(.restartCount)"] | sort | join(","))"'
}

rendered_sha() { # rendered_sha POD -> sha256 of the mounted file, hashed INSIDE the app container
  # Same technique as the e2e test: the value never crosses kubectl, only its
  # hash does. tr drops a newline in case one is added; the value has none.
  k -n "$APP_NS" exec "$1" -c "$APP_DEPLOYMENT" -- \
    sh -c "tr -d '\\r\\n' < $MOUNTED_FILE | sha256sum" 2>/dev/null | awk '{print $1}' || true
}

ROT_POD=""
ROT_WANT=""
rendered_is_new() { [[ "$(rendered_sha "$ROT_POD")" == "$ROT_WANT" ]]; }

rotate_secret() {
  # Rotation WITHOUT a restart. The CSI driver runs with
  # --enable-secret-rotation and --rotation-poll-interval=10s
  # (lab/terraform/k8s/platform): it re-reads every mounted object on that
  # interval, with a fresh token for the pod's service account, and rewrites
  # the file. Proven here: a new version in Key Vault becomes the new file
  # content in the SAME pod (same UID) with no container restarted. Whether
  # the app re-reads the file is the app's business (this one reads it on
  # every loop); a connection pool would need its own reload.
  local pod before after old got t0 waited
  pod=$(app_pod)
  [[ -n "$pod" ]] || stage_fail "no Ready $APP_DEPLOYMENT pod to rotate under"
  before=$(pod_fingerprint "$pod")
  old=$(tr -d ' \r\n' < "$SEED_SHA_FILE")
  got=$(rendered_sha "$pod")
  [[ "$got" == "$old" ]] \
    || stage_fail "before rotation $pod should render the seeded value (in-pod sha256 ${got:0:12}..., seeded ${old:0:12}...)"
  stage_pass "before: $pod serves the seeded value (sha256 ${old:0:12}...)"

  write_db_value rotated
  ROT_POD="$pod"
  ROT_WANT=$(tr -d ' \r\n' < "$SEED_SHA_FILE")
  t0=$SECONDS
  wait_until 90 rendered_is_new \
    || stage_fail "the driver did not write the new value within 90s (see rotationPollInterval in lab/terraform/k8s/platform)"
  waited=$((SECONDS - t0))
  stage_pass "driver rewrote $MOUNTED_FILE in ~${waited}s (in-pod sha256 ${ROT_WANT:0:12}..., value not printed)"

  after=$(pod_fingerprint "$pod")
  [[ "$after" == "$before" && "$(app_pod)" == "$pod" ]] \
    || stage_fail "the pod changed: before [$before] after [$after], newest Ready pod now $(app_pod)"
  stage_pass "same pod, same uid ${after:0:8}..., still Ready, no container restarted"
  printf '      restart counts before = after: %s\n' "${after#* }"
  STAGE_NOTE[9]="new value live in ~${waited}s, same pod"
}

# --- stage 10: drift detection --------------------------------------------------------
mallory_can() { # mallory_can VERB RESOURCE -> "yes" / "no" for the drift user in clinical-apps
  k -n "$APP_NS" auth can-i "$1" "$2" --as="$DRIFT_USER" 2>/dev/null || true
}
# The API server's RBAC authorizer reads RoleBindings through an informer
# cache, so a binding change takes a moment to be enforced (more on a busy CI
# runner): wait for the expected answer instead of trusting the first one.
mallory_has_access() { [[ "$(mallory_can create deployments)" == yes ]]; }
mallory_lost_access() { [[ "$(mallory_can create deployments)" == no ]]; }

drift_detect_heal() {
  # Terraform owns the human RBAC. Somebody with cluster-admin (here the kind
  # admin, the same identity Terraform runs as) quietly adds a user to the
  # deployer RoleBinding: a change that never went through a PR. IaC is a
  # control, not just an installer, only if plan notices (exit 2, on exactly
  # that resource), applying the REVIEWED plan reverts it, and a fresh plan
  # is clean (exit 0). The audit-log record of both writes is checked by the
  # e2e test (section h). Same TF_VAR_* as stage 6, so the plan compares the
  # cluster against the configuration that was applied, nothing else.
  local admin rc changed removed patch
  admin=$(k auth whoami -o json | jq -r '.status.userInfo.username')
  [[ "$(mallory_can create deployments)" == no ]] || stage_fail "$DRIFT_USER has access before the drill"
  log "drift, out of band, as the kind admin ($admin):"
  log "  + subject User/$DRIFT_USER on rolebinding $DRIFT_RB"
  patch=$(jq -nc --arg u "$DRIFT_USER" \
    '[{op: "add", path: "/subjects/-", value: {kind: "User", apiGroup: "rbac.authorization.k8s.io", name: $u}}]')
  k -n "$APP_NS" patch rolebinding "$DRIFT_RB" --type=json -p "$patch" | indent
  wait_until 20 mallory_has_access || stage_fail "the injected subject did not take effect within 20s"
  log "$DRIFT_USER can now create deployments in $APP_NS: the drift is a real grant"

  rc=0
  tf "$TF_IDENTITY" plan -detailed-exitcode -input=false -no-color -out="$WORK/drift.tfplan" \
    > "$WORK/drift-plan.log" 2>&1 || rc=$?
  # The resource diff only: the "Refreshing state..." lines are noise on camera.
  { grep -v 'Refreshing state\.\.\.' "$WORK/drift-plan.log" || true; } | mask_out | indent
  [[ $rc -eq 2 ]] || stage_fail "terraform plan -detailed-exitcode returned $rc; 2 (changes present) expected"
  tf "$TF_IDENTITY" show -json "$WORK/drift.tfplan" > "$WORK/drift-plan.json"
  changed=$(jq -r '[.resource_changes[] | select(.change.actions != ["no-op"] and .change.actions != ["read"])
    | "\(.address) (\(.change.actions | join("+")))"] | join(", ")' "$WORK/drift-plan.json")
  removed=$(jq -r --arg a "$DRIFT_ADDR" '[.resource_changes[] | select(.address == $a)
    | ((.change.before.subject // []) | map("\(.kind)/\(.name)")) - ((.change.after.subject // []) | map("\(.kind)/\(.name)"))]
    | add // [] | join(",")' "$WORK/drift-plan.json")
  printf '\nDRIFT DETECTED  %s\n                apply removes: %s\n\n' "${changed:-nothing}" "${removed:-nothing}"
  [[ "$changed" == "$DRIFT_ADDR (update)" && "$removed" == "User/$DRIFT_USER" ]] \
    || stage_fail "expected exactly one change, $DRIFT_ADDR (update), removing User/$DRIFT_USER"
  stage_pass "terraform plan -detailed-exitcode = 2, on exactly the tampered resource"

  # Heal with the plan that was just reviewed, not a fresh one: what is
  # applied is exactly what was shown above. The root's outputs (printed in
  # full by stage 6) are cut here: on camera they would bury the PASS line.
  tf "$TF_IDENTITY" apply -input=false -no-color "$WORK/drift.tfplan" 2>&1 | mask_out \
    | sed '/^Outputs:$/,$d' | indent
  rc=0
  tf "$TF_IDENTITY" plan -detailed-exitcode -input=false -no-color > "$WORK/drift-plan.log" 2>&1 || rc=$?
  if [[ $rc -ne 0 ]]; then
    { grep -v 'Refreshing state\.\.\.' "$WORK/drift-plan.log" || true; } | mask_out | indent
    stage_fail "after the apply, terraform plan -detailed-exitcode returned $rc; 0 expected"
  fi
  wait_until 20 mallory_lost_access || stage_fail "$DRIFT_USER still has access 20s after the heal"
  stage_pass "drift healed: plan -detailed-exitcode = 0, $DRIFT_USER can no longer create deployments"
  STAGE_NOTE[10]="DRIFT DETECTED (plan 2) -> healed (0)"
}

# --- stage 11 -------------------------------------------------------------------------------
e2e_tests() {
  # The test runs as the WORKLOAD wherever it touches Entra or Key Vault: it
  # mints the workload's own service-account token and exchanges it itself,
  # so a passing test cannot be the operator quietly doing the work. It gets
  # the current value's SHA-256 (after stage 9's rotation), not the value,
  # and run.env (identifiers only).
  K8S_E2E_SEED_SHA256_FILE="$SEED_SHA_FILE" bash "$E2E_TEST" 2>&1 | mask_out | tee "$WORK/e2e.log"
  STAGE_NOTE[11]="$(sed -n 's/^K8S E2E PASSED (\(.*\))$/\1/p' "$WORK/e2e.log") assertions passed"
}

# --- stage 12: secrets out of state -----------------------------------------------------
count_needles() { # count_needles < HAYSTACK -> "c1 c2 ... cK": occurrences of $NEEDLE_1..$NEEDLE_K, K=$NEEDLE_COUNT
  # Needles come from the ENVIRONMENT (awk ENVIRON), never from an argument
  # list `ps` would show, and index() is a literal substring match (a value is
  # never read as a regex). Every needle is checked non-empty by the caller:
  # an empty one would match everywhere.
  awk 'BEGIN { k = ENVIRON["NEEDLE_COUNT"] + 0
               for (j = 1; j <= k; j++) { nd[j] = ENVIRON["NEEDLE_" j]; c[j] = 0 } }
       { for (j = 1; j <= k; j++) {
           s = $0
           while ((i = index(s, nd[j])) > 0) { c[j]++; s = substr(s, i + length(nd[j])) } } }
       END { for (j = 1; j <= k; j++) printf "%s%d", (j > 1 ? " " : ""), c[j]; printf "\n" }'
}

sum_hits() { # sum_hits FILE "I J ..." -> sum of the counts at 1-based positions I, J, ...
  local -a c
  local i s=0
  read -r -a c < "$1"
  for i in $2; do s=$((s + c[i - 1])); done
  echo "$s"
}

secrets_out_of_state() {
  # Where a secret must NOT be: Terraform state (plain JSON that every state
  # reader and backend admin can see; all three roots) and the API-server
  # audit log (the reason Secrets and tokens are logged at Metadata level
  # only). Searched for: every stored version of clinical-db (the seed AND
  # the rotated value) and the decoy, each plain and base64.
  # Positive control: the namespace name must be found in all four
  # haystacks, so an empty or unreadable haystack cannot "pass".
  # The values are read back from Key Vault as the operator into THIS
  # SUBSHELL's environment, for awk; only counts are printed. The subshell
  # keeps them out of the environment of everything that runs afterwards.
  local d
  for d in "$TF_PLATFORM" "$TF_IDENTITY" "$TF_KEYVAULT_TRUST"; do
    tf_has_state "$d" || stage_fail "no Terraform state in ${d#"$REPO_ROOT"/} to search"
  done
  (
    NEEDLE_COUNT=0
    add_needle() { # add_needle VALUE -> next NEEDLE_n (exported: export is a builtin, no argv)
      [[ -n "$1" ]] || die "refusing an empty needle"
      NEEDLE_COUNT=$((NEEDLE_COUNT + 1))
      export "NEEDLE_$NEEDLE_COUNT=$1" NEEDLE_COUNT
    }
    local id val kv_plain="" kv_b64="" dec_plain="" dec_b64="" nver=0 want current=0
    want=$(tr -d ' \r\n' < "$SEED_SHA_FILE")
    for id in $(kv_secret_versions "$SECRET_NAME"); do
      val=$(kv_secret_value "$id") || val=""
      [[ -n "$val" ]] || { log "$SECRET_NAME version ${id##*/}: no value (disabled?) - not searched"; continue; }
      if [[ "$(printf '%s' "$val" | sha256_stdin)" == "$want" ]]; then current=1; fi
      add_needle "$val"
      kv_plain="$kv_plain $NEEDLE_COUNT"
      add_needle "$(printf '%s' "$val" | base64 | tr -d '\n')"
      kv_b64="$kv_b64 $NEEDLE_COUNT"
      nver=$((nver + 1))
      val=""
    done
    [[ $nver -ge 2 ]] || die "expected at least 2 stored versions of $SECRET_NAME (seed + rotation), found $nver"
    [[ $current -eq 1 ]] || die "no stored version of $SECRET_NAME hashes to this run's current value"
    for id in $(kv_secret_versions "$DECOY_SECRET"); do
      val=$(kv_secret_value "$id") || val=""
      [[ -n "$val" ]] || continue
      add_needle "$val"; dec_plain="$dec_plain $NEEDLE_COUNT"
      add_needle "$(printf '%s' "$val" | base64 | tr -d '\n')"; dec_b64="$dec_b64 $NEEDLE_COUNT"
      val=""
    done
    [[ -n "$dec_plain" ]] || die "could not read $DECOY_SECRET back"
    add_needle "$APP_NS"

    local h
    for h in platform identity trust; do
      case $h in
        platform) d="$TF_PLATFORM" ;;
        identity) d="$TF_IDENTITY" ;;
        trust)    d="$TF_KEYVAULT_TRUST" ;;
      esac
      if ! tf "$d" state pull | count_needles > "$WORK/hits.$h"; then
        stage_fail "terraform state pull failed: ${d#"$REPO_ROOT"/}"
      fi
    done
    # audit.log plus any rotated backup (audit-<timestamp>.log) in the node.
    # shellcheck disable=SC2016  # $1 is expanded by the sh inside the node
    if ! docker exec "$CP_CONTAINER" sh -c 'cat "$1"/*.log' sh "${AUDIT_LOG_IN_NODE%/*}" \
         | count_needles > "$WORK/hits.audit"; then
      stage_fail "could not read the audit log in $CP_CONTAINER"
    fi

    local row v bad=0
    printf '      %-30s %10s %10s %10s %10s\n' "searched for (counts only)" "platform" "identity" "trust" "audit log"
    for row in "$SECRET_NAME, $nver versions|$kv_plain" "  same, base64|$kv_b64" \
               "$DECOY_SECRET (decoy)|$dec_plain" "  same, base64|$dec_b64"; do
      printf '      %-30s' "${row%%|*}"
      for h in platform identity trust audit; do
        v=$(sum_hits "$WORK/hits.$h" "${row#*|}")
        [[ $v -eq 0 ]] || bad=1
        printf ' %10s' "$v"
      done
      printf '\n'
    done
    printf '      %-30s' "control: \"$APP_NS\" (> 0)"
    for h in platform identity trust audit; do
      v=$(sum_hits "$WORK/hits.$h" "$NEEDLE_COUNT")
      [[ $v -gt 0 ]] || bad=2
      printf ' %10s' "$v"
    done
    printf '\n'
    [[ $bad -ne 2 ]] || stage_fail "a haystack is empty or unreadable (the control string was not found in it)"
    [[ $bad -eq 0 ]] || stage_fail "a secret was found in Terraform state or in the audit log (counts above)"
    stage_pass "$SECRET_NAME (all $nver versions) + decoy: 0 hits in 3 Terraform states + audit log"
    printf '%s' "0 secret hits: 3 states + audit log" > "$WORK/note.12"
  )
  STAGE_NOTE[12]=$(cat "$WORK/note.12")
}

# --- diagnostics + teardown (EXIT trap) --------------------------------------------
diagnostics() {
  # Safe to dump: nothing here holds a secret value. The provider's and the
  # driver's logs name objects and errors (an Entra AADSTS code, a Key Vault
  # 403), never a value; mask_out still redacts any JWT.
  printf '\n==> diagnostics (stage %s failed)\n' "$1"
  {
    k get nodes -o wide
    k get pods -A -o wide
    k -n "$APP_NS" get events --sort-by=.lastTimestamp | tail -40
    k -n "$CSI_NS" get events --sort-by=.lastTimestamp | tail -20
    local p
    for p in $(k -n "$APP_NS" get pods -o name); do
      k -n "$APP_NS" describe "$p"
    done
    k -n "$CSI_NS" logs -l app=csi-secrets-store-provider-azure --tail=40
    k -n "$CSI_NS" logs -l app=secrets-store-csi-driver -c secrets-store --tail=40
  } 2>&1 | mask_out | indent
}

tf_destroy() { # tf_destroy DIR -> 0 when there was nothing to destroy or destroy worked
  tf_has_state "$1" || return 0
  log "terraform destroy ${1#"$REPO_ROOT"/}"
  tf "$1" init -input=false -lockfile=readonly -no-color >/dev/null &&
    tf "$1" destroy -input=false -auto-approve -no-color 2>&1 | mask_out | indent
}

teardown() {
  if [[ "$KEEP_CLUSTER" == 1 && "$TEARDOWN_ONLY" != 1 ]]; then
    TEARDOWN_RESULT=KEPT
    if [[ "$CLUSTER_TOUCHED" == 1 || "$AZURE_TOUCHED" == 1 ]]; then
      log "KEEP_CLUSTER=1: cluster $KIND_CLUSTER_NAME and run ${RUN_ID:-?}'s Azure objects left in place. To poke around (from the repo root):"
      cat <<KEPT | indent
kubectl --context $KUBE_CONTEXT get pods -A
lab/scripts/operator/op lab/k8s/test/k8s-e2e.sh            # re-run only the tests
lab/scripts/operator/op lab/k8s/ci/pipeline.sh --teardown  # delete all of it (costs cents per day until then)
KEPT
    fi
    return 0
  fi
  local ok=0
  if [[ "$CLUSTER_TOUCHED" == 1 ]] && cluster_exists; then
    # Identity first: its SecretProviderClass needs the CRD platform installs.
    tf_destroy "$TF_IDENTITY" || ok=1
    tf_destroy "$TF_PLATFORM" || ok=1
    log "kind delete cluster $KIND_CLUSTER_NAME"
    kind delete cluster --name "$KIND_CLUSTER_NAME" --kubeconfig "$KUBECONFIG_PATH" 2>&1 | indent || ok=1
  fi
  if [[ "$CLUSTER_TOUCHED" == 1 ]]; then discard_stale_state; fi
  if [[ "$AZURE_TOUCHED" == 1 ]]; then
    azure_down || ok=1
  fi
  if [[ $ok -eq 0 ]]; then
    rm -f "$SEED_SHA_FILE"
    rmdir "$STATE_DIR" 2>/dev/null || true
    TEARDOWN_RESULT=PASS
  else
    TEARDOWN_RESULT=FAIL
  fi
}

summary_row() { printf '  %-40s %5s  %-6s %s\n' "$@"; }

summary() { # summary RC   (<= 100 columns: it is the last frame of a screen recording)
  local n total=0 overall=PASS
  printf '\n==> summary\n'
  summary_row "stage" "secs" "result" "evidence"
  for ((n = 1; n <= NSTAGES; n++)); do
    summary_row "[$n/$NSTAGES] ${STAGE_NAMES[n]}" "${STAGE_SECS[n]}" "${STAGE_RESULT[n]}" "${STAGE_NOTE[n]}"
    total=$((total + STAGE_SECS[n]))
  done
  summary_row "teardown" "$TEARDOWN_SECS" "$TEARDOWN_RESULT" ""
  total=$((total + TEARDOWN_SECS))
  [[ "$1" -eq 0 ]] || overall=FAIL
  summary_row "total" "$total" "$overall" ""
}

on_exit() {
  local rc=$?
  set +e
  trap - EXIT INT TERM
  if [[ $CURRENT_STAGE -ne 0 ]]; then
    STAGE_SECS[CURRENT_STAGE]=$((SECONDS - STAGE_T0))
    [[ $rc -ne 0 ]] || rc=1
    # Cluster-side evidence for a failed apply / rollout / test.
    if [[ $CURRENT_STAGE -ge 6 && "$CLUSTER_TOUCHED" == 1 ]]; then diagnostics "$CURRENT_STAGE"; fi
  fi
  local t0=$SECONDS
  printf '\n==> teardown\n'
  teardown
  TEARDOWN_SECS=$((SECONDS - t0))
  # A full, green run must also tear down cleanly (destroy is part of what the
  # IaC promises). After an earlier failure, teardown is best effort only.
  if [[ $rc -eq 0 && "$TEARDOWN_RESULT" == FAIL ]]; then rc=1; fi
  # Green means every stage up to STOP_AFTER (default: all of them) ran and
  # passed, whatever ended the script.
  local n
  for ((n = 1; n <= NSTAGES; n++)); do
    if [[ $n -le $STOP_AFTER && $rc -eq 0 && "${STAGE_RESULT[n]}" != PASS ]]; then rc=1; fi
  done
  summary "$rc"
  if [[ -d "$WORK" && "$WORK" == */k8s-pipeline.* ]]; then rm -rf "$WORK"; fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# --- run ------------------------------------------------------------------------------
if [[ "$TEARDOWN_ONLY" == 1 ]]; then
  # Delete what a KEEP_CLUSTER=1 run left: its cluster and its Azure objects.
  STOP_AFTER=0
  if [[ -d "$HOME/.local/bin" && ":$PATH:" != *":$HOME/.local/bin:"* ]]; then PATH="$PATH:$HOME/.local/bin"; fi
  need kind; need terraform; need jq
  az_preflight
  CLUSTER_TOUCHED=1
  if load_run_env; then
    AZURE_TOUCHED=1
    identity_vars
  fi
  exit 0   # the EXIT trap tears down and prints the summary
fi
stage 1 preflight
stage 2 terraform_static
stage 3 run_checkov
stage 4 azure_up
stage 5 kind_cluster
stage 6 platform_apply
stage 7 identity_apply
stage 8 deploy_workload
stage 9 rotate_secret
stage 10 drift_detect_heal     # before the tests: the e2e audit check looks for this drill
stage 11 e2e_tests
stage 12 secrets_out_of_state  # last: the audit log then holds everything the run did
