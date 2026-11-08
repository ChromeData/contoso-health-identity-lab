#!/usr/bin/env bash
# shellcheck disable=SC2329  # assertion helpers are called indirectly, through check / expect_*
# =============================================================================
# lab/k8s/test/k8s-e2e.sh - prove the Kubernetes workload-identity segment on
# the running contoso-k8s kind cluster (stage 11 of lab/k8s/ci/pipeline.sh,
# after the rotation drill in stage 9 and the drift drill in stage 10).
#
#   a. platform     node, CSI driver + Azure provider Ready, the CSIDriver
#                   requests tokens for exactly api://AzureADTokenExchange,
#                   Pod Security labels on both namespaces, the public
#                   issuer serves the API server's own discovery doc + JWKS
#   b. workload     nightly-report Ready and NOTHING injected; the mounted
#                   /mnt/secrets-store/db hashes to the CURRENT value (hashed
#                   inside the pod); the pod holds no token of any kind; the
#                   Deployment carries no env value / Secret reference; the
#                   SecretProviderClass syncs nothing into a Secret
#   c. Entra +      a TokenRequest for nightly-report (aud AzureADTokenExchange,
#      Key Vault    10 min) is exchanged by Entra for a Key Vault token of
#                   this app only; it reads clinical-db (sha256 = current), and
#                   Key Vault refuses it the decoy in the SAME vault, a write
#                   and a list (403, RBAC); Entra refuses unapproved-job's
#                   token and nightly-report's default-audience token; the
#                   API server refuses the exchange-audience token (401)
#                   while accepting a default-audience one
#   d. binding      identity is namespace + name, not a name: a service
#                   account called nightly-report in another namespace
#                   (other-team, a fixture created and deleted here) is
#                   refused by Entra; a token dies with its service account
#                   at the API server (deleted and recreated -> 401); a REAL
#                   pod running as unapproved-job that names the same
#                   SecretProviderClass never gets the file (Entra refuses
#                   the driver's token for it)
#   e. no static    the value is in no Secret / ConfigMap / Deployment /
#      secret       ReplicaSet / Pod in clinical-apps (plain, base64, decoded);
#                   no legacy service-account token Secrets; both service
#                   accounts opt out of token automount
#   f. RBAC         the can-i matrix (4 identities x 7 permissions, every cell
#                   enforced), then impersonated Kubernetes groups (on AKS:
#                   Entra group object IDs): deployers ship Deployments but
#                   cannot write pods or ReplicaSets, read Secrets, touch
#                   kube-system, mint the workload's token, grant RBAC, or
#                   exec / attach / port-forward / debug into pods; auditors
#                   read but cannot read Secrets or delete; no
#                   ClusterRoleBinding for either group
#   g. admission    the ValidatingAdmissionPolicy denies (server-side dry
#                   runs, nothing persisted), each with a positive control:
#                   nightly-report with any image but the approved digest
#                   (even for the pipeline identity), a tag-only image, an
#                   automounted API token; and the deployer borrowing or
#                   hijacking the identity four ways - a new Deployment as
#                   nightly-report, re-pointing its image, keeping the image
#                   but swapping the command, moving it to another service
#                   account in the same patch. PSA still rejects the
#                   privileged pod in manifests/negative/
#   h. audit        the API-server audit log (inside the kind node) holds the
#                   deployer's FORBIDDEN Secret read; Secret / TokenRequest /
#                   TokenReview events carry no body; the drift drill's
#                   RoleBinding patch (+ User mallory, by the kind admin, with
#                   bodies) and Terraform's revert; the VAP's write
#
# Never as the operator for Entra or Key Vault: the script uses no az and no
# operator credential. Every Entra and Key Vault assertion uses the token the
# WORKLOAD gets by exchanging its own service-account token. (Kubernetes
# fixtures and server-side dry runs use the kind admin's kubeconfig, as a
# cluster operator would; RBAC assertions impersonate the identity under
# test.)
#
# The secret value is never printed. Its hash is compared inside the pod; the
# copy read back over the workload's own Key Vault token (to search the
# namespace's objects for it) only lives in a shell variable. JWTs and access
# tokens travel in 0600 files / stdin, never on a command line, and command
# output echoed as evidence passes through redact first.
#
# Negative checks cannot pass by accident: a "denied" must be the server's
# own Forbidden / 403 / 400 naming the reason (an Entra AADSTS code, Key
# Vault's ForbiddenByRbac), not a connection error. Each block also has a
# positive control (the same exchange works for nightly-report; the same
# group CAN do its allowed action) run against the same cluster first.
#
# Usage: lab/k8s/test/k8s-e2e.sh
#   K8S_E2E_SEED_SHA256_FILE  sha256 of the CURRENT clinical-db value (set by
#                             pipeline.sh, which rewrites it after the stage-9
#                             rotation; default lab/k8s/ci/.state/seed.sha256)
#   lab/k8s/ci/.state/run.env this run's tenant, client id and vault name
#                             (identifiers only; written by pipeline stage 4)
#   Run standalone on a kept cluster (KEEP_CLUSTER=1), section (h) expects
#   the audit trail of the pipeline's drift drill (stage 10) from that run.
# Prints PASS/FAIL per assertion; last line "K8S E2E PASSED (n/n)", else exit 1.
# =============================================================================
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../ci/lib.sh disable=SC1091  # followed with shellcheck -x
source "$(dirname "${BASH_SOURCE[0]}")/../ci/lib.sh"
need kubectl; need jq; need curl; need docker; need base64

load_run_env || die "no $RUN_ENV - run lab/k8s/ci/pipeline.sh (KEEP_CLUSTER=1 keeps a cluster you can re-test)"
[[ -n "${WORKLOAD_CLIENT_ID:-}" && -n "${AZ_TENANT_ID:-}" && -n "${KV_NAME:-}" && -n "${SA_ISSUER:-}" ]] \
  || die "$RUN_ENV is incomplete (stage 4 did not finish)"
KV_URL="https://$KV_NAME.vault.azure.net"

SEED_FILE="${K8S_E2E_SEED_SHA256_FILE:-$STATE_DIR/seed.sha256}"
[[ -s "$SEED_FILE" ]] || die "no seed hash at $SEED_FILE - run lab/k8s/ci/pipeline.sh (KEEP_CLUSTER=1 keeps a cluster you can re-test)"
SEED_SHA=$(tr -d ' \r\n' < "$SEED_FILE")
[[ "$SEED_SHA" =~ ^[0-9a-f]{64}$ ]] || die "$SEED_FILE does not hold a sha256"

T=$(mktemp -d "${TMPDIR:-/tmp}/k8s-e2e.XXXXXX")
DB_VALUE=""
JWT_OLD=""
THIEF_EVENT=""
# Section (d)'s fixture namespace. Created and deleted by this script; the
# EXIT trap removes it too if the script dies in between.
OTHER_NS=other-team
OTHER_NS_CREATED=0
cleanup() {
  DB_VALUE=""; JWT_OLD=""
  k -n "$APP_NS" delete pod e2e-spc-borrow --ignore-not-found --wait=false >/dev/null 2>&1 || true
  if [[ "$OTHER_NS_CREATED" == 1 ]]; then
    k delete namespace "$OTHER_NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  fi
  if [[ -d "$T" && "$T" == */k8s-e2e.* ]]; then rm -rf "$T"; fi
}
trap cleanup EXIT

# Impersonated humans. On this cluster they are plain strings sent with
# --as/--as-group (the kind admin may impersonate); on AKS with Entra ID
# integration the group would be the Entra group's object ID, carried in the
# user's Entra token. Test identities, not lab personas.
DEPLOYER=(--as=e2e-deployer@contosohealth.io --as-group=k8s-clinical-deployers)
AUDITOR=(--as=e2e-auditor@contosohealth.io --as-group=k8s-clinical-auditors)
# A Secret name nobody uses: the deployer's forbidden GET of it is the needle
# the audit-log check looks for. Authorization runs before lookup, so the
# answer is 403 Forbidden, never 404.
PROBE_SECRET="e2e-audit-probe-$(date -u +%H%M%S)-$RANDOM"
# The image the admission tests try to run as nightly-report: digest-pinned
# (so ONLY the identity allowlist can object to it) and deliberately not
# real. ".invalid" is a reserved TLD (RFC 2606) and the digest is the sha256
# of a label, not of any image; it is only ever used in server-side dry runs,
# so nothing tries to pull it.
OTHER_IMAGE="registry.invalid/contoso-e2e/not-approved@sha256:$(printf 'contoso-e2e-not-approved' | sha256_stdin)"

PASSES=0
FAILS=0
LAST_OUT=""
pass()  { printf 'PASS  %s\n' "$*"; PASSES=$((PASSES + 1)); }
fail()  { printf 'FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }
# No redirections on a `check` line: they would apply to check itself and
# swallow its PASS/FAIL line. Put them inside a helper function instead.
check() { local d="$1"; shift; if "$@"; then pass "$d"; else fail "$d"; fi; }
abort() { fail "$*"; printf '\nK8S E2E ABORTED (%d failure(s))\n' "$FAILS"; exit 1; }
step()  { printf '\n'; log "== $*"; }
info()  { printf '%s\n' "$*" | indent; }   # evidence lines - never a secret
# Belt and braces for echoed command output: JWTs (header.payload.signature,
# base64url, the header always starts eyJ) - service-account tokens and
# Entra access tokens alike.
redact() {
  sed -E -e 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/<jwt redacted>/g'
}

expect_ok() { # expect_ok DESC CMD... : must exit 0
  local d="$1" rc=0; shift
  LAST_OUT=$("$@" 2>&1) || rc=$?
  printf '%s\n' "$LAST_OUT" | redact | indent
  if [[ $rc -eq 0 ]]; then pass "$d"; else fail "$d (exit $rc)"; fi
}

expect_forbidden() { # expect_forbidden DESC PATTERN CMD... : non-zero exit AND the API server's "forbidden" naming PATTERN
  local d="$1" pat="$2" rc=0; shift 2
  LAST_OUT=$("$@" 2>&1) || rc=$?
  printf '%s\n' "$LAST_OUT" | redact | indent
  if [[ $rc -ne 0 ]] && grep -qi 'forbidden' <<<"$LAST_OUT" && grep -qF -- "$pat" <<<"$LAST_OUT"; then
    pass "$d"
  else
    fail "$d (exit $rc)"
  fi
}

expect_vap_denied() { # expect_vap_denied DESC RULE_ERE CMD... : non-zero exit AND the VAP's own denial AND its message matches RULE_ERE
  # A ValidatingAdmissionPolicy denial reads "ValidatingAdmissionPolicy
  # '<policy>' with binding '<binding>' denied request: <message>" (reason
  # Invalid / HTTP 422 unless the validation sets another reason, so it need
  # not say "forbidden"). The API server reports only the FIRST failing
  # validation (in list order), so RULE_ERE (case-insensitive) checks that
  # the rule under test is the first one each fixture breaks. Most break
  # only that rule; the deployer's image swap breaks rule 2 AND rule 4 (it
  # is reported as rule 2), which is why rule 4 has fixtures of its own.
  local d="$1" pat="$2" rc=0; shift 2
  LAST_OUT=$("$@" 2>&1) || rc=$?
  printf '%s\n' "$LAST_OUT" | redact | indent
  if [[ $rc -ne 0 ]] && grep -qF "ValidatingAdmissionPolicy '$VAP_NAME'" <<<"$LAST_OUT" \
     && grep -qF 'denied request' <<<"$LAST_OUT" && grep -qiE -- "$pat" <<<"$LAST_OUT"; then
    pass "$d"
  else
    fail "$d (exit $rc)"
  fi
}

cannot() { # cannot VERB RESOURCE [--subresource=X] IMPERSONATION... : `kubectl auth can-i` answers exactly "no"
  local out rc=0 what="$1 $2"
  if [[ "${3:-}" == --subresource=* ]]; then what="$what/${3#--subresource=}"; fi
  out=$(k -n "$APP_NS" auth can-i "$1" "$2" "${@:3}" 2>&1) || rc=$?
  info "can-i $what -> $out"
  [[ $rc -ne 0 && "$out" == no* ]]
}

no_shell_into_pods() { # no_shell_into_pods IMPERSONATION... : every way INTO a running pod's processes is "no"
  # --subresource, not "pods/exec": kubectl reads "pods/exec" as the pod NAMED
  # exec and would answer for plain "create pods".
  local vs ok=0
  for vs in create:exec create:attach create:portforward update:ephemeralcontainers patch:ephemeralcontainers; do
    cannot "${vs%%:*}" pods --subresource="${vs#*:}" "$@" || ok=1
  done
  return "$ok"
}

nodes_ready() { k wait --for=condition=Ready node --all --timeout=60s >/dev/null 2>&1; }

pods_ready() { # pods_ready NAMESPACE SELECTOR : at least one pod, all Ready
  k -n "$1" wait --for=condition=Ready pod -l "$2" --timeout=90s >/dev/null 2>&1
}

# --- workload helpers ----------------------------------------------------------------
find_pod() { # newest Ready, not-terminating nightly-report pod -> $POD
  POD=$(k -n "$APP_NS" get pods -l "$APP_SELECTOR" -o json 2>/dev/null | jq -r '
    [.items[] | select(.metadata.deletionTimestamp == null)
              | select(any(.status.conditions[]?; .type == "Ready" and .status == "True"))]
    | sort_by(.metadata.creationTimestamp) | last | .metadata.name // empty') || POD=""
  [[ -n "$POD" ]]
}

pod_exec() { k -n "$APP_NS" exec "$POD" -c "$WORKLOAD_CTR" -- "$@"; }

nothing_injected() {
  # The CSI driver adds no container: the pod runs exactly what the
  # Deployment declares (one app container, no init containers).
  local cs ics
  cs=$(jq -r '[.spec.containers[].name] | join(",")' "$T/pod.json")
  ics=$(jq -r '[.spec.initContainers[]?.name] | join(",")' "$T/pod.json")
  info "pod $POD containers=[$cs] initContainers=[${ics}]"
  [[ "$cs" == "$WORKLOAD_CTR" && -z "$ics" ]]
}

csi_volume_mounted() {
  jq -e --arg spc "$SPC_NAME" '[.spec.volumes[]? | select(.csi.driver == "secrets-store.csi.k8s.io"
      and .csi.volumeAttributes.secretProviderClass == $spc)] | length == 1' "$T/pod.json" >/dev/null
}

rendered_file_matches() {
  # Hashed INSIDE the app container: the value never crosses kubectl.
  local got
  got=$(pod_exec sh -c "test -s $MOUNTED_FILE && tr -d '\\r\\n' < $MOUNTED_FILE | sha256sum" 2>/dev/null | awk '{print $1}') || return 1
  info "in-pod sha256 ${got:0:12}...  current ${SEED_SHA:0:12}...  (value not printed)"
  [[ -n "$got" && "$got" == "$SEED_SHA" ]]
}

app_has_no_kube_token() {
  jq -e '.spec.automountServiceAccountToken == false' "$T/pod.json" >/dev/null || return 1
  # The exec must WORK and find nothing: a failed exec is a non-zero exit too,
  # but then `test` never ran, so the check fails rather than passes.
  pod_exec sh -c 'test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token && echo absent' 2>/dev/null | grep -qx absent
}

pod_holds_no_token() {
  # No projected service-account token volume at all: the CSI driver gets
  # the pod's token from the kubelet and hands it only to the provider.
  local n
  n=$(jq '[.spec.volumes[]? | .projected.sources[]?.serviceAccountToken | select(. != null)] | length' "$T/pod.json")
  info "projected serviceAccountToken volumes in the pod spec: $n"
  [[ "$n" == 0 ]]
}

spc_syncs_nothing() {
  local spc
  spc=$(k -n "$APP_NS" get secretproviderclass "$SPC_NAME" -o json) || return 1
  info "SecretProviderClass $SPC_NAME: provider=$(jq -r '.spec.provider' <<<"$spc") usePodIdentity=$(jq -r '.spec.parameters.usePodIdentity' <<<"$spc") clientID=$(jq -r '.spec.parameters.clientID[0:8]' <<<"$spc")... secretObjects=$(jq '.spec.secretObjects // [] | length' <<<"$spc")"
  jq -e --arg c "$WORKLOAD_CLIENT_ID" '(.spec.secretObjects // [] | length) == 0 and .spec.parameters.usePodIdentity == "false"
    and .spec.parameters.clientID == $c' <<<"$spc" >/dev/null
}

deployment_has_no_static_secret() {
  jq -e '.spec.template.spec as $s
    | ($s.containers + ($s.initContainers // [])) as $all
    | ([$all[] | (.env // [])[] | select(has("value") or (.valueFrom.secretKeyRef != null))] | length == 0)
      and ([$all[] | (.envFrom // [])[] | select(.secretRef != null)] | length == 0)
      and ([($s.volumes // [])[] | select(.secret != null or ([.projected.sources[]? | select(.secret != null)] | length > 0))] | length == 0)
      and ($s.automountServiceAccountToken == false)' "$T/deploy.json" >/dev/null
}

# --- Entra + Key Vault helpers -----------------------------------------------------------
mint_token_ns() { # mint_token_ns NAMESPACE SA [AUDIENCE] -> JWT on stdout (captured, never printed)
  if [[ -n "${3:-}" ]]; then
    k -n "$1" create token "$2" --audience "$3" --duration 10m
  else
    k -n "$1" create token "$2" --duration 10m   # the API server's default audience
  fi
}

mint_token() { mint_token_ns "$APP_NS" "$@"; }   # mint_token SA [AUDIENCE], in clinical-apps

jwt_claims() { # printf '%s' JWT | jwt_claims -> payload JSON (base64url; checking the signature is Entra's job)
  jq -R 'split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | . + ("=" * ((4 - length % 4) % 4)) | @base64d | fromjson'
}

entra_exchange() { # entra_exchange JWT -> EX_CODE; body in $T/ex.json; on success the bearer header in $T/kv.hdr
  # OAuth 2.0 client credentials with a federated client assertion (Microsoft
  # Learn, "Microsoft identity platform and the OAuth 2.0 client credentials
  # flow", third case: federated credential). The body goes on stdin: the JWT
  # is never an argument. client_id is the app's id, not a secret.
  rm -f "$T/kv.hdr"
  EX_CODE=$(printf 'grant_type=client_credentials&client_id=%s&scope=%s&client_assertion_type=%s&client_assertion=%s' \
      "$WORKLOAD_CLIENT_ID" "https%3A%2F%2Fvault.azure.net%2F.default" \
      "urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer" "$1" \
    | https_status POST "https://login.microsoftonline.com/$AZ_TENANT_ID/oauth2/v2.0/token" "$T/ex.json" "" - \
        application/x-www-form-urlencoded)
  local at
  at=$(jq -r '.access_token // empty' "$T/ex.json" 2>/dev/null || true)
  if [[ -n "$at" ]]; then
    printf 'Authorization: Bearer %s\n' "$at" > "$T/kv.hdr"
    printf '%s' "$at" | jwt_claims > "$T/at-claims.json" 2>/dev/null || true
  fi
  at=""
  jq 'del(.access_token)' "$T/ex.json" > "$T/ex.safe.json" 2>/dev/null || true
  rm -f "$T/ex.json"
}

entra_error() { # -> the AADSTS code and the first words of Entra's error (never secret)
  jq -r '"\(.error // "?") \((.error_description // "") | capture("(?<c>AADSTS[0-9]+)").c // "") \((.error_description // "") | split("\r\n")[0] | .[0:110])"' \
    "$T/ex.safe.json" 2>/dev/null || echo "(no JSON body)"
}

claims_ok() {
  local c
  c=$(printf '%s' "$JWT_EX" | jwt_claims) || return 1
  info "$(jq -r '"iss=\(.iss) aud=\(.aud | join(",")) sub=\(.sub) lifetime=\(.exp - .iat)s"' <<<"$c")"
  jq -e --arg iss "$SA_ISSUER" --arg aud "$EXCHANGE_AUDIENCE" \
    '.iss == $iss and .aud == [$aud] and .sub == "system:serviceaccount:clinical-apps:nightly-report" and (.exp - .iat) <= 600' <<<"$c" >/dev/null
}

exchange_ok() {
  entra_exchange "$JWT_EX"
  if [[ "$EX_CODE" != 200 || ! -s "$T/kv.hdr" ]]; then
    info "Entra: HTTP $EX_CODE $(entra_error)"
    return 1
  fi
  info "Entra: HTTP 200, token_type=$(jq -r '.token_type' "$T/ex.safe.json"), expires_in=$(jq -r '.expires_in' "$T/ex.safe.json")s"
}

access_token_scoped() {
  # The claims of the Entra access token (its payload only; the token itself
  # is never printed): for Key Vault, issued to THIS app, in THIS tenant.
  [[ -s "$T/at-claims.json" ]] || return 1
  info "$(jq -r '"aud=\(.aud) appid=\(.appid // .azp | .[0:8])... tid=\(.tid | .[0:8])... idtyp=\(.idtyp // "?") lifetime=\(.exp - .iat)s"' "$T/at-claims.json")"
  # aud: a v1 token names Key Vault by URL; a v2 token (what the lab tenant
  # issued in the first live run, 2026-11-07) by the application id of
  # Microsoft's "Azure Key Vault" first-party app, cfa8b339-82a2-471a-a3c9-0fc0be7a4093.
  jq -e --arg c "$WORKLOAD_CLIENT_ID" --arg t "$AZ_TENANT_ID" \
    '(.aud == "https://vault.azure.net" or .aud == "https://vault.azure.net/" or .aud == "cfa8b339-82a2-471a-a3c9-0fc0be7a4093")
     and ((.appid // .azp) == $c) and .tid == $t and (.exp - .iat) > 0' \
    "$T/at-claims.json" >/dev/null
}

kv() { # kv METHOD PATH [BODY_FILE|-] -> HTTP status, as the WORKLOAD's Key Vault token; body in $T/kv.json
  https_status "$1" "$KV_URL/$2?api-version=$KV_API_VERSION" "$T/kv.json" "$T/kv.hdr" "${3:-}"
}

kv_error() { jq -r '"\(.error.code // "?")/\(.error.innererror.code // "-")"' "$T/kv.json" 2>/dev/null || echo "(no JSON body)"; }

read_db_ok() {
  local code got
  [[ -s "$T/kv.hdr" ]] || return 1
  code=$(kv GET "secrets/$SECRET_NAME")
  DB_VALUE=$(jq -r '.value // empty' "$T/kv.json" 2>/dev/null || true)
  rm -f "$T/kv.json"
  [[ "$code" == 200 && -n "$DB_VALUE" ]] || { info "Key Vault: HTTP $code"; return 1; }
  got=$(printf '%s' "$DB_VALUE" | sha256_stdin)
  info "GET secrets/$SECRET_NAME -> HTTP 200; sha256 ${got:0:12}... (current ${SEED_SHA:0:12}..., value not printed)"
  [[ "$got" == "$SEED_SHA" ]]
}

kv_denied() { # kv_denied METHOD PATH [BODY_FILE|-] : a WORKING workload token gets 403 from Azure RBAC
  # A dead or wrong-audience token is refused with 401, so a 403 here is
  # Key Vault's authorization saying no; the positive read must still work.
  local code
  [[ -s "$T/kv.hdr" && "$(kv GET "secrets/$SECRET_NAME")" == 200 ]] || { info "workload token not usable"; return 1; }
  rm -f "$T/kv.json"
  code=$(kv "$@")
  info "$1 $2 -> HTTP $code $(kv_error)"
  jq -r '.value // empty' "$T/kv.json" 2>/dev/null | grep -q . && { info "a value came back"; return 1; }
  [[ "$code" == 403 ]] && grep -q 'Forbidden' "$T/kv.json"
}

write_denied() { printf '{"value":"e2e-overwrite-attempt"}' | kv_denied PUT "secrets/$SECRET_NAME" -; }

# Entra's refusal codes for a federated credential that does not match
# (seen in the 2026-11-07 run): the subject (namespace:name) -> 700213, the
# audience -> 700212. A check accepts ONLY its own code: an expired assertion
# or a failed issuer lookup is a different AADSTS code and must not pass as
# proof of the refusal under test.
AADSTS_SUBJECT=AADSTS700213
AADSTS_AUDIENCE=AADSTS700212

exchange_denied() { # exchange_denied JWT CLAIMS_FILTER EXPECTED_AADSTS : Entra answers 400/401 with exactly that code and issues no token
  # The token must exist and carry exactly the claims under test (jq filter),
  # so the refusal is about that ONE difference from the positive control.
  local c
  [[ -n "$1" ]] || { info "no token was minted"; return 1; }
  c=$(printf '%s' "$1" | jwt_claims) || return 1
  info "presented: $(jq -r '"aud=\(.aud | join(",")) sub=\(.sub)"' <<<"$c")"
  jq -e "$2" <<<"$c" >/dev/null || { info "token claims are not the ones under test"; return 1; }
  entra_exchange "$1"
  info "Entra: HTTP $EX_CODE $(entra_error)"
  [[ -n "${3:-}" ]] || { info "no expected AADSTS code given"; return 1; }
  [[ ( "$EX_CODE" == 400 || "$EX_CODE" == 401 ) && ! -s "$T/kv.hdr" ]] || return 1
  grep -qE "(^|[^0-9A-Za-z])$3([^0-9]|$)" "$T/ex.safe.json" \
    || { info "refused, but not with $3 (a different failure is not this proof)"; return 1; }
}

api_endpoint() { # -> API_SERVER (URL) + $T/api-ca.crt, from the kind context (only those two fields are read)
  local ca
  API_SERVER=$(k config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null) || API_SERVER=""
  ca=$(k config view --minify --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' 2>/dev/null) || ca=""
  [[ -n "$API_SERVER" && -n "$ca" ]] || return 1
  printf '%s' "$ca" | jq -Rr '@base64d' > "$T/api-ca.crt"
  [[ -s "$T/api-ca.crt" ]]
}

api_status() { # api_status JWT -> HTTP status of GET $API_SERVER/api with that bearer token
  # The JWT goes in a 0600 header file (curl -H @file), never on curl's argv.
  printf 'Authorization: Bearer %s\n' "$1" > "$T/api.hdr"
  curl -sS --max-time 20 --cacert "$T/api-ca.crt" -H "@$T/api.hdr" \
    -o "$T/api.json" -w '%{http_code}' "$API_SERVER/api" 2>/dev/null || true
  rm -f "$T/api.hdr"
}

api_rejects_exchange_audience() {
  # GET /api is open to every AUTHENTICATED identity (ClusterRole
  # system:discovery), so the status code is purely the authentication result:
  # 200 = the API server accepted the token, 401 = it did not.
  # Positive control first: a default-audience token for the same SA -> 200.
  local jwt_api jwt_ex code_api code_ex
  api_endpoint || { info "API server URL / CA not found in context $KUBE_CONTEXT"; return 1; }
  jwt_api=$(mint_token nightly-report 2>/dev/null) || jwt_api=""
  jwt_ex=$(mint_token nightly-report "$EXCHANGE_AUDIENCE" 2>/dev/null) || jwt_ex=""
  [[ -n "$jwt_api" && -n "$jwt_ex" ]] || { info "could not mint the two tokens"; return 1; }
  code_api=$(api_status "$jwt_api")
  code_ex=$(api_status "$jwt_ex")
  jwt_api=""; jwt_ex=""
  info "GET $API_SERVER/api as nightly-report: default-audience token -> HTTP $code_api; aud=$EXCHANGE_AUDIENCE token -> HTTP $code_ex"
  [[ "$code_api" == 200 && "$code_ex" == 401 ]]
}

# --- platform helpers ----------------------------------------------------------------------
csidriver_one_audience() {
  local aud
  aud=$(k get csidriver secrets-store.csi.k8s.io -o json | jq -c '[.spec.tokenRequests[]?.audience]') || return 1
  info "CSIDriver secrets-store.csi.k8s.io tokenRequests audiences=$aud"
  [[ "$aud" == "[\"$EXCHANGE_AUDIENCE\"]" ]]
}

csidriver_token_lifetime() {
  # The lifetime the CSI driver itself requests for the pod's token: the live
  # CSIDriver object, not a token this test mints with --duration.
  local exp
  exp=$(k get csidriver secrets-store.csi.k8s.io -o json | jq -c '[.spec.tokenRequests[]?.expirationSeconds]') || return 1
  info "CSIDriver secrets-store.csi.k8s.io tokenRequests expirationSeconds=$exp"
  [[ "$exp" == "[600]" ]]
}

issuer_published() {
  # What Entra fetches, fetched the same way (anonymous HTTPS), must be the
  # API server's own documents byte for byte.
  local p want got ok=0
  for p in .well-known/openid-configuration openid/v1/jwks; do
    want=$(k get --raw "/$p" | sha256_stdin) || return 1
    got=$(curl -fsS --max-time 20 "$SA_ISSUER/$p" 2>/dev/null | sha256_stdin) || got=""
    info "$SA_ISSUER/$p: public sha256 ${got:0:12}..., API server ${want:0:12}..."
    [[ -n "$got" && "$got" == "$want" ]] || ok=1
  done
  return "$ok"
}

# --- binding helpers: namespace + object, not a name -------------------------------------
fixture_ns_up() { # a fresh namespace other-team holding a service account named nightly-report
  # Same NAME as the approved workload, another namespace: what any team that
  # controls its own namespace can create in one command. It holds no pods.
  if k get namespace "$OTHER_NS" >/dev/null 2>&1; then
    info "leftover namespace $OTHER_NS from an earlier run: deleting it first"
    k delete namespace "$OTHER_NS" --wait=true --timeout=120s >/dev/null 2>&1 || return 1
  fi
  k create namespace "$OTHER_NS" >/dev/null || return 1
  OTHER_NS_CREATED=1
  k label namespace "$OTHER_NS" app.kubernetes.io/part-of=contoso-health-identity-lab \
    contoso.health/e2e-fixture=true >/dev/null || return 1
  k -n "$OTHER_NS" create serviceaccount nightly-report >/dev/null || return 1
  info "created namespace $OTHER_NS + serviceaccount $OTHER_NS/nightly-report (deleted at the end of (d))"
}

old_token_refused() { [[ "$(api_status "$JWT_OLD")" == 401 ]]; }

token_dies_with_sa() {
  # A bound service-account token names its service account's UID
  # (claim kubernetes.io.serviceaccount.uid) and the API server checks that
  # the object still exists with that UID. Deleting the service account
  # revokes every token it was issued, and recreating one with the SAME name
  # does not bring them back. Positive controls: the old token works before,
  # and a fresh token for the new object works after.
  local old_uid new_uid code jwt_new
  api_endpoint || { info "API server URL / CA not found in context $KUBE_CONTEXT"; return 1; }
  k -n "$OTHER_NS" create serviceaccount ephemeral >/dev/null || return 1
  JWT_OLD=$(mint_token_ns "$OTHER_NS" ephemeral 2>/dev/null) || JWT_OLD=""
  [[ -n "$JWT_OLD" ]] || { info "could not mint a token for $OTHER_NS/ephemeral"; return 1; }
  old_uid=$(printf '%s' "$JWT_OLD" | jwt_claims | jq -r '.["kubernetes.io"].serviceaccount.uid // empty') || old_uid=""
  code=$(api_status "$JWT_OLD")
  info "control: GET /api with a token for $OTHER_NS/ephemeral (claim sa uid ${old_uid:0:8}...) -> HTTP $code"
  [[ "$code" == 200 && -n "$old_uid" ]] || return 1
  k -n "$OTHER_NS" delete serviceaccount ephemeral --wait=true >/dev/null || return 1
  k -n "$OTHER_NS" create serviceaccount ephemeral >/dev/null || return 1
  new_uid=$(k -n "$OTHER_NS" get serviceaccount ephemeral -o jsonpath='{.metadata.uid}') || new_uid=""
  [[ -n "$new_uid" && "$new_uid" != "$old_uid" ]] || { info "recreated service account uid: ${new_uid:-none}"; return 1; }
  # The authenticator reads service accounts through an informer cache, so the
  # deletion can take a moment to reach it: retry for up to 30 s.
  if ! wait_until 30 old_token_refused; then
    info "the old token is still accepted 30 s after its service account was replaced"
    return 1
  fi
  info "deleted + recreated $OTHER_NS/ephemeral (same name, uid ${new_uid:0:8}...): the old token -> HTTP 401"
  jwt_new=$(mint_token_ns "$OTHER_NS" ephemeral 2>/dev/null) || jwt_new=""
  code=$(api_status "$jwt_new")
  jwt_new=""; JWT_OLD=""
  info "control: a fresh token for the recreated service account -> HTTP $code"
  [[ "$code" == 200 ]]
}

# A REAL pod, not a dry run: unapproved-job runs the approved image and names
# nightly-report's SecretProviderClass. The CSI driver asks for a token for
# THIS pod's service account, so Entra must refuse it and the kubelet never
# starts the container. Created by the kind admin (the pipeline identity):
# admission admits it (only nightly-report is bound to the launcher), which
# is the point - naming the class is not enough.
THIEF_POD=e2e-spc-borrow
thief_pod_up() {
  k -n "$APP_NS" delete pod "$THIEF_POD" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  jq -n --arg n "$THIEF_POD" --arg img "$APP_IMAGE" --arg spc "$SPC_NAME" --arg ns "$APP_NS" '{
    apiVersion: "v1", kind: "Pod",
    metadata: {name: $n, namespace: $ns, labels: {"app.kubernetes.io/name": "e2e-spc-borrow"}},
    spec: {serviceAccountName: "unapproved-job", automountServiceAccountToken: false, enableServiceLinks: false,
      terminationGracePeriodSeconds: 0,
      securityContext: {runAsNonRoot: true, runAsUser: 10001, seccompProfile: {type: "RuntimeDefault"}},
      containers: [{name: "probe", image: $img, command: ["sleep", "3600"],
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}},
        volumeMounts: [{name: "secrets-store", mountPath: "/mnt/secrets-store", readOnly: true}]}],
      volumes: [{name: "secrets-store", csi: {driver: "secrets-store.csi.k8s.io", readOnly: true,
        volumeAttributes: {secretProviderClass: $spc}}}]}}' | k create -f - >/dev/null
}

thief_mount_failed() {
  THIEF_EVENT=$(k -n "$APP_NS" get events --field-selector "involvedObject.name=$THIEF_POD,reason=FailedMount" -o json 2>/dev/null \
    | jq -r '[.items[].message | select(test("AADSTS"))] | last // empty | capture("(?<c>AADSTS[0-9]+)[^.]*\\.?").c // empty') || THIEF_EVENT=""
  # Only the subject-mismatch refusal proves "this SA may not borrow the
  # credential"; any other Entra error keeps waiting (and fails at 120 s).
  [[ "$THIEF_EVENT" == "$AADSTS_SUBJECT" ]]
}

spc_borrow_refused() {
  local phase ready
  thief_pod_up || { info "could not create pod $THIEF_POD"; return 1; }
  if ! wait_until 120 thief_mount_failed; then
    info "no FailedMount event with an Entra error for $THIEF_POD within 120 s"
    k -n "$APP_NS" delete pod "$THIEF_POD" --wait=false >/dev/null 2>&1 || true
    return 1
  fi
  phase=$(k -n "$APP_NS" get pod "$THIEF_POD" -o jsonpath='{.status.phase}' 2>/dev/null) || phase=""
  ready=$(k -n "$APP_NS" get pod "$THIEF_POD" -o json | jq -r '[.status.containerStatuses[]?.started // false] | any')
  info "pod $THIEF_POD (SA unapproved-job, same image, same SecretProviderClass): phase=$phase started=$ready; FailedMount: Entra $THIEF_EVENT"
  k -n "$APP_NS" delete pod "$THIEF_POD" --wait=true --timeout=60s >/dev/null 2>&1 || true
  [[ "$phase" == Pending && "$ready" == false ]]
}

fixture_ns_down() {
  k delete namespace "$OTHER_NS" --wait=true --timeout=120s >/dev/null 2>&1 || return 1
  OTHER_NS_CREATED=0
  if k get namespace "$OTHER_NS" >/dev/null 2>&1; then return 1; fi
  info "namespace $OTHER_NS and its service accounts are gone"
}

# --- "no static secret" helpers ---------------------------------------------------------
value_absent_everywhere() {
  [[ -n "$DB_VALUE" ]] || { info "no value to search for (the workload's Key Vault read failed)"; return 1; }
  local raw decoded b64 counts
  raw=$(k -n "$APP_NS" get secrets,configmaps,deployments,replicasets,pods -o json) || return 1
  # Secret data is base64: search the decoded values too, in case the value
  # is embedded in a larger blob (where its own base64 would not line up).
  decoded=$(printf '%s' "$raw" | jq -r '.items[] | select(.kind == "Secret") | (.data // {}) | to_entries[] | .value | @base64d') || return 1
  b64=$(printf '%s' "$DB_VALUE" | base64 | tr -d '\n')
  counts=$(printf '%s' "$raw" | jq -r '[.items[].kind] | group_by(.) | map("\(.[0])=\(length)") | join(" ")')
  info "searched clinical-apps: ${counts:-nothing} (plain, base64, decoded Secret data)"
  case "$raw"$'\n'"$decoded" in
    *"$DB_VALUE"*|*"$b64"*) return 1 ;;
  esac
}

no_legacy_sa_token_secrets() {
  k -n "$APP_NS" get secrets -o json \
    | jq -e '[.items[] | select(.type == "kubernetes.io/service-account-token")] | length == 0' >/dev/null
}

sas_opt_out_of_automount() {
  k -n "$APP_NS" get serviceaccount nightly-report unapproved-job -o json \
    | jq -e '(.items | length) == 2 and all(.items[]; .automountServiceAccountToken == false)' >/dev/null
}

# --- RBAC helpers -------------------------------------------------------------------------
probe_deployment() { # probe_deployment [SA] [IMAGE] -> a restricted-compliant Deployment, for a server-side dry-run create
  # No SA = the namespace's "default" service account; no IMAGE = the app's.
  jq -n --arg sa "${1:-}" --arg img "${2:-$APP_IMAGE}" --arg ns "$APP_NS" '{
    apiVersion: "apps/v1", kind: "Deployment",
    metadata: {name: "e2e-rbac-probe", namespace: $ns},
    spec: {replicas: 1,
      selector: {matchLabels: {"app.kubernetes.io/name": "e2e-rbac-probe"}},
      template: {metadata: {labels: {"app.kubernetes.io/name": "e2e-rbac-probe"}},
        spec: ({automountServiceAccountToken: false,
          securityContext: {runAsNonRoot: true, runAsUser: 10001, seccompProfile: {type: "RuntimeDefault"}},
          containers: [{name: "probe", image: $img, command: ["sleep", "3600"],
            securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}]}
          + (if $sa == "" then {} else {serviceAccountName: $sa} end))}}}'
}

deployer_creates_deployment() { probe_deployment | k create --dry-run=server -f - -o name "${DEPLOYER[@]}"; }

deployer_creates_as() { # deployer_creates_as SA IMAGE : the deployer creates a Deployment running as SA (dry run)
  probe_deployment "$1" "$2" | k create --dry-run=server -f - -o name "${DEPLOYER[@]}"
}

can() { # can VERB RESOURCE [--subresource=X] IMPERSONATION... : `kubectl auth can-i` answers exactly "yes"
  local out rc=0 what="$1 $2"
  if [[ "${3:-}" == --subresource=* ]]; then what="$what/${3#--subresource=}"; fi
  out=$(k -n "$APP_NS" auth can-i "$1" "$2" "${@:3}" 2>&1) || rc=$?
  info "can-i $what -> $out"
  [[ $rc -eq 0 && "$out" == yes* ]]
}

deployer_cannot_write_pods() {
  # Pods come only from Deployments (whose ReplicaSet controller creates them
  # under its own identity), and admission checks both. With no pod write
  # verb, the deployer cannot start a bare pod as nightly-report or swap a
  # running container's image in place.
  local v ok=0
  for v in create update patch delete deletecollection; do
    cannot "$v" pods "${DEPLOYER[@]}" || ok=1
  done
  return "$ok"
}

deployer_reads_pods() { can list pods "${DEPLOYER[@]}" && can get pods --subresource=log "${DEPLOYER[@]}"; }

deployer_replicasets_read_only() {
  # Deleting nightly-report's ReplicaSet would make the Deployment controller
  # (a trusted launcher) recreate it: a restart that rule 4 refuses when it
  # is asked for as `kubectl rollout restart`. Reading stays (rollout
  # status / history / undo read ReplicaSets): positive control first.
  local v ok=0
  can list replicasets "${DEPLOYER[@]}" || ok=1
  for v in create update patch delete; do
    cannot "$v" replicasets "${DEPLOYER[@]}" || ok=1
  done
  return "$ok"
}

# --- the RBAC matrix (G) ---------------------------------------------------------------------
# Rows: who; columns: what. Every cell is one SelfSubjectAccessReview
# (`kubectl auth can-i` impersonating the row), i.e. what the API server's
# authorizer answers, not what the YAML seems to say. Every cell has an
# expected value and any difference fails the check. Printed for the demo.
MATRIX_ROWS=("deployer" "auditor" "SA nightly-report" "SA unapproved-job")
MATRIX_EXPECT=("yes no no no no no no" "no no no no no no no" "no no no no no no no" "no no no no no no no")
MATRIX_NCOLS=7
WHO=()

matrix_who() { # matrix_who ROW_INDEX -> WHO=(impersonation flags)
  case "$1" in
    0) WHO=("${DEPLOYER[@]}") ;;
    1) WHO=("${AUDITOR[@]}") ;;
    # Impersonating a service-account username also gives it that account's
    # groups (system:serviceaccounts, system:serviceaccounts:<namespace>).
    2) WHO=(--as="system:serviceaccount:$APP_NS:nightly-report") ;;
    3) WHO=(--as="system:serviceaccount:$APP_NS:unapproved-job") ;;
  esac
}

can_i() { # can_i NAMESPACE VERB RESOURCE [--subresource=X] -> yes | no | err, as "${WHO[@]}"
  local out rc=0
  out=$(k -n "$1" auth can-i "${@:2}" "${WHO[@]}" 2>/dev/null) || rc=$?
  case "$rc:$out" in
    0:yes*) echo yes ;;
    1:no*)  echo no ;;
    *)      echo err ;;
  esac
}

matrix_cell() { # matrix_cell COLUMN (1-7) -> yes | no | err, as "${WHO[@]}"
  local a r=no
  case "$1" in
    1) can_i "$APP_NS" create deployments ;;
    2) can_i "$APP_NS" patch pods ;;
    3) can_i "$APP_NS" get secrets ;;
    4) can_i "$APP_NS" create rolebindings ;;
    5) # impersonating ANY user, group or service account = becoming someone else
       for a in users groups serviceaccounts; do
         case "$(can_i "$APP_NS" impersonate "$a")" in
           yes) r=yes ;;
           err) [[ "$r" == yes ]] || r=err ;;
         esac
       done
       echo "$r" ;;
    6) can_i "$APP_NS" create pods --subresource=exec ;;
    7) can_i kube-system list pods ;;
  esac
}

matrix_line() { printf '%-19s%-10s%-10s%-10s%-10s%-10s%-10s%s' "$@"; }   # <= 100 columns with indent

rbac_matrix() {
  local i c got want line bad=""
  local -a exp
  info "kubectl auth can-i as each identity; namespace $APP_NS, last column kube-system"
  info "$(matrix_line "" create patch get create imper- pods/ "list pods")"
  info "$(matrix_line "" deploys pods secrets rolebind sonate exec kube-sys)"
  for ((i = 0; i < ${#MATRIX_ROWS[@]}; i++)); do
    matrix_who "$i"
    read -r -a exp <<<"${MATRIX_EXPECT[i]}"
    line=$(printf '%-19s' "${MATRIX_ROWS[i]}")
    for ((c = 1; c <= MATRIX_NCOLS; c++)); do
      got=$(matrix_cell "$c")
      want="${exp[c - 1]}"
      if [[ "$got" != "$want" ]]; then
        bad="$bad ${MATRIX_ROWS[i]}/col$c=$got(expected $want)"
        got="$got*"
      fi
      line="$line$(printf '%-10s' "$got")"
    done
    info "${line%"${line##*[! ]}"}"   # without the last cell's padding
  done
  info "expected: only the deployer may create Deployments; every other cell no (* = mismatch)"
  [[ -z "$bad" ]] || { info "mismatch:$bad"; return 1; }
}

# --- admission helpers (ValidatingAdmissionPolicy) -------------------------------------------
vap_installed() {
  local p b
  p=$(k get validatingadmissionpolicies.admissionregistration.k8s.io "$VAP_NAME" -o json 2>/dev/null) \
    || { info "no ValidatingAdmissionPolicy $VAP_NAME"; return 1; }
  b=$(k get validatingadmissionpolicybindings.admissionregistration.k8s.io -o json 2>/dev/null \
    | jq -c --arg p "$VAP_NAME" '[.items[] | select(.spec.policyName == $p)]') || return 1
  info "policy:  $(jq -r '"failurePolicy=\(.spec.failurePolicy // "Fail") validations=\(.spec.validations | length) match=\([.spec.matchConstraints.resourceRules[]? | "\(.apiGroups | map(if . == "" then "core" else . end) | join("|"))/\(.resources | join("|")):\(.operations | join("+"))"] | join(" "))"' <<<"$p")"
  info "binding: $(jq -r 'map("\(.metadata.name) validationActions=\(.spec.validationActions | join(","))") | join("; ")' <<<"$b")"
  jq -e 'length >= 1 and all(.[]; .spec.validationActions == ["Deny"])' <<<"$b" >/dev/null || return 1
  jq -e '
    def covers($g; $r): any(.spec.matchConstraints.resourceRules[]?;
      (.apiGroups | index($g) or index("*")) and (.resources | index($r) or index("*"))
      and (.operations | (index("CREATE") or index("*")) and (index("UPDATE") or index("*"))));
    covers(""; "pods") and covers("apps"; "deployments")' <<<"$p" >/dev/null || return 1
  # Scoped to clinical-apps: a namespaceSelector on the policy or the binding
  # names it (kubernetes.io/metadata.name, set by the API server itself).
  jq -e --arg ns "$APP_NS" '[.. | strings] | index($ns) != null' <<<"[$p,$b]" >/dev/null
}

pod_images_pinned() { # every image the RUNNING pod runs is digest-pinned
  info "$(jq -r '[(.spec.initContainers // [])[], .spec.containers[] | "\(.name): \(.image | split("@sha256:")
    | if length == 2 then "\(.[0])@sha256:\(.[1][0:12])..." else .[0] + "  (NO DIGEST)" end)"] | join("\n")' "$T/pod.json")"
  jq -e '[(.spec.initContainers // [])[], .spec.containers[] | .image | contains("@sha256:")] | all' "$T/pod.json" >/dev/null
}

probe_pod() { # probe_pod NAME SA IMAGE AUTOMOUNT(true|false) -> a PSA-restricted-compliant Pod for a server-side dry run
  # Compliant with everything EXCEPT what the caller varies, so a denial can
  # only come from the one rule under test.
  jq -n --arg n "$1" --arg sa "$2" --arg img "$3" --argjson am "$4" --arg ns "$APP_NS" '{
    apiVersion: "v1", kind: "Pod",
    metadata: {name: $n, namespace: $ns, labels: {"app.kubernetes.io/name": "e2e-vap-probe"}},
    spec: {serviceAccountName: $sa, automountServiceAccountToken: $am, enableServiceLinks: false,
      securityContext: {runAsNonRoot: true, runAsUser: 10001, seccompProfile: {type: "RuntimeDefault"}},
      containers: [{name: "probe", image: $img, command: ["sleep", "3600"],
        securityContext: {allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: {drop: ["ALL"]}}}]}}'
}

admin_dry_run_pod() { probe_pod "$@" | k create --dry-run=server -f - -o name; }   # as the kind admin: admission applies to admins too

deployer_patch_app() { # deployer_patch_app FIELD JSON_VALUE : the deployer changes the APP container of nightly-report (dry run)
  # The JSON-patch "test" op makes sure it is the app container being changed
  # (a patch that fails for another reason fails the check: the VAP's own
  # message is required).
  local p
  p=$(jq -nc --arg c "$WORKLOAD_CTR" --arg f "$1" --argjson v "$2" '[
    {op: "test", path: "/spec/template/spec/containers/0/name", value: $c},
    {op: "replace", path: "/spec/template/spec/containers/0/\($f)", value: $v}]')
  k -n "$APP_NS" patch deployment "$APP_DEPLOYMENT" --type=json --dry-run=server "${DEPLOYER[@]}" -p "$p"
}

# Another digest-pinned image, as identity nightly-report.
deployer_patch_image() { deployer_patch_app image "$(jq -nc --arg i "$OTHER_IMAGE" '$i')"; }

# The SAME approved image, a different command: print the rendered file into
# pods/log, which the deployer may read. Only the launcher rule can see this.
deployer_patch_command() { deployer_patch_app args '["cat /mnt/secrets-store/db; sleep 3600"]'; }

sa_move_patch() { # sa_move_patch SA -> JSON patch: nightly-report's pod template to SA, with a new command
  jq -nc --arg c "$WORKLOAD_CTR" --arg sa "$1" '[
    {op: "test", path: "/spec/template/spec/serviceAccountName", value: "nightly-report"},
    {op: "test", path: "/spec/template/spec/containers/0/name", value: $c},
    {op: "replace", path: "/spec/template/spec/serviceAccountName", value: $sa},
    {op: "replace", path: "/spec/template/spec/containers/0/args", value: ["echo taken over; sleep 3600"]}]'
}

# Hijack instead of borrow: one patch moves the live nightly-report Deployment
# OFF its identity and rewrites what it runs. Rules 2 and 4 judged only the
# new object would see a "default" workload and admit it; rule 4 also
# judges the object before the update (variables.wasNightlyReport).
deployer_patch_sa_away() {
  k -n "$APP_NS" patch deployment "$APP_DEPLOYMENT" --type=json --dry-run=server "${DEPLOYER[@]}" -p "$(sa_move_patch default)"
}

# Positive control: the pipeline identity may make that change (rule 4
# refuses non-launchers, it does not freeze the workload).
admin_patch_sa_away() {
  k -n "$APP_NS" patch deployment "$APP_DEPLOYMENT" --type=json --dry-run=server -o name -p "$(sa_move_patch unapproved-job)"
}

no_cluster_bindings_for_groups() {
  local hits
  hits=$(k get clusterrolebindings -o json | jq -r '[.items[] | select(any(.subjects[]?; .kind == "Group" and (.name | startswith("k8s-clinical-")))) | .metadata.name] | join(",")') || return 1
  info "ClusterRoleBindings naming a k8s-clinical-* group: ${hits:-none}"
  [[ -z "$hits" ]]
}

ns_label() { k get namespace "$1" -o json | jq -r --arg l "pod-security.kubernetes.io/$2" '.metadata.labels[$l] // "unset"'; }

psa_labels_ok() {
  local a e w v x
  e=$(ns_label "$APP_NS" enforce); w=$(ns_label "$APP_NS" warn); a=$(ns_label "$APP_NS" audit)
  v=$(ns_label "$CSI_NS" enforce); x=$(ns_label "$CSI_NS" warn)
  info "$APP_NS enforce=$e warn=$w audit=$a; $CSI_NS enforce=$v warn=$x (CSI node plugin)"
  [[ "$e" == restricted && "$w" == restricted && "$a" == restricted && "$v" == privileged && "$x" == baseline ]]
}

# --- audit helpers --------------------------------------------------------------------------
audit_event() { # -> one-line summary of the deployer's forbidden GET of PROBE_SECRET ("" if not logged)
  docker exec "$CP_CONTAINER" grep -F -- "$PROBE_SECRET" "$AUDIT_LOG_IN_NODE" 2>/dev/null \
    | jq -rs --arg n "$PROBE_SECRET" '
        [.[] | select(.objectRef.resource == "secrets" and .objectRef.name == $n and .verb == "get"
                      and .responseStatus.code == 403
                      and ((.impersonatedUser.groups // []) | index("k8s-clinical-deployers")))]
        | first // empty
        | "\(.stageTimestamp) user=\(.user.username) impersonating=\(.impersonatedUser.username) groups=\(.impersonatedUser.groups | join(",")) \(.verb) \(.objectRef.namespace)/\(.objectRef.resource)/\(.objectRef.name) -> \(.responseStatus.code) decision=\(.annotations["authorization.k8s.io/decision"] // "?")"'
}

audit_logged() { AUDIT_LINE=$(audit_event || true); [[ -n "$AUDIT_LINE" ]]; }

audit_has_forbidden_read() {
  wait_until 30 audit_logged || { info "no matching event in $CP_CONTAINER:$AUDIT_LOG_IN_NODE"; return 1; }
  info "$AUDIT_LINE"
}

audit_lines() { # audit_lines [FIXED_STRING] -> the audit log (only the lines containing FIXED_STRING), from inside the node
  if [[ -n "${1:-}" ]]; then
    docker exec "$CP_CONTAINER" grep -F -- "$1" "$AUDIT_LOG_IN_NODE" 2>/dev/null || true
  else
    docker exec "$CP_CONTAINER" cat "$AUDIT_LOG_IN_NODE" 2>/dev/null || true
  fi
}

audit_sensitive_metadata_only() {
  # Every Secret, TokenRequest (serviceaccounts/token: the RESPONSE is a JWT)
  # and TokenReview (the REQUEST carries a bearer token) event in the log:
  # level must be Metadata and no event may carry a request/response body.
  # Secrets and TokenRequests must each occur at least once (the run made
  # both: the deployer's Secret probe, `kubectl create token` and the CSI
  # driver's rotation tokens), so "0 bodies" cannot come from an empty or
  # unreadable log. TokenReviews are counted but may be 0: nothing in this
  # design calls TokenReview (Entra checks the JWKS instead).
  # jq -R + fromjson?: a line the API server is still writing is skipped.
  local s
  s=$(audit_lines | jq -nRr 'inputs | fromjson? | select(.objectRef != null)
      | select(.objectRef.resource == "secrets" or .objectRef.resource == "tokenreviews"
               or (.objectRef.resource == "serviceaccounts" and .objectRef.subresource == "token"))
      | "\(.objectRef.resource)\(if .objectRef.subresource then "/" + .objectRef.subresource else "" end) \(.level) \(if has("requestObject") or has("responseObject") then "BODY" else "-" end)"' \
      | sort | uniq -c | awk '{ n[$2] += $1; if ($3 != "Metadata" || $4 != "-") bad += $1 }
          END { printf "secrets=%d serviceaccounts/token=%d tokenreviews=%d not-metadata-or-with-body=%d\n",
                n["secrets"], n["serviceaccounts/token"], n["tokenreviews"], bad }') || return 1
  info "events: $s"
  [[ "$s" =~ ^secrets=([0-9]+)\ serviceaccounts/token=([0-9]+)\ tokenreviews=([0-9]+)\ not-metadata-or-with-body=([0-9]+)$ ]] || return 1
  [[ ${BASH_REMATCH[1]} -gt 0 && ${BASH_REMATCH[2]} -gt 0 && ${BASH_REMATCH[4]} -eq 0 ]]
}

drift_audit_events() { # -> $T/drift-audit.json: {drift, heal} one-line summaries ("" when not found)
  # The drift drill (pipeline stage 10): the LAST patch of the RoleBinding by
  # the kind admin (not impersonating) whose request adds User mallory and
  # whose response object lists it; then the first later write of the same
  # RoleBinding by Terraform (its user agent; Terraform runs with the same
  # kind admin credentials) whose response no longer lists mallory.
  audit_lines "$DRIFT_RB" | jq -nR --arg ns "$APP_NS" --arg rb "$DRIFT_RB" --arg u "$DRIFT_USER" --arg admin "$KIND_ADMIN" '
    def subj: [(.responseObject.subjects // [])[] | "\(.kind)/\(.name)"];
    def has_u: (subj | index("User/" + $u)) != null;
    def req: (.requestObject | if type == "array"
               then map("\(.op) \(.path) \(.value.kind // "")/\(.value.name // "")") | join("; ")
               else tostring | .[0:80] end);
    def who: "by \(.user.username) (\((.userAgent // "?") | split(" ") | .[0:2] | join(" ")))\n  level \(.level)";
    [inputs | fromjson? | select(.stage == "ResponseComplete" and .objectRef.resource == "rolebindings"
        and .objectRef.namespace == $ns and .objectRef.name == $rb
        and (.verb == "patch" or .verb == "update") and (.responseStatus.code // 0) < 300)] as $ev
    | ([$ev[] | select(.verb == "patch" and .user.username == $admin and .impersonatedUser == null
          and ((.requestObject | tostring) | contains($u)) and has_u)] | last) as $d
    | if $d == null then {drift: "", heal: ""} else
        ([$ev[] | select(.requestReceivedTimestamp > $d.requestReceivedTimestamp
              and ((.userAgent // "") | test("Terraform/"))
              and .responseObject.subjects != null and (has_u | not))] | first) as $h
        | {drift: "\($d.requestReceivedTimestamp) \($d.verb) \($d | who); requestObject: \($d | req)\n  responseObject.subjects: \($d | subj | join(", "))",
           heal: (if $h == null then "" else
             "\($h.requestReceivedTimestamp) \($h.verb) \($h | who)\n  responseObject.subjects: \($h | subj | join(", "))" end)}
      end' > "$T/drift-audit.json"
}

audit_drift_patch() {
  [[ -n "$KIND_ADMIN" ]] || { info "could not tell who the kind admin is (kubectl auth whoami)"; return 1; }
  drift_audit_events || return 1
  local d
  d=$(jq -r '.drift' "$T/drift-audit.json")
  [[ -n "$d" ]] || { info "no patch of $APP_NS/$DRIFT_RB by $KIND_ADMIN adding User/$DRIFT_USER"; return 1; }
  info "$d"
}

audit_drift_heal() {
  local h
  h=$(jq -r '.heal // empty' "$T/drift-audit.json" 2>/dev/null) || h=""
  [[ -n "$h" ]] || { info "no later write of $APP_NS/$DRIFT_RB by Terraform without User/$DRIFT_USER"; return 1; }
  info "$h"
}

audit_vap_write() {
  # The policy object itself, not its /status subresource: kube-controller-
  # manager's validatingadmissionpolicy-status-controller patches status
  # (type-checking results) after every write, and the audit policy keeps
  # those controller writes at Metadata on purpose (they are not a change to
  # the guardrail). Without the subresource filter, "last write" is that one.
  local line
  line=$(audit_lines "$VAP_NAME" | jq -nRr --arg n "$VAP_NAME" '[inputs | fromjson? | select(.stage == "ResponseComplete"
        and .objectRef.resource == "validatingadmissionpolicies" and .objectRef.name == $n
        and (.objectRef.subresource // "") == ""
        and (.verb == "create" or .verb == "update" or .verb == "patch") and (.responseStatus.code // 0) < 300)]
      | last // empty
      | "\(.requestReceivedTimestamp) \(.verb) by \(.user.username) (\((.userAgent // "?") | split(" ") | .[0:2] | join(" ")))\n  level \(.level); responseObject: \(.responseObject.kind // "none") with \((.responseObject.spec.validations // []) | length) validations"') || line=""
  [[ -n "$line" ]] || { info "no write of validatingadmissionpolicies/$VAP_NAME in the log"; return 1; }
  info "$line"
  [[ "$line" == *"level RequestResponse; responseObject: ValidatingAdmissionPolicy with "* && "$line" != *" with 0 validations"* ]]
}

# =============================================================================
step "(a) platform: kind node, CSI driver + Azure provider, public issuer, Pod Security labels"
k version >/dev/null 2>&1 || abort "API server reachable through context $KUBE_CONTEXT"
info "$(k get nodes -o jsonpath='{range .items[*]}{.metadata.name} kubelet={.status.nodeInfo.kubeletVersion}{"\n"}{end}')"
check "node(s) Ready" nodes_ready
check "Secrets Store CSI Driver pods Ready" pods_ready "$CSI_NS" "app=secrets-store-csi-driver"
check "Azure Key Vault provider pods Ready" pods_ready "$CSI_NS" "app=csi-secrets-store-provider-azure"
check "CSIDriver requests tokens for exactly one audience: $EXCHANGE_AUDIENCE" csidriver_one_audience
check "PSA: $APP_NS enforce/warn/audit=restricted, $CSI_NS enforce=privileged warn=baseline" psa_labels_ok
check "the public issuer serves the API server's own discovery document and JWKS" issuer_published

# =============================================================================
step "(b) workload: nightly-report gets its credential from a CSI volume"
k -n "$APP_NS" get deployment "$APP_DEPLOYMENT" -o json > "$T/deploy.json" 2>/dev/null \
  || abort "deployment $APP_NS/$APP_DEPLOYMENT exists"
APP_SELECTOR=$(jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")' "$T/deploy.json")
WORKLOAD_CTR=$(jq -r '.spec.template.spec.containers[0].name' "$T/deploy.json")
APP_IMAGE=$(jq -r '.spec.template.spec.containers[0].image' "$T/deploy.json")
POD=""
wait_until 120 find_pod || abort "a Ready nightly-report pod ($APP_SELECTOR)"
k -n "$APP_NS" get pod "$POD" -o json > "$T/pod.json"
pass "nightly-report pod Ready: $POD"
check "nothing injected: the pod runs only the app container" nothing_injected
check "the pod mounts SecretProviderClass $SPC_NAME through the CSI driver" csi_volume_mounted
check "$MOUNTED_FILE in '$WORKLOAD_CTR' hashes to the CURRENT value (seeded, then rotated)" rendered_file_matches
check "app container has no Kubernetes API token (automount off, nothing at the default path)" app_has_no_kube_token
check "the pod spec holds no projected service-account token at all" pod_holds_no_token
check "Deployment: no env value, no secretKeyRef/envFrom Secret, no Secret volume, automount off" deployment_has_no_static_secret
check "SecretProviderClass: Workload ID (this app's client id), no secretObjects (never a Kubernetes Secret)" spc_syncs_nothing

# =============================================================================
step "(c) Entra Workload ID + Key Vault RBAC: who gets a token, and what it is worth"
JWT_EX=$(mint_token nightly-report "$EXCHANGE_AUDIENCE" 2>/dev/null) || JWT_EX=""
check "the CSI driver itself requests 600 s tokens (live CSIDriver spec.tokenRequests)" csidriver_token_lifetime
check "a test TokenRequest for clinical-apps/nightly-report: iss=public issuer, aud=[$EXCHANGE_AUDIENCE], <= 600s" claims_ok
check "Entra exchanges it for an access token (federated credential, no client secret)" exchange_ok
JWT_EX=""
check "the access token is for Key Vault, issued to this app, in this tenant" access_token_scoped
check "it can read $SECRET_NAME (sha256 = current value)" read_db_ok
check "it cannot read $DECOY_SECRET in the SAME vault (403, Azure RBAC)" kv_denied GET "secrets/$DECOY_SECRET"
check "it cannot write $SECRET_NAME (403)" write_denied
check "it cannot list the vault's secrets (403)" kv_denied GET secrets
rm -f "$T/kv.hdr"
JWT_OTHER=$(mint_token unapproved-job "$EXCHANGE_AUDIENCE" 2>/dev/null) || JWT_OTHER=""
check "Entra refuses unapproved-job's token with $AADSTS_SUBJECT (same audience, no federated credential)" exchange_denied "$JWT_OTHER" \
  '.aud == ["api://AzureADTokenExchange"] and .sub == "system:serviceaccount:clinical-apps:unapproved-job"' "$AADSTS_SUBJECT"
JWT_OTHER=""
JWT_DEFAULT=$(mint_token nightly-report 2>/dev/null) || JWT_DEFAULT=""
check "Entra refuses nightly-report's token WITHOUT the exchange audience, with $AADSTS_AUDIENCE" exchange_denied "$JWT_DEFAULT" \
  '.sub == "system:serviceaccount:clinical-apps:nightly-report" and (.aud | index("api://AzureADTokenExchange")) == null' "$AADSTS_AUDIENCE"
JWT_DEFAULT=""
check "the Kubernetes API refuses the exchange-audience token (401; a default-audience one: 200)" api_rejects_exchange_audience

# =============================================================================
step "(d) identity = namespace + name, not just a name"
check "fixture: namespace $OTHER_NS with its own service account named nightly-report" fixture_ns_up
JWT_TWIN=$(mint_token_ns "$OTHER_NS" nightly-report "$EXCHANGE_AUDIENCE" 2>/dev/null) || JWT_TWIN=""
check "Entra refuses $OTHER_NS/nightly-report with $AADSTS_SUBJECT (same name, same audience, other namespace)" \
  exchange_denied "$JWT_TWIN" ".aud == [\"api://AzureADTokenExchange\"] and .sub == \"system:serviceaccount:$OTHER_NS:nightly-report\"" "$AADSTS_SUBJECT"
JWT_TWIN=""
check "a token dies with its ServiceAccount: SA deleted + recreated (same name) -> old token 401" token_dies_with_sa
check "fixture namespace $OTHER_NS deleted again" fixture_ns_down
check "a real pod as unapproved-job naming $SPC_NAME never starts (Entra refuses the driver's token)" spc_borrow_refused

# =============================================================================
step "(e) no static secret anywhere in the namespace"
check "the value is in no Secret/ConfigMap/Deployment/ReplicaSet/Pod in $APP_NS" value_absent_everywhere
DB_VALUE=""
check "no legacy long-lived service-account token Secrets in $APP_NS" no_legacy_sa_token_secrets
check "service accounts nightly-report + unapproved-job: automountServiceAccountToken=false" sas_opt_out_of_automount

# =============================================================================
step "(f) RBAC as code: can-i matrix, impersonated groups (AKS: Entra group object IDs)"
check "RBAC matrix: ${#MATRIX_ROWS[@]} identities x $MATRIX_NCOLS permissions, every cell as expected" rbac_matrix
expect_ok "deployer: can create a Deployment in $APP_NS (server-side dry run)" deployer_creates_deployment
check "deployer: can list pods and read pods/log (positive control)" deployer_reads_pods
check "deployer: cannot create / update / patch / delete pods (no bare pod, no in-place image swap)" \
  deployer_cannot_write_pods
check "deployer: ReplicaSets read-only (deleting one would restart nightly-report)" deployer_replicasets_read_only
expect_forbidden "deployer: cannot get Secrets in $APP_NS" 'cannot get resource "secrets"' \
  k -n "$APP_NS" get secret "$PROBE_SECRET" "${DEPLOYER[@]}"
expect_forbidden "deployer: cannot list pods in kube-system" 'cannot list resource "pods"' \
  k -n kube-system get pods "${DEPLOYER[@]}"
expect_forbidden "deployer: cannot mint a token for nightly-report (serviceaccounts/token)" 'serviceaccounts/token' \
  k -n "$APP_NS" create token nightly-report --audience "$EXCHANGE_AUDIENCE" "${DEPLOYER[@]}"
check "deployer: cannot create RoleBindings (no self-escalation)" cannot create rolebindings "${DEPLOYER[@]}"
check "deployer: no exec / attach / port-forward / ephemeral containers on pods" no_shell_into_pods "${DEPLOYER[@]}"
expect_ok "auditor: can list pods in $APP_NS" k -n "$APP_NS" get pods -o name "${AUDITOR[@]}"
expect_forbidden "auditor: cannot get Secrets in $APP_NS" 'cannot get resource "secrets"' \
  k -n "$APP_NS" get secret "$PROBE_SECRET" "${AUDITOR[@]}"
expect_forbidden "auditor: cannot list Secrets in $APP_NS (not even their names)" 'cannot list resource "secrets"' \
  k -n "$APP_NS" get secrets "${AUDITOR[@]}"
expect_forbidden "auditor: cannot delete pods in $APP_NS (server-side dry run)" 'cannot delete resource "pods"' \
  k -n "$APP_NS" delete pod "$POD" --dry-run=server "${AUDITOR[@]}"
check "no ClusterRoleBinding for the k8s-clinical-* groups (namespace-scoped only)" no_cluster_bindings_for_groups

# =============================================================================
# Server-side dry runs: the full admission chain (mutating webhooks, then
# validation: Pod Security, then the ValidatingAdmissionPolicy), nothing
# persisted. The cluster admin is denied too: admission is not RBAC.
# Each denial is matched on the fixed opening phrase of ONE rule's message
# (lab/terraform/k8s/identity/main.tf, local.policy_validations): the first
# rule, in list order, that the fixture breaks (see expect_vap_denied):
VAP_RULE_DIGEST='image not pinned by digest'                    # (1)
VAP_RULE_ALLOWLIST='may run only the approved app image'        # (2)
VAP_RULE_AUTOMOUNT='automountServiceAccountToken must be false' # (3)
VAP_RULE_LAUNCHER='only the release pipeline may create or change'  # (4)
step "(g) admission: ValidatingAdmissionPolicy $VAP_NAME + PSA"
TAG_IMAGE="${APP_IMAGE%@*}"   # the approved image's tag, without its digest
check "VAP + binding installed: Deny on CREATE/UPDATE of pods + deployments in $APP_NS" vap_installed
check "the running nightly-report pod: every image (app + injected agent) is pinned by digest" pod_images_pinned
expect_ok "control: the pipeline identity runs nightly-report on the approved digest -> admitted" \
  admin_dry_run_pod e2e-vap-approved nightly-report "$APP_IMAGE" false
expect_vap_denied "even the pipeline: nightly-report + a different digest-pinned image -> denied" \
  "$VAP_RULE_ALLOWLIST" admin_dry_run_pod e2e-vap-borrow nightly-report "$OTHER_IMAGE" false
expect_ok "control: unapproved-job may run that image -> admitted (the allowlist binds nightly-report)" \
  admin_dry_run_pod e2e-vap-other-sa unapproved-job "$OTHER_IMAGE" false
expect_vap_denied "tag-only image ($TAG_IMAGE, no @sha256 digest) -> denied" \
  "$VAP_RULE_DIGEST" admin_dry_run_pod e2e-vap-tag unapproved-job "$TAG_IMAGE" false
expect_vap_denied "automountServiceAccountToken: true -> denied" \
  "$VAP_RULE_AUTOMOUNT" admin_dry_run_pod e2e-vap-automount unapproved-job "$APP_IMAGE" true
expect_ok "control: the deployer ships its own Deployment (as unapproved-job) -> admitted" \
  deployer_creates_as unapproved-job "$OTHER_IMAGE"
expect_vap_denied "deployer creates a Deployment AS nightly-report (approved image) -> denied" \
  "$VAP_RULE_LAUNCHER" deployer_creates_as nightly-report "$APP_IMAGE"
expect_vap_denied "deployer re-points nightly-report to another image digest -> denied" \
  "$VAP_RULE_ALLOWLIST" deployer_patch_image
expect_vap_denied "deployer keeps the image, swaps the command to print the secret -> denied" \
  "$VAP_RULE_LAUNCHER" deployer_patch_command
expect_vap_denied "deployer moves nightly-report to SA default + new command, one patch -> denied" \
  "$VAP_RULE_LAUNCHER" deployer_patch_sa_away
expect_ok "control: the pipeline identity may move it off nightly-report -> admitted" \
  admin_patch_sa_away
# Pod Security runs before the ValidatingAdmissionPolicy in the API server's
# validating admission order (PodSecurity precedes ValidatingAdmissionPolicy
# in kube-apiserver's recommended plugin order), so this pod - which would
# also fail the VAP's automount rule - is rejected with PSA's message.
expect_forbidden "manifests/negative/privileged-pod.yaml rejected by Pod Security (enforce=restricted)" \
  'violates PodSecurity "restricted' k -n "$APP_NS" apply --dry-run=server -f "$NEGATIVE_POD"

# =============================================================================
step "(h) API-server audit log: who tried what, who changed what, what it never holds"
AUDIT_LINE=""
KIND_ADMIN=$(k auth whoami -o json 2>/dev/null | jq -r '.status.userInfo.username // empty') || KIND_ADMIN=""
check "the deployer's forbidden Secret read is logged (403, impersonated user + group)" audit_has_forbidden_read
check "Secret / TokenRequest / TokenReview events: Metadata level, no request or response body" \
  audit_sensitive_metadata_only
check "drift drill: ${KIND_ADMIN:-the kind admin} patched the deployer RoleBinding, + User/$DRIFT_USER (bodies)" \
  audit_drift_patch
check "drift drill: Terraform's revert of that RoleBinding (User/$DRIFT_USER gone) is logged after it" audit_drift_heal
check "the ValidatingAdmissionPolicy write is logged with its body (RequestResponse)" audit_vap_write

# --- summary --------------------------------------------------------------------------------
TOTAL=$((PASSES + FAILS))
if [[ $FAILS -eq 0 ]]; then
  printf '\nK8S E2E PASSED (%d/%d)\n' "$PASSES" "$TOTAL"
  exit 0
fi
printf '\nK8S E2E FAILED (%d/%d passed, %d failed)\n' "$PASSES" "$TOTAL" "$FAILS"
exit 1
