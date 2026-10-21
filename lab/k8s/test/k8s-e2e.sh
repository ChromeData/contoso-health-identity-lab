#!/usr/bin/env bash
# shellcheck disable=SC2329  # assertion helpers are called indirectly, through check / expect_*
# =============================================================================
# lab/k8s/test/k8s-e2e.sh - prove the Kubernetes workload-identity segment on
# the running contoso-k8s kind cluster (stage 11 of lab/k8s/ci/pipeline.sh,
# after the rotation drill in stage 9 and the drift drill in stage 10).
#
#   a. platform     node, Vault server + injector Ready, Vault version pinned,
#                   Pod Security Admission labels on both namespaces
#   b. workload     nightly-report Ready WITH the injected vault-agent; the
#                   rendered /vault/secrets/db hashes to the CURRENT value
#                   (hashed inside the pod); the app container has no
#                   Kubernetes token; only the agent holds the aud=vault token;
#                   the Deployment carries no env value / Secret reference
#   c. Vault        a TokenRequest for nightly-report (aud=vault, 10 min) logs
#                   in; the Vault token is least-privilege and <= 15 min; read
#                   db OK, read other -> 403, write db -> 403; unapproved-job
#                   (aud=vault) and nightly-report WITHOUT aud=vault are both
#                   refused; the API server refuses the aud=vault token (401)
#                   while accepting a default-audience one; a revoked token is
#                   refused
#   d. binding      identity is namespace + name + OBJECT, not a name: a
#                   service account called nightly-report in another namespace
#                   (other-team, a fixture created and deleted here) is
#                   refused by Vault; a token dies with its service account
#                   (deleted and recreated under the same name -> 401)
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
# Never as root for Vault: the pipeline starts this script without the Vault
# root token in its environment, and the script unsets VAULT_TOKEN anyway.
# Every Vault assertion uses the token the WORKLOAD gets from its own
# Kubernetes login. (Kubernetes fixtures and server-side dry runs use the
# kind admin's kubeconfig, as a cluster operator would; RBAC assertions
# impersonate the identity under test.)
#
# The secret value is never printed. Its hash is compared inside the pod; the
# copy read back over the workload's Vault login (to search the namespace's
# objects for it) only lives in a shell variable. JWTs and Vault tokens travel
# in 0600 files / stdin, never on a command line, and command output echoed as
# evidence passes through redact first (a regression that lets the deployer
# mint a token would otherwise print that token).
#
# Negative checks cannot pass by accident: a "denied" must be the server's
# own Forbidden / 403 / 400 naming the reason, not a connection error. Each
# block also has a positive control (the same role logs in; the same group
# CAN do its allowed action) run against the same cluster first.
#
# Usage: lab/k8s/test/k8s-e2e.sh
#   K8S_E2E_SEED_SHA256_FILE  sha256 of the CURRENT clinical/data/db value
#                             (set by pipeline.sh, which rewrites it after the
#                             stage-9 rotation; default
#                             lab/k8s/ci/.state/seed.sha256, kept when the
#                             pipeline ran with KEEP_CLUSTER=1)
#   Run standalone on a kept cluster, section (h) expects the audit trail of
#   the pipeline's drift drill (stage 10) from that run.
#   VAULT_ADDR                default http://127.0.0.1:18200
# Prints PASS/FAIL per assertion; last line "K8S E2E PASSED (n/n)", else exit 1.
# =============================================================================
# shellcheck source-path=SCRIPTDIR
# shellcheck source=../ci/lib.sh disable=SC1091  # followed with shellcheck -x
source "$(dirname "${BASH_SOURCE[0]}")/../ci/lib.sh"
need kubectl; need jq; need curl; need docker; need base64

unset VAULT_TOKEN   # see header: never as root

SEED_FILE="${K8S_E2E_SEED_SHA256_FILE:-$STATE_DIR/seed.sha256}"
[[ -s "$SEED_FILE" ]] || die "no seed hash at $SEED_FILE - run lab/k8s/ci/pipeline.sh (KEEP_CLUSTER=1 keeps a cluster you can re-test)"
SEED_SHA=$(tr -d ' \r\n' < "$SEED_FILE")
[[ "$SEED_SHA" =~ ^[0-9a-f]{64}$ ]] || die "$SEED_FILE does not hold a sha256"

T=$(mktemp -d "${TMPDIR:-/tmp}/k8s-e2e.XXXXXX")
DB_VALUE=""
JWT_OLD=""
# Section (d)'s fixture namespace. Created and deleted by this script; the
# EXIT trap removes it too if the script dies in between.
OTHER_NS=other-team
OTHER_NS_CREATED=0
cleanup() {
  DB_VALUE=""; JWT_OLD=""
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
# base64url, the header always starts eyJ) and Vault service/batch tokens.
redact() {
  sed -E -e 's/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/<jwt redacted>/g' \
         -e 's/hv[sb]\.[A-Za-z0-9_-]{20,}/<vault token redacted>/g'
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

sidecar_injected() {
  local cs ics
  cs=$(jq -r '[.spec.containers[].name] | join(",")' "$T/pod.json")
  ics=$(jq -r '[.spec.initContainers[]?.name] | join(",")' "$T/pod.json")
  info "pod $POD containers=[$cs] initContainers=[$ics]"
  jq -e '[.spec.containers[].name] | index("vault-agent") != null' "$T/pod.json" >/dev/null
}

rendered_file_matches() {
  # Hashed INSIDE the app container: the value never crosses kubectl. tr drops
  # a trailing newline in case a template adds one; the seed has none.
  local got
  got=$(pod_exec sh -c 'test -s /vault/secrets/db && tr -d "\r\n" < /vault/secrets/db | sha256sum' 2>/dev/null | awk '{print $1}') || return 1
  info "in-pod sha256 ${got:0:12}...  seeded ${SEED_SHA:0:12}...  (value not printed)"
  [[ -n "$got" && "$got" == "$SEED_SHA" ]]
}

app_has_no_kube_token() {
  jq -e '.spec.automountServiceAccountToken == false' "$T/pod.json" >/dev/null || return 1
  # The exec must WORK and find nothing: a failed exec is a non-zero exit too,
  # but then `test` never ran, so the check fails rather than passes.
  pod_exec sh -c 'test ! -e /var/run/secrets/kubernetes.io/serviceaccount/token && echo absent' 2>/dev/null | grep -qx absent
}

only_agent_holds_vault_token() {
  local mp
  mp=$(jq -r '[.spec.containers[] | select(.name == "vault-agent") | .volumeMounts[]? | select(.name == "vault-token") | .mountPath] | first // empty' "$T/pod.json")
  info "vault-token: projected, audience=$(jq -r '[.spec.volumes[]? | select(.name == "vault-token") | .projected.sources[]?.serviceAccountToken | select(. != null)] | first | "\(.audience), expirationSeconds=\(.expirationSeconds)"' "$T/pod.json"); vault-agent mounts it at ${mp:-?}"
  jq -e --arg app "$WORKLOAD_CTR" '
    ([.spec.volumes[]? | select(.name == "vault-token") | .projected.sources[]?.serviceAccountToken
      | select(. != null and .audience == "vault" and .expirationSeconds <= 600)] | length == 1)
    and ([.spec.containers[] | select(.name == "vault-agent") | .volumeMounts[]? | select(.name == "vault-token")] | length >= 1)
    and ([.spec.containers[] | select(.name == $app) | .volumeMounts[]? | select(.name == "vault-token")] | length == 0)' \
    "$T/pod.json" >/dev/null
}

deployment_has_no_static_secret() {
  jq -e '.spec.template.spec as $s
    | ($s.containers + ($s.initContainers // [])) as $all
    | ([$all[] | (.env // [])[] | select(has("value") or (.valueFrom.secretKeyRef != null))] | length == 0)
      and ([$all[] | (.envFrom // [])[] | select(.secretRef != null)] | length == 0)
      and ([($s.volumes // [])[] | select(.secret != null or ([.projected.sources[]? | select(.secret != null)] | length > 0))] | length == 0)
      and ($s.automountServiceAccountToken == false)' "$T/deploy.json" >/dev/null
}

# --- Vault helpers ---------------------------------------------------------------------
mint_token_ns() { # mint_token_ns NAMESPACE SA [AUDIENCE] -> JWT on stdout (captured, never printed)
  if [[ -n "${3:-}" ]]; then
    k -n "$1" create token "$2" --audience "$3" --duration 10m
  else
    k -n "$1" create token "$2" --duration 10m   # the API server's default audience
  fi
}

mint_token() { mint_token_ns "$APP_NS" "$@"; }   # mint_token SA [AUDIENCE], in clinical-apps

jwt_claims() { # printf '%s' JWT | jwt_claims -> payload JSON (base64url; the signature is Vault's TokenReview's job)
  jq -R 'split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | . + ("=" * ((4 - length % 4) % 4)) | @base64d | fromjson'
}

vault_login() { # vault_login ROLE JWT -> LOGIN_CODE, LOGIN_TOKEN ("" if none); body in $T/login.json
  # jq builds the body from stdin (-R): the JWT is never an argument.
  printf '%s' "$2" | jq -Rc --arg role "$1" '{role: $role, jwt: .}' > "$T/login-req.json"
  LOGIN_CODE=$(vault_http POST auth/kubernetes/login "$T/login.json" "" "$T/login-req.json")
  rm -f "$T/login-req.json"
  LOGIN_TOKEN=$(jq -r '.auth.client_token // empty' "$T/login.json" 2>/dev/null || true)
}

login_denied() { # login_denied ROLE JWT CLAIMS_FILTER : Vault answers 400/403 with an error and issues no token
  # The token must exist and carry exactly the claims under test (jq filter),
  # so the refusal is about that ONE difference from the positive control -
  # an empty or malformed JWT ("missing jwt") would otherwise "pass".
  local c
  [[ -n "$2" ]] || { info "no token was minted"; return 1; }
  c=$(printf '%s' "$2" | jwt_claims) || return 1
  info "presented: $(jq -r '"aud=\(.aud | join(",")) sub=\(.sub)"' <<<"$c")"
  jq -e "$3" <<<"$c" >/dev/null || { info "token claims are not the ones under test"; return 1; }
  vault_login "$1" "$2"
  info "Vault: HTTP $LOGIN_CODE $(vault_errors "$T/login.json")"
  [[ ( "$LOGIN_CODE" == 400 || "$LOGIN_CODE" == 403 ) && -z "$LOGIN_TOKEN" ]]
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

api_rejects_vault_audience() {
  # GET /api is open to every AUTHENTICATED identity (ClusterRole
  # system:discovery), so the status code is purely the authentication result:
  # 200 = the API server accepted the token, 401 = it did not.
  # Positive control first: a default-audience token for the same SA -> 200.
  local jwt_api jwt_vault code_api code_vault
  api_endpoint || { info "API server URL / CA not found in context $KUBE_CONTEXT"; return 1; }
  jwt_api=$(mint_token nightly-report 2>/dev/null) || jwt_api=""
  jwt_vault=$(mint_token nightly-report vault 2>/dev/null) || jwt_vault=""
  [[ -n "$jwt_api" && -n "$jwt_vault" ]] || { info "could not mint the two tokens"; return 1; }
  code_api=$(api_status "$jwt_api")
  code_vault=$(api_status "$jwt_vault")
  jwt_api=""; jwt_vault=""
  info "GET $API_SERVER/api as nightly-report: default-audience token -> HTTP $code_api; aud=vault token -> HTTP $code_vault"
  [[ "$code_api" == 200 && "$code_vault" == 401 ]]
}

wl() { # wl METHOD PATH [BODY_FILE|-] -> HTTP status, as the WORKLOAD's Vault token; body in $T/wl.json
  vault_http "$1" "$2" "$T/wl.json" "$T/wl.hdr" "${3:-}"
}

vault_healthy_pinned() {
  local code
  code=$(vault_http GET sys/health "$T/health.json")
  info "GET $VAULT_ADDR/v1/sys/health -> $code $(jq -c '{initialized, sealed, version}' "$T/health.json" 2>/dev/null)"
  [[ "$code" == 200 ]] && jq -e '.initialized == true and .sealed == false' "$T/health.json" >/dev/null
}

vault_version_pinned() { jq -e '.version | startswith("2.1.1")' "$T/health.json" >/dev/null 2>&1; }

claims_ok() {
  local c
  c=$(printf '%s' "$JWT_VAULT" | jwt_claims) || return 1
  info "$(jq -r '"aud=\(.aud | join(",")) sub=\(.sub) lifetime=\(.exp - .iat)s"' <<<"$c")"
  jq -e '.aud == ["vault"] and .sub == "system:serviceaccount:clinical-apps:nightly-report" and (.exp - .iat) <= 600' <<<"$c" >/dev/null
}

login_ok() {
  vault_login nightly-report "$JWT_VAULT"
  if [[ "$LOGIN_CODE" != 200 || -z "$LOGIN_TOKEN" ]]; then
    info "Vault: HTTP $LOGIN_CODE $(vault_errors "$T/login.json")"
    return 1
  fi
  printf 'X-Vault-Token: %s\n' "$LOGIN_TOKEN" > "$T/wl.hdr"
  LOGIN_TOKEN=""
  info "$(jq -r '.auth | "policies=\(.token_policies | join(",")) lease=\(.lease_duration)s sa=\(.metadata.service_account_namespace)/\(.metadata.service_account_name)"' "$T/login.json")"
}

wl_lookup() { [[ -s "$T/wl.hdr" && "$(wl GET auth/token/lookup-self)" == 200 ]] && cp "$T/wl.json" "$T/lookup.json"; }

policies_minimal() {
  [[ -s "$T/lookup.json" ]] || return 1
  info "token policies: $(jq -r '.data.policies | join(",")' "$T/lookup.json")"
  jq -e '(.data.policies - ["default"]) == ["nightly-report-read"]' "$T/lookup.json" >/dev/null
}

ttl_bounded() {
  [[ -s "$T/lookup.json" ]] || return 1
  info "$(jq -r '.data | "ttl=\(.ttl)s creation_ttl=\(.creation_ttl)s renewable=\(.renewable)"' "$T/lookup.json")"
  jq -e '.data.ttl > 0 and .data.ttl <= 900 and .data.creation_ttl <= 900' "$T/lookup.json" >/dev/null
}

read_db_ok() {
  local code got
  [[ -s "$T/wl.hdr" ]] || return 1
  code=$(wl GET clinical/data/db)
  DB_VALUE=$(jq -r '.data.data.password // empty' "$T/wl.json" 2>/dev/null || true)
  rm -f "$T/wl.json"
  [[ "$code" == 200 && -n "$DB_VALUE" ]] || { info "Vault: HTTP $code"; return 1; }
  got=$(printf '%s' "$DB_VALUE" | sha256_stdin)
  info "HTTP 200; sha256 ${got:0:12}... (seeded ${SEED_SHA:0:12}..., value not printed)"
  [[ "$got" == "$SEED_SHA" ]]
}

wl_status_is() { # wl_status_is WANT METHOD PATH [BODY_FILE|-]
  local want="$1" code; shift
  [[ -s "$T/wl.hdr" ]] || return 1
  code=$(wl "$@")
  info "$1 $2 -> HTTP $code $(vault_errors "$T/wl.json")"
  [[ "$code" == "$want" ]]
}

wl_denied() { # wl_denied METHOD PATH [BODY_FILE|-] : a LIVE workload token gets 403 "permission denied" (policy, not auth)
  # A dead/invalid token is refused with 403 too, so prove the token still
  # works (lookup-self 200) before reading a 403 as "the policy said no".
  local code
  [[ -s "$T/wl.hdr" && "$(wl GET auth/token/lookup-self)" == 200 ]] || { info "workload token not usable"; return 1; }
  code=$(wl "$@")
  info "$1 $2 -> HTTP $code $(vault_errors "$T/wl.json")"
  [[ "$code" == 403 ]] && grep -qi 'permission denied' "$T/wl.json"
}

write_denied() { printf '{"data":{"password":"e2e-overwrite-attempt"}}' | wl_denied POST clinical/data/db -; }

revoke_and_refused() {
  [[ -s "$T/wl.hdr" ]] || return 1
  local code
  code=$(wl POST auth/token/revoke-self)
  info "POST auth/token/revoke-self -> HTTP $code"
  [[ "$code" == 204 ]] || return 1
  wl_status_is 403 GET auth/token/lookup-self
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

fixture_ns_down() {
  k delete namespace "$OTHER_NS" --wait=true --timeout=120s >/dev/null 2>&1 || return 1
  OTHER_NS_CREATED=0
  if k get namespace "$OTHER_NS" >/dev/null 2>&1; then return 1; fi
  info "namespace $OTHER_NS and its service accounts are gone"
}

# --- "no static secret" helpers ---------------------------------------------------------
value_absent_everywhere() {
  [[ -n "$DB_VALUE" ]] || { info "no value to search for (the workload's Vault read failed)"; return 1; }
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

pod_images_pinned() { # every image the RUNNING pod runs - the app and the injected agent - is digest-pinned
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
deployer_patch_command() { deployer_patch_app args '["cat /vault/secrets/db; sleep 3600"]'; }

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
  local a e w v
  e=$(ns_label "$APP_NS" enforce); w=$(ns_label "$APP_NS" warn); a=$(ns_label "$APP_NS" audit)
  v=$(ns_label "$VAULT_NS" enforce)
  info "$APP_NS enforce=$e warn=$w audit=$a; $VAULT_NS enforce=$v"
  [[ "$e" == restricted && "$w" == restricted && "$a" == restricted && "$v" == baseline ]]
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
  # Each kind must also occur at least once (the run made all three: the
  # deployer's Secret probe, `kubectl create token`, Vault's TokenReviews),
  # so "0 bodies" cannot come from an empty or unreadable log.
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
  [[ ${BASH_REMATCH[1]} -gt 0 && ${BASH_REMATCH[2]} -gt 0 && ${BASH_REMATCH[3]} -gt 0 && ${BASH_REMATCH[4]} -eq 0 ]]
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
step "(a) platform: kind node, Vault, injector, Pod Security labels"
k version >/dev/null 2>&1 || abort "API server reachable through context $KUBE_CONTEXT"
info "$(k get nodes -o jsonpath='{range .items[*]}{.metadata.name} kubelet={.status.nodeInfo.kubeletVersion}{"\n"}{end}')"
check "node(s) Ready" nodes_ready
check "Vault server pod Ready" pods_ready "$VAULT_NS" "app.kubernetes.io/name=vault,component=server"
check "Vault API healthy at $VAULT_ADDR (initialized, unsealed)" vault_healthy_pinned
check "Vault runs the pinned version 2.1.1" vault_version_pinned
check "Vault Agent Injector (mutating webhook) Ready" pods_ready "$VAULT_NS" "app.kubernetes.io/name=vault-agent-injector"
check "PSA: $APP_NS enforce/warn/audit=restricted, $VAULT_NS enforce=baseline" psa_labels_ok

# =============================================================================
step "(b) workload: nightly-report gets its credential from the injected agent"
k -n "$APP_NS" get deployment "$APP_DEPLOYMENT" -o json > "$T/deploy.json" 2>/dev/null \
  || abort "deployment $APP_NS/$APP_DEPLOYMENT exists"
APP_SELECTOR=$(jq -r '.spec.selector.matchLabels | to_entries | map("\(.key)=\(.value)") | join(",")' "$T/deploy.json")
WORKLOAD_CTR=$(jq -r '.spec.template.spec.containers[0].name' "$T/deploy.json")
APP_IMAGE=$(jq -r '.spec.template.spec.containers[0].image' "$T/deploy.json")
POD=""
wait_until 120 find_pod || abort "a Ready nightly-report pod ($APP_SELECTOR)"
k -n "$APP_NS" get pod "$POD" -o json > "$T/pod.json"
pass "nightly-report pod Ready: $POD"
check "vault-agent sidecar injected (Vault Agent Injector webhook)" sidecar_injected
check "/vault/secrets/db in '$WORKLOAD_CTR' hashes to the CURRENT value (seeded, then rotated)" rendered_file_matches
check "app container has no Kubernetes API token (automount off, nothing at the default path)" app_has_no_kube_token
check "only vault-agent mounts the projected aud=vault token (<= 600s); the app container does not" only_agent_holds_vault_token
check "Deployment: no env value, no secretKeyRef/envFrom Secret, no Secret volume, automount off" deployment_has_no_static_secret

# =============================================================================
step "(c) Vault Kubernetes auth: who may log in, and what the login is worth"
JWT_VAULT=$(mint_token nightly-report vault 2>/dev/null) || JWT_VAULT=""
check "TokenRequest for clinical-apps/nightly-report: aud=[vault], <= 600s" claims_ok
check "Vault login (auth/kubernetes, role nightly-report) with that token succeeds" login_ok
JWT_VAULT=""
wl_lookup || true
check "the Vault token carries only the nightly-report-read policy (no root)" policies_minimal
check "the Vault token's TTL is <= 900s" ttl_bounded
check "it can read clinical/data/db (sha256 = current value)" read_db_ok
check "it cannot read clinical/data/other (403)" wl_denied GET clinical/data/other
check "it cannot write clinical/data/db (403)" write_denied
JWT_OTHER=$(mint_token unapproved-job vault 2>/dev/null) || JWT_OTHER=""
check "unapproved-job token (aud=vault) cannot log in as nightly-report" login_denied nightly-report "$JWT_OTHER" \
  '.aud == ["vault"] and .sub == "system:serviceaccount:clinical-apps:unapproved-job"'
JWT_OTHER=""
JWT_DEFAULT=$(mint_token nightly-report 2>/dev/null) || JWT_DEFAULT=""
check "nightly-report token WITHOUT aud=vault (API-server audience) is refused" login_denied nightly-report "$JWT_DEFAULT" \
  '.sub == "system:serviceaccount:clinical-apps:nightly-report" and (.aud | index("vault")) == null'
JWT_DEFAULT=""
check "the Kubernetes API refuses the aud=vault token (401; a default-audience one for the SA: 200)" api_rejects_vault_audience
check "after revoke-self the workload's Vault token is refused (403)" revoke_and_refused

# =============================================================================
step "(d) identity = namespace + name + object, not just a name"
check "fixture: namespace $OTHER_NS with its own service account named nightly-report" fixture_ns_up
JWT_TWIN=$(mint_token_ns "$OTHER_NS" nightly-report vault 2>/dev/null) || JWT_TWIN=""
check "$OTHER_NS/nightly-report (same name, aud=vault) cannot log in to Vault role nightly-report" \
  login_denied nightly-report "$JWT_TWIN" ".aud == [\"vault\"] and .sub == \"system:serviceaccount:$OTHER_NS:nightly-report\""
JWT_TWIN=""
check "a token dies with its ServiceAccount: SA deleted + recreated (same name) -> old token 401" token_dies_with_sa
check "fixture namespace $OTHER_NS deleted again" fixture_ns_down

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
  k -n "$APP_NS" create token nightly-report --audience vault "${DEPLOYER[@]}"
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
