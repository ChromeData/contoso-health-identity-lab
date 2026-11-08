#!/usr/bin/env bash
# Offline tests for .github/scripts/pipeline-config.sh: a fake `az` on PATH
# serves secrets from a folder. No Azure, no network.
# shellcheck disable=SC2015  # ok()/bad() only count, they never fail
#   bash .github/scripts/tests/pipeline-config.test.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
script="$here/../pipeline-config.sh"
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/secrets"
cat >"$work/bin/az" <<'FAKE'
#!/usr/bin/env bash
# az keyvault secret show --vault-name V --name N --query value -o tsv
name=""; while [ $# -gt 0 ]; do [ "$1" = "--name" ] && name="$2"; shift; done
f="$FAKE_SECRETS/$name"
if [ -f "$f" ]; then cat "$f"; exit 0; fi
echo "ERROR: (SecretNotFound) A secret with (name/id) $name was not found in this key vault." >&2; exit 3
FAKE
chmod +x "$work/bin/az"
export PATH="$work/bin:$PATH" FAKE_SECRETS="$work/secrets"
pass=0; fail=0
ok() { pass=$((pass+1)); echo "ok - $1"; }
bad() { fail=$((fail+1)); echo "not ok - $1"; }
seed() {
  rm -f "$work/secrets"/*
  printf '%s' '["198.51.100.7/32"]' >"$work/secrets/tf-operator-ip-ranges"
  printf '%s' 'alerts@example.org' >"$work/secrets/tf-alert-email"
  printf '%s' '["11111111-1111-1111-1111-111111111111","22222222-2222-2222-2222-222222222222"]' >"$work/secrets/tf-app-owner-object-ids"
  printf '%s' '[]' >"$work/secrets/tf-saml-cert-notification-emails"
  printf '%s' 'pim@example.org' >"$work/secrets/tf-pim-alert-mailbox"
}
run() { : >"$work/env"; GITHUB_ENV="$work/env" PIPELINE_CONFIG_VAULT="${1:-kv-test-cicd}" bash "$script" >"$work/out" 2>&1; }

# 1. All five present: exported, masked (whole + each element), never echoed bare.
seed
if run; then ok "all five read"; else bad "all five read"; cat "$work/out"; fi
grep -q '^TF_VAR_app_owner_object_ids<<EOF_' "$work/env" && ok "list exported with a heredoc delimiter" || bad "list exported"
grep -qx '::add-mask::11111111-1111-1111-1111-111111111111' "$work/out" && ok "each list element masked" || bad "each list element masked"
grep -qx '::add-mask::alerts@example.org' "$work/out" && ok "string masked" || bad "string masked"
grep -qx '::add-mask::\[\]' "$work/out" && bad "empty list masked" || ok "empty list not masked"
[ "$(grep -v '::add-mask::' "$work/out" | grep -c 'example.org\|198.51.100.7')" = 0 ] && ok "no value printed outside a mask command" || bad "value printed"
[ "$(grep -c '^TF_VAR_' "$work/env")" = 5 ] && ok "five TF_VAR_ exported" || bad "five TF_VAR_ exported"

# 2. A missing secret fails closed (the old '[]' fallback planned removals).
seed; rm "$work/secrets/tf-operator-ip-ranges"
if run; then bad "missing secret fails"; else grep -q "SecretNotFound" "$work/out" && ok "missing secret fails closed, reason named" || bad "missing reason"; fi

# 3. An empty value fails.
seed; : >"$work/secrets/tf-alert-email"
if run; then bad "empty value fails"; else ok "empty value fails"; fi

# 4. A list that is not a JSON list of strings fails, without printing it.
seed; printf '%s' 'not-json-secret' >"$work/secrets/tf-app-owner-object-ids"
if run; then bad "bad list fails"; else ok "bad list fails"; fi
grep -v '::add-mask::' "$work/out" | grep -q 'not-json-secret' && bad "bad value printed" || ok "bad value not printed"

# 5. A bad vault name is refused before any read.
seed
if run 'bad name!'; then bad "bad vault name refused"; else ok "bad vault name refused"; fi

# 6. A value cannot inject another variable (delimiter is random).
seed; printf '%s' $'alerts@example.org\nTF_VAR_injected=1' >"$work/secrets/tf-alert-email"
if run; then bad "multi-line value refused"; else ok "multi-line value refused"; fi
grep -q '^TF_VAR_injected=1$' "$work/env" && bad "value injected a variable" || ok "no variable injected"

echo "# $pass passed, $fail failed"
[ "$fail" = 0 ]
