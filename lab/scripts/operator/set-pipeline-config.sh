#!/usr/bin/env bash
# =============================================================================
# set-pipeline-config.sh - write ONE pipeline privacy value to the pipeline
# config vault (envs/bootstrap pipeline-config.tf), as the lab operator.
# -----------------------------------------------------------------------------
#   lab/scripts/operator/set-pipeline-config.sh <vault> <secret-name>  < value-file
#   printf '%s' '["198.51.100.7/32"]' | lab/scripts/operator/set-pipeline-config.sh kv-idlab-cicd-20f1 tf-operator-ip-ranges
#
# The value comes on STDIN only: never in argv (visible in `ps`), never
# printed. It is checked against the shape .github/scripts/pipeline-config.sh
# accepts (the same five names; a JSON list of non-empty strings for the
# list ones, one non-empty line for the others), so a value CI would refuse
# is refused here first. Then it is sent to `az` as a file (--file), not as
# --value.
#
# Who may write: Key Vault Secrets Officer on the vault (the lab operator
# holds it at subscription scope; a human admin also can). CI never writes.
# =============================================================================
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

vault="${1:-}"; name="${2:-}"
case "$name" in
  tf-operator-ip-ranges|tf-app-owner-object-ids|tf-saml-cert-notification-emails) kind=list ;;
  tf-alert-email|tf-pim-alert-mailbox) kind=string ;;
  *) echo "usage: $0 <vault> <tf-operator-ip-ranges|tf-alert-email|tf-app-owner-object-ids|tf-saml-cert-notification-emails|tf-pim-alert-mailbox> < value" >&2; exit 2 ;;
esac
[[ "$vault" =~ ^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$ ]] || { echo "not a Key Vault name: $vault" >&2; exit 2; }
[ -t 0 ] && { echo "the value must come on stdin (a pipe or a file), not typed into argv" >&2; exit 2; }

umask 077
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/value"
python3 -I - "$tmp/value" "$kind" <<'EOF' || { echo "refused: '$name' does not have the shape CI accepts (value not shown)" >&2; exit 1; }
import json, sys
v = open(sys.argv[1]).read()
assert v and "\n" not in v.rstrip("\n") and v.strip() == v.rstrip("\n").strip()
v = v.rstrip("\n")
if sys.argv[2] == "list":
    x = json.loads(v)
    assert isinstance(x, list) and all(isinstance(e, str) and e for e in x)
else:
    assert v.strip()
open(sys.argv[1], "w").write(v)
EOF

"$here/op" az keyvault secret set --vault-name "$vault" --name "$name" --file "$tmp/value" \
  --content-type "pipeline-config/$kind" --query "{name:name, updated:attributes.updated}" -o tsv
