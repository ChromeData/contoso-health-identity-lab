#!/usr/bin/env bash
# =============================================================================
# new-operator-cert.sh - make (or rotate) the lab operator's certificate
# -----------------------------------------------------------------------------
# Generates an RSA-2048 key and a self-signed certificate valid for 179 days
# (inside the tenant app-management policy cap of 180), then:
#   * stores the PRIVATE KEY in the login Keychain (generic password
#     "contoso-lab-operator-key", base64 PEM), passed to `security` on STDIN,
#     never on the command line
#   * writes only the PUBLIC certificate to ~/.contoso-operator/operator.crt
#     for lab/terraform/envs/operator to upload
# The key is generated in a private temp dir and removed before exit.
# Rotation: run again, then re-apply envs/operator (a human apply).
# =============================================================================
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
. "$here/common.sh"

days=179
umask 077
mkdir -p "$OP_HOME/session"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days "$days" \
  -subj "/CN=Contoso Lab Operator/O=contoso-health-identity-lab" \
  -keyout "$tmp/key.pem" -out "$tmp/cert.pem" 2>/dev/null

b64="$(base64 < "$tmp/key.pem" | tr -d '\n')"
# -U updates an existing item. The secret goes in through stdin (security -i).
printf 'add-generic-password -U -s %s -a operator -l "Contoso Lab Operator private key (base64 PEM)" -w %s\n' \
  "$OP_KEYCHAIN_SERVICE" "$b64" | security -i >/dev/null
unset b64

cp "$tmp/cert.pem" "$OP_HOME/operator.crt"
chmod 700 "$OP_HOME"
end="$(openssl x509 -in "$OP_HOME/operator.crt" -noout -enddate | cut -d= -f2)"
fp="$(openssl x509 -in "$OP_HOME/operator.crt" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)"
echo "New operator certificate: thumbprint $fp, valid until $end."
echo "Private key: login Keychain, item $OP_KEYCHAIN_SERVICE. Public cert: $OP_HOME/operator.crt"
echo "Next: apply lab/terraform/envs/operator (human admin) so Entra trusts it."
