#!/usr/bin/env bash
# fetch-metadata.sh adfs|entra - save an IdP's SAML federation metadata to
# idp-metadata/<name>.xml (public data). Fails closed: an HTTP error, an
# empty file or a file without an IDPSSODescriptor stops with exit 1 and
# leaves the old file in place.
#
#   adfs:  ADFS_HOST (default sts.corp.contosohealthlab.com) and ADFS_IP (DC01's
#          public IP) - curl --resolve, so no /etc/hosts edit is needed. The
#          AD FS TLS certificate is self-signed: it is pinned by its SHA-256
#          public-key hash in ADFS_PIN (printed by `pin` below), not ignored.
#   entra: TENANT_ID and CLIENT_ID (terraform output claims_viewer_client_id).
#   pin:   print the AD FS certificate's public-key pin (TOFU, first contact).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p idp-metadata
host="${ADFS_HOST:-sts.corp.contosohealthlab.com}"
case "${1:-}" in
  pin)
    : "${ADFS_IP:?set ADFS_IP}"
    openssl s_client -connect "$ADFS_IP:443" -servername "$host" </dev/null 2>/dev/null \
      | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
      | openssl dgst -sha256 -binary | openssl enc -base64
    exit 0 ;;
  adfs)
    : "${ADFS_IP:?set ADFS_IP}" "${ADFS_PIN:?set ADFS_PIN (fetch-metadata.sh pin)}"
    url="https://$host/FederationMetadata/2007-06/FederationMetadata.xml"
    tmp=$(mktemp)
    curl -fsS --resolve "$host:443:$ADFS_IP" --insecure --pinnedpubkey "sha256//$ADFS_PIN" -o "$tmp" "$url" ;;
  entra)
    : "${TENANT_ID:?set TENANT_ID}" "${CLIENT_ID:?set CLIENT_ID}"
    tmp=$(mktemp)
    curl -fsS -o "$tmp" "https://login.microsoftonline.com/$TENANT_ID/federationmetadata/2007-06/federationmetadata.xml?appid=$CLIENT_ID" ;;
  *) echo "usage: fetch-metadata.sh adfs|entra|pin" >&2; exit 2 ;;
esac
if [[ ! -s "$tmp" ]] || ! grep -q 'IDPSSODescriptor' "$tmp"; then rm -f "$tmp"; echo "fetch-metadata: no SAML IdP metadata" >&2; exit 1; fi
mv "$tmp" "idp-metadata/$1.xml"
echo "saved idp-metadata/$1.xml ($(sed -n 's/.*entityID="\([^"]*\)".*/\1/p' "idp-metadata/$1.xml" | head -1))"
