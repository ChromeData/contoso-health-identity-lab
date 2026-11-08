#!/usr/bin/env bash
# cutover.sh - point the Contoso Claims Viewer at one identity provider.
#
#   cutover.sh entra      the cutover: the app now trusts ONLY Entra
#   cutover.sh adfs       the roll-back: the app trusts ONLY AD FS again
#   cutover.sh status     which IdP the running app trusts
#
# Why this is the whole cutover: a SAML app trusts an identity provider by
# its federation metadata (entity ID, sign-in URL, signing certificate).
# Swapping that one file is what "repoint the app" means for every real SAML
# app (ServiceNow, AWS, Salesforce...: "upload the new IdP metadata"). The
# roll-back is the same command with the old file, which is why the AD FS
# relying party stays in place until 19-Remove-Adfs.ps1 (ADR 0009 phase 3:
# "Point the app back at the AD FS metadata").
#
# Metadata files (public data, not secrets) live in idp-metadata/:
#   adfs.xml   from https://<sts>/FederationMetadata/2007-06/FederationMetadata.xml
#              (13-Get-AdfsClaims.ps1 prints its URL; fetch-metadata.sh adfs)
#   entra.xml  from https://login.microsoftonline.com/<tenant>/federationmetadata/
#              2007-06/federationmetadata.xml?appid=<client id>  (fetch-metadata.sh entra)
set -euo pipefail
cd "$(dirname "$0")"

target="${1:-}"
case "$target" in
  entra|adfs)
    f="idp-metadata/$target.xml"
    [[ -s "$f" ]] || { echo "cutover: $f is missing; run fetch-metadata.sh $target first" >&2; exit 2; }
    grep -q 'IDPSSODescriptor' "$f" || { echo "cutover: $f has no IDPSSODescriptor (not SAML IdP metadata)" >&2; exit 2; }
    printf 'CV_IDP_FILE=%s.xml\n' "$target" > .env
    docker compose up -d --build --force-recreate >/dev/null
    echo "$(date -u +%FT%TZ) claims-viewer now trusts: $target ($(sed -n 's/.*entityID="\([^"]*\)".*/\1/p' "$f" | head -1))"
    ;;
  status)
    docker exec contoso-claims-viewer printenv CV_IDP_FILE 2>/dev/null || { echo "not running" ; exit 1; }
    ;;
  *) echo "usage: cutover.sh entra|adfs|status" >&2; exit 2 ;;
esac
