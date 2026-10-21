#!/usr/bin/env bash
# =============================================================================
# samba-ad-entrypoint - first start: provision CORP.TEST.LOCAL and seed the
# DC01 account layout; every start: run samba (AD DC) in the foreground.
#
#   * Passwords come from compose secrets (/run/secrets/*, mounted from
#     lab/pam/.secrets/test/, 0600) - never from argv, never printed.
#   * NOT privileged: Samba keeps NT ACLs (sysvol) in the security.NTACL
#     xattr, and writing security.* xattrs needs CAP_SYS_ADMIN. The xattr_tdb
#     VFS module stores them in private/xattr.tdb instead, so provisioning
#     works in an unprivileged container. (samba-tool 4.22 no longer has the
#     old `--use-xattrs=no` switch; this is what it used to configure.)
#   * TLS: Samba would self-generate a CA + host certificate in private/tls,
#     but Vault (Go crypto/x509) refuses it: the CA has a NEGATIVE serial
#     number ("failed to parse certificate x509: negative serial number") and
#     the host certificate names dc01.corp.test.local only in the CN, with no
#     subjectAltName (Go ignores the CN). So this script plays AD CS instead:
#     a one-off lab root CA signs a DC certificate with SAN
#     DNS:dc01.corp.test.local, written to the paths Samba reads by default
#     (private/tls/{ca,cert,key}.pem). The CA key is deleted after signing.
#     e2e.sh hands ca.pem to Vault, as 03-Get-LdapsCaCert.ps1 does on DC01.
#   * old password allowed period = 0: by default a Samba DC keeps accepting
#     the PREVIOUS password for 60 minutes after a reset (Windows has a
#     shorter NTLM-only window: OldPasswordAllowedPeriod, default 5 min after
#     a change per KB906305; verify: whether it applies to admin resets).
#     e2e.sh asserts that
#     a rotated-away password stops working, so the window is closed here.
# =============================================================================
set -euo pipefail

REALM="${SAMBA_REALM:-CORP.TEST.LOCAL}"
DOMAIN="${SAMBA_DOMAIN:-CORP}"
STATE=/var/lib/samba
MARKER="$STATE/.provisioned"
SAVED_CONF="$STATE/smb.conf.dc"   # /etc/samba is not on the volume

log() { printf '[samba-ad %s] %s\n' "$(date -u +%H:%M:%SZ)" "$*"; }

issue_dc_certificate() { # lab root CA -> DC certificate (SAN = $1), Samba's default paths
  local fqdn="$1" tls="$STATE/private/tls" work
  work=$(mktemp -d)
  mkdir -p "$tls"
  cat > "$work/ca.cnf" <<CNF
[req]
distinguished_name = dn
prompt = no
x509_extensions = ext
[dn]
O = Contoso Test Lab
CN = CORP Test Root CA
[ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
CNF
  cat > "$work/dc.ext" <<EXT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:${fqdn}, DNS:${fqdn%%.*}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EXT
  openssl req -x509 -new -config "$work/ca.cnf" -newkey rsa:3072 -nodes -days 825 -sha256 \
    -keyout "$work/ca-key.pem" -out "$tls/ca.pem" 2>/dev/null
  openssl req -new -newkey rsa:3072 -nodes -subj "/CN=${fqdn}" \
    -keyout "$tls/key.pem" -out "$work/dc.csr" 2>/dev/null
  # OpenSSL 3 picks a random POSITIVE serial when none is given.
  openssl x509 -req -in "$work/dc.csr" -CA "$tls/ca.pem" -CAkey "$work/ca-key.pem" \
    -days 825 -sha256 -extfile "$work/dc.ext" -out "$tls/cert.pem" 2>/dev/null
  rm -rf "$work"                      # CA private key included: nothing else is ever signed
  chmod 0600 "$tls/key.pem"           # samba refuses a key readable by others
  chmod 0644 "$tls/ca.pem" "$tls/cert.pem"
  openssl verify -CAfile "$tls/ca.pem" -verify_hostname "$fqdn" "$tls/cert.pem" >/dev/null
  touch "$tls/.lab-ca-issued"
  log "Issued LDAPS certificate for $fqdn (lab root CA: private/tls/ca.pem)"
}

expected_fqdn="$(hostname -s).${REALM,,}"
[[ "$(hostname -f 2>/dev/null || true)" == "$expected_fqdn" ]] \
  || log "WARNING: hostname -f is not $expected_fqdn (set hostname/domainname in compose)"

if [[ ! -f "$MARKER" ]]; then
  # A missing marker with data present means an earlier bootstrap died half
  # way. Test DC: start over rather than run on a half-built directory.
  if [[ -e "$STATE/private/sam.ldb" ]]; then
    log "Incomplete earlier provision found - wiping and starting over"
    find "$STATE" -mindepth 1 -delete
  fi
  mkdir -p "$STATE/private"
  rm -f /etc/samba/smb.conf

  log "Provisioning realm $REALM (domain $DOMAIN, SAMBA_INTERNAL DNS)"
  # samba-tool only takes the Administrator password as an argument, so give
  # it a throwaway that is never stored or printed; seed-accounts.py replaces
  # it straight away with the value from the secret file.
  throwaway="Tw-$(openssl rand -hex 16)-9Z"
  samba-tool domain provision \
    --realm="$REALM" --domain="$DOMAIN" --server-role=dc \
    --dns-backend=SAMBA_INTERNAL --use-rfc2307 \
    --option="vfs objects = dfs_samba4 acl_xattr xattr_tdb" \
    --option="xattr_tdb:file = $STATE/private/xattr.tdb" \
    --adminpass="$throwaway" 2>&1 \
    | { grep -v -i -e 'password' -e 'Update [0-9]*:' || true; }   # never log a password
  unset throwaway
  [[ -f "$STATE/private/sam.ldb" ]] || { log "provision failed"; exit 1; }

  log "Seeding OUs and PAM accounts (layout of 02-Configure-Domain.ps1)"
  python3 /usr/local/lib/samba-ad/seed-accounts.py

  cp /etc/samba/smb.conf "$SAVED_CONF"
  touch "$MARKER"
  log "Bootstrap complete"
fi

# Also on later starts, so a volume provisioned before these steps gets fixed.
[[ -f "$STATE/private/tls/.lab-ca-issued" ]] || issue_dc_certificate "$expected_fqdn"
# Not persisted by `provision --option`, so set it in the saved smb.conf.
grep -q '^[[:space:]]*old password allowed period' "$SAVED_CONF" \
  || sed -i '/^\[global\]/a\	old password allowed period = 0' "$SAVED_CONF"

cp -f "$SAVED_CONF" /etc/samba/smb.conf
cp -f "$STATE/private/krb5.conf" /etc/krb5.conf

log "Starting samba (AD DC) in the foreground"
exec samba --foreground --no-process-group --debug-stdout
