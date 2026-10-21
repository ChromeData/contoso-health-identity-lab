#!/usr/bin/env bash
# rdp-target entrypoint: Kerberos realm + KDC from the DC mapping, the AD
# accounts' local (uid-only) entries, a fresh TLS certificate and RSA keys,
# then xrdp-sesman + xrdp in the foreground (logs to stdout = `docker compose
# logs rdp-target`). Fails closed: without a DC there is no way to log in, so
# it does not start.
set -euo pipefail

# DC_FQDN comes from .env (vault-onboard-ad.sh / test/e2e.sh); the name
# resolves only through compose's extra_hosts mapping, as for Vault.
: "${DC_FQDN:?rdp-target: DC_FQDN is empty - onboard a DC first (vault-onboard-ad.sh or test/e2e.sh)}"
[[ "$DC_FQDN" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]] || { echo "rdp-target: DC_FQDN '$DC_FQDN' is not a host name" >&2; exit 1; }
DOMAIN="${DC_FQDN#*.}"
REALM=$(printf '%s' "$DOMAIN" | tr '[:lower:]' '[:upper:]')
cat > /etc/krb5.conf <<KRB
[libdefaults]
    default_realm = $REALM
    dns_lookup_kdc = false
    dns_lookup_realm = false
    rdns = false
    dns_canonicalize_hostname = false
    udp_preference_limit = 1
[realms]
    $REALM = {
        kdc = $DC_FQDN
    }
[domain_realm]
    .$DOMAIN = $REALM
    $DOMAIN = $REALM
KRB
chmod 0644 /etc/krb5.conf

# One local entry per AD account that may RDP in (no local password: "*").
for u in ${RDP_AD_USERS:-tier0-admin-01 tier0-admin-02}; do
  [[ "$u" =~ ^[a-z][a-z0-9._-]{1,30}$ ]] || { echo "rdp-target: '$u' is not a valid account name" >&2; exit 1; }
  id "$u" >/dev/null 2>&1 || useradd --create-home --shell /bin/bash --groups rdp-admins "$u"
  usermod -p '*' "$u"
done

# Fresh TLS certificate (guacd: ignore-cert, as for DC01's self-signed RDP
# certificate in the lab) and RSA keys, per container - never baked into the image.
mkdir -p /etc/xrdp/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=rdp-target" \
  -keyout /etc/xrdp/tls/key.pem -out /etc/xrdp/tls/cert.pem >/dev/null 2>&1
chown -R root:xrdp /etc/xrdp/tls && chmod 0750 /etc/xrdp/tls && chmod 0640 /etc/xrdp/tls/key.pem && chmod 0644 /etc/xrdp/tls/cert.pem
xrdp-keygen xrdp /etc/xrdp/rsakeys.ini >/dev/null 2>&1 || true   # classic RDP keys; unused with security_layer=tls
mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix
rm -f /run/xrdp/*.pid /var/run/xrdp/*.pid 2>/dev/null || true
echo "rdp-target: Linux xrdp stand-in for DC01; Kerberos realm $REALM via $DC_FQDN; RDP users: ${RDP_AD_USERS:-tier0-admin-01 tier0-admin-02}" >&2

# Both daemons in the foreground; if either dies, the container stops.
xrdp-sesman --nodaemon &
xrdp --nodaemon &
wait -n
echo "rdp-target: xrdp or xrdp-sesman exited" >&2
exit 1
