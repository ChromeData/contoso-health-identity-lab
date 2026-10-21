# =============================================================================
# lab/pam/test/samba-ad/Dockerfile - a REAL Active Directory DC for rehearsal
# -----------------------------------------------------------------------------
# Samba 4 in AD DC mode, built from Debian's own apt repository on a Docker
# Official Image (no third-party Samba images). It stands in for DC01 so the
# PAM scripts can be exercised end to end without Azure: real LDAPS, real
# unicodePwd resets, real pwdLastSet - the same protocol surface Vault's LDAP
# secrets engine uses against Windows AD.
#
#   realm CORP.TEST.LOCAL   domain CORP   host dc01.corp.test.local
#   OU=ServiceAccounts     svc-vault-rotator, svc-backup
#   OU=PrivilegedAccounts  tier0-admin-01/02 (Domain Admins)
#
# TEST HARNESS ONLY - started by lab/pam/test/e2e.sh, never by pam-up.sh.
# =============================================================================
FROM debian:trixie-20260918-slim

# samba-ad-dc        the AD DC role (samba binary, dsdb modules)
# samba-ad-provision schema + provision templates (only a Recommends of
#                    samba-ad-dc, so it must be named with --no-install-recommends)
# winbind            required by the AD DC for idmap / ntlm_auth
# krb5-user          kinit/klist for poking at the KDC by hand
# ldb-tools          ldbsearch against sam.ldb (pwdLastSet assertions)
# ldap-utils         ldapwhoami / ldapsearch over LDAPS (bind assertions)
# openssl            inspect the auto-generated LDAPS certificate
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      samba-ad-dc samba-ad-provision winbind krb5-user ldb-tools ldap-utils openssl \
 && rm -rf /var/lib/apt/lists/* \
 # The package ships a member-server smb.conf; provisioning writes the DC one.
 && rm -f /etc/samba/smb.conf

COPY entrypoint.sh /usr/local/sbin/samba-ad-entrypoint
COPY seed-accounts.py /usr/local/lib/samba-ad/seed-accounts.py
RUN chmod 0755 /usr/local/sbin/samba-ad-entrypoint

# Directory database, sysvol, generated smb.conf copy and the TLS material.
VOLUME ["/var/lib/samba"]

# LDAPS is what Vault talks; the rest is what a DC normally listens on.
EXPOSE 53 88 135 389 445 464 636 3268 3269

ENTRYPOINT ["/usr/local/sbin/samba-ad-entrypoint"]
