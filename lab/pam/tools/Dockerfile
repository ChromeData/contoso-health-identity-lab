# =============================================================================
# lab/pam/tools/Dockerfile - the PAM operations toolbox (pam-tools image)
# -----------------------------------------------------------------------------
# One small image, three jobs, so the host needs nothing beyond docker + jq:
#
#   discover.py         AD discovery over LDAPS (ldapsearch, paged), run by
#                       ../discover.sh through `docker compose run pam-tools`.
#                       The container gets the same DC host mapping and AD
#                       root CA as Vault, so it reaches DC01 (or the Samba
#                       test DC) exactly the way Vault does.
#   mock_servicenow.py  the itsm-mock service: a ServiceNow Table API v2
#                       stand-in that psm-session.sh validates tickets against
#                       (CyberArk's "ticketing integration" moment).
#   ldapwhoami / ssh    reconcile.sh's CPM-style "verify" bind and the
#                       SSH certificate checks in test/e2e.sh.
#
# Debian's own packages on the same pinned Docker Official Image the Samba
# test DC uses (already in the local cache, one base to patch). Scripts are
# bind-mounted read-only, not baked in, so editing them needs no rebuild.
# Runs as an unprivileged user: nothing here needs root.
# =============================================================================
FROM debian:trixie-20260918-slim
#checkov:skip=CKV_DOCKER_2:Health is per role: compose gives itsm-mock its HTTP healthcheck; the discovery/verify role is a one-shot `compose run`.

# ldap-utils       ldapsearch / ldapwhoami (discovery, verify binds)
# python3          discover.py classification, the ITSM mock (stdlib only)
# openssh-client   ssh + ssh-keygen for the Vault SSH CA checks
# curl, jq         Vault public-key fetch, JSON handling in shell steps
# ca-certificates  public CA bundle (the AD root CA is mounted separately)
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ldap-utils python3 openssh-client curl jq ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin pamtools

USER 10001:10001
WORKDIR /pam
