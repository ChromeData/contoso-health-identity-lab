# =============================================================================
# lab/pam/ssh-target/Dockerfile - a small Linux server for the Vault SSH CA
# segment (stands in for a Tier-1 Linux host; PAM equivalent: a target
# reached through PSM for SSH / PSMP with an ephemeral credential).
#
# The ONLY way in is an OpenSSH user certificate signed by Vault's SSH CA:
#   * TrustedUserCAKeys  = Vault's CA public key, fetched at start from
#                          http://vault:8200/v1/<mount>/public_key
#   * AuthorizedPrincipalsFile maps the certificate principal "linux-admin"
#     to the local account labadmin (no authorized_keys anywhere)
#   * passwords and keyboard-interactive are off; root login is off
# sshd logs at VERBOSE, so every login line names the certificate's key ID
# (which Vault fills with the requesting token's display name = the
# operator) and serial: the "who" survives to the target's own log.
#
# Built from the same pinned Debian image as pam-tools. TEST/LAB ONLY:
# started by `docker compose --profile ssh`, never published on a host port.
# =============================================================================
FROM debian:trixie-20260918-slim
#checkov:skip=CKV_DOCKER_1:This IS the SSH target; port 22 is never published to the host (compose has no ports), only guacd and pam-tools reach it.
#checkov:skip=CKV_DOCKER_3:sshd must start as root to switch to the logged-in user (privilege separation); no other process runs.

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      openssh-server curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* /etc/ssh/ssh_host_* \
 && useradd --create-home --shell /bin/bash labadmin \
 # No usable password: "*", not useradd's "!". With UsePAM no, OpenSSH treats
 # a "!" shadow entry as a LOCKED account and refuses even certificate logins.
 && usermod -p '*' labadmin \
 && mkdir -p /run/sshd /etc/ssh/auth_principals \
 && printf 'linux-admin\n' > /etc/ssh/auth_principals/labadmin \
 && chmod 0644 /etc/ssh/auth_principals/labadmin

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/sbin/ssh-target-entrypoint
RUN chmod 0755 /usr/local/sbin/ssh-target-entrypoint && chmod 0644 /etc/ssh/sshd_config

EXPOSE 22
# Healthy = sshd accepts TCP on 22 (bash's /dev/tcp: no extra package).
HEALTHCHECK --interval=10s --timeout=3s --retries=6 CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/22"]
ENTRYPOINT ["/usr/local/sbin/ssh-target-entrypoint"]
