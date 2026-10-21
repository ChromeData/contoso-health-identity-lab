# =============================================================================
# lab/pam/rdp-target/Dockerfile - a LINUX xrdp STAND-IN for an RDP session to
# DC01 (the lab's Windows Server domain controller), for the Samba AD harness.
# -----------------------------------------------------------------------------
# Samba AD has no RDP, so without this the brokered, recorded RDP path
# (psm-session.sh -> Guacamole -> guacd -> RDP) could only run against DC01 in
# Azure. This container closes that gap WITHOUT pretending to be Windows:
#
#   * xrdp 0.10 + xorgxrdp (Debian packages), TLS security layer. No NLA:
#     xrdp has none, so guacd connects with security=tls, not DC01's nla.
#   * The ONLY way in is an AD account's DOMAIN password, checked by Kerberos
#     (pam_krb5, AS-REQ) against the Samba AD DC - the same tier0-admin-0N
#     account psm-session.sh checks out of Vault and injects into Guacamole.
#     The local accounts exist only so a session has a uid and a home; their
#     local password field is "*" (no local password can match). After the
#     check-in rotation the injected password stops working here too.
#   * Only members of rdp-admins may open a session (sesman
#     AlwaysGroupCheck); root may not. Clipboard and drive redirection off.
#   * The session is ONE xterm, no desktop; typing `exit` ends the session
#     and xrdp drops the connection, so a scripted session ends cleanly.
#
# Built from the same pinned Debian image as pam-tools / ssh-target / the Samba
# DC, pinned here by tag AND digest (the multi-arch index digest). TEST/LAB
# ONLY: compose profile "rdp", never published on a host port (guacd reaches
# it on the project network). README: "RDP recording without DC01".
# =============================================================================
FROM debian:trixie-20260918-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
#checkov:skip=CKV_DOCKER_1:This IS the RDP target; 3389 is never published to the host (compose has no ports), only guacd reaches it.
#checkov:skip=CKV_DOCKER_3:xrdp-sesman must start as root to authenticate users (PAM) and start their sessions as them.

# xrdp, xorgxrdp   RDP server + its Xorg backend (headless, dummy video)
# xterm, xfonts-base  the session: one terminal, core fonts
# libpam-krb5      PAM -> Kerberos AS-REQ against the AD DC (the domain password)
# krb5-user        kinit: the harness checks the injected password (and, after
#                  check-in, that the old one is refused) from here
# openssl          a fresh self-signed TLS certificate per container start
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      xrdp xorgxrdp xterm xfonts-base libpam-krb5 krb5-user openssl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 # The package ships a snakeoil certificate and RSA keys made at BUILD time
 # (every container would share them); the entrypoint makes fresh ones.
 && rm -f /etc/xrdp/cert.pem /etc/xrdp/key.pem /etc/xrdp/rsakeys.ini \
 && groupadd --system rdp-admins

COPY xrdp.ini sesman.ini /etc/xrdp/
COPY startwm.sh /etc/xrdp/startwm.sh
COPY xrdp-sesman.pam /etc/pam.d/xrdp-sesman
COPY entrypoint.sh /usr/local/sbin/rdp-target-entrypoint
RUN chmod 0644 /etc/xrdp/xrdp.ini /etc/xrdp/sesman.ini /etc/pam.d/xrdp-sesman \
 && chmod 0755 /etc/xrdp/startwm.sh /usr/local/sbin/rdp-target-entrypoint

EXPOSE 3389
# Healthy = a socket LISTENS on 3389 (read from /proc, so the probe opens no
# RDP connection: a bare TCP connect makes xrdp log an X.224 error every time).
HEALTHCHECK --interval=5s --timeout=3s --retries=12 CMD ["sh", "-c", "grep -qE ':0D3D [0-9A-F]+:0000 0A ' /proc/net/tcp /proc/net/tcp6"]
ENTRYPOINT ["/usr/local/sbin/rdp-target-entrypoint"]
