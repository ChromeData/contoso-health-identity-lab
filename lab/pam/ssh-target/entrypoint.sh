#!/usr/bin/env bash
# ssh-target entrypoint: fresh host key, Vault's SSH CA public key, then sshd
# in the foreground (logs to stderr = `docker compose logs ssh-target`).
# Fails closed: without the CA key there is no way in, so do not start.
set -euo pipefail

VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
SSH_CA_MOUNT="${SSH_CA_MOUNT:-ssh-client-signer}"

[[ -s /etc/ssh/ssh_host_ed25519_key ]] || ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key

# public_key is an unauthenticated endpoint by design: the CA's PUBLIC half
# is meant to be distributed to every host that trusts it.
for _ in $(seq 1 30); do
  if curl -fsS "$VAULT_ADDR/v1/$SSH_CA_MOUNT/public_key" -o /etc/ssh/trusted-user-ca-keys.pem.tmp \
     && grep -q '^ssh-' /etc/ssh/trusted-user-ca-keys.pem.tmp; then
    mv /etc/ssh/trusted-user-ca-keys.pem.tmp /etc/ssh/trusted-user-ca-keys.pem
    break
  fi
  sleep 2
done
[[ -s /etc/ssh/trusted-user-ca-keys.pem ]] || { echo "ssh-target: no SSH CA public key at $VAULT_ADDR/v1/$SSH_CA_MOUNT/public_key (run ./psm-ssh.sh setup)" >&2; exit 1; }
chmod 0644 /etc/ssh/trusted-user-ca-keys.pem
echo "ssh-target: trusting user certificates from Vault CA $(awk '{print $1}' /etc/ssh/trusted-user-ca-keys.pem)" >&2

exec /usr/sbin/sshd -D -e
