# Vault server config for the scale harness (compose project contoso-pamscale,
# test/e2e-scale.sh). Same shape as ../../vault/vault.hcl: NOT dev mode - real
# init/unseal, persistent storage; the harness turns the file audit device on,
# so the measured throughput includes audit logging, as in production.
ui            = false
disable_mlock = false

storage "file" {
  path = "/vault/file"
}

# Plain HTTP because the listener is published on the host's loopback only
# (test/docker-compose.pam-scale.yml). Production: TLS on, always.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = "http://127.0.0.1:8240"
