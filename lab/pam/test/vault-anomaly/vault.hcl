# Vault server config for the vault-anomaly harness (compose project
# contoso-vaultanom, test/e2e-vault-anomaly.sh). Same shape as ../../vault/vault.hcl:
# NOT dev mode - real init/unseal, persistent storage, and the file audit
# device the harness turns on (its records are what the test asserts on).
ui            = false
disable_mlock = false

storage "file" {
  path = "/vault/file"
}

# Plain HTTP because the listener is published on the host's loopback only
# (test/docker-compose.vault-anomaly.yml). Production: TLS on, always.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = "http://127.0.0.1:8230"
