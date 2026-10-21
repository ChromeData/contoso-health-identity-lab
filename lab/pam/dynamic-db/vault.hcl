# Vault server config for the dynamic-database segment (contoso-dyndb).
# Same shape as ../vault/vault.hcl: NOT dev mode - real init/unseal,
# persistent storage, and the audit log setup.sh turns on.
ui            = true
disable_mlock = false

storage "file" {
  path = "/vault/file"
}

# Plain HTTP because the listener is published on the host's loopback only
# (docker-compose.dynamic-db.yml). Production: TLS on, always.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = "http://127.0.0.1:8220"
