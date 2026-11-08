# Vault server config for the lab stand-in (NOT dev mode: real init/unseal,
# persistent storage, audit log - the parts that map to a managed vault such as Azure Key Vault).
ui            = true
disable_mlock = false

storage "file" {
  path = "/vault/file"
}

# TLS is terminated nowhere because the listener is bound to the host's
# loopback only (see docker-compose ports). Production: TLS on, always.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr = "http://127.0.0.1:8200"
