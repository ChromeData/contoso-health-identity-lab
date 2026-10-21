# =============================================================================
# lab/pam/ha/unsealer.hcl - the transit "unsealer" Vault for the HA cluster.
# STAND-IN for Azure Key Vault (seal "azurekeyvault", README "HA/DR"): it holds
# the key that wraps the cluster's root key, so cluster nodes unseal
# themselves after a restart with no human and no Shamir shares.
#
# Not dev mode: file storage on a volume, 1 key share (LAB ONLY), unsealed by
# ./vault-ha.sh up. A dev-mode unsealer would lose the transit key on its
# first restart and with it every snapshot of the cluster.
# =============================================================================
ui            = false
disable_mlock = true
api_addr      = "http://vault-unsealer:8200"

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}
