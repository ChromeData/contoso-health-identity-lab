# =============================================================================
# scanner self-test :: fixtures/good  -  the clean twin of fixtures/bad.
# -----------------------------------------------------------------------------
# The same resource with the exposure removed: RDP only from one operator
# /32 (documentation range 203.0.113.0/24, RFC 5737), as ADR 0013 allows for
# DC01. The self-test FAILS if Checkov flags anything here or TruffleHog
# finds a secret: a gate that also blocks clean code gets switched off.
# Outside lab/terraform and in no Terraform root: never planned or applied.
# =============================================================================

resource "azurerm_network_security_group" "selftest_good" {
  name                = "nsg-selftest-good"
  location            = "eastus2"
  resource_group_name = "rg-selftest-never-applied"

  security_rule {
    name                       = "rdp-from-operator-only"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "203.0.113.7/32"
    destination_address_prefix = "*"
  }
}
