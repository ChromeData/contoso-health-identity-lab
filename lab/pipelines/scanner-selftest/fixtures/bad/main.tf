# =============================================================================
# scanner self-test :: fixtures/bad  -  DELIBERATELY UNSAFE. Never "fix" it.
# -----------------------------------------------------------------------------
# This folder exists to prove the merge gate's scanners can fail. The
# self-test (../../selftest.sh, CI job "scanner positive control") runs them
# on it and FAILS if either reports zero findings:
#   * Checkov (same image and framework as the gate) must flag the network
#     rules below: RDP and SSH open to the whole internet, the exposure
#     ADR 0013 forbids for DC01.
#   * TruffleHog must find the private key the self-test GENERATES into a
#     temporary copy of this folder at run time (planted-key.pem). No secret,
#     real or fake, is committed here, so the repo's own secret scan and
#     GitHub push protection never see one.
# It is outside lab/terraform on purpose: the gate's Checkov job scans
# lab/terraform only, so this file can never block a real merge, and no
# Terraform root includes it (nothing here is ever planned or applied).
# =============================================================================

resource "azurerm_network_security_group" "selftest_bad" {
  name                = "nsg-selftest-bad"
  location            = "eastus2"
  resource_group_name = "rg-selftest-never-applied"

  # Checkov CKV_AZURE_9: RDP (3389) reachable from the internet.
  security_rule {
    name                       = "rdp-from-anywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # Checkov CKV_AZURE_10: SSH (22) reachable from the internet.
  security_rule {
    name                       = "ssh-from-internet"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}
