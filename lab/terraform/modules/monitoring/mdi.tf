# =============================================================================
# modules/monitoring :: mdi.tf
# -----------------------------------------------------------------------------
# Microsoft Defender for Identity (MDI) - the native on-prem AD-attack
# detection layer (ADR 0023). MDI is the PRIMARY detector for the native
# signatures (Kerberoasting, DCSync, lateral movement, reconnaissance) because
# it is purpose-built and maintained by Microsoft. The lab's four hand-written
# SecurityEvent rules are kept as the portable, offline-testable TWINS of those
# signatures:
#   lab/kql/kerberoast-rc4-service-ticket.kql
#   lab/kql/dcsync-replication-request.kql
#   lab/kql/ad-privileged-group-change.kql
#   (the recon half of tier0-logon-without-checkout.kql)
# Two rules stay genuinely custom, because they correlate against signals MDI
# cannot see, and are NOT twins:
#   tier0-logon-without-checkout.kql   (joins the PAM Vault check-out feed)
#   dc-logon-outside-operator-allowlist.kql (judges the operator_ips allowlist)
#
# WHAT IS CODIFIABLE HERE (and what is NOT):
#   * The sensor on DC01, the MDI workspace, the directory service account and
#     the Defender licence (free 90-day trial) are PORTAL / HUMAN steps: the
#     azurerm / azuread providers cannot create an MDI workspace or install a
#     sensor. They live in the runbook
#     (lab/docs/runbooks/deploy-defender-for-identity-dc01.md), the same way
#     Cloud Sync (lab/scripts/dc) and the AWS permission set (lab/terraform/aws,
#     human-applied root) are human steps the docs carry.
#   * The ONE piece Terraform can express is the wiring that lands MDI alerts
#     in the SAME Log Analytics workspace the KQL rules use. There is no
#     standalone MDI Sentinel connector any more: MDI alerts reach Microsoft
#     Sentinel through the Microsoft Defender XDR connector, into the
#     SecurityAlert / SecurityIncident tables. That connector IS an azurerm
#     resource, so it is codified below (gated by enable_defender_for_identity,
#     which needs enable_sentinel: the connector is a Sentinel feature).
#
# verify (first apply, because the unified portal changes this):
#   * Once the workspace is onboarded to the unified Defender portal, the
#     Defender XDR connection may be MANAGED there automatically, and creating
#     azurerm_sentinel_data_connector_microsoft_threat_protection by hand can
#     conflict. If so, drop this resource and keep enable_defender_for_identity
#     as the flag the runbook reads (the connector becomes a portal step too).
#   * The connector streams ALL Defender XDR product alerts, not only MDI; MDI
#     is one source. The notify automation rule (main.tf) filters to lab
#     analytic-rule ids, so an MDI / Defender XDR incident is not double-
#     notified - MDI has its own response actions.
#   * The tenant must have MDI provisioned and the sensor Healthy before the
#     connector carries any MDI alert (runbook step order).
# =============================================================================

resource "azurerm_sentinel_data_connector_microsoft_threat_protection" "mdi" {
  # The connector is a Sentinel feature over an onboarded workspace, so it
  # needs enable_sentinel; the flag stages it off until a human has run the
  # runbook (trial started, sensor Healthy on DC01).
  count = var.enable_sentinel && var.enable_defender_for_identity ? 1 : 0

  name                       = "defender-xdr-mdi"
  log_analytics_workspace_id = azurerm_sentinel_log_analytics_workspace_onboarding.this[0].workspace_id
  # tenant_id is left to the provider default (the workspace's tenant). The
  # alerts land in SecurityAlert, where MDI's Kerberoasting / DCSync / lateral-
  # movement / recon detections sit beside the twin KQL rules' incidents.
}
