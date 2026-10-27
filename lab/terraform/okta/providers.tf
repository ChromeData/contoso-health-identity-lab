# =============================================================================
# okta :: providers.tf
# -----------------------------------------------------------------------------
# Applied LOCALLY by a human admin of the Okta org, never by CI (same rule as
# lab/terraform/aws and envs/bootstrap). The pipeline's identities are Entra
# and Azure only; an Okta API token never enters GitHub.
#
# AUTHENTICATION: the API token comes from the environment variable
# OKTA_API_TOKEN in the applying human's shell (the provider reads it when
# api_token is unset). There is NO api_token argument here and there must
# never be: no Okta token in code, tfvars, state or the shell history
# (`read -s OKTA_API_TOKEN && export OKTA_API_TOKEN`). Integrator Free issues
# SSWS API tokens (Security -> API -> Tokens); a token inherits the admin's
# rights and expires after 30 days unused, so the human who applies is the
# human whose name the Okta System Log shows. [prod] an OAuth 2.0 service app
# with scoped grants (okta.idps.manage, okta.policies.manage, okta.groups.manage,
# okta.apps.manage) and a private key, which the provider also supports
# (client_id / private_key / scopes).
# =============================================================================

provider "okta" {
  org_name = var.okta_org_name
  base_url = var.okta_base_url
}
