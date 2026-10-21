<#
.SYNOPSIS
    Runs every post-apply step - the tenant configuration the Terraform
    providers cannot express - in dependency order, for exactly the staging
    flags that are ON. Dry-run by default.

.DESCRIPTION
    After `terraform apply` of lab/terraform/envs/dev, several Graph objects
    still have to be created by script (access-review definitions, the B2B
    connected organization, the authentication-methods policy, the
    authentication context + CA021, the Global Administrator PIM policy, the
    app management + consent policies, PIM eligibility, the Agent ID). Each
    script is idempotent and safe on its own; what goes wrong in practice is
    ORDER and FORGETTING one. This script reads the Terraform outputs once,
    decides which steps apply (a step whose feature flag is off has a null
    output and is skipped), and runs them in this order:

      #  step                 script                                   runs when (flag / output)
      1  baseline (GATE)      01-Verify-Baseline.ps1                   enable_premium
      1b admin-accounts       New-AdminAccounts.ps1 (lab/iga/          enable_premium
                              admin-accounts.json -> Admin-Accounts)
      2  auth-methods         Set-AuthenticationMethodsPolicy.ps1      enable_premium
      3  auth-context         Set-AuthContextPolicies.ps1              enable_pim_auth_context
      3b protected-actions    Set-AuthContextPolicies.ps1 (CA023, c2)  enable_protected_actions_ca
                              + MANUAL: bind c2 to the protected actions (only once CA023 is enforced)
      4  token-protection     Set-TokenProtectionPolicy.ps1 (CA011)    enable_intune_vm + premium (CA005 pilot device)
      5  auto-assignment      Set-AutoAssignmentPolicies.ps1           enable_governance
      6  sod                  Set-IncompatibleAccessPackages.ps1       enable_governance
      7  lifecycle-workflows  New-LifecycleWorkflows.ps1               enable_governance
      8  directory-role-pim   Set-DirectoryRolePimPolicies.ps1         enable_global_admin_pim_policy
      9  pim-eligibility      Set-PimGroupEligibility.ps1 (per group)  -PimEligibility given
     10  helpdesk-au          (manual Graph PATCH: dynamic AU rule)    enable_helpdesk_au_scoping
     11  restricted-au        New-RestrictedAdminUnit.ps1 (RMAU-VIP)   enable_helpdesk_au_scoping + -VipUserPrincipalNames
     12  access-reviews       New-AccessReviewDefinitions.ps1          enable_access_reviews_privileged / _inactive
     13  b2b                  New-B2BConnectedOrganization.ps1         enable_b2b_governance
     14  external-collab      Set-ExternalCollaboration.ps1            enable_b2b_governance
     15  aws-saml-cert        (manual command from Terraform output)   enable_sso_apps
     16  app-governance       Set-AppGovernancePolicy.ps1              enable_nhi_governance
     17  consent              Set-ConsentPolicy.ps1                    enable_nhi_governance
     18  agent-identity       New-AgentIdentity.ps1                    enable_agent_identity
     19  build-account (LAST) Convert-BuildAccountToEligible.ps1       enable_global_admin_pim_policy + -BuildAccountUpn,
                                                                       and only if NO earlier step failed
     20  manual hand-offs     containment playbook, vault feed, evidence-store writer grant,
                              guacamole-psm client id                  their flags

    WHY THIS ORDER
      1 first and a GATE: every later step changes sign-in behaviour, so
        break-glass must provably be excluded from every CA policy (exit 1 =
        stop everything).
      1b before 2 and 9: the adm- accounts (and, with -BuildAccountUpn, the
        build account) must be in the STANDING Admin-Accounts group before
        the admin passkey profile targets it, and must exist before anyone
        is made PIM-eligible.
      2 before anything that depends on people having passkeys (CA008 pilot,
        CA021's phishing-resistant step-up, 07-Passwordless-Rollout), and it
        re-checks the break-glass method invariants itself.
      3 before 8: the Global Administrator policy may require authentication
        context c1, which must exist and be published first (Learn: the CA
        policy before PIM uses the context). This step writes CA021 and c1.
        The Tier-0 groups' PIM policies are written by `terraform apply`,
        which runs BEFORE every post-apply step, so ordering here cannot
        protect them: Terraform refuses to hand PIM the context until the
        tenant attestation ca021_enforced_in_tenant is set - in a LATER apply,
        after this step has reported CA021 "enabled".
      5 before 6: Set-IncompatibleAccessPackages never links a package that
        has an automatic (birthright) policy, so those policies must exist
        first - a link on a birthright package could block a nurse's
        automatic grant. (Set-AccessPackageSoD.ps1 is only a forwarding shim
        now.)
      8 and 9 before 12: the privileged-review self-review guard reads PIM
        eligibility, and the first review instance should see the eligible
        members (Global Administrator eligibility included).
      13 before 14: the external-collaboration lock-down runs once the one
        open guest path (the sponsor-approved access package) exists.
      15 and 16: the app management policy (180-day certificate cap) runs AFTER
        the SSO apps exist and their SAML signing certificate is activated -
        verify: whether the cap would block a gallery app's 3-year signing
        certificate (Set-AppGovernancePolicy.ps1 notes).
      17 after 16 (both NHI), and needs App-Consent-Reviewers (Terraform).
      19 LAST, opt-in and only after a clean run: it removes the build
        account's standing Global Administrator, so every step that needs
        Global Administrator / Privileged Role Administrator must already
        have run, and its own eight checks need step 8's policy. It still
        asks for the typed UPN.

    MODES
      default    every step in its own dry-run mode: -WhatIf, or the script's
                 PLAN / preview mode (Set-AuthenticationMethodsPolicy and
                 Set-TokenProtectionPolicy without -Apply, New-AgentIdentity
                 -OfflinePreview). Steps still READ the tenant.
      -Execute   real changes. High-impact scripts still prompt (-Confirm)
                 unless you pass -Confirm:$false yourself to that script.
      -ListOnly  print the ordered plan from the outputs and stop - no Graph
                 connection at all.

    Rendered Terraform outputs handed to scripts as files (access reviews,
    B2B, CA021, the Global Administrator policy) go to a private temp folder
    that is deleted at the end. directory_role_pim_policies carries
    pim_alert_mailbox: never copy that file into the repo.

    Nothing here has run against a tenant.

.PARAMETER OutputsPath
    A saved `terraform -chdir=lab/terraform/envs/dev output -json`. Default:
    run that command (needs access to the remote state).

.PARAMETER PimEligibility
    Group mailNickname => adm- ADMIN accounts to make ELIGIBLE (PIM for
    Groups) - never a workforce account. The register lab/iga/admin-accounts.json
    records who should be eligible for what, e.g.
    @{ 'pim-tier0-ca-admins' = @('adm-ava.lin@<tenant>.onmicrosoft.com')
       'pim-tier1-helpdesk'  = @('adm-raj.patel@<tenant>.onmicrosoft.com') }
    Only privileged-iam-admins and the PIM tier groups (output
    pim_tier_group_mail_nicknames) are accepted. Empty = step skipped (the
    adm- accounts must exist first: step admin-accounts).

.PARAMETER AgentSponsorUserPrincipalName
    Accountable human for the Agent ID (New-AgentIdentity.ps1 default if empty).

.PARAMETER AcceptAgentIdPreview
    Required with -Execute to create the Agent ID (passes -AcceptPreview).

.PARAMETER AdminAllowedAaguids
    Override for the admin AAGUID list. Default: the Terraform output
    admin_fido2_allowed_aaguids (the list the admin strength - CA002 / CA021 /
    CA022 - enforces), so the key models admins may REGISTER and the models CA
    ACCEPTS stay one list. With the workforce rollout on and no list (and no
    accept_admin_synced_passkey_risk output = true),
    Set-AuthenticationMethodsPolicy.ps1 FAILs the staff target.

.PARAMETER GlobalAdminEligible
    adm- accounts to make ELIGIBLE (180 days) for Global Administrator through
    Set-DirectoryRolePimPolicies.ps1 -EligibleUserPrincipalNames. Empty = the
    role policy only. Never break-glass (the script refuses it).

.PARAMETER VipUserPrincipalNames
    VIP workforce accounts for the restricted management administrative unit
    (New-RestrictedAdminUnit.ps1 -MemberUserPrincipalNames). Empty = the
    restricted-au step is skipped: plan the RMAU-scoped support role first
    (the script's help lists the consequences of membership).

.PARAMETER BuildAccountUpn
    The tenant-creation account (admin@<tenant>.onmicrosoft.com) whose
    standing Global Administrator Convert-BuildAccountToEligible.ps1 turns
    eligible. Empty = the build-account step is skipped. It runs LAST, only
    when every earlier step succeeded, and still asks for the typed UPN.
    Also passed to admin-accounts (adds it to Admin-Accounts) and to
    auth-methods (FAILs while no passkey target covers it).

.PARAMETER Only / Skip
    Step ids to run / leave out (see the table above).

.PARAMETER ScriptRoot
    Folder holding 01-Verify-Baseline.ps1 and post-apply/. Default: this
    script's parent. (The Pester suite points it at stubs.)

.EXAMPLE
    terraform -chdir=lab/terraform/envs/dev output -json > /tmp/tf-out.json
    ./Invoke-PostApply.ps1 -OutputsPath /tmp/tf-out.json -ListOnly
    ./Invoke-PostApply.ps1 -OutputsPath /tmp/tf-out.json                  # dry run
    ./Invoke-PostApply.ps1 -OutputsPath /tmp/tf-out.json -Execute -Only access-reviews,b2b
    ./Invoke-PostApply.ps1 -OutputsPath /tmp/tf-out.json -Execute -Only auth-context   # CA021 + c1, before the PIM switch to c1
    (The saved file holds sensitive outputs - delete it afterwards; never commit it.)
#>

#Requires -Version 7.0

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputsPath = '',

    [Parameter()]
    [string]$TerraformDir = (Join-Path $PSScriptRoot '..' '..' '..' 'terraform' 'envs' 'dev'),

    [Parameter()]
    [hashtable]$PimEligibility = @{},

    [Parameter()]
    [string]$AgentSponsorUserPrincipalName = '',

    [Parameter()]
    [switch]$AcceptAgentIdPreview,

    [Parameter()]
    [string[]]$AdminAllowedAaguids = @(),

    [Parameter()]
    [string[]]$GlobalAdminEligible = @(),

    [Parameter()]
    [string[]]$VipUserPrincipalNames = @(),

    [Parameter()]
    [string]$BuildAccountUpn = '',

    [Parameter()]
    [ValidateSet('baseline', 'admin-accounts', 'auth-methods', 'auth-context', 'protected-actions', 'token-protection', 'auto-assignment', 'sod', 'lifecycle-workflows', 'directory-role-pim', 'pim-eligibility', 'helpdesk-au', 'restricted-au', 'access-reviews', 'b2b', 'external-collab', 'aws-saml-cert', 'app-governance', 'consent', 'agent-identity', 'build-account', 'manual')]
    [string[]]$Only = @(),

    [Parameter()]
    [ValidateSet('baseline', 'admin-accounts', 'auth-methods', 'auth-context', 'protected-actions', 'token-protection', 'auto-assignment', 'sod', 'lifecycle-workflows', 'directory-role-pim', 'pim-eligibility', 'helpdesk-au', 'restricted-au', 'access-reviews', 'b2b', 'external-collab', 'aws-saml-cert', 'app-governance', 'consent', 'agent-identity', 'build-account', 'manual')]
    [string[]]$Skip = @(),

    [Parameter()]
    [switch]$Execute,

    [Parameter()]
    [switch]$ListOnly,

    [Parameter()]
    [string]$ScriptRoot = (Join-Path $PSScriptRoot '..')
)

# Operator console output. Write-Host on purpose (colour, -NoNewline); every
# script-level status line goes through here, so the analyzer suppression is
# scoped to this one function, never to the file.
function Write-Console {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Interactive operator console (colour, -NoNewline): status lines for the person running the script, not pipeline data.')]
    param()
    Write-Host @args
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# =============================================================================
# Helpers
# =============================================================================
function Get-TfValue {
    # Value of one output from `terraform output -json` (null when absent).
    param([System.Collections.IDictionary]$Outputs, [string]$Name)
    if ($Outputs.Contains($Name) -and $Outputs[$Name] -is [System.Collections.IDictionary] -and $Outputs[$Name].Contains('value')) { return $Outputs[$Name]['value'] }
    return $null
}

function Test-HasValue {
    # null, '' and an empty map/list all mean "flag off / nothing rendered".
    param($Value)
    if ($null -eq $Value) { return $false }
    if ($Value -is [string]) { return $Value -ne '' }
    if ($Value -is [System.Collections.IDictionary]) { return $Value.Count -gt 0 }
    if ($Value -is [System.Collections.IEnumerable]) { return @($Value).Count -gt 0 }
    return $true
}

function ConvertTo-PlanStep {
    # RequiresClean: run only if no earlier step failed (the lockout-prone
    # build-account conversion).
    param([string]$Id, [string]$Name, [bool]$Applies, [string]$Reason, [string]$Script = '', [hashtable]$Params = @{}, [string]$Manual = '', [switch]$Gate, [switch]$RequiresClean)
    [pscustomobject]@{ Id = $Id; Name = $Name; Applies = $Applies; Reason = $Reason; Script = $Script; Params = $Params; Manual = $Manual; Gate = [bool]$Gate; RequiresClean = [bool]$RequiresClean }
}

function Split-WorkspaceId {
    # /subscriptions/<s>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<name>
    # -> @{ ResourceGroup; WorkspaceName } (empty when the id has another shape).
    param([string]$WorkspaceId)
    if ($WorkspaceId -match '(?i)/resourceGroups/(?<rg>[^/]+)/providers/Microsoft\.OperationalInsights/workspaces/(?<ws>[^/]+)$') {
        return @{ ResourceGroup = $Matches.rg; WorkspaceName = $Matches.ws }
    }
    return @{}
}

function Get-PostApplyPlan {
    # Pure: outputs + options -> ordered steps. Unit-tested offline.
    param(
        [Parameter(Mandatory)][System.Collections.IDictionary]$Outputs,
        [hashtable]$PimEligibility = @{},
        [string]$AgentSponsorUserPrincipalName = '',
        [string[]]$AdminAllowedAaguids = @(),
        [string[]]$GlobalAdminEligible = @(),
        [string[]]$VipUserPrincipalNames = @(),
        [string]$BuildAccountUpn = '',
        [bool]$Execute = $false,
        [bool]$AcceptAgentIdPreview = $false,
        [string]$WorkDir = [System.IO.Path]::GetTempPath()
    )
    $dry = -not $Execute
    $whatIf = if ($dry) { @{ WhatIf = $true } } else { @{} }
    $steps = [System.Collections.Generic.List[object]]::new()

    # 1. Baseline gate (read-only; no -WhatIf - the script has none).
    # (Select-Object, not [0]: indexing an empty array throws under StrictMode.)
    $firstBg = [string](@(Get-TfValue -Outputs $Outputs -Name 'break_glass_user_principal_names') | Where-Object { $_ } | Select-Object -First 1)
    $premium = Test-HasValue (Get-TfValue -Outputs $Outputs -Name 'break_glass_group_object_id')
    $domain = if ($firstBg -match '@(.+)$') { $Matches[1] } else { '' }
    $steps.Add((ConvertTo-PlanStep -Id 'baseline' -Name 'Break-glass excluded from every CA policy (GATE)' -Applies ($premium -and $domain -ne '') `
                -Reason $(if (-not $premium) { 'enable_premium is off' } elseif (-not $domain) { 'no break-glass UPN in the outputs' } else { 'always first' }) `
                -Script '01-Verify-Baseline.ps1' -Params @{ OnMicrosoftDomain = $domain } -Gate))

    # 1b. Admin accounts (register -> cloud-only adm- accounts -> standing
    #     Admin-Accounts group, the admin passkey target).
    $aa = $whatIf.Clone()
    if ($domain) { $aa['OnMicrosoftDomain'] = $domain }
    if ($BuildAccountUpn) { $aa['BuildAccountUpn'] = $BuildAccountUpn }
    $steps.Add((ConvertTo-PlanStep -Id 'admin-accounts' -Name 'Admin accounts (lab/iga/admin-accounts.json) -> Admin-Accounts passkey target' -Applies ($premium -and $domain -ne '') `
                -Reason $(if (-not $premium) { 'enable_premium is off' } elseif (-not $domain) { 'no break-glass UPN in the outputs (domain unknown)' } else { 'before auth-methods and PIM eligibility' }) `
                -Script 'post-apply/New-AdminAccounts.ps1' -Params $aa))

    # 2. Authentication methods (PLAN without -Apply).
    $am = @{}
    if (-not $dry) { $am['Apply'] = $true }
    if (Test-HasValue (Get-TfValue -Outputs $Outputs -Name 'all_workforce_group_object_id')) { $am['IncludeStaffRollout'] = $true }
    $caNames = Get-TfValue -Outputs $Outputs -Name 'ca_policy_display_names'
    if ($caNames -is [System.Collections.IDictionary] -and $caNames.Contains('CA006') -and $null -ne $caNames['CA006']) { $am['EnableReportSuspiciousActivity'] = $true }
    # Same AAGUID list as the admin strength (CA002 / CA021 / CA022; Terraform output) unless overridden.
    $aaguids = @(if ($AdminAllowedAaguids.Count) { $AdminAllowedAaguids } else { @(Get-TfValue -Outputs $Outputs -Name 'admin_fido2_allowed_aaguids') | Where-Object { $_ } })
    if ($aaguids.Count) { $am['AdminAllowedAaguids'] = [string[]]$aaguids }
    if ((Get-TfValue -Outputs $Outputs -Name 'accept_admin_synced_passkey_risk') -eq $true) { $am['AcceptAdminSyncedPasskeyRisk'] = $true }
    if ($BuildAccountUpn) { $am['BuildAccountUpn'] = $BuildAccountUpn }
    $steps.Add((ConvertTo-PlanStep -Id 'auth-methods' -Name 'Authentication methods policy (passkey profiles, TAP, campaign)' -Applies $premium -Reason $(if ($premium) { 'premium' } else { 'enable_premium is off' }) `
                -Script 'post-apply/Set-AuthenticationMethodsPolicy.ps1' -Params $am))

    # 3. Authentication context c1 + CA021 (Graph-managed; the script refuses a
    #    null output, so a missing output means "skip", never "run anyway").
    $ca021 = Get-TfValue -Outputs $Outputs -Name 'pim_auth_context_requests'
    $hasCa021 = Test-HasValue $ca021
    $acp = $whatIf.Clone(); $acp['RequestsPath'] = Join-Path $WorkDir 'pim_auth_context_requests.json'
    $acReason = if (-not $hasCa021) { 'enable_pim_auth_context is off' } elseif ($ca021 -is [System.Collections.IDictionary] -and $ca021['policy_state'] -eq 'enabled') { 'CA021 ENFORCED in code - run before PIM requires c1' } else { 'CA021 report-only' }
    $steps.Add((ConvertTo-PlanStep -Id 'auth-context' -Name 'Authentication context c1 + CA021 (PIM activation step-up)' -Applies $hasCa021 -Reason $acReason `
                -Script 'post-apply/Set-AuthContextPolicies.ps1' -Params $acp))

    # 3b. Protected actions: authentication context c2 + CA023 (same script),
    #     then a MANUAL binding of c2 to the protected actions - printed with
    #     its verify: note, and only meaningful once CA023 is enforced.
    $ca023 = Get-TfValue -Outputs $Outputs -Name 'protected_actions_auth_context_requests'
    $hasCa023 = Test-HasValue $ca023
    $pap = $whatIf.Clone(); $pap['RequestsPath'] = Join-Path $WorkDir 'protected_actions_auth_context_requests.json'
    $ca023Enforced = $hasCa023 -and $ca023 -is [System.Collections.IDictionary] -and $ca023['policy_state'] -eq 'enabled'
    $steps.Add((ConvertTo-PlanStep -Id 'protected-actions' -Name 'Authentication context c2 + CA023 (protected actions step-up)' -Applies $hasCa023 `
                -Reason $(if (-not $hasCa023) { 'enable_protected_actions_ca is off' } elseif ($ca023Enforced) { 'CA023 ENFORCED in code' } else { 'CA023 report-only' }) `
                -Script 'post-apply/Set-AuthContextPolicies.ps1' -Params $pap))
    $bindCtx = if ($hasCa023 -and $ca023 -is [System.Collections.IDictionary]) { [string]$ca023['auth_context_id'] } else { '' }
    $bindCmd = if ($ca023Enforced) { "Entra admin center -> Roles & admins -> Protected actions -> add microsoft.directory/conditionalAccessPolicies/basic/update + /delete and microsoft.directory/namedLocations/basic/update + /delete with authentication context '$bindCtx' (verify: Graph beta PATCH .../roleManagement/directory/resourceNamespaces/microsoft.directory/resourceActions/<id> { authenticationContextId = '$bindCtx' })" } else { '' }
    $steps.Add((ConvertTo-PlanStep -Id 'manual' -Name 'Bind the protected-actions context to CA policy / named-location changes' -Applies ($bindCmd -ne '') `
                -Reason $(if (-not $hasCa023) { 'enable_protected_actions_ca is off' } elseif (-not $ca023Enforced) { 'only once CA023 is enforced (report-only applies no step-up)' } else { 'CA023 enforced' }) -Manual $bindCmd))

    # 4. Token protection pilot (CA011, report-only): only where the CA005
    #    pilot device exists. PLAN without -Apply.
    $intune = [string](Get-TfValue -Outputs $Outputs -Name 'intune_vm_name')
    $tpApplies = $premium -and $intune -ne ''
    $tp = @{}
    if (-not $dry) { $tp['Apply'] = $true }
    $steps.Add((ConvertTo-PlanStep -Id 'token-protection' -Name 'Token protection pilot (CA011, report-only, CA005 pilot group)' -Applies $tpApplies `
                -Reason $(if (-not $premium) { 'enable_premium is off' } elseif (-not $intune) { 'enable_intune_vm is off (no CA005 pilot device)' } else { 'pilot device exists' }) `
                -Script 'post-apply/Set-TokenProtectionPolicy.ps1' -Params $tp))

    # 5-7. Governance: automatic (birthright) policies BEFORE the SoD links,
    #      which are never put on a package that has one.
    $gov = Test-HasValue (Get-TfValue -Outputs $Outputs -Name 'access_package_ids')
    $govReason = if ($gov) { 'governance' } else { 'enable_governance is off' }
    $steps.Add((ConvertTo-PlanStep -Id 'auto-assignment' -Name 'Birthright automatic assignment policies (lab/iga/birthright-rules.json)' -Applies $gov -Reason $govReason -Script 'post-apply/Set-AutoAssignmentPolicies.ps1' -Params $whatIf.Clone()))
    $steps.Add((ConvertTo-PlanStep -Id 'sod' -Name 'Access-package separation of duties (lab/iga/sod-rules.json)' -Applies $gov -Reason $govReason -Script 'post-apply/Set-IncompatibleAccessPackages.ps1' -Params $whatIf.Clone()))
    $steps.Add((ConvertTo-PlanStep -Id 'lifecycle-workflows' -Name 'Joiner + leaver Lifecycle Workflows' -Applies $gov -Reason $govReason -Script 'post-apply/New-LifecycleWorkflows.ps1' -Params $whatIf.Clone()))

    # 8. Global Administrator's own PIM policy (+ named, expiring eligibility).
    $gaPolicy = Get-TfValue -Outputs $Outputs -Name 'directory_role_pim_policies'
    $hasGa = $premium -and (Test-HasValue $gaPolicy)
    $dp = $whatIf.Clone(); $dp['PolicyPath'] = Join-Path $WorkDir 'directory_role_pim_policies.json'
    if ($GlobalAdminEligible.Count) { $dp['EligibleUserPrincipalNames'] = [string[]]$GlobalAdminEligible }
    $steps.Add((ConvertTo-PlanStep -Id 'directory-role-pim' -Name 'Global Administrator PIM policy (approval, step-up, 180-day eligibility)' -Applies $hasGa `
                -Reason $(if ($hasGa) { "policy$(if ($GlobalAdminEligible.Count) { " + $($GlobalAdminEligible.Count) eligible" } else { ' only' })" } else { 'enable_global_admin_pim_policy is off' }) `
                -Script 'post-apply/Set-DirectoryRolePimPolicies.ps1' -Params $dp))

    # 9. PIM eligibility, one invocation per group.
    $allowed = @('privileged-iam-admins') + @((Get-TfValue -Outputs $Outputs -Name 'pim_tier_group_mail_nicknames') | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { $_.Values } })
    if ($PimEligibility.Count -eq 0) {
        $steps.Add((ConvertTo-PlanStep -Id 'pim-eligibility' -Name 'PIM-for-Groups eligibility' -Applies $false -Reason 'no -PimEligibility given (the adm- admin accounts must exist first: step admin-accounts, lab/iga/admin-accounts.json)'))
    }
    foreach ($nick in @($PimEligibility.Keys | Sort-Object)) {
        $ok = $premium -and ($nick -in $allowed)
        $why = if (-not $premium) { 'enable_premium is off' } elseif ($nick -notin $allowed) { "'$nick' is not a PIM-governed group in the outputs (is enable_pim_tiers on?)" } else { 'eligible, never active' }
        $p = $whatIf.Clone(); $p['GroupMailNickname'] = $nick; $p['UserPrincipalNames'] = @($PimEligibility[$nick])
        $steps.Add((ConvertTo-PlanStep -Id 'pim-eligibility' -Name "PIM eligibility: $nick" -Applies $ok -Reason $why -Script 'post-apply/Set-PimGroupEligibility.ps1' -Params $p))
    }

    # 10-11. Help-desk scoping: the AU's dynamic rule (TENANT-TIME Graph PATCH
    #        the provider cannot express) and, opt-in, the VIP restricted
    #        management AU (immutable flag: Graph only, never Terraform).
    $auId = [string](Get-TfValue -Outputs $Outputs -Name 'pim_workforce_au_object_id')
    $auBody = [string](Get-TfValue -Outputs $Outputs -Name 'pim_workforce_au_membership_body')
    $auCmd = if ($auId -and $auBody) { "Invoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/v1.0/directory/administrativeUnits/$auId' -Body '$auBody' -ContentType 'application/json'   # AdministrativeUnit.ReadWrite.All; P1 per member for a dynamic AU" } else { '' }
    $steps.Add((ConvertTo-PlanStep -Id 'helpdesk-au' -Name 'AU-Workforce-Standard dynamic membership rule' -Applies ($auCmd -ne '') -Reason $(if ($auCmd) { 'help-desk AU scoping' } else { 'enable_helpdesk_au_scoping is off' }) -Manual $auCmd))
    $ra = $whatIf.Clone()
    if ($VipUserPrincipalNames.Count) { $ra['MemberUserPrincipalNames'] = [string[]]$VipUserPrincipalNames }
    $raApplies = ($auId -ne '') -and $VipUserPrincipalNames.Count -gt 0
    $steps.Add((ConvertTo-PlanStep -Id 'restricted-au' -Name 'VIP restricted management administrative unit (RMAU-VIP)' -Applies $raApplies `
                -Reason $(if (-not $auId) { 'enable_helpdesk_au_scoping is off' } elseif (-not $VipUserPrincipalNames.Count) { 'no -VipUserPrincipalNames (assign the RMAU-scoped support role first; see the script help)' } else { "$($VipUserPrincipalNames.Count) VIP(s)" }) `
                -Script 'post-apply/New-RestrictedAdminUnit.ps1' -Params $ra))

    # 12. Standalone access reviews (PIM-group + GA eligibility + inactive users;
    #     modules/entitlement merges modules/pim's bodies under the T1 flag).
    $reviews = Get-TfValue -Outputs $Outputs -Name 'access_review_definitions'
    $hasReviews = Test-HasValue $reviews
    $rp = $whatIf.Clone(); $rp['DefinitionsPath'] = Join-Path $WorkDir 'access_review_definitions.json'
    $steps.Add((ConvertTo-PlanStep -Id 'access-reviews' -Name 'Privileged + inactive-user access reviews' -Applies $hasReviews -Reason $(if ($hasReviews) { "$(@($reviews.Keys).Count) definition(s)" } else { 'enable_access_reviews_privileged / _inactive are off (or governance)' }) `
                -Script 'post-apply/New-AccessReviewDefinitions.ps1' -Params $rp))

    # 13-14. B2B connected organization, then the tenant's external
    #        collaboration lock-down (the package stays the one guest path).
    $b2b = Test-HasValue (Get-TfValue -Outputs $Outputs -Name 'b2b_post_apply')
    $bp = $whatIf.Clone(); $bp['PostApplyPath'] = Join-Path $WorkDir 'b2b_post_apply.json'
    $steps.Add((ConvertTo-PlanStep -Id 'b2b' -Name 'B2B connected organization + guest lifecycle' -Applies $b2b -Reason $(if ($b2b) { 'b2b governance' } else { 'enable_b2b_governance is off' }) `
                -Script 'post-apply/New-B2BConnectedOrganization.ps1' -Params $bp))
    $steps.Add((ConvertTo-PlanStep -Id 'external-collab' -Name 'External collaboration settings (who invites, guest access, no self-service sign-up)' -Applies $b2b -Reason $(if ($b2b) { 'b2b governance' } else { 'enable_b2b_governance is off' }) `
                -Script 'post-apply/Set-ExternalCollaboration.ps1' -Params $whatIf.Clone()))

    # 15. AWS SAML signing certificate activation (manual: one command).
    $cert = [string](Get-TfValue -Outputs $Outputs -Name 'aws_saml_signing_cert_activation_command')
    $steps.Add((ConvertTo-PlanStep -Id 'aws-saml-cert' -Name 'Activate the AWS SAML signing certificate' -Applies ($cert -ne '') -Reason $(if ($cert) { 'sso apps' } else { 'enable_sso_apps is off' }) -Manual $cert))

    # 16-17. NHI governance tenant policies.
    $nhi = Test-HasValue (Get-TfValue -Outputs $Outputs -Name 'app_consent_reviewers_group_object_id')
    $nhiReason = if ($nhi) { 'nhi governance' } else { 'enable_nhi_governance is off' }
    $steps.Add((ConvertTo-PlanStep -Id 'app-governance' -Name 'App management policy (no new secrets, 180-day certificates)' -Applies $nhi -Reason $nhiReason -Script 'post-apply/Set-AppGovernancePolicy.ps1' -Params $whatIf.Clone()))
    $steps.Add((ConvertTo-PlanStep -Id 'consent' -Name 'User consent policy + admin consent workflow' -Applies $nhi -Reason $nhiReason -Script 'post-apply/Set-ConsentPolicy.ps1' -Params $whatIf.Clone()))

    # 18. Agent ID (preview API: needs an explicit second key to create).
    $mi = [string](Get-TfValue -Outputs $Outputs -Name 'agent_runtime_uami_principal_id')
    $ap = @{ ManagedIdentityPrincipalId = $mi }
    if ($AgentSponsorUserPrincipalName) { $ap['SponsorUserPrincipalName'] = $AgentSponsorUserPrincipalName }
    $agentApplies = $mi -ne ''
    $agentReason = if (-not $agentApplies) { 'enable_agent_identity is off' } elseif ($dry) { 'offline preview' } elseif ($AcceptAgentIdPreview) { 'preview accepted' } else { 'preview API: pass -AcceptAgentIdPreview to create' }
    if ($dry) { $ap['OfflinePreview'] = $true }
    elseif ($AcceptAgentIdPreview) { $ap['AcceptPreview'] = $true }
    else { $agentApplies = $false }
    $steps.Add((ConvertTo-PlanStep -Id 'agent-identity' -Name 'Entra Agent ID (blueprint + agent, MI-federated, no secret)' -Applies $agentApplies -Reason $agentReason -Script 'post-apply/New-AgentIdentity.ps1' -Params $ap))

    # 19. LAST: build account standing GA -> eligible. Opt-in (-BuildAccountUpn),
    #     needs the GA policy of step 8, and runs only if nothing failed before.
    $ba = $whatIf.Clone()
    if ($BuildAccountUpn) { $ba['BuildAccountUpn'] = $BuildAccountUpn }
    if ($domain) { $ba['OnMicrosoftDomain'] = $domain }
    $ws = Split-WorkspaceId -WorkspaceId ([string](Get-TfValue -Outputs $Outputs -Name 'log_analytics_workspace_id'))
    foreach ($k in $ws.Keys) { $ba[$k] = $ws[$k] }
    $baApplies = $hasGa -and $BuildAccountUpn -ne ''
    $steps.Add((ConvertTo-PlanStep -Id 'build-account' -Name 'Build account: standing Global Administrator -> eligible (LAST)' -Applies $baApplies `
                -Reason $(if (-not $BuildAccountUpn) { 'no -BuildAccountUpn (opt-in)' } elseif (-not $hasGa) { 'enable_global_admin_pim_policy is off (its check [7/8] would refuse)' } else { 'only after a clean run; asks for the typed UPN' }) `
                -Script 'post-apply/Convert-BuildAccountToEligible.ps1' -Params $ba -RequiresClean))

    # 20. Manual hand-offs that need a human or a different tool.
    $itdr = Test-HasValue (Get-TfValue -Outputs $Outputs -Name 'itdr_rule_keys')
    $contain = Test-HasValue (Get-TfValue -Outputs $Outputs -Name 'containment_automation_rule_id')
    $steps.Add((ConvertTo-PlanStep -Id 'manual' -Name 'Containment playbook' -Applies ($itdr -and -not $contain) -Reason $(if (-not $itdr) { 'enable_itdr_detections is off' } elseif ($contain) { 'already wired' } else { 'deploy, then set TF_CONTAINMENT_PLAYBOOK_ID + enable_itdr_containment' }) `
                -Manual 'pwsh lab/scripts/monitoring/Deploy-ContainmentPlaybook.ps1 -WhatIf   # then without -WhatIf; authorize the Teams connection in the portal'))
    $vault = Get-TfValue -Outputs $Outputs -Name 'vault_ingestion'
    # vault_feed_v2_columns on -> the extended feed (Ticket / Operator /
    # ErrorText + the five extra signals) MUST be what is shipped, or every
    # Tier-0 check-out alerts as unticketed.
    $signals = [string](Get-TfValue -Outputs $Outputs -Name 'vault_ingest_signals')
    $sigArg = if ($signals -eq 'all') { ' --signals all' } else { '' }
    $vaultCmd = if (Test-HasValue $vault) { "lab/scripts/monitoring/ingest-vault-audit.sh --endpoint '$($vault['endpoint'])' --dcr-id '$($vault['dcr_immutable_id'])'$sigArg --follow 60   # after a human grants Monitoring Metrics Publisher on the DCR" } else { '' }
    $steps.Add((ConvertTo-PlanStep -Id 'manual' -Name 'Vault check-out feed -> VaultCheckout_CL' -Applies ($vaultCmd -ne '') -Reason $(if ($vaultCmd) { 'itdr telemetry' } else { 'enable_itdr_detections is off' }) -Manual $vaultCmd))
    $ev = [string](Get-TfValue -Outputs $Outputs -Name 'evidence_container_id')
    $evCmd = if ($ev) { "az role assignment create --assignee-object-id `"`$(az ad signed-in-user show --query id -o tsv)`" --assignee-principal-type User --role 'Storage Blob Data Contributor' --scope '$ev' --condition-version 2.0 --condition `"`$(terraform -chdir=lab/terraform/envs/dev output -raw evidence_writer_abac_condition)`"   # HUMAN Owner/UAA; then the WORM canary (evidence-capture-plan P3)" } else { '' }
    $steps.Add((ConvertTo-PlanStep -Id 'manual' -Name 'Evidence store writer grant (delete-denying)' -Applies ($ev -ne '') -Reason $(if ($ev) { 'evidence store' } else { 'enable_evidence_store is off' }) -Manual $evCmd))
    $guac = [string](Get-TfValue -Outputs $Outputs -Name 'guacamole_psm_client_id')
    $steps.Add((ConvertTo-PlanStep -Id 'manual' -Name 'guacamole-psm client id -> lab/pam/.env' -Applies ($guac -ne '') -Reason $(if ($guac) { 'pam oidc app' } else { 'enable_pam_oidc_app is off' }) `
                -Manual $(if ($guac) { "set OIDC_CLIENT_ID=$guac (and OIDC_TENANT_ID) in lab/pam/.env, add operators to PAM-Operators, then lab/pam/README.md section 6 step 3" } else { '' })))
    return , $steps.ToArray()
}

# =============================================================================
# Main
# =============================================================================
if ($OutputsPath) {
    if (-not (Test-Path -LiteralPath $OutputsPath -PathType Leaf)) { throw "OutputsPath '$OutputsPath' not found." }
    $outputsJson = Get-Content -LiteralPath $OutputsPath -Raw
}
else {
    Write-Console "Reading Terraform outputs from $TerraformDir ..." -ForegroundColor DarkGray
    $outputsJson = (& terraform "-chdir=$TerraformDir" output -json) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "terraform output failed (exit $LASTEXITCODE). Pass -OutputsPath with a saved 'terraform output -json'." }
}
$outputs = $outputsJson | ConvertFrom-Json -AsHashtable
if ($null -eq $outputs -or $outputs.Count -eq 0) { throw 'No Terraform outputs - has envs/dev been applied?' }

$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ("postapply-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $workDir | Out-Null
try {
    # Hand the rendered-body outputs to their scripts as files (the scripts'
    # documented input shape: the single output's JSON value). The folder is
    # private temp and removed in `finally` (directory_role_pim_policies is a
    # sensitive output: it carries pim_alert_mailbox).
    foreach ($n in 'access_review_definitions', 'b2b_post_apply', 'pim_auth_context_requests', 'protected_actions_auth_context_requests', 'directory_role_pim_policies') {
        $val = Get-TfValue -Outputs $outputs -Name $n
        if ($null -ne $val) { ($val | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath (Join-Path $workDir "$n.json") -Encoding utf8NoBOM }
    }

    $plan = Get-PostApplyPlan -Outputs $outputs -PimEligibility $PimEligibility -AgentSponsorUserPrincipalName $AgentSponsorUserPrincipalName `
        -AdminAllowedAaguids $AdminAllowedAaguids -GlobalAdminEligible $GlobalAdminEligible -VipUserPrincipalNames $VipUserPrincipalNames `
        -BuildAccountUpn $BuildAccountUpn -Execute $Execute.IsPresent -AcceptAgentIdPreview $AcceptAgentIdPreview.IsPresent -WorkDir $workDir
    if ($Only.Count) { $plan = @($plan | Where-Object { $_.Id -in $Only }) }
    if ($Skip.Count) { $plan = @($plan | Where-Object { $_.Id -notin $Skip }) }

    $mode = if ($ListOnly) { 'LIST ONLY (no tenant calls)' } elseif ($Execute) { 'EXECUTE (real changes)' } else { 'DRY RUN (-WhatIf / plan / preview)' }
    Write-Console "Post-apply plan - $mode" -ForegroundColor Cyan
    $i = 0
    foreach ($s in $plan) {
        $i++
        $tag = if (-not $s.Applies) { 'skip' } elseif ($s.Manual) { 'MANUAL' } else { 'run' }
        Write-Console ("  {0,2}. [{1,-6}] {2,-20} {3}  ({4})" -f $i, $tag, $s.Id, $s.Name, $s.Reason) -ForegroundColor $(if ($tag -eq 'skip') { 'DarkGray' } elseif ($tag -eq 'MANUAL') { 'Yellow' } else { 'White' })
    }
    if ($ListOnly) { return }

    $failed = @()
    foreach ($s in $plan) {
        if (-not $s.Applies) { continue }
        if ($s.Manual) {
            Write-Console "`n== MANUAL: $($s.Name)" -ForegroundColor Yellow
            Write-Console "   $($s.Manual)"
            continue
        }
        if ($s.RequiresClean -and $failed.Count) {
            Write-Warning "   $($s.Id) NOT run: earlier step(s) failed ($($failed -join ', ')). It only runs after a clean run - fix those, then re-run with -Only $($s.Id)."
            $failed += $s.Id
            continue
        }
        $path = Join-Path $ScriptRoot $s.Script
        Write-Console "`n== $($s.Id): $($s.Name)" -ForegroundColor Cyan
        Write-Console "   $($s.Script) $(@($s.Params.Keys | Sort-Object | ForEach-Object { "-$_" }) -join ' ')" -ForegroundColor DarkGray
        $global:LASTEXITCODE = 0
        $ok = $true
        try {
            $p = $s.Params
            & $path @p
            if ($LASTEXITCODE -ne 0) { $ok = $false }
        }
        catch {
            Write-Warning "   $($s.Id) threw: $($_.Exception.Message)"
            $ok = $false
        }
        if (-not $ok) {
            $failed += $s.Id
            if ($s.Gate) {
                Write-Warning "GATE FAILED ($($s.Id)): nothing after it runs. Fix the finding (break-glass must be excluded from every CA policy), then re-run."
                exit 1
            }
            Write-Warning "   $($s.Id) reported a failure - continuing (each step is independent and idempotent; re-run after fixing)."
        }
    }

    Write-Console "`nNext (evidence, not configuration): 01-Verify-Baseline.ps1 again (CA021 / CA011 / the build account change what it sees), 06-NHI-Inventory.ps1, Find-ShadowAdmins.ps1, 08-Measure-KPIs.ps1 -Label baseline - lab/docs/evidence-capture-plan.md." -ForegroundColor Cyan
    if ($failed.Count) { Write-Warning "Failed step(s): $($failed -join ', ')"; exit 1 }
}
finally {
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
