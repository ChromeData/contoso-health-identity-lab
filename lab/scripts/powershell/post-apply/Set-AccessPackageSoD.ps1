<#
.SYNOPSIS
    DEPRECATED - forwards to Set-IncompatibleAccessPackages.ps1. Separation of
    duties now comes from lab/iga/sod-rules.json (SOD-01..09), not from one
    hard-coded Nurse <-> Pharmacy pair.

.DESCRIPTION
    WHAT CHANGED
      This script used to write ONE pair, "Nurse - Clinical Apps" <->
      "Pharmacy - Controlled Substances Apps", in BOTH directions. Since ADR
      0012 the Nurse package is BIRTHRIGHT (assigned by an HR-attribute
      automatic policy), and an incompatibility link ON a birthright package
      could block a nurse's automatic assignment - a clinical lockout created
      by a control. Set-IncompatibleAccessPackages.ps1 writes all nine rules,
      only on requestable packages (Pharmacy, ICU - Float Access, ...), reports
      the old Nurse -> Pharmacy link as drift (exit 1) and removes it with
      -Prune.

    WHY A FORWARDING SHIM, NOT A HARD STOP
      * post-apply/Invoke-PostApply.ps1 (step 3, 'sod') still calls this file
        by name until it is rewired to Set-AutoAssignmentPolicies.ps1 then
        Set-IncompatibleAccessPackages.ps1. Forwarding keeps that step doing
        the RIGHT thing (and its -WhatIf dry run) in the meantime; a hard stop
        would turn the step red and invite someone to restore the old logic.
      * The old two-way write can never run again: this file no longer
        contains a Graph call, and its old -PackageA / -PackageB parameters
        are refused before anything is read.
      * The exit code is the new script's, so a link that gates a birthright
        package (or a failed lookup) still fails the step.
      It does NOT add -Prune on its own: removing a link is a decision for the
      operator (run with -Prune -WhatIf first).

    FORWARDED: -WhatIf, -Confirm, -RuleId, -Prune, -RenderOnly. Declining the
    confirmation (or -WhatIf) forwards a -WhatIf run, which reads the tenant
    and shows what would change without changing it.

.PARAMETER PackageA
    Legacy. Refused: pairs live in lab/iga/sod-rules.json now.

.PARAMETER PackageB
    Legacy. Refused: pairs live in lab/iga/sod-rules.json now.

.PARAMETER RuleId
    Forwarded: only ADD the links these rules ask for (e.g. SOD-01).

.PARAMETER Prune
    Forwarded: remove catalog links the rules do not ask for (the legacy
    Nurse -> Pharmacy link among them).

.PARAMETER RenderOnly
    Forwarded: print the plan from the rule files; no Graph, no tenant.

.EXAMPLE
    ./Set-AccessPackageSoD.ps1 -RenderOnly            # same as Set-IncompatibleAccessPackages.ps1 -RenderOnly
.EXAMPLE
    ./Set-AccessPackageSoD.ps1 -WhatIf -Prune         # prefer calling Set-IncompatibleAccessPackages.ps1 directly

.NOTES
    TENANT-TIME: nothing here has run against Entra. Graph scopes, roles and
    verify: notes are those of Set-IncompatibleAccessPackages.ps1.
#>

#Requires -Version 7.0

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter()]
    [string]$PackageA,

    [Parameter()]
    [string]$PackageB,

    [Parameter()]
    [ValidatePattern('^SOD-\d{2}$')]
    [string[]]$RuleId = @(),

    [Parameter()]
    [switch]$Prune,

    [Parameter()]
    [switch]$RenderOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($PSBoundParameters.ContainsKey('PackageA') -or $PSBoundParameters.ContainsKey('PackageB')) {
    $msg = ("Set-AccessPackageSoD.ps1 is deprecated: a -PackageA/-PackageB pair ('{0}' / '{1}') is no longer accepted. " +
        'Add or change the rule in lab/iga/sod-rules.json (every name must be in lab/iga/access-catalog.json), ' +
        'then run post-apply/Set-IncompatibleAccessPackages.ps1. Nothing was sent to Graph.') -f $PackageA, $PackageB
    throw $msg
}

$target = Join-Path $PSScriptRoot 'Set-IncompatibleAccessPackages.ps1'
if (-not (Test-Path -LiteralPath $target -PathType Leaf)) {
    throw "Set-IncompatibleAccessPackages.ps1 not found next to this shim ($target). Nothing was sent to Graph."
}

Write-Warning 'Set-AccessPackageSoD.ps1 is DEPRECATED: running post-apply/Set-IncompatibleAccessPackages.ps1 (lab/iga/sod-rules.json, links only on requestable packages - ADR 0012). Call that script directly.'

$forward = @{}
foreach ($name in 'RuleId', 'Prune', 'RenderOnly', 'Confirm') {
    if ($PSBoundParameters.ContainsKey($name)) { $forward[$name] = $PSBoundParameters[$name] }
}
# The real run is gated here as well as in the target. Declined or -WhatIf ->
# a read-only -WhatIf run of the target, so the operator still sees the plan.
if (-not $RenderOnly -and -not $PSCmdlet.ShouldProcess('separation-of-duties links from lab/iga/sod-rules.json', 'apply with Set-IncompatibleAccessPackages.ps1')) {
    $forward['WhatIf'] = $true
}

$global:LASTEXITCODE = 0
& $target @forward
exit $LASTEXITCODE
