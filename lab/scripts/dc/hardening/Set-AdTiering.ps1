<#
.SYNOPSIS
    Admin tiering on DC01: Tier 0/1/2 OUs, one new admin account per tier,
    Protected Users for the NEW accounts only, and a GPO that stops Tier 0
    accounts from signing in to Tier 1 and Tier 2 computers. Idempotent.

.DESCRIPTION
    Runs ON DC01 as SYSTEM through lab/scripts/dc/run-on-dc.py (Windows
    PowerShell 5.1). Without -Apply yes it only prints what it would do.

    WHAT A TIER IS (plain words)
      A tier is a trust zone. Tier 0 controls the directory itself (domain
      controllers, Domain Admins). Tier 1 runs servers and applications.
      Tier 2 is the help desk and the staff workstations. An admin account
      belongs to ONE tier and signs in only to that tier's computers. Why:
      when an admin signs in to a computer, Windows keeps a reusable
      credential there for the session. If a Domain Admin signs in to a
      nurse's PC and that PC is compromised, the attacker takes the whole
      domain. Keeping Tier 0 credentials off lower tiers breaks that path.

    WHAT IT BUILDS
      OUs       OU=Tier0 {Accounts, Groups}
                OU=Tier1 {Accounts, Groups, Servers}
                OU=Tier2 {Accounts, Groups, Devices}
                (none of these is in the Cloud Sync scope: Workforce and
                Disabled only, so nothing here reaches Entra)
      Groups    Tier0-Admins, Tier1-Admins, Tier2-Admins (global security)
      Accounts  t0-adm-01 (Tier0-Admins + Domain Admins), t1-adm-01
                (Tier1-Admins), t2-adm-01 (Tier2-Admins). Each one is
                "sensitive and cannot be delegated" and a member of
                Protected Users. Passwords come in as PROTECTED run-command
                parameters from the Mac Keychain (contoso-lab-ad-<name>),
                set once at creation and never printed.
      GPO       "Tier0 - Deny logon to Tier1 and Tier2": the five Deny user
                rights (local, Remote Desktop, network, batch, service) for
                Domain Admins, Enterprise Admins, Schema Admins and
                Tier0-Admins. Linked ONLY to OU=Servers,OU=Tier1 and
                OU=Devices,OU=Tier2, never to Domain Controllers or the
                domain root, so Tier 0 keeps its own machines.
                Source: Microsoft, "Best Practices for Securing Active
                Directory", Appendix F (secure Domain Admins groups).

    WHY THE OLD ADMINS STAY OUT OF PROTECTED USERS
      tier0-admin-01, tier0-admin-02 and contosoadmin are NOT added, on
      purpose. Protected Users turns off NTLM for its members (Microsoft
      Learn, "Protected Users security group"). The lab's current remote-
      session path into DC01 authenticates with NTLM, so adding them would
      lock that path out. Assert-ProtectedUsersScope refuses those names.

.PARAMETER Apply
    'yes' to make changes. Anything else is a dry run.
#>
#Requires -Version 5.1
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '',
    Justification = 'The password arrives as a protected run-command parameter and must reach New-ADUser as a SecureString; it never leaves process memory.')]
[CmdletBinding()]
param(
    [string]$Apply = 'no',
    [string]$T0Password,
    [string]$T1Password,
    [string]$T2Password
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Accounts that must NEVER be put in Protected Users here (see header).
$script:LegacyAdmins = @('tier0-admin-01', 'tier0-admin-02', 'contosoadmin')

# The five Deny rights from Appendix F, as security-template names.
$script:DenyRights = @('SeDenyInteractiveLogonRight', 'SeDenyRemoteInteractiveLogonRight',
    'SeDenyNetworkLogonRight', 'SeDenyBatchLogonRight', 'SeDenyServiceLogonRight')

# Client-side extension pair for "Security Settings" in gPCMachineExtensionNames.
$script:SecurityCse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'

function Assert-ProtectedUsersScope {
    # Returns the names unchanged, or throws if any is a legacy admin.
    param([string[]]$Names)
    foreach ($n in $Names) {
        if ($script:LegacyAdmins -contains $n.ToLowerInvariant()) {
            throw "REFUSED: $n stays out of Protected Users (its remote-session path uses NTLM)"
        }
    }
    return , $Names
}

function Assert-AccountPassword {
    # Throws only when an account is about to be CREATED without a password.
    param([bool]$DoApply, [string]$Sam, [string]$Password)
    if ($DoApply -and -not $Password) { throw "No password parameter for $Sam (pass it as a protected parameter from the Keychain)" }
}

function New-DenyLogonInf {
    # Security template text (GptTmpl.inf) that denies every right in
    # $script:DenyRights to each SID. '*' marks a SID in a template.
    param([Parameter(Mandatory)][string[]]$Sids)
    if (-not $Sids) { throw 'No SIDs given' }
    $list = ($Sids | ForEach-Object { "*$_" }) -join ','
    $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO$"', 'Revision=1', '[Privilege Rights]')
    foreach ($r in $script:DenyRights) { $lines += "$r = $list" }
    return ($lines -join "`r`n") + "`r`n"
}

function Get-NextGpoVersion {
    # versionNumber: user version in the high 16 bits, computer version in
    # the low 16 bits. A computer-side change bumps only the low half.
    param([int]$Current)
    $user = $Current -band 0xFFFF0000
    $computer = ($Current -band 0xFFFF) + 1
    if ($computer -gt 0xFFFF) { $computer = 1 }
    return $user -bor $computer
}

function Write-Step {
    # Host stream, not the success stream: Confirm-OU returns a DN, and a log
    # line on the success stream would be returned with it. powershell.exe
    # -File still sends host output to the stdout that run-command captures.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingWriteHost', '', Justification = 'Log lines must not join function return values (see comment).')]
    param([string]$Message)
    Write-Host $Message
}

function Confirm-OU([string]$Name, [string]$Path) {
    $dn = "OU=$Name,$Path"
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$dn'")) {
        if ($script:DoApply) { New-ADOrganizationalUnit -Name $Name -Path $Path -ProtectedFromAccidentalDeletion $true }
        Write-Step "  + OU $dn"
    }
    return $dn
}

function Confirm-Group([string]$Name, [string]$Path, [string]$Description) {
    if (-not (Get-ADGroup -Filter "SamAccountName -eq '$Name'")) {
        if ($script:DoApply) { New-ADGroup -Name $Name -SamAccountName $Name -GroupScope Global -GroupCategory Security -Path $Path -Description $Description }
        Write-Step "  + group $Name"
    }
}

# ---------------------------------------------------------------------------
$script:DoApply = ($Apply -eq 'yes')
Write-Output ("Set-AdTiering {0} at {1:u}" -f $(if ($script:DoApply) { 'APPLY' } else { 'DRY RUN' }), (Get-Date).ToUniversalTime())
Import-Module ActiveDirectory
Import-Module GroupPolicy
$domain = Get-ADDomain
$base = $domain.DistinguishedName
$sid = $domain.DomainSID.Value

# 1. OUs ---------------------------------------------------------------------
Write-Output 'OUs'
$ou = @{}
foreach ($t in 'Tier0', 'Tier1', 'Tier2') {
    $root = Confirm-OU $t $base
    $ou[$t] = $root
    foreach ($c in 'Accounts', 'Groups') { $ou["$t-$c"] = Confirm-OU $c $root }
}
$ou['Tier1-Servers'] = Confirm-OU 'Servers' $ou['Tier1']
$ou['Tier2-Devices'] = Confirm-OU 'Devices' $ou['Tier2']

# 2. Groups -------------------------------------------------------------------
Write-Output 'Groups'
Confirm-Group 'Tier0-Admins' $ou['Tier0-Groups'] 'Tier 0: controls AD itself. Signs in only to Tier 0 machines.'
Confirm-Group 'Tier1-Admins' $ou['Tier1-Groups'] 'Tier 1: servers and applications. Reads Tier 1 server LAPS passwords.'
Confirm-Group 'Tier2-Admins' $ou['Tier2-Groups'] 'Tier 2: help desk and staff workstations.'

# 3. Accounts -----------------------------------------------------------------
Write-Output 'Accounts'
$accounts = @(
    @{ Sam = 't0-adm-01'; Tier = 'Tier0'; Groups = @('Tier0-Admins', 'Domain Admins'); Pw = $T0Password }
    @{ Sam = 't1-adm-01'; Tier = 'Tier1'; Groups = @('Tier1-Admins'); Pw = $T1Password }
    @{ Sam = 't2-adm-01'; Tier = 'Tier2'; Groups = @('Tier2-Admins'); Pw = $T2Password }
)
foreach ($a in $accounts) {
    $u = Get-ADUser -Filter "SamAccountName -eq '$($a.Sam)'"
    if (-not $u) {
        # A dry run creates nothing, so it needs no secret; an apply does.
        Assert-AccountPassword -DoApply $script:DoApply -Sam $a.Sam -Password $a.Pw
        if ($script:DoApply) {
            New-ADUser -Name $a.Sam -SamAccountName $a.Sam -UserPrincipalName "$($a.Sam)@$($domain.DNSRoot)" `
                -Path $ou["$($a.Tier)-Accounts"] -Description "$($a.Tier) admin account. Signs in only to $($a.Tier) machines." `
                -Enabled $true -AccountPassword (ConvertTo-SecureString $a.Pw -AsPlainText -Force)
        }
        Write-Output "  + $($a.Sam) in $($ou["$($a.Tier)-Accounts"])"
    }
    else { Write-Output "  = $($a.Sam) exists (password left as it is)" }
    if ($script:DoApply) {
        Set-ADAccountControl -Identity $a.Sam -AccountNotDelegated $true
        foreach ($g in $a.Groups) { Add-ADGroupMember -Identity $g -Members $a.Sam }
    }
}

# 4. Protected Users: the new accounts only ----------------------------------
Write-Output 'Protected Users'
$targets = Assert-ProtectedUsersScope -Names @($accounts | ForEach-Object { $_.Sam })
if ($script:DoApply) { Add-ADGroupMember -Identity 'Protected Users' -Members $targets }
Write-Output "  members (new accounts only): $($targets -join ', ')"
Write-Output "  left out on purpose (NTLM remote-session path): $($script:LegacyAdmins -join ', ')"

# 5. Deny-logon GPO -----------------------------------------------------------
Write-Output 'GPO: Tier0 - Deny logon to Tier1 and Tier2'
$gpoName = 'Tier0 - Deny logon to Tier1 and Tier2'
$denySids = @("$sid-512", "$sid-519", "$sid-518")   # Domain / Enterprise / Schema Admins
if ($script:DoApply) {
    $denySids += (Get-ADGroup 'Tier0-Admins').SID.Value
    $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
    if (-not $gpo) { $gpo = New-GPO -Name $gpoName -Comment 'Tier 0 credentials never land on Tier 1 or Tier 2 computers. Code: lab/scripts/dc/hardening/Set-AdTiering.ps1' }
    $sysvol = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters').SysVol
    $gpt = Join-Path $sysvol ("{0}\Policies\{{{1}}}" -f $domain.DNSRoot, $gpo.Id.ToString().ToUpperInvariant())
    $secEdit = Join-Path $gpt 'Machine\Microsoft\Windows NT\SecEdit'
    if (-not (Test-Path -LiteralPath $secEdit)) { New-Item -ItemType Directory -Path $secEdit -Force | Out-Null }
    [IO.File]::WriteAllText((Join-Path $secEdit 'GptTmpl.inf'), (New-DenyLogonInf -Sids $denySids), [Text.Encoding]::Unicode)
    $adGpo = Get-ADObject -Identity $gpo.Path -Properties versionNumber, gPCMachineExtensionNames
    $next = Get-NextGpoVersion -Current ([int]$adGpo.versionNumber)
    $cse = "$($adGpo.gPCMachineExtensionNames)"
    # Literal match: -like would read the brackets in the CSE string as a wildcard set.
    if (-not $cse.Contains($script:SecurityCse)) { $cse = $cse + $script:SecurityCse }
    Set-ADObject -Identity $gpo.Path -Replace @{ versionNumber = $next; gPCMachineExtensionNames = $cse }
    $ini = Join-Path $gpt 'GPT.INI'
    [IO.File]::WriteAllText($ini, "[General]`r`nVersion=$next`r`n", [Text.Encoding]::ASCII)
    foreach ($target in $ou['Tier1-Servers'], $ou['Tier2-Devices']) {
        $links = (Get-GPInheritance -Target $target).GpoLinks | Where-Object DisplayName -EQ $gpoName
        if (-not $links) { New-GPLink -Guid $gpo.Id -Target $target -LinkEnabled Yes | Out-Null; Write-Output "  + linked to $target" }
    }
    Write-Output "  GPO $($gpo.Id) version $next, deny SIDs: $($denySids -join ', ')"
}
else { Write-Output "  would deny $($script:DenyRights -join ', ') to Domain/Enterprise/Schema Admins + Tier0-Admins on Tier1\Servers and Tier2\Devices" }

$n = @(Get-ADComputer -Filter * -SearchBase $base | Where-Object { $_.DistinguishedName -like "*,$($ou['Tier1'])" -or $_.DistinguishedName -like "*,$($ou['Tier2'])" }).Count
Write-Output "Computers in Tier 1 / Tier 2 OUs today: $n (the deny GPO applies to these only)"
Write-Output 'Set-AdTiering done.'
