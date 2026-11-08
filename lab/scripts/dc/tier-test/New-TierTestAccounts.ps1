<#
.SYNOPSIS
    ON DC01: makes the three DISPOSABLE accounts for one Tier GPO proof run,
    so no real admin password ever reaches the Tier 2 test device.

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM (run-on-dc.py). Status: BUILT (mocked tests:
    lab/scripts/powershell/tests/TierTest.Tests.ps1); not yet RAN.

    Why (Greptile, PR #239): the test device is a Tier 2 machine. A Tier 2
    admin there could read any password the proof sends to it. So the
    passwords sent there must open nothing above Tier 2:

      t0-tiertest    OU=Accounts,OU=Tier0. Member of Tier0-Admins (the SID
                     the deny GPO names) and Protected Users (like t0-adm-01)
                     ONLY. Tier0-Admins gives no AD rights by itself
                     (Set-AdTiering.ps1: t0-adm-01's rights come from Domain
                     Admins, not from Tier0-Admins). So this account is
                     denied like a Tier 0 admin, but its password controls
                     nothing.
      t2-tiertest    OU=Accounts,OU=Tier2. Member of Tier2-Admins only.
      tiertest-join  OU=Accounts,OU=Tier2. No group. Delegated join rights on
                     OU=Devices,OU=Tier2 only (below). Replaces the build
                     admin (contosoadmin) for the domain join.

    Every account expires after -Hours (default 3), so a missed clean-up
    still ends it. Remove-TierTestAccounts.ps1 deletes them after the proof.

    Delegated join rights (dsacls on OU=Devices,OU=Tier2; Microsoft Learn
    "dsacls": /G user:perm;object;inheritedType, /I:T this object and
    children, /I:S children only): create/delete computer objects; on
    computer objects: Reset Password, write Account Restrictions, validated
    write to DNS host name and to service principal name.
    verify: on the first run, the join (Join-Tier2Device.ps1) must succeed
    with these rights and no more.

    Refuses when any of the three accounts already exists: run
    Remove-TierTestAccounts.ps1 first. The passwords come from the Keychain
    (tier2-device.py test-passwords), so a fresh run gets fresh passwords.

.PARAMETER T0Password / T2Password / JoinPassword
    PROTECTED parameters only (keychain:contoso-lab-tiertest-t0 / -t2 / -join).
#>
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Justification = 'Protected run-command parameters; each becomes a SecureString at once.')]
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingConvertToSecureStringWithPlainText', '', Justification = 'Only way to turn a protected parameter into an AD account password.')]
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$T0Password,
    [Parameter(Mandatory)][string]$T2Password,
    [Parameter(Mandatory)][string]$JoinPassword,
    [ValidateRange(1, 8)][int]$Hours = 3
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$d = Get-ADDomain
$dn = $d.DistinguishedName
$nb = $d.NetBIOSName
$expires = (Get-Date).AddHours($Hours)
$accounts = @(
    @{ Sam = 't0-tiertest'; Path = "OU=Accounts,OU=Tier0,$dn"; Groups = @('Tier0-Admins', 'Protected Users'); Pw = $T0Password }
    @{ Sam = 't2-tiertest'; Path = "OU=Accounts,OU=Tier2,$dn"; Groups = @('Tier2-Admins'); Pw = $T2Password }
    @{ Sam = 'tiertest-join'; Path = "OU=Accounts,OU=Tier2,$dn"; Groups = @(); Pw = $JoinPassword }
)
foreach ($a in $accounts) {
    # -ErrorAction Stop: "could not read" must never look like "not there".
    if (Get-ADUser -Filter "SamAccountName -eq '$($a.Sam)'" -ErrorAction Stop) {
        throw "REFUSED: $($a.Sam) already exists. Run Remove-TierTestAccounts.ps1 first."
    }
}
foreach ($a in $accounts) {
    New-ADUser -Name $a.Sam -SamAccountName $a.Sam -UserPrincipalName "$($a.Sam)@$($d.DNSRoot)" -Path $a.Path `
        -Description 'DISPOSABLE: Tier GPO proof only. Delete after (lab/scripts/dc/tier-test).' `
        -AccountExpirationDate $expires -Enabled $true -AccountPassword (ConvertTo-SecureString $a.Pw -AsPlainText -Force)
    Set-ADAccountControl -Identity $a.Sam -AccountNotDelegated $true
    foreach ($g in $a.Groups) { Add-ADGroupMember -Identity $g -Members $a.Sam }
    Write-Output "+ $($a.Sam) in $($a.Path), groups: $(if ($a.Groups) { $a.Groups -join ', ' } else { 'none' }), expires $($expires.ToUniversalTime().ToString('u'))"
}
$T0Password = $null; $T2Password = $null; $JoinPassword = $null

$ou = "OU=Devices,OU=Tier2,$dn"
$who = "$nb\tiertest-join"
foreach ($grant in @(
        @('/I:T', "${who}:CCDC;computer"),
        @('/I:S', "${who}:CA;Reset Password;computer"),
        @('/I:S', "${who}:WP;Account Restrictions;computer"),
        @('/I:S', "${who}:WS;Validated write to DNS host name;computer"),
        @('/I:S', "${who}:WS;Validated write to service principal name;computer"))) {
    $null = & dsacls.exe $ou $grant[0] /G $grant[1]
    if ($LASTEXITCODE -ne 0) { throw "dsacls $($grant[0]) /G $($grant[1]) failed (exit $LASTEXITCODE)." }
}
Write-Output "Delegated join on ${ou}: $who (create computers; reset password, account restrictions, DNS name, SPN)"
