<#
.SYNOPSIS
    README step 3b (and its undo in step 10): give the AD FS service account
    (gMSA gmsa-adfs) the "Generate security audits" right on domain
    controllers, or take it away again.

.DESCRIPTION
    Runs INSIDE DC01 as SYSTEM (lab/scripts/dc/run-on-dc.py).

    WHY. AD FS writes its sign-in audits (events 1200/1202 and the rest) to
    the Security log. Windows lets an account write there only if it holds
    the user right "Generate security audits" (SeAuditPrivilege). On a member
    server the AD FS install grants it locally. On a domain controller the
    right comes from the Default Domain Controllers Policy, which normally
    lists only LOCAL SERVICE and NETWORK SERVICE, so the gMSA does not get
    it. Without it AD FS writes no sign-in audits, and Microsoft Entra
    Connect Health (and so the AD FS application migration report) sees no
    sign-ins. Microsoft Learn, "AD FS troubleshooting - auditing events and
    logging" (windows-server/identity/ad-fs/troubleshooting/ad-fs-tshoot-logging,
    read 2026-11-07): confirm the AD FS service account is listed under
    User Rights Assignment > "Generate security audits". The page notes that
    the local-policy steps apply to a standalone member server; on a DC the
    same right is set in the Default Domain Controllers Policy instead.

    WHAT IT CHANGES. One line in one Tier-0 GPO: the SeAuditPrivilege line of
    the Default Domain Controllers Policy security template (GptTmpl.inf in
    SYSVOL), plus the GPO's computer version number so DCs pick it up. It
    touches no other right. -Mode Revoke removes exactly the gMSA's SID again
    and leaves the other entries as they were. A LAB SHORTCUT: production
    runs AD FS on a dedicated server, where this GPO is not involved.

    Idempotent, and a re-run REPAIRS a half-done change. The change has
    three writes (template, AD versionNumber, GPT.INI) and then gpupdate. If
    a run stopped after the template write, the template alone is no proof:
    DCs apply a GPO only when its version moves. So when the template
    already says the right thing, the script still checks (a) AD
    versionNumber = GPT.INI Version, (b) the security extension is listed in
    gPCMachineExtensionNames, (c) secedit's effective line on DC01 matches
    the mode. Only if all three hold does it change nothing and say so.
    Otherwise it bumps the version again (AD and GPT.INI), runs gpupdate and
    reads the right back, exactly like a first run.

.PARAMETER Mode
    Grant or Revoke.

.PARAMETER GmsaName
    Default gmsa-adfs (the account 10-Install-Adfs.ps1 creates).

.PARAMETER GmsaSid
    Revoke only, and only if the gMSA is already deleted (README step 10
    revokes BEFORE 19-Remove-Adfs.ps1 -Apply yes, so this is the recovery
    path): the gMSA's SID (S-1-5-21-...), from the template line in
    03b-audit-right-grant-readback.log or the Grant run's lineAfter. Without
    it the script resolves the SID from AD and stops if the account is gone.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Grant', 'Revoke')][string]$Mode,
    [string]$GmsaName = 'gmsa-adfs',
    [ValidatePattern('^(|S-1-5-21-\d+-\d+-\d+-\d+)$')][string]$GmsaSid = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# The Default Domain Controllers Policy has the same fixed GUID in every domain.
$DdcpGuid = '6AC1786C-016F-11D2-945F-00C04FB984F9'
$SecurityCse = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'

function Get-EffectiveAuditLine {
    # What the DC enforces now (secedit export), not what the template says.
    $tmp = Join-Path $env:TEMP ("secpol-{0}.inf" -f [guid]::NewGuid())
    $null = & secedit.exe /export /areas USER_RIGHTS /cfg $tmp
    $l = (Get-Content $tmp | Where-Object { $_ -like 'SeAuditPrivilege*' })
    Remove-Item $tmp -Force
    return "$l"
}
function Test-AuditRight([string]$Line) {
    # secedit writes a SID as *S-1-... but writes some accounts by NAME
    # (seen on DC01 2026-11-07: "gmsa-adfs$"). Accept either form.
    $items = @(($Line -split '=', 2)[-1].Split(',') | ForEach-Object { $_.Trim() })
    return [bool](($items -contains "*$gmsaSid") -or ($items -contains "$GmsaName`$") -or ($items -contains "$($domain.NetBIOSName)\$GmsaName`$"))
}

$cs = Get-CimInstance Win32_ComputerSystem
if ($cs.DomainRole -lt 4) { throw 'Not a domain controller. This script is for DC01 only.' }

$domain = Get-ADDomain
if ($GmsaSid) {
    if ($Mode -ne 'Revoke') { throw '-GmsaSid is for Revoke after the gMSA is deleted. Grant resolves the live account.' }
    $gmsaSid = $GmsaSid
} else {
    $gmsaSid = (Get-ADServiceAccount $GmsaName).SID.Value   # throws if the gMSA is gone: pass -GmsaSid
}
$gpoDn = "CN={$DdcpGuid},CN=Policies,CN=System,$($domain.DistinguishedName)"
$sysvol = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters').SysVol
$gpt = Join-Path $sysvol ("{0}\Policies\{{{1}}}" -f $domain.DNSRoot, $DdcpGuid)
$inf = Join-Path $gpt 'Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf'
if (-not (Test-Path -LiteralPath $inf)) { throw "Not found: $inf (fail closed: will not create a new template for the Default Domain Controllers Policy)." }

$text = [IO.File]::ReadAllText($inf)          # BOM-aware; the file is UTF-16 LE
$lines = [Collections.Generic.List[string]]($text -split "`r`n")
$idx = -1
for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i] -match '^\s*SeAuditPrivilege\s*=') { $idx = $i; break } }
if ($idx -lt 0) { throw 'No SeAuditPrivilege line in the Default Domain Controllers Policy. Stop: the policy is not in its default shape; check it by hand.' }

$before = $lines[$idx]
$entries = @(($before -split '=', 2)[1].Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$mine = "*$gmsaSid"
$has = $entries -contains $mine
function Get-GpoVersionState {
    # AD half and SYSVOL half of the GPO version, and the security CSE.
    $o = Get-ADObject -Identity $gpoDn -Properties versionNumber, gPCMachineExtensionNames
    $iniPath = Join-Path $gpt 'GPT.INI'
    $iniVer = $null
    if (Test-Path -LiteralPath $iniPath) {
        $m = [regex]::Match([IO.File]::ReadAllText($iniPath), 'Version=(\d+)')
        if ($m.Success) { $iniVer = [long]$m.Groups[1].Value }
    }
    [pscustomobject]@{
        ad      = $o
        adVer   = [long]$o.versionNumber
        iniVer  = $iniVer
        cseOk   = "$($o.gPCMachineExtensionNames)".Contains($SecurityCse)
    }
}

$templateDone = (($Mode -eq 'Grant' -and $has) -or ($Mode -eq 'Revoke' -and -not $has))
if ($templateDone) {
    # The template already says the right thing. That is proof of a finished
    # change only if the version halves agree, the CSE is listed and DC01
    # enforces it. Otherwise an earlier run stopped half way: repair below.
    $st = Get-GpoVersionState
    $eff = Get-EffectiveAuditLine
    $effOk = ((Test-AuditRight $eff) -eq ($Mode -eq 'Grant'))
    if ($st.cseOk -and ($st.adVer -eq $st.iniVer) -and $effOk) {
        if ($Mode -eq 'Grant') { Restart-Service adfssrv }   # make sure the running service has the right
        [pscustomobject]@{ mode = $Mode; changed = $false; line = $before; effectiveOnDc01 = $eff; holds = (Test-AuditRight $eff) } | ConvertTo-Json
        return
    }
    Write-Output ("[audit-right] template already updated, but the change is unfinished (AD version {0}, GPT.INI version {1}, security CSE listed: {2}, effective matches: {3}); repairing" -f $st.adVer, $st.iniVer, $st.cseOk, $effOk)
} else {
    if ($Mode -eq 'Grant') { $entries += $mine } else { $entries = @($entries | Where-Object { $_ -ne $mine }) }
    if (-not $entries) { throw 'Refusing to leave SeAuditPrivilege empty.' }
    $lines[$idx] = 'SeAuditPrivilege = ' + ($entries -join ',')
    [IO.File]::WriteAllText($inf, ($lines -join "`r`n"), [Text.Encoding]::Unicode)
}

# Computer-side change: bump only the low 16 bits of versionNumber, and GPT.INI to match.
# Start from the higher half, so a repair never moves a version backwards.
$st = Get-GpoVersionState
$ad = $st.ad
$cur = [long][Math]::Max($st.adVer, [long]$st.iniVer)
$computer = ($cur -band 0xFFFF) + 1
if ($computer -gt 0xFFFF) { $computer = 1 }
$next = ($cur -band 0xFFFF0000) -bor $computer
$cse = "$($ad.gPCMachineExtensionNames)"
if (-not $cse.Contains($SecurityCse)) { $cse = $cse + $SecurityCse }
Set-ADObject -Identity $gpoDn -Replace @{ versionNumber = $next; gPCMachineExtensionNames = $cse }
$ini = Join-Path $gpt 'GPT.INI'
$iniText = [IO.File]::ReadAllText($ini)
if ($iniText -match 'Version=\d+') { $iniText = $iniText -replace 'Version=\d+', "Version=$next" } else { $iniText = "[General]`r`nVersion=$next`r`n" }
[IO.File]::WriteAllText($ini, $iniText, [Text.Encoding]::ASCII)

$null = & gpupdate.exe /target:computer /force
# Read back what the DC now enforces (not what we wrote).
$effective = Get-EffectiveAuditLine
$now = Test-AuditRight $effective
if (($Mode -eq 'Grant') -ne $now) { throw "Read-back mismatch: effective line '$effective'." }
if ($Mode -eq 'Grant') { Restart-Service adfssrv }   # the service picks up the new token right on start

[pscustomobject]@{
    mode            = $Mode
    changed         = $true
    repaired        = $templateDone
    gpo             = 'Default Domain Controllers Policy'
    lineBefore      = $before
    lineAfter       = $lines[$idx]
    versionNumber   = $next
    effectiveOnDc01 = $effective
} | ConvertTo-Json
