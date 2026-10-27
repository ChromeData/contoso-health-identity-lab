# Issue a one-time Temporary Access Pass for the live PIM demo account and
# write ONLY the pass to stdout, for the calling process to keep in memory.
# The pass is never printed by the caller, stored, or passed on a command line.
param([Parameter(Mandatory)][string]$Upn, [Parameter(Mandatory)][string]$TenantId)
$ErrorActionPreference = 'Stop'
Connect-MgGraph -TenantId $TenantId -Scopes UserAuthenticationMethod.ReadWrite.All -NoWelcome | Out-Null
$old = Invoke-MgGraphRequest GET "v1.0/users/$Upn/authentication/temporaryAccessPassMethods"
foreach ($m in $old.value) { Invoke-MgGraphRequest DELETE "v1.0/users/$Upn/authentication/temporaryAccessPassMethods/$($m.id)" | Out-Null }
$body = @{ lifetimeInMinutes = 60; isUsableOnce = $true } | ConvertTo-Json
$tap = Invoke-MgGraphRequest POST "v1.0/users/$Upn/authentication/temporaryAccessPassMethods" -Body $body -ContentType 'application/json'
[Console]::Out.Write($tap.temporaryAccessPass)
