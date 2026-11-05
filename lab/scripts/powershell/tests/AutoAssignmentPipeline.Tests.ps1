# Pester 5 tests for the pipeline path of post-apply/Set-AutoAssignmentPolicies.ps1:
# terraform-apply.yml runs it after a successful apply as the APPLY identity
# (-UseAzureCliToken) and puts its -SummaryPath lines in the Apply summary.
#   * The plain-English summary (pure functions): who each package goes to,
#     "No automatic access rules needed changing.", failures and refusals.
#   * Contract: the APPLY identity's baseline Graph roles
#     (modules/pipeline-identity apply_graph_roles) cover what the script
#     needs, so the pipeline step never needs a new grant.
#   * The whole script, app-only: az, Connect-MgGraph and Graph are mocks; the
#     tenant is built from lab/iga/access-catalog.json, so the tests follow
#     the catalog when packages are added. The token is never printed, the
#     fail-closed guards still stop writes, -WhatIf still writes nothing.
# No tenant is contacted.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $script:Saa = Get-LabScriptPath 'post-apply/Set-AutoAssignmentPolicies.ps1'
    . (Get-ScriptFunctionBlock -Path $script:Saa -Name 'Read-IgaJson', 'Get-CatalogEntry', 'ConvertTo-RuleLiteral', 'ConvertTo-MembershipRule', 'Get-DesiredAutoPolicy',
        'Get-MissingGraphPermission', 'ConvertTo-AudienceText', 'Get-AutoAssignmentFailureText', 'ConvertTo-AutoAssignmentSummary')
    $script:LabRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..' '..' '..'))
    $script:Rules = Read-IgaJson (Join-Path $script:LabRoot 'iga' 'birthright-rules.json')
    $script:Catalog = Read-IgaJson (Join-Path $script:LabRoot 'iga' 'access-catalog.json')
    function Copy-Rules { return ($script:Rules | ConvertTo-Json -Depth 50 | ConvertFrom-Json -AsHashtable -Depth 50) }
    function New-Row([string]$Package, [string]$Action, [string]$Detail = '') { [pscustomobject]@{ Package = $Package; Action = $Action; Detail = $Detail } }

    # The APPLY identity's baseline Graph application roles, read from the
    # Terraform default (comments stripped: one of them quotes a Graph error).
    $vt = Get-Content -LiteralPath (Join-Path $script:LabRoot 'terraform' 'modules' 'pipeline-identity' 'variables.tf') -Raw
    $block = [regex]::Match($vt, '(?s)variable "apply_graph_roles"\s*\{.*?default\s*=\s*\[(?<list>.*?)\]').Groups['list'].Value
    $global:SaaApplyRoles = @([regex]::Matches(($block -replace '(?m)#.*$', ''), '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value })
    $global:SaaFakeToken = 'eyFAKE.apply-token.never-printed'

    function Set-PipelineTenant {
        # Every Terraform package in the catalog exists, with as many group
        # scopes as its catalog 'resources' (the guard compares the counts);
        # one enabled Member with a hire date per birthright department.
        param([hashtable]$Policies = @{}, [hashtable]$Groups = @{}, [hashtable]$RawScopes = @{}, $Users = $null, [string[]]$FailUris = @())
        $pk = @{}; $res = @{}; $i = 0
        foreach ($e in @($script:Catalog['accessPackages'] | Where-Object { $_['status'] -eq 'terraform' })) {
            $i++; $id = "ap-$i"; $pk[[string]$e['name']] = $id
            $res[$id] = @(@($e['resources']) | Where-Object { $_ } | ForEach-Object { "g-$id-$_" })
        }
        if ($null -eq $Users) {
            $Users = @(@($script:Rules['jobProfiles']) | Where-Object { @($_['birthright']).Count } | ForEach-Object { [string]$_['department'] } | Sort-Object -Unique |
                    ForEach-Object { @{ id = "u-$_"; department = $_; employeeHireDate = '2024-01-08T00:00:00Z' } })
        }
        $global:SaaPipe = @{ Packages = $pk; Resources = $res; Policies = $Policies; Groups = $Groups; RawScopes = $RawScopes; Users = @($Users); FailUris = $FailUris
            Writes = [System.Collections.Generic.List[object]]::new(); Out = [System.Collections.Generic.List[string]]::new() }
        Mock Write-Host { $global:SaaPipe.Out.Add([string]$Object) }
        Mock az { $global:LASTEXITCODE = 0; $global:SaaFakeToken }
        Mock Connect-MgGraph {}
        # What Get-MgContext shows after Connect-MgGraph -AccessToken: the token's app roles.
        Mock Get-MgContext { [pscustomobject]@{ Scopes = $global:SaaApplyRoles; AuthType = 'UserProvidedAccessToken'; TenantId = '11111111-1111-1111-1111-111111111111'; Account = $null } }
        Mock Invoke-MgGraphRequest {
            $t = $global:SaaPipe; $u = [uri]::UnescapeDataString("$Uri")
            foreach ($f in $t.FailUris) { if ($u -like $f) { throw "HTTP 403 Forbidden ($u)" } }
            if ($Method -in 'POST', 'PUT', 'DELETE', 'PATCH') {
                $t.Writes.Add(@{ Method = $Method; Uri = $u; Body = $(if ($Body) { $Body | ConvertFrom-Json -AsHashtable -Depth 50 } else { $null }) })
                if ($Method -eq 'POST') { return @{ id = 'pol-new' } }
                return $null
            }
            if ($u -match "accessPackages\?\`$filter=displayName eq '(?<n>.+)'&") {
                $n = $Matches.n.Replace("''", "'")
                return @{ value = @($(if ($t.Packages.ContainsKey($n)) { @{ id = $t.Packages[$n]; displayName = $n } })) | Where-Object { $_ } }
            }
            if ($u -match 'accessPackages/(?<id>[^/?]+)\?\$expand=resourceRoleScopes') {
                if ($t.RawScopes.ContainsKey($Matches.id)) { return $t.RawScopes[$Matches.id] }
                return @{ id = $Matches.id; resourceRoleScopes = @(@($t.Resources[$Matches.id]) | Where-Object { $_ } | ForEach-Object { @{ scope = @{ originSystem = 'AadGroup'; originId = $_ }; role = @{ originSystem = 'AadGroup' } } }) }
            }
            if ($u -match 'accessPackages/(?<id>[^/?]+)\?\$expand=assignmentPolicies') {
                return @{ id = $Matches.id; assignmentPolicies = @(@($t.Policies[$Matches.id]) | Where-Object { $_ } | ForEach-Object { @{ id = $_['id'] } }) }
            }
            if ($u -match 'assignmentPolicies/(?<id>[^/?]+)$') {
                foreach ($list in $t.Policies.Values) { foreach ($p in @($list)) { if ($p -and $p['id'] -eq $Matches.id) { return $p } } }
                throw "404 policy $($Matches.id)"
            }
            if ($u -match '/groups/(?<id>[^/?]+)\?\$select=id,displayName,isAssignableToRole') {
                if ($t.Groups.ContainsKey($Matches.id)) { return $t.Groups[$Matches.id] }
                return @{ id = $Matches.id; displayName = 'App-Group'; isAssignableToRole = $false }
            }
            if ($u -match '/users\?\$filter=accountEnabled eq true') { return @{ value = @($t.Users) } }
            if ($u -match '/assignments\?\$filter=accessPackage/id eq') { return @{ value = @() } }
            throw "unexpected Graph call in test: $Method $u"
        }
    }

    function New-AutoPolicyFor($Desired, [string]$Id) {
        @{ id = $Id; displayName = $Desired.DisplayName; description = $Desired.Description; allowedTargetScope = 'specificDirectoryUsers'
            specificAllowedTargets = @(@{ '@odata.type' = '#microsoft.graph.attributeRuleMembers'; description = 'r'; membershipRule = $Desired.MembershipRule })
            automaticRequestSettings = @{ requestAccessForAllowedTargets = $true; removeAccessWhenTargetLeavesAllowedTargets = $true; gracePeriodBeforeAccessRemoval = 'P3D' }
            expiration = @{ type = 'noExpiration' }; requestorSettings = @{ enableTargetsToSelfAddAccess = $false } }
    }
    # Terraform-built birthright packages (status terraform, automatic) = what a real run creates.
    function Get-BuiltBirthright {
        @(Get-DesiredAutoPolicy -Rules $script:Rules -MatchOn jobTitle | Where-Object { [string](Get-CatalogEntry -Catalog $script:Catalog -Kind accessPackages -Name $_.Package)['status'] -eq 'terraform' })
    }
    function Invoke-Saa {
        # The pipeline call (terraform-apply.yml), with both summary files.
        param([hashtable]$Extra = @{})
        $script:Plain = Join-Path $TestDrive ('plain-' + [guid]::NewGuid().ToString('N') + '.md')
        $script:Tech = Join-Path $TestDrive ('tech-' + [guid]::NewGuid().ToString('N') + '.md')
        & $script:Saa -UseAzureCliToken -Confirm:$false -SummaryPath $script:Plain -SummaryDetailsPath $script:Tech -WarningAction SilentlyContinue @Extra
    }
    function Get-PlainText { if (Test-Path -LiteralPath $script:Plain) { Get-Content -LiteralPath $script:Plain -Raw } else { '' } }
}

AfterAll { Remove-Variable -Name SaaPipe, SaaApplyRoles, SaaFakeToken -Scope Global -ErrorAction SilentlyContinue }

Describe 'Plain-English summary of the automatic access rules' {
    It 'says who a package goes to in the rule''s own terms (department + job title)' {
        ConvertTo-AudienceText -Rules $script:Rules -Package 'Nurse - Clinical Apps' -MatchOn jobTitle |
            Should -BeExactly 'everyone in Nursing with the job title Nurse Manager or Registered Nurse'
    }

    It 'renders the Cloud Engineering line exactly as the Apply summary shows it' {
        $r = Copy-Rules
        $r['jobProfiles'] += @{ department = 'Information Technology'; jobTitle = 'Cloud Engineer'; jobCode = 'IT-CLOUD'; birthright = @('IT - Cloud Engineering Apps'); requestable = @() }
        $s = ConvertTo-AutoAssignmentSummary -Results @(New-Row 'IT - Cloud Engineering Apps' 'created' 'policy pol-new. Entitlement management evaluates the rule within minutes') -Rules $r -MatchOn jobTitle
        $s.Plain | Should -Be @('- Automatic access rule set: **IT - Cloud Engineering Apps** goes to everyone in Information Technology with the job title Cloud Engineer.')
        ($s.Details -join "`n") | Should -Match 'IT - Cloud Engineering Apps: created \(policy pol-new'
    }

    It 'lists three titles with commas and "or", and joins departments with "; and"' {
        $r = Copy-Rules
        $r['jobProfiles'] = @(
            @{ department = 'B'; jobTitle = 'z'; birthright = @('P') }, @{ department = 'A'; jobTitle = 'y'; birthright = @('P') },
            @{ department = 'A'; jobTitle = 'w'; birthright = @('P') }, @{ department = 'A'; jobTitle = 'x'; birthright = @('P') })
        ConvertTo-AudienceText -Rules $r -Package 'P' -MatchOn jobTitle | Should -BeExactly 'everyone in A with the job title w, x or y; and everyone in B with the job title z'
    }

    It 'names job codes in jobCode mode' {
        ConvertTo-AudienceText -Rules $script:Rules -Package 'ICU - Critical Care Apps' -MatchOn jobCode | Should -BeExactly 'everyone in ICU with the job code NUR-MGR or NUR-RN'
    }

    It 'says "No automatic access rules needed changing." when every rule was already right' {
        $s = ConvertTo-AutoAssignmentSummary -Results @((New-Row 'Nurse - Clinical Apps' 'in-sync' 'policy pol-n'), (New-Row 'Radiology - Imaging Apps' 'skipped-planned' 'planned')) -Rules $script:Rules -MatchOn jobTitle
        $s.Plain | Should -Be @('- No automatic access rules needed changing.')
        ($s.Details -join "`n") | Should -Match 'Nurse - Clinical Apps: in-sync \(policy pol-n\)'
        ($s.Details -join "`n") | Should -Match 'planned, not built yet \(skipped\): Radiology - Imaging Apps'
    }

    It 'an updated rule says "now goes to"' {
        (ConvertTo-AutoAssignmentSummary -Results @(New-Row 'ICU - Critical Care Apps' 'updated' 'policy p: membershipRule') -Rules $script:Rules -MatchOn jobTitle).Plain |
            Should -Be @('- Automatic access rule updated: **ICU - Critical Care Apps** now goes to everyone in ICU with the job title Nurse Manager or Registered Nurse.')
    }

    It 'explains a failure in plain words: <Case>' -ForEach @(
        @{ Case = 'privileged group'; Detail = 'grants privileged group(s) Some-Admins; privileged access is never birthright. Nothing changed.'; Expect = '*admin access is never given automatically*' }
        @{ Case = 'catalog mismatch'; Detail = 'privileged-resource check: 0 group scope(s) in the tenant, 2 in access-catalog.json ''resources'' - fix the catalog or the package before granting it automatically (failing closed).'; Expect = '*do not match the access catalog*' }
        @{ Case = 'missing package'; Detail = 'not found in the tenant. Apply Terraform envs/dev with enable_governance = true first.'; Expect = '*does not exist in Entra yet*' }
        @{ Case = 'two automatic policies'; Detail = '2 automatic policies. Microsoft supports this only with no overlap'; Expect = '*more than one automatic rule*' }
        @{ Case = '403'; Detail = 'Response status code does not indicate success: Forbidden (403).'; Expect = '*missing a permission*' }
    ) {
        $s = ConvertTo-AutoAssignmentSummary -Results @((New-Row 'Nurse - Clinical Apps' 'failed' $Detail), (New-Row 'ICU - Critical Care Apps' 'in-sync' 'policy p')) -Rules $script:Rules -MatchOn jobTitle
        $s.Plain.Count | Should -Be 1
        $s.Plain[0] | Should -BeLike '- **Automatic access rule not set: Nurse - Clinical Apps.** *Nothing was changed for this package.'
        $s.Plain[0] | Should -BeLike $Expect
    }

    It 'asks for a person when a request-only package is handed out automatically (never deleted)' {
        (ConvertTo-AutoAssignmentSummary -Results @(New-Row 'Pharmacy - Controlled Substances Apps' 'drift-found' 'has 1 automatic policy') -Rules $script:Rules -MatchOn jobTitle).Plain[0] |
            Should -BeLike '- **Needs a person: Pharmacy - Controlled Substances Apps** *Nothing was removed*'
    }

    It 'a refusal says nothing was changed: <Kind>' -ForEach @(
        @{ Kind = 'unsafe-rules'; Refusal = @{ kind = 'unsafe-rules'; count = 2 }; Expect = '*failed its safety checks (2 problem(s)*nothing was sent*' }
        @{ Kind = 'no-hire-date'; Refusal = @{ kind = 'no-hire-date'; inScope = 3 }; Expect = '*none of the 3 people*start date*Nothing was sent*' }
        @{ Kind = 'sign-in'; Refusal = @{ kind = 'sign-in' }; Expect = '*not checked:** the pipeline could not get a Microsoft Graph sign-in*' }
        @{ Kind = 'graph-read'; Refusal = @{ kind = 'graph-read' }; Expect = '*not checked:** Microsoft Graph did not answer a read*' }
    ) {
        $s = ConvertTo-AutoAssignmentSummary -Rules $script:Rules -MatchOn jobTitle -Refusal $Refusal
        $s.Plain.Count | Should -Be 1
        $s.Plain[0] | Should -BeLike $Expect
        ($s.Details -join "`n") | Should -Match "stopped before any change \($Kind\)"
    }
}

Describe 'Contract: the APPLY identity already holds what the pipeline step needs' {
    It 'read the APPLY baseline roles from modules/pipeline-identity' {
        $global:SaaApplyRoles | Should -Contain 'EntitlementManagement.ReadWrite.All'
        $global:SaaApplyRoles.Count | Should -BeGreaterThan 5
    }

    It 'covers the script''s required permissions (a ReadWrite role covers its Read)' {
        $line = (Get-Content -LiteralPath $script:Saa | Where-Object { $_ -match '^\$requiredScopes\s*=' }) | Select-Object -First 1
        $required = @([regex]::Matches($line, "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
        $required | Should -Be @('EntitlementManagement.ReadWrite.All', 'Group.Read.All', 'User.Read.All')
        @(Get-MissingGraphPermission -Have $global:SaaApplyRoles -Required $required) | Should -BeNullOrEmpty
    }

    It 'still flags a permission nobody holds, and stays quiet when the context lists none' {
        @(Get-MissingGraphPermission -Have @('Group.ReadWrite.All', 'User.ReadWrite.All') -Required 'EntitlementManagement.ReadWrite.All', 'Group.Read.All', 'User.Read.All') | Should -Be @('EntitlementManagement.ReadWrite.All')
        @(Get-MissingGraphPermission -Have @() -Required 'EntitlementManagement.ReadWrite.All') | Should -BeNullOrEmpty
    }
}

Describe 'Set-AutoAssignmentPolicies.ps1 -UseAzureCliToken (app-only, inside the apply run)' {
    BeforeEach {
        $global:LASTEXITCODE = 0
        $script:SavedGha = $env:GITHUB_ACTIONS
        $env:GITHUB_ACTIONS = $null
    }
    AfterEach { $env:GITHUB_ACTIONS = $script:SavedGha }

    It 'signs in with the Azure CLI token (SecureString, never printed) and writes the summary lines' {
        Set-PipelineTenant
        $out = @(Invoke-Saa)
        $LASTEXITCODE | Should -Be 0
        Should -Invoke az -Times 1 -Exactly -ParameterFilter { $args -contains 'get-access-token' -and $args -contains 'ms-graph' }
        Should -Invoke Connect-MgGraph -Times 1 -Exactly -ParameterFilter { $AccessToken -is [securestring] -and [System.Net.NetworkCredential]::new('', $AccessToken).Password -eq $global:SaaFakeToken }
        Should -Invoke Connect-MgGraph -Times 0 -ParameterFilter { $Scopes }
        ($global:SaaPipe.Out -join "`n") | Should -Not -Match ([regex]::Escape($global:SaaFakeToken))
        $built = Get-BuiltBirthright
        @($global:SaaPipe.Writes | Where-Object Method -eq 'POST').Count | Should -Be $built.Count
        $plain = Get-PlainText
        foreach ($d in $built) {
            $plain | Should -Match ([regex]::Escape("- Automatic access rule set: **$($d.Package)** goes to $(ConvertTo-AudienceText -Rules $script:Rules -Package $d.Package -MatchOn jobTitle)."))
        }
        $plain | Should -Match ([regex]::Escape('- Automatic access rule set: **Nurse - Clinical Apps** goes to everyone in Nursing with the job title Nurse Manager or Registered Nurse.'))
        (Get-Content -LiteralPath $script:Tech -Raw) | Should -Match 'Nurse - Clinical Apps: created \(policy pol-new'
        @($out | Where-Object Action -eq 'created').Count | Should -Be $built.Count
    }

    It 'takes the APPLY roles as enough: no "does not list" warning' {
        Set-PipelineTenant
        $null = & $script:Saa -UseAzureCliToken -Confirm:$false -WarningVariable wv -WarningAction SilentlyContinue
        ($wv -join "`n") | Should -Not -Match 'does not list'
    }

    It 'masks the token in GitHub Actions (::add-mask::) - the only line that ever carries it' {
        $env:GITHUB_ACTIONS = 'true'
        Set-PipelineTenant
        $null = Invoke-Saa
        $hits = @($global:SaaPipe.Out | Where-Object { $_ -match [regex]::Escape($global:SaaFakeToken) })
        $hits.Count | Should -Be 1
        $hits[0] | Should -BeExactly "::add-mask::$($global:SaaFakeToken)"
    }

    It 'stops before any Graph call when the Azure CLI has no session, and the summary says so' {
        Set-PipelineTenant
        Mock az { $global:LASTEXITCODE = 1 }
        { Invoke-Saa } | Should -Throw '*No Microsoft Graph token from the Azure CLI*'
        Should -Invoke Invoke-MgGraphRequest -Times 0
        Get-PlainText | Should -Match 'not checked:\*\* the pipeline could not get a Microsoft Graph sign-in'
    }

    It 'is idempotent: rules already right get no write and "No automatic access rules needed changing."' {
        $pol = @{}; $i = 0
        Set-PipelineTenant
        foreach ($d in Get-BuiltBirthright) { $i++; $pol[$global:SaaPipe.Packages[$d.Package]] = @(New-AutoPolicyFor $d "pol-$i") }
        Set-PipelineTenant -Policies $pol
        $null = Invoke-Saa
        $LASTEXITCODE | Should -Be 0
        $global:SaaPipe.Writes.Count | Should -Be 0
        (Get-PlainText).Trim() | Should -BeExactly '- No automatic access rules needed changing.'
    }

    It 'keeps the privileged guard: a role-assignable group fails the package, exit 1, nothing written' {
        Set-PipelineTenant
        $nurseId = $global:SaaPipe.Packages['Nurse - Clinical Apps']
        $g = @($global:SaaPipe.Resources[$nurseId])[0]
        Set-PipelineTenant -Groups @{ $g = @{ id = $g; displayName = 'Some-Admins'; isAssignableToRole = $true } }
        $out = @(Invoke-Saa -Extra @{ AccessPackage = 'Nurse - Clinical Apps' })
        $LASTEXITCODE | Should -Be 1
        ($out | Where-Object Package -eq 'Nurse - Clinical Apps').Action | Should -Be 'failed'
        @($global:SaaPipe.Writes).Count | Should -Be 0
        Get-PlainText | Should -Match 'Automatic access rule not set: Nurse - Clinical Apps\.\*\* It would hand out admin-level access'
    }

    It 'keeps the catalog guard: tenant groups that do not match the catalog fail closed' {
        Set-PipelineTenant
        $nurseId = $global:SaaPipe.Packages['Nurse - Clinical Apps']
        Set-PipelineTenant -RawScopes @{ $nurseId = @{ id = $nurseId; resourceRoleScopes = @() } }
        $out = @(Invoke-Saa -Extra @{ AccessPackage = 'Nurse - Clinical Apps' })
        $LASTEXITCODE | Should -Be 1
        ($out | Where-Object Package -eq 'Nurse - Clinical Apps').Detail | Should -BeLike '*failing closed*'
        @($global:SaaPipe.Writes).Count | Should -Be 0
        Get-PlainText | Should -Match 'do not match the access catalog'
    }

    It 'keeps the hire-date preflight: nobody in scope with a start date = refused, nothing written' {
        Set-PipelineTenant -Users @(@{ id = 'u-1'; department = 'Nursing'; employeeHireDate = $null }, @{ id = 'u-2'; department = 'ICU' })
        { Invoke-Saa } | Should -Throw '*Hire-date preflight*'
        @($global:SaaPipe.Writes).Count | Should -Be 0
        Get-PlainText | Should -Match 'none of the 2 people'
    }

    It 'an unsafe rule file stops before signing in, with a summary line' {
        Set-PipelineTenant
        $bad = Join-Path $TestDrive 'bad-rules.json'
        $r = Copy-Rules; $r['jobProfiles'][0]['birthright'] = @('Pharmacy - Controlled Substances Apps')
        $r | ConvertTo-Json -Depth 50 | Set-Content -LiteralPath $bad
        { Invoke-Saa -Extra @{ RulesPath = $bad } } | Should -Throw '*not safe to apply*'
        Should -Invoke az -Times 0
        Should -Invoke Invoke-MgGraphRequest -Times 0
        Get-PlainText | Should -Match 'failed its safety checks'
    }

    It '-WhatIf signs in (it must read the tenant) but writes nothing, and the summary says dry run' {
        Set-PipelineTenant
        $null = & $script:Saa -UseAzureCliToken -WhatIf -SummaryPath (Join-Path $TestDrive 'whatif.md') -WarningAction SilentlyContinue
        $LASTEXITCODE | Should -Be 0
        @($global:SaaPipe.Writes).Count | Should -Be 0
        Should -Invoke Connect-MgGraph -Times 1 -Exactly
        (Get-Content -LiteralPath (Join-Path $TestDrive 'whatif.md') -Raw) | Should -Match 'Dry run: would set the automatic access rule for \*\*Nurse - Clinical Apps\*\*'
    }
}
