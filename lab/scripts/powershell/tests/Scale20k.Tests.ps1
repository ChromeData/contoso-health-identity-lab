# Pester 5: scale evidence for the tenant reports (karen-review I2).
#
# A synthetic 20,000-user tenant, fully mocked: no tenant is contacted.
# Invoke-MgGraphRequest serves 20,000 objects in pages of 999 linked by
# @odata.nextLink (21 pages), and throttles one page with HTTP 429 and a
# Retry-After header. Each paged reader must:
#   * follow every page and return exactly 20,000 objects;
#   * wait the Retry-After seconds Graph asked for, then retry that page;
#   * fail (throw), never return a partial list, when the throttle outlasts
#     the retries;
#   * finish inside a time budget (Start-Sleep is mocked, so the budget
#     measures the script's own work, not the wait).
# Readers under test: 08-Measure-KPIs.ps1 (Get-GraphCollection, Invoke-Graph),
# 06-NHI-Inventory.ps1 (Invoke-GraphGetAll) and 09-SoD-Report.ps1
# (Get-GraphCollection, shared with the other lab/iga scripts).
#
# What this does NOT prove: Graph's real page sizes and throttling limits in a
# 20,000-user tenant. It proves the scripts' paging and retry logic.

BeforeAll {
    . (Join-Path $PSScriptRoot 'TestHelpers.ps1')

    function Get-NamedFunctionText([string]$Rel, [string]$Name) {
        # Nested helpers too (09-SoD-Report.ps1 defines its Graph readers inside the tenant branch).
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Get-LabScriptPath $Rel), [ref]$tokens, [ref]$errors)
        if ($errors) { throw "Parse errors in ${Rel}: $($errors[0].Message)" }
        $f = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $Name }, $true) | Select-Object -First 1
        if (-not $f) { throw "$Name not found in $Rel" }
        return $f.Extent.Text
    }
    function Import-Reader([string]$Rel, [string[]]$Names) {
        $text = @($Names | ForEach-Object { Get-NamedFunctionText $Rel $_ }) -join [Environment]::NewLine
        return [scriptblock]::Create($text)
    }

    $script:Total = 20000
    $script:PageSize = 999
    $script:Pages = [int][math]::Ceiling($script:Total / $script:PageSize)   # 21

    function New-ThrottleError([int]$Seconds) {
        # The shape Microsoft.Graph's HttpResponseException carries: a Response
        # (HttpResponseMessage) with StatusCode 429 and a Retry-After header.
        $resp = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]429)
        $resp.Headers.RetryAfter = [System.Net.Http.Headers.RetryConditionHeaderValue]::new([timespan]::FromSeconds($Seconds))
        $ex = [System.Exception]::new('Response status code does not indicate success: TooManyRequests (Too Many Requests).')
        $ex | Add-Member -NotePropertyName Response -NotePropertyValue $resp
        return [System.Management.Automation.ErrorRecord]::new($ex, 'TooManyRequests', 'LimitsExceeded', $null)
    }

    # Serves page N of the synthetic collection. $global:ScaleTest controls the
    # throttle: which page, how many times in a row, and the Retry-After value.
    function Get-SyntheticPage([string]$Uri) {
        $t = $global:ScaleTest
        $t.Calls++
        $n = 0
        if ($Uri -match '[?&]page=(\d+)') { $n = [int]$Matches[1] }
        if ($n -eq $t.ThrottlePage -and $t.ThrottlesLeft -gt 0) {
            $t.ThrottlesLeft--
            throw (New-ThrottleError -Seconds $t.RetryAfter)
        }
        $t.PagesServed[$n] = 1 + [int]$t.PagesServed[$n]
        $start = $n * $script:PageSize
        $end = [math]::Min($start + $script:PageSize, $script:Total) - 1
        $value = foreach ($i in $start..$end) { @{ id = ('u-{0:d5}' -f $i); accountEnabled = $true } }
        $page = @{ value = @($value) }
        if ($n + 1 -lt $script:Pages) { $page['@odata.nextLink'] = "https://graph.microsoft.com/v1.0/users?page=$($n + 1)" }
        return $page
    }

    function Reset-ScaleTest([int]$ThrottlePage = 7, [int]$Throttles = 1, [int]$RetryAfter = 17) {
        $global:ScaleTest = @{ Calls = 0; PagesServed = @{}; ThrottlePage = $ThrottlePage; ThrottlesLeft = $Throttles; RetryAfter = $RetryAfter }
    }
}

AfterAll { Remove-Variable -Name ScaleTest -Scope Global -ErrorAction SilentlyContinue }

Describe '<Script>: 20,000 users over 21 pages, one page throttled' -ForEach @(
    @{ Script = '08-Measure-KPIs.ps1'; Functions = @('Get-GraphThrottleDelay', 'Invoke-GraphGetWithRetry', 'Invoke-Graph', 'Get-GraphCollection'); Call = 'Get-GraphCollection' }
    @{ Script = '06-NHI-Inventory.ps1'; Functions = @('Get-GraphThrottleDelay', 'Invoke-GraphGetWithRetry', 'Invoke-GraphGetAll'); Call = 'Invoke-GraphGetAll' }
    @{ Script = '09-SoD-Report.ps1'; Functions = @('Get-GraphThrottleDelay', 'Invoke-GraphGetWithRetry', 'Get-GraphCollection'); Call = 'Get-GraphCollection' }
) {
    BeforeAll {
        . (Import-Reader $Script $Functions)
        Mock Invoke-MgGraphRequest { Get-SyntheticPage -Uri $Uri }
        Mock Start-Sleep {}
        Mock Write-Warning {}
    }

    It 'follows every page, waits the Retry-After seconds once, and returns exactly 20,000 objects in time' {
        Reset-ScaleTest -ThrottlePage 7 -Throttles 1 -RetryAfter 17
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $items = @(& $Call -Uri 'https://graph.microsoft.com/v1.0/users?page=0')
        $sw.Stop()
        $items.Count | Should -Be 20000
        @($items | ForEach-Object { $_['id'] } | Sort-Object -Unique).Count | Should -Be 20000
        $global:ScaleTest.PagesServed.Count | Should -Be 21
        @($global:ScaleTest.PagesServed.Values | Where-Object { $_ -ne 1 }).Count | Should -Be 0   # no page read twice into the result
        $global:ScaleTest.Calls | Should -Be 22                                                   # 21 pages + 1 retry
        Should -Invoke Start-Sleep -Times 1 -Exactly -ParameterFilter { $Seconds -eq 17 }
        $sw.Elapsed.TotalSeconds | Should -BeLessThan 60
    }

    It 'fails closed when the throttle outlasts the retries (no partial list)' {
        Reset-ScaleTest -ThrottlePage 12 -Throttles 99 -RetryAfter 3
        { & $Call -Uri 'https://graph.microsoft.com/v1.0/users?page=0' } | Should -Throw '*TooManyRequests*'
        Should -Invoke Start-Sleep -Times 5 -Exactly
    }

    It 'does not retry an error that is not a throttle' {
        Reset-ScaleTest -ThrottlePage -1 -Throttles 0
        Mock Invoke-MgGraphRequest { throw 'Response status code does not indicate success: Forbidden (Forbidden).' }
        { & $Call -Uri 'https://graph.microsoft.com/v1.0/users?page=0' } | Should -Throw '*Forbidden*'
        Should -Invoke Start-Sleep -Times 0 -Exactly
    }
}

Describe 'Get-GraphThrottleDelay (how long to wait)' {
    BeforeAll { . (Import-Reader '08-Measure-KPIs.ps1' @('Get-GraphThrottleDelay')) }
    It 'uses the Retry-After header' { Get-GraphThrottleDelay -ErrorRecord (New-ThrottleError -Seconds 42) | Should -Be 42 }
    It 'caps a very long Retry-After at 120 seconds' { Get-GraphThrottleDelay -ErrorRecord (New-ThrottleError -Seconds 900) | Should -Be 120 }
    It 'waits 10 seconds on a 429 with no header' {
        $er = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('Response status code does not indicate success: TooManyRequests (Too Many Requests).'), 'x', 'LimitsExceeded', $null)
        Get-GraphThrottleDelay -ErrorRecord $er | Should -Be 10
    }
    It 'treats 503 Service Unavailable as a throttle' {
        $er = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('Response status code does not indicate success: ServiceUnavailable (Service Unavailable).'), 'x', 'NotSpecified', $null)
        Get-GraphThrottleDelay -ErrorRecord $er | Should -Be 10
    }
    It 'returns nothing for an error that is not a throttle' {
        $er = [System.Management.Automation.ErrorRecord]::new([System.Exception]::new('Forbidden'), 'x', 'PermissionDenied', $null)
        Get-GraphThrottleDelay -ErrorRecord $er | Should -BeNullOrEmpty
    }
}

Describe 'Parity: the throttle helpers are identical in every script that has them' {
    It '<Name> is the same everywhere' -ForEach @(
        @{ Name = 'Get-GraphThrottleDelay' }
        @{ Name = 'Invoke-GraphGetWithRetry' }
    ) {
        $scripts = @('08-Measure-KPIs.ps1', '06-NHI-Inventory.ps1', '09-SoD-Report.ps1', '10-Review-KPIs.ps1',
            'post-apply/Set-AutoAssignmentPolicies.ps1', 'post-apply/Set-IncompatibleAccessPackages.ps1')
        $texts = @($scripts | ForEach-Object { (Get-NamedFunctionText $_ $Name) -replace '\s+', ' ' })
        @($texts | Sort-Object -Unique).Count | Should -Be 1
    }
}
