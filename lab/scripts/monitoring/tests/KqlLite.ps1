<#
    KqlLite.ps1 - a small, deliberately partial KQL interpreter for the ITDR
    fixture tests (Itdr.Tests.ps1). Dot-source it; it defines functions only.

    WHY IT EXISTS
      There is no Kusto engine offline. The regex-chain fixtures prove the
      patterns a rule ships with; this runs the rule's own ROW-LEVEL pipeline,
      read from the shipped .kql file, over fixture rows shaped like the Log
      Analytics tables (columns checked against fixtures/table-schemas.json):
      a positive row must come through with the expected columns, a negative
      row must be dropped by the step that is meant to drop it. A name the
      rule reads that is neither a column of the table, a computed column nor
      a let fails the test - in a workspace that query would not compile.
      Passing proves the logic does what the comments say on these rows; it
      does not replace running the rule in the tenant (the README's
      tenant-time steps).

    SCOPE - anything outside it throws or stops the pipeline, never guesses:
      operators   where; extend; project (Name = expr | Name); take / limit;
                  sort / order (no-op); mv-apply v = expr [to typeof(string)]
                  on ( where | take | extend | summarize <aggregates, no by> )
                  - "to typeof(string)" is CAST-ONLY as Learn (mv-expand)
                  documents: a string element stays, any other element
                  (object, array, number, bool) becomes null, never its text
                  (tostring() is the conversion);
                  join kind=leftouter <let name> on Col | $left.A == $right.B
                  (the right-hand rows come from the fixture). A top-level
                  summarize (or any other operator) STOPS the row-level run:
                  the rows at that point are the result. A later stage runs
                  from just after the Nth top-level summarize, on aggregated
                  fixture rows whose columns that summarize must name.
      scalars     string / verbatim (@'..', @"..") / long / real / bool /
                  timespan (1h, 15m, 2d, 30s, 100ms) literals, dynamic([..]),
                  let constants, columns, dotted and indexed dynamic access,
                  and / or / not(), == != =~ !~ < <= > >= + - * /, in / !in /
                  in~ / !in~ (dynamic arrays flatten), has / !has / has_cs /
                  hasprefix / hassuffix / has_any / has_all, contains /
                  !contains / contains_cs, startswith / endswith (and the !
                  and _cs forms), matches regex, between (a .. b)
      functions   tostring toupper tolower toint tolong isempty isnotempty
                  isnull isnotnull iff iif case coalesce not strcat
                  strcat_array split extract extract_all trim trim_start
                  trim_end array_length set_difference set_intersect
                  set_union set_has_element parse_json todynamic ago now
                  dynamic
      aggregates  (inside mv-apply summarize) take_any take_anyif make_list
                  make_set count countif max min

    SEMANTICS (Microsoft Learn, Kusto "String operators"): a term is a maximal
    run of alphanumeric characters; has* match whole terms ("KustoExplorer-
    QueryRun" has "Explorer" is false), case-insensitive unless _cs. == / !=
    / in / !in / matches regex are case-sensitive; =~ / !~ / in~ / contains /
    startswith / endswith are not. The KqlLite self-tests in Itdr.Tests.ps1
    pin these to the documented examples.
    Approximations (each a "verify:" against a real workspace):
      * has with a multi-word / punctuated right-hand side: it must start and
        end on term boundaries (alphanumeric = ASCII letters and digits).
      * Regexes run on .NET, not RE2 (the rules keep to the shared subset).
      * tostring(dynamic) is compact JSON in the fixture's key order.
      * A missing string value compares as "" (Kusto strings are never null).
#>

# ------------------------------------------------------------------ text ----

function ConvertTo-KqlCode {
    # The query text with // comments removed; string literals kept intact.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $sb = [System.Text.StringBuilder]::new()
    $i = 0; $n = $Text.Length
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($c -eq '@' -and $i + 1 -lt $n -and ($Text[$i + 1] -eq '"' -or $Text[$i + 1] -eq "'")) {
            $j = $Text.IndexOf($Text[$i + 1], $i + 2)
            if ($j -lt 0) { throw "KqlLite: unterminated verbatim string at offset $i" }
            [void]$sb.Append($Text, $i, $j - $i + 1); $i = $j + 1; continue
        }
        if ($c -eq '"' -or $c -eq "'") {
            $j = $i + 1
            while ($j -lt $n -and $Text[$j] -ne $c) { if ($Text[$j] -eq '\') { $j++ }; $j++ }
            if ($j -ge $n) { throw "KqlLite: unterminated string at offset $i" }
            [void]$sb.Append($Text, $i, $j - $i + 1); $i = $j + 1; continue
        }
        if ($c -eq '/' -and $i + 1 -lt $n -and $Text[$i + 1] -eq '/') {
            while ($i -lt $n -and $Text[$i] -ne "`n") { $i++ }
            continue
        }
        [void]$sb.Append($c); $i++
    }
    return $sb.ToString()
}

function Split-KqlTopLevel {
    # Splits on a separator that is outside strings and outside ( ) [ ] { }.
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text, [Parameter(Mandatory)][char]$Separator)
    $parts = [System.Collections.Generic.List[string]]::new()
    $depth = 0; $start = 0; $i = 0; $n = $Text.Length
    while ($i -lt $n) {
        $c = $Text[$i]
        if ($c -eq '@' -and $i + 1 -lt $n -and ($Text[$i + 1] -eq '"' -or $Text[$i + 1] -eq "'")) {
            $j = $Text.IndexOf($Text[$i + 1], $i + 2)
            if ($j -lt 0) { throw "KqlLite: unterminated verbatim string at offset $i" }
            $i = $j + 1; continue
        }
        if ($c -eq '"' -or $c -eq "'") {
            $j = $i + 1
            while ($j -lt $n -and $Text[$j] -ne $c) { if ($Text[$j] -eq '\') { $j++ }; $j++ }
            $i = $j + 1; continue
        }
        if ($c -eq '(' -or $c -eq '[' -or $c -eq '{') { $depth++ }
        elseif ($c -eq ')' -or $c -eq ']' -or $c -eq '}') { $depth-- }
        elseif ($c -eq $Separator -and $depth -eq 0) { $parts.Add($Text.Substring($start, $i - $start)); $start = $i + 1 }
        $i++
    }
    $parts.Add($Text.Substring($start))
    return , $parts.ToArray()
}

function Format-KqlStep {
    # One line, single spaces: how a step is named in test output / droppedBy.
    param([AllowEmptyString()][string]$Text)
    return ([regex]::Replace($Text, '\s+', ' ')).Trim()
}

# ---------------------------------------------------------------- tokens ----

$script:KqlNumberRx = [regex]::new('\G(\d+(?:\.\d+)?)(ms|d|h|m|s)?(?![A-Za-z0-9_])')
$script:KqlIdentRx = [regex]::new('\G[A-Za-z_$][A-Za-z0-9_]*')
$script:KqlOp2 = @('==', '!=', '=~', '!~', '<=', '>=', '..')

function ConvertTo-KqlToken {
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    $out = [System.Collections.Generic.List[object]]::new()
    $i = 0; $n = $Text.Length
    while ($i -lt $n) {
        $c = $Text[$i]
        if ([char]::IsWhiteSpace($c)) { $i++; continue }
        if ($c -eq '@' -and $i + 1 -lt $n -and ($Text[$i + 1] -eq '"' -or $Text[$i + 1] -eq "'")) {
            $j = $Text.IndexOf($Text[$i + 1], $i + 2)
            if ($j -lt 0) { throw "KqlLite: unterminated verbatim string at offset $i" }
            $out.Add(@{ T = 'str'; V = $Text.Substring($i + 2, $j - $i - 2) }); $i = $j + 1; continue
        }
        if ($c -eq '"' -or $c -eq "'") {
            $sb = [System.Text.StringBuilder]::new(); $j = $i + 1
            while ($true) {
                if ($j -ge $n) { throw "KqlLite: unterminated string at offset $i" }
                $d = $Text[$j]
                if ($d -eq '\' -and $j + 1 -lt $n) {
                    switch -CaseSensitive ([string]$Text[$j + 1]) {
                        'n' { [void]$sb.Append("`n") }
                        't' { [void]$sb.Append("`t") }
                        'r' { [void]$sb.Append("`r") }
                        default { [void]$sb.Append($Text[$j + 1]) }
                    }
                    $j += 2; continue
                }
                if ($d -eq $c) { break }
                [void]$sb.Append($d); $j++
            }
            $out.Add(@{ T = 'str'; V = $sb.ToString() }); $i = $j + 1; continue
        }
        if ([char]::IsDigit($c)) {
            $m = $script:KqlNumberRx.Match($Text, $i)
            if (-not $m.Success) { throw "KqlLite: bad number at offset $i in: $Text" }
            $num = $m.Groups[1].Value
            if ($m.Groups[2].Success) {
                $v = [double]::Parse($num, [cultureinfo]::InvariantCulture)
                $ts = switch -CaseSensitive ($m.Groups[2].Value) {
                    'd' { [timespan]::FromDays($v) } 'h' { [timespan]::FromHours($v) } 'm' { [timespan]::FromMinutes($v) }
                    's' { [timespan]::FromSeconds($v) } 'ms' { [timespan]::FromMilliseconds($v) }
                }
                $out.Add(@{ T = 'lit'; V = $ts })
            }
            elseif ($num.Contains('.')) { $out.Add(@{ T = 'lit'; V = [double]::Parse($num, [cultureinfo]::InvariantCulture) }) }
            else { $out.Add(@{ T = 'lit'; V = [long]::Parse($num, [cultureinfo]::InvariantCulture) }) }
            $i += $m.Length; continue
        }
        if ([char]::IsLetter($c) -or $c -eq '_' -or $c -eq '$') {
            $m = $script:KqlIdentRx.Match($Text, $i)
            $out.Add(@{ T = 'id'; V = $m.Value }); $i += $m.Length; continue
        }
        if ($i + 1 -lt $n -and $script:KqlOp2 -ccontains $Text.Substring($i, 2)) {
            $out.Add(@{ T = 'op'; V = $Text.Substring($i, 2) }); $i += 2; continue
        }
        if ('()[]{},.<>=+-*/%!~:'.Contains($c)) { $out.Add(@{ T = 'op'; V = [string]$c }); $i++; continue }
        throw "KqlLite: unexpected character '$c' at offset $i in: $Text"
    }
    return , $out.ToArray()
}

# ---------------------------------------------------------------- parser ----

function Test-KqlTokenAt {
    param([hashtable]$P, [string]$Type, [string]$Value, [int]$Ahead = 0)
    $k = $P.I + $Ahead
    if ($k -ge $P.T.Count) { return $false }
    $t = $P.T[$k]
    if ($t.T -cne $Type) { return $false }
    if ($Value -and [string]$t.V -cne $Value) { return $false }
    return $true
}

function Step-KqlToken {
    param([hashtable]$P, [string]$Type, [string]$Value)
    if (-not (Test-KqlTokenAt -P $P -Type $Type -Value $Value)) {
        $at = if ($P.I -lt $P.T.Count) { "'$($P.T[$P.I].V)'" } else { 'end of text' }
        throw "KqlLite: expected '$Value' but found $at in: $($P.Src)"
    }
    $P.I++
}

function Read-KqlList {
    # Comma-separated expressions up to (and consuming) the closing token.
    param([hashtable]$P, [string]$Close)
    $items = [System.Collections.Generic.List[object]]::new()
    if (Test-KqlTokenAt -P $P -Type 'op' -Value $Close) { $P.I++; return , $items.ToArray() }
    while ($true) {
        $items.Add((Read-KqlOr -P $P))
        if (Test-KqlTokenAt -P $P -Type 'op' -Value ',') { $P.I++; continue }
        Step-KqlToken -P $P -Type 'op' -Value $Close
        return , $items.ToArray()
    }
}

function Read-KqlOr {
    param([hashtable]$P)
    $left = Read-KqlAnd -P $P
    while (Test-KqlTokenAt -P $P -Type 'id' -Value 'or') { $P.I++; $left = @{ K = 'or'; L = $left; R = (Read-KqlAnd -P $P) } }
    return $left
}

function Read-KqlAnd {
    param([hashtable]$P)
    $left = Read-KqlComparison -P $P
    while (Test-KqlTokenAt -P $P -Type 'id' -Value 'and') { $P.I++; $left = @{ K = 'and'; L = $left; R = (Read-KqlComparison -P $P) } }
    return $left
}

$script:KqlStringOps = @('has', 'has_cs', 'hasprefix', 'hasprefix_cs', 'hassuffix', 'hassuffix_cs', 'contains', 'contains_cs',
    'startswith', 'startswith_cs', 'endswith', 'endswith_cs')

function Read-KqlComparison {
    param([hashtable]$P)
    $left = Read-KqlAdditive -P $P
    $neg = $false
    if ((Test-KqlTokenAt -P $P -Type 'op' -Value '!') -and (Test-KqlTokenAt -P $P -Type 'id' -Ahead 1)) { $neg = $true; $P.I++ }
    if (-not $neg -and $P.I -lt $P.T.Count -and $P.T[$P.I].T -eq 'op' -and @('==', '!=', '=~', '!~', '<', '<=', '>', '>=') -ccontains $P.T[$P.I].V) {
        $op = $P.T[$P.I].V; $P.I++
        return @{ K = 'cmp'; Op = $op; L = $left; R = (Read-KqlAdditive -P $P) }
    }
    if (Test-KqlTokenAt -P $P -Type 'id') {
        $word = $P.T[$P.I].V
        if ($word -ceq 'in') {
            $P.I++
            $ci = $false
            if (Test-KqlTokenAt -P $P -Type 'op' -Value '~') { $ci = $true; $P.I++ }
            Step-KqlToken -P $P -Type 'op' -Value '('
            return @{ K = 'in'; Neg = $neg; Ci = $ci; L = $left; Items = (Read-KqlList -P $P -Close ')') }
        }
        if ($word -ceq 'has_any' -or $word -ceq 'has_all') {
            $P.I++
            Step-KqlToken -P $P -Type 'op' -Value '('
            return @{ K = 'hasany'; All = ($word -ceq 'has_all'); Neg = $neg; L = $left; Items = (Read-KqlList -P $P -Close ')') }
        }
        if ($script:KqlStringOps -ccontains $word) {
            $P.I++
            return @{ K = 'str'; Op = $word; Neg = $neg; L = $left; R = (Read-KqlAdditive -P $P) }
        }
        if ($word -ceq 'matches') {
            $P.I++
            Step-KqlToken -P $P -Type 'id' -Value 'regex'
            return @{ K = 'str'; Op = 'matches'; Neg = $neg; L = $left; R = (Read-KqlAdditive -P $P) }
        }
        if ($word -ceq 'between') {
            $P.I++
            Step-KqlToken -P $P -Type 'op' -Value '('
            $lo = Read-KqlAdditive -P $P
            Step-KqlToken -P $P -Type 'op' -Value '..'
            $hi = Read-KqlAdditive -P $P
            Step-KqlToken -P $P -Type 'op' -Value ')'
            return @{ K = 'between'; Neg = $neg; L = $left; Lo = $lo; Hi = $hi }
        }
    }
    if ($neg) { throw "KqlLite: unsupported negated operator in: $($P.Src)" }
    return $left
}

function Read-KqlAdditive {
    param([hashtable]$P)
    $left = Read-KqlMultiplicative -P $P
    while ((Test-KqlTokenAt -P $P -Type 'op' -Value '+') -or (Test-KqlTokenAt -P $P -Type 'op' -Value '-')) {
        $op = $P.T[$P.I].V; $P.I++
        $left = @{ K = 'arith'; Op = $op; L = $left; R = (Read-KqlMultiplicative -P $P) }
    }
    return $left
}

function Read-KqlMultiplicative {
    param([hashtable]$P)
    $left = Read-KqlUnary -P $P
    while ((Test-KqlTokenAt -P $P -Type 'op' -Value '*') -or (Test-KqlTokenAt -P $P -Type 'op' -Value '/') -or (Test-KqlTokenAt -P $P -Type 'op' -Value '%')) {
        $op = $P.T[$P.I].V; $P.I++
        $left = @{ K = 'arith'; Op = $op; L = $left; R = (Read-KqlUnary -P $P) }
    }
    return $left
}

function Read-KqlUnary {
    param([hashtable]$P)
    if (Test-KqlTokenAt -P $P -Type 'op' -Value '-') { $P.I++; return @{ K = 'arith'; Op = '-'; L = @{ K = 'lit'; V = [long]0 }; R = (Read-KqlUnary -P $P) } }
    return Read-KqlPostfix -P $P
}

function Read-KqlPostfix {
    param([hashtable]$P)
    $x = Read-KqlPrimary -P $P
    while ($true) {
        if ((Test-KqlTokenAt -P $P -Type 'op' -Value '.') -and (Test-KqlTokenAt -P $P -Type 'id' -Ahead 1)) {
            $x = @{ K = 'member'; O = $x; N = $P.T[$P.I + 1].V }; $P.I += 2; continue
        }
        if (Test-KqlTokenAt -P $P -Type 'op' -Value '[') {
            $P.I++
            $idx = Read-KqlOr -P $P
            Step-KqlToken -P $P -Type 'op' -Value ']'
            $x = @{ K = 'index'; O = $x; I = $idx }; continue
        }
        return $x
    }
}

function Read-KqlPrimary {
    param([hashtable]$P)
    if ($P.I -ge $P.T.Count) { throw "KqlLite: unexpected end of expression in: $($P.Src)" }
    $t = $P.T[$P.I]
    if ($t.T -eq 'str' -or $t.T -eq 'lit') { $P.I++; return @{ K = 'lit'; V = $t.V } }
    if ($t.T -eq 'op' -and $t.V -eq '(') {
        $P.I++
        $x = Read-KqlOr -P $P
        Step-KqlToken -P $P -Type 'op' -Value ')'
        return $x
    }
    if ($t.T -eq 'op' -and $t.V -eq '[') { $P.I++; return @{ K = 'arr'; Items = (Read-KqlList -P $P -Close ']') } }
    if ($t.T -eq 'id') {
        $P.I++
        if ($t.V -ceq 'true') { return @{ K = 'lit'; V = $true } }
        if ($t.V -ceq 'false') { return @{ K = 'lit'; V = $false } }
        if ($t.V -ceq 'null') { return @{ K = 'lit'; V = $null } }   # as in dynamic(null)
        if (Test-KqlTokenAt -P $P -Type 'op' -Value '(') {
            $P.I++
            return @{ K = 'call'; F = $t.V; A = (Read-KqlList -P $P -Close ')') }
        }
        return @{ K = 'id'; N = $t.V }
    }
    throw "KqlLite: unexpected '$($t.V)' in: $($P.Src)"
}

function ConvertTo-KqlAst {
    # Parses one scalar expression.
    param([Parameter(Mandatory)][string]$Text)
    $p = @{ T = (ConvertTo-KqlToken -Text $Text); I = 0; Src = (Format-KqlStep $Text) }
    $ast = Read-KqlOr -P $p
    if ($p.I -lt $p.T.Count) { throw "KqlLite: unexpected '$($p.T[$p.I].V)' after a complete expression in: $($p.Src)" }
    return $ast
}

# ---------------------------------------------------------------- values ----

function Test-KqlNumber {
    param($Value)
    return ($Value -is [long] -or $Value -is [int] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single] -or $Value -is [int16] -or $Value -is [byte])
}

function Test-KqlArray {
    param($Value)
    return ($null -ne $Value -and $Value -isnot [string] -and $Value -isnot [System.Collections.IDictionary] -and $Value -is [System.Collections.IList])
}

function Test-KqlTrue {
    param($Value)
    return ($Value -is [bool] -and $Value)
}

function ConvertTo-KqlString {
    # tostring(): null -> "", dynamic -> compact JSON.
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffffffZ', [cultureinfo]::InvariantCulture) }
    if ($Value -is [timespan]) { return $Value.ToString('c', [cultureinfo]::InvariantCulture) }
    if (Test-KqlNumber $Value) { return [string]::Format([cultureinfo]::InvariantCulture, '{0}', $Value) }
    return (ConvertTo-Json -InputObject $Value -Compress -Depth 64)
}

function Get-KqlMember {
    # Dynamic property access: exact-case key, null when absent.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in $Object.Keys) { if ([string]$k -ceq $Name) { return , $Object[$k] } }
        return $null
    }
    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        foreach ($pp in $Object.PSObject.Properties) { if ($pp.Name -ceq $Name) { return , $pp.Value } }
        return $null
    }
    return $null
}

function Get-KqlIndex {
    param($Object, $Index)
    if ($null -eq $Object -or $null -eq $Index) { return $null }
    if ($Index -is [string]) { return , (Get-KqlMember -Object $Object -Name $Index) }
    if ((Test-KqlArray $Object) -and (Test-KqlNumber $Index)) {
        $k = [long]$Index
        if ($k -lt 0) { $k = $Object.Count + $k }
        if ($k -lt 0 -or $k -ge $Object.Count) { return $null }
        return , $Object[[int]$k]
    }
    return $null
}

function Test-KqlEqual {
    # $true / $false, or $null when either side is null outside a string comparison.
    param($A, $B, [switch]$IgnoreCase)
    if ($A -is [string] -or $B -is [string]) {
        if ($null -eq $A) { $A = '' }
        if ($null -eq $B) { $B = '' }
        if ($A -isnot [string] -or $B -isnot [string]) { throw "KqlLite: comparing a string with a $($(if ($A -is [string]) { $B } else { $A }).GetType().Name) ('$A' vs '$B')" }
        $cmp = if ($IgnoreCase) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
        return [string]::Equals($A, $B, $cmp)
    }
    if ($null -eq $A -or $null -eq $B) { return $null }
    if ((Test-KqlNumber $A) -and (Test-KqlNumber $B)) { return ([double]$A -eq [double]$B) }
    if ($A -is [bool] -and $B -is [bool]) { return ($A -eq $B) }
    if ($A -is [datetime] -and $B -is [datetime]) { return ($A.ToUniversalTime() -eq $B.ToUniversalTime()) }
    if ($A -is [timespan] -and $B -is [timespan]) { return ($A -eq $B) }
    return ((ConvertTo-KqlString $A) -ceq (ConvertTo-KqlString $B))
}

function Compare-KqlValue {
    # -1 / 0 / 1, or $null when not comparable.
    param($A, $B)
    if ($null -eq $A -or $null -eq $B) { return $null }
    if ((Test-KqlNumber $A) -and (Test-KqlNumber $B)) { return ([double]$A).CompareTo([double]$B) }
    if ($A -is [datetime] -and $B -is [datetime]) { return $A.ToUniversalTime().CompareTo($B.ToUniversalTime()) }
    if ($A -is [timespan] -and $B -is [timespan]) { return $A.CompareTo($B) }
    if ($A -is [string] -and $B -is [string]) { return [math]::Sign([string]::CompareOrdinal($A, $B)) }
    throw "KqlLite: cannot order a $($A.GetType().Name) against a $($B.GetType().Name)"
}

function Test-KqlTerm {
    # has / hasprefix / hassuffix: RHS on term boundaries (alphanumeric runs).
    param([string]$Haystack, [string]$Needle, [ValidateSet('whole', 'prefix', 'suffix')][string]$Mode, [switch]$CaseSensitive)
    if ($Needle.Length -eq 0) { return $true }
    $before = '(?<![A-Za-z0-9])'
    $after = '(?![A-Za-z0-9])'
    $rx = switch ($Mode) {
        'whole' { $before + [regex]::Escape($Needle) + $after }
        'prefix' { $before + [regex]::Escape($Needle) }
        'suffix' { [regex]::Escape($Needle) + $after }
    }
    $opt = if ($CaseSensitive) { [System.Text.RegularExpressions.RegexOptions]::None } else { [System.Text.RegularExpressions.RegexOptions]::IgnoreCase }
    return [regex]::IsMatch($Haystack, $rx, $opt)
}

function Get-KqlFlatList {
    # The values of an in / has_any list: dynamic arrays flatten into it.
    param([object[]]$Items, [hashtable]$Ctx)
    $vals = [System.Collections.Generic.List[object]]::new()
    foreach ($it in $Items) {
        $v = Invoke-KqlExpression -Ast $it -Ctx $Ctx
        if (Test-KqlArray $v) { foreach ($e in $v) { $vals.Add($e) } } else { $vals.Add($v) }
    }
    return , $vals.ToArray()
}

function Get-KqlDistinct {
    param([object[]]$Values)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($v in $Values) {
        $seen = $false
        foreach ($o in $out) { if (Test-KqlTrue (Test-KqlEqual -A $o -B $v)) { $seen = $true; break } }
        if (-not $seen) { $out.Add($v) }
    }
    return , $out.ToArray()
}

# ------------------------------------------------------------ evaluation ----

function Resolve-KqlName {
    param([string]$Name, [hashtable]$Ctx)
    if ($Ctx.Row.ContainsKey($Name)) { return , $Ctx.Row[$Name] }
    if ($Ctx.Lets.ContainsKey($Name)) {
        $l = $Ctx.Lets[$Name]
        if ($l.Kind -eq 'value') { return , $l.Value }
        throw "KqlLite: let '$Name' is $($l.Kind) - a case that needs it gives its value under 'lets'"
    }
    if ($null -ne $Ctx.Schema -and $Ctx.Schema.ContainsKey($Name)) {
        # A column of the table that this row leaves empty.
        if ($Ctx.Schema[$Name] -eq 'string') { return '' }
        return $null
    }
    throw "KqlLite: unresolved name '$Name' - not a column of $($Ctx.Table), not a computed column, not a let (the query would not compile)"
}

function Invoke-KqlExpression {
    param([Parameter(Mandatory)][hashtable]$Ast, [Parameter(Mandatory)][hashtable]$Ctx)
    switch ($Ast.K) {
        'lit' { return , $Ast.V }
        'arr' {
            $vals = [System.Collections.Generic.List[object]]::new()
            foreach ($it in $Ast.Items) { $vals.Add((Invoke-KqlExpression -Ast $it -Ctx $Ctx)) }
            return , $vals.ToArray()
        }
        'id' { return , (Resolve-KqlName -Name $Ast.N -Ctx $Ctx) }
        'member' { return , (Get-KqlMember -Object (Invoke-KqlExpression -Ast $Ast.O -Ctx $Ctx) -Name $Ast.N) }
        'index' { return , (Get-KqlIndex -Object (Invoke-KqlExpression -Ast $Ast.O -Ctx $Ctx) -Index (Invoke-KqlExpression -Ast $Ast.I -Ctx $Ctx)) }
        'or' {
            $l = Invoke-KqlExpression -Ast $Ast.L -Ctx $Ctx
            if ($null -ne $l -and $l -isnot [bool]) { throw "KqlLite: 'or' operand is a $($l.GetType().Name), not bool" }
            if (Test-KqlTrue $l) { return $true }
            $r = Invoke-KqlExpression -Ast $Ast.R -Ctx $Ctx
            if ($null -ne $r -and $r -isnot [bool]) { throw "KqlLite: 'or' operand is a $($r.GetType().Name), not bool" }
            if (Test-KqlTrue $r) { return $true }
            if ($l -is [bool] -and $r -is [bool]) { return $false }
            return $null
        }
        'and' {
            $l = Invoke-KqlExpression -Ast $Ast.L -Ctx $Ctx
            if ($null -ne $l -and $l -isnot [bool]) { throw "KqlLite: 'and' operand is a $($l.GetType().Name), not bool" }
            if ($l -is [bool] -and -not $l) { return $false }
            $r = Invoke-KqlExpression -Ast $Ast.R -Ctx $Ctx
            if ($null -ne $r -and $r -isnot [bool]) { throw "KqlLite: 'and' operand is a $($r.GetType().Name), not bool" }
            if ($r -is [bool] -and -not $r) { return $false }
            if ((Test-KqlTrue $l) -and (Test-KqlTrue $r)) { return $true }
            return $null
        }
        'cmp' {
            $l = Invoke-KqlExpression -Ast $Ast.L -Ctx $Ctx
            $r = Invoke-KqlExpression -Ast $Ast.R -Ctx $Ctx
            switch -CaseSensitive ($Ast.Op) {
                '==' { return , (Test-KqlEqual -A $l -B $r) }
                '=~' { return , (Test-KqlEqual -A $l -B $r -IgnoreCase) }
                '!=' { $e = Test-KqlEqual -A $l -B $r; if ($null -eq $e) { return $null }; return (-not $e) }
                '!~' { $e = Test-KqlEqual -A $l -B $r -IgnoreCase; if ($null -eq $e) { return $null }; return (-not $e) }
                default {
                    $c = Compare-KqlValue -A $l -B $r
                    if ($null -eq $c) { return $null }
                    switch -CaseSensitive ($Ast.Op) { '<' { return ($c -lt 0) } '<=' { return ($c -le 0) } '>' { return ($c -gt 0) } '>=' { return ($c -ge 0) } }
                }
            }
        }
        'in' {
            $l = Invoke-KqlExpression -Ast $Ast.L -Ctx $Ctx
            $found = $false
            foreach ($v in (Get-KqlFlatList -Items $Ast.Items -Ctx $Ctx)) {
                if (Test-KqlTrue (Test-KqlEqual -A $l -B $v -IgnoreCase:$Ast.Ci)) { $found = $true; break }
            }
            return ($found -xor $Ast.Neg)
        }
        'hasany' {
            $l = ConvertTo-KqlString (Invoke-KqlExpression -Ast $Ast.L -Ctx $Ctx)
            $vals = Get-KqlFlatList -Items $Ast.Items -Ctx $Ctx
            $hits = 0
            foreach ($v in $vals) { if (Test-KqlTerm -Haystack $l -Needle (ConvertTo-KqlString $v) -Mode whole) { $hits++ } }
            $res = if ($Ast.All) { $hits -eq $vals.Count } else { $hits -gt 0 }
            return ($res -xor $Ast.Neg)
        }
        'str' {
            $l = ConvertTo-KqlString (Invoke-KqlExpression -Ast $Ast.L -Ctx $Ctx)
            $r = ConvertTo-KqlString (Invoke-KqlExpression -Ast $Ast.R -Ctx $Ctx)
            $cs = $Ast.Op.EndsWith('_cs')
            $cmp = if ($cs) { [System.StringComparison]::Ordinal } else { [System.StringComparison]::OrdinalIgnoreCase }
            $res = switch -CaseSensitive ($Ast.Op -replace '_cs$', '') {
                'has' { Test-KqlTerm -Haystack $l -Needle $r -Mode whole -CaseSensitive:$cs }
                'hasprefix' { Test-KqlTerm -Haystack $l -Needle $r -Mode prefix -CaseSensitive:$cs }
                'hassuffix' { Test-KqlTerm -Haystack $l -Needle $r -Mode suffix -CaseSensitive:$cs }
                'contains' { $l.IndexOf($r, $cmp) -ge 0 }
                'startswith' { $l.StartsWith($r, $cmp) }
                'endswith' { $l.EndsWith($r, $cmp) }
                'matches' { [regex]::IsMatch($l, $r) }
            }
            return ([bool]$res -xor $Ast.Neg)
        }
        'between' {
            $l = Invoke-KqlExpression -Ast $Ast.L -Ctx $Ctx
            $lo = Compare-KqlValue -A $l -B (Invoke-KqlExpression -Ast $Ast.Lo -Ctx $Ctx)
            $hi = Compare-KqlValue -A $l -B (Invoke-KqlExpression -Ast $Ast.Hi -Ctx $Ctx)
            if ($null -eq $lo -or $null -eq $hi) { return $null }
            return ((($lo -ge 0) -and ($hi -le 0)) -xor $Ast.Neg)
        }
        'arith' { return , (Invoke-KqlArithmetic -Op $Ast.Op -A (Invoke-KqlExpression -Ast $Ast.L -Ctx $Ctx) -B (Invoke-KqlExpression -Ast $Ast.R -Ctx $Ctx)) }
        'call' { return , (Invoke-KqlFunction -Name $Ast.F -Arguments $Ast.A -Ctx $Ctx) }
        default { throw "KqlLite: unknown node '$($Ast.K)'" }
    }
}

function Invoke-KqlArithmetic {
    param([string]$Op, $A, $B)
    if ($null -eq $A -or $null -eq $B) { return $null }
    if ((Test-KqlNumber $A) -and (Test-KqlNumber $B)) {
        $isLong = ($A -isnot [double] -and $B -isnot [double] -and $A -isnot [decimal] -and $B -isnot [decimal])
        switch -CaseSensitive ($Op) {
            '+' { if ($isLong) { return [long]$A + [long]$B } else { return [double]$A + [double]$B } }
            '-' { if ($isLong) { return [long]$A - [long]$B } else { return [double]$A - [double]$B } }
            '*' { if ($isLong) { return [long]$A * [long]$B } else { return [double]$A * [double]$B } }
            '/' { if ($isLong) { return [long][math]::Truncate([double]$A / [double]$B) } else { return [double]$A / [double]$B } }
            '%' { return [long]$A % [long]$B }
        }
    }
    if ($A -is [datetime] -and $B -is [timespan]) { if ($Op -eq '+') { return $A.Add($B) } if ($Op -eq '-') { return $A.Subtract($B) } }
    if ($A -is [timespan] -and $B -is [datetime] -and $Op -eq '+') { return $B.Add($A) }
    if ($A -is [datetime] -and $B -is [datetime] -and $Op -eq '-') { return $A.ToUniversalTime().Subtract($B.ToUniversalTime()) }
    if ($A -is [timespan] -and $B -is [timespan]) { if ($Op -eq '+') { return $A.Add($B) } if ($Op -eq '-') { return $A.Subtract($B) } }
    if ($A -is [timespan] -and (Test-KqlNumber $B) -and $Op -eq '*') { return [timespan]::FromTicks([long]($A.Ticks * [double]$B)) }
    throw "KqlLite: unsupported arithmetic $($A.GetType().Name) $Op $($B.GetType().Name)"
}

$script:KqlAggregates = @('take_any', 'take_anyif', 'make_list', 'make_set', 'count', 'countif', 'max', 'min')

function Invoke-KqlAggregate {
    param([string]$Name, [object[]]$Arguments, [hashtable]$Ctx)
    $rows = $Ctx.AggRows
    $sub = $Ctx.Clone()
    $sub.AggRows = $null
    switch -CaseSensitive ($Name) {
        'take_any' { foreach ($r in $rows) { $sub.Row = $r; return , (Invoke-KqlExpression -Ast $Arguments[0] -Ctx $sub) }; return $null }
        'take_anyif' {
            foreach ($r in $rows) {
                $sub.Row = $r
                if (Test-KqlTrue (Invoke-KqlExpression -Ast $Arguments[1] -Ctx $sub)) { return , (Invoke-KqlExpression -Ast $Arguments[0] -Ctx $sub) }
            }
            return $null
        }
        'make_list' {
            $vals = [System.Collections.Generic.List[object]]::new()
            foreach ($r in $rows) { $sub.Row = $r; $v = Invoke-KqlExpression -Ast $Arguments[0] -Ctx $sub; if ($null -ne $v) { $vals.Add($v) } }
            return , $vals.ToArray()
        }
        'make_set' {
            $vals = [System.Collections.Generic.List[object]]::new()
            foreach ($r in $rows) { $sub.Row = $r; $v = Invoke-KqlExpression -Ast $Arguments[0] -Ctx $sub; if ($null -ne $v) { $vals.Add($v) } }
            return , (Get-KqlDistinct -Values $vals.ToArray())
        }
        'count' { return [long]@($rows).Count }
        'countif' {
            $n = 0
            foreach ($r in $rows) { $sub.Row = $r; if (Test-KqlTrue (Invoke-KqlExpression -Ast $Arguments[0] -Ctx $sub)) { $n++ } }
            return [long]$n
        }
        { $_ -ceq 'max' -or $_ -ceq 'min' } {
            $best = $null
            $sign = if ($Name -ceq 'max') { 1 } else { -1 }
            foreach ($r in $rows) {
                $sub.Row = $r
                $v = Invoke-KqlExpression -Ast $Arguments[0] -Ctx $sub
                if ($null -ne $v -and ($null -eq $best -or (Compare-KqlValue -A $v -B $best) * $sign -gt 0)) { $best = $v }
            }
            return , $best
        }
    }
}

function Invoke-KqlFunction {
    param([string]$Name, [object[]]$Arguments, [hashtable]$Ctx)
    if ($script:KqlAggregates -ccontains $Name) {
        if ($null -eq $Ctx.AggRows) { throw "KqlLite: aggregate $Name() outside summarize" }
        return , (Invoke-KqlAggregate -Name $Name -Arguments $Arguments -Ctx $Ctx)
    }
    $arg = { param([int]$k) , (Invoke-KqlExpression -Ast $Arguments[$k] -Ctx $Ctx) }
    switch -CaseSensitive ($Name) {
        'tostring' { return (ConvertTo-KqlString (& $arg 0)) }
        'toupper' { return (ConvertTo-KqlString (& $arg 0)).ToUpperInvariant() }
        'tolower' { return (ConvertTo-KqlString (& $arg 0)).ToLowerInvariant() }
        { $_ -ceq 'toint' -or $_ -ceq 'tolong' } {
            $v = & $arg 0
            if ($null -eq $v) { return $null }
            if ($v -is [bool]) { if ($v) { return [long]1 } else { return [long]0 } }
            if (Test-KqlNumber $v) { return [long][math]::Truncate([double]$v) }
            $parsed = [long]0
            if ([long]::TryParse([string]$v, [System.Globalization.NumberStyles]::Integer, [cultureinfo]::InvariantCulture, [ref]$parsed)) { return $parsed }
            return $null
        }
        'isempty' { $v = & $arg 0; return ($null -eq $v -or ($v -is [string] -and $v.Length -eq 0)) }
        'isnotempty' { $v = & $arg 0; return -not ($null -eq $v -or ($v -is [string] -and $v.Length -eq 0)) }
        'isnull' { return ($null -eq (& $arg 0)) }
        'isnotnull' { return ($null -ne (& $arg 0)) }
        { $_ -ceq 'iff' -or $_ -ceq 'iif' } {
            if (Test-KqlTrue (& $arg 0)) { return , (& $arg 1) }
            return , (& $arg 2)
        }
        'case' {
            if ($Arguments.Count % 2 -ne 1) { throw 'KqlLite: case() needs an else value' }
            for ($k = 0; $k -lt $Arguments.Count - 1; $k += 2) { if (Test-KqlTrue (& $arg $k)) { return , (& $arg ($k + 1)) } }
            return , (& $arg ($Arguments.Count - 1))
        }
        'coalesce' {
            for ($k = 0; $k -lt $Arguments.Count; $k++) {
                $v = & $arg $k
                if ($null -ne $v -and -not ($v -is [string] -and $v.Length -eq 0)) { return , $v }
            }
            return $null
        }
        'not' {
            $v = & $arg 0
            if ($null -eq $v) { return $null }
            if ($v -isnot [bool]) { throw "KqlLite: not() of a $($v.GetType().Name)" }
            return (-not $v)
        }
        'strcat' { return (-join @(for ($k = 0; $k -lt $Arguments.Count; $k++) { ConvertTo-KqlString (& $arg $k) })) }
        'strcat_array' {
            $a = & $arg 0
            if (-not (Test-KqlArray $a)) { return '' }
            $parts = [System.Collections.Generic.List[string]]::new()
            foreach ($e in $a) { $parts.Add((ConvertTo-KqlString $e)) }
            return ($parts -join (ConvertTo-KqlString (& $arg 1)))
        }
        'split' { return , [object[]]((ConvertTo-KqlString (& $arg 0)).Split([string](ConvertTo-KqlString (& $arg 1)), [System.StringSplitOptions]::None)) }
        'extract' {
            $m = [regex]::Match((ConvertTo-KqlString (& $arg 2)), (ConvertTo-KqlString (& $arg 0)))
            $g = [int](& $arg 1)
            if ($m.Success -and $g -lt $m.Groups.Count -and $m.Groups[$g].Success) { return $m.Groups[$g].Value }
            return ''
        }
        'extract_all' {
            $rx = [regex]::new((ConvertTo-KqlString (& $arg 0)))
            $src = ConvertTo-KqlString (& $arg ($Arguments.Count - 1))
            $ms = $rx.Matches($src)
            if ($ms.Count -eq 0) { return $null }
            $groups = $rx.GetGroupNumbers().Count - 1
            $vals = [System.Collections.Generic.List[object]]::new()
            foreach ($m in $ms) {
                if ($groups -eq 0) { $vals.Add($m.Value) }
                elseif ($groups -eq 1) { $vals.Add($m.Groups[1].Value) }
                else { $vals.Add([object[]]@(for ($k = 1; $k -le $groups; $k++) { $m.Groups[$k].Value })) }
            }
            return , $vals.ToArray()
        }
        { $_ -ceq 'trim' -or $_ -ceq 'trim_start' -or $_ -ceq 'trim_end' } {
            $rx = ConvertTo-KqlString (& $arg 0)
            $s = ConvertTo-KqlString (& $arg 1)
            if ($Name -ne 'trim_end') { $s = [regex]::Replace($s, "^(?:$rx)+", '') }
            if ($Name -ne 'trim_start') { $s = [regex]::Replace($s, "(?:$rx)+$", '') }
            return $s
        }
        'array_length' { $a = & $arg 0; if (Test-KqlArray $a) { return [long]$a.Count }; return $null }
        { $_ -ceq 'set_difference' -or $_ -ceq 'set_intersect' -or $_ -ceq 'set_union' } {
            $sets = [System.Collections.Generic.List[object]]::new()
            for ($k = 0; $k -lt $Arguments.Count; $k++) {
                $s = & $arg $k
                if (-not (Test-KqlArray $s)) { return $null }
                $sets.Add($s)
            }
            $all = [System.Collections.Generic.List[object]]::new()
            foreach ($s in $sets) { foreach ($e in $s) { $all.Add($e) } }
            if ($Name -ceq 'set_union') { return , (Get-KqlDistinct -Values $all.ToArray()) }
            $out = [System.Collections.Generic.List[object]]::new()
            foreach ($v in (Get-KqlDistinct -Values ([object[]]$sets[0]))) {
                $inOthers = 0
                for ($k = 1; $k -lt $sets.Count; $k++) {
                    foreach ($o in $sets[$k]) { if (Test-KqlTrue (Test-KqlEqual -A $o -B $v)) { $inOthers++; break } }
                }
                if ($Name -ceq 'set_difference' -and $inOthers -eq 0) { $out.Add($v) }
                if ($Name -ceq 'set_intersect' -and $inOthers -eq $sets.Count - 1) { $out.Add($v) }
            }
            return , $out.ToArray()
        }
        { $_ -ceq 'parse_json' -or $_ -ceq 'todynamic' } {
            # A string holding JSON becomes dynamic; anything else is returned as is.
            $v = & $arg 0
            if ($v -isnot [string]) { return , $v }
            try { return , (ConvertFrom-Json -InputObject $v -NoEnumerate -ErrorAction Stop) }
            catch { return $v }
        }
        'set_has_element' {
            $a = & $arg 0
            if (-not (Test-KqlArray $a)) { return $null }
            $v = & $arg 1
            foreach ($e in $a) { if (Test-KqlTrue (Test-KqlEqual -A $e -B $v)) { return $true } }
            return $false
        }
        'ago' { return $Ctx.Now.Subtract([timespan](& $arg 0)) }
        'now' { return $Ctx.Now }
        'dynamic' { return , (& $arg 0) }
        default { throw "KqlLite: function $Name() is not supported" }
    }
}

# -------------------------------------------------------------- pipeline ----

function ConvertTo-KqlAssignment {
    # "Name = expr" items of extend / project / summarize.
    param([string]$Text, [switch]$AllowBareName)
    $items = foreach ($part in (Split-KqlTopLevel -Text $Text -Separator ',')) {
        if ($part -match '^(?s)\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(?![=~])\s*(.+?)\s*$') {
            @{ Name = $Matches[1]; Ast = (ConvertTo-KqlAst -Text $Matches[2]) }
        }
        elseif ($AllowBareName -and $part -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*$') {
            @{ Name = $Matches[1]; Ast = @{ K = 'id'; N = $Matches[1] } }
        }
        else { throw "KqlLite: unsupported assignment '$(Format-KqlStep $part)'" }
    }
    return , @($items)
}

function ConvertTo-KqlOperator {
    param([string]$Text, [switch]$Inner)
    $t = $Text.Trim()
    $step = Format-KqlStep $t
    if ($t -match '^(?s)where\s+(.+)$') { return @{ Op = 'where'; Ast = (ConvertTo-KqlAst -Text $Matches[1]); Text = $step } }
    if ($t -match '^(?s)extend\s+(.+)$') { return @{ Op = 'extend'; Items = (ConvertTo-KqlAssignment -Text $Matches[1]); Text = $step } }
    if ($t -match '^(?:take|limit)\s+(\d+)$') { return @{ Op = 'take'; N = [int]$Matches[1]; Text = $step } }
    if ($Inner) {
        if ($t -match '^(?s)summarize\s+(.+)$' -and $Matches[1] -notmatch '(?s)\bby\b') {
            return @{ Op = 'aggregate'; Items = (ConvertTo-KqlAssignment -Text $Matches[1]); Text = $step }
        }
        throw "KqlLite: unsupported operator inside mv-apply: $step"
    }
    if ($t -match '^(?s)project\s+(.+)$') { return @{ Op = 'project'; Items = (ConvertTo-KqlAssignment -Text $Matches[1] -AllowBareName); Text = $step } }
    if ($t -match '^(?s)mv-apply\s+([A-Za-z_]\w*)\s*=\s*(.+?)(?:\s+to\s+typeof\((\w+)\))?\s+on\s*\((.*)\)\s*$') {
        $var = $Matches[1]; $srcText = $Matches[2]; $cast = $Matches[3]; $innerText = $Matches[4]
        if ($cast -and $cast -cne 'string') { throw "KqlLite: mv-apply to typeof($cast) is not supported" }
        $sub = [System.Collections.Generic.List[object]]::new()
        foreach ($seg in (Split-KqlTopLevel -Text $innerText -Separator '|')) { $sub.Add((ConvertTo-KqlOperator -Text $seg -Inner)) }
        return @{ Op = 'mvapply'; Var = $var; Source = (ConvertTo-KqlAst -Text $srcText); CastString = [bool]$cast; Sub = $sub.ToArray(); Text = $step }
    }
    if ($t -match '^(?s)join\s+kind\s*=\s*leftouter\s+([A-Za-z_]\w*)\s+on\s+(.+)$') {
        $right = $Matches[1]; $on = $Matches[2].Trim()
        if ($on -match '^\$left\.(\w+)\s*==\s*\$right\.(\w+)$') { return @{ Op = 'join'; Right = $right; LeftKey = $Matches[1]; RightKey = $Matches[2]; Text = $step } }
        if ($on -match '^(\w+)$') { return @{ Op = 'join'; Right = $right; LeftKey = $Matches[1]; RightKey = $Matches[1]; Text = $step } }
        throw "KqlLite: unsupported join condition: $step"
    }
    if ($t -match '^(?:sort|order)\s+by\b') { return @{ Op = 'noop'; Text = $step } }
    return @{ Op = 'stop'; Text = $step }
}

function Get-KqlProgram {
    # Parses a .kql file: its let statements and its query.
    param([Parameter(Mandatory)][string]$Path, [datetime]$Now = [datetime]::UtcNow)
    $raw = Get-Content -Raw -LiteralPath $Path
    $render = @{}
    foreach ($m in [regex]::Matches($raw, '(?m)^\s*let\s+([A-Za-z_]\w*)\s*=[^\n]*//\s*@@[A-Z_]+@@')) { $render[$m.Groups[1].Value] = $true }
    $lets = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    $main = $null
    foreach ($stmt in (Split-KqlTopLevel -Text (ConvertTo-KqlCode -Text $raw) -Separator ';')) {
        $s = $stmt.Trim()
        if (-not $s) { continue }
        if ($s -match '^(?s)let\s+([A-Za-z_]\w*)\s*=\s*(.+)$') {
            $name = $Matches[1]; $body = $Matches[2].Trim()
            $entry = @{ Name = $name; Text = $body; Render = [bool]$render[$name]; Kind = 'value'; Value = $null }
            if ((Split-KqlTopLevel -Text $body -Separator '|').Count -gt 1) { $entry.Kind = 'tabular' }
            elseif ($body -match '^toscalar\s*\(') { $entry.Kind = 'scalar-data' }
            else {
                $ctx = @{ Row = @{}; Lets = $lets; Schema = $null; Table = '(let)'; Now = $Now; AggRows = $null }
                try { $entry.Value = Invoke-KqlExpression -Ast (ConvertTo-KqlAst -Text $body) -Ctx $ctx }
                catch { $entry.Kind = 'unsupported'; $entry.Error = $_.Exception.Message }
            }
            $lets[$name] = $entry
        }
        elseif ($null -ne $main) { throw "KqlLite: $Path has more than one query statement" }
        else { $main = $s }
    }
    return @{ Path = $Path; Lets = $lets; Main = $main; Now = $Now; Pipelines = @{} }
}

function Get-KqlPipeline {
    param([hashtable]$Program, [string]$Text)
    if (-not $Program.Pipelines.ContainsKey($Text)) {
        $segs = Split-KqlTopLevel -Text $Text -Separator '|'
        $ops = [System.Collections.Generic.List[object]]::new()
        for ($k = 1; $k -lt $segs.Count; $k++) { $ops.Add((ConvertTo-KqlOperator -Text $segs[$k])) }
        $Program.Pipelines[$Text] = @{ Source = $segs[0].Trim(); Ops = $ops.ToArray() }
    }
    return $Program.Pipelines[$Text]
}

function Copy-KqlRow {
    param([System.Collections.IDictionary]$Row)
    $copy = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($k in $Row.Keys) { $copy[[string]$k] = $Row[$k] }
    return , $copy
}

function Invoke-KqlOperator {
    # One operator over a list of rows; returns the new list.
    param([hashtable]$Op, [object[]]$Rows, [hashtable]$State)
    $out = [System.Collections.Generic.List[object]]::new()
    switch ($Op.Op) {
        'where' {
            foreach ($r in $Rows) {
                $ctx = $State.Ctx.Clone(); $ctx.Row = $r
                $v = Invoke-KqlExpression -Ast $Op.Ast -Ctx $ctx
                if ($null -ne $v -and $v -isnot [bool]) { throw "KqlLite: where-clause is a $($v.GetType().Name), not bool: $($Op.Text)" }
                if (Test-KqlTrue $v) { $out.Add($r) }
            }
        }
        'extend' {
            foreach ($r in $Rows) {
                $n = Copy-KqlRow $r
                $ctx = $State.Ctx.Clone(); $ctx.Row = $n
                foreach ($it in $Op.Items) { $n[$it.Name] = Invoke-KqlExpression -Ast $it.Ast -Ctx $ctx }
                $out.Add($n)
            }
        }
        'project' {
            foreach ($r in $Rows) {
                $ctx = $State.Ctx.Clone(); $ctx.Row = $r
                $n = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
                foreach ($it in $Op.Items) { $n[$it.Name] = Invoke-KqlExpression -Ast $it.Ast -Ctx $ctx }
                $out.Add($n)
            }
            $State.Ctx.Schema = $null   # after project only the projected columns exist
        }
        'take' { for ($k = 0; $k -lt [math]::Min($Op.N, $Rows.Count); $k++) { $out.Add($Rows[$k]) } }
        'noop' { foreach ($r in $Rows) { $out.Add($r) } }
        'mvapply' {
            foreach ($r in $Rows) {
                $ctx = $State.Ctx.Clone(); $ctx.Row = $r
                $arr = Invoke-KqlExpression -Ast $Op.Source -Ctx $ctx
                $sub = [System.Collections.Generic.List[object]]::new()
                if (Test-KqlArray $arr) {
                    foreach ($e in $arr) {
                        $x = Copy-KqlRow $r
                        # Not "= if (...) { $e }": an if-expression would unroll an array element.
                        $val = $e
                        # to typeof(string) casts, it does not convert (Learn, mv-expand: "Array
                        # elements that don't conform with the declared type become null values").
                        if ($Op.CastString -and $e -isnot [string]) { $val = $null }
                        $x[$Op.Var] = $val
                        $sub.Add($x)
                    }
                }
                $cur = $sub.ToArray()
                $agg = $false
                foreach ($sop in $Op.Sub) {
                    if ($sop.Op -eq 'aggregate') {
                        $n = Copy-KqlRow $r
                        $actx = $State.Ctx.Clone(); $actx.Row = $n; $actx.AggRows = $cur
                        foreach ($it in $sop.Items) { $n[$it.Name] = Invoke-KqlExpression -Ast $it.Ast -Ctx $actx }
                        $cur = @($n); $agg = $true
                    }
                    else { $cur = Invoke-KqlOperator -Op $sop -Rows $cur -State $State }
                }
                if (-not $agg -and $cur.Count -eq 0) { continue }   # mv-apply drops a row whose subquery is empty
                foreach ($x in $cur) { $out.Add($x) }
            }
        }
        'join' {
            if (-not $State.JoinRows.ContainsKey($Op.Right)) { throw "KqlLite: '$($Op.Text)' needs the right-hand rows: give joinRows.$($Op.Right) (columns + rows) in the case" }
            $right = $State.JoinRows[$Op.Right]
            foreach ($r in $Rows) {
                if (-not $r.ContainsKey($Op.LeftKey)) { throw "KqlLite: join key '$($Op.LeftKey)' is not a column at '$($Op.Text)'" }
                $matched = [System.Collections.Generic.List[object]]::new()
                foreach ($rr in $right.Rows) {
                    $rv = $null
                    if ($rr.ContainsKey($Op.RightKey)) { $rv = $rr[$Op.RightKey] }
                    if (Test-KqlTrue (Test-KqlEqual -A $r[$Op.LeftKey] -B $rv)) { $matched.Add($rr) }
                }
                if ($matched.Count -eq 0) { $matched.Add($null) }   # leftouter: the left row with empty right columns
                foreach ($m in $matched) {
                    $n = Copy-KqlRow $r
                    foreach ($col in $right.Columns) {
                        $name = $col; $k = 1
                        while ($r.ContainsKey($name)) { $name = "$col$k"; $k++ }
                        $val = $null
                        if ($null -ne $m -and $m.ContainsKey($col)) { $val = $m[$col] }
                        $n[$name] = $val
                    }
                    $out.Add($n)
                }
            }
        }
        default { throw "KqlLite: cannot run operator $($Op.Op)" }
    }
    return , $out.ToArray()
}

function Invoke-KqlTabular {
    # Runs a pipeline over the input rows until it ends or reaches an operator
    # KqlLite does not run. Returns @{ Rows; StoppedAt; DroppedBy }.
    param([hashtable]$Program, [string]$Text, [object[]]$InputRows, [hashtable]$State, [int]$AfterSummarize = 0)
    $pl = Get-KqlPipeline -Program $Program -Text $Text
    $ops = $pl.Ops
    if ($AfterSummarize -gt 0) {
        $idx = @(for ($k = 0; $k -lt $ops.Count; $k++) { if ($ops[$k].Op -eq 'stop' -and $ops[$k].Text -match '^summarize\b') { $k } })
        if ($idx.Count -lt $AfterSummarize) { throw "KqlLite: the query has $($idx.Count) top-level summarize step(s), not $AfterSummarize" }
        $at = $idx[$AfterSummarize - 1]
        # The summarize's output columns: its aggregates and its by-columns.
        if ($ops[$at].Text -notmatch '^summarize\s+(.+?)(?:\s+by\s+(.+))?$') { throw "KqlLite: cannot read the columns of '$($ops[$at].Text)'" }
        $aggText = $Matches[1]; $byText = $Matches[2]
        $produced = @{}
        foreach ($part in (Split-KqlTopLevel -Text $aggText -Separator ',')) { if ($part -match '^\s*([A-Za-z_]\w*)\s*=(?![=~])') { $produced[$Matches[1]] = 'dynamic' } }
        if ($byText) {
            foreach ($part in (Split-KqlTopLevel -Text $byText -Separator ',')) {
                if ($part -match '^\s*([A-Za-z_]\w*)\s*(?:=(?![=~])|$)') { $produced[$Matches[1]] = 'dynamic' }
            }
        }
        foreach ($r in $InputRows) {
            foreach ($col in $r.Keys) {
                if (-not $produced.ContainsKey($col)) { throw "KqlLite: aggregated input column '$col' is not an output of '$($ops[$at].Text)'" }
            }
        }
        $rows = $InputRows
        $ops = @(for ($k = $at + 1; $k -lt $ops.Count; $k++) { $ops[$k] })
        $State.Ctx.Schema = $produced
        $State.Ctx.Table = 'the summarize output'
    }
    elseif ($State.Lets.ContainsKey($pl.Source) -and $State.Lets[$pl.Source].Kind -eq 'tabular') {
        $inner = Invoke-KqlTabular -Program $Program -Text $State.Lets[$pl.Source].Text -InputRows $InputRows -State $State
        if ($inner.StoppedAt) { return @{ Rows = $inner.Rows; StoppedAt = "inside let $($pl.Source): $($inner.StoppedAt)"; DroppedBy = $inner.DroppedBy } }
        if ($inner.DroppedBy) { return $inner }
        $rows = $inner.Rows
    }
    else {
        if ($pl.Source -cne $State.Ctx.Table) { throw "KqlLite: the query reads '$($pl.Source)' but the case feeds '$($State.Ctx.Table)'" }
        $rows = $InputRows
    }
    foreach ($op in $ops) {
        if ($op.Op -eq 'stop') { return @{ Rows = $rows; StoppedAt = $op.Text; DroppedBy = $null } }
        $rows = Invoke-KqlOperator -Op $op -Rows $rows -State $State
        if ($rows.Count -eq 0) { return @{ Rows = $rows; StoppedAt = $null; DroppedBy = $op.Text } }
    }
    return @{ Rows = $rows; StoppedAt = $null; DroppedBy = $null }
}

function ConvertTo-KqlValue {
    # Fixture JSON -> KqlLite value: "ago:30m" -> datetime; schema-typed columns coerced.
    param($Value, [string]$Type, [datetime]$Now)
    if ($Value -is [string] -and $Value -match '^ago:(\d+)(s|m|h|d)$') {
        $n = [double]$Matches[1]
        $span = switch -CaseSensitive ($Matches[2]) { 's' { [timespan]::FromSeconds($n) } 'm' { [timespan]::FromMinutes($n) } 'h' { [timespan]::FromHours($n) } 'd' { [timespan]::FromDays($n) } }
        return $Now.Subtract($span)
    }
    if ($Type -in @('int', 'long') -and (Test-KqlNumber $Value)) { return [long]$Value }
    if ($Type -eq 'real' -and (Test-KqlNumber $Value)) { return [double]$Value }
    return , $Value
}

function Get-KqlPair {
    # @(name, value) pairs of a fixture object (PSCustomObject or dictionary).
    param($Object)
    $pairs = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Object) { return , $pairs.ToArray() }
    if ($Object -is [System.Collections.IDictionary]) { foreach ($k in $Object.Keys) { $pairs.Add([object[]]@([string]$k, $Object[$k])) } }
    else { foreach ($pp in $Object.PSObject.Properties) { $pairs.Add([object[]]@($pp.Name, $pp.Value)) } }
    return , $pairs.ToArray()
}

function Invoke-KqlFixtureQuery {
    <#
        Runs one fixture row (or aggregated rows) through a rule.
          -Row            the input row (PSCustomObject / hashtable), or for
                          -AfterSummarize the aggregated rows (array)
          -Table          the table the row belongs to (its schema: -Schema)
          -Query          '' = the rule's query; else a tabular let's name
          -Lets           overrides: only lets Terraform renders (a // @@...@@
                          marker) or data-derived ones (tabular / toscalar);
                          a constant let is the rule's logic and is refused
          -JoinRows       @{ <let> = @{ columns = @(...); rows = @(...) } }
        Returns @{ Rows; StoppedAt; DroppedBy }.
    #>
    param(
        [Parameter(Mandatory)][hashtable]$Program,
        [Parameter(Mandatory)][AllowNull()]$Row,
        [Parameter(Mandatory)][string]$Table,
        [hashtable]$Schema,
        [string]$Query = '',
        $Lets,
        $JoinRows,
        [int]$AfterSummarize = 0
    )
    $now = $Program.Now
    $letTable = [System.Collections.Generic.Dictionary[string, object]]::new($Program.Lets, [System.StringComparer]::Ordinal)
    foreach ($pair in (Get-KqlPair -Object $Lets)) {
        $name = $pair[0]
        if (-not $letTable.ContainsKey($name)) { throw "KqlLite: the case overrides let '$name', which the rule does not define" }
        $orig = $letTable[$name]
        if (-not ($orig.Render -or $orig.Kind -in @('tabular', 'scalar-data'))) {
            throw "KqlLite: let '$name' is a constant of the rule (no // @@...@@ render marker) - a fixture may not change the rule's logic"
        }
        $v = $pair[1]
        if (Test-KqlArray $v) {
            $conv = [System.Collections.Generic.List[object]]::new()
            foreach ($e in $v) { $conv.Add((ConvertTo-KqlValue -Value $e -Type '' -Now $now)) }
            $v = $conv.ToArray()
        }
        else { $v = ConvertTo-KqlValue -Value $v -Type '' -Now $now }
        $letTable[$name] = @{ Name = $name; Kind = 'value'; Value = $v; Render = $orig.Render; Text = $orig.Text }
    }
    $join = @{}
    foreach ($pair in (Get-KqlPair -Object $JoinRows)) {
        $spec = $pair[1]
        # Assigned, not wrapped in @(): Get-KqlMember returns the array itself.
        $colsValue = Get-KqlMember -Object $spec -Name 'columns'
        $cols = [string[]]$colsValue
        $rowsValue = Get-KqlMember -Object $spec -Name 'rows'
        $rrows = [System.Collections.Generic.List[object]]::new()
        foreach ($rr in $rowsValue) {
            if ($null -eq $rr) { continue }
            $d = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
            foreach ($p2 in (Get-KqlPair -Object $rr)) {
                if ($cols -cnotcontains $p2[0]) { throw "KqlLite: joinRows.$($pair[0]) row has column '$($p2[0])' that its columns list does not name" }
                $d[$p2[0]] = ConvertTo-KqlValue -Value $p2[1] -Type '' -Now $now
            }
            $rrows.Add($d)
        }
        $join[$pair[0]] = @{ Columns = $cols; Rows = $rrows.ToArray() }
    }
    $inputs = [System.Collections.Generic.List[object]]::new()
    if ($AfterSummarize -gt 0) { foreach ($x in @($Row)) { $inputs.Add($x) } } else { $inputs.Add($Row) }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($in in $inputs) {
        $d = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
        foreach ($p2 in (Get-KqlPair -Object $in)) {
            $type = ''
            if ($AfterSummarize -eq 0) {
                if ($null -eq $Schema -or -not $Schema.ContainsKey($p2[0])) { throw "KqlLite: '$($p2[0])' is not a column of $Table (fixtures/table-schemas.json, from Microsoft Learn)" }
                $type = $Schema[$p2[0]]
            }
            $d[$p2[0]] = ConvertTo-KqlValue -Value $p2[1] -Type $type -Now $now
        }
        if ($AfterSummarize -eq 0 -and -not $d.ContainsKey('TimeGenerated')) { $d['TimeGenerated'] = $now.AddMinutes(-30) }
        $rows.Add($d)
    }
    $ctx = @{ Row = $null; Lets = $letTable; Schema = $Schema; Table = $Table; Now = $now; AggRows = $null }
    $state = @{ Ctx = $ctx; Lets = $letTable; JoinRows = $join }
    $text = $Program.Main
    if ($Query) {
        if (-not $letTable.ContainsKey($Query) -or $letTable[$Query].Kind -ne 'tabular') { throw "KqlLite: '$Query' is not a tabular let of the rule" }
        $text = $letTable[$Query].Text
    }
    return Invoke-KqlTabular -Program $Program -Text $text -InputRows $rows.ToArray() -State $state -AfterSummarize $AfterSummarize
}
