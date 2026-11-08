<#
    Offline Pester tests for the ITDR pack: no tenant, no Azure, no Splunk.
        Invoke-Pester ./lab/scripts/monitoring/tests/Itdr.Tests.ps1 -Output Detailed
    (Pester 5.x.) They guard the invariants a reviewer would otherwise have to
    re-check by eye on every change:
      * the containment playbook only ever calls the four Graph operations its
        managed identity is granted, asks a human first, refuses break-glass
        accounts BY OBJECT ID, accepts an answer only from a listed approver
        who is not the subject (and fails closed without a responder id),
        confirms the user compromised on Contain, and never exposes the
        ServiceNow secret;
      * the notify playbook stamps the correlation id the containment run
        looks the ticket up by;
      * every ITDR KQL rule has its SPL twin, a MITRE section, balanced
        brackets and terminated let statements; the Splunk conf is in sync;
      * no rule decides "IaC" by display name: the KQL carries the empty
        IacPrincipalIds placeholder Terraform renders, the SPL a lookup;
      * mocked audit rows (fixtures/itdr-cases.json): each case's operation
        string is one the rule and its twin really match, and the regexes
        that classify a row (hyphenated permissions, removed countries,
        phishable auth-strength combinations, group names read from
        modified properties, the 4769 encryption type in EventData, DCSync
        right GUIDs) give the expected answer when run on the sample text
        (.NET regex; the patterns use only the subset RE2 and .NET share);
      * fixture rows per case, positive and negative, shaped like the Log
        Analytics tables (fixtures/table-schemas.json, from Microsoft Learn),
        run through the rule's OWN row-level pipeline read from the .kql
        (KqlLite.ps1: where / extend / mv-apply / leftouter join / project):
        a positive row comes out with the expected columns (Severity, the
        classification), a negative row is dropped by the step meant to drop
        it, and a name the table does not have fails like it would in the
        workspace. Every case must have a regex chain or rows, and rows must
        include at least one positive and one dropped negative;
      * KqlLite itself against the string-operator examples Microsoft Learn
        documents (has is term-based, case rules of == / =~ / in / in~ ...),
        and mv-apply's "to typeof(string)" as the cast Learn documents (an
        object element becomes null; tostring() is the conversion);
      * the monitoring module references only rule files that exist;
      * the PowerShell scripts pass PSScriptAnalyzer and support -WhatIf.
    There is no Kusto engine offline: KqlLite is a small interpreter of the
    subset these rules use (its header lists the scope and approximations).
    Rules and stages it does not run - summarize aggregation itself, unions,
    functions - are checked structurally only; the semantics are checked in
    the tenant (see the README's tenant-time steps).
#>

BeforeDiscovery {
    $script:LabRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..' '..')).Path
    $script:ItdrRules = @(
        'app-credential-added', 'app-consent-granted', 'ca-policy-changed', 'role-assigned-outside-pim',
        'pim-group-member-added-outside-pim', 'auth-method-changed-by-admin', 'identity-risk',
        'tier0-logon-without-checkout', 'ad-privileged-group-change', 'kerberoast-rc4-service-ticket',
        'dcsync-replication-request',
        # Third set (itdr_v3.tf, 2026-11-06): same structural checks.
        'dormant-privileged-account-reactivation', 'keyvault-bulk-secret-read',
        # Fourth set (itdr_v4.tf, 2026-11-07, review findings B1, B2, C5, D1).
        'operator-signin-outside-allowlist', 'operator-permissions-changed', 'break-glass-auth-method-added',
        'hr-leaver-lag', 'failed-signin-spray-by-asn'
    )
    $script:IacAwareRules = @('app-credential-added', 'app-consent-granted', 'ca-policy-changed',
        'role-assigned-outside-pim', 'pim-group-member-added-outside-pim')
    $script:Cases = @(Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'itdr-cases.json') | ConvertFrom-Json)
    $script:Scripts = @('Deploy-ContainmentPlaybook.ps1', 'Invoke-AdContainment.ps1', 'Deploy-Playbook.ps1')
}

BeforeAll {
    $LabRoot = (Resolve-Path (Join-Path $PSScriptRoot '..' '..' '..')).Path
    . (Join-Path $PSScriptRoot 'KqlLite.ps1')
    $Schemas = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'fixtures' 'table-schemas.json') | ConvertFrom-Json -AsHashtable

    function Merge-FixtureMap {
        # Case-level lets / joinRows, overridden per row.
        param($CaseLevel, $RowLevel)
        $m = @{}
        foreach ($o in @($CaseLevel, $RowLevel)) {
            if ($null -eq $o) { continue }
            foreach ($p in $o.PSObject.Properties) { $m[$p.Name] = $p.Value }
        }
        return $m
    }

    function Get-WorkflowAction {
        # Flattens a Logic App definition into @{ Name; Action; Scope; Siblings }.
        param([hashtable]$Actions, [string]$Scope = 'root')
        foreach ($name in $Actions.Keys) {
            $a = $Actions[$name]
            [pscustomobject]@{ Name = $name; Action = $a; Scope = $Scope; Siblings = @($Actions.Keys) }
            if ($a.ContainsKey('actions')) { Get-WorkflowAction -Actions $a.actions -Scope $name }
            if ($a.ContainsKey('else') -and $a.else.ContainsKey('actions')) { Get-WorkflowAction -Actions $a.else.actions -Scope "$name/else" }
            if ($a.ContainsKey('cases')) { foreach ($c in $a.cases.Keys) { Get-WorkflowAction -Actions $a.cases[$c].actions -Scope "$name/$c" } }
            if ($a.ContainsKey('default') -and $a.default.ContainsKey('actions')) { Get-WorkflowAction -Actions $a.default.actions -Scope "$name/default" }
        }
    }

    function Get-KqlBody {
        # Query text with // comments and string literals removed, for bracket counting.
        param([string]$Path)
        $text = (Get-Content -LiteralPath $Path) | Where-Object { $_ -notmatch '^\s*//' } | ForEach-Object { $_ -replace '\s//\s.*$', '' }
        $joined = $text -join "`n"
        $joined = [regex]::Replace($joined, "@'[^']*'", "''")
        $joined = [regex]::Replace($joined, '@"[^"]*"', '""')
        $joined = [regex]::Replace($joined, '"(?:\\.|[^"\\])*"', '""')
        $joined = [regex]::Replace($joined, "'(?:\\.|[^'\\])*'", "''")
        return $joined
    }

    $contain = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'monitoring' 'playbook-contain.json') | ConvertFrom-Json -AsHashtable
    $notify = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'monitoring' 'playbook-notify.json') | ConvertFrom-Json -AsHashtable
    $wf = @($contain.resources | Where-Object { $_.type -eq 'Microsoft.Logic/workflows' })[0]
    $actions = @(Get-WorkflowAction -Actions $wf.properties.definition.actions)
    $http = @($actions | Where-Object { $_.Action.type -eq 'Http' })
    $graphCalls = @($http | Where-Object { $_.Action.inputs.uri -like 'https://graph.microsoft.com/*' })
    $snowCalls = @($http | Where-Object { $_.Action.inputs.uri -like '*service-now.com*' })
}

Describe 'Containment playbook (lab/monitoring/playbook-contain.json)' {
    It 'is a valid ARM template with a system-assigned identity' {
        $contain.'$schema' | Should -Match 'deploymentTemplate.json'
        $wf.identity.type | Should -Be 'SystemAssigned'
    }

    It 'keeps the ServiceNow password a securestring with an empty default' {
        $contain.parameters.snowPassword.type | Should -Be 'securestring'
        $contain.parameters.snowPassword.defaultValue | Should -BeNullOrEmpty
        $wf.properties.definition.parameters.snowPassword.type | Should -Be 'SecureString'
    }

    It 'hides inputs of every ServiceNow call from run history (secureData)' {
        $snowCalls.Count | Should -BeGreaterThan 0
        foreach ($c in $snowCalls) { $c.Action.runtimeConfiguration.secureData.properties | Should -Contain 'inputs' -Because $c.Name }
    }

    It 'calls Graph only with its managed identity' {
        foreach ($c in $graphCalls) {
            $c.Action.inputs.authentication.type | Should -Be 'ManagedServiceIdentity' -Because $c.Name
            $c.Action.inputs.authentication.audience | Should -Be 'https://graph.microsoft.com' -Because $c.Name
        }
    }

    It 'makes only the Graph calls its app roles cover (read user, read its restricted AUs, revoke sessions, confirm compromised, disable)' {
        $shapes = $graphCalls | ForEach-Object {
            # Expressions first (they contain '?'), then the query string.
            $u = $_.Action.inputs.uri -replace '@\{[^}]+\}', '{id}' -replace '\?.*$', ''
            "$($_.Action.inputs.method) $u"
        } | Sort-Object -Unique
        $allowed = @(
            'GET https://graph.microsoft.com/v1.0/users/{id}',
            'GET https://graph.microsoft.com/v1.0/users/{id}/memberOf/microsoft.graph.administrativeUnit',
            'PATCH https://graph.microsoft.com/v1.0/users/{id}',
            'POST https://graph.microsoft.com/v1.0/users/{id}/revokeSignInSessions',
            'POST https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/confirmCompromised'
        )
        foreach ($s in $shapes) { $allowed | Should -Contain $s }
        $patch = @($graphCalls | Where-Object { $_.Action.inputs.method -eq 'PATCH' })
        foreach ($p in $patch) { @($p.Action.inputs.body.Keys) | Should -Be @('accountEnabled') }
    }

    It 'waits for a Teams approval (4 h timeout) before any Graph write' {
        $wait = @($actions | Where-Object { $_.Name -eq 'Post_approval_card_and_wait' })[0]
        $wait.Action.type | Should -Be 'ApiConnectionWebhook'
        $wait.Action.limit.timeout | Should -Be 'PT4H'
        # The supported Teams action (PostCardAndWaitForResponse, Flow bot, channel), not the
        # deprecated flowcontinuation one the connector swagger marks "deprecated": true (live read 2026-11-05).
        $wait.Action.inputs.path | Should -Match '^/v1\.0/teams/conversation/gatherinput/poster/Flow bot/location/'
        $wait.Action.inputs.path | Should -Not -Match 'flowcontinuation'
        $wait.Action.inputs.body.notificationUrl | Should -Be '@{listCallbackUrl()}'
        # Logic Apps refuses a 'method' on ApiConnectionWebhook inputs ("The 'method' must not be
        # provided in the 'ApiConnectionWebhook' action inputs", run 2026-11-05): the subscribe is always a POST.
        @($wait.Action.inputs.Keys) | Should -Not -Contain 'method'
        $wait.Action.inputs.body.body.recipient.groupId | Should -Be "@parameters('teamsGroupId')"
        $wait.Action.inputs.body.body.recipient.channelId | Should -Be "@parameters('teamsChannelId')"
        # Every write lives under the decided scope -> Switch_on_decision.
        $writes = @($graphCalls | Where-Object { $_.Action.inputs.method -ne 'GET' })
        foreach ($w in $writes) { $w.Scope | Should -Match '^Switch_on_decision/|^Condition_synced_from_AD/else$' -Because $w.Name }
    }

    It 'refuses protected (break-glass) accounts by OBJECT ID only, before the card' {
        $cond = @($actions | Where-Object Name -EQ 'Condition_protected_account')[0]
        $expr = $cond.Action.expression | ConvertTo-Json -Depth 10 -Compress
        $expr | Should -Match 'protectedObjectIds'
        # A UPN prefix anyone can rename into must never decide protection.
        $expr | Should -Not -Match 'Filter_protected_prefixes'
        $contain.parameters.protectedUpnPrefixes.metadata.description | Should -Match 'LOG-ONLY'
        ($actions | Where-Object Name -EQ 'Post_approval_card_and_wait').Scope | Should -Be 'Condition_RMAU_member/else'
        ($actions | Where-Object Name -EQ 'Condition_RMAU_member').Scope | Should -Be 'Condition_protected_account/else'
    }

    It 'escalates restricted-management-AU members to a human instead of asking for an approval it cannot act on' {
        $get = @($actions | Where-Object Name -EQ 'Get_restricted_AUs')[0]
        $get.Action.inputs.uri | Should -Match '/memberOf/microsoft\.graph\.administrativeUnit\?\$select=.*isMemberManagementRestricted'
        $filter = @($actions | Where-Object Name -EQ 'Filter_restricted_AUs')[0]
        $filter.Action.inputs.where | Should -Match "isMemberManagementRestricted'\], true"
        $cond = @($actions | Where-Object Name -EQ 'Condition_RMAU_member')[0]
        @($cond.Action.actions.Keys) | Should -Be @('Append_rmau_escalated')
        $cond.Action.actions.Append_rmau_escalated.inputs.value | Should -Match 'RMAU-scoped responder'
        # No Graph write anywhere on the RMAU branch; a failed AU read is logged, never silent.
        @($graphCalls | Where-Object { $_.Scope -eq 'Condition_RMAU_member' }).Count | Should -Be 0
        @($actions | Where-Object Name -EQ 'Append_rmau_check_failed')[0].Action.runAfter.Get_restricted_AUs | Should -Contain 'Failed'
        # The deploy script grants the read it needs.
        (Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'Deploy-ContainmentPlaybook.ps1') -Raw) | Should -Match "'AdministrativeUnit\.Read\.All'"
    }

    It 'accepts an answer only from a listed approver who is not the subject, and fails closed' {
        $contain.parameters.approverObjectIds.type | Should -Be 'array'
        @($contain.parameters.approverObjectIds.defaultValue).Count | Should -Be 0 -Because 'empty list = every answer ignored'
        $auth = @($actions | Where-Object Name -EQ 'Condition_authorized_approver')[0]
        $auth | Should -Not -BeNullOrEmpty
        $auth.Scope | Should -Be 'Scope_decided'
        $expr = $auth.Action.expression | ConvertTo-Json -Depth 10 -Compress
        $expr | Should -Match 'approverObjectIds'
        $expr | Should -Match "responder'\]\?\['objectId'\]"
        $expr | Should -Match "responder'\]\?\['userPrincipalName'\]"
        # Missing responder identity: coalesced to '' and required to be non-empty (no '#none#' fail-open).
        $expr | Should -Not -Match '#none#'
        @($auth.Action.expression.and).Count | Should -Be 5
        # The decision switch only exists on the authorised branch.
        ($actions | Where-Object Name -EQ 'Switch_on_decision').Scope | Should -Be 'Condition_authorized_approver'
        ($actions | Where-Object Name -EQ 'Append_answer_ignored').Scope | Should -Be 'Condition_authorized_approver/else'
    }

    It 'confirms the user compromised on Contain (closes the loop with CA006), cloud and synced alike' {
        $confirm = @($actions | Where-Object Name -EQ 'Confirm_compromised')[0]
        $confirm.Scope | Should -Be 'Switch_on_decision/Contain'
        $confirm.Action.inputs.body.userIds | Should -Be @("@{body('Get_user')?['id']}")
        $confirm.Action.runAfter.Keys | Should -Contain 'Revoke_sessions'
        (@($actions | Where-Object Name -EQ 'Condition_synced_from_AD')[0]).Action.runAfter.Keys | Should -Contain 'Confirm_compromised'
    }

    It 'never writes to AD: AD-only and synced accounts are flagged for Invoke-AdContainment.ps1' {
        $json = $wf.properties.definition | ConvertTo-Json -Depth 50
        $json | Should -Match 'Invoke-AdContainment\.ps1'
        @($actions | Where-Object { $_.Action.type -eq 'Http' -and $_.Action.inputs.uri -notmatch 'graph\.microsoft\.com|service-now\.com' }) | Should -BeNullOrEmpty
    }

    It 'has unique action names and only same-scope runAfter references' {
        $dupes = $actions.Name | Group-Object | Where-Object Count -GT 1
        $dupes | Should -BeNullOrEmpty
        foreach ($a in $actions) {
            if ($a.Action.ContainsKey('runAfter')) {
                foreach ($dep in $a.Action.runAfter.Keys) { $a.Siblings | Should -Contain $dep -Because "$($a.Name) runAfter $dep" }
            }
        }
    }

    It 'posts the incident card to the SOC channel through the Teams connector, with no webhook secret' {
        $nwf = @($notify.resources | Where-Object { $_.type -eq 'Microsoft.Logic/workflows' })[0]
        # The Workflows webhook URL was a bearer credential (anyone holding it could post): gone.
        @($notify.parameters.Keys) | Should -Not -Contain 'teamsWebhookUrl'
        ($notify | ConvertTo-Json -Depth 50) | Should -Not -Match 'teamsWebhookUrl'
        @($notify.resources | Where-Object { $_.type -eq 'Microsoft.Web/connections' -and $_.name -like '*teams-*' }).Count | Should -Be 1
        $nwf.properties.parameters.'$connections'.value.teams.connectionId | Should -Match "teams-"
        $nwf.dependsOn -join ' ' | Should -Match "teams-"
        $if = $nwf.properties.definition.actions.If_Teams_configured
        ($if.expression | ConvertTo-Json -Depth 10 -Compress) | Should -Match 'teamsGroupId'
        ($if.expression | ConvertTo-Json -Depth 10 -Compress) | Should -Match 'teamsChannelId'
        $post = $if.actions.If_no_card_yet.actions.Post_card_to_SOC_channel
        $post.type | Should -Be 'ApiConnection'
        $post.inputs.host.connection.name | Should -Be "@parameters('`$connections')['teams']['connectionId']"
        $post.inputs.path | Should -Match '^/v1\.0/teams/conversation/adaptivecard/poster/Flow bot/location/'
        $post.inputs.body.recipient.groupId | Should -Be "@parameters('teamsGroupId')"
        $post.inputs.body.recipient.channelId | Should -Be "@parameters('teamsChannelId')"
        $notify.outputs.teamsConnectionName | Should -Not -BeNullOrEmpty
        # The deploy script no longer reads a webhook secret.
        (Get-Content -LiteralPath (Join-Path $PSScriptRoot '..' 'Deploy-Playbook.ps1') -Raw) | Should -Not -Match "'teams-webhook-url'"
    }

    It 'updates the notify ticket by the correlation id the notify playbook sets' {
        $find = @($actions | Where-Object Name -EQ 'Find_ticket_by_correlation_id')[0]
        $find.Action.inputs.queries.sysparm_query | Should -Match "correlation_id=@\{triggerBody\(\)\?\['object'\]\?\['name'\]\}"
        $nwf = @($notify.resources | Where-Object { $_.type -eq 'Microsoft.Logic/workflows' })[0]
        $body = $nwf.properties.definition.actions.If_ServiceNow_configured.actions.If_open_ticket_exists.else.actions.Create_ServiceNow_incident.inputs.body
        $body.correlation_id | Should -Be "@{triggerBody()?['object']?['name']}"
    }
}

Describe 'Notify playbook: one ticket and one card per incident (review finding D2)' {
    BeforeAll {
        $nwf = @($notify.resources | Where-Object { $_.type -eq 'Microsoft.Logic/workflows' })[0]
        $na = $nwf.properties.definition.actions
        $nAll = @(Get-WorkflowAction -Actions $na)
        $sev = "@triggerBody()?['object']?['properties']?['severity']"
    }

    It 'looks for the OPEN ticket of this incident (correlation_id + active) before anything else in the ServiceNow branch' {
        $sn = $na.If_ServiceNow_configured.actions
        @($sn.Keys)[0] | Should -Be 'Find_open_ticket'
        $sn.Find_open_ticket.inputs.method | Should -Be 'GET'
        $sn.Find_open_ticket.inputs.queries.sysparm_query | Should -Be "correlation_id=@{triggerBody()?['object']?['name']}^active=true"
        $sn.Find_open_ticket.runtimeConfiguration.secureData.properties | Should -Contain 'inputs'
    }

    It 'creates a ticket ONLY when none is open, and only after a successful lookup (a failed read never doubles tickets)' {
        $creates = @($nAll | Where-Object { $_.Action.type -eq 'Http' -and $_.Action.inputs.method -eq 'POST' })
        $creates.Count | Should -Be 1
        $creates[0].Name | Should -Be 'Create_ServiceNow_incident'
        $creates[0].Scope | Should -Be 'If_open_ticket_exists/else'
        $na.If_ServiceNow_configured.actions.If_open_ticket_exists.runAfter.Find_open_ticket | Should -Be @('Succeeded')
    }

    It 'a joined alert is a work note on the existing ticket and a comment on the incident' {
        $yes = $na.If_ServiceNow_configured.actions.If_open_ticket_exists.actions
        $yes.Add_work_note_for_joined_alert.inputs.method | Should -Be 'PATCH'
        $yes.Add_work_note_for_joined_alert.inputs.uri | Should -Match "first\(body\('Find_open_ticket'\)\?\['result'\]\)\?\['sys_id'\]"
        $yes.Add_work_note_for_joined_alert.inputs.body.work_notes | Should -Match 'No new ticket was opened'
        $yes.Comment_joined_alert_on_Sentinel_incident.inputs.path | Should -Be '/Incidents/Comment'
    }

    It 'runs one at a time, so two runs can never both miss the ticket or the card marker' {
        $trig = $nwf.properties.definition.triggers.Microsoft_Sentinel_incident
        $trig.runTimeConfiguration.concurrency.runs | Should -Be 1
        $trig.runTimeConfiguration.concurrency.maximumWaitingRuns | Should -BeGreaterThan 0
    }

    It 'posts the card only while the incident (read now, not the trigger copy) lacks the teams-card-posted label, and writes the label only after a delivered card' {
        $t = $na.If_Teams_configured
        # Parallel with ServiceNow (PR #230 review): a slow ServiceNow never holds the card.
        @($t.runAfter.Keys) | Should -Be @('Map_severity_to_priority')
        $t.runAfter.Map_severity_to_priority | Should -Be @('Succeeded')
        @($na.If_ServiceNow_configured.runAfter.Keys) | Should -Be @('Map_severity_to_priority')
        ($t | ConvertTo-Json -Depth 50) | Should -Not -Match "(body|outputs|actions)\\('(Find_open_ticket|Create_ServiceNow_incident|Add_work_note_for_joined_alert)'\\)"
        $t.actions.Read_incident_now.inputs.method | Should -Be 'GET'
        $t.actions.Read_incident_now.inputs.authentication.type | Should -Be 'ManagedServiceIdentity'
        $t.actions.If_no_card_yet.runAfter.Read_incident_now | Should -Be @('Succeeded')
        ($t.actions.If_no_card_yet.expression | ConvertTo-Json -Depth 6 -Compress) | Should -Match 'teams-card-posted'
        $card = $t.actions.If_no_card_yet.actions
        $card.Mark_card_posted.runAfter.Post_card_to_SOC_channel | Should -Be @('Succeeded')
        $card.Mark_card_posted.actions.Write_card_marker.inputs.method | Should -Be 'PUT'
        $card.Mark_card_posted.actions.Write_card_marker.inputs.body.properties | Should -Match 'teams-card-posted'
        @($nAll | Where-Object { $_.Action.type -eq 'ApiConnection' -and $_.Action.inputs.path -like '/v1.0/teams/*' }).Count | Should -Be 1
        @($nAll | Where-Object { $_.Name -eq 'Post_card_to_SOC_channel' })[0].Scope | Should -Be 'If_no_card_yet'
    }

    It 'retries the card marker with a FRESH incident read (new etag) and never re-posts the card (PR #230 review)' {
        $loop = $na.If_Teams_configured.actions.If_no_card_yet.actions.Mark_card_posted
        $loop.type | Should -Be 'Until'
        [int]$loop.limit.count | Should -BeGreaterThan 1
        $loop.limit.timeout | Should -Not -BeNullOrEmpty
        $loop.expression | Should -Match "outputs\('Write_card_marker'\)\?\['statusCode'\]"
        $inner = $loop.actions
        $inner.Read_incident_for_marker.inputs.method | Should -Be 'GET'
        $inner.Read_incident_for_marker.inputs.authentication.type | Should -Be 'ManagedServiceIdentity'
        $inner.Write_card_marker.runAfter.Read_incident_for_marker | Should -Be @('Succeeded')
        # The etag and properties come from the read INSIDE the loop, never the pre-post copy.
        $inner.Write_card_marker.inputs.body.etag | Should -Be "@body('Read_incident_for_marker')?['etag']"
        $inner.Write_card_marker.inputs.body.properties | Should -Not -Match 'Read_incident_now'
        $inner.Write_card_marker.inputs.body.properties | Should -Match "body\('Read_incident_for_marker'\)"
        # The Teams post is outside the loop: a retry writes the label only.
        @($nAll | Where-Object { $_.Scope -eq 'Mark_card_posted' -and $_.Action.type -eq 'ApiConnection' }).Count | Should -Be 0
        @($nAll | Where-Object { $_.Name -eq 'Post_card_to_SOC_channel' })[0].Scope | Should -Be 'If_no_card_yet'
    }

    It 'Informational incidents open no ticket and post no card (review finding B5)' {
        foreach ($b in 'If_ServiceNow_configured', 'If_Teams_configured') {
            ($na[$b].expression.and | ConvertTo-Json -Depth 5 -Compress) | Should -Match ([regex]::Escape('{"not":{"equals":["' + $sev + '","Informational"]}}')) -Because $b
        }
    }
}

Describe 'Teams drill helpers (authorize-teams-connection.mjs, answer-teams-card.mjs)' {
    BeforeAll {
        $authorize = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..' 'authorize-teams-connection.mjs')
        $answer = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..' 'answer-teams-card.mjs')
    }

    It 'authorizes Teams connections only, and only counts Connected AS the requested account' {
        $authorize | Should -Match "conn\.api !== 'teams'"
        $authorize | Should -Match "conn\.status === 'Connected' && conn\.user\.toLowerCase\(\) === upn"
        # The consent code reaches az on stdin, never in argv.
        $authorize | Should -Match "'--body', '@/dev/stdin'"
        $authorize | Should -Match 'confirmConsentCode'
        $authorize | Should -Not -Match "'--body', [^']*code"
        # The owner and break-glass refusal comes from the toolkit's checkUpn.
        $authorize | Should -Match 'checkUpn\('
    }

    It 'acts (Contain / Revoke) only when every account on the incident is a test or drill account, read from Sentinel + Graph, never the card text' {
        # Trusted sources: the incident's entities, then each UPN by object id.
        $answer | Should -Match '/entities\?\$\{api\}'
        $answer | Should -Match 'graph\.microsoft\.com/v1\.0/users/\$\{id\}\?\$select=userPrincipalName'
        $answer | Should -Match "choice !== 'reject'"
        $answer | Should -Match '!drillOnly\(subjects\)'
        # A brand-new incident's empty entity list is retried, never taken as an answer.
        $answer | Should -Match 'if \(subjects\.length\) break'
        # No subject parsed out of card text (a display name can hold a fake address).
        $answer | Should -Not -Match 'subjectOf'
        # The click goes to the tagged button, never to a page-wide index that can shift.
        $answer | Should -Match 'button\[data-soc-drill='
        $answer | Should -Not -Match "locator\('button'\)\.nth\("
        $node = Get-Command node -ErrorAction SilentlyContinue
        if (-not $node) { Set-ItResult -Skipped -Because 'node is not installed'; return }
        $fn = [regex]::Match($answer, '(?ms)^function drillOnly.*?^}').Value
        $re = [regex]::Match($answer, 'const DRILL_SUBJECT = (/.*/i);').Groups[1].Value
        $fn | Should -Not -BeNullOrEmpty
        $js = @"
const DRILL_SUBJECT = $re;
$fn
const cases = [
  [['itdr-drill-20261105@ContosoHealthLab.onmicrosoft.com'], true],
  [['test-user-a@contosohealthlab.com', 'itdr-drill-x@contosohealthlab.com'], true],
  [['MichaelWilliams@ContosoHealthLab.onmicrosoft.com'], false],
  [['test-user-a@contosohealthlab.com', 'adm-raj@contosohealthlab.com'], false],
  [['test-user-a@evil.example'], false],
  [[''], false],
  [[], false],
];
const bad = cases.filter(([u, ok]) => drillOnly(u) !== ok);
console.log(bad.length);
"@
        $out = $js | & $node.Source -
        $out | Should -Be '0'
    }
}

Describe 'ITDR detection <_> (KQL + SPL twin)' -ForEach $ItdrRules {
    BeforeAll {
        $kql = Join-Path $LabRoot 'kql' "$_.kql"
        $spl = Join-Path $LabRoot 'splunk' 'detections' "$_.spl"
        $kqlText = Get-Content -Raw -LiteralPath $kql
        $splText = Get-Content -Raw -LiteralPath $spl
        $body = Get-KqlBody -Path $kql
    }

    It 'has both files' {
        $kql | Should -Exist
        $spl | Should -Exist
    }

    It 'carries the header sections reviewers rely on' {
        foreach ($s in 'WHAT IT CATCHES', 'TABLE / SOURCE', 'LICENSE', 'MITRE ATT&CK', 'FALSE-POSITIVE NOTES', 'AUTOMATED RESPONSE') {
            $kqlText | Should -Match ([regex]::Escape($s))
        }
        $kqlText | Should -Match 'T1[0-9]{3}'
    }

    It 'has balanced brackets once comments and strings are removed' {
        foreach ($pair in @(@('(', ')'), @('[', ']'), @('{', '}'))) {
            ([regex]::Matches($body, [regex]::Escape($pair[0]))).Count | Should -Be ([regex]::Matches($body, [regex]::Escape($pair[1]))).Count -Because "$($pair[0])$($pair[1]) in $_"
        }
    }

    It 'terminates every let statement' {
        $lets = [regex]::Matches($body, '(?ms)^\s*let\s+\w+\s*=.*?(;|\z)')
        foreach ($l in $lets) { $l.Value.TrimEnd() | Should -Match ';$' -Because $l.Value.Substring(0, [Math]::Min(60, $l.Value.Length)) }
    }

    It 'computes the Severity column the Sentinel rule reads' {
        $body | Should -Match '\|\s*extend\s+Severity\s*='
    }

    It 'SPL twin: base search on line 1, one @stanza, points at its KQL twin' {
        ($splText -split "`n")[0] | Should -Match '^index=entra '
        ([regex]::Matches($splText, '@stanza ')).Count | Should -Be 1
        $splText | Should -Match ([regex]::Escape("lab/kql/$_.kql"))
    }

    It 'SPL twin: the pipeline is real SPL, not commented out (review of #233)' {
        $lines = $splText -split "`n"
        @($lines | Where-Object { $_ -match '^\| (where|eval|stats|table|lookup|spath)\b' }).Count | Should -BeGreaterThan 1
        @($lines | Where-Object { $_ -match '^``` \| ' }).Count | Should -Be 0
        @($lines | Select-Object -Skip 1 | Where-Object { $_ -and $_ -notmatch '^```' -and $_ -notmatch '^\|' }).Count | Should -Be 0
    }
}

Describe 'Splunk app and Terraform module stay in sync' {
    It 'savedsearches.conf matches detections/*.spl (render-savedsearches.sh --check)' {
        $renderer = Join-Path $LabRoot 'splunk' 'render-savedsearches.sh'
        $out = & bash $renderer --check 2>&1
        $LASTEXITCODE | Should -Be 0 -Because ($out -join "`n")
    }

    It 'modules/monitoring references only rule files that exist' {
        $tf = (Get-ChildItem (Join-Path $LabRoot 'terraform' 'modules' 'monitoring') -Filter '*.tf' | Get-Content -Raw) -join "`n"
        $files = [regex]::Matches($tf, 'file\s+=\s+"([a-z0-9-]+\.kql)"') | ForEach-Object { $_.Groups[1].Value }
        $files.Count | Should -BeGreaterOrEqual 16
        foreach ($f in $files) { Join-Path $LabRoot 'kql' $f | Should -Exist }
    }
}

Describe 'IaC identity by immutable id (<_>)' -ForEach $IacAwareRules {
    BeforeAll {
        $kqlText = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'kql' "$_.kql")
        $splText = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'splunk' 'detections' "$_.spl")
    }

    It 'KQL carries the empty IacPrincipalIds placeholder Terraform renders, and never trusts the display name' {
        $kqlText | Should -Match ([regex]::Escape('let IacPrincipalIds = dynamic([]); // @@IAC_PRINCIPAL_IDS@@'))
        $kqlText | Should -Match 'InitiatedBy\.app\.servicePrincipalId'
        $kqlText | Should -Match 'InitiatedBy\.app\.appId'
        $kqlText | Should -Not -Match 'ActorApp in \('
        $kqlText | Should -Match 'IacNameSpoof, +"High"|IacNameSpoof,\s+"High"'
    }

    It 'SPL twin uses the contoso_iac_principals lookup on servicePrincipalId / appId' {
        $splText | Should -Match 'lookup contoso_iac_principals\.csv principal_id AS Actor(App)?SpId'
        $splText | Should -Match 'lookup contoso_iac_principals\.csv principal_id AS ActorAppId'
        $splText | Should -Not -Match 'in\(ActorApp, "gh-oidc'
    }
}

Describe 'KqlLite: <_.expr>' -ForEach @(
    # Examples from Microsoft Learn (Kusto "String operators" and the function
    # pages): KqlLite must give the documented answer before its verdict on a
    # rule means anything.
    @{ expr = '"aBc" == "aBc"'; want = $true }
    @{ expr = '"abc" != "ABC"'; want = $true }
    @{ expr = '"abc" =~ "ABC"'; want = $true }
    @{ expr = '"aBc" !~ "xyz"'; want = $true }
    @{ expr = '"FabriKam" contains "BRik"'; want = $true }
    @{ expr = '"Fabrikam" !contains "xyz"'; want = $true }
    @{ expr = '"FabriKam" contains_cs "Kam"'; want = $true }
    @{ expr = '"Fabrikam" endswith "Kam"'; want = $true }
    @{ expr = '"Fabrikam" endswith_cs "kam"'; want = $true }
    @{ expr = '"Fabrikam" !endswith "brik"'; want = $true }
    @{ expr = '"North America" has "america"'; want = $true }
    @{ expr = '"North America" !has "amer"'; want = $true }
    @{ expr = '"North America" has_cs "America"'; want = $true }
    @{ expr = '"North and South America" has_all("south", "north")'; want = $true }
    @{ expr = '"North America" has_any("south", "north")'; want = $true }
    @{ expr = '"North America" hasprefix "ame"'; want = $true }
    @{ expr = '"North America" hassuffix "ica"'; want = $true }
    @{ expr = '"KustoExplorerQueryRun" has "Explorer"'; want = $false }
    @{ expr = '"KustoExplorerQueryRun" contains "Explorer"'; want = $true }
    @{ expr = '"abc" in ("123", "345", "abc")'; want = $true }
    @{ expr = '"bca" !in ("123", "345", "abc")'; want = $true }
    @{ expr = '"Abc" in~ ("123", "345", "abc")'; want = $true }
    @{ expr = '"bCa" !in~ ("123", "345", "ABC")'; want = $true }
    @{ expr = '"Abc" in ("123", "345", "abc")'; want = $false }
    @{ expr = '"Fabrikam" matches regex "b.*k"'; want = $true }
    @{ expr = '"Fabrikam" startswith "fab"'; want = $true }
    @{ expr = '"Fabrikam" startswith_cs "Fab"'; want = $true }
    @{ expr = '"Fabrikam" !startswith_cs "fab"'; want = $true }
    @{ expr = 'extract("x=([0-9.]+)", 1, "hello x=45.6|wo")'; want = '45.6' }
    @{ expr = 'trim("--", "--https://www.bing.com--")'; want = 'https://www.bing.com' }
    @{ expr = 'split("aa_bb", "_")'; want = @('aa', 'bb') }
    @{ expr = 'coalesce(tolong("not a number"), tolong("42"), 33)'; want = 42 }
    @{ expr = 'set_difference(dynamic([1, 2, 3]), dynamic([1, 2]))'; want = @(3) }
    @{ expr = 'isempty("") and isnotempty("a") and isnull(dynamic(null))'; want = $true }
) {
    It 'gives the answer Microsoft Learn documents' {
        $ctx = @{ Row = @{}; Lets = @{}; Schema = $null; Table = 'none'; Now = [datetime]::UtcNow; AggRows = $null }
        $got = Invoke-KqlExpression -Ast (ConvertTo-KqlAst -Text $expr) -Ctx $ctx
        (ConvertTo-Json -InputObject $got -Compress) | Should -Be (ConvertTo-Json -InputObject $want -Compress)
    }
}

Describe 'KqlLite: mv-apply element typing (Learn, mv-expand)' {
    # "to typeof(string)" is cast-only: Learn says array elements that do not
    # conform with the declared type become null values. tostring() converts.
    # app-credential-added.kql diffs FIC objects, so it must use tostring():
    # KqlLite used to stringify on the cast, which hid exactly that bug.
    BeforeAll {
        $script:MvApplyList = {
            param([string]$Step)
            $row = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
            $row['a'] = ConvertFrom-Json -NoEnumerate -InputObject '[{"Issuer":"https://token.actions.githubusercontent.com","Subject":"repo:x"},"[KeyType=Password]"]'
            $ctx = @{ Row = $null; Lets = @{}; Schema = $null; Table = 'none'; Now = [datetime]::UtcNow; AggRows = $null }
            $out = Invoke-KqlOperator -Op (ConvertTo-KqlOperator -Text $Step) -Rows @($row) -State @{ Ctx = $ctx; Lets = @{}; JoinRows = @{} }
            , @($out[0]['l'])
        }
    }

    It 'to typeof(string) keeps a string element and turns an object into null (make_list skips it)' {
        $got = & $script:MvApplyList 'mv-apply e = a to typeof(string) on (summarize l = make_list(e))'
        $got.Count | Should -Be 1
        $got[0] | Should -BeExactly '[KeyType=Password]'
    }

    It 'tostring() turns the object into its JSON text' {
        $got = & $script:MvApplyList 'mv-apply e = a on (summarize l = make_list(tostring(e)))'
        $got.Count | Should -Be 2
        $got[0] | Should -BeExactly '{"Issuer":"https://token.actions.githubusercontent.com","Subject":"repo:x"}'
        $got[1] | Should -BeExactly '[KeyType=Password]'
    }
}

Describe 'Mocked audit rows (fixtures/itdr-cases.json): <_.rule> / <_.case>' -ForEach $Cases {
    BeforeAll {
        $case = $_
        $kqlText = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'kql' "$($case.rule).kql")
        $splText = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'splunk' 'detections' "$($case.rule).spl")
        $program = Get-KqlProgram -Path (Join-Path $LabRoot 'kql' "$($case.rule).kql")
    }

    It 'the rule and its SPL twin match this operation / category' {
        if ($case.operation) {
            $kqlText.ToLowerInvariant() | Should -Match ([regex]::Escape($case.operation.ToLowerInvariant()))
            $splText.ToLowerInvariant() | Should -Match ([regex]::Escape($case.operation.ToLowerInvariant()))
        }
        if ($case.category) { $kqlText | Should -Match ([regex]::Escape('"' + $case.category + '"')) }
        foreach ($t in @($case.expectInKql)) { $kqlText | Should -Match ([regex]::Escape($t)) }
    }

    It 'is exercised on data: a regex chain, or rows with a positive and a dropped negative' {
        # No structural-only case: a case either runs the rule's regexes on
        # sample text or runs its pipeline on rows (most do both).
        $rows = @($case.rows | Where-Object { $_ })
        (@($case.regexChain | Where-Object { $_ }).Count + $rows.Count) | Should -BeGreaterThan 0
        if ($rows.Count) {
            $case.table | Should -BeIn @($Schemas.Keys) -Because 'rows need the table they belong to'
            @($rows | Where-Object { $null -ne $_.expect }).Count | Should -BeGreaterThan 0 -Because 'at least one positive row'
            @($rows | Where-Object { $null -eq $_.expect -and $_.droppedBy }).Count | Should -BeGreaterThan 0 -Because 'at least one negative row, with the step that drops it'
        }
    }

    if ($_.rows) {
        It 'row - <_.label>' -ForEach @($_.rows) {
            $fx = $_
            $after = if ($fx.afterSummarize) { [int]$fx.afterSummarize } else { 0 }
            $inputRow = if ($after) { , @($fx.rows) } else { $fx.row }
            $query = if ($case.query) { [string]$case.query } else { '' }
            $res = Invoke-KqlFixtureQuery -Program $program -Row $inputRow -Table $case.table -Schema $Schemas[$case.table] `
                -Query $query -Lets (Merge-FixtureMap $case.lets $fx.lets) -JoinRows (Merge-FixtureMap $case.joinRows $fx.joinRows) `
                -AfterSummarize $after
            if ($null -eq $fx.expect) {
                @($res.Rows).Count | Should -Be 0 -Because 'a negative row must be dropped'
                $res.DroppedBy | Should -Not -BeNullOrEmpty
                $res.DroppedBy.Contains($fx.droppedBy) | Should -BeTrue -Because "dropped by '$($res.DroppedBy)', expected the step containing '$($fx.droppedBy)'"
            }
            else {
                @($res.Rows).Count | Should -Be 1 -Because "a positive row must come through (dropped by: $($res.DroppedBy))"
                $out = $res.Rows[0]
                foreach ($p in $fx.expect.PSObject.Properties) {
                    $out.ContainsKey($p.Name) | Should -BeTrue -Because "column $($p.Name) (stopped at: $($res.StoppedAt))"
                    (ConvertTo-Json -InputObject $out[$p.Name] -Compress -Depth 10) |
                        Should -Be (ConvertTo-Json -InputObject $p.Value -Compress -Depth 10) -Because "column $($p.Name)"
                }
            }
        }
    }

    if ($_.regexChain) {
        It 'the classifying regex chain gives the expected set on the sample text' {
            # Every pattern must be in the KQL VERBATIM (so this runs the regex the
            # rule ships with), then it is applied in order: each step's group 1
            # (or whole match) feeds the next; the last step yields the set.
            foreach ($rx in $case.regexChain) { $kqlText | Should -Match ([regex]::Escape($rx)) }
            $extract = {
                param([string]$Text, [string[]]$Chain)
                $vals = @($Text)
                foreach ($rx in $Chain) {
                    $next = foreach ($v in $vals) {
                        foreach ($m in [regex]::Matches([string]$v, $rx)) { if ($m.Groups.Count -gt 1) { $m.Groups[1].Value } else { $m.Value } }
                    }
                    $vals = @($next)
                }
                , @($vals | Where-Object { $_ -ne '' })
            }
            $old = & $extract $case.oldText $case.regexChain
            $new = & $extract $case.newText $case.regexChain
            $result = @()
            if ($case.op -eq 'oldMinusNew') { $result = @($old | Where-Object { $_ -notin $new }) }
            elseif ($case.op -eq 'newMinusOld') { $result = @($new | Where-Object { $_ -notin $old }) }
            else { $result = @($new) }
            $minus = @($case.minus | Where-Object { $_ })
            if ($minus.Count -gt 0) { $result = @($result | Where-Object { $_ -notin $minus }) }
            @($result | Sort-Object) | Should -Be @($case.expect | Sort-Object)
        }
    }
}

Describe 'PowerShell script <_>' -ForEach $Scripts {
    BeforeAll { $path = Join-Path $PSScriptRoot '..' $_ }

    It 'passes PSScriptAnalyzer (no warnings or errors)' {
        $findings = Invoke-ScriptAnalyzer -Path $path -Severity Warning, Error
        $findings | Should -BeNullOrEmpty -Because (($findings | ForEach-Object { "$($_.RuleName) line $($_.Line): $($_.Message)" }) -join '; ')
    }

    It 'supports -WhatIf' {
        (Get-Command $path).Parameters.Keys | Should -Contain 'WhatIf'
    }
}

Describe 'Splunk break-glass search: one result per throttle key (PR #230 review)' {
    BeforeAll {
        $bgSpl = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'splunk' 'detections' 'break-glass-signin.spl')
    }

    It 'every alert.suppress field is a stats BY field, so a new IP is never folded into a throttled row' {
        $suppress = ([regex]::Match($bgSpl, 'alert\.suppress\.fields = ([A-Za-z,]+)')).Groups[1].Value -split ','
        $suppress | Should -Contain 'IPAddress'
        $statsLine = @($bgSpl -split "`n" | Where-Object { $_ -match '^\|\s*stats\s' })[-1]
        $by = ([regex]::Match($statsLine, '\sBY\s+(.+)$')).Groups[1].Value -split '[,\s]+' | Where-Object { $_ }
        foreach ($f in $suppress) { $by | Should -Contain $f -Because "throttle key $f must split results" }
        $statsLine | Should -Not -Match 'latest\(IPAddress\)'
    }

    It 'a missing IPAddress is kept as empty, not dropped by stats BY' {
        $bgSpl | Should -Match 'IPAddress=coalesce\(IPAddress, ""\)'
    }
}

Describe 'HR leaver lag: only a SUCCESSFUL cloud write counts as a disable (PR #233 review)' {
    BeforeAll {
        $llKql = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'kql' 'hr-leaver-lag.kql')
        $llSpl = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'splunk' 'detections' 'hr-leaver-lag.spl')
        $llCases = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'monitoring' 'kusto-harness' 'cases' 'hr-leaver-lag.json') | ConvertFrom-Json
    }

    It 'KQL CloudDisabled requires ProvisioningStatusInfo.Status == success' {
        $block = ([regex]::Match($llKql, '(?s)let CloudDisabled = .*?;')).Value
        $block | Should -Match ([regex]::Escape('where tostring(parse_json(ProvisioningStatusInfo).Status) =~ "success"'))
    }

    It 'SPL drops a cloud row whose status is not success (null-safe) and keeps InboundStatus from inbound rows only' {
        $llSpl | Should -Match ([regex]::Escape('eval Kind=if(Kind=="cloud" AND coalesce(lower(RowStatus), "")!="success", null(), Kind)'))
        $llSpl | Should -Match ([regex]::Escape('eval InboundStatus=if(Kind=="inbound", RowStatus, null())'))
    }

    It 'the engine cases include a failed cloud export that still alerts' {
        $c = @($llCases.cases | Where-Object id -EQ 'cloud-export-failed')
        $c.Count | Should -Be 1
        $c[0].kind | Should -Be 'positive'
        ($c[0].tables.AADProvisioningLogs | Where-Object { $_.ServicePrincipal -match 'corp\.contosohealthlab\.com' }).ProvisioningStatusInfo | Should -Match 'failure'
    }
}

Describe 'KQL break-glass-signin: one row per account keeps every sign-in IP, result and correlation id (PR #230 review)' {
    BeforeAll {
        $bgKql = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'kql' 'break-glass-signin.kql')
        $bgCases = Get-Content -Raw -LiteralPath (Join-Path $LabRoot 'monitoring' 'kusto-harness' 'cases' 'break-glass-signin.json') | ConvertFrom-Json
    }

    It 'summarizes by account only, and collects IPAddresses, ResultTypes and CorrelationIds next to arg_max' {
        $bgKql | Should -Match 'by UserPrincipalName, UserId'
        $bgKql | Should -Match 'IPAddresses = make_set\(IPAddress, \d+\)'
        $bgKql | Should -Match 'ResultTypes = make_set\(tostring\(ResultType\), \d+\)'
        $bgKql | Should -Match 'CorrelationIds = make_set\(CorrelationId, \d+\)'
        $project = ([regex]::Match($bgKql, '(?ms)^\| project (.+?)^\| sort')).Groups[1].Value
        foreach ($c in 'IPAddresses', 'ResultTypes', 'CorrelationIds') { $project | Should -Match "\b$c\b" -Because "$c must reach the alert" }
    }

    It 'has an engine case where an older success from another IP survives in the one row' {
        $c = @($bgCases.cases | Where-Object id -EQ 'two-ips-one-row-keeps-both')[0]
        $c | Should -Not -BeNullOrEmpty
        $c.expectRows | Should -Be 1
        @($c.tables.SigninLogs).Count | Should -Be 2
        @($c.expect[0].IPAddresses).Count | Should -Be 2
        $c.expect[0].ResultTypes | Should -Contain '0'
    }
}
