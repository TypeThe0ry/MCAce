[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$targets = [ordered]@{
    matrix = Join-Path $PSScriptRoot 'federation-proxy-matrix-smoke.ps1'
    restart = Join-Path $PSScriptRoot 'federation-target-restart-residual-smoke.ps1'
}

function Assert-True {
    param(
        [Parameter(Mandatory)][bool]$Condition,
        [Parameter(Mandatory)][string]$Message
    )
    if (-not $Condition) { throw "FEDERATION_EVIDENCE_TEST_FAILED: $Message" }
}

function Get-ScriptParse {
    param([Parameter(Mandatory)][string]$Path)

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    Assert-True ($errors.Count -eq 0) "PowerShell parse errors in $Path"
    return [pscustomobject]@{
        ast = $ast
        source = [System.IO.File]::ReadAllText($Path)
    }
}

function Get-ParameterNames {
    param([Parameter(Mandatory)]$Ast)

    return @($Ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
}

function Get-FunctionText {
    param(
        [Parameter(Mandatory)]$Ast,
        [Parameter(Mandatory)][string[]]$Names
    )

    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($name in $Names) {
        $matches = @($Ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
                $node.Name -ceq $name
        }, $true))
        Assert-True ($matches.Count -eq 1) "function $name must exist exactly once"
        $parts.Add($matches[0].Extent.Text)
    }
    return ($parts -join "`n`n")
}

function New-ValidatorModule {
    param(
        [Parameter(Mandatory)]$Parse,
        [Parameter(Mandatory)][ValidateSet('matrix', 'restart')][string]$Kind
    )

    $common = @('Get-JsonPropertyNames', 'Test-ExactJsonProperties', 'Test-JsonString',
        'Test-JsonBoolean', 'Test-JsonInteger', 'Test-JsonArray', 'ConvertFrom-StrictJson',
        'ConvertTo-FreshUtcTimestamp', 'Assert-RawTimestampWindow', 'Assert-SanitizedJson',
        'Assert-CommitMarkerRaw')
    if ($Kind -eq 'matrix') {
        $functions = $common + @('Assert-RawCaseReport', 'Assert-PassingAggregateRaw',
            'Get-LatestCompleteEvidenceReport')
        $context = @'
$reportSchema = 'MCACE_FEDERATION_PROXY_MATRIX_EXECUTED_V3'
$bindingSchema = 'MCACE_FEDERATION_PROXY_MATRIX_BINDING_V1'
$commitSchema = 'MCACE_FEDERATION_PROXY_MATRIX_COMMIT_V1'
$MaximumReportAgeMinutes = 60
$fileTimestampLowerBoundTolerance = [TimeSpan]::FromSeconds(2)
$allCases = @(
    [pscustomobject]@{ Pair = 'VelocityToVelocity'; Source = 'VELOCITY'; Target = 'VELOCITY'; SourceNetwork = 'matrix-source-velocity'; TargetNetwork = 'matrix-target-velocity' },
    [pscustomobject]@{ Pair = 'VelocityToBungee'; Source = 'VELOCITY'; Target = 'BUNGEE'; SourceNetwork = 'matrix-source-velocity'; TargetNetwork = 'matrix-target-bungee' },
    [pscustomobject]@{ Pair = 'BungeeToVelocity'; Source = 'BUNGEE'; Target = 'VELOCITY'; SourceNetwork = 'matrix-source-bungee'; TargetNetwork = 'matrix-target-velocity' },
    [pscustomobject]@{ Pair = 'BungeeToBungee'; Source = 'BUNGEE'; Target = 'BUNGEE'; SourceNetwork = 'matrix-source-bungee'; TargetNetwork = 'matrix-target-bungee' }
)
'@
    } else {
        $functions = $common + @('Assert-RawRestartReport', 'Get-RestartReportPropertyNames', 'Assert-PassingAggregateRaw',
            'Get-LatestCompleteEvidenceReport')
        $context = @'
$reportSchema = 'MCACE_FEDERATION_TARGET_RESTART_EXECUTED_V2'
$bindingSchema = 'MCACE_FEDERATION_TARGET_RESTART_BINDING_V1'
$commitSchema = 'MCACE_FEDERATION_TARGET_RESTART_COMMIT_V1'
$MaximumReportAgeMinutes = 60
$fileTimestampLowerBoundTolerance = [TimeSpan]::FromSeconds(2)
'@
    }
    $body = $context + "`n" + (Get-FunctionText -Ast $Parse.ast -Names $functions)
    return New-Module -ScriptBlock ([scriptblock]::Create($body))
}

function Assert-Throws {
    param(
        [Parameter(Mandatory)][scriptblock]$Action,
        [Parameter(Mandatory)][string]$Message
    )

    $threw = $false
    try { & $Action }
    catch { $threw = $true }
    Assert-True $threw $Message
}

function Assert-ReportOnlyReadOnly {
    param(
        [Parameter(Mandatory)]$Parse,
        [Parameter(Mandatory)][string]$Kind
    )

    $branches = @($Parse.ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.IfStatementAst] -and
            $node.Clauses.Count -gt 0 -and
            $node.Clauses[0].Item1.Extent.Text -match '\$ReportOnly'
    }, $true))
    Assert-True ($branches.Count -eq 1) "$Kind must have exactly one ReportOnly branch"
    $text = $branches[0].Extent.Text
    foreach ($forbidden in @('New-EvidencePair', 'WriteAllBytes', 'Directory]::Move',
            'New-Item', 'Remove-Item')) {
        Assert-True (-not $text.Contains($forbidden)) "$Kind ReportOnly branch can mutate evidence: $forbidden"
    }
    Assert-True ($text -match 'Assert-EvidencePair') "$Kind ReportOnly does not validate the committed pair"
    Assert-True ($text -match '(?m)^\s*exit\s+0\s*$') "$Kind ReportOnly does not terminate before Execute"
}

function Assert-GradleProjectDirectoryPinned {
    param(
        [Parameter(Mandatory)]$Parse,
        [Parameter(Mandatory)][string]$Kind
    )

    $commands = @($Parse.ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.Extent.Text.Contains('org.gradle.launcher.GradleMain')
    }, $true))
    if ($commands.Count -eq 1) {
        # Legacy direct invocation: keep the AST-level argument-boundary check.
        $elements = @($commands[0].CommandElements)
        $pins = 0
        for ($index = 0; $index -lt ($elements.Count - 1); $index++) {
            if ($elements[$index] -is [System.Management.Automation.Language.StringConstantExpressionAst] -and
                    $elements[$index].Value -ceq '--project-dir' -and
                    $elements[$index + 1] -is [System.Management.Automation.Language.VariableExpressionAst] -and
                    $elements[$index + 1].VariablePath.UserPath -ceq 'repoRoot') {
                $pins++
            }
        }
        Assert-True ($pins -eq 1) "$Kind GradleMain is not pinned exactly once to --project-dir repoRoot"
    } else {
        # ProcessStartInfo.ArgumentList keeps JVM/Gradle tokens separated on
        # Windows, so GradleMain is an ArgumentList item rather than a
        # PowerShell CommandAst.  Assert its exact token path instead of
        # weakening the project-directory pin.
        Assert-True ($commands.Count -eq 0) "$Kind has an unexpected GradleMain command count: $($commands.Count)"
        Assert-True ($Parse.source -match "ArgumentList\.Add\('org\.gradle\.launcher\.GradleMain'\)") `
            "$Kind ProcessStartInfo is missing the GradleMain token"
        Assert-True ($Parse.source.Contains("'--project-dir', `$repoRoot")) `
            "$Kind GradleArguments is missing the --project-dir token"
        Assert-True ($Parse.source -match 'ArgumentList\.Add\(\[string\]\$argument\)') `
            "$Kind ProcessStartInfo does not preserve each Gradle argument boundary"
    }
    
    Assert-True ($Parse.source -match '\$repoRoot\s*=.*\$PSScriptRoot') `
        "$Kind repository root depends on the caller working directory"
}

function Invoke-MaliciousWorkingDirectoryFixture {
    param(
        [Parameter(Mandatory)]$Matrix,
        [Parameter(Mandatory)]$Restart
    )

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
        ('mcace-federation-malicious-gradle-' + [System.IO.Path]::GetRandomFileName())
    $oldLocation = Get-Location
    try {
        [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'settings.gradle.kts'),
            'rootProject.name = "malicious-shadow"; include("mcace-runtime-integration")')
        [System.IO.File]::WriteAllText((Join-Path $tempRoot 'build.gradle.kts'),
            'allprojects { group = "malicious-shadow" }')
        $shadowModule = Join-Path $tempRoot 'mcace-runtime-integration'
        [System.IO.Directory]::CreateDirectory($shadowModule) | Out-Null
        [System.IO.File]::WriteAllText((Join-Path $shadowModule 'build.gradle.kts'),
            'tasks.register("test") { doLast { error("malicious shadow task must never run") } }')
        Set-Location -LiteralPath $tempRoot
        Assert-GradleProjectDirectoryPinned $Matrix matrix
        Assert-GradleProjectDirectoryPinned $Restart restart
    } finally {
        Set-Location -LiteralPath $oldLocation
        if (Test-Path -LiteralPath $tempRoot) {
            $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
            $tempPrefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
            if (-not $resolvedTemp.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                    -not (Split-Path -Leaf $resolvedTemp).StartsWith(
                        'mcace-federation-malicious-gradle-', [StringComparison]::Ordinal)) {
                throw 'FEDERATION_EVIDENCE_TEST_MALICIOUS_TEMP_DELETE_TARGET_INVALID'
            }
            Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
        }
    }
}

function New-MatrixFixture {
    $cases = @(
        [ordered]@{ pair = 'VelocityToVelocity'; source_proxy = 'VELOCITY'; target_proxy = 'VELOCITY' },
        [ordered]@{ pair = 'VelocityToBungee'; source_proxy = 'VELOCITY'; target_proxy = 'BUNGEE' },
        [ordered]@{ pair = 'BungeeToVelocity'; source_proxy = 'BUNGEE'; target_proxy = 'VELOCITY' },
        [ordered]@{ pair = 'BungeeToBungee'; source_proxy = 'BUNGEE'; target_proxy = 'BUNGEE' }
    )
    foreach ($case in $cases) {
        foreach ($name in @('source_authenticated', 'grant_stored_in_memory',
                'source_client_disconnected_before_target_auth', 'target_locally_authenticated',
                'presentation_sent', 'presentation_shape_valid', 'nonce_distinct_attempted',
                'target_observed', 'same_assertion_replay_rejected', 'content_free_audit',
                'source_audit_healthy', 'target_audit_healthy',
                'local_trust_risk_admission_unchanged', 'target_paper_admission_verified', 'passed')) {
            $case[$name] = $true
        }
    }
    return [ordered]@{
        schema = 'MCACE_FEDERATION_PROXY_MATRIX_EXECUTED_V3'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        source_mode = 'EXECUTED'
        pair_scope = 'ALL'
        expected_case_count = 4
        observed_case_count = 4
        all_cases_passed = $true
        matrix_completed = $true
        transfer_model = 'CLIENT_CARRIED_PROCESS_MEMORY_ONLY'
        source_to_target_broker_present = $false
        explicit_consent_required = $true
        same_process_replay_rejection_covered = $true
        durable_audit_health_covered = $true
        target_restart_residual_covered = $false
        fabric_gui_coverage = $false
        cases = $cases
    }
}

function New-RestartFixture {
    $fixture = [ordered]@{
        schema = 'MCACE_FEDERATION_TARGET_RESTART_EXECUTED_V2'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        source_mode = 'EXECUTED'
        source_proxy = 'VELOCITY'
        target_proxy = 'VELOCITY'
    }
    foreach ($name in @('source_authenticated', 'grant_stored_in_memory_test_harness',
            'source_client_disconnected_before_target_auth', 'first_target_locally_authenticated',
            'first_target_observed', 'old_target_proxy_terminated', 'target_paper_kept_running',
            'target_identity_preserved', 'target_federation_config_preserved',
            'restarted_target_locally_authenticated', 'target_session_changed', 'target_challenge_changed',
            'old_outer_session_rejected', 'old_session_proof_rejected', 'invalid_old_proofs_no_observation',
            'target_restart_residual_reobserved', 'residual_reacceptance',
            'post_restart_same_process_replay_rejected', 'residual_is_observation_only',
            'local_trust_risk_admission_unchanged', 'target_paper_admission_verified', 'content_free_audit',
            'source_audit_healthy', 'target_audit_healthy', 'temporary_proxy_private_keys_removed', 'passed')) {
        $fixture[$name] = $true
    }
    foreach ($name in @('durable_replay_protection',
            'test_only_retained_grant_or_source_session_key_written_to_disk', 'fabric_gui_coverage')) {
        $fixture[$name] = $false
    }
    $fixture.limitations_count = 0
    $fixture.cleanup_process_count = 5
    $fixture.remaining_run_process_count = 0
    return $fixture
}

function New-MatrixRawFixture {
    return [ordered]@{
        schema = 2
        source_proxy = 'VELOCITY'
        target_proxy = 'VELOCITY'
        source_network_id = 'matrix-source-velocity'
        target_network_id = 'matrix-target-velocity'
        source_authenticated = $true
        grant_stored_in_memory = $true
        source_client_disconnected_before_target_auth = $true
        target_locally_authenticated = $true
        presentation_sent = $true
        first_outer_length = 1477
        inner_length = 1319
        nonce_distinct_attempted = $true
        target_observed = $true
        same_assertion_replay_rejected = $true
        content_free_audit = $true
        source_audit_healthy = $true
        target_audit_healthy = $true
        local_trust_risk_admission_unchanged = $true
        target_paper_admission_verified = $true
        fabric_gui_coverage = $false
        limitations = @()
        cleanup_process_ids = @(101, 102, 103, 104)
        remaining_run_processes = @()
        passed = $true
    }
}

function New-RestartRawFixture {
    $fixture = [ordered]@{
        schema = 2
        source_proxy = 'VELOCITY'
        target_proxy = 'VELOCITY'
    }
    foreach ($name in @('source_authenticated', 'grant_stored_in_memory_test_harness',
            'source_client_disconnected_before_target_auth', 'first_target_locally_authenticated',
            'first_target_observed', 'old_target_proxy_terminated', 'target_paper_kept_running',
            'target_identity_preserved', 'target_federation_config_preserved',
            'restarted_target_locally_authenticated', 'target_session_changed', 'target_challenge_changed',
            'old_outer_session_rejected', 'old_session_proof_rejected', 'invalid_old_proofs_no_observation',
            'target_restart_residual_reobserved', 'residual_reacceptance',
            'post_restart_same_process_replay_rejected', 'residual_is_observation_only',
            'local_trust_risk_admission_unchanged', 'target_paper_admission_verified', 'content_free_audit',
            'source_audit_healthy', 'target_audit_healthy', 'temporary_proxy_private_keys_removed', 'passed')) {
        $fixture[$name] = $true
    }
    foreach ($name in @('durable_replay_protection',
            'test_only_retained_grant_or_source_session_key_written_to_disk', 'fabric_gui_coverage')) {
        $fixture[$name] = $false
    }
    $fixture.limitations = @()
    $fixture.cleanup_process_ids = @(201, 202, 203, 204, 205)
    $fixture.remaining_run_processes = @()
    return $fixture
}

function Invoke-StaticChecks {
    param(
        [Parameter(Mandatory)]$Matrix,
        [Parameter(Mandatory)]$Restart
    )

    $matrixParameters = Get-ParameterNames $Matrix.ast
    $restartParameters = Get-ParameterNames $Restart.ast
    foreach ($forbidden in @('ReportPath', 'BindingPath', 'RawReportPath', 'EvidenceRoot',
            'AggregatePath', 'RunPath')) {
        Assert-True ($forbidden -notin $matrixParameters) "matrix exposes ReportOnly path parameter $forbidden"
        Assert-True ($forbidden -notin $restartParameters) "restart exposes ReportOnly path parameter $forbidden"
    }
    Assert-True ($Matrix.source -match "DefaultParameterSetName\s*=\s*'Execute'") 'matrix parameter sets missing'
    Assert-True ($Restart.source -match "DefaultParameterSetName\s*=\s*'Execute'") 'restart parameter sets missing'
    Assert-True ($Matrix.source -match "ParameterSetName\s*=\s*'Report',\s*Mandatory") 'matrix ReportOnly not mandatory/report-only'
    Assert-True ($Restart.source -match "ParameterSetName\s*=\s*'Report',\s*Mandatory") 'restart ReportOnly not mandatory/report-only'
    Assert-True ($Matrix.source -match 'FEDERATION_MATRIX_COMPLETE_4_OF_4_EXECUTION_REQUIRED') 'matrix no 4/4 fail-closed rule'
    Assert-ReportOnlyReadOnly $Matrix matrix
    Assert-ReportOnlyReadOnly $Restart restart

    foreach ($parse in @($Matrix, $Restart)) {
        foreach ($token in @('binding.json', 'commit.json', 'COMMIT_V1',
                'source_manifest_sha256', 'source_file_count',
                'wrapper_sha256', 'velocity_plugin_sha256', 'bungee_plugin_sha256',
                'paper_plugin_sha256', 'java_executable_sha256', 'java_file_version',
                'java_major', 'gradle_version', 'gradle_distribution_sha256',
                'gradle_command_sha256', 'gradle_launcher_sha256', 'gradle_core_sha256',
                'gradle_installation_manifest_sha256', 'raw_report_sha256',
                'raw_report_last_write_at', 'invocation_started_at', 'invocation_finished_at',
                'paper_server_sha256', 'paper_prepared_manifest_sha256',
                'paper_prepared_file_count', 'Get-LatestCompleteEvidenceReport',
                'Open-LockedJsonEvidence', 'Assert-SanitizedJson', 'Assert-EvidencePair',
                'Assert-CommitMarkerRaw', 'Directory]::Move', '.staging-',
                'org.gradle.launcher.GradleMain', '--offline', '--dependency-verification=strict',
                '--rerun-tasks', '--no-build-cache', '--no-configuration-cache', '--no-daemon',
                '--no-parallel', '--max-workers=1', '--gradle-user-home', '--project-dir')) {
            Assert-True ($parse.source.Contains($token)) "required durability token missing: $token"
        }
        Assert-True ($parse.source -notmatch '(?m)^\s*&\s*\$gradle\b') 'gradlew/gradle command execution remains'
        Assert-True ($parse.source -notmatch 'source_mode\s*=\s*if\s*\(\$ReportOnly\)') 'ReportOnly can mint evidence'
        Assert-True ($parse.source -match "source_mode\s*=\s*'EXECUTED'") 'EXECUTED evidence mode missing'
        Assert-True ($parse.source -match 'mcace-server-velocity\\build\\libs') 'current Velocity JAR binding missing'
        Assert-True ($parse.source -match 'mcace-server-bungeecord\\build\\libs') 'current Bungee JAR binding missing'
        Assert-True ($parse.source -match 'mcace-server-paper\\build\\libs') 'current Paper JAR binding missing'
        Assert-True ($parse.source -notmatch 'UtcNow\.AddSeconds\(-2\)') 'two-second pre-run freshness window remains'
    }
    # Both federation probes are release-bound to the immutable Paper
    # 1.21.11/132 asset tree; assert each owner explicitly so a future fixture
    # split cannot silently weaken the release contract.
    Assert-True ($Matrix.source -match 'runtime-assets\\paper\\1\.21\.11\\132\\prepared') `
        'release-bound prepared Paper binding missing'
    Assert-True ($Restart.source -match 'runtime-assets\\paper\\1\.21\.11\\132\\prepared') `
        'restart release-bound prepared Paper binding missing'
    Assert-True ($Matrix.source -match 'velocity_server_sha256') 'matrix Velocity server binding missing'
    Assert-True ($Matrix.source -match 'bungee_server_sha256') 'matrix Bungee server binding missing'
    Assert-True ($Restart.source -match 'velocity_server_sha256') 'restart Velocity server binding missing'
    Assert-True ($Matrix.source -match 'expected_case_count\s*=\s*4') 'matrix expected 4 missing'
    Assert-True ($Matrix.source -match 'observed_case_count\s*=\s*\$aggregateCases\.Count') 'matrix observed count not derived'
    Assert-True ($Matrix.source -match 'source_audit_healthy') 'matrix source audit truth missing'
    Assert-True ($Matrix.source -match 'target_audit_healthy') 'matrix target audit truth missing'
    Assert-True ($Restart.source -match 'residual_reacceptance') 'restart residual truth missing'
    Assert-True ($Restart.source -match 'durable_replay_protection''.*\$report\.\$name' -or
        $Restart.source -match 'durable_replay_protection\s*=\s*\[bool\]') 'restart durable false truth missing'
}

function Invoke-LatestCompleteFixture {
    param(
        [Parameter(Mandatory)]$Module,
        [Parameter(Mandatory)][string]$Kind
    )

    $tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) `
        ("mcace-federation-evidence-" + [System.IO.Path]::GetRandomFileName())
    try {
        [System.IO.Directory]::CreateDirectory($tempRoot) | Out-Null
        $oldComplete = Join-Path $tempRoot '2026-01-01T00-00-00-0000000Z'
        $newComplete = Join-Path $tempRoot '2026-01-02T00-00-00-0000000Z'
        $newestIncomplete = Join-Path $tempRoot '2026-01-03T00-00-00-0000000Z'
        foreach ($directory in @($oldComplete, $newComplete, $newestIncomplete)) {
            [System.IO.Directory]::CreateDirectory($directory) | Out-Null
            [System.IO.File]::WriteAllText((Join-Path $directory 'report.json'), '{}')
        }
        [System.IO.File]::WriteAllText((Join-Path $oldComplete 'binding.json'), '{}')
        [System.IO.File]::WriteAllText((Join-Path $oldComplete 'commit.json'), '{}')
        [System.IO.File]::WriteAllText((Join-Path $newComplete 'binding.json'), '{}')
        [System.IO.File]::WriteAllText((Join-Path $newComplete 'commit.json'), '{}')
        [System.IO.File]::SetLastWriteTimeUtc((Join-Path $oldComplete 'report.json'),
            [DateTime]::UtcNow.AddMinutes(-2))
        [System.IO.File]::SetLastWriteTimeUtc((Join-Path $newComplete 'report.json'),
            [DateTime]::UtcNow.AddMinutes(-1))
        [System.IO.File]::SetLastWriteTimeUtc((Join-Path $newestIncomplete 'report.json'),
            [DateTime]::UtcNow)
        $selected = & $Module {
            param($root)
            $script:evidenceRunsRoot = $root
            Get-LatestCompleteEvidenceReport
        } $tempRoot
        Assert-True ($selected -eq (Join-Path $newComplete 'report.json')) `
            "$Kind did not select latest committed report+binding+marker triplet"

        # Once the newest directory receives a marker it is the latest committed candidate,
        # even when its contents are invalid. ReportOnly must select it and fail closed during
        # pair validation rather than silently fall back to older evidence.
        [System.IO.File]::WriteAllText((Join-Path $newestIncomplete 'binding.json'), '{}')
        [System.IO.File]::WriteAllText((Join-Path $newestIncomplete 'commit.json'), '{}')
        $selectedBad = & $Module {
            param($root)
            $script:evidenceRunsRoot = $root
            Get-LatestCompleteEvidenceReport
        } $tempRoot
        Assert-True ($selectedBad -eq (Join-Path $newestIncomplete 'report.json')) `
            "$Kind fell back past the newest bad committed pair"
    } finally {
        if (Test-Path -LiteralPath $tempRoot) {
            $resolvedTemp = [System.IO.Path]::GetFullPath($tempRoot)
            $tempPrefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\') + '\'
            if (-not $resolvedTemp.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                    -not (Split-Path -Leaf $resolvedTemp).StartsWith('mcace-federation-evidence-',
                        [StringComparison]::Ordinal)) {
                throw 'FEDERATION_EVIDENCE_TEST_TEMP_DELETE_TARGET_INVALID'
            }
            Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
        }
    }
}

function Invoke-CommitMarkerFixture {
    param(
        [Parameter(Mandatory)]$Module,
        [Parameter(Mandatory)][ValidateSet('matrix', 'restart')][string]$Kind
    )

    $generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
    $reportSha = ('a' * 64) -join ''
    $bindingSha = ('b' * 64) -join ''
    $marker = [ordered]@{
        schema = if ($Kind -eq 'matrix') {
            'MCACE_FEDERATION_PROXY_MATRIX_COMMIT_V1'
        } else {
            'MCACE_FEDERATION_TARGET_RESTART_COMMIT_V1'
        }
        generated_at = $generatedAt
        report_schema = if ($Kind -eq 'matrix') {
            'MCACE_FEDERATION_PROXY_MATRIX_EXECUTED_V3'
        } else {
            'MCACE_FEDERATION_TARGET_RESTART_EXECUTED_V2'
        }
        binding_schema = if ($Kind -eq 'matrix') {
            'MCACE_FEDERATION_PROXY_MATRIX_BINDING_V1'
        } else {
            'MCACE_FEDERATION_TARGET_RESTART_BINDING_V1'
        }
        report_sha256 = $reportSha
        binding_sha256 = $bindingSha
        committed = $true
    }
    $report = [pscustomobject]@{ generated_at = $generatedAt }
    $json = $marker | ConvertTo-Json -Depth 4
    & $Module {
        param($raw, $reportHash, $bindingHash, $aggregate)
        Assert-CommitMarkerRaw $raw $reportHash $bindingHash $aggregate
    } $json $reportSha $bindingSha $report

    Assert-Throws { & $Module {
            param($raw, $reportHash, $bindingHash, $aggregate)
            Assert-CommitMarkerRaw $raw $reportHash $bindingHash $aggregate
        } $json $reportSha ((('c' * 64) -join '')) $report } `
        "$Kind commit marker accepted a mixed binding"
    $marker.committed = $false
    Assert-Throws { & $Module {
            param($raw, $reportHash, $bindingHash, $aggregate)
            Assert-CommitMarkerRaw $raw $reportHash $bindingHash $aggregate
        } ($marker | ConvertTo-Json -Depth 4) $reportSha $bindingSha $report } `
        "$Kind accepted an uncommitted marker"
}

function Invoke-RawTimestampWindowFixture {
    param(
        [Parameter(Mandatory)]$Module,
        [Parameter(Mandatory)][string]$Kind
    )

    $started = [DateTimeOffset]::UtcNow.AddSeconds(-10)
    $finished = $started.AddSeconds(5)
    & $Module {
        param($observed, $notBefore, $notAfter)
        Assert-RawTimestampWindow $observed $notBefore $notAfter 'fixture'
    } $started.AddSeconds(-1) $started $finished
    Assert-Throws { & $Module {
            param($observed, $notBefore, $notAfter)
            Assert-RawTimestampWindow $observed $notBefore $notAfter 'fixture'
        } $started.AddSeconds(-3) $started $finished } `
        "$Kind accepted raw evidence older than filesystem precision tolerance"
    Assert-Throws { & $Module {
            param($observed, $notBefore, $notAfter)
            Assert-RawTimestampWindow $observed $notBefore $notAfter 'fixture'
        } $finished.AddTicks(1) $started $finished } `
        "$Kind accepted future raw evidence"
    Assert-Throws { & $Module {
            param($observed, $notBefore, $notAfter)
            Assert-RawTimestampWindow $observed $notBefore $notAfter 'fixture'
        } ([DateTimeOffset]::UtcNow.AddSeconds(1)) $started ([DateTimeOffset]::UtcNow.AddSeconds(2)) } `
        "$Kind accepted an absolute future raw timestamp"
}

$matrixParse = Get-ScriptParse $targets.matrix
$restartParse = Get-ScriptParse $targets.restart
Invoke-StaticChecks $matrixParse $restartParse
Invoke-MaliciousWorkingDirectoryFixture $matrixParse $restartParse

$matrixModule = New-ValidatorModule $matrixParse matrix
$restartModule = New-ValidatorModule $restartParse restart
try {
    $matrixFixture = New-MatrixFixture
    $matrixJson = $matrixFixture | ConvertTo-Json -Depth 10
    & $matrixModule { param($raw) Assert-SanitizedJson $raw } $matrixJson
    & $matrixModule { param($raw) $null = Assert-PassingAggregateRaw $raw } $matrixJson
    $matrixBadType = New-MatrixFixture
    $matrixBadType.cases[0].source_audit_healthy = 'true'
    Assert-Throws { & $matrixModule { param($raw) $null = Assert-PassingAggregateRaw $raw } `
        ($matrixBadType | ConvertTo-Json -Depth 10) } 'matrix accepted string boolean'
    $matrixIncomplete = New-MatrixFixture
    $matrixIncomplete.cases = @($matrixIncomplete.cases | Select-Object -First 3)
    $matrixIncomplete.observed_case_count = 3
    Assert-Throws { & $matrixModule { param($raw) $null = Assert-PassingAggregateRaw $raw } `
        ($matrixIncomplete | ConvertTo-Json -Depth 10) } 'matrix accepted incomplete 3/4 fixture'
    $matrixRaw = New-MatrixRawFixture
    $matrixRawDefinition = [pscustomobject]@{
        Pair = 'VelocityToVelocity'; Source = 'VELOCITY'; Target = 'VELOCITY'
        SourceNetwork = 'matrix-source-velocity'; TargetNetwork = 'matrix-target-velocity'
    }
    & $matrixModule {
        param($raw, $definition)
        $null = Assert-RawCaseReport ([pscustomobject]@{ raw = $raw }) $definition
    } ($matrixRaw | ConvertTo-Json -Depth 8) $matrixRawDefinition
    $matrixRawBad = New-MatrixRawFixture
    $matrixRawBad.remaining_run_processes = @(999)
    Assert-Throws { & $matrixModule {
            param($raw, $definition)
            $null = Assert-RawCaseReport ([pscustomobject]@{ raw = $raw }) $definition
        } ($matrixRawBad | ConvertTo-Json -Depth 8) $matrixRawDefinition } `
        'matrix raw validator accepted remaining process residue'

    $restartFixture = New-RestartFixture
    $restartJson = $restartFixture | ConvertTo-Json -Depth 8
    & $restartModule { param($raw) Assert-SanitizedJson $raw } $restartJson
    & $restartModule { param($raw) $null = Assert-PassingAggregateRaw $raw } $restartJson
    $restartBadResidual = New-RestartFixture
    $restartBadResidual.residual_reacceptance = $false
    Assert-Throws { & $restartModule { param($raw) $null = Assert-PassingAggregateRaw $raw } `
        ($restartBadResidual | ConvertTo-Json -Depth 8) } 'restart accepted residual_reacceptance=false'
    $restartBadDurable = New-RestartFixture
    $restartBadDurable.durable_replay_protection = $true
    Assert-Throws { & $restartModule { param($raw) $null = Assert-PassingAggregateRaw $raw } `
        ($restartBadDurable | ConvertTo-Json -Depth 8) } 'restart accepted durable_replay_protection=true'
    $restartRaw = New-RestartRawFixture
    & $restartModule {
        param($raw)
        $null = Assert-RawRestartReport ([pscustomobject]@{ raw = $raw })
    } ($restartRaw | ConvertTo-Json -Depth 8)
    $restartRawBad = New-RestartRawFixture
    $restartRawBad.test_only_retained_grant_or_source_session_key_written_to_disk = $true
    Assert-Throws { & $restartModule {
            param($raw)
            $null = Assert-RawRestartReport ([pscustomobject]@{ raw = $raw })
        } ($restartRawBad | ConvertTo-Json -Depth 8) } `
        'restart raw validator accepted retained secret on disk'

    foreach ($module in @($matrixModule, $restartModule)) {
        & $module { Assert-SanitizedJson '{"raw_report":"build/runtime/report.json"}' }
        foreach ($bad in @(
                '{"path":"C:\\secret\\report.json"}',
                '{"path":"/home/user/report.json"}',
                '{"run_id":"123e4567-e89b-12d3-a456-426614174000"}',
                '{"process_id":1234}',
                '{"listener_port":25565}')) {
            Assert-Throws { & $module { param($raw) Assert-SanitizedJson $raw } $bad } `
                'sanitizer accepted UUID/absolute-path/PID/port fixture'
        }
    }

    Invoke-LatestCompleteFixture $matrixModule matrix
    Invoke-LatestCompleteFixture $restartModule restart
    Invoke-CommitMarkerFixture $matrixModule matrix
    Invoke-CommitMarkerFixture $restartModule restart
    Invoke-RawTimestampWindowFixture $matrixModule matrix
    Invoke-RawTimestampWindowFixture $restartModule restart
} finally {
    if ($null -ne $matrixModule) { Remove-Module $matrixModule -Force }
    if ($null -ne $restartModule) { Remove-Module $restartModule -Force }
}

Write-Output ("FEDERATION_EVIDENCE_BINDING_TEST_PASS|PowerShell=" + $PSVersionTable.PSVersion.ToString())
