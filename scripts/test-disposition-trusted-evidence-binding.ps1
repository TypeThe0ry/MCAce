[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$targets = @(
    [pscustomobject]@{
        Name = 'disposition-proxy-matrix-smoke.ps1'
        Prefix = 'DISPOSITION'
        CompleteError = 'DISPOSITION_ADVISORY_COMPLETE_8_OF_8_EXECUTION_REQUIRED'
        Count = 8
        Aggregate = 'MCACE_DISPOSITION_ADVISORY_GUARD_AGGREGATE_V4'
        Binding = 'MCACE_DISPOSITION_ADVISORY_GUARD_BINDING_V3'
        Commit = 'MCACE_DISPOSITION_ADVISORY_GUARD_COMMIT_V1'
    },
    [pscustomobject]@{
        Name = 'trusted-disposition-proxy-matrix-smoke.ps1'
        Prefix = 'TRUSTED_DISPOSITION'
        CompleteError = 'TRUSTED_DISPOSITION_COMPLETE_6_OF_6_EXECUTION_REQUIRED'
        Count = 6
        Aggregate = 'MCACE_TRUSTED_DISPOSITION_PROCESS_AGGREGATE_V4'
        Binding = 'MCACE_TRUSTED_DISPOSITION_PROCESS_BINDING_V3'
        Commit = 'MCACE_TRUSTED_DISPOSITION_PROCESS_COMMIT_V1'
    }
)

function Assert-True {
    param([bool]$Condition, [Parameter(Mandatory)][string]$Message)
    if (-not $Condition) { throw $Message }
}

function Parse-Target {
    param([Parameter(Mandatory)][string]$Path)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseFile(
        $Path, [ref]$tokens, [ref]$errors)
    Assert-True (@($errors).Count -eq 0) "PowerShell parse failed: $Path / $($errors -join '; ')"
    return [pscustomobject]@{
        Ast = $ast
        Source = Get-Content -LiteralPath $Path -Raw
        Tokens = $tokens
    }
}

function Get-FunctionText {
    param($Parse, [Parameter(Mandatory)][string]$Name)
    $function = @($Parse.Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $Name
    }, $true))
    Assert-True ($function.Count -eq 1) "missing or duplicate function $Name"
    return $function[0].Extent.Text
}

function Test-StaticContract {
    param([Parameter(Mandatory)]$Target)

    $path = Join-Path $PSScriptRoot $Target.Name
    $parse = Parse-Target $path
    $source = $parse.Source
    $topLevelParameters = @($parse.Ast.ParamBlock.Parameters | ForEach-Object {
        $_.Name.VariablePath.UserPath
    })
    foreach ($forbidden in @('ReportPath', 'BindingPath', 'CommitPath', 'EvidencePath')) {
        Assert-True ($topLevelParameters -notcontains $forbidden) `
            "$($Target.Name) exposes forbidden evidence path parameter $forbidden"
    }
    foreach ($required in @(
            $Target.Aggregate, $Target.Binding, $Target.Commit, $Target.CompleteError,
            'FabricTarget', 'targetDefinitions', 'target_minecraft_version', 'target_protocol',
            'target_server_java_feature', 'target_server_java_sha256', 'target_prepared_tree_sha256',
            'mcace.runtime.backend-kind=PAPER', 'mcace.runtime.backend.prepared-root.sha256',
            'mcace.runtime.server-java', 'mcace.runtime.server-java-feature',
            'mcace.runtime.velocity-observer.jar',
            'Get-LatestCommittedPair', 'Assert-CommitMarker', 'Get-NewCaseReport',
            'raw_report_last_write_at', 'invocation_started_at', 'invocation_finished_at',
            'case_bindings', 'velocity_server_sha256', 'bungee_server_sha256',
            'paper_server_sha256', 'paper_prepared_manifest_sha256',
            'actual_run_root_digest_coverage', 'runtime_asset_binding_limitation',
            'Close-CaseReportStreams', 'Remove-OwnedRawRoots',
            'Remove-UnpublishedEvidenceRoot',
            'ORG_GRADLE_PROJECT_*', "'--project-dir'", "'--gradle-user-home'",
            "'--offline'", "'--dependency-verification=strict'", "'--rerun-tasks'",
            "'--no-build-cache'", "'--no-configuration-cache'", "'--no-daemon'",
            "'--no-parallel'", "'--max-workers=1'", 'org.gradle.launcher.GradleMain',
            '.staging-', '.attempt-', 'commit.json', '[System.IO.Directory]::Move')) {
        Assert-True ($source.Contains($required)) "$($Target.Name) missing contract: $required"
    }
    Assert-True ($source -notmatch '&\s+\$gradle\b') `
        "$($Target.Name) executes gradlew instead of bound GradleMain"
    Assert-True ($source -notmatch 'Invoke-WebRequest|Invoke-RestMethod|HttpClient|WebClient|curl|wget') `
        "$($Target.Name) contains a network client"
    Assert-True ($source -match 'if\s*\(\s*-not\s+\$ReportOnly\s+-and\s+\$Proxy\s+-cne\s+''Both''\s*\)') `
        "$($Target.Name) does not reject partial Execute scope"
    $expectedCountPattern = 'expected_case_count\s*=\s*' + $Target.Count + '\b'
    Assert-True ($source -match $expectedCountPattern) `
        "$($Target.Name) does not emit exact complete case count"
    Assert-True ($source -match 'matrix_completed\s*=\s*\$true') `
        "$($Target.Name) can emit an incomplete published matrix"
    if ($Target.Prefix -ceq 'DISPOSITION') {
        Assert-True ($source -match
            '\$openRemoteLiveness\s*=\s*@\(\s*''PACKET''\s*,\s*''QUIET_TIMEOUT''\s*,\s*''DATA_FORMAT''\s*\)') `
            "$($Target.Name) remote-liveness open set is not exact"
        Assert-True ($source.Contains('$openRemoteLiveness -ccontains $report.remote_liveness')) `
            "$($Target.Name) does not restrict remote liveness to the explicit open set"
    }

    $selector = Get-FunctionText $parse 'Get-LatestCommittedPair'
    Assert-True ($selector.Contains("Sort-Object Name -Descending")) `
        "$($Target.Name) selector does not use canonical name ordering"
    Assert-True ($selector.Contains("'commit.json'")) `
        "$($Target.Name) selector accepts uncommitted pairs"
    Assert-True ($selector.Contains("'.attempt-*'") -and $selector.Contains("'.staging-*'")) `
        "$($Target.Name) selector can hide an interrupted newer execution"
    Assert-True ($selector -notmatch 'Sort-Object\s+LastWriteTimeUtc') `
        "$($Target.Name) selector trusts mutable directory mtime"

    $reader = Get-FunctionText $parse 'Read-BoundedJsonEvidence'
    Assert-True ($reader.Contains('[System.IO.FileShare]::Read')) `
        "$($Target.Name) evidence reads are not held against delete/write"
    Assert-True ($reader.Contains('Stream = $stream')) `
        "$($Target.Name) evidence lock is not returned to the caller"

    $newRaw = Get-FunctionText $parse 'Get-NewCaseReport'
    foreach ($required in @('BeforePaths', 'InvocationStartedAt', 'InvocationFinishedAt',
            '$newPaths.Count -ne 1', '$writeAt -gt $InvocationFinishedAt',
            '$writeAt -gt [DateTimeOffset]::UtcNow')) {
        Assert-True ($newRaw.Contains($required)) `
            "$($Target.Name) fresh raw gate missing $required"
    }

    $pair = Get-FunctionText $parse 'Assert-EvidencePair'
    Assert-True ($pair.Contains('Assert-CurrentBindingUnchanged $current $currentAfter')) `
        "$($Target.Name) omits final current-binding revalidation"
    Assert-True ($pair.Contains("'binding.json'") -and $pair.Contains("'commit.json'")) `
        "$($Target.Name) pair validation is not an exact committed triplet"

    $aggregateValidator = Get-FunctionText $parse 'Assert-Aggregate'
    Assert-True ($aggregateValidator.Contains('[AllowEmptyCollection()]')) `
        "$($Target.Name) rejects the initially empty held-raw evidence collector"

    $cleanupOrderPattern = '(?s)\}\s*catch\s*\{\s*\$executionFailure\s*=\s*\$_\s*' +
        'Close-CaseReportStreams\s+\$caseReports\s*if\s*\(\s*-not\s+\$published\s*\)' +
        '.*?Remove-OwnedRawRoots\s+\$ownedRawRoots'
    Assert-True ($source -match $cleanupOrderPattern) `
        "$($Target.Name) can delete raw roots before disposing their Windows read locks"
    $publishOrderPattern = '(?s)\[System\.IO\.Directory\]::Move\(\$stagingRoot,\s*\$evidenceRoot\)' +
        '.*?Close-CaseReportStreams\s+\$caseReports' +
        '.*?\[System\.IO\.Directory\]::Delete\(\$attemptRoot,\s*\$false\)' +
        '.*?\$published\s*=\s*\$true'
    Assert-True ($source -match $publishOrderPattern) `
        "$($Target.Name) does not retain raw locks through validation and atomic publish"
    $rollbackOrderPattern = '(?s)if\s*\(\$evidenceMoved\).*?' +
        'Remove-UnpublishedEvidenceRoot\s+\$evidenceRoot.*?' +
        'Remove-OwnedRawRoots\s+\$ownedRawRoots'
    Assert-True ($source -match $rollbackOrderPattern) `
        "$($Target.Name) can retain a minted pair or delete raw inputs after a failed publish"
    $cleanup = Get-FunctionText $parse 'Remove-OwnedRawRoots'
    foreach ($required in @('$entries.Count -ne 1', '$entries[0].Name -cne ''report.json''',
            '[System.IO.File]::Delete', '[System.IO.Directory]::Delete')) {
        Assert-True ($cleanup.Contains($required)) `
            "$($Target.Name) raw cleanup is not exact-owned: $required"
    }
    $closer = Get-FunctionText $parse 'Close-CaseReportStreams'
    Assert-True ($closer.Contains('$report.Stream.Dispose()') -and
            $closer.Contains('$report.Stream = $null')) `
        "$($Target.Name) raw lock disposal is not idempotent for catch/finally"

    $invocations = @($parse.Ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst] -and
            $node.Extent.Text.Contains('org.gradle.launcher.GradleMain')
    }, $true))
    Assert-True ($invocations.Count -eq 1) `
        "$($Target.Name) must contain exactly one GradleMain invocation"
    foreach ($argument in @("'--project-dir'", "'--gradle-user-home'", "'--offline'",
            "'--dependency-verification=strict'", "'--rerun-tasks'", "'--no-build-cache'",
            "'--no-configuration-cache'", "'--no-daemon'", "'--no-parallel'",
            "'--max-workers=1'")) {
        Assert-True ($invocations[0].Extent.Text.Contains($argument)) `
            "$($Target.Name) Gradle argv missing $argument"
    }
}

function Write-FixtureTarget {
    param([Parameter(Mandatory)]$Target, [Parameter(Mandatory)][string]$Root)

    $sourcePath = Join-Path $PSScriptRoot $Target.Name
    $source = Get-Content -LiteralPath $sourcePath -Raw
    $injection = @'
if ($env:MCACE_EVIDENCE_CLEANUP_FIXTURE -ceq '1') {
    $fixtureReport = Assert-DirectLocalPath $env:MCACE_EVIDENCE_CLEANUP_FIXTURE_REPORT
    $fixtureReports = [System.Collections.Generic.List[object]]::new()
    $fixtureRoots = [System.Collections.Generic.List[string]]::new()
    $fixtureStream = [System.IO.File]::Open(
        $fixtureReport, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    $fixtureReports.Add([pscustomobject]@{ Stream = $fixtureStream })
    $fixtureRoots.Add((Split-Path -Parent $fixtureReport))
    $lockedDeleteRejected = $false
    try {
        [System.IO.File]::Delete($fixtureReport)
    } catch {
        $lockedDeleteRejected = Test-Path -LiteralPath $fixtureReport -PathType Leaf
    }
    if (-not $lockedDeleteRejected) {
        throw 'STATIC_CLEANUP_FIXTURE_WINDOWS_LOCK_NOT_ENFORCED'
    }
    Close-CaseReportStreams $fixtureReports
    Remove-OwnedRawRoots $fixtureRoots
    if (Test-Path -LiteralPath (Split-Path -Parent $fixtureReport)) {
        throw 'STATIC_CLEANUP_FIXTURE_ROOT_RETAINED'
    }
    Write-Output 'STATIC_CLEANUP_FIXTURE_PASS'
    exit 0
}

if ($env:MCACE_EVIDENCE_STATIC_FIXTURE -ceq '1') {
    if (-not $ReportOnly -and $Proxy -cne 'Both') { throw '__COMPLETE_ERROR__' }
    $selected = Get-LatestCommittedPair
    Write-Output "STATIC_FIXTURE_SELECTED|$($selected.ReportPath)"
    exit 0
}

if ($ReportOnly) {
'@.Replace('__COMPLETE_ERROR__', $Target.CompleteError)
    $source = $source.Replace(
        'if ($ReportOnly) {', $injection)
    $path = Join-Path $Root $Target.Name
    [System.IO.File]::WriteAllText($path, $source, [Text.UTF8Encoding]::new($false))
    return $path
}

function Invoke-Fixture {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string[]]$Arguments
    )

    $engine = (Get-Process -Id $PID).Path
    $saved = $env:MCACE_EVIDENCE_STATIC_FIXTURE
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $env:MCACE_EVIDENCE_STATIC_FIXTURE = '1'
        # Windows PowerShell 5.1 wraps native stderr as a non-terminating
        # ErrorRecord. Keep it in the captured output instead of allowing this
        # fixture's top-level Stop policy to terminate before LASTEXITCODE is
        # available.
        $ErrorActionPreference = 'Continue'
        $output = @(& $engine -NoProfile -NonInteractive -ExecutionPolicy Bypass `
            -File $Path @Arguments 2>&1)
        return [pscustomobject]@{ ExitCode = $LASTEXITCODE; Text = $output -join "`n" }
    } finally {
        $ErrorActionPreference = $savedErrorActionPreference
        $env:MCACE_EVIDENCE_STATIC_FIXTURE = $saved
    }
}

function Test-DynamicSelectorAndScope {
    param([Parameter(Mandatory)]$Target)

    $root = Join-Path ([System.IO.Path]::GetTempPath()) (
        'mcace-disposition-static-fixture-' + [Guid]::NewGuid().ToString('N'))
    try {
        [void][System.IO.Directory]::CreateDirectory((Join-Path $root 'scripts'))
        $targetPath = Write-FixtureTarget $Target (Join-Path $root 'scripts')
        $evidenceRoot = Join-Path $root $(if ($Target.Prefix -eq 'DISPOSITION') {
            'build/runtime-disposition-matrix/evidence-runs'
        } else { 'build/runtime-trusted-disposition/evidence-runs' })
        [void][System.IO.Directory]::CreateDirectory($evidenceRoot)

        $partial = Invoke-Fixture $targetPath $root @('-Proxy', 'Velocity', '-FabricTarget', '1.21.11')
        Assert-True ($partial.ExitCode -ne 0 -and $partial.Text.Contains($Target.CompleteError)) `
            "$($Target.Name) accepted partial Execute scope: $($partial.Text)"

        $older = Join-Path $evidenceRoot '2026-08-13T00-00-00-0000000Z'
        $newer = Join-Path $evidenceRoot '2026-08-13T00-00-01-0000000Z'
        foreach ($directory in @($older, $newer)) {
            [void][System.IO.Directory]::CreateDirectory($directory)
            [System.IO.File]::WriteAllText((Join-Path $directory 'commit.json'), '{}')
        }
        [System.IO.File]::SetLastWriteTimeUtc((Join-Path $older 'commit.json'), [DateTime]::UtcNow.AddHours(1))
        [System.IO.File]::SetLastWriteTimeUtc((Join-Path $newer 'commit.json'), [DateTime]::UtcNow.AddHours(-1))
        $selected = Invoke-Fixture $targetPath $root @('-ReportOnly', '-FabricTarget', '1.21.11')
        Assert-True ($selected.ExitCode -eq 0 -and $selected.Text.Contains(
                '2026-08-13T00-00-01-0000000Z')) `
            "$($Target.Name) did not select canonical newest committed pair: $($selected.Text)"

        $attempt = Join-Path $evidenceRoot '.attempt-2026-08-13T00-00-02-0000000Z'
        [void][System.IO.Directory]::CreateDirectory($attempt)
        $blocked = Invoke-Fixture $targetPath $root @('-ReportOnly', '-FabricTarget', '1.21.11')
        Assert-True ($blocked.ExitCode -ne 0 -and
                $blocked.Text.Contains('UNCOMMITTED_EXECUTION_PRESENT')) `
            "$($Target.Name) hid an interrupted newer execution: $($blocked.Text)"
        Remove-Item -LiteralPath $attempt -Force

        $badNewest = Join-Path $evidenceRoot '2026-08-13T00-00-03-0000000Z'
        [void][System.IO.Directory]::CreateDirectory($badNewest)
        [System.IO.File]::WriteAllText((Join-Path $badNewest 'report.json'), '{}')
        $badBlocked = Invoke-Fixture $targetPath $root @('-ReportOnly', '-FabricTarget', '1.21.11')
        Assert-True ($badBlocked.ExitCode -ne 0 -and
                $badBlocked.Text.Contains('NEWEST_EVIDENCE_NOT_COMMITTED')) `
            "$($Target.Name) fell back past a malformed newest pair: $($badBlocked.Text)"

        $rawRoot = Join-Path $root $(if ($Target.Prefix -eq 'DISPOSITION') {
            'build/runtime-disposition-matrix/runs/velocity-fixture-cleanup'
        } else { 'build/runtime-trusted-disposition/runs/velocity-fixture-cleanup' })
        [void][System.IO.Directory]::CreateDirectory($rawRoot)
        $rawReport = Join-Path $rawRoot 'report.json'
        [System.IO.File]::WriteAllText($rawReport, '{}')
        $savedCleanupFixture = $env:MCACE_EVIDENCE_CLEANUP_FIXTURE
        $savedCleanupReport = $env:MCACE_EVIDENCE_CLEANUP_FIXTURE_REPORT
        try {
            $env:MCACE_EVIDENCE_CLEANUP_FIXTURE = '1'
            $env:MCACE_EVIDENCE_CLEANUP_FIXTURE_REPORT = $rawReport
            $cleanupResult = Invoke-Fixture $targetPath $root @('-ReportOnly', '-FabricTarget', '1.21.11')
        } finally {
            $env:MCACE_EVIDENCE_CLEANUP_FIXTURE = $savedCleanupFixture
            $env:MCACE_EVIDENCE_CLEANUP_FIXTURE_REPORT = $savedCleanupReport
        }
        Assert-True ($cleanupResult.ExitCode -eq 0 -and
                $cleanupResult.Text.Contains('STATIC_CLEANUP_FIXTURE_PASS') -and
                -not (Test-Path -LiteralPath $rawRoot)) `
            "$($Target.Name) did not dispose before exact raw cleanup: $($cleanupResult.Text)"
    } finally {
        $resolved = [System.IO.Path]::GetFullPath($root)
        $prefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/') +
            [System.IO.Path]::DirectorySeparatorChar + 'mcace-disposition-static-fixture-'
        if ($resolved.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
            Remove-Item -LiteralPath $resolved -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

foreach ($target in $targets) {
    Test-StaticContract $target
    Test-DynamicSelectorAndScope $target
}

Write-Output 'DISPOSITION_TRUSTED_EVIDENCE_BINDING_TEST_PASS'
