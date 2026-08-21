[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'vulcan-paper-enablement-smoke.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) { throw "VULCAN_ENABLEMENT_WRAPPER_PARSE_FAILED: $($errors -join '; ')" }
$source = Get-Content -LiteralPath $target -Raw

$parameters = @{}
foreach ($parameter in $ast.ParamBlock.Parameters) {
    $parameters[$parameter.Name.VariablePath.UserPath] = $parameter
}
$expectedParameters = @('Execute', 'ReportOnly', 'VulcanJar', 'VulcanSha256', 'PaperJar',
    'PaperSha256', 'MCAceJar', 'MCAceSha256', 'PreparedRoot', 'AllowTemporaryPaperRemap',
    'PreparedManifestSha256', 'NetworkPolicy', 'NetworkIsolationAttested', 'MaximumReportAgeMinutes')
$missing = @($expectedParameters | Where-Object { -not $parameters.ContainsKey($_) })
if ($missing.Count -ne 0) { throw "VULCAN_ENABLEMENT_WRAPPER_PARAMETERS_MISSING: $($missing -join ', ')" }

function Test-Mandatory([System.Management.Automation.Language.ParameterAst]$Parameter,
        [string]$ParameterSet) {
    foreach ($attribute in $Parameter.Attributes) {
        if ($attribute.TypeName.FullName -ne 'Parameter') { continue }
        $mandatory = $false
        $set = $null
        foreach ($named in $attribute.NamedArguments) {
            if ($named.ArgumentName -eq 'Mandatory') { $mandatory = $true }
            if ($named.ArgumentName -eq 'ParameterSetName') { $set = $named.Argument.Extent.Text.Trim("'", '"') }
        }
        if ($mandatory -and $set -eq $ParameterSet) { return $true }
    }
    return $false
}

foreach ($name in @('Execute', 'VulcanJar', 'PaperJar', 'MCAceJar', 'PreparedRoot',
        'AllowTemporaryPaperRemap', 'NetworkPolicy', 'NetworkIsolationAttested')) {
    if (-not (Test-Mandatory $parameters[$name] 'Execute')) {
        throw "VULCAN_ENABLEMENT_WRAPPER_EXECUTE_PARAMETER_NOT_MANDATORY: $name"
    }
}
if (-not (Test-Mandatory $parameters.ReportOnly 'Report')) {
    throw 'VULCAN_ENABLEMENT_WRAPPER_REPORT_ONLY_NOT_MANDATORY'
}

$commands = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst]
}, $true))
$commandNames = @($commands | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
$forbidden = @('Invoke-WebRequest', 'Invoke-RestMethod', 'Start-BitsTransfer', 'curl', 'curl.exe',
    'wget', 'wget.exe', 'gradle', 'gradle.bat', 'gradlew', 'gradlew.bat')
$presentForbidden = @($forbidden | Where-Object { $_ -in $commandNames })
if ($presentForbidden.Count -ne 0) {
    throw "VULCAN_ENABLEMENT_WRAPPER_FORBIDDEN_COMMAND: $($presentForbidden -join ', ')"
}

$preparedPinGuard = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Assert-ExpectedPreparedManifest'
}, $true)
if ($null -eq $preparedPinGuard) { throw 'VULCAN_ENABLEMENT_PREPARED_PIN_GUARD_MISSING' }
Invoke-Expression $preparedPinGuard.Extent.Text
$wrongPreparedPinRejected = $false
try {
    Assert-ExpectedPreparedManifest ('a' * 64) ('b' * 64)
} catch {
    $wrongPreparedPinRejected = $_.Exception.Message -eq `
        'VULCAN_ENABLEMENT_PREPARED_MANIFEST_HASH_MISMATCH'
}
if (-not $wrongPreparedPinRejected) {
    throw 'VULCAN_ENABLEMENT_WRONG_PREPARED_PIN_NOT_REJECTED'
}
$copyCommands = @($commands | Where-Object { $_.GetCommandName() -eq 'Copy-Item' })
foreach ($command in $copyCommands) {
    if ($command.Extent.Text -match '(?i)vulcan|mcace') {
        throw 'VULCAN_ENABLEMENT_WRAPPER_PROPRIETARY_OR_PLUGIN_COPY_FOUND'
    }
}

$required = [ordered]@{
    explicit_execute = $source -match '\[switch\]\$Execute' -and
        $source -match 'VULCAN_ENABLEMENT_EXPLICIT_EXECUTION_REMAP_AND_NETWORK_ATTESTATION_REQUIRED'
    explicit_remap = $source -match '\[switch\]\$AllowTemporaryPaperRemap'
    explicit_network = $source -match "\[ValidateSet\('DenyAll'\)\]" -and
        $source -match '\[switch\]\$NetworkIsolationAttested'
    operator_only_network_claim = $source -match 'network_isolation_operator_attested = \$true' -and
        $source -match 'network_isolation_os_verified_by_script = \$false' -and
        $source -match 'NETWORK_ISOLATION_OPERATOR_ATTESTED_NOT_OS_VERIFIED_BY_SCRIPT'
    three_hash_pins = $source -match '\$VulcanSha256' -and $source -match '\$PaperSha256' -and
        $source -match '\$MCAceSha256' -and $source -match 'Open-LockedJar'
    reviewed_vulcan = $source -match '7ee3a4fdd7e9da5269f9efc327478e507563e6e7df7abec2222acd3b499bc993'
    absolute_local_no_reparse = $source -match 'IsPathRooted' -and
        $source -match '\[System\.IO\.DriveType\]::Fixed' -and
        $source -match 'VULCAN_ENABLEMENT_REPARSE_PATH_REJECTED'
    locked_read_only_artifacts = $source -match '\[System\.IO\.FileShare\]::Read' -and
        $source -match '\$lockedVulcan\.stream\.Dispose\(\)'
    direct_add_plugin = $source -match '''--add-plugin'', \$lockedVulcan\.path' -and
        $source -match '''--add-plugin'', \$lockedMCAce\.path'
    no_download_api = $source -notmatch '(?i)HttpClient|WebClient|WebRequest|DownloadFile|bitsadmin'
    prepared_assets = $source -match '\$PreparedRoot' -and
        $source -match '\$PreparedManifestSha256' -and
        $source -match "@\('cache', 'libraries', 'versions'\)" -and
        $source -match 'VULCAN_ENABLEMENT_PREPARED_CACHE_INCOMPLETE' -and
        $source -match 'VULCAN_ENABLEMENT_PREPARED_MANIFEST_HASH_MISMATCH'
    report_only_prepared_pin_bound = $source -match `
        '\$binding\.prepared_manifest_sha256 -cne \$ExpectedPrepared' -and
        $source -match 'Assert-EvidencePair \$path \$expectedVulcan \$expectedPaper \$expectedMCAce \$expectedPrepared'
    isolated_root = $source -match 'Assert-DescendantPath' -and
        $source -match 'build\\vulcan-paper-enablement\\runs'
    loopback_monitor = $source -match 'server-ip=127\.0\.0\.1' -and
        $source -match '127\.0\.0\.1:9' -and $source -match 'mode: MONITOR'
    exact_markers = $source -match '\[Vulcan\\\] Enabling Vulcan v2\\\.9\\\.0' -and
        $source -match 'MCAce Vulcan behavior adapter enabled' -and
        $source -match 'Done \\\(' -and $source -match '\$paperReadyObserved'
    exact_process_cleanup = $source -match 'Test-OwnedProcess' -and
        $source -match 'ExpectedStartTimeUtc' -and $source -match 'processMarker' -and
        $source -match 'VULCAN_ENABLEMENT_PROCESS_OWNERSHIP_UNPROVEN'
    honest_marker_residue = $source -match 'remaining_marker_process_count' -and
        $source -notmatch 'remaining_owned_process_count'
    original_parent_remap_unchanged = $source -match 'function Get-RemapState' -and
        $source -match 'VULCAN_ENABLEMENT_ORIGINAL_ARTIFACT_PARENT_REMAP_CHANGED'
    sanitized_coverage = $source -match 'Assert-SanitizedEvidence' -and
        $source -match 'licensed_plugin_enablement_coverage = \$true' -and
        $source -match 'mcace_listener_registration_coverage = \$true' -and
        $source -match 'real_behavior_event_delivery_coverage = \$false'
    strict_report = $source -match 'Test-ExactProperties' -and
        $source -match 'Test-JsonBoolean' -and $source -match 'Test-JsonInteger'
    bound_report_only = $source -match 'MCACE_VULCAN_PAPER_ENABLEMENT_BINDING_V1' -and
        $source -match 'report_sha256 = Get-BytesSha256 \$reportBytes' -and
        $source -match 'Assert-EvidencePair'
    current_source_runtime_binding = $source -match 'wrapper_sha256' -and
        $source -match 'source_manifest_sha256' -and $source -match 'source_file_count' -and
        $source -match 'java_executable_sha256' -and $source -match 'java_file_version' -and
        $source -match 'function Get-CurrentBinding' -and $source -match 'prepared_manifest_sha256' -and
        $source -match 'prepared_file_count' -and
        $source -match 'VULCAN_ENABLEMENT_PREPARED_CACHE_CHANGED_DURING_RUN'
}
$failed = @($required.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
if ($failed.Count -ne 0) { throw "VULCAN_ENABLEMENT_WRAPPER_STATIC_FAILED: $($failed -join ', ')" }

Write-Output 'VULCAN_ENABLEMENT_WRAPPER_STATIC_PASS'
