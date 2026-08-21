[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$target = Join-Path $PSScriptRoot 'vulcan-genuine-event-smoke.ps1'
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $target, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) {
    throw "VULCAN_GENUINE_EVENT_WRAPPER_PARSE_FAILED: $($errors -join '; ')"
}
$source = Get-Content -LiteralPath $target -Raw

$parameters = @{}
foreach ($parameter in $ast.ParamBlock.Parameters) {
    $parameters[$parameter.Name.VariablePath.UserPath] = $parameter
}
$expectedParameters = @(
    'Execute', 'ReportOnly', 'VulcanJar', 'VulcanSha256', 'PaperJar', 'PaperSha256',
    'MCAceJar', 'MCAceSha256', 'PreparedRoot', 'PreparedManifestSha256',
    'AllowTemporaryPaperRemap', 'NetworkPolicy', 'NetworkIsolationAttested',
    'GenuineExternalTriggerAttested', 'NoSyntheticEventInjectionAttested',
    'ExpectedPlayerUuid', 'PaperListenPort', 'HumanTriggerTimeoutSeconds',
    'MaximumReportAgeMinutes')
$missing = @($expectedParameters | Where-Object { -not $parameters.ContainsKey($_) })
if ($missing.Count -ne 0) {
    throw "VULCAN_GENUINE_EVENT_WRAPPER_PARAMETERS_MISSING: $($missing -join ', ')"
}

function Test-Mandatory(
        [Management.Automation.Language.ParameterAst]$Parameter, [string]$ParameterSet) {
    foreach ($attribute in $Parameter.Attributes) {
        if ($attribute.TypeName.FullName -ne 'Parameter') { continue }
        $mandatory = $false
        $set = $null
        foreach ($named in $attribute.NamedArguments) {
            if ($named.ArgumentName -eq 'Mandatory') { $mandatory = $true }
            if ($named.ArgumentName -eq 'ParameterSetName') {
                $set = $named.Argument.Extent.Text.Trim("'", '"')
            }
        }
        if ($mandatory -and $set -eq $ParameterSet) { return $true }
    }
    return $false
}

foreach ($name in @(
        'Execute', 'VulcanJar', 'PaperJar', 'MCAceJar', 'PreparedRoot',
        'AllowTemporaryPaperRemap', 'NetworkPolicy', 'NetworkIsolationAttested',
        'GenuineExternalTriggerAttested', 'NoSyntheticEventInjectionAttested',
        'ExpectedPlayerUuid', 'PaperListenPort')) {
    if (-not (Test-Mandatory $parameters[$name] 'Execute')) {
        throw "VULCAN_GENUINE_EVENT_EXECUTE_PARAMETER_NOT_MANDATORY: $name"
    }
}
if (-not (Test-Mandatory $parameters.ReportOnly 'Report')) {
    throw 'VULCAN_GENUINE_EVENT_REPORT_ONLY_NOT_MANDATORY'
}

$commands = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.CommandAst]
}, $true))
$commandNames = @($commands | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
$forbiddenCommands = @(
    'Invoke-WebRequest', 'Invoke-RestMethod', 'Start-BitsTransfer',
    'curl', 'curl.exe', 'wget', 'wget.exe', 'gradle', 'gradle.bat',
    'gradlew', 'gradlew.bat', 'java', 'java.exe')
$presentForbidden = @($forbiddenCommands | Where-Object { $_ -in $commandNames })
if ($presentForbidden.Count -ne 0) {
    throw "VULCAN_GENUINE_EVENT_FORBIDDEN_COMMAND: $($presentForbidden -join ', ')"
}

$preparedPinGuard = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Assert-ExpectedPreparedManifest'
}, $true)
if ($null -eq $preparedPinGuard) {
    throw 'VULCAN_GENUINE_EVENT_PREPARED_PIN_GUARD_MISSING'
}
Invoke-Expression $preparedPinGuard.Extent.Text
$wrongPreparedPinRejected = $false
try {
    Assert-ExpectedPreparedManifest ('a' * 64) ('b' * 64)
} catch {
    $wrongPreparedPinRejected = $_.Exception.Message -eq
        'VULCAN_GENUINE_EVENT_PREPARED_MANIFEST_HASH_MISMATCH'
}
if (-not $wrongPreparedPinRejected) {
    throw 'VULCAN_GENUINE_EVENT_WRONG_PREPARED_PIN_NOT_REJECTED'
}

$directLocalPathGuard = $ast.Find({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Assert-DirectLocalPath'
}, $true)
if ($null -eq $directLocalPathGuard) {
    throw 'VULCAN_GENUINE_EVENT_DIRECT_LOCAL_PATH_GUARD_MISSING'
}
$expectedWindowsDriveRegex = '''^[A-Za-z]:[\\/]'''
if (-not $directLocalPathGuard.Extent.Text.Contains($expectedWindowsDriveRegex)) {
    throw 'VULCAN_GENUINE_EVENT_WINDOWS_BACKSLASH_REGEX_MISSING'
}
Invoke-Expression $directLocalPathGuard.Extent.Text
$backslashAbsoluteDirectory = [System.IO.Path]::GetFullPath($PSScriptRoot).Replace('/', '\')
$resolvedBackslashDirectory = Assert-DirectLocalPath $backslashAbsoluteDirectory -Directory
if ($resolvedBackslashDirectory -cne (Get-Item -LiteralPath $backslashAbsoluteDirectory -Force).FullName) {
    throw 'VULCAN_GENUINE_EVENT_WINDOWS_BACKSLASH_PATH_CHANGED'
}

$copyCommands = @($commands | Where-Object { $_.GetCommandName() -eq 'Copy-Item' })
foreach ($command in $copyCommands) {
    if ($command.Extent.Text -match '(?i)vulcan|mcace') {
        throw 'VULCAN_GENUINE_EVENT_PROPRIETARY_OR_PLUGIN_COPY_FOUND'
    }
}

$required = [ordered]@{
    explicit_execution = $source -match '\[switch\]\$Execute' -and
        $source -match 'VULCAN_GENUINE_EVENT_EXPLICIT_EXECUTION_AND_ATTESTATIONS_REQUIRED'
    explicit_trigger_attestation =
        $source -match '\[switch\]\$GenuineExternalTriggerAttested' -and
        $source -match '\[switch\]\$NoSyntheticEventInjectionAttested'
    explicit_isolation = $source -match "\[ValidateSet\('DenyAll'\)\]" -and
        $source -match '\[switch\]\$NetworkIsolationAttested' -and
        $source -match 'NETWORK_ISOLATION_OPERATOR_ATTESTED_NOT_OS_VERIFIED_BY_SCRIPT'
    explicit_remap = $source -match '\[switch\]\$AllowTemporaryPaperRemap'
    three_hash_pins = $source -match '\$VulcanSha256' -and
        $source -match '\$PaperSha256' -and $source -match '\$MCAceSha256' -and
        $source -match 'Open-LockedJar'
    reviewed_vulcan =
        $source -match '7ee3a4fdd7e9da5269f9efc327478e507563e6e7df7abec2222acd3b499bc993'
    absolute_local_no_reparse = $source -match 'IsPathRooted' -and
        $source -match '\[System\.IO\.DriveType\]::Fixed' -and
        $source -match 'VULCAN_GENUINE_EVENT_REPARSE_PATH_REJECTED'
    read_only_locked_artifacts = $source -match '\[IO\.FileShare\]::Read' -and
        $source -match '\$lockedVulcan\.stream\.Dispose\(\)'
    prepared_pin = $source -match "@\('cache', 'libraries', 'versions'\)" -and
        $source -match 'VULCAN_GENUINE_EVENT_PREPARED_MANIFEST_HASH_MISMATCH' -and
        $source -match 'VULCAN_GENUINE_EVENT_PREPARED_CACHE_CHANGED_DURING_RUN'
    direct_plugins = $source -match '''--add-plugin'', \$lockedVulcan\.path' -and
        $source -match '''--add-plugin'', \$lockedMCAce\.path'
    loopback_observer = $source -match 'function New-LoopbackObserver' -and
        $source -match '\[Net\.IPAddress\]::Loopback' -and
        $source -match '/v1/auth/challenges' -and $source -match '/v1/auth/tokens' -and
        $source -match '/v1/risk-events'
    expected_player_in_memory_only = $source -match 'ConvertTo-ExpectedUuid' -and
        $source -match 'expected_player_matched = \$true' -and
        $source -notmatch 'expected_player_uuid\s*='
    strict_payload = $source -match 'function Test-GenuineRiskPayload' -and
        $source -match '\$Payload\.origin -cne ''SERVER_CONFIRMED''' -and
        $source -match '\$details\.provider -cne ''vulcan''' -and
        $source -match '\[string\]::IsNullOrWhiteSpace\(\$details\.check\)' -and
        $source -match '\[string\]::IsNullOrWhiteSpace\(\$details\.stable_check\)' -and
        $source -match '\[int64\]\$details\.flag_count -lt 1'
    unique_delivery = $source -match 'unique_matching_event_count = 1' -and
        $source -match 'total_risk_event_count = 1' -and
        $source -match 'VULCAN_GENUINE_EVENT_DELIVERY_NOT_OBSERVED_EXACTLY_ONCE'
    real_chain_claim = $source -match 'mcace_adapter_extraction_coverage = \$true' -and
        $source -match 'mcace_correlator_coverage = \$true' -and
        $source -match 'mcace_queue_auth_delivery_coverage = \$true' -and
        $source -match 'real_behavior_event_delivery_coverage = \$true'
    no_synthetic_generation = $source -notmatch '(?i)PluginManager\.callEvent|\.callEvent\(' -and
        $source -notmatch '(?i)MockBukkit|VulcanFlagEvent\(|new\s+VulcanViolationEvent' -and
        $source -notmatch '(?i)dispatchCommand|performCommand'
    honest_attestation_limit =
        $source -match 'HUMAN_TRIGGER_ORIGIN_OPERATOR_ATTESTED_NOT_OS_OR_VENDOR_VERIFIED_BY_SCRIPT'
    sanitized = $source -match 'function Assert-SanitizedEvidence' -and
        $source -match 'player_uuid\|event_id\|check\|stable_check' -and
        $source -match 'gate_invoked_plugin_manager_call_event = \$false' -and
        $source -match 'gate_used_test_fixture = \$false' -and
        $source -match 'gate_used_vendor_synthetic_event = \$false'
    strict_report_only = $source -match 'function Test-ExactProperties' -and
        $source -match 'function Assert-EvidencePair' -and
        $source -match 'VULCAN_GENUINE_EVENT_REPORT_ONLY_EXECUTION_INPUT_REJECTED' -and
        $source -match 'Assert-EvidencePair\s+`?\s*\$path'
    current_binding = $source -match 'function Get-CurrentBinding' -and
        $source -match 'wrapper_sha256' -and $source -match 'source_manifest_sha256' -and
        $source -match 'java_executable_sha256' -and $source -match 'java_file_version' -and
        $source -match 'prepared_manifest_sha256' -and $source -match 'report_sha256'
    cleanup = $source -match 'function Test-OwnedProcess' -and
        $source -match 'ExpectedStartTimeUtc' -and
        $source -match 'remaining_marker_process_count = 0' -and
        $source -match 'VULCAN_GENUINE_EVENT_ORIGINAL_ARTIFACT_PARENT_REMAP_CHANGED'
    no_download_api = $source -notmatch '(?i)HttpClient|WebClient|WebRequest|DownloadFile|bitsadmin'
}
$failed = @($required.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
if ($failed.Count -ne 0) {
    throw "VULCAN_GENUINE_EVENT_WRAPPER_STATIC_FAILED: $($failed -join ', ')"
}

Write-Output 'VULCAN_GENUINE_EVENT_WRAPPER_STATIC_PASS'
