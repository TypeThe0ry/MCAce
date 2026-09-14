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
    'ExpectedPlayerUuid', 'PaperListenPort', 'SourceCommit', 'ProductVersion',
    'HumanTriggerTimeoutSeconds',
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

function Test-CommonMandatory([Management.Automation.Language.ParameterAst]$Parameter) {
    foreach ($attribute in $Parameter.Attributes) {
        if ($attribute.TypeName.FullName -ne 'Parameter') { continue }
        $mandatory = $false
        $hasSet = $false
        foreach ($named in $attribute.NamedArguments) {
            if ($named.ArgumentName -eq 'Mandatory') { $mandatory = $true }
            if ($named.ArgumentName -eq 'ParameterSetName') { $hasSet = $true }
        }
        if ($mandatory -and -not $hasSet) { return $true }
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
foreach ($name in @('SourceCommit', 'ProductVersion')) {
    if (-not (Test-CommonMandatory $parameters[$name])) {
        throw "VULCAN_GENUINE_EVENT_COMMON_PARAMETER_NOT_MANDATORY: $name"
    }
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
    ed25519_client_proof = $source -match 'function Test-Ed25519Signature' -and
        $source -match 'Signature\.getInstance\("Ed25519"\)' -and
        $source -match 'ConvertFrom-StrictBase64Url \$EncodedSignature 64' -and
        $source -match 'challenge_signature_verified = \$true'
    single_use_challenge_ttl = $source -match 'function Test-ObserverChallengeExchangeWindow' -and
        $source -match '\$Observer\.challenge_consumed = \$true' -and
        $source -match '\$Observer\.challenge_exchange_count\+\+' -and
        $source -match 'challenge_expires_at = \$Now\.AddSeconds'
    run_bound_expiring_token = $source -match 'function Get-ObserverAccessTokenBinding' -and
        $source -match '''run_nonce='' \+ \$Observer\.run_nonce' -and
        $source -match '''server_id='' \+ \$Observer\.server_id' -and
        $source -match '''challenge_id='' \+ \$Observer\.challenge_id' -and
        $source -match '\$Now -ge \$Observer\.token_expires_at'
    causal_replay_guard = $source -match '\$RunStartedAt -gt \$firstObserved' -and
        $source -match '\$observedAt -gt \$TokenIssuedAt' -and
        $source -match '\$SeenEventIds\.Contains\(\$Payload\.event_id\)' -and
        $source -match 'invalid_or_replayed_event'
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
    explicit_non_release_v2 =
        $source -match 'OPERATOR_ATTESTED_V2_EVIDENCE_NOT_RELEASE_ELIGIBLE_WITHOUT_EXTERNAL_PINNED_SUPERVISOR_RECEIPT' -and
        $source -match 'release_eligible = \$false' -and
        $source -match '\$report\.release_eligible -or' -and
        $source -match '\$binding\.release_eligible -or' -and
        $source -match '\$commit\.release_eligible -or'
    sanitized = $source -match 'function Assert-SanitizedEvidence' -and
        $source -match 'player_uuid\|event_id\|check\|stable_check' -and
        $source -match 'gate_invoked_plugin_manager_call_event = \$false' -and
        $source -match 'gate_used_test_fixture = \$false' -and
        $source -match 'gate_used_vendor_synthetic_event = \$false'
    strict_report_only = $source -match 'function Test-ExactProperties' -and
        $source -match 'function Assert-EvidenceTriplet' -and
        $source -match 'VULCAN_GENUINE_EVENT_REPORT_ONLY_EXECUTION_INPUT_REJECTED' -and
        $source -match 'Assert-EvidenceTriplet\s+`?\s*\$path'
    v2_triplet = $source -match 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2' -and
        $source -match 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V2' -and
        $source -match 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_COMMIT_V2' -and
        $source -match 'function Assert-CommitRaw' -and
        $source -match "@\('binding\.json', 'commit\.json', 'report\.json'\)"
    exact_source = $source -match 'function Assert-ExactGitSourceIdentity' -and
        $source -match 'VULCAN_GENUINE_EVENT_SOURCE_HEAD_MISMATCH' -and
        $source -match 'VULCAN_GENUINE_EVENT_SOURCE_WORKTREE_DIRTY' -and
        $source -match 'source_commit = \$expectedSourceCommit' -and
        $source -match 'product_version = \$ProductVersion'
    atomic_commit_last = $source -match 'function Write-AtomicEvidenceBytes' -and
        $source -match '\[IO\.FileOptions\]::WriteThrough' -and
        $source -match 'Write-AtomicEvidenceBytes \(Join-Path \$runRoot ''commit\.json''\)'
    byte_binding = $source -match 'report_size_bytes' -and
        $source -match 'binding_size_bytes' -and
        $source -match '\$bindingEvidence\.size' -and
        $source -match '\$bindingEvidence\.sha256' -and
        $source -match '\$commitEvidence\.raw'
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

function Get-TargetFunctionText([string]$Name) {
    $definition = $ast.Find({ param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $Name
    }, $true)
    if ($null -eq $definition) {
        throw "VULCAN_GENUINE_EVENT_TEST_FUNCTION_MISSING: $Name"
    }
    return $definition.Extent.Text
}

foreach ($name in @('Assert-DescendantPath', 'Get-BytesSha256',
        'ConvertTo-Sha256',
        'ConvertTo-Base64Url', 'ConvertFrom-StrictBase64Url',
        'ConvertFrom-StrictUtcInstant', 'Write-Ed25519VerifierSource',
        'Initialize-Ed25519Verifier', 'Test-Ed25519Signature',
        'Test-ObserverChallengeExchangeWindow',
        'Get-ObserverAccessTokenBinding', 'Test-ObserverRiskAuthorization',
        'ConvertTo-SourceCommit', 'Test-JsonString', 'Test-JsonBoolean',
        'Test-JsonInteger', 'Get-JsonGraphPropertyCount',
        'Assert-NoCaseAmbiguousJsonProperties', 'ConvertFrom-StrictJsonRaw',
        'Get-JsonPropertyNames', 'Test-ExactProperties',
        'Test-GenuineRiskPayload', 'Assert-CommitRaw',
        'Test-RsaPkcs1Sha256Signature','Get-VulcanV3ReceiptSigningPayload',
        'Assert-VulcanV3TrustRoot','Assert-VulcanV3RawRiskEvent',
        'Assert-VulcanV3CallbackLedger','Assert-VulcanV3Receipt')) {
    Invoke-Expression (Get-TargetFunctionText $name)
}

$normalizedCommit = ConvertTo-SourceCommit ('A' * 40)
if ($normalizedCommit -cne ('a' * 40)) {
    throw 'VULCAN_GENUINE_EVENT_SOURCE_COMMIT_NORMALIZATION_FAILED'
}
$invalidCommitRejected = $false
try { $null = ConvertTo-SourceCommit ('f' * 39) }
catch { $invalidCommitRejected = $_.Exception.Message -eq 'VULCAN_GENUINE_EVENT_SOURCE_COMMIT_INVALID' }
if (-not $invalidCommitRejected) {
    throw 'VULCAN_GENUINE_EVENT_INVALID_SOURCE_COMMIT_NOT_REJECTED'
}

$script:commitSchema = 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_COMMIT_V2'
$script:reportSchema = 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_V2'
$script:bindingSchema = 'MCACE_VULCAN_GENUINE_EVENT_DELIVERY_BINDING_V2'
$script:observerAuthProtocol = 'MCACE_VULCAN_OBSERVER_AUTH_V1'
$generatedAt = [DateTimeOffset]::UtcNow.ToString('o')
$sourceCommit = '1' * 40
$reportSha = '2' * 64
$bindingSha = '3' * 64
$reportSize = 1024L
$bindingSize = 2048L
$report = [pscustomobject]@{ generated_at = $generatedAt }
$validCommit = [ordered]@{
    schema = $script:commitSchema
    generated_at = $generatedAt
    report_schema = $script:reportSchema
    binding_schema = $script:bindingSchema
    report_generated_at = $generatedAt
    report_sha256 = $reportSha
    report_size_bytes = $reportSize
    binding_sha256 = $bindingSha
    binding_size_bytes = $bindingSize
    source_mode = 'EXECUTED_HUMAN_TRIGGER_OPERATOR_ATTESTED'
    source_commit = $sourceCommit
    product_version = '0.0.1'
    release_eligible = $false
    committed = $true
}
$null = Assert-CommitRaw ($validCommit | ConvertTo-Json -Depth 4) `
    $reportSha $reportSize $bindingSha $bindingSize $report $sourceCommit '0.0.1'

$dateProbe = ConvertFrom-StrictJsonRaw (
    '{"generated_at":"' + $generatedAt + '"}')
if ($dateProbe.generated_at -isnot [string]) {
    throw 'VULCAN_GENUINE_EVENT_STRICT_JSON_DATE_STRING_NOT_PRESERVED'
}
$duplicateRejected = $false
try {
    $null = ConvertFrom-StrictJsonRaw '{"schema":"first","schema":"second"}'
} catch {
    $duplicateRejected = $_.Exception.Message -eq
        'VULCAN_GENUINE_EVENT_DUPLICATE_OR_AMBIGUOUS_PROPERTY'
}
if (-not $duplicateRejected) {
    throw 'VULCAN_GENUINE_EVENT_DUPLICATE_JSON_PROPERTY_NOT_REJECTED'
}

$negativeCases = @(
    @{ name='source'; property='source_commit'; value=('4' * 40) },
    @{ name='report_hash'; property='report_sha256'; value=('5' * 64) },
    @{ name='binding_hash'; property='binding_sha256'; value=('6' * 64) },
    @{ name='report_size'; property='report_size_bytes'; value=1025L },
    @{ name='binding_size'; property='binding_size_bytes'; value=2049L },
    @{ name='release_eligible'; property='release_eligible'; value=$true },
    @{ name='committed'; property='committed'; value=$false }
)
foreach ($case in $negativeCases) {
    $copy = [ordered]@{}
    foreach ($entry in $validCommit.GetEnumerator()) { $copy[$entry.Key] = $entry.Value }
    $copy[$case.property] = $case.value
    $rejected = $false
    try {
        $null = Assert-CommitRaw ($copy | ConvertTo-Json -Depth 4) `
            $reportSha $reportSize $bindingSha $bindingSize $report $sourceCommit '0.0.1'
    } catch {
        $rejected = $_.Exception.Message -eq 'VULCAN_GENUINE_EVENT_COMMIT_INVALID'
    }
    if (-not $rejected) {
        throw "VULCAN_GENUINE_EVENT_COMMIT_TAMPER_NOT_REJECTED: $($case.name)"
    }
}

$extraField = [ordered]@{}
foreach ($entry in $validCommit.GetEnumerator()) { $extraField[$entry.Key] = $entry.Value }
$extraField['unexpected'] = 'rejected'
$extraRejected = $false
try {
    $null = Assert-CommitRaw ($extraField | ConvertTo-Json -Depth 4) `
        $reportSha $reportSize $bindingSha $bindingSize $report $sourceCommit '0.0.1'
} catch {
    $extraRejected = $_.Exception.Message -eq 'VULCAN_GENUINE_EVENT_COMMIT_PROPERTIES_INVALID'
}
if (-not $extraRejected) {
    throw 'VULCAN_GENUINE_EVENT_EXTRA_COMMIT_PROPERTY_NOT_REJECTED'
}

$dynamicNegativeCases = 0
$signatureBytes = New-Object byte[] 64
for ($index = 0; $index -lt $signatureBytes.Length; $index++) {
    $signatureBytes[$index] = [byte]$index
}
$canonicalSignature = ConvertTo-Base64Url $signatureBytes
[byte[]]$decodedSignature = ConvertFrom-StrictBase64Url `
    $canonicalSignature 64 'test_signature'
if ($decodedSignature.Length -ne 64 -or
        (ConvertTo-Base64Url $decodedSignature) -cne $canonicalSignature) {
    throw 'VULCAN_GENUINE_EVENT_BASE64URL_ROUND_TRIP_FAILED'
}
foreach ($invalid in @(
        ($canonicalSignature + '='),
        $canonicalSignature.Substring(0, $canonicalSignature.Length - 1),
        ('+' + $canonicalSignature.Substring(1)),
        ($canonicalSignature.Substring(0, $canonicalSignature.Length - 1) + 'B'))) {
    $rejected = $false
    try { $null = ConvertFrom-StrictBase64Url $invalid 64 'test_signature' }
    catch { $rejected = $_.Exception.Message -eq
            'VULCAN_GENUINE_EVENT_BASE64URL_INVALID: test_signature' }
    if (-not $rejected) {
        throw 'VULCAN_GENUINE_EVENT_NONCANONICAL_SIGNATURE_ENCODING_NOT_REJECTED'
    }
    $dynamicNegativeCases++
}

function ConvertFrom-TestHex([string]$Value) {
    if ($Value.Length % 2 -ne 0 -or $Value -notmatch '^[0-9a-f]+$') {
        throw 'VULCAN_GENUINE_EVENT_TEST_HEX_INVALID'
    }
    [byte[]]$result = New-Object byte[] ($Value.Length / 2)
    for ($index = 0; $index -lt $result.Length; $index++) {
        $result[$index] = [Convert]::ToByte($Value.Substring($index * 2, 2), 16)
    }
    return ,$result
}

$javaPath = $null
if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
    $candidate = Join-Path $env:JAVA_HOME 'bin\java.exe'
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $javaPath = $candidate }
}
if ($null -eq $javaPath) {
    $javaCommand = Get-Command java.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -ne $javaCommand) { $javaPath = $javaCommand.Source }
}
if ($null -eq $javaPath) {
    throw 'VULCAN_GENUINE_EVENT_DYNAMIC_ED25519_JAVA_REQUIRED'
}
$buildRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\build'))
if (-not (Test-Path -LiteralPath $buildRoot)) {
    New-Item -ItemType Directory -Path $buildRoot | Out-Null
}
$null = Assert-DirectLocalPath $buildRoot -Directory
$verifierRoot = Assert-DescendantPath $buildRoot (
    Join-Path $buildRoot ('vulcan-auth-test-' + [guid]::NewGuid().ToString('N')))
New-Item -ItemType Directory -Path $verifierRoot | Out-Null
try {
    $verifierClassRoot = Initialize-Ed25519Verifier $javaPath $verifierRoot
    $publicKey = 'MCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo='
    [byte[]]$knownSignatureBytes = ConvertFrom-TestHex (
        '1b79abc415a34efe5915b4c1b53d2435e731b3c92d0ba440de29cab2999fa885' +
        'bd0eb3c71dfd8df6fbecf8c0ef403e8902dec8e2abd00ab9b04b1df027929609')
    $knownSignature = ConvertTo-Base64Url $knownSignatureBytes
    if (-not (Test-Ed25519Signature `
            $javaPath $verifierClassRoot $publicKey 'cg' $knownSignature)) {
        throw 'VULCAN_GENUINE_EVENT_REAL_ED25519_VECTOR_NOT_VERIFIED'
    }
    $tamperedSignature = if ($knownSignature[0] -ceq 'A') {
        'B' + $knownSignature.Substring(1)
    } else { 'A' + $knownSignature.Substring(1) }
    if (Test-Ed25519Signature `
            $javaPath $verifierClassRoot $publicKey 'cg' $tamperedSignature) {
        throw 'VULCAN_GENUINE_EVENT_TAMPERED_ED25519_SIGNATURE_ACCEPTED'
    }
    $dynamicNegativeCases++
    if (Test-Ed25519Signature `
            $javaPath $verifierClassRoot $publicKey 'cg' ($knownSignature + '=')) {
        throw 'VULCAN_GENUINE_EVENT_PADDED_ED25519_SIGNATURE_ACCEPTED'
    }
    $dynamicNegativeCases++
} finally {
    $verifiedRoot = Assert-DescendantPath $buildRoot $verifierRoot
    if (Test-Path -LiteralPath $verifiedRoot) {
        Remove-Item -LiteralPath $verifiedRoot -Recurse -Force
    }
}

$now = [DateTimeOffset]::UtcNow
$observer = [pscustomobject]@{
    auth_protocol = $script:observerAuthProtocol
    run_nonce = '1' * 32
    server_id = 'vulcan-genuine-event-gate-' + ('1' * 32)
    challenge_id = '2' * 32
    challenge_issued = $true
    challenge_consumed = $false
    challenge_signature_verified = $true
    challenge_issued_at = $now.AddSeconds(-1)
    challenge_expires_at = $now.AddSeconds(29)
    access_token = ConvertTo-Base64Url ([Text.Encoding]::ASCII.GetBytes('12345678901234567890123456789012'))
    access_token_binding = ''
    token_issued = $true
    token_issued_at = $now.AddMilliseconds(-500)
    token_expires_at = $now.AddSeconds(60)
}
if (-not (Test-ObserverChallengeExchangeWindow $observer $now)) {
    throw 'VULCAN_GENUINE_EVENT_LIVE_CHALLENGE_WINDOW_REJECTED'
}
$observer.challenge_consumed = $true
if (Test-ObserverChallengeExchangeWindow $observer $now) {
    throw 'VULCAN_GENUINE_EVENT_CONSUMED_CHALLENGE_ACCEPTED'
}
$dynamicNegativeCases++
$observer.challenge_consumed = $false
$observer.challenge_expires_at = $now
if (Test-ObserverChallengeExchangeWindow $observer $now) {
    throw 'VULCAN_GENUINE_EVENT_EXPIRED_CHALLENGE_ACCEPTED'
}
$dynamicNegativeCases++
$observer.challenge_consumed = $true
$observer.challenge_expires_at = $now.AddSeconds(29)
$observer.access_token_binding = Get-ObserverAccessTokenBinding $observer
$authorization = 'Bearer ' + $observer.access_token
if (-not (Test-ObserverRiskAuthorization $observer $authorization $now)) {
    throw 'VULCAN_GENUINE_EVENT_RUN_BOUND_TOKEN_REJECTED'
}
foreach ($field in @('run_nonce', 'server_id', 'challenge_id')) {
    $original = $observer.$field
    $observer.$field = 'tampered-' + $field
    if (Test-ObserverRiskAuthorization $observer $authorization $now) {
        throw "VULCAN_GENUINE_EVENT_TOKEN_BINDING_TAMPER_ACCEPTED: $field"
    }
    $dynamicNegativeCases++
    $observer.$field = $original
}
if (Test-ObserverRiskAuthorization $observer 'Bearer wrong' $now) {
    throw 'VULCAN_GENUINE_EVENT_WRONG_BEARER_ACCEPTED'
}
$dynamicNegativeCases++
if (Test-ObserverRiskAuthorization $observer $authorization $observer.token_expires_at) {
    throw 'VULCAN_GENUINE_EVENT_EXPIRED_TOKEN_ACCEPTED'
}
$dynamicNegativeCases++

function Format-TestInstant([DateTimeOffset]$Value) {
    return $Value.ToUniversalTime().ToString(
        "yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [Globalization.CultureInfo]::InvariantCulture)
}

function New-TestRiskPayload(
        [string]$EventId, [string]$PlayerUuid,
        [DateTimeOffset]$FirstObserved, [DateTimeOffset]$Observed) {
    return [pscustomobject]@{
        event_id = $EventId
        player_uuid = $PlayerUuid
        type = 'BEHAVIOR_HIGH_RISK'
        source_component = 'vulcan-adapter'
        origin = 'SERVER_CONFIRMED'
        corroborated = $false
        observed_at = Format-TestInstant $Observed
        details = [pscustomobject]@{
            schema = 'mcace.behavior-alert.v1'
            provider = 'vulcan'
            provider_version = '2.9.0'
            check = 'Speed'
            stable_check = 'speed-a'
            provider_event_id_sha256 = ('a' * 64)
            flag_count = 1
            window_ms = 10000
            first_observed_at = Format-TestInstant $FirstObserved
            maximum_violation_level = 1.0D
            experimental = $false
            independent_providers = @('vulcan')
        }
    }
}

$runStarted = $now.AddSeconds(-10)
$firstObserved = $runStarted.AddSeconds(1)
$observed = $runStarted.AddSeconds(2)
$tokenIssued = $runStarted.AddSeconds(3)
$received = $runStarted.AddSeconds(4)
$playerUuid = [guid]::NewGuid().ToString('D')
$eventId = [guid]::NewGuid().ToString('D')
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
$validPayload = New-TestRiskPayload $eventId $playerUuid $firstObserved $observed
$matched = Test-GenuineRiskPayload `
    $validPayload $playerUuid '2.9.0' $runStarted $tokenIssued $received $seen
if ($null -eq $matched -or -not $matched.event_causality_verified -or $seen.Count -ne 1) {
    throw 'VULCAN_GENUINE_EVENT_CAUSAL_PAYLOAD_REJECTED'
}
if ($null -ne (Test-GenuineRiskPayload `
        $validPayload $playerUuid '2.9.0' $runStarted $tokenIssued $received $seen)) {
    throw 'VULCAN_GENUINE_EVENT_REPLAYED_EVENT_ACCEPTED'
}
$dynamicNegativeCases++

$causalCases = @(
    @{ name='before_run'; first=$runStarted.AddMilliseconds(-1); observed=$observed },
    @{ name='first_after_event'; first=$observed.AddMilliseconds(1); observed=$observed },
    @{ name='after_token'; first=$firstObserved; observed=$tokenIssued.AddMilliseconds(1) }
)
foreach ($case in $causalCases) {
    $probe = New-TestRiskPayload `
        ([guid]::NewGuid().ToString('D')) $playerUuid $case.first $case.observed
    $probeSeen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if ($null -ne (Test-GenuineRiskPayload `
            $probe $playerUuid '2.9.0' $runStarted $tokenIssued $received $probeSeen)) {
        throw "VULCAN_GENUINE_EVENT_CAUSAL_VIOLATION_ACCEPTED: $($case.name)"
    }
    $dynamicNegativeCases++
}
$offsetTimestamp = New-TestRiskPayload `
    ([guid]::NewGuid().ToString('D')) $playerUuid $firstObserved $observed
$offsetTimestamp.observed_at = $offsetTimestamp.observed_at.Replace('Z', '+00:00')
$offsetSeen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
if ($null -ne (Test-GenuineRiskPayload `
        $offsetTimestamp $playerUuid '2.9.0' $runStarted $tokenIssued $received $offsetSeen)) {
    throw 'VULCAN_GENUINE_EVENT_NONCANONICAL_TIMESTAMP_ACCEPTED'
}
$dynamicNegativeCases++

# V3 fixture validates only the cryptographic/parser contract.  It is explicitly fixture=true and
# release_eligible=false by construction; neither the runner, publisher nor readiness accepts it as
# real release evidence.
$script:expectedPluginVersion='2.9.0'
$script:v3TrustRootSchema='MCACE_VULCAN_GENUINE_EVENT_SUPERVISOR_TRUST_ROOT_V1'
$script:v3ReceiptSchema='MCACE_VULCAN_GENUINE_EVENT_SUPERVISOR_RECEIPT_V1'
$script:v3SigningDomain='MCACE-VULCAN-GENUINE-EVENT-SUPERVISOR-RECEIPT-V1'
$script:v3ReceiptPropertyNames=@(
    'schema','artifact_class','source_mode','signed_at','expires_at','source_commit',
    'product_version','run_attempt_id','challenge_nonce','challenge_issued_at',
    'signing_request_sha256','report_sha256','report_size_bytes','binding_sha256',
    'binding_size_bytes','raw_event_sha256','raw_event_size_bytes','callback_ledger_sha256',
    'callback_ledger_size_bytes','callback_record_sha256','vulcan_sha256','vulcan_size',
    'paper_sha256','paper_size','mcace_sha256','mcace_size','paper_process_id',
    'paper_process_started_at','paper_process_incarnation_sha256','provider_plugin_name',
    'provider_plugin_version','provider_plugin_main_class','provider_event_class',
    'accessor_provenance_sha256','signer_key_id','signer_trust_root_sha256',
    'signature_algorithm','fixture','signature_base64')

# Canonical runtime provenance fixture.  This exercises the parser/commitment contract only;
# its hashes are test values and it cannot be published as release evidence.
$v3Attempt=('b'*32);$v3Challenge=('c'*64);$v3Vulcan=('4'*64);$v3MCAce=('6'*64)
$v3Player=[guid]::NewGuid().ToString('D');$v3ProviderEvent=('a'*64)
$v3ProcessId=1234;$v3ProcessStarted=Format-TestInstant ([DateTimeOffset]::UtcNow.AddMinutes(-1))
$v3Observed=Format-TestInstant ([DateTimeOffset]::UtcNow.AddSeconds(-4))
$v3Raw=[pscustomobject][ordered]@{
    event_id=[guid]::NewGuid().ToString('D');player_uuid=$v3Player
    type='BEHAVIOR_HIGH_RISK';source_component='vulcan-adapter';origin='SERVER_CONFIRMED'
    corroborated=$false;observed_at=$v3Observed
    details=[pscustomobject][ordered]@{
        schema='mcace.behavior-alert.v1';provider='vulcan';provider_version='2.9.0'
        check='Speed';stable_check='speed-a';provider_event_id_sha256=$v3ProviderEvent
        flag_count=1;window_ms=10000;first_observed_at=$v3Observed
        maximum_violation_level=1.0D;experimental=$false;independent_providers=@('vulcan')
    }
}
$v3ValidatedRaw=Assert-VulcanV3RawRiskEvent $v3Raw
$v3CheckHash=Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes('Speed'))
$v3StableHash=Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes('speed-a'))
$v3Accessor='me.frep.vulcan.api.event.VulcanFlagEvent#getPlayer()->org.bukkit.entity.Player@vulcan.jar;me.frep.vulcan.api.event.VulcanFlagEvent#getCheck()->java.lang.String@vulcan.jar'
$v3AccessorHash=Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($v3Accessor))
$v3Semantic="player_uuid=$v3Player`nprovider_event_id=$v3ProviderEvent`n"+
    "check_sha256=$v3CheckHash`nstable_check_sha256=$v3StableHash`n"+
    "violation_hex=0x1.0p0`nobserved_at=$v3Observed`n"
$v3Incarnation=Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes(
    "pid=$v3ProcessId`nstarted_at=$v3ProcessStarted`n"))
$v3Ledger=[ordered]@{
    schema='MCACE_VULCAN_CALLBACK_PROVENANCE_V1';sequence=1;callback_at=$v3Observed
    capture_attempt_id=$v3Attempt;capture_challenge_nonce=$v3Challenge
    process_id=$v3ProcessId;process_started_at=$v3ProcessStarted
    process_incarnation_sha256=$v3Incarnation;owner_plugin_name='MCAce'
    owner_plugin_version='0.0.1';owner_plugin_main_class='com.ellan.mcace.paper.MCAcePaperPlugin'
    owner_plugin_code_source_sha256=$v3MCAce;provider_plugin_name='Vulcan'
    provider_plugin_version='2.9.0';provider_plugin_main_class='me.frep.vulcan.Vulcan'
    provider_plugin_code_source_sha256=$v3Vulcan
    registered_event_class='me.frep.vulcan.api.event.VulcanFlagEvent'
    registered_event_code_source_sha256=$v3Vulcan
    runtime_event_class='me.frep.vulcan.api.event.VulcanFlagEvent'
    runtime_event_code_source_sha256=$v3Vulcan;handler_owner_plugin='MCAce'
    handler_listener_class='com.ellan.mcace.paper.behavior.VulcanBehaviorIntegration$1'
    handler_priority='MONITOR';handler_ignore_cancelled=$true;callback_thread_id=1
    callback_thread_name='Server thread';player_uuid=$v3Player
    provider_event_id_sha256=$v3ProviderEvent;check_sha256=$v3CheckHash
    stable_check_sha256=$v3StableHash;violation_hex='0x1.0p0';observed_at=$v3Observed
    semantic_fields_sha256=Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($v3Semantic))
    accessor_provenance=$v3Accessor;accessor_provenance_sha256=$v3AccessorHash
    previous_record_sha256=('0'*64)
}
$v3Unsigned=([pscustomobject]$v3Ledger|ConvertTo-Json -Compress)
$v3Ledger['record_sha256']=Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($v3Unsigned))
$v3LedgerRaw=([pscustomobject]$v3Ledger|ConvertTo-Json -Compress)+"`n"
$null=Assert-VulcanV3CallbackLedger ([pscustomobject]@{raw=$v3LedgerRaw}) $v3ValidatedRaw `
    $v3Attempt $v3Challenge $v3Vulcan $v3MCAce $v3ProcessId $v3ProcessStarted
# A correlated event may summarize an earlier first flag.  The callback record
# must stay bound to the top-level observation that caused delivery, not to the
# correlation-window floor.
$v3CorrelatedRaw=$v3Raw.PSObject.Copy()
$v3CorrelatedRaw.details=$v3Raw.details.PSObject.Copy()
$v3CorrelatedRaw.details.flag_count=2
$v3CorrelatedRaw.details.first_observed_at=Format-TestInstant (
    (ConvertFrom-StrictUtcInstant $v3Observed 'fixture_observed').AddSeconds(-2))
$v3ValidatedCorrelatedRaw=Assert-VulcanV3RawRiskEvent $v3CorrelatedRaw
$null=Assert-VulcanV3CallbackLedger ([pscustomobject]@{raw=$v3LedgerRaw}) `
    $v3ValidatedCorrelatedRaw $v3Attempt $v3Challenge $v3Vulcan $v3MCAce `
    $v3ProcessId $v3ProcessStarted
foreach($mutation in @(
        @{name='fake_jar';field='provider_plugin_code_source_sha256';value=('9'*64)},
        @{name='fake_event';field='runtime_event_class';value='org.bukkit.event.Event'},
        @{name='synthetic_callback';field='handler_owner_plugin';value='Vulcan'})) {
    $bad=[ordered]@{};foreach($entry in $v3Ledger.GetEnumerator()){
        if($entry.Key -cne 'record_sha256'){$bad[$entry.Key]=$entry.Value}}
    $bad[$mutation.field]=$mutation.value
    $badUnsigned=([pscustomobject]$bad|ConvertTo-Json -Compress)
    $bad['record_sha256']=Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($badUnsigned))
    $rejected=$false
    try{$null=Assert-VulcanV3CallbackLedger `
            ([pscustomobject]@{raw=(([pscustomobject]$bad|ConvertTo-Json -Compress)+"`n")}) `
            $v3ValidatedRaw $v3Attempt $v3Challenge $v3Vulcan $v3MCAce `
            $v3ProcessId $v3ProcessStarted}catch{$rejected=$true}
    if(-not $rejected){throw "VULCAN_GENUINE_EVENT_V3_PROVENANCE_MUTATION_ACCEPTED|$($mutation.name)"}
    $dynamicNegativeCases++
}
$oldRaw=$v3Raw.PSObject.Copy();$oldRaw.details=$v3Raw.details.PSObject.Copy()
$oldRaw.details.schema='mcace.behavior-alert.v0'
$rejected=$false;try{$null=Assert-VulcanV3RawRiskEvent $oldRaw}catch{$rejected=$true}
if(-not $rejected){throw 'VULCAN_GENUINE_EVENT_V3_OLD_EVENT_SCHEMA_ACCEPTED'}
$dynamicNegativeCases++

$fixtureRsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048)
try {
    $fixtureRsa.PersistKeyInCsp=$false
    $public=$fixtureRsa.ExportParameters($false)
    $trust=[ordered]@{
        schema=$v3TrustRootSchema;artifact_class='TEST_VULCAN_SUPERVISOR_TRUST_ROOT_FIXTURE'
        key_id='vulcan-v3-fixture';algorithm='RSA_PKCS1_SHA256'
        modulus_base64=[Convert]::ToBase64String($public.Modulus)
        exponent_base64=[Convert]::ToBase64String($public.Exponent);fixture=$true
    }
    $trustRaw=([pscustomobject]$trust|ConvertTo-Json -Compress)
    $trustEvidence=[pscustomobject]@{
        raw=$trustRaw;sha256=Get-BytesSha256 ([Text.UTF8Encoding]::new($false).GetBytes($trustRaw))
    }
    $validatedTrust=Assert-VulcanV3TrustRoot $trustEvidence $trustEvidence.sha256 '' -AllowTestFixture
    $issued=[DateTimeOffset]::UtcNow.AddSeconds(-2)
    $signed=$issued.AddSeconds(1)
    $receipt=[ordered]@{
        schema=$v3ReceiptSchema;artifact_class='TEST_VULCAN_SUPERVISOR_RECEIPT_FIXTURE'
        source_mode='TEST_SIGNED_CONTRACT_FIXTURE';signed_at=Format-TestInstant $signed
        expires_at=Format-TestInstant $signed.AddMinutes(10);source_commit=('a'*40)
        product_version='0.0.1';run_attempt_id=('b'*32);challenge_nonce=('c'*64)
        challenge_issued_at=Format-TestInstant $issued;signing_request_sha256=('d'*64)
        report_sha256=('e'*64);report_size_bytes=1000;binding_sha256=('f'*64)
        binding_size_bytes=900;raw_event_sha256=('1'*64);raw_event_size_bytes=800
        callback_ledger_sha256=('2'*64);callback_ledger_size_bytes=1200
        callback_record_sha256=('3'*64);vulcan_sha256=('4'*64);vulcan_size=3820392
        paper_sha256=('5'*64);paper_size=5000;mcace_sha256=('6'*64);mcace_size=4000
        paper_process_id=1234;paper_process_started_at=Format-TestInstant $issued.AddMinutes(-1)
        paper_process_incarnation_sha256=('7'*64);provider_plugin_name='Vulcan'
        provider_plugin_version='2.9.0';provider_plugin_main_class='me.frep.vulcan.Vulcan'
        provider_event_class='me.frep.vulcan.api.event.VulcanFlagEvent'
        accessor_provenance_sha256=('8'*64);signer_key_id='vulcan-v3-fixture'
        signer_trust_root_sha256=$trustEvidence.sha256;signature_algorithm='RSA_PKCS1_SHA256'
        fixture=$true;signature_base64=''
    }
    $receipt.signature_base64=[Convert]::ToBase64String($fixtureRsa.SignData(
        (Get-VulcanV3ReceiptSigningPayload ([pscustomobject]$receipt)),'SHA256'))
    $receiptRaw=([pscustomobject]$receipt|ConvertTo-Json -Compress)
    $receiptEvidence=[pscustomobject]@{raw=$receiptRaw}
    $receiptExpected=@{};foreach($name in $v3ReceiptPropertyNames){$receiptExpected[$name]=$receipt[$name]}
    $null=Assert-VulcanV3Receipt $receiptEvidence $validatedTrust $receiptExpected `
        ([DateTimeOffset]::UtcNow) -AllowTestFixture -RequireCurrentlyValid
    foreach($tamper in @('report_sha256','callback_record_sha256')) {
        $bad=[ordered]@{};foreach($name in $v3ReceiptPropertyNames){$bad[$name]=$receipt[$name]}
        $bad[$tamper]='9'*64
        $badRaw=([pscustomobject]$bad|ConvertTo-Json -Compress)
        $rejected=$false
        try{$null=Assert-VulcanV3Receipt ([pscustomobject]@{raw=$badRaw}) $validatedTrust `
                $receiptExpected ([DateTimeOffset]::UtcNow) -AllowTestFixture}catch{$rejected=$true}
        if(-not $rejected){throw "VULCAN_GENUINE_EVENT_V3_TAMPER_ACCEPTED|$tamper"}
        $dynamicNegativeCases++
    }
    $badSignature=[ordered]@{};foreach($name in $v3ReceiptPropertyNames){$badSignature[$name]=$receipt[$name]}
    $badSignature.signature_base64=[Convert]::ToBase64String((New-Object byte[] $public.Modulus.Length))
    $badSignatureExpected=@{};foreach($name in $v3ReceiptPropertyNames){$badSignatureExpected[$name]=$badSignature[$name]}
    $rejected=$false
    try{$null=Assert-VulcanV3Receipt ([pscustomobject]@{raw=([pscustomobject]$badSignature|ConvertTo-Json -Compress)}) `
            $validatedTrust $badSignatureExpected ([DateTimeOffset]::UtcNow) -AllowTestFixture}catch{$rejected=$true}
    if(-not $rejected){throw 'VULCAN_GENUINE_EVENT_V3_BAD_SIGNATURE_ACCEPTED'}
    $dynamicNegativeCases++
    $rejected=$false
    try{$null=Assert-VulcanV3TrustRoot $trustEvidence ('9'*64) '' -AllowTestFixture}catch{$rejected=$true}
    if(-not $rejected){throw 'VULCAN_GENUINE_EVENT_V3_BAD_PIN_ACCEPTED'}
    $dynamicNegativeCases++
    $expired=[ordered]@{};foreach($name in $v3ReceiptPropertyNames){$expired[$name]=$receipt[$name]}
    $expired.signed_at=Format-TestInstant ([DateTimeOffset]::UtcNow.AddMinutes(-20))
    $expired.expires_at=Format-TestInstant ([DateTimeOffset]::UtcNow.AddMinutes(-10))
    $expired.challenge_issued_at=Format-TestInstant ([DateTimeOffset]::UtcNow.AddMinutes(-21))
    $expired.signature_base64=''
    $expired.signature_base64=[Convert]::ToBase64String($fixtureRsa.SignData(
        (Get-VulcanV3ReceiptSigningPayload ([pscustomobject]$expired)),'SHA256'))
    $expiredExpected=@{};foreach($name in $v3ReceiptPropertyNames){$expiredExpected[$name]=$expired[$name]}
    $rejected=$false
    try{$null=Assert-VulcanV3Receipt ([pscustomobject]@{raw=([pscustomobject]$expired|ConvertTo-Json -Compress)}) `
            $validatedTrust $expiredExpected ([DateTimeOffset]::UtcNow) -AllowTestFixture -RequireCurrentlyValid}catch{$rejected=$true}
    if(-not $rejected){throw 'VULCAN_GENUINE_EVENT_V3_EXPIRED_RECEIPT_ACCEPTED'}
    $dynamicNegativeCases++
    $null=Assert-VulcanV3Receipt `
        ([pscustomobject]@{raw=([pscustomobject]$expired|ConvertTo-Json -Compress)}) `
        $validatedTrust $expiredExpected ([DateTimeOffset]::UtcNow) -AllowTestFixture
} finally {$fixtureRsa.Dispose()}

$v3Static=[ordered]@{
    external_exchange=$source -match 'VULCAN_GENUINE_EVENT_V3_SIGNING_REQUEST_READY' -and
        $source -match 'EXTERNAL_SUPERVISOR_SIGNING_REQUEST'
    no_repo_key=$source -match 'EXTERNAL_MATERIAL_MUST_BE_OUT_OF_BAND' -and
        $source -match 'APPROVED_TRUST_ROOT_PIN_REQUIRED'
    genuine_runtime_ledger=$source -match 'MCACE_VULCAN_CALLBACK_PROVENANCE_V1' -and
        $source -match 'provider_plugin_code_source_sha256' -and
        $source -match 'accessor_provenance'
    raw_event=$source -match 'raw-risk-event\.json' -and $source -match 'raw_event_sha256'
    immutable_acceptance_window=$source -match 'PACKAGE_ACCEPTANCE_WINDOW_INVALID' -and
        $source -match 'expires_at=\$request\.expires_at' -and
        $source -match 'RequireCurrentlyValid:\$RequireCurrentlyValidReceipt'
    fail_closed_synthetic=$source -match 'non_synthetic_callback_chain_verified' -and
        $source -notmatch '(?i)PluginManager\.callEvent|\.callEvent\('
    v2_terminal=$source -match 'OPERATOR_ATTESTED_V2_EVIDENCE_NOT_RELEASE_ELIGIBLE'
}
$v3Failed=@($v3Static.GetEnumerator()|?{-not $_.Value}|% Key)
if($v3Failed.Count-ne 0){throw "VULCAN_GENUINE_EVENT_V3_STATIC_FAILED: $($v3Failed-join ', ')"}

$negativeCaseCount = $negativeCases.Count + 2 + $dynamicNegativeCases
Write-Output (
    "VULCAN_GENUINE_EVENT_WRAPPER_V3_CONTRACT_PASS|negative_cases=$negativeCaseCount" +
    '|fixture_release_eligible=false|v2_diagnostic_only=true')
