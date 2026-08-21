[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$target = Join-Path $PSScriptRoot 'vulcan-licensed-api-compatibility-smoke.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $target,
    [ref]$tokens,
    [ref]$parseErrors)
if (@($parseErrors).Count -ne 0) {
    throw "VULCAN_WRAPPER_STATIC_TEST_PARSE_FAILED: $($parseErrors -join '; ')"
}

$source = Get-Content -Raw -LiteralPath $target
$parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object {
    $_.Name.VariablePath.UserPath
})
$expectedParameters = @(
    'VulcanJar',
    'ReportOnly',
    'ArtifactSha256',
    'MaximumReportAgeMinutes'
)
$missingParameters = @($expectedParameters | Where-Object { $_ -notin $parameterNames })
if ($missingParameters.Count -ne 0) {
    throw "VULCAN_WRAPPER_STATIC_TEST_PARAMETERS_MISSING: $($missingParameters -join ', ')"
}

$commands = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst]
}, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
$forbiddenCommands = @(
    'Copy-Item',
    'Expand-Archive',
    'Invoke-RestMethod',
    'Invoke-WebRequest',
    'Move-Item',
    'Start-BitsTransfer',
    'Start-Process'
)
$presentForbiddenCommands = @($forbiddenCommands | Where-Object { $_ -in $commands })
if ($presentForbiddenCommands.Count -ne 0) {
    throw "VULCAN_WRAPPER_STATIC_TEST_FORBIDDEN_COMMANDS: $($presentForbiddenCommands -join ', ')"
}

$requirements = [ordered]@{
    offline_gradle = $source -match "'--offline'"
    direct_local_gradle = $source -match 'function Resolve-OfflineGradle' `
        -and $source -match '& \$offlineGradle\.command_path' `
        -and $source -notmatch '& \$gradlewPath'
    single_worker = $source -match "'--max-workers=1'"
    no_daemon = $source -match "'--no-daemon'"
    no_build_cache = $source -match "'--no-build-cache'"
    no_configuration_cache = $source -match "'--no-configuration-cache'"
    direct_read_lock = $source -match '\[System\.IO\.FileShare\]::Read\)'
    stream_sha256 = $source -match 'function Get-StreamSha256'
    pre_post_sha256 = $source -match '\$lockedSha256Before' `
        -and $source -match '\$lockedSha256After' `
        -and $source -match 'VULCAN_LICENSED_ARTIFACT_CHANGED_DURING_PREFLIGHT'
    unc_rejected = $source -match 'VULCAN_LICENSED_ARTIFACT_NETWORK_PATH_REJECTED' `
        -and $source -match "StartsWith\('\\\\'"
    mapped_network_rejected = $source -match '\[System\.IO\.DriveType\]::Network'
    parent_reparse_rejected = $source -match 'links and junctions are not accepted'
    powershell_51_relative_helper = $source -match 'function ConvertTo-RepoRelativePath' `
        -and $source -notmatch 'Path\]::GetRelativePath'
    report_only_sha_required = $source -match 'VULCAN_LICENSED_ARTIFACT_SHA256_REQUIRED' `
        -and $source -match 'ExpectedArtifactSha256'
    report_only_path_rejected = $source -match 'VULCAN_REPORT_ONLY_ARTIFACT_PATH_REJECTED'
    bound_sidecar_required = $source -match 'VULCAN_LICENSED_API_COMPATIBILITY_BINDING_V1' `
        -and $source -match 'VULCAN_COMPATIBILITY_BINDING_REQUIRED'
    report_digest_bound = $source -match 'report_sha256 = \$ReportSha256' `
        -and $source -match 'Open-LockedTextEvidence' `
        -and $source -match '-ReportSha256 \$reportEvidence\.sha256'
    source_digest_bound = $source -match 'source_manifest_sha256' `
        -and $source -match 'gradle_distribution_sha256' `
        -and $source -match 'gradle_launcher_sha256' `
        -and $source -match 'gradle_installation_manifest_sha256' `
        -and $source -match 'java_executable_sha256' `
        -and $source -match 'java_major'
    full_gradle_tree_bound = $source -match 'function Get-DirectLocalTreeManifest' `
        -and $source -match 'installation_file_count' `
        -and $source -match 'installation_directory_count'
    exact_json_properties = $source -match 'function Test-JsonExactProperties' `
        -and $source -match 'function Test-JsonExactTopLevelPropertyNames' `
        -and $source -match 'Get-GateReportPropertyNames' `
        -and $source -match 'Get-BindingPropertyNames'
    clean_execution_inputs = $source -match 'function Assert-CleanGradleEnvironment' `
        -and $source -match 'ORG_GRADLE_PROJECT_' `
        -and $source -match 'function Assert-NoUserGradleInputs'
    exact_gradle_java = $source -match 'function Get-GradleJavaBinding' `
        -and $source -match 'VULCAN_GRADLE_JAVA_21_REQUIRED'
    full_repo_source_manifest = $source -match 'function Get-SourceInputPaths' `
        -and $source -match "@\('\.git', '\.gradle', 'build'\)"
    execution_evidence_locked = $source -match '-ReportSha256 \$reportEvidence\.sha256' `
        -and $source -match 'Open-LockedTextEvidence -Path \$bindingItem\.FullName'
    freshness_bounded = $source -match 'MaximumReportAgeMinutes' `
        -and $source -match 'VULCAN_LICENSED_API_COMPATIBILITY_REPORT_STALE'
    artifact_path_omitted = $source -match 'artifact_path_recorded = \$false'
    exact_gate_method = $source -match 'validatesExplicitlySuppliedLicensedArtifactWithoutCopyingIt'
    strict_json_scalars = $source -match 'function Test-JsonString' `
        -and $source -match 'Test-JsonInteger'
}
$failed = @($requirements.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
if ($failed.Count -ne 0) {
    throw "VULCAN_WRAPPER_STATIC_TEST_REQUIREMENTS_FAILED: $($failed -join ', ')"
}

$forbiddenDotNetPatterns = [ordered]@{
    http_client = '(?i)System\.Net\.Http\.HttpClient|System\.Net\.WebClient|WebRequest'
    file_copy = '(?i)System\.IO\.File\]::Copy|System\.IO\.FileInfo\]::CopyTo'
    archive_extract = '(?i)ZipFile\]::Extract|ZipArchiveMode\]::Update'
    native_download = '(?im)^\s*(?:curl|wget|bitsadmin)(?:\.exe)?\b'
}
$presentDotNetPatterns = @($forbiddenDotNetPatterns.GetEnumerator() |
    Where-Object { $source -match $_.Value } |
    ForEach-Object Key)
if ($presentDotNetPatterns.Count -ne 0) {
    throw "VULCAN_WRAPPER_STATIC_TEST_FORBIDDEN_APIS: $($presentDotNetPatterns -join ', ')"
}

# Load only function definitions from the wrapper. This exercises the actual validators
# without running the wrapper main body, Gradle, or a proprietary artifact.
$functionDefinitions = @($ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $true))
foreach ($definition in $functionDefinitions) {
    Invoke-Expression $definition.Extent.Text
}

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$scriptPath = [System.IO.Path]::GetFullPath($target)
$gateTestPath = Join-Path $repoRoot 'mcace-server-paper/src/test/java/com/ellan/mcace/paper/behavior/LicensedVulcanApiCompatibilityGateTest.java'
$compatibilitySourcePath = Join-Path $repoRoot 'mcace-server-paper/src/main/java/com/ellan/mcace/paper/behavior/VulcanApiCompatibility.java'
$paperBuildPath = Join-Path $repoRoot 'mcace-server-paper/build.gradle.kts'
$rootBuildPath = Join-Path $repoRoot 'build.gradle.kts'
$settingsPath = Join-Path $repoRoot 'settings.gradle.kts'
$gradlewPath = Join-Path $repoRoot 'gradlew.bat'
$wrapperJarPath = Join-Path $repoRoot 'gradle/wrapper/gradle-wrapper.jar'
$wrapperPropertiesPath = Join-Path $repoRoot 'gradle/wrapper/gradle-wrapper.properties'
$verificationMetadataPath = Join-Path $repoRoot 'gradle/verification-metadata.xml'
$gradlePropertiesPath = Join-Path $repoRoot 'gradle.properties'
$test = 'com.ellan.mcace.paper.behavior.LicensedVulcanApiCompatibilityGateTest.validatesExplicitlySuppliedLicensedArtifactWithoutCopyingIt'
$bindingSchema = 'VULCAN_LICENSED_API_COMPATIBILITY_BINDING_V1'
$MaximumReportAgeMinutes = 60
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("mcace-vulcan-wrapper-static-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot -ErrorAction Stop | Out-Null
try {
    $expectedSha256 = 'a' * 64
    $reportPath = Join-Path $temporaryRoot 'report.json'
    $validReport = [ordered]@{
        schema = 'VULCAN_LICENSED_API_COMPATIBILITY'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        failure_stage = 'NONE'
        artifact_sha256 = $expectedSha256
        artifact_size = 123
        plugin_name = 'Vulcan'
        plugin_version = 'test'
        event_type = 'me.frep.vulcan.api.event.VulcanFlagEvent'
        player_accessor = 'getPlayer'
        check_accessor = 'getCheck'
        check_name_accessor = 'getCheckName'
        stable_check_accessor = 'getStableKey'
        event_violation_accessor = 'getViolationLevel'
        check_violation_accessor = 'none'
        artifact_path_recorded = $false
        artifact_copied_or_redistributed = $false
        paper_process_coverage = $false
        licensed_plugin_enablement_coverage = $false
        real_behavior_event_delivery_coverage = $false
        limitations = @('STRUCTURAL_PREFLIGHT_ONLY')
        passed = $true
    }
    $validRaw = $validReport | ConvertTo-Json -Depth 5
    $null = Read-AndAssertGateReport `
        -ReportPath $reportPath `
        -ExpectedArtifactSha256 $expectedSha256 `
        -ExpectedArtifactSize 123 `
        -RawReport $validRaw

    $arrayReport = [ordered]@{} + $validReport
    $arrayReport.artifact_sha256 = @($expectedSha256, 'evil')
    $arrayRejected = $false
    try {
        $null = Read-AndAssertGateReport `
            -ReportPath $reportPath `
            -ExpectedArtifactSha256 $expectedSha256 `
            -ExpectedArtifactSize 123 `
            -RawReport ($arrayReport | ConvertTo-Json -Depth 5)
    } catch {
        $arrayRejected = $_.Exception.Message -like 'VULCAN_LICENSED_API_COMPATIBILITY_REPORT_INVALID*'
    }
    if (-not $arrayRejected) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_ARRAY_REPORT_ACCEPTED'
    }

    foreach ($field in @($validReport.Keys | Where-Object { $_ -ne 'limitations' })) {
        foreach ($variant in @('ARRAY', 'OBJECT')) {
            $mutated = [ordered]@{}
            foreach ($key in $validReport.Keys) {
                $mutated[$key] = $validReport[$key]
            }
            $mutated[$field] = if ($variant -eq 'ARRAY') {
                @($validReport[$field], $validReport[$field])
            } else {
                [ordered]@{unexpected = $validReport[$field]}
            }
            $rejected = $false
            try {
                $null = Read-AndAssertGateReport `
                    -ReportPath $reportPath `
                    -ExpectedArtifactSha256 $expectedSha256 `
                    -ExpectedArtifactSize 123 `
                    -RawReport ($mutated | ConvertTo-Json -Depth 8)
            } catch {
                $rejected = $_.Exception.Message -like 'VULCAN_LICENSED_API_COMPATIBILITY_REPORT_INVALID*'
            }
            if (-not $rejected) {
                throw "VULCAN_WRAPPER_BEHAVIOR_TEST_REPORT_SCALAR_ACCEPTED: $field/$variant"
            }
        }
    }
    $invalidLimitationCases = @(
        [pscustomobject]@{value = 'STRUCTURAL_PREFLIGHT_ONLY'},
        [pscustomobject]@{value = [ordered]@{unexpected = 'value'}},
        [pscustomobject]@{value = @('STRUCTURAL_PREFLIGHT_ONLY', 'EXTRA')},
        [pscustomobject]@{value = @([ordered]@{unexpected = 'element'})}
    )
    foreach ($invalidLimitationCase in $invalidLimitationCases) {
        $mutated = [ordered]@{} + $validReport
        $mutated.limitations = $invalidLimitationCase.value
        $rejected = $false
        try {
            $null = Read-AndAssertGateReport `
                -ReportPath $reportPath `
                -ExpectedArtifactSha256 $expectedSha256 `
                -ExpectedArtifactSize 123 `
                -RawReport ($mutated | ConvertTo-Json -Depth 8)
        } catch {
            $rejected = $_.Exception.Message -like 'VULCAN_LICENSED_API_COMPATIBILITY_REPORT_INVALID*'
        }
        if (-not $rejected) {
            throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_LIMITATIONS_TYPE_ACCEPTED'
        }
    }
    $extraReport = [ordered]@{} + $validReport
    $extraReport.operator_path = 'C:\sensitive\Vulcan.jar'
    $extraReportRejected = $false
    try {
        $null = Read-AndAssertGateReport `
            -ReportPath $reportPath `
            -ExpectedArtifactSha256 $expectedSha256 `
            -ExpectedArtifactSize 123 `
            -RawReport ($extraReport | ConvertTo-Json -Depth 8)
    } catch {
        $extraReportRejected = $_.Exception.Message `
            -like 'VULCAN_LICENSED_API_COMPATIBILITY_REPORT_INVALID*'
    }
    if (-not $extraReportRejected) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_EXTRA_REPORT_PROPERTY_ACCEPTED'
    }
    $duplicateReportRaw = $validRaw.TrimEnd()
    $duplicateReportRaw = $duplicateReportRaw.Substring(0, $duplicateReportRaw.Length - 1) `
        + ",`n  `"schema`": `"VULCAN_LICENSED_API_COMPATIBILITY`"`n}"
    $duplicateReportRejected = $false
    try {
        $null = Read-AndAssertGateReport `
            -ReportPath $reportPath `
            -ExpectedArtifactSha256 $expectedSha256 `
            -ExpectedArtifactSize 123 `
            -RawReport $duplicateReportRaw
    } catch {
        $duplicateReportRejected = $_.Exception.Message `
            -like 'VULCAN_LICENSED_API_COMPATIBILITY_REPORT_INVALID*'
    }
    if (-not $duplicateReportRejected) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_DUPLICATE_REPORT_PROPERTY_ACCEPTED'
    }

    $runRoot = Join-Path $temporaryRoot '2026-08-13T00-00-00-0000000Z'
    New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop | Out-Null
    $boundReportPath = Join-Path $runRoot 'report.json'
    $bindingPath = Join-Path $runRoot 'binding.json'
    $currentSource = [pscustomobject][ordered]@{
        source_manifest_sha256 = 'b' * 64
        source_file_count = 20
        gradle_version = '9.6.1'
        gradle_distribution_sha256 = 'c' * 64
        gradle_command_sha256 = 'd' * 64
        gradle_launcher_sha256 = 'e' * 64
        gradle_core_sha256 = 'f' * 64
        gradle_installation_manifest_sha256 = '3' * 64
        gradle_installation_file_count = 701
        gradle_installation_directory_count = 18
        java_executable_sha256 = '1' * 64
        java_file_version = '21.0.8.0'
        java_major = 21
    }
    $validBinding = [ordered]@{
        schema = $bindingSchema
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        source_mode = 'EXECUTED'
        run_id = '2026-08-13T00-00-00-0000000Z'
        report_name = 'report.json'
        report_generated_at = $validReport.generated_at
        report_sha256 = '2' * 64
        artifact_sha256 = $expectedSha256
        artifact_size = 123
        artifact_path_recorded = $false
        source_manifest_sha256 = $currentSource.source_manifest_sha256
        source_file_count = $currentSource.source_file_count
        gradle_version = $currentSource.gradle_version
        gradle_distribution_sha256 = $currentSource.gradle_distribution_sha256
        gradle_command_sha256 = $currentSource.gradle_command_sha256
        gradle_launcher_sha256 = $currentSource.gradle_launcher_sha256
        gradle_core_sha256 = $currentSource.gradle_core_sha256
        gradle_installation_manifest_sha256 = $currentSource.gradle_installation_manifest_sha256
        gradle_installation_file_count = $currentSource.gradle_installation_file_count
        gradle_installation_directory_count = $currentSource.gradle_installation_directory_count
        java_executable_sha256 = $currentSource.java_executable_sha256
        java_file_version = $currentSource.java_file_version
        java_major = $currentSource.java_major
        gradle_task = ':mcace-server-paper:test'
        test_selector = $test
        gradle_offline = $true
    }
    $writtenBindingPath = Join-Path $runRoot 'written-binding.json'
    Write-ExecutionBinding `
        -BindingPath $writtenBindingPath `
        -ReportPath $boundReportPath `
        -ReportSha256 $validBinding.report_sha256 `
        -Report ([pscustomobject]$validReport) `
        -SourceBinding $currentSource `
        -ArtifactSize 123
    $writtenBindingRaw = [System.IO.File]::ReadAllText($writtenBindingPath)
    $null = Read-AndAssertBinding `
        -BindingPath $writtenBindingPath `
        -ReportPath $boundReportPath `
        -ExpectedArtifactSha256 $expectedSha256 `
        -CurrentSourceBinding $currentSource `
        -RawBinding $writtenBindingRaw `
        -LockedReportSha256 $validBinding.report_sha256
    $bindingOverwriteRejected = $false
    try {
        Write-ExecutionBinding `
            -BindingPath $writtenBindingPath `
            -ReportPath $boundReportPath `
            -ReportSha256 $validBinding.report_sha256 `
            -Report ([pscustomobject]$validReport) `
            -SourceBinding $currentSource `
            -ArtifactSize 123
    } catch [System.IO.IOException] {
        $bindingOverwriteRejected = $true
    }
    if (-not $bindingOverwriteRejected) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_BINDING_OVERWRITE_ACCEPTED'
    }
    $null = Read-AndAssertBinding `
        -BindingPath $bindingPath `
        -ReportPath $boundReportPath `
        -ExpectedArtifactSha256 $expectedSha256 `
        -CurrentSourceBinding $currentSource `
        -RawBinding ($validBinding | ConvertTo-Json -Depth 5) `
        -LockedReportSha256 $validBinding.report_sha256

    $arrayBinding = [ordered]@{} + $validBinding
    $arrayBinding.source_manifest_sha256 = @($currentSource.source_manifest_sha256, 'evil')
    $arrayBindingRejected = $false
    try {
        $null = Read-AndAssertBinding `
            -BindingPath $bindingPath `
            -ReportPath $boundReportPath `
            -ExpectedArtifactSha256 $expectedSha256 `
            -CurrentSourceBinding $currentSource `
            -RawBinding ($arrayBinding | ConvertTo-Json -Depth 5) `
            -LockedReportSha256 $validBinding.report_sha256
    } catch {
        $arrayBindingRejected = $_.Exception.Message -like 'VULCAN_LICENSED_API_COMPATIBILITY_BINDING_INVALID*'
    }
    if (-not $arrayBindingRejected) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_ARRAY_BINDING_ACCEPTED'
    }

    foreach ($field in $validBinding.Keys) {
        foreach ($variant in @('ARRAY', 'OBJECT')) {
            $mutated = [ordered]@{}
            foreach ($key in $validBinding.Keys) {
                $mutated[$key] = $validBinding[$key]
            }
            $mutated[$field] = if ($variant -eq 'ARRAY') {
                @($validBinding[$field], $validBinding[$field])
            } else {
                [ordered]@{unexpected = $validBinding[$field]}
            }
            $rejected = $false
            try {
                $null = Read-AndAssertBinding `
                    -BindingPath $bindingPath `
                    -ReportPath $boundReportPath `
                    -ExpectedArtifactSha256 $expectedSha256 `
                    -CurrentSourceBinding $currentSource `
                    -RawBinding ($mutated | ConvertTo-Json -Depth 8) `
                    -LockedReportSha256 $validBinding.report_sha256
            } catch {
                $rejected = $_.Exception.Message -like 'VULCAN_LICENSED_API_COMPATIBILITY_BINDING_INVALID*'
            }
            if (-not $rejected) {
                throw "VULCAN_WRAPPER_BEHAVIOR_TEST_BINDING_SCALAR_ACCEPTED: $field/$variant"
            }
        }
    }
    $extraBinding = [ordered]@{} + $validBinding
    $extraBinding.operator_path = 'C:\sensitive\Vulcan.jar'
    $extraBindingRejected = $false
    try {
        $null = Read-AndAssertBinding `
            -BindingPath $bindingPath `
            -ReportPath $boundReportPath `
            -ExpectedArtifactSha256 $expectedSha256 `
            -CurrentSourceBinding $currentSource `
            -RawBinding ($extraBinding | ConvertTo-Json -Depth 8) `
            -LockedReportSha256 $validBinding.report_sha256
    } catch {
        $extraBindingRejected = $_.Exception.Message `
            -like 'VULCAN_LICENSED_API_COMPATIBILITY_BINDING_INVALID*'
    }
    if (-not $extraBindingRejected) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_EXTRA_BINDING_PROPERTY_ACCEPTED'
    }
    $validBindingRaw = $validBinding | ConvertTo-Json -Depth 8
    $duplicateBindingRaw = $validBindingRaw.TrimEnd()
    $duplicateBindingRaw = $duplicateBindingRaw.Substring(0, $duplicateBindingRaw.Length - 1) `
        + ",`n  `"schema`": `"$bindingSchema`"`n}"
    $duplicateBindingRejected = $false
    try {
        $null = Read-AndAssertBinding `
            -BindingPath $bindingPath `
            -ReportPath $boundReportPath `
            -ExpectedArtifactSha256 $expectedSha256 `
            -CurrentSourceBinding $currentSource `
            -RawBinding $duplicateBindingRaw `
            -LockedReportSha256 $validBinding.report_sha256
    } catch {
        $duplicateBindingRejected = $_.Exception.Message `
            -like 'VULCAN_LICENSED_API_COMPATIBILITY_BINDING_INVALID*'
    }
    if (-not $duplicateBindingRejected) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_DUPLICATE_BINDING_PROPERTY_ACCEPTED'
    }

    $uncRejected = $false
    try {
        $null = Get-DirectLocalItem `
            -Path '\\example.invalid\share\Vulcan.jar' `
            -RequireLeaf `
            -MissingError 'missing'
    } catch {
        $uncRejected = $_.Exception.Message -like 'VULCAN_LICENSED_ARTIFACT_NETWORK_PATH_REJECTED*'
    }
    if (-not $uncRejected) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_UNC_ACCEPTED'
    }

    $fakeEvidencePath = Join-Path $temporaryRoot 'locked.json'
    $utf8 = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($fakeEvidencePath, '{"ok":true}', $utf8)
    $evidence = Open-LockedTextEvidence -Path $fakeEvidencePath
    try {
        Assert-LockedTextEvidenceUnchanged -Evidence $evidence
        $replacementBlocked = $false
        try {
            [System.IO.File]::Delete($fakeEvidencePath)
        } catch [System.IO.IOException] {
            $replacementBlocked = $true
        }
        if (-not $replacementBlocked) {
            throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_EVIDENCE_LOCK_MISSING'
        }
    } finally {
        $evidence.stream.Dispose()
    }

    $controlledEnvironmentNames = @(
        '_JAVA_OPTIONS',
        'JAVA_TOOL_OPTIONS',
        'JDK_JAVA_OPTIONS',
        'GRADLE_OPTS',
        'JAVA_OPTS'
    )
    $originalGradleUserHome = $env:GRADLE_USER_HOME
    $originalControlledEnvironment = @{}
    foreach ($name in $controlledEnvironmentNames) {
        $originalControlledEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
        [Environment]::SetEnvironmentVariable($name, $null, 'Process')
    }
    try {
        $env:GRADLE_USER_HOME = $temporaryRoot
        $distributionRejected = $false
        try {
            $null = Resolve-OfflineGradle
        } catch {
            $distributionRejected = $_.Exception.Message -like 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_REQUIRED*'
        }
        if (-not $distributionRejected) {
            throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_MISSING_DISTRIBUTION_ACCEPTED'
        }
    } finally {
        $env:GRADLE_USER_HOME = $originalGradleUserHome
        foreach ($name in $controlledEnvironmentNames) {
            [Environment]::SetEnvironmentVariable(
                $name,
                $originalControlledEnvironment[$name],
                'Process')
        }
    }

    $originalJavaToolOptions = $env:JAVA_TOOL_OPTIONS
    try {
        $env:JAVA_TOOL_OPTIONS = '-Dmcace.unbound=true'
        $environmentRejected = $false
        try {
            Assert-CleanGradleEnvironment
        } catch {
            $environmentRejected = $_.Exception.Message `
                -like 'VULCAN_GRADLE_ENVIRONMENT_INPUT_REJECTED*'
        }
        if (-not $environmentRejected) {
            throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_ENVIRONMENT_INPUT_ACCEPTED'
        }
    } finally {
        $env:JAVA_TOOL_OPTIONS = $originalJavaToolOptions
    }
    $projectEnvironmentName = 'ORG_GRADLE_PROJECT_mcaceSyntheticInput'
    $originalProjectEnvironment = [Environment]::GetEnvironmentVariable(
        $projectEnvironmentName,
        'Process')
    try {
        [Environment]::SetEnvironmentVariable(
            $projectEnvironmentName,
            'unbound',
            'Process')
        $projectEnvironmentRejected = $false
        try {
            Assert-CleanGradleEnvironment
        } catch {
            $projectEnvironmentRejected = $_.Exception.Message `
                -like 'VULCAN_GRADLE_ENVIRONMENT_INPUT_REJECTED*'
        }
        if (-not $projectEnvironmentRejected) {
            throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_PROJECT_ENVIRONMENT_INPUT_ACCEPTED'
        }
    } finally {
        [Environment]::SetEnvironmentVariable(
            $projectEnvironmentName,
            $originalProjectEnvironment,
            'Process')
    }

    $fakeInitPath = Join-Path $temporaryRoot 'init.gradle'
    [System.IO.File]::WriteAllText($fakeInitPath, '// synthetic static-test input', $utf8)
    $initRejected = $false
    try {
        Assert-NoUserGradleInputs -GradleUserHome $temporaryRoot
    } catch {
        $initRejected = $_.Exception.Message -like 'VULCAN_UNBOUND_USER_GRADLE_INPUT_REJECTED*'
    }
    if (-not $initRejected) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_USER_INIT_ACCEPTED'
    }
    [System.IO.File]::Delete($fakeInitPath)

    $fakeJavaHome = Join-Path $temporaryRoot 'fake-java-home'
    $fakeJavaBin = Join-Path $fakeJavaHome 'bin'
    New-Item -ItemType Directory -Path $fakeJavaBin -ErrorAction Stop | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $fakeJavaBin 'java.exe'), 'not a JDK', $utf8)
    $originalJavaHome = $env:JAVA_HOME
    try {
        $env:JAVA_HOME = $fakeJavaHome
        $javaRejected = $false
        try {
            $null = Get-GradleJavaBinding
        } catch {
            $javaRejected = $_.Exception.Message -like 'VULCAN_GRADLE_JAVA_21_REQUIRED*'
        }
        if (-not $javaRejected) {
            throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_NON_JDK21_JAVA_ACCEPTED'
        }
    } finally {
        $env:JAVA_HOME = $originalJavaHome
    }

    $now = [DateTimeOffset]::UtcNow
    $staleRejected = $false
    try {
        Assert-FreshTimestamp -Timestamp $now.AddMinutes(-61) -Now $now -Field 'test'
    } catch {
        $staleRejected = $_.Exception.Message -like 'VULCAN_LICENSED_API_COMPATIBILITY_REPORT_STALE*'
    }
    if (-not $staleRejected) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_STALE_TIMESTAMP_ACCEPTED'
    }

    $treeRoot = Join-Path $temporaryRoot 'synthetic-gradle-tree'
    $treeLib = Join-Path $treeRoot 'lib'
    New-Item -ItemType Directory -Path $treeLib -ErrorAction Stop | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $treeRoot 'gradle.bat'), '@echo off', $utf8)
    [System.IO.File]::WriteAllText((Join-Path $treeLib 'launcher.jar'), 'synthetic', $utf8)
    $treeManifestBefore = Get-DirectLocalTreeManifest -RootPath $treeRoot
    $treeManifestAgain = Get-DirectLocalTreeManifest -RootPath $treeRoot
    if ($treeManifestBefore.sha256 -ne $treeManifestAgain.sha256 `
            -or $treeManifestBefore.file_count -ne 2 `
            -or $treeManifestBefore.directory_count -ne 2) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_GRADLE_TREE_MANIFEST_INVALID'
    }
    [System.IO.File]::WriteAllText((Join-Path $treeLib 'launcher.jar'), 'changed', $utf8)
    $treeManifestAfter = Get-DirectLocalTreeManifest -RootPath $treeRoot
    if ($treeManifestAfter.sha256 -eq $treeManifestBefore.sha256) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_GRADLE_TREE_CHANGE_NOT_DETECTED'
    }

    $offlineGradle = [pscustomobject][ordered]@{
        version = '9.6.1'
        distribution_sha256 = '3' * 64
        command_sha256 = '4' * 64
        launcher_sha256 = '5' * 64
        core_sha256 = '6' * 64
        installation_manifest_sha256 = $treeManifestAfter.sha256
        installation_file_count = $treeManifestAfter.file_count
        installation_directory_count = $treeManifestAfter.directory_count
        java_executable_sha256 = '7' * 64
        java_file_version = '21.0.8.0'
        java_major = 21
    }
    $sourceBinding = Get-SourceBinding -OfflineGradle $offlineGradle
    if ($sourceBinding.source_manifest_sha256 -notmatch '^[0-9a-f]{64}$' `
            -or $sourceBinding.source_file_count -lt 10 `
            -or $sourceBinding.gradle_installation_manifest_sha256 `
                -ne $treeManifestAfter.sha256 `
            -or $sourceBinding.java_executable_sha256 -notmatch '^[0-9a-f]{64}$' `
            -or $sourceBinding.java_major -ne 21) {
        throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_SOURCE_BINDING_INVALID'
    }
} finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
        $temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        $temporaryBase = $temporaryBase.TrimEnd([char[]]@('\', '/')) `
            + [System.IO.Path]::DirectorySeparatorChar
        if (-not $resolvedTemporaryRoot.StartsWith(
                $temporaryBase,
                [System.StringComparison]::OrdinalIgnoreCase) `
                -or -not (Split-Path $resolvedTemporaryRoot -Leaf).StartsWith(
                    'mcace-vulcan-wrapper-static-',
                    [System.StringComparison]::Ordinal)) {
            throw 'VULCAN_WRAPPER_BEHAVIOR_TEST_TEMP_PATH_INVALID'
        }
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
}

Write-Output 'VULCAN_WRAPPER_STATIC_TEST_PASS'
