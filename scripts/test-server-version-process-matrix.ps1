[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$target = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'server-version-process-matrix.ps1'))

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "SERVER_VERSION_MATRIX_STATIC_TEST_FAILED|$Message" }
}

function Assert-Contains([string]$Source, [string]$Needle, [string]$Label) {
    Assert-True ($Source.IndexOf($Needle, [StringComparison]::Ordinal) -ge 0) $Label
}

$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    $target, [ref]$tokens, [ref]$parseErrors)
Assert-True ($parseErrors.Count -eq 0) 'target script does not parse'
$source = [IO.File]::ReadAllText($target, [Text.Encoding]::UTF8)
Assert-Contains $source 'return ,$set' `
    'raw run directory set must remain a single HashSet object when empty'

# The wrapper is an explicit gate, never an accidental default execution path.
$noMode = $null
try { & $target 2>&1 | Out-Null }
catch { $noMode = $_.Exception.Message }
Assert-True ($noMode -like '*SERVER_VERSION_MATRIX_EXPLICIT_MODE_REQUIRED*') `
    'no-mode invocation did not fail closed'
$bothModes = $null
try { & $target -Execute -ReportOnly 2>&1 | Out-Null }
catch { $bothModes = $_.Exception.Message }
Assert-True ($bothModes -like '*SERVER_VERSION_MATRIX_EXPLICIT_MODE_REQUIRED*') `
    'dual-mode invocation did not fail closed'
$resumeOnly = $null
try { & $target -Resume -ReportOnly 2>&1 | Out-Null }
catch { $resumeOnly = $_.Exception.Message }
Assert-True ($resumeOnly -like '*SERVER_VERSION_MATRIX_RESUME_EXECUTE_REQUIRED*') `
    'resume without Execute did not fail closed'

$expectedAssets = @(
    @('paper','1.21.11','132','5ffef465eeeb5f2a3c23a24419d97c51afd7dbb4923ff42df9a3f58bba1ccfba','54846016','STABLE','21'),
    @('paper','26.1.2','74','1d70b1dab9cf4a6de615209a536f3a45a2186240253c428213ce2188ab95e5f7','52893229','STABLE','25'),
    @('paper','26.2','116','17eee738bc0f6b747646be4199672c4efcb2084efd7e291ec5254a45d5ae6f2e','64426830','STABLE','25'),
    @('folia','1.21.11','14','f52c408490a0225611e67907a3ca19f7e6da2c6bc899e715d5f46844e7103c39','55082693','STABLE','21'),
    @('folia','26.1.2','8','607afd1c3320008e1ffd2eaee6780ace4419d5f8c527b75e79f259be79ebf57b','53184326','STABLE','25'),
    @('folia','26.2','6','9a728381da3a3bea6732ee210519f8f6ab7d6affe132a430ee167c44c4603d08','64694365','BETA','25'),
    @('velocity','3.5.1-615','615','b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3','18932366','REVIEWED','21'),
    @('bungeecord','2085','2085','e6914a29c0ae04c0ed6335f201e409322b3c67548906a91e92e832d665cd6fce','25599274','REVIEWED','21')
)
foreach ($asset in $expectedAssets) {
    foreach ($value in $asset) {
        Assert-Contains $source ([string]$value) "asset identity token missing: $value"
    }
}

foreach ($token in @(
    "`$targetVersions = @('1.21.11', '26.1.2', '26.2')",
    "'1.21.11'=774", "'26.1.2'=775", "'26.2'=776",
    "'1.21.11'=21", "'26.1.2'=25", "'26.2'=25",
    "'1.21.11'='0x30'", "'26.1.2'='0x31'", "'26.2'='0x31'",
    'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V1',
    'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V1',
    'MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V1',
    'MCACE_PREPARED_TREE_SHA256_V1',
    'MCACE_SERVER_VERSION_PROCESS_MATRIX_CHECKPOINT_V1',
    'Read-ExecutionCheckpoint', 'Write-ExecutionCheckpoint',
    'SERVER_VERSION_MATRIX_RESUME_EXECUTE_REQUIRED')) {
    Assert-Contains $source $token "matrix/protocol/schema token missing: $token"
}

foreach ($selector in @(
    'realVelocityModernForwardingOfflinePlayerProbeReachesMCAceChannel',
    'realBungeeIpForwardingOfflinePlayerProbeReachesMCAceChannel',
    'realVelocityModernForwardingToFoliaReturnsShadowContext',
    'realBungeeIpForwardingToFoliaReturnsShadowContext')) {
    Assert-Contains $source $selector "exact selector missing: $selector"
}

foreach ($property in @(
    'mcace.runtime.player-probe.enabled','mcace.runtime.folia-context.enabled',
    'mcace.runtime.backend-kind','mcace.runtime.minecraft-version',
    'mcace.runtime.minecraft-protocol','mcace.runtime.server-java-feature',
    'mcace.runtime.backend.jar','mcace.runtime.backend.jar.sha256',
    'mcace.runtime.backend.prepared-root','mcace.runtime.backend.prepared-root.sha256',
    'mcace.runtime.server-java','mcace.runtime.server-java.sha256',
    'mcace.runtime.velocity.jar','mcace.runtime.velocity.jar.sha256',
    'mcace.runtime.bungee.jar','mcace.runtime.bungee.jar.sha256')) {
    Assert-Contains $source $property "required runtime property missing: $property"
}

foreach ($flag in @(
    '--rerun-tasks','--offline','--dependency-verification=strict','--no-build-cache',
    '--no-configuration-cache','--no-daemon','--no-parallel','--max-workers=1',
    '--console=plain','--gradle-user-home','--project-dir')) {
    Assert-Contains $source $flag "strict Gradle flag missing: $flag"
}
foreach ($token in @(
    'gradle-9.6.1-bin','Resolve-CachedGradle961','Resolve-CachedJdk 21',
    'Resolve-CachedJdk 25','java_executable_sha256','modules_sha256','jvm_sha256',
    'source_manifest_sha256','wrapper_sha256','wrapper_test_sha256',
    'runtime_assets_manifest_sha256','prepared_manifest_sha256','product_jars',
    'server_asset_identity','proxy_asset_identity','raw_report_sha256',
    'raw_report_last_write_at','prepared_tree_sha256','sensitive_artifact_count')) {
    Assert-Contains $source $token "binding token missing: $token"
}
Assert-True ($source -match 'stable_case_count\s*=\s*10' -and
    $source -match 'beta_case_count\s*=\s*2') `
    '26.2 Folia must produce two BETA proxy cases and ten STABLE cases'

foreach ($token in @(
    "`$preparedRoots = @('cache', 'libraries', 'versions')",
    'Get-Int32BigEndianBytes','Get-Int64BigEndianBytes','TransformBlock',
    'Assert-NoSensitiveRunArtifacts','forwarding.secret','private[-_]?key',
    'PRIVATE KEY-----','Assert-RunRootBytes','Get-RunProcesses',
    'remaining_run_processes','cleanup_process_ids','schema -ne 4')) {
    Assert-Contains $source $token "runtime byte/cleanup token missing: $token"
}

Assert-True ($source -notmatch "(?<![0-9.])'1\.21\.1'(?![0-9.])") `
    'legacy 1.21.1 fallback is present'
Assert-True ($source -notmatch "(?<![0-9.])'1\.21\.4'(?![0-9.])") `
    'legacy 1.21.4 fallback is present'
foreach ($forbidden in @('Invoke-WebRequest','Invoke-RestMethod','Start-BitsTransfer')) {
    Assert-True ($source.IndexOf($forbidden, [StringComparison]::OrdinalIgnoreCase) -lt 0) `
        "network/wrapper fallback present: $forbidden"
}
Assert-True ($source -notmatch '(?im)^\s*&[^\r\n]*gradlew(?:\.bat)?\b') `
    'Gradle wrapper is used as an execution fallback'

$reportOnlyBranches = @($ast.FindAll({
    param($node)
    $node -is [Management.Automation.Language.IfStatementAst] -and
        $node.Clauses.Count -gt 0 -and
        $node.Clauses[0].Item1.Extent.Text.Trim() -ceq '$ReportOnly'
}, $true))
Assert-True ($reportOnlyBranches.Count -eq 1) 'ReportOnly branch is not unique'
$reportOnlyText = $reportOnlyBranches[0].Extent.Text
foreach ($required in @('Get-CurrentBinding','Get-LatestCompleteEvidenceReport',
        'Assert-EvidenceTriplet','exit 0')) {
    Assert-Contains $reportOnlyText $required "ReportOnly validation missing: $required"
}
foreach ($forbidden in @('Invoke-StrictGradle','Invoke-ProductBuild','Invoke-MatrixCase',
        'New-EvidenceTriplet','CreateDirectory','WriteAllBytes','Write-NewFileBytes')) {
    Assert-True ($reportOnlyText.IndexOf($forbidden, [StringComparison]::Ordinal) -lt 0) `
        "ReportOnly can execute/mutate: $forbidden"
}

$reportWrite = $source.IndexOf('Write-NewFileBytes $stagingReport $reportBytes',
    [StringComparison]::Ordinal)
$bindingWrite = $source.IndexOf("Write-NewFileBytes (Join-Path `$stagingRoot 'binding.json') `$bindingBytes",
    [StringComparison]::Ordinal)
$commitWrite = $source.IndexOf("Write-NewFileBytes (Join-Path `$stagingRoot 'commit.json') `$commitBytes",
    [StringComparison]::Ordinal)
$publishMove = $source.IndexOf('[IO.Directory]::Move($stagingRoot, $finalRoot)',
    [StringComparison]::Ordinal)
Assert-True ($reportWrite -ge 0 -and $reportWrite -lt $bindingWrite -and
    $bindingWrite -lt $commitWrite -and $commitWrite -lt $publishMove) `
    'report/binding/commit/rename publication order is invalid'

function Get-FunctionText([string]$Name) {
    $matches = @($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -ceq $Name
    }, $true))
    Assert-True ($matches.Count -eq 1) "fixture function missing/duplicate: $Name"
    return $matches[0].Extent.Text
}

# Exercise the target's timestamp normalizer through the same JSON round trip that turns ISO text
# into local DateTime objects on PowerShell 7 while remaining a string on Windows PowerShell 5.
$timestampFixtureSource = @"
param([object]`$Value, [string]`$Label)
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
$(Get-FunctionText 'ConvertTo-ExactDateTimeOffset')
ConvertTo-ExactDateTimeOffset `$Value `$Label
"@
$timestampFixtureScript = [ScriptBlock]::Create($timestampFixtureSource)
$timestampCompareFixtureSource = @"
param([object]`$Left, [object]`$Right, [string]`$Label)
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
$(Get-FunctionText 'ConvertTo-ExactDateTimeOffset')
$(Get-FunctionText 'Test-ExactDateTimeOffsetInstant')
Test-ExactDateTimeOffsetInstant `$Left `$Right `$Label
"@
$timestampCompareFixtureScript = [ScriptBlock]::Create($timestampCompareFixtureSource)
$zJson = '{"mtime":"2026-08-14T05:02:32.3274496Z"}'
$zValue = ($zJson | ConvertFrom-Json).mtime
$roundTripValue = (([pscustomobject]@{ mtime = $zValue } | ConvertTo-Json -Compress) |
    ConvertFrom-Json).mtime
$plusEightValue = ('{"mtime":"2026-08-14T13:02:32.3274496+08:00"}' |
    ConvertFrom-Json).mtime
$zInstant = & $timestampFixtureScript $zValue 'z'
$roundTripInstant = & $timestampFixtureScript $roundTripValue 'roundtrip'
$plusEightInstant = & $timestampFixtureScript $plusEightValue 'plus-eight'
Assert-True ($zInstant.Ticks -eq $roundTripInstant.Ticks -and
    $zInstant.Ticks -eq $plusEightInstant.Ticks) `
    'equal JSON timestamp instants with Z/+08 offsets were not normalized exactly'
Assert-True ([bool](& $timestampCompareFixtureScript $roundTripValue $plusEightValue 'equal')) `
    'actual timestamp comparator rejected equal JSON Z/+08 instants'
$driftValue = ('{"mtime":"2026-08-14T05:02:32.3274497Z"}' | ConvertFrom-Json).mtime
$driftInstant = & $timestampFixtureScript $driftValue 'one-tick-drift'
Assert-True (($driftInstant.Ticks - $zInstant.Ticks) -eq 1) `
    'one-tick timestamp drift was not preserved for exact rejection'
Assert-True (-not [bool](& $timestampCompareFixtureScript $zValue $driftValue 'drift')) `
    'actual timestamp comparator accepted a one-tick drift'
$invalidTimestampMessage = $null
try { & $timestampFixtureScript 'not-a-timestamp' 'invalid' | Out-Null }
catch { $invalidTimestampMessage = $_.Exception.Message }
Assert-True ($invalidTimestampMessage -like '*SERVER_VERSION_MATRIX_TIMESTAMP_INVALID|invalid*') `
    'invalid timestamp was not rejected'

function Get-ReferencePreparedHash([string]$Root) {
    $records = [Collections.Generic.SortedDictionary[string,string]]::new(
        [StringComparer]::Ordinal)
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\','/')) +
        [IO.Path]::DirectorySeparatorChar
    foreach ($rootName in @('cache','libraries','versions')) {
        foreach ($file in @(Get-ChildItem -LiteralPath (Join-Path $Root $rootName) `
                -Recurse -File -Force)) {
            $full = [IO.Path]::GetFullPath($file.FullName)
            $relative = $full.Substring($prefix.Length).Replace('\','/')
            $records.Add($relative, $full)
        }
    }
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $domain = [Text.Encoding]::ASCII.GetBytes("MCACE_PREPARED_TREE_SHA256_V1`0")
        [void]$sha.TransformBlock($domain,0,$domain.Length,$domain,0)
        foreach ($pair in $records.GetEnumerator()) {
            $relative = [Text.UTF8Encoding]::new($false).GetBytes($pair.Key)
            $length = [BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder([int]$relative.Length))
            [void]$sha.TransformBlock($length,0,$length.Length,$length,0)
            [void]$sha.TransformBlock($relative,0,$relative.Length,$relative,0)
            $size = [BitConverter]::GetBytes([Net.IPAddress]::HostToNetworkOrder(
                [long](Get-Item -LiteralPath $pair.Value).Length))
            [void]$sha.TransformBlock($size,0,$size.Length,$size,0)
            $bytes = [IO.File]::ReadAllBytes($pair.Value)
            [void]$sha.TransformBlock($bytes,0,$bytes.Length,$bytes,0)
        }
        [void]$sha.TransformFinalBlock([byte[]]::new(0),0,0)
        return ([BitConverter]::ToString($sha.Hash)).Replace('-','').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) (
    'mcace-server-version-matrix-static-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($fixtureRoot)
try {
    foreach ($name in @('cache','libraries','versions','plugins')) {
        [void][IO.Directory]::CreateDirectory((Join-Path $fixtureRoot $name))
    }
    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'cache\alpha.bin'), 'alpha',
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'libraries\beta.bin'), 'beta',
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'versions\gamma.bin'), 'gamma',
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'plugins\ignored.txt'), 'one',
        [Text.UTF8Encoding]::new($false))

    $functionNames = @(
        'ConvertTo-LowerHex','Get-Int32BigEndianBytes','Get-Int64BigEndianBytes',
        'Add-DigestBytes','Assert-DirectLocalPath','Assert-CanonicalRelative',
        'Get-PreparedTreeSnapshot')
    $fixtureSource = @"
param([string]`$Root)
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
`$preparedTreeDomain = "MCACE_PREPARED_TREE_SHA256_V1``0"
`$preparedRoots = @('cache','libraries','versions')
$($functionNames | ForEach-Object { Get-FunctionText $_ } | Out-String)
Get-PreparedTreeSnapshot `$Root
"@
    $fixtureScript = [ScriptBlock]::Create($fixtureSource)
    $first = & $fixtureScript $fixtureRoot
    $reference = Get-ReferencePreparedHash $fixtureRoot
    Assert-True ([string]$first.tree_sha256 -ceq $reference) `
        'prepared hash differs from independent three-root reference'
    Assert-True ($first.file_count -eq 3) 'prepared hash did not use exactly three fixture files'

    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'plugins\ignored.txt'), 'changed',
        [Text.UTF8Encoding]::new($false))
    $ignoredMutation = & $fixtureScript $fixtureRoot
    Assert-True ([string]$ignoredMutation.tree_sha256 -ceq [string]$first.tree_sha256) `
        'noncanonical root affected prepared hash'

    [IO.File]::WriteAllText((Join-Path $fixtureRoot 'libraries\beta.bin'), 'zeta',
        [Text.UTF8Encoding]::new($false))
    $canonicalMutation = & $fixtureScript $fixtureRoot
    Assert-True ([string]$canonicalMutation.tree_sha256 -cne [string]$first.tree_sha256) `
        'canonical same-size mutation did not affect prepared hash'
    Assert-True ([string]$canonicalMutation.tree_sha256 -ceq
        (Get-ReferencePreparedHash $fixtureRoot)) `
        'mutated prepared hash differs from independent reference'

    # Execute the target's actual cached-Gradle resolver against a sealed fake cache. This catches
    # PowerShell's case-insensitive collision between a local $home variable and read-only $HOME.
    $fakeGradleUserHome = Join-Path $fixtureRoot 'gradle-user-home'
    $fakeGradleHome = Join-Path $fakeGradleUserHome `
        'wrapper\dists\gradle-9.6.1-bin\fixture-hash\gradle-9.6.1'
    [void][IO.Directory]::CreateDirectory((Join-Path $fakeGradleHome 'bin'))
    [void][IO.Directory]::CreateDirectory((Join-Path $fakeGradleHome 'lib'))
    [IO.File]::WriteAllText((Join-Path $fakeGradleHome 'bin\gradle.bat'), '@echo off',
        [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $fakeGradleHome 'lib\gradle-launcher-9.6.1.jar'),
        'fixture-launcher', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path $fakeGradleHome 'lib\gradle-core-9.6.1.jar'),
        'fixture-core', [Text.UTF8Encoding]::new($false))
    $gradleFunctionNames = @(
        'ConvertTo-LowerHex','Add-DigestBytes','Assert-DirectLocalPath','Assert-PathBelow',
        'Get-StableFileDigest','Assert-CanonicalRelative','Get-DirectoryManifestDigest',
        'Resolve-CachedGradle961')
    $gradleFixtureSource = @"
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
$($gradleFunctionNames | ForEach-Object { Get-FunctionText $_ } | Out-String)
Resolve-CachedGradle961
"@
    $oldGradleUserHome = $env:GRADLE_USER_HOME
    try {
        $env:GRADLE_USER_HOME = $fakeGradleUserHome
        $resolvedGradle = & ([ScriptBlock]::Create($gradleFixtureSource))
    } finally {
        $env:GRADLE_USER_HOME = $oldGradleUserHome
    }
    Assert-True ([IO.Path]::GetFullPath([string]$resolvedGradle.home) -ceq
        [IO.Path]::GetFullPath($fakeGradleHome)) `
        'actual cached-Gradle resolver returned the wrong installation home'
    Assert-True ([string]$resolvedGradle.public.version -ceq '9.6.1' -and
        [int]$resolvedGradle.public.installation_file_count -eq 3) `
        'actual cached-Gradle resolver did not bind the complete fixture installation'
    foreach ($hash in @(
            $resolvedGradle.public.command_sha256,
            $resolvedGradle.public.launcher_sha256,
            $resolvedGradle.public.core_sha256,
            $resolvedGradle.public.installation_manifest_sha256)) {
        Assert-True ([string]$hash -cmatch '^[0-9a-f]{64}$') `
            'actual cached-Gradle resolver returned an invalid digest'
    }

    # Execute the actual invocation helper with a fake native command. Multiple stdout/stderr
    # lines must remain visible and logged without contaminating the function success pipeline.
    $fakeGradleCommand = Join-Path $fakeGradleHome 'bin\gradle.bat'
    [IO.File]::WriteAllText($fakeGradleCommand, @'
@echo off
echo fixture stdout line one
echo fixture stdout line two
echo fixture stderr line three 1>&2
exit /b 0
'@, [Text.UTF8Encoding]::new($false))
    $fakeJdkHome = Join-Path $fixtureRoot 'fake-jdk'
    [void][IO.Directory]::CreateDirectory((Join-Path $fakeJdkHome 'bin'))
    $fakeInvocationRoot = Join-Path $fixtureRoot 'fake-invocations'
    [void][IO.Directory]::CreateDirectory($fakeInvocationRoot)
    $invokeFunctionNames = @(
        'ConvertTo-LowerHex','Assert-DirectLocalPath','Assert-ExistingOrParentDirect',
        'Get-StableFileDigest','Get-StrictGradleFlags','Invoke-StrictGradle')
    $invokeFixtureSource = @"
param([string]`$FixtureRepoRoot, [string]`$FixtureInvocationRoot,
    [string]`$FixtureCommand, [string]`$FixtureJdkHome,
    [string]`$FixtureGradleUserHome, [string]`$FixtureLogName)
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
`$repoRoot = `$FixtureRepoRoot
`$invocationRoot = `$FixtureInvocationRoot
$($invokeFunctionNames | ForEach-Object { Get-FunctionText $_ } | Out-String)
`$fixtureCurrent = [pscustomobject]@{
    jdk21 = [pscustomobject]@{ home = `$FixtureJdkHome }
    gradle = [pscustomobject]@{
        command = `$FixtureCommand
        user_home = `$FixtureGradleUserHome
    }
}
Invoke-StrictGradle -Current `$fixtureCurrent -Arguments @('fixture-task') -LogName `$FixtureLogName
"@
    $invokeFixtureScript = [ScriptBlock]::Create($invokeFixtureSource)
    $successResult = @(& $invokeFixtureScript $fixtureRoot $fakeInvocationRoot `
        $fakeGradleCommand $fakeJdkHome $fakeGradleUserHome 'fixture-success')
    Assert-True ($successResult.Count -eq 1) `
        'actual invocation helper leaked native output into its success pipeline'
    Assert-True ([string]$successResult[0].sha256 -cmatch '^[0-9a-f]{64}$') `
        'actual invocation helper did not return one digest object'
    $successLog = Join-Path $fakeInvocationRoot 'fixture-success.log'
    Assert-True ((Get-FileHash -LiteralPath $successLog -Algorithm SHA256).Hash.ToLowerInvariant() `
        -ceq [string]$successResult[0].sha256) `
        'actual invocation helper digest does not bind the written log'
    $successLogText = [IO.File]::ReadAllText($successLog)
    foreach ($line in @('fixture stdout line one','fixture stdout line two',
            'fixture stderr line three')) {
        Assert-True ($successLogText.IndexOf($line, [StringComparison]::Ordinal) -ge 0) `
            "actual invocation helper omitted a native log line: $line"
    }

    [IO.File]::WriteAllText($fakeGradleCommand, @'
@echo off
echo fixture failing line
exit /b 7
'@, [Text.UTF8Encoding]::new($false))
    $failureMessage = $null
    try {
        & $invokeFixtureScript $fixtureRoot $fakeInvocationRoot $fakeGradleCommand `
            $fakeJdkHome $fakeGradleUserHome 'fixture-failure' | Out-Null
    } catch { $failureMessage = $_.Exception.Message }
    Assert-True ($failureMessage -like '*SERVER_VERSION_MATRIX_GRADLE_FAILED|fixture-failure|7*') `
        'actual invocation helper accepted a nonzero native exit code'

    # Execute the target's actual manifest resolver against all eight reviewed identities using
    # the preparer's real layout: server assets include /version/build/, proxy assets do not.
    $assetFixtureRoot = Join-Path $fixtureRoot 'runtime-assets'
    [void][IO.Directory]::CreateDirectory($assetFixtureRoot)
    $assetDescriptors = @(
        [ordered]@{ project='paper'; version='1.21.11'; build='132'; channel='STABLE'; java_major=21 },
        [ordered]@{ project='paper'; version='26.1.2'; build='74'; channel='STABLE'; java_major=25 },
        [ordered]@{ project='paper'; version='26.2'; build='116'; channel='STABLE'; java_major=25 },
        [ordered]@{ project='folia'; version='1.21.11'; build='14'; channel='STABLE'; java_major=21 },
        [ordered]@{ project='folia'; version='26.1.2'; build='8'; channel='STABLE'; java_major=25 },
        [ordered]@{ project='folia'; version='26.2'; build='6'; channel='BETA'; java_major=25 },
        [ordered]@{ project='velocity'; version='3.5.1-615'; build='615'; channel='REVIEWED'; java_major=21 },
        [ordered]@{ project='bungeecord'; version='2085'; build='2085'; channel='REVIEWED'; java_major=21 }
    )
    $fixtureExpectedAssets = [Collections.Generic.List[object]]::new()
    $fixtureManifestAssets = [Collections.Generic.List[object]]::new()
    $expectedFixturePaths = [Collections.Generic.Dictionary[string,string]]::new(
        [StringComparer]::Ordinal)
    foreach ($descriptor in $assetDescriptors) {
        $isProxyFixture = $descriptor.project -in @('velocity','bungeecord')
        $relative = if ($isProxyFixture) {
            Join-Path ([string]$descriptor.project) `
                (Join-Path ([string]$descriptor.version) 'server.jar')
        } else {
            Join-Path ([string]$descriptor.project) (Join-Path ([string]$descriptor.version) `
                (Join-Path ([string]$descriptor.build) 'server.jar'))
        }
        $assetPath = Join-Path $assetFixtureRoot $relative
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $assetPath))
        [IO.File]::WriteAllText($assetPath,
            "$($descriptor.project)|$($descriptor.version)|$($descriptor.build)",
            [Text.UTF8Encoding]::new($false))
        $assetItem = Get-Item -LiteralPath $assetPath
        $sha256 = (Get-FileHash -LiteralPath $assetPath -Algorithm SHA256).Hash.ToLowerInvariant()
        $url = "https://fixture.invalid/$($descriptor.project)/$($descriptor.version)/server.jar"
        $expected = [pscustomobject][ordered]@{
            project = [string]$descriptor.project
            version = [string]$descriptor.version
            build = [string]$descriptor.build
            sha256 = $sha256
            size = [long]$assetItem.Length
            channel = [string]$descriptor.channel
            java_major = [int]$descriptor.java_major
            url = $url
        }
        [void]$fixtureExpectedAssets.Add($expected)
        $manifestEntry = [ordered]@{
            project = [string]$descriptor.project
            version = [string]$descriptor.version
            build = [string]$descriptor.build
            url = $url
            sha256 = $sha256
            size = [long]$assetItem.Length
            channel = [string]$descriptor.channel
            java_major = [int]$descriptor.java_major
        }
        if ($isProxyFixture) {
            $manifestEntry['target_versions'] = @('1.21.11','26.1.2','26.2')
        }
        [void]$fixtureManifestAssets.Add([pscustomobject]$manifestEntry)
        $identity = "$($descriptor.project):$($descriptor.version):$($descriptor.build)"
        $expectedFixturePaths.Add($identity, [IO.Path]::GetFullPath($assetPath))
    }
    $fixtureManifestPath = Join-Path $assetFixtureRoot 'manifest.json'
    $fixtureManifest = [pscustomobject][ordered]@{
        schema = 'MCACE_SERVER_VERSION_MATRIX_ASSETS_V1'
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        prepared_tree_status = 'DEFERRED'
        assets = $fixtureManifestAssets.ToArray()
    }
    [IO.File]::WriteAllText($fixtureManifestPath,
        ($fixtureManifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
    $assetFunctionNames = @(
        'ConvertTo-LowerHex','Get-BytesSha256','Assert-DirectLocalPath',
        'Get-StableFileDigest','Test-ExactProperties','Read-StableJson',
        'Get-ExpectedAsset','Get-AssetIdentity','Assert-AssetManifest')
    $assetFixtureSource = @"
param([string]`$FixtureAssetRoot, [string]`$FixtureManifestPath,
    [object[]]`$FixtureExpectedAssets, [string[]]`$FixtureTargetVersions)
Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'
`$assetRoot = `$FixtureAssetRoot
`$assetManifestPath = `$FixtureManifestPath
`$expectedAssets = `$FixtureExpectedAssets
`$targetVersions = `$FixtureTargetVersions
$($assetFunctionNames | ForEach-Object { Get-FunctionText $_ } | Out-String)
Assert-AssetManifest
"@
    $resolvedAssets = & ([ScriptBlock]::Create($assetFixtureSource)) `
        $assetFixtureRoot $fixtureManifestPath $fixtureExpectedAssets.ToArray() `
        ([string[]]@('1.21.11','26.1.2','26.2'))
    Assert-True (@($resolvedAssets.assets).Count -eq 8 -and
        $resolvedAssets.by_identity.Count -eq 8) `
        'actual asset manifest resolver did not bind all eight identities'
    foreach ($identity in $expectedFixturePaths.Keys) {
        Assert-True ($resolvedAssets.by_identity.ContainsKey($identity)) `
            "actual asset manifest resolver omitted identity: $identity"
        Assert-True ([IO.Path]::GetFullPath(
                [string]$resolvedAssets.by_identity[$identity].path) -ceq
            $expectedFixturePaths[$identity]) `
            "actual asset manifest resolver used the wrong layout: $identity"
    }
} finally {
    if (Test-Path -LiteralPath $fixtureRoot -PathType Container) {
        $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd(
            [char[]]@('\','/')) + [IO.Path]::DirectorySeparatorChar
        $fixtureFull = [IO.Path]::GetFullPath($fixtureRoot)
        if (-not $fixtureFull.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                -not (Split-Path -Leaf $fixtureFull).StartsWith(
                    'mcace-server-version-matrix-static-', [StringComparison]::Ordinal)) {
            throw 'SERVER_VERSION_MATRIX_STATIC_FIXTURE_CLEANUP_PATH_REJECTED'
        }
        [IO.Directory]::Delete($fixtureFull, $true)
    }
}

Write-Output 'SERVER_VERSION_PROCESS_MATRIX_STATIC_TEST_PASS'
exit 0
