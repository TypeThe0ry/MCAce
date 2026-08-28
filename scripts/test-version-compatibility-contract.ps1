[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$scriptPath = Join-Path $PSScriptRoot 'version-compatibility-contract-smoke.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

foreach ($token in @(
        "MCACE_VERSION_COMPATIBILITY_EXECUTE_PASS",
        "MCACE_VERSION_COMPATIBILITY_REPORTONLY_PASS",
        "MCACE_COMPATIBILITY_CONTRACT_MODE_REQUIRED",
        "MCACE_COMPATIBILITY_NESTED_JAR_CONTRACT_MISMATCH",
        "ExpectedSourceCommit",
        "ExpectedArtifactSourceCommit",
        "MCACE_COMPATIBILITY_SOURCE_COMMIT_MISMATCH",
        "MCACE_COMPATIBILITY_ARTIFACT_SOURCE_COMMIT_MISMATCH",
        "MCACE_COMPATIBILITY_MANIFEST_DUPLICATE_KEY",
        "MCACE_COMPATIBILITY_PROPERTY_SET_INVALID",
        "MCACE_COMPATIBILITY_SHA256SUMS_DUPLICATE_FILE",
        "MCACE_COMPATIBILITY_SHA256SUMS_FILE_SET_INVALID",
        "MCACE_COMPATIBILITY_TOP_LEVEL_ENTRY_SET_INVALID",
        "MCACE_COMPATIBILITY_REPARSE_POINT_REJECTED",
        "MCACE_COMPATIBILITY_ZIP_DUPLICATE_ENTRY",
        "MCACE_COMPATIBILITY_NESTED_JAR_ENTRY_SET_INVALID",
        "MCACE_COMPATIBILITY_REPORT_SOURCE_COMMIT_MISMATCH",
        "MCACE_COMPATIBILITY_REPORT_ARTIFACT_SOURCE_COMMIT_MISMATCH",
        "MCACE_COMPATIBILITY_REPORT_UNSUPPORTED_EXAMPLES_INVALID",
        "MCACE_COMPATIBILITY_REPORT_AGE_INVALID",
        "ConvertTo-ReportTimestamp",
        "MCACE_RELEASE_BUNDLE_V4",
        "artifact_source_commit",
        "'1.21.11'",
        "'26.1.2'",
        "'26.2'",
        "'1.21.1'",
        "'26.3'")) {
    if ($source.IndexOf($token, [StringComparison]::Ordinal) -lt 0) {
        throw "MCACE_VERSION_COMPATIBILITY_STATIC_TOKEN_MISSING|$token"
    }
}

if ($source -match "targetVersions\s*=.*1\.21\.1" -or
        $source -match "ValidateSet\([^)]*1\.21\.1") {
    throw 'MCACE_VERSION_COMPATIBILITY_LEGACY_TARGET_ACCEPTED'
}
if ($source -notmatch 'bundle_entry_count.*-ne 8' -or
        $source -notmatch 'unsupported_versions_are_fail_closed') {
    throw 'MCACE_VERSION_COMPATIBILITY_FAIL_CLOSED_ASSERTION_MISSING'
}

function Get-TestSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-TestArtifactKey([string]$Name) {
    return $Name.Substring(0, $Name.Length - 4).Replace('-', '_').Replace('.', '_')
}

function New-TestJar([string]$Path, [object]$Metadata, [string[]]$NestedEntries) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::Open($Path, [IO.Compression.ZipArchiveMode]::Create)
    try {
        $metadataEntry = $archive.CreateEntry('fabric.mod.json')
        $writer = [IO.StreamWriter]::new($metadataEntry.Open(), [Text.UTF8Encoding]::new($false))
        try { $writer.Write(($Metadata | ConvertTo-Json -Depth 10 -Compress)) }
        finally { $writer.Dispose() }
        foreach ($nested in $NestedEntries) {
            $entry = $archive.CreateEntry($nested)
            $stream = $entry.Open()
            try {
                $bytes = [Text.Encoding]::ASCII.GetBytes('fixture')
                $stream.Write($bytes, 0, $bytes.Length)
            }
            finally { $stream.Dispose() }
        }
    }
    finally { $archive.Dispose() }
}

function New-CompatibilityFixture {
    $container = Join-Path ([IO.Path]::GetTempPath()) ('mcace-compat-' + [Guid]::NewGuid().ToString('N'))
    $root = Join-Path $container 'bundle'
    [IO.Directory]::CreateDirectory($root) | Out-Null
    $sourceCommit = 'a' * 40
    $artifactCommit = 'b' * 40
    $version = '0.0.1'
    $definitions = @(
        [ordered]@{
            version='1.21.11'; loader='0.19.3'; api='0.141.6+1.21.11'; java=21
            nested=@(
                'META-INF/jars/mcace-client-common-0.0.1.jar',
                'META-INF/jars/mcace-core-0.0.1-client-safe.jar',
                'META-INF/jars/mcace-protocol-0.0.1.jar',
                'META-INF/jars/mcace-sdk-0.0.1.jar',
                'META-INF/jars/protobuf-java-4.32.1.jar'
            )
        },
        [ordered]@{
            version='26.1.2'; loader='0.19.3'; api='0.155.2+26.1.2'; java=25
            nested=@('META-INF/jars/protobuf-java-4.32.1.jar')
        },
        [ordered]@{
            version='26.2'; loader='0.19.3'; api='0.157.0+26.2'; java=25
            nested=@('META-INF/jars/protobuf-java-4.32.1.jar')
        }
    )
    $jarNames = @()
    foreach ($definition in $definitions) {
        $name = "mcace-client-fabric-$($definition.version).jar"
        $jarNames += $name
        $metadata = [ordered]@{
            schemaVersion = 1
            id = 'mcace'
            version = $version
            environment = 'client'
            entrypoints = [ordered]@{ client=@('com.ellan.mcace.fabric.MCAceFabricClient') }
            depends = [ordered]@{
                fabricloader=">=$($definition.loader)"
                minecraft=$definition.version
                'fabric-api'=$definition.api
                java=">=$($definition.java)"
            }
            custom = [ordered]@{
                'mcace:client_build_id'="fabric-$($definition.version)-$artifactCommit"
            }
            jars = @($definition.nested | ForEach-Object { [ordered]@{file=$_} })
        }
        New-TestJar (Join-Path $root $name) $metadata @($definition.nested)
    }
    foreach ($name in @('mcace-server-velocity.jar','mcace-server-bungeecord.jar','mcace-server-paper.jar')) {
        $jarNames += $name
        [IO.File]::WriteAllBytes((Join-Path $root $name), [Text.Encoding]::ASCII.GetBytes("fixture-$name"))
    }

    $manifest = [Collections.Generic.List[string]]::new()
    foreach ($line in @(
            'schema=MCACE_RELEASE_BUNDLE_V4',
            'bundle_profile=RELEASE',
            'release_identity=true',
            'deployable_count=6',
            'bundle_entry_count=8',
            "product_version=$version",
            "source_commit=$sourceCommit",
            "artifact_source_commit=$artifactCommit",
            'root_java_version=21.0.10',
            'root_java_specification_version=21',
            'root_gradle_version=9.6.1',
            'modern_java_version=25.0.4.1',
            'modern_java_specification_version=25',
            'modern_gradle_version=9.6.1')) {
        $manifest.Add($line)
    }
    foreach ($name in $jarNames) {
        $key = Get-TestArtifactKey $name
        $manifest.Add("artifact.$key.file=$name")
        $manifest.Add("artifact.$key.sha256=$(Get-TestSha256 (Join-Path $root $name))")
        if ($name.StartsWith('mcace-client-fabric-', [StringComparison]::Ordinal)) {
            $minecraftVersion = $name.Substring('mcace-client-fabric-'.Length)
            $minecraftVersion = $minecraftVersion.Substring(0, $minecraftVersion.Length - 4)
            $manifest.Add("artifact.$key.minecraft_version=$minecraftVersion")
            $manifest.Add("artifact.$key.client_build_id=fabric-$minecraftVersion-$artifactCommit")
        }
    }
    [IO.File]::WriteAllText(
        (Join-Path $root 'release-manifest.properties'),
        (($manifest -join "`n") + "`n"),
        [Text.UTF8Encoding]::new($false))
    $sums = @($jarNames | ForEach-Object { "$(Get-TestSha256 (Join-Path $root $_))  $_" })
    [IO.File]::WriteAllText(
        (Join-Path $root 'SHA256SUMS'),
        (($sums -join "`n") + "`n"),
        [Text.UTF8Encoding]::new($false))
    return [pscustomobject]@{
        container=$container; root=$root; report=(Join-Path $container 'report.json')
        source_commit=$sourceCommit; artifact_source_commit=$artifactCommit
    }
}

function Invoke-ExpectedFailure([scriptblock]$Action, [string]$Marker) {
    try {
        & $Action | Out-Null
        throw "MCACE_VERSION_COMPATIBILITY_EXPECTED_FAILURE_NOT_OBSERVED|$Marker"
    }
    catch {
        if ($_.Exception.Message -notlike "*$Marker*") { throw }
    }
}

$fixtures = [Collections.Generic.List[object]]::new()
$negativeCases = 0
try {
    $valid = New-CompatibilityFixture; $fixtures.Add($valid)
    $executeOutput = @(& $scriptPath -Execute -BundleRoot $valid.root -ReportPath $valid.report `
        -ExpectedSourceCommit $valid.source_commit `
        -ExpectedArtifactSourceCommit $valid.artifact_source_commit)
    if ('MCACE_VERSION_COMPATIBILITY_EXECUTE_PASS' -notin $executeOutput) {
        throw 'MCACE_VERSION_COMPATIBILITY_EXECUTE_FIXTURE_FAILED'
    }
    $rawReport = [IO.File]::ReadAllText($valid.report, [Text.Encoding]::UTF8)
    $generatedAtMatch = [regex]::Match(
        $rawReport,
        '"generated_at"\s*:\s*"(?<value>[^"\\]+)"',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $generatedAtMatch.Success -or
            $generatedAtMatch.Groups['value'].Value -notmatch 'Z$') {
        throw 'MCACE_VERSION_COMPATIBILITY_GENERATED_AT_NOT_UTC_Z'
    }
    $reportHash = Get-TestSha256 $valid.report
    $reportOnlyOutput = @(& $scriptPath -ReportOnly -ReportPath $valid.report `
        -ExpectedReportSha256 $reportHash `
        -ExpectedSourceCommit $valid.source_commit `
        -ExpectedArtifactSourceCommit $valid.artifact_source_commit `
        -MaximumReportAgeMinutes 60)
    if ('MCACE_VERSION_COMPATIBILITY_REPORTONLY_PASS' -notin $reportOnlyOutput) {
        throw 'MCACE_VERSION_COMPATIBILITY_REPORTONLY_FRESH_Z_FIXTURE_FAILED'
    }

    $expiredReport = Join-Path $valid.container 'report-expired.json'
    $expiredTimestamp = '2000-01-01T00:00:00.0000000Z'
    $timestampStart = $generatedAtMatch.Groups['value'].Index
    $timestampLength = $generatedAtMatch.Groups['value'].Length
    $expiredRaw = $rawReport.Substring(0, $timestampStart) +
        $expiredTimestamp +
        $rawReport.Substring($timestampStart + $timestampLength)
    [IO.File]::WriteAllText($expiredReport, $expiredRaw, [Text.UTF8Encoding]::new($false))
    $expiredHash = Get-TestSha256 $expiredReport
    Invoke-ExpectedFailure {
        & $scriptPath -ReportOnly -ReportPath $expiredReport `
            -ExpectedReportSha256 $expiredHash `
            -ExpectedSourceCommit $valid.source_commit `
            -ExpectedArtifactSourceCommit $valid.artifact_source_commit `
            -MaximumReportAgeMinutes 60
    } 'MCACE_COMPATIBILITY_REPORT_AGE_INVALID'
    $negativeCases++

    # Keep a default-age check as a regression for callers that rely on the
    # script's documented one-day ReportOnly window as well.
    $defaultAgeOutput = @(& $scriptPath -ReportOnly -ReportPath $valid.report `
        -ExpectedReportSha256 $reportHash `
        -ExpectedSourceCommit $valid.source_commit `
        -ExpectedArtifactSourceCommit $valid.artifact_source_commit)
    if ('MCACE_VERSION_COMPATIBILITY_REPORTONLY_PASS' -notin $defaultAgeOutput) {
        throw 'MCACE_VERSION_COMPATIBILITY_REPORTONLY_DEFAULT_AGE_FIXTURE_FAILED'
    }

    $duplicateManifest = New-CompatibilityFixture; $fixtures.Add($duplicateManifest)
    [IO.File]::AppendAllText(
        (Join-Path $duplicateManifest.root 'release-manifest.properties'),
        "source_commit=$($duplicateManifest.source_commit)`n",
        [Text.UTF8Encoding]::new($false))
    Invoke-ExpectedFailure {
        & $scriptPath -Execute -BundleRoot $duplicateManifest.root -ReportPath $duplicateManifest.report
    } 'MCACE_COMPATIBILITY_MANIFEST_DUPLICATE_KEY'
    $negativeCases++

    $duplicateSum = New-CompatibilityFixture; $fixtures.Add($duplicateSum)
    $sumPath = Join-Path $duplicateSum.root 'SHA256SUMS'
    $sumLines = @(Get-Content -LiteralPath $sumPath)
    $sumLines[$sumLines.Count - 1] = $sumLines[0]
    [IO.File]::WriteAllText($sumPath, (($sumLines -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))
    Invoke-ExpectedFailure {
        & $scriptPath -Execute -BundleRoot $duplicateSum.root -ReportPath $duplicateSum.report
    } 'MCACE_COMPATIBILITY_SHA256SUMS_DUPLICATE_FILE'
    $negativeCases++

    $extraDirectory = New-CompatibilityFixture; $fixtures.Add($extraDirectory)
    [IO.Directory]::CreateDirectory((Join-Path $extraDirectory.root 'unexpected')) | Out-Null
    Invoke-ExpectedFailure {
        & $scriptPath -Execute -BundleRoot $extraDirectory.root -ReportPath $extraDirectory.report
    } 'MCACE_COMPATIBILITY_TOP_LEVEL_ENTRY_SET_INVALID'
    $negativeCases++

    $missingNested = New-CompatibilityFixture; $fixtures.Add($missingNested)
    $jarPath = Join-Path $missingNested.root 'mcace-client-fabric-26.2.jar'
    $archive = [IO.Compression.ZipFile]::Open($jarPath, [IO.Compression.ZipArchiveMode]::Update)
    try {
        $nestedEntry = $archive.GetEntry('META-INF/jars/protobuf-java-4.32.1.jar')
        $nestedEntry.Delete()
    }
    finally { $archive.Dispose() }
    $jarKey = Get-TestArtifactKey 'mcace-client-fabric-26.2.jar'
    $manifestPath = Join-Path $missingNested.root 'release-manifest.properties'
    $manifestText = [IO.File]::ReadAllText($manifestPath)
    $oldHash = [regex]::Match($manifestText, "artifact\.$jarKey\.sha256=([0-9a-f]{64})").Groups[1].Value
    $newHash = Get-TestSha256 $jarPath
    $manifestText = $manifestText.Replace($oldHash, $newHash)
    [IO.File]::WriteAllText($manifestPath, $manifestText, [Text.UTF8Encoding]::new($false))
    $sumPath = Join-Path $missingNested.root 'SHA256SUMS'
    $sumText = [IO.File]::ReadAllText($sumPath).Replace($oldHash, $newHash)
    [IO.File]::WriteAllText($sumPath, $sumText, [Text.UTF8Encoding]::new($false))
    Invoke-ExpectedFailure {
        & $scriptPath -Execute -BundleRoot $missingNested.root -ReportPath $missingNested.report
    } 'MCACE_COMPATIBILITY_NESTED_JAR_ENTRY_SET_INVALID'
    $negativeCases++

    $reportMismatch = New-CompatibilityFixture; $fixtures.Add($reportMismatch)
    & $scriptPath -Execute -BundleRoot $reportMismatch.root -ReportPath $reportMismatch.report | Out-Null
    Invoke-ExpectedFailure {
        & $scriptPath -ReportOnly -ReportPath $reportMismatch.report `
            -ExpectedSourceCommit ('c' * 40) `
            -ExpectedArtifactSourceCommit $reportMismatch.artifact_source_commit
    } 'MCACE_COMPATIBILITY_REPORT_SOURCE_COMMIT_MISMATCH'
    $negativeCases++
}
finally {
    foreach ($fixture in $fixtures) {
        if ($null -ne $fixture -and (Test-Path -LiteralPath $fixture.container)) {
            Remove-Item -LiteralPath $fixture.container -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Write-Output "MCACE_VERSION_COMPATIBILITY_STATIC_PASS|dynamic=true|negative_cases=$negativeCases"
