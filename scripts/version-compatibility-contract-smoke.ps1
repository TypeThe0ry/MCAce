[CmdletBinding()]
param(
    [switch]$Execute,
    [switch]$ReportOnly,
    [string]$BundleRoot = (Join-Path $PSScriptRoot '..\build\release-bundle'),
    [string]$ReportPath = (Join-Path $PSScriptRoot '..\build\compatibility-contract\report.json'),
    [string]$ExpectedReportSha256,
    [ValidateRange(1, 10080)]
    [int]$MaximumReportAgeMinutes = 1440
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($Execute -eq $ReportOnly) {
    throw 'MCACE_COMPATIBILITY_CONTRACT_MODE_REQUIRED|select exactly one of -Execute or -ReportOnly'
}

$schema = 'MCACE_VERSION_COMPATIBILITY_CONTRACT_V1'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))

$targets = @(
    [ordered]@{
        minecraft_version = '1.21.11'
        protocol = 774
        java_major = 21
        loader = '0.19.3'
        fabric_api = '0.141.6+1.21.11'
        artifact = 'mcace-client-fabric-1.21.11.jar'
        artifact_mode = 'FINAL_REMAP_JAR'
        expected_nested = @(
            'META-INF/jars/mcace-client-common-{VERSION}.jar'
            'META-INF/jars/mcace-core-{VERSION}.jar'
            'META-INF/jars/mcace-protocol-{VERSION}.jar'
            'META-INF/jars/mcace-sdk-{VERSION}.jar'
            'META-INF/jars/protobuf-java-4.32.1.jar'
        )
    }
    [ordered]@{
        minecraft_version = '26.1.2'
        protocol = 775
        java_major = 25
        loader = '0.19.3'
        fabric_api = '0.155.2+26.1.2'
        artifact = 'mcace-client-fabric-26.1.2.jar'
        artifact_mode = 'FINAL_NAMED_JAR'
        expected_nested = @('META-INF/jars/protobuf-java-4.32.1.jar')
    }
    [ordered]@{
        minecraft_version = '26.2'
        protocol = 776
        java_major = 25
        loader = '0.19.3'
        fabric_api = '0.157.0+26.2'
        artifact = 'mcace-client-fabric-26.2.jar'
        artifact_mode = 'FINAL_NAMED_JAR'
        expected_nested = @('META-INF/jars/protobuf-java-4.32.1.jar')
    }
)

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-Sha256([string]$Path, [string]$Expected, [string]$Label) {
    $actual = Get-Sha256 $Path
    if ($actual -cne $Expected.ToLowerInvariant()) {
        throw "MCACE_COMPATIBILITY_SHA256_MISMATCH|$Label|expected=$Expected|actual=$actual"
    }
    return $actual
}

function Read-Manifest([string]$Path) {
    $values = [ordered]@{}
    foreach ($line in Get-Content -LiteralPath $Path) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        $separator = $line.IndexOf('=')
        if ($separator -lt 1) { throw "MCACE_COMPATIBILITY_MANIFEST_LINE_INVALID|$line" }
        $values[$line.Substring(0, $separator)] = $line.Substring($separator + 1)
    }
    return [pscustomobject]$values
}

function Read-ZipJson([string]$ZipPath, [string]$EntryName) {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ZipPath)
    try {
        $entry = $archive.GetEntry($EntryName)
        if ($null -eq $entry) { throw "MCACE_COMPATIBILITY_ZIP_ENTRY_MISSING|$EntryName" }
        $reader = [IO.StreamReader]::new($entry.Open())
        try { return ($reader.ReadToEnd() | ConvertFrom-Json) }
        finally { $reader.Dispose() }
    }
    finally { $archive.Dispose() }
}

function Assert-TargetArtifact([object]$Target, [object]$Manifest, [string]$Root) {
    $artifactPath = Join-Path $Root $Target.artifact
    if (-not (Test-Path -LiteralPath $artifactPath -PathType Leaf)) {
        throw "MCACE_COMPATIBILITY_ARTIFACT_MISSING|$($Target.artifact)"
    }
    $propertyPrefix = 'artifact.mcace_client_fabric_' + ($Target.minecraft_version -replace '\.', '_')
    $manifestFile = [string]$Manifest."$propertyPrefix.file"
    $manifestSha = [string]$Manifest."$propertyPrefix.sha256"
    if ($manifestFile -cne $Target.artifact) {
        throw "MCACE_COMPATIBILITY_MANIFEST_ARTIFACT_MISMATCH|$($Target.minecraft_version)"
    }
    $artifactSha = Assert-Sha256 $artifactPath $manifestSha $Target.artifact
    $metadata = Read-ZipJson $artifactPath 'fabric.mod.json'
    if ([string]$metadata.depends.minecraft -cne $Target.minecraft_version -or
            [string]$metadata.depends.'fabric-api' -cne $Target.fabric_api -or
            [string]$metadata.depends.fabricloader -cne ">=$($Target.loader)" -or
            [string]$metadata.custom.'mcace:client_build_id' -cne "fabric-$($Target.minecraft_version)-$($Manifest.source_commit)") {
        throw "MCACE_COMPATIBILITY_METADATA_MISMATCH|$($Target.minecraft_version)"
    }
    $javaRequirement = [string]$metadata.depends.java
    if ($javaRequirement -cne ">=$($Target.java_major)") {
        throw "MCACE_COMPATIBILITY_JAVA_REQUIREMENT_MISMATCH|$($Target.minecraft_version)"
    }
    $productVersion = [string]$Manifest.product_version
    if ($productVersion -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$') {
        throw 'MCACE_COMPATIBILITY_PRODUCT_VERSION_INVALID'
    }
    $expectedNested = @($Target.expected_nested | ForEach-Object {
        $_ -replace '\{VERSION\}', $productVersion
    })
    $nested = @($metadata.jars | ForEach-Object { [string]$_.file })
    if ((@($nested) -join '|') -cne (@($expectedNested) -join '|')) {
        throw "MCACE_COMPATIBILITY_NESTED_JAR_CONTRACT_MISMATCH|$($Target.minecraft_version)"
    }
    [ordered]@{
        minecraft_version = $Target.minecraft_version
        protocol = [int]$Target.protocol
        java_major = [int]$Target.java_major
        artifact_mode = $Target.artifact_mode
        artifact = $Target.artifact
        sha256 = $artifactSha
        nested_jar_count = @($nested).Count
        passed = $true
    }
}

function Invoke-Execute {
    $root = [IO.Path]::GetFullPath($BundleRoot)
    $manifestPath = Join-Path $root 'release-manifest.properties'
    $sumsPath = Join-Path $root 'SHA256SUMS'
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf) -or
            -not (Test-Path -LiteralPath $sumsPath -PathType Leaf)) {
        throw 'MCACE_COMPATIBILITY_RELEASE_BUNDLE_REQUIRED|release-manifest.properties and SHA256SUMS are required'
    }
    $manifest = Read-Manifest $manifestPath
    if ([string]$manifest.schema -cne 'MCACE_RELEASE_BUNDLE_V3' -or
            [string]$manifest.bundle_profile -cne 'RELEASE' -or
            [string]$manifest.release_identity -cne 'true' -or
            [string]$manifest.product_version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$' -or
            [int]$manifest.deployable_count -ne 6 -or
            [int]$manifest.bundle_entry_count -ne 8) {
        throw 'MCACE_COMPATIBILITY_RELEASE_MANIFEST_CONTRACT_INVALID'
    }
    if ([string]$manifest.source_commit -notmatch '^[0-9a-f]{40}$') {
        throw 'MCACE_COMPATIBILITY_SOURCE_COMMIT_INVALID'
    }
    $jarNames = @($targets | ForEach-Object { $_.artifact }) + @('mcace-server-velocity.jar', 'mcace-server-bungeecord.jar', 'mcace-server-paper.jar')
    $sumLines = @(Get-Content -LiteralPath $sumsPath)
    if (@($sumLines).Count -ne 6) { throw 'MCACE_COMPATIBILITY_SHA256SUMS_COUNT_INVALID' }
    foreach ($line in $sumLines) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -ne 2 -or $parts[1] -notin $jarNames) { throw "MCACE_COMPATIBILITY_SHA256SUMS_ENTRY_INVALID|$line" }
        Assert-Sha256 (Join-Path $root $parts[1]) $parts[0] $parts[1] | Out-Null
    }
    $results = @($targets | ForEach-Object { Assert-TargetArtifact $_ $manifest $root })
    $topLevel = @(Get-ChildItem -LiteralPath $root -File | Select-Object -ExpandProperty Name | Sort-Object)
    $expectedTopLevel = @($jarNames + 'release-manifest.properties' + 'SHA256SUMS' | Sort-Object)
    if ((@($topLevel) -join '|') -cne (@($expectedTopLevel) -join '|')) {
        throw 'MCACE_COMPATIBILITY_TOP_LEVEL_ENTRY_SET_INVALID'
    }
    $report = [ordered]@{
        schema = $schema
        generated_at = (Get-Date).ToUniversalTime().ToString('o')
        source_commit = [string]$manifest.source_commit
        target_count = @($results).Count
        exact_bundle_entry_count = [int]$manifest.bundle_entry_count
        unsupported_versions_are_fail_closed = $true
        unsupported_examples = @('1.21.1', '1.21.10', '26.1', '26.3')
        targets = $results
        passed = $true
    }
    $outRoot = Split-Path -Parent ([IO.Path]::GetFullPath($ReportPath))
    [IO.Directory]::CreateDirectory($outRoot) | Out-Null
    $staging = Join-Path $outRoot ('.staging-' + [Guid]::NewGuid().ToString('N'))
    $stagingFile = Join-Path $staging 'report.json'
    [IO.Directory]::CreateDirectory($staging) | Out-Null
    try {
        $json = $report | ConvertTo-Json -Depth 8
        [IO.File]::WriteAllText($stagingFile, $json, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $stagingFile -Destination ([IO.Path]::GetFullPath($ReportPath)) -Force
    }
    finally { if (Test-Path -LiteralPath $staging) { Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue } }
    Write-Output 'MCACE_VERSION_COMPATIBILITY_EXECUTE_PASS'
}

function Invoke-ReportOnly {
    if (-not (Test-Path -LiteralPath $ReportPath -PathType Leaf)) { throw 'MCACE_COMPATIBILITY_REPORT_MISSING' }
    if ($ExpectedReportSha256) { Assert-Sha256 $ReportPath $ExpectedReportSha256 'report' | Out-Null }
    $report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
    if ([string]$report.schema -cne $schema -or
            $report.passed -ne $true -or
            [int]$report.target_count -ne 3 -or
            [int]$report.exact_bundle_entry_count -ne 8 -or
            $report.unsupported_versions_are_fail_closed -ne $true -or
            @($report.targets).Count -ne 3 -or
            @($report.targets | Where-Object { $_.passed -ne $true }).Count -ne 0) {
        throw 'MCACE_COMPATIBILITY_REPORT_CONTRACT_INVALID'
    }
    $generated = [DateTimeOffset]::Parse([string]$report.generated_at)
    if ($generated -lt [DateTimeOffset]::UtcNow.AddMinutes(-$MaximumReportAgeMinutes) -or $generated -gt [DateTimeOffset]::UtcNow.AddMinutes(1)) {
        throw 'MCACE_COMPATIBILITY_REPORT_AGE_INVALID'
    }
    Write-Output 'MCACE_VERSION_COMPATIBILITY_REPORTONLY_PASS'
}

if ($Execute) { Invoke-Execute }
else { Invoke-ReportOnly }
