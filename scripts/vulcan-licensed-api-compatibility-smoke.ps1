[CmdletBinding()]
param(
    [string]$VulcanJar = '',
    [switch]$ReportOnly,
    [string]$ArtifactSha256 = '',
    [ValidateRange(1, 1440)]
    [int]$MaximumReportAgeMinutes = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runsRoot = Join-Path $repoRoot 'build/vulcan-compatibility/runs'
$test = 'com.ellan.mcace.paper.behavior.LicensedVulcanApiCompatibilityGateTest.validatesExplicitlySuppliedLicensedArtifactWithoutCopyingIt'
$bindingSchema = 'VULCAN_LICENSED_API_COMPATIBILITY_BINDING_V1'
function Get-GateReportPropertyNames {
    return @(
    'schema',
    'generated_at',
    'failure_stage',
    'artifact_sha256',
    'artifact_size',
    'plugin_name',
    'plugin_version',
    'event_type',
    'player_accessor',
    'check_accessor',
    'check_name_accessor',
    'stable_check_accessor',
    'event_violation_accessor',
    'check_violation_accessor',
    'artifact_path_recorded',
    'artifact_copied_or_redistributed',
    'paper_process_coverage',
    'licensed_plugin_enablement_coverage',
    'real_behavior_event_delivery_coverage',
    'limitations',
    'passed'
    )
}
function Get-BindingPropertyNames {
    return @(
    'schema',
    'generated_at',
    'source_mode',
    'run_id',
    'report_name',
    'report_generated_at',
    'report_sha256',
    'artifact_sha256',
    'artifact_size',
    'artifact_path_recorded',
    'source_manifest_sha256',
    'source_file_count',
    'gradle_version',
    'gradle_distribution_sha256',
    'gradle_command_sha256',
    'gradle_launcher_sha256',
    'gradle_core_sha256',
    'gradle_installation_manifest_sha256',
    'gradle_installation_file_count',
    'gradle_installation_directory_count',
    'java_executable_sha256',
    'java_file_version',
    'java_major',
    'gradle_task',
    'test_selector',
    'gradle_offline'
    )
}
$wrapperPropertiesPath = Join-Path $repoRoot 'gradle/wrapper/gradle-wrapper.properties'
$gradlePropertiesPath = Join-Path $repoRoot 'gradle.properties'

function ConvertTo-RepoRelativePath {
    param([Parameter(Mandatory)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootPrefix = $repoRoot.TrimEnd([char[]]@('\', '/')) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "VULCAN_COMPATIBILITY_REPORT_PATH_INVALID: path escapes the repository root"
    }
    return $fullPath.Substring($rootPrefix.Length).Replace('\', '/')
}

function Get-StreamSha256 {
    param([Parameter(Mandatory)][System.IO.Stream]$Stream)

    if (-not $Stream.CanRead -or -not $Stream.CanSeek) {
        throw 'VULCAN_LICENSED_ARTIFACT_UNREADABLE: a readable seekable file handle is required'
    }
    $originalPosition = $Stream.Position
    $digest = [System.Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0L
        $encoded = $digest.ComputeHash($Stream)
        return [System.BitConverter]::ToString($encoded).Replace('-', '').ToLowerInvariant()
    } finally {
        $Stream.Position = $originalPosition
        $digest.Dispose()
    }
}

function Get-PathSha256 {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        return Get-StreamSha256 -Stream $stream
    } finally {
        $stream.Dispose()
    }
}

function Open-LockedTextEvidence {
    param([Parameter(Mandatory)][string]$Path)

    $stream = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $size = $stream.Length
        $sha256 = Get-StreamSha256 -Stream $stream
        $stream.Position = 0L
        $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
        $reader = [System.IO.StreamReader]::new($stream, $strictUtf8, $true, 4096, $true)
        try {
            $raw = $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
        return [pscustomobject][ordered]@{
            stream = $stream
            size = $size
            sha256 = $sha256
            raw = $raw
        }
    } catch {
        $stream.Dispose()
        throw
    }
}

function Assert-LockedTextEvidenceUnchanged {
    param([Parameter(Mandatory)]$Evidence)

    if ($Evidence.stream.Length -ne $Evidence.size `
            -or (Get-StreamSha256 -Stream $Evidence.stream) -ne $Evidence.sha256) {
        throw 'VULCAN_LICENSED_API_COMPATIBILITY_EVIDENCE_CHANGED_DURING_VALIDATION'
    }
}

function ConvertTo-ArtifactSha256 {
    param(
        [string]$Value,
        [Parameter(Mandatory)][string]$MissingError
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw $MissingError
    }
    $normalized = $Value.Trim().ToLowerInvariant()
    if ($normalized -notmatch '^[0-9a-f]{64}$') {
        throw 'VULCAN_LICENSED_ARTIFACT_SHA256_INVALID: expected 64 hexadecimal characters'
    }
    return $normalized
}

function Test-JsonInteger {
    param($Value)

    return $Value -is [int] -or $Value -is [long]
}

function Test-JsonString {
    param($Value)

    return $Value -is [string]
}

function Test-JsonTimestampScalar {
    param($Value)

    return $Value -is [string] -or $Value -is [DateTime] -or $Value -is [DateTimeOffset]
}

function Test-JsonExactProperties {
    param(
        $Value,
        [Parameter(Mandatory)][string[]]$Expected
    )

    if ($null -eq $Value -or $Value -is [System.Array] `
            -or $Value -is [string] -or $Value -is [ValueType]) {
        return $false
    }
    $actual = @($Value.PSObject.Properties | ForEach-Object Name)
    if ($actual.Count -ne $Expected.Count) {
        return $false
    }
    foreach ($name in $Expected) {
        if ($actual -cnotcontains $name) {
            return $false
        }
    }
    return $true
}

function Test-JsonExactTopLevelPropertyNames {
    param(
        [Parameter(Mandatory)][string]$RawJson,
        [Parameter(Mandatory)][string[]]$Expected
    )

    $names = New-Object 'System.Collections.Generic.List[string]'
    $braceDepth = 0
    $inString = $false
    $escaped = $false
    $stringStart = -1
    for ($index = 0; $index -lt $RawJson.Length; $index++) {
        $character = $RawJson[$index]
        if ($inString) {
            if ($escaped) {
                $escaped = $false
                continue
            }
            if ($character -eq '\') {
                $escaped = $true
                continue
            }
            if ($character -ne '"') {
                continue
            }
            $inString = $false
            if ($braceDepth -ne 1) {
                continue
            }
            $after = $index + 1
            while ($after -lt $RawJson.Length -and [char]::IsWhiteSpace($RawJson[$after])) {
                $after++
            }
            if ($after -lt $RawJson.Length -and $RawJson[$after] -eq ':') {
                $names.Add($RawJson.Substring($stringStart, $index - $stringStart))
            }
            continue
        }
        if ($character -eq '"') {
            $inString = $true
            $stringStart = $index + 1
        } elseif ($character -eq '{') {
            $braceDepth++
        } elseif ($character -eq '}') {
            $braceDepth--
            if ($braceDepth -lt 0) {
                return $false
            }
        }
    }
    if ($inString -or $braceDepth -ne 0 -or $names.Count -ne $Expected.Count) {
        return $false
    }
    foreach ($name in $Expected) {
        if (@($names | Where-Object { $_ -ceq $name }).Count -ne 1) {
            return $false
        }
    }
    return $true
}

function Get-DirectLocalItem {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$MissingError,
        [switch]$RequireDirectory,
        [switch]$RequireLeaf
    )

    $resolved = [System.IO.Path]::GetFullPath($Path)
    if ($resolved.StartsWith('\\', [System.StringComparison]::Ordinal) `
            -or $resolved.StartsWith('//', [System.StringComparison]::Ordinal)) {
        throw 'VULCAN_LICENSED_ARTIFACT_NETWORK_PATH_REJECTED: UNC and device paths are not accepted'
    }
    $root = [System.IO.Path]::GetPathRoot($resolved)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw 'VULCAN_LICENSED_ARTIFACT_NETWORK_PATH_REJECTED: a rooted local filesystem path is required'
    }
    try {
        $drive = [System.IO.DriveInfo]::new($root)
    } catch {
        throw 'VULCAN_LICENSED_ARTIFACT_NETWORK_PATH_REJECTED: the local drive identity could not be established'
    }
    if ($drive.DriveType -eq [System.IO.DriveType]::Network) {
        throw 'VULCAN_LICENSED_ARTIFACT_NETWORK_PATH_REJECTED: mapped network drives are not accepted'
    }
    if ($drive.DriveType -notin @(
            [System.IO.DriveType]::Fixed,
            [System.IO.DriveType]::Removable,
            [System.IO.DriveType]::Ram)) {
        throw 'VULCAN_LICENSED_ARTIFACT_NETWORK_PATH_REJECTED: unsupported non-local drive type'
    }

    try {
        $currentItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    } catch {
        throw $MissingError
    }
    if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'VULCAN_LICENSED_ARTIFACT_INVALID: path roots implemented by links are not accepted'
    }
    $relative = $resolved.Substring($root.Length)
    $segments = @($relative.Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries))
    $current = $root
    foreach ($segment in $segments) {
        $current = Join-Path $current $segment
        try {
            $currentItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        } catch {
            throw $MissingError
        }
        if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'VULCAN_LICENSED_ARTIFACT_INVALID: links and junctions are not accepted'
        }
    }
    if ($RequireDirectory -and -not $currentItem.PSIsContainer) {
        throw $MissingError
    }
    if ($RequireLeaf -and $currentItem.PSIsContainer) {
        throw $MissingError
    }
    return $currentItem
}

function Get-DirectLocalTreeManifest {
    param([Parameter(Mandatory)][string]$RootPath)

    $rootItem = Get-DirectLocalItem `
        -Path $RootPath `
        -RequireDirectory `
        -MissingError 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_REQUIRED'
    $rootFullName = $rootItem.FullName.TrimEnd([char[]]@('\', '/'))
    $rootPrefix = $rootFullName + [System.IO.Path]::DirectorySeparatorChar
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($rootFullName)
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $fileCount = 0
    $directoryCount = 0
    while ($pending.Count -gt 0) {
        $directoryPath = $pending.Pop()
        $directoryItem = Get-DirectLocalItem `
            -Path $directoryPath `
            -RequireDirectory `
            -MissingError 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_REQUIRED'
        $relativeDirectory = if ($directoryItem.FullName.Equals(
                $rootFullName,
                [System.StringComparison]::OrdinalIgnoreCase)) {
            ''
        } else {
            $directoryItem.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        }
        $directoryName = [Convert]::ToBase64String(
            [System.Text.Encoding]::UTF8.GetBytes($relativeDirectory))
        $lines.Add("D`t$directoryName")
        $directoryCount++

        foreach ($child in @(Get-ChildItem -LiteralPath $directoryItem.FullName -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_INVALID: links and junctions are not accepted'
            }
            $verifiedChild = Get-DirectLocalItem `
                -Path $child.FullName `
                -MissingError 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_REQUIRED'
            if ($verifiedChild.PSIsContainer) {
                $pending.Push($verifiedChild.FullName)
                continue
            }
            $relativeFile = $verifiedChild.FullName.Substring($rootPrefix.Length).Replace('\', '/')
            $fileName = [Convert]::ToBase64String(
                [System.Text.Encoding]::UTF8.GetBytes($relativeFile))
            $stream = [System.IO.File]::Open(
                $verifiedChild.FullName,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read)
            try {
                $length = $stream.Length
                $sha256 = Get-StreamSha256 -Stream $stream
                if ($stream.Length -ne $length) {
                    throw 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_CHANGED_DURING_BINDING'
                }
            } finally {
                $stream.Dispose()
            }
            $lines.Add("F`t$fileName`t$length`t$sha256")
            $fileCount++
        }
    }
    $orderedLines = $lines.ToArray()
    [System.Array]::Sort($orderedLines, [System.StringComparer]::Ordinal)
    $encoded = [System.Text.Encoding]::UTF8.GetBytes(($orderedLines -join "`n") + "`n")
    $digest = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [pscustomobject][ordered]@{
            sha256 = [System.BitConverter]::ToString($digest.ComputeHash($encoded)).Replace('-', '').ToLowerInvariant()
            file_count = $fileCount
            directory_count = $directoryCount
        }
    } finally {
        $digest.Dispose()
    }
}

function Resolve-DirectLocalArtifact {
    param([Parameter(Mandatory)][string]$Path)

    $resolved = [System.IO.Path]::GetFullPath($Path)
    $item = Get-DirectLocalItem `
        -Path $resolved `
        -RequireLeaf `
        -MissingError 'VULCAN_LICENSED_ARTIFACT_REQUIRED: the supplied local JAR does not exist'
    if (-not $item.Extension.Equals('.jar', [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'VULCAN_LICENSED_ARTIFACT_INVALID: use a direct local .jar file'
    }
    return $resolved
}

function Initialize-DirectLocalRunsRoot {
    $null = Get-DirectLocalItem `
        -Path $repoRoot `
        -RequireDirectory `
        -MissingError 'VULCAN_COMPATIBILITY_OUTPUT_ROOT_INVALID'
    $current = $repoRoot
    foreach ($segment in @('build', 'vulcan-compatibility', 'runs')) {
        $current = Join-Path $current $segment
        try {
            $null = Get-DirectLocalItem `
                -Path $current `
                -RequireDirectory `
                -MissingError 'VULCAN_COMPATIBILITY_OUTPUT_DIRECTORY_MISSING'
        } catch {
            if ($_.Exception.Message -ne 'VULCAN_COMPATIBILITY_OUTPUT_DIRECTORY_MISSING') {
                throw
            }
            New-Item -ItemType Directory -Path $current -ErrorAction Stop | Out-Null
            $null = Get-DirectLocalItem `
                -Path $current `
                -RequireDirectory `
                -MissingError 'VULCAN_COMPATIBILITY_OUTPUT_ROOT_INVALID'
        }
    }
}

function Get-WrapperProperty {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string[]]$Lines
    )

    $prefix = $Name + '='
    $matches = @($Lines | Where-Object { $_.StartsWith($prefix, [System.StringComparison]::Ordinal) })
    if ($matches.Count -ne 1) {
        throw "VULCAN_OFFLINE_GRADLE_CONFIGURATION_INVALID: $Name"
    }
    return $matches[0].Substring($prefix.Length).Replace('\:', ':').Trim()
}

function Assert-CleanGradleEnvironment {
    foreach ($name in @('_JAVA_OPTIONS', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'GRADLE_OPTS', 'JAVA_OPTS')) {
        $value = [System.Environment]::GetEnvironmentVariable($name, 'Process')
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            throw "VULCAN_GRADLE_ENVIRONMENT_INPUT_REJECTED: $name"
        }
    }
    foreach ($entry in [System.Environment]::GetEnvironmentVariables('Process').GetEnumerator()) {
        $name = [string]$entry.Key
        if ($name.StartsWith('ORG_GRADLE_PROJECT_', [System.StringComparison]::OrdinalIgnoreCase) `
                -and -not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            throw "VULCAN_GRADLE_ENVIRONMENT_INPUT_REJECTED: $name"
        }
    }
}

function Assert-NoProjectGradleJvmOverride {
    $propertiesItem = Get-DirectLocalItem `
        -Path $gradlePropertiesPath `
        -RequireLeaf `
        -MissingError 'VULCAN_COMPATIBILITY_SOURCE_BINDING_UNAVAILABLE'
    foreach ($line in @(Get-Content -LiteralPath $propertiesItem.FullName)) {
        if ($line -match '^\s*org\.gradle\.java\.home\s*=') {
            throw 'VULCAN_GRADLE_JAVA_OVERRIDE_REJECTED: org.gradle.java.home'
        }
    }
    $missing = 'VULCAN_OPTIONAL_GRADLE_DAEMON_CRITERIA_MISSING'
    try {
        $null = Get-DirectLocalItem `
            -Path (Join-Path $repoRoot 'gradle/gradle-daemon-jvm.properties') `
            -RequireLeaf `
            -MissingError $missing
        throw 'VULCAN_GRADLE_JAVA_OVERRIDE_REJECTED: gradle-daemon-jvm.properties'
    } catch {
        if ($_.Exception.Message -ne $missing) {
            throw
        }
    }
}

function Assert-NoUserGradleInputs {
    param([Parameter(Mandatory)][string]$GradleUserHome)

    $userHomeItem = Get-DirectLocalItem `
        -Path $GradleUserHome `
        -RequireDirectory `
        -MissingError 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_REQUIRED'
    $missing = 'VULCAN_OPTIONAL_USER_GRADLE_INPUT_MISSING'
    foreach ($name in @('gradle.properties', 'init.gradle', 'init.gradle.kts')) {
        try {
            $null = Get-DirectLocalItem `
                -Path (Join-Path $userHomeItem.FullName $name) `
                -RequireLeaf `
                -MissingError $missing
            throw "VULCAN_UNBOUND_USER_GRADLE_INPUT_REJECTED: $name"
        } catch {
            if ($_.Exception.Message -eq $missing) {
                continue
            }
            throw
        }
    }

    $initRoot = $null
    try {
        $initRoot = Get-DirectLocalItem `
            -Path (Join-Path $userHomeItem.FullName 'init.d') `
            -RequireDirectory `
            -MissingError $missing
    } catch {
        if ($_.Exception.Message -ne $missing) {
            throw
        }
    }
    if ($null -eq $initRoot) {
        return
    }
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($initRoot.FullName)
    while ($pending.Count -gt 0) {
        $directory = Get-DirectLocalItem `
            -Path $pending.Pop() `
            -RequireDirectory `
            -MissingError 'VULCAN_UNBOUND_USER_GRADLE_INPUT_REJECTED'
        foreach ($child in @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop)) {
            if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'VULCAN_UNBOUND_USER_GRADLE_INPUT_REJECTED: reparse point in init.d'
            }
            $verifiedChild = Get-DirectLocalItem `
                -Path $child.FullName `
                -MissingError 'VULCAN_UNBOUND_USER_GRADLE_INPUT_REJECTED'
            if ($verifiedChild.PSIsContainer) {
                $pending.Push($verifiedChild.FullName)
            } elseif ($verifiedChild.Name -match '(?i)\.gradle(?:\.kts)?$') {
                throw "VULCAN_UNBOUND_USER_GRADLE_INPUT_REJECTED: $($verifiedChild.Name)"
            }
        }
    }
}

function Get-GradleJavaBinding {
    $javaPath = $null
    if (-not [string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
        if ($env:JAVA_HOME.IndexOf('"') -ge 0) {
            throw 'VULCAN_GRADLE_JAVA_INVALID: quoted JAVA_HOME is not accepted'
        }
        $javaHomeItem = Get-DirectLocalItem `
            -Path $env:JAVA_HOME `
            -RequireDirectory `
            -MissingError 'VULCAN_GRADLE_JAVA_21_REQUIRED'
        $javaPath = Join-Path $javaHomeItem.FullName 'bin/java.exe'
    } else {
        $java = Get-Command java.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
        $javaPath = $java.Source
    }
    $item = Get-DirectLocalItem `
        -Path $javaPath `
        -RequireLeaf `
        -MissingError 'VULCAN_GRADLE_JAVA_21_REQUIRED'
    $fileVersion = [string]$item.VersionInfo.FileVersion
    if ($fileVersion -notmatch '^(\d+)(?:\.|$)' -or [int]$Matches[1] -ne 21) {
        throw "VULCAN_GRADLE_JAVA_21_REQUIRED: selected Java version is $fileVersion"
    }
    return [pscustomobject][ordered]@{
        executable_sha256 = Get-PathSha256 -Path $item.FullName
        file_version = $fileVersion
        major = 21
    }
}

function Resolve-OfflineGradle {
    Assert-CleanGradleEnvironment
    Assert-NoProjectGradleJvmOverride
    $null = Get-DirectLocalItem `
        -Path $wrapperPropertiesPath `
        -RequireLeaf `
        -MissingError 'VULCAN_OFFLINE_GRADLE_CONFIGURATION_REQUIRED'
    $lines = @(Get-Content -LiteralPath $wrapperPropertiesPath)
    $distributionUrl = Get-WrapperProperty -Name 'distributionUrl' -Lines $lines
    $distributionSha256 = (Get-WrapperProperty -Name 'distributionSha256Sum' -Lines $lines).ToLowerInvariant()
    if ($distributionUrl -notmatch '/gradle-([0-9]+(?:\.[0-9]+)*)-bin\.zip$') {
        throw 'VULCAN_OFFLINE_GRADLE_CONFIGURATION_INVALID'
    }
    $version = $Matches[1]
    if ($distributionSha256 -notmatch '^[0-9a-f]{64}$') {
        throw 'VULCAN_OFFLINE_GRADLE_CONFIGURATION_INVALID'
    }
    $gradleUserHome = if ([string]::IsNullOrWhiteSpace($env:GRADLE_USER_HOME)) {
        Join-Path $env:USERPROFILE '.gradle'
    } else {
        [System.IO.Path]::GetFullPath($env:GRADLE_USER_HOME)
    }
    Assert-NoUserGradleInputs -GradleUserHome $gradleUserHome
    $distributionRoot = Join-Path $gradleUserHome "wrapper/dists/gradle-$version-bin"
    $rootItem = Get-DirectLocalItem `
        -Path $distributionRoot `
        -RequireDirectory `
        -MissingError 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_REQUIRED: install the verified wrapper distribution before preflight'
    $installations = @(Get-ChildItem -LiteralPath $rootItem.FullName -Directory -ErrorAction Stop)
    $valid = @()
    foreach ($installation in $installations) {
        try {
            $null = Get-DirectLocalItem `
                -Path $installation.FullName `
                -RequireDirectory `
                -MissingError 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_REQUIRED'
            $okPath = Join-Path $installation.FullName "gradle-$version-bin.zip.ok"
            $commandPath = Join-Path $installation.FullName "gradle-$version/bin/gradle.bat"
            $launcherPath = Join-Path $installation.FullName "gradle-$version/lib/gradle-launcher-$version.jar"
            $corePath = Join-Path $installation.FullName "gradle-$version/lib/gradle-core-$version.jar"
            $installationPath = Join-Path $installation.FullName "gradle-$version"
            foreach ($path in @($okPath, $commandPath, $launcherPath, $corePath)) {
                $null = Get-DirectLocalItem `
                    -Path $path `
                    -RequireLeaf `
                    -MissingError 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_REQUIRED'
            }
            $installationManifest = Get-DirectLocalTreeManifest -RootPath $installationPath
            $valid += [pscustomobject][ordered]@{
                version = $version
                distribution_sha256 = $distributionSha256
                command_path = $commandPath
                command_sha256 = Get-PathSha256 -Path $commandPath
                launcher_path = $launcherPath
                launcher_sha256 = Get-PathSha256 -Path $launcherPath
                core_path = $corePath
                core_sha256 = Get-PathSha256 -Path $corePath
                installation_manifest_sha256 = $installationManifest.sha256
                installation_file_count = $installationManifest.file_count
                installation_directory_count = $installationManifest.directory_count
            }
        } catch {
            if ($_.Exception.Message -notlike 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_REQUIRED*') {
                throw
            }
        }
    }
    if ($valid.Count -ne 1) {
        throw 'VULCAN_OFFLINE_GRADLE_DISTRIBUTION_REQUIRED: expected exactly one verified local installation'
    }
    $selected = $valid[0]
    $javaBinding = Get-GradleJavaBinding
    $selected | Add-Member -NotePropertyName java_executable_sha256 -NotePropertyValue $javaBinding.executable_sha256
    $selected | Add-Member -NotePropertyName java_file_version -NotePropertyValue $javaBinding.file_version
    $selected | Add-Member -NotePropertyName java_major -NotePropertyValue $javaBinding.major
    return $selected
}

function Get-SourceInputPaths {
    $repoItem = Get-DirectLocalItem `
        -Path $repoRoot `
        -RequireDirectory `
        -MissingError 'VULCAN_COMPATIBILITY_SOURCE_BINDING_UNAVAILABLE'
    $paths = New-Object 'System.Collections.Generic.List[string]'
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($repoItem.FullName)
    while ($pending.Count -gt 0) {
        $directory = Get-DirectLocalItem `
            -Path $pending.Pop() `
            -RequireDirectory `
            -MissingError 'VULCAN_COMPATIBILITY_SOURCE_BINDING_UNAVAILABLE'
        foreach ($child in @(Get-ChildItem -LiteralPath $directory.FullName -Force -ErrorAction Stop)) {
            $verifiedChild = Get-DirectLocalItem `
                -Path $child.FullName `
                -MissingError 'VULCAN_COMPATIBILITY_SOURCE_BINDING_UNAVAILABLE'
            if ($verifiedChild.PSIsContainer) {
                if ($verifiedChild.Name -in @('.git', '.gradle', 'build')) {
                    continue
                }
                $pending.Push($verifiedChild.FullName)
                continue
            }
            $paths.Add($verifiedChild.FullName)
        }
    }
    return @($paths.ToArray() | Sort-Object -Unique)
}

function Get-SourceManifestSha256 {
    param([Parameter(Mandatory)][string[]]$Paths)

    $lines = @()
    foreach ($path in $Paths) {
        $item = Get-DirectLocalItem `
            -Path $path `
            -RequireLeaf `
            -MissingError 'VULCAN_COMPATIBILITY_SOURCE_BINDING_UNAVAILABLE'
        $relative = ConvertTo-RepoRelativePath -Path $item.FullName
        $relativeName = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($relative))
        $stream = [System.IO.File]::Open(
            $item.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        try {
            $length = $stream.Length
            $sha256 = Get-StreamSha256 -Stream $stream
            if ($stream.Length -ne $length) {
                throw 'VULCAN_COMPATIBILITY_SOURCE_CHANGED_DURING_BINDING'
            }
        } finally {
            $stream.Dispose()
        }
        $lines += "$relativeName`t$length`t$sha256"
    }
    $orderedLines = [string[]]$lines
    [System.Array]::Sort($orderedLines, [System.StringComparer]::Ordinal)
    $encoded = [System.Text.Encoding]::UTF8.GetBytes(($orderedLines -join "`n") + "`n")
    $digest = [System.Security.Cryptography.SHA256]::Create()
    try {
        return [System.BitConverter]::ToString($digest.ComputeHash($encoded)).Replace('-', '').ToLowerInvariant()
    } finally {
        $digest.Dispose()
    }
}

function Get-SourceBinding {
    param([Parameter(Mandatory)]$OfflineGradle)

    $sourcePaths = Get-SourceInputPaths
    return [pscustomobject][ordered]@{
        source_manifest_sha256 = Get-SourceManifestSha256 -Paths $sourcePaths
        source_file_count = $sourcePaths.Count
        gradle_version = $OfflineGradle.version
        gradle_distribution_sha256 = $OfflineGradle.distribution_sha256
        gradle_command_sha256 = $OfflineGradle.command_sha256
        gradle_launcher_sha256 = $OfflineGradle.launcher_sha256
        gradle_core_sha256 = $OfflineGradle.core_sha256
        gradle_installation_manifest_sha256 = $OfflineGradle.installation_manifest_sha256
        gradle_installation_file_count = $OfflineGradle.installation_file_count
        gradle_installation_directory_count = $OfflineGradle.installation_directory_count
        java_executable_sha256 = $OfflineGradle.java_executable_sha256
        java_file_version = $OfflineGradle.java_file_version
        java_major = $OfflineGradle.java_major
    }
}

function Test-SourceBindingEqual {
    param(
        [Parameter(Mandatory)]$Left,
        [Parameter(Mandatory)]$Right
    )

    return $Left.source_manifest_sha256 -eq $Right.source_manifest_sha256 `
        -and $Left.source_file_count -eq $Right.source_file_count `
        -and $Left.gradle_version -eq $Right.gradle_version `
        -and $Left.gradle_distribution_sha256 -eq $Right.gradle_distribution_sha256 `
        -and $Left.gradle_command_sha256 -eq $Right.gradle_command_sha256 `
        -and $Left.gradle_launcher_sha256 -eq $Right.gradle_launcher_sha256 `
        -and $Left.gradle_core_sha256 -eq $Right.gradle_core_sha256 `
        -and $Left.gradle_installation_manifest_sha256 -eq $Right.gradle_installation_manifest_sha256 `
        -and $Left.gradle_installation_file_count -eq $Right.gradle_installation_file_count `
        -and $Left.gradle_installation_directory_count -eq $Right.gradle_installation_directory_count `
        -and $Left.java_executable_sha256 -eq $Right.java_executable_sha256 `
        -and $Left.java_file_version -eq $Right.java_file_version `
        -and $Left.java_major -eq $Right.java_major
}

function ConvertTo-UtcTimestamp {
    param(
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][string]$Field
    )

    if ($Value -is [DateTimeOffset]) {
        return $Value.ToUniversalTime()
    }
    if ($Value -is [DateTime]) {
        return [DateTimeOffset]::new($Value).ToUniversalTime()
    }
    if ($Value -isnot [string]) {
        throw "VULCAN_LICENSED_API_COMPATIBILITY_TIMESTAMP_INVALID: $Field"
    }
    $parsed = [DateTimeOffset]::MinValue
    $valid = [DateTimeOffset]::TryParse(
        $Value,
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$parsed)
    if (-not $valid) {
        throw "VULCAN_LICENSED_API_COMPATIBILITY_TIMESTAMP_INVALID: $Field"
    }
    return $parsed.ToUniversalTime()
}

function Assert-FreshTimestamp {
    param(
        [Parameter(Mandatory)][DateTimeOffset]$Timestamp,
        [Parameter(Mandatory)][DateTimeOffset]$Now,
        [Parameter(Mandatory)][string]$Field
    )

    if ($Timestamp -gt $Now.AddMinutes(5)) {
        throw "VULCAN_LICENSED_API_COMPATIBILITY_TIMESTAMP_FUTURE: $Field"
    }
    if ($Timestamp -lt $Now.AddMinutes(-$MaximumReportAgeMinutes)) {
        throw "VULCAN_LICENSED_API_COMPATIBILITY_REPORT_STALE: $Field"
    }
}

function Read-AndAssertGateReport {
    param(
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][string]$ExpectedArtifactSha256,
        [long]$ExpectedArtifactSize = -1L,
        [Parameter(Mandatory)][string]$RawReport
    )

    if (-not (Test-JsonExactTopLevelPropertyNames `
            -RawJson $RawReport `
            -Expected (Get-GateReportPropertyNames))) {
        throw "VULCAN_LICENSED_API_COMPATIBILITY_REPORT_INVALID (properties): $ReportPath"
    }
    $report = $RawReport | ConvertFrom-Json
    if (-not (Test-JsonExactProperties `
            -Value $report `
            -Expected (Get-GateReportPropertyNames))) {
        throw "VULCAN_LICENSED_API_COMPATIBILITY_REPORT_INVALID (properties): $ReportPath"
    }
    $required = [ordered]@{
        schema = (Test-JsonString -Value $report.schema) `
            -and $report.schema -eq 'VULCAN_LICENSED_API_COMPATIBILITY'
        generated_at = (Test-JsonTimestampScalar -Value $report.generated_at) `
            -and -not [string]::IsNullOrWhiteSpace([string]$report.generated_at)
        failure_stage = (Test-JsonString -Value $report.failure_stage) `
            -and $report.failure_stage -eq 'NONE'
        artifact_sha256 = (Test-JsonString -Value $report.artifact_sha256) `
            -and $report.artifact_sha256 -eq $ExpectedArtifactSha256
        artifact_size = (Test-JsonInteger -Value $report.artifact_size) `
            -and $report.artifact_size -gt 0 `
            -and ($ExpectedArtifactSize -lt 0L -or $report.artifact_size -eq $ExpectedArtifactSize)
        plugin_name = (Test-JsonString -Value $report.plugin_name) `
            -and $report.plugin_name -eq 'Vulcan'
        plugin_version = (Test-JsonString -Value $report.plugin_version) `
            -and -not [string]::IsNullOrWhiteSpace($report.plugin_version)
        event_type = (Test-JsonString -Value $report.event_type) -and $report.event_type -in @(
            'me.frep.vulcan.api.event.VulcanFlagEvent',
            'me.frep.vulcan.api.event.VulcanViolationEvent')
        player_accessor = (Test-JsonString -Value $report.player_accessor) `
            -and $report.player_accessor -eq 'getPlayer'
        check_accessor = (Test-JsonString -Value $report.check_accessor) `
            -and $report.check_accessor -eq 'getCheck'
        check_name_accessor = (Test-JsonString -Value $report.check_name_accessor) `
            -and $report.check_name_accessor -in @('getCheckName', 'getName', 'getType')
        stable_check_accessor = (Test-JsonString -Value $report.stable_check_accessor) `
            -and $report.stable_check_accessor -in @('getStableKey', 'getIdentifier', 'getName')
        event_violation_accessor = (Test-JsonString -Value $report.event_violation_accessor) `
            -and $report.event_violation_accessor -in @('none', 'getViolationLevel', 'getVl', 'getVL')
        check_violation_accessor = (Test-JsonString -Value $report.check_violation_accessor) `
            -and $report.check_violation_accessor -in @('none', 'getViolationLevel', 'getVl', 'getVL')
        artifact_path_recorded = $report.artifact_path_recorded -is [bool] `
            -and $report.artifact_path_recorded -eq $false
        artifact_copied_or_redistributed = $report.artifact_copied_or_redistributed -is [bool] `
            -and $report.artifact_copied_or_redistributed -eq $false
        paper_process_coverage = $report.paper_process_coverage -is [bool] `
            -and $report.paper_process_coverage -eq $false
        licensed_plugin_enablement_coverage = $report.licensed_plugin_enablement_coverage -is [bool] `
            -and $report.licensed_plugin_enablement_coverage -eq $false
        real_behavior_event_delivery_coverage = $report.real_behavior_event_delivery_coverage -is [bool] `
            -and $report.real_behavior_event_delivery_coverage -eq $false
        limitations = $report.limitations -is [System.Array] `
            -and @($report.limitations).Count -eq 1 `
            -and (Test-JsonString -Value $report.limitations[0]) `
            -and $report.limitations[0] -eq 'STRUCTURAL_PREFLIGHT_ONLY'
        passed = $report.passed -is [bool] -and $report.passed -eq $true
    }
    $failed = @($required.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
    if ($failed.Count -gt 0) {
        throw "VULCAN_LICENSED_API_COMPATIBILITY_REPORT_INVALID ($($failed -join ', ')): $ReportPath"
    }
    return $report
}

function Write-ExecutionBinding {
    param(
        [Parameter(Mandatory)][string]$BindingPath,
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][string]$ReportSha256,
        [Parameter(Mandatory)]$Report,
        [Parameter(Mandatory)]$SourceBinding,
        [Parameter(Mandatory)][long]$ArtifactSize
    )

    $binding = [ordered]@{
        schema = $bindingSchema
        generated_at = [DateTimeOffset]::UtcNow.ToString('o')
        source_mode = 'EXECUTED'
        run_id = Split-Path (Split-Path $ReportPath -Parent) -Leaf
        report_name = 'report.json'
        report_generated_at = $Report.generated_at
        report_sha256 = $ReportSha256
        artifact_sha256 = $Report.artifact_sha256
        artifact_size = $ArtifactSize
        artifact_path_recorded = $false
        source_manifest_sha256 = $SourceBinding.source_manifest_sha256
        source_file_count = $SourceBinding.source_file_count
        gradle_version = $SourceBinding.gradle_version
        gradle_distribution_sha256 = $SourceBinding.gradle_distribution_sha256
        gradle_command_sha256 = $SourceBinding.gradle_command_sha256
        gradle_launcher_sha256 = $SourceBinding.gradle_launcher_sha256
        gradle_core_sha256 = $SourceBinding.gradle_core_sha256
        gradle_installation_manifest_sha256 = $SourceBinding.gradle_installation_manifest_sha256
        gradle_installation_file_count = $SourceBinding.gradle_installation_file_count
        gradle_installation_directory_count = $SourceBinding.gradle_installation_directory_count
        java_executable_sha256 = $SourceBinding.java_executable_sha256
        java_file_version = $SourceBinding.java_file_version
        java_major = $SourceBinding.java_major
        gradle_task = ':mcace-server-paper:test'
        test_selector = $test
        gradle_offline = $true
    }
    $json = $binding | ConvertTo-Json -Depth 4
    $utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
    $stream = [System.IO.File]::Open(
        $BindingPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
    try {
        $writer = New-Object System.IO.StreamWriter($stream, $utf8WithoutBom, 4096, $true)
        try {
            $writer.Write($json + [Environment]::NewLine)
            $writer.Flush()
            $stream.Flush()
        } finally {
            $writer.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Read-AndAssertBinding {
    param(
        [Parameter(Mandatory)][string]$BindingPath,
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][string]$ExpectedArtifactSha256,
        [Parameter(Mandatory)]$CurrentSourceBinding,
        [Parameter(Mandatory)][string]$RawBinding,
        [string]$LockedReportSha256 = ''
    )

    if (-not (Test-JsonExactTopLevelPropertyNames `
            -RawJson $RawBinding `
            -Expected (Get-BindingPropertyNames))) {
        throw "VULCAN_LICENSED_API_COMPATIBILITY_BINDING_INVALID (properties): $BindingPath"
    }
    $binding = $RawBinding | ConvertFrom-Json
    if (-not (Test-JsonExactProperties `
            -Value $binding `
            -Expected (Get-BindingPropertyNames))) {
        throw "VULCAN_LICENSED_API_COMPATIBILITY_BINDING_INVALID (properties): $BindingPath"
    }
    $expectedRunId = Split-Path (Split-Path $ReportPath -Parent) -Leaf
    $required = [ordered]@{
        schema = (Test-JsonString -Value $binding.schema) -and $binding.schema -eq $bindingSchema
        generated_at = (Test-JsonTimestampScalar -Value $binding.generated_at) `
            -and -not [string]::IsNullOrWhiteSpace([string]$binding.generated_at)
        source_mode = (Test-JsonString -Value $binding.source_mode) `
            -and $binding.source_mode -eq 'EXECUTED'
        run_id = (Test-JsonString -Value $binding.run_id) `
            -and $binding.run_id -eq $expectedRunId `
            -and $binding.run_id -match '^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{7}Z$'
        report_name = (Test-JsonString -Value $binding.report_name) `
            -and $binding.report_name -eq 'report.json'
        report_generated_at = (Test-JsonTimestampScalar -Value $binding.report_generated_at) `
            -and -not [string]::IsNullOrWhiteSpace([string]$binding.report_generated_at)
        artifact_sha256 = (Test-JsonString -Value $binding.artifact_sha256) `
            -and $binding.artifact_sha256 -eq $ExpectedArtifactSha256
        artifact_size = (Test-JsonInteger -Value $binding.artifact_size) `
            -and $binding.artifact_size -gt 0
        artifact_path_recorded = $binding.artifact_path_recorded -is [bool] `
            -and $binding.artifact_path_recorded -eq $false
        report_sha256 = (Test-JsonString -Value $binding.report_sha256) `
            -and $binding.report_sha256 -match '^[0-9a-f]{64}$' `
            -and $binding.report_sha256 -eq $(if ([string]::IsNullOrWhiteSpace($LockedReportSha256)) {
                Get-PathSha256 -Path $ReportPath
            } else {
                $LockedReportSha256
            })
        source_manifest_sha256 = (Test-JsonString -Value $binding.source_manifest_sha256) `
            -and $binding.source_manifest_sha256 -match '^[0-9a-f]{64}$' `
            -and $binding.source_manifest_sha256 -eq $CurrentSourceBinding.source_manifest_sha256
        source_file_count = (Test-JsonInteger -Value $binding.source_file_count) `
            -and $binding.source_file_count -eq $CurrentSourceBinding.source_file_count
        gradle_version = (Test-JsonString -Value $binding.gradle_version) `
            -and $binding.gradle_version -eq $CurrentSourceBinding.gradle_version
        gradle_distribution_sha256 = (Test-JsonString -Value $binding.gradle_distribution_sha256) `
            -and $binding.gradle_distribution_sha256 -eq $CurrentSourceBinding.gradle_distribution_sha256
        gradle_command_sha256 = (Test-JsonString -Value $binding.gradle_command_sha256) `
            -and $binding.gradle_command_sha256 -eq $CurrentSourceBinding.gradle_command_sha256
        gradle_launcher_sha256 = (Test-JsonString -Value $binding.gradle_launcher_sha256) `
            -and $binding.gradle_launcher_sha256 -eq $CurrentSourceBinding.gradle_launcher_sha256
        gradle_core_sha256 = (Test-JsonString -Value $binding.gradle_core_sha256) `
            -and $binding.gradle_core_sha256 -eq $CurrentSourceBinding.gradle_core_sha256
        gradle_installation_manifest_sha256 = `
            (Test-JsonString -Value $binding.gradle_installation_manifest_sha256) `
            -and $binding.gradle_installation_manifest_sha256 -match '^[0-9a-f]{64}$' `
            -and $binding.gradle_installation_manifest_sha256 `
                -eq $CurrentSourceBinding.gradle_installation_manifest_sha256
        gradle_installation_file_count = `
            (Test-JsonInteger -Value $binding.gradle_installation_file_count) `
            -and $binding.gradle_installation_file_count -gt 0 `
            -and $binding.gradle_installation_file_count `
                -eq $CurrentSourceBinding.gradle_installation_file_count
        gradle_installation_directory_count = `
            (Test-JsonInteger -Value $binding.gradle_installation_directory_count) `
            -and $binding.gradle_installation_directory_count -gt 0 `
            -and $binding.gradle_installation_directory_count `
                -eq $CurrentSourceBinding.gradle_installation_directory_count
        java_executable_sha256 = (Test-JsonString -Value $binding.java_executable_sha256) `
            -and $binding.java_executable_sha256 -eq $CurrentSourceBinding.java_executable_sha256
        java_file_version = (Test-JsonString -Value $binding.java_file_version) `
            -and $binding.java_file_version -eq $CurrentSourceBinding.java_file_version
        java_major = (Test-JsonInteger -Value $binding.java_major) `
            -and $binding.java_major -eq 21 `
            -and $binding.java_major -eq $CurrentSourceBinding.java_major
        gradle_task = (Test-JsonString -Value $binding.gradle_task) `
            -and $binding.gradle_task -eq ':mcace-server-paper:test'
        test_selector = (Test-JsonString -Value $binding.test_selector) `
            -and $binding.test_selector -eq $test
        gradle_offline = $binding.gradle_offline -is [bool] `
            -and $binding.gradle_offline -eq $true
    }
    $failed = @($required.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key)
    if ($failed.Count -gt 0) {
        throw "VULCAN_LICENSED_API_COMPATIBILITY_BINDING_INVALID ($($failed -join ', ')): $BindingPath"
    }
    return $binding
}

$reportPath = $null
$bindingPath = $null

if ($ReportOnly) {
    if (-not [string]::IsNullOrWhiteSpace($VulcanJar)) {
        throw 'VULCAN_REPORT_ONLY_ARTIFACT_PATH_REJECTED: bind by -ArtifactSha256 without reopening the JAR'
    }
    $expectedSha256 = ConvertTo-ArtifactSha256 `
        -Value $ArtifactSha256 `
        -MissingError 'VULCAN_LICENSED_ARTIFACT_SHA256_REQUIRED: pass the operator-recorded SHA-256 with -ReportOnly'
    $offlineGradle = Resolve-OfflineGradle
    $sourceBinding = Get-SourceBinding -OfflineGradle $offlineGradle
    $runsItem = Get-DirectLocalItem `
        -Path $runsRoot `
        -RequireDirectory `
        -MissingError 'VULCAN_COMPATIBILITY_REPORT_REQUIRED'
    $latestRun = Get-ChildItem -LiteralPath $runsItem.FullName -Directory -ErrorAction Stop |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1
    if ($null -eq $latestRun) {
        throw 'VULCAN_COMPATIBILITY_REPORT_REQUIRED'
    }
    $runItem = Get-DirectLocalItem `
        -Path $latestRun.FullName `
        -RequireDirectory `
        -MissingError 'VULCAN_COMPATIBILITY_REPORT_REQUIRED'
    $reportItem = Get-DirectLocalItem `
        -Path (Join-Path $runItem.FullName 'report.json') `
        -RequireLeaf `
        -MissingError 'VULCAN_COMPATIBILITY_REPORT_REQUIRED'
    $bindingItem = Get-DirectLocalItem `
        -Path (Join-Path $runItem.FullName 'binding.json') `
        -RequireLeaf `
        -MissingError 'VULCAN_COMPATIBILITY_BINDING_REQUIRED: old unbound reports are not current evidence'
    $reportPath = $reportItem.FullName
    $bindingPath = $bindingItem.FullName

    $reportEvidence = $null
    $bindingEvidence = $null
    try {
        $reportEvidence = Open-LockedTextEvidence -Path $reportPath
        $bindingEvidence = Open-LockedTextEvidence -Path $bindingPath
        $binding = Read-AndAssertBinding `
            -BindingPath $bindingPath `
            -ReportPath $reportPath `
            -ExpectedArtifactSha256 $expectedSha256 `
            -CurrentSourceBinding $sourceBinding `
            -RawBinding $bindingEvidence.raw `
            -LockedReportSha256 $reportEvidence.sha256
        $report = Read-AndAssertGateReport `
            -ReportPath $reportPath `
            -ExpectedArtifactSha256 $expectedSha256 `
            -ExpectedArtifactSize $binding.artifact_size `
            -RawReport $reportEvidence.raw

        $now = [DateTimeOffset]::UtcNow
        $reportTimestamp = ConvertTo-UtcTimestamp -Value $report.generated_at -Field 'report.generated_at'
        $bindingTimestamp = ConvertTo-UtcTimestamp -Value $binding.generated_at -Field 'binding.generated_at'
        $boundReportTimestamp = ConvertTo-UtcTimestamp `
            -Value $binding.report_generated_at `
            -Field 'binding.report_generated_at'
        Assert-FreshTimestamp -Timestamp $reportTimestamp -Now $now -Field 'report.generated_at'
        Assert-FreshTimestamp -Timestamp $bindingTimestamp -Now $now -Field 'binding.generated_at'
        if ($boundReportTimestamp -ne $reportTimestamp) {
            throw 'VULCAN_LICENSED_API_COMPATIBILITY_BINDING_INVALID: report timestamp mismatch'
        }
        $lockedReportItem = Get-DirectLocalItem `
            -Path $reportPath `
            -RequireLeaf `
            -MissingError 'VULCAN_COMPATIBILITY_REPORT_REQUIRED'
        $lockedBindingItem = Get-DirectLocalItem `
            -Path $bindingPath `
            -RequireLeaf `
            -MissingError 'VULCAN_COMPATIBILITY_BINDING_REQUIRED'
        $reportMtime = [DateTimeOffset]::new($lockedReportItem.LastWriteTimeUtc)
        $bindingMtime = [DateTimeOffset]::new($lockedBindingItem.LastWriteTimeUtc)
        Assert-FreshTimestamp -Timestamp $reportMtime -Now $now -Field 'report.last_write_time'
        Assert-FreshTimestamp -Timestamp $bindingMtime -Now $now -Field 'binding.last_write_time'
        Assert-LockedTextEvidenceUnchanged -Evidence $reportEvidence
        Assert-LockedTextEvidenceUnchanged -Evidence $bindingEvidence
    } finally {
        if ($null -ne $bindingEvidence) {
            $bindingEvidence.stream.Dispose()
        }
        if ($null -ne $reportEvidence) {
            $reportEvidence.stream.Dispose()
        }
    }
} else {
    if ([string]::IsNullOrWhiteSpace($VulcanJar)) {
        throw 'VULCAN_LICENSED_ARTIFACT_REQUIRED: pass -VulcanJar with an operator-obtained local JAR'
    }
    $resolved = Resolve-DirectLocalArtifact -Path $VulcanJar
    $expectedSha256 = $null
    if (-not [string]::IsNullOrWhiteSpace($ArtifactSha256)) {
        $expectedSha256 = ConvertTo-ArtifactSha256 `
            -Value $ArtifactSha256 `
            -MissingError 'VULCAN_LICENSED_ARTIFACT_SHA256_REQUIRED'
    }

    $artifactStream = $null
    try {
        $artifactStream = [System.IO.File]::Open(
            $resolved,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read)
        $lockedSizeBefore = $artifactStream.Length
        if ($lockedSizeBefore -le 0L) {
            throw 'VULCAN_LICENSED_ARTIFACT_INVALID: the supplied JAR is empty'
        }
        $lockedSha256Before = Get-StreamSha256 -Stream $artifactStream
        if ($null -ne $expectedSha256 -and $lockedSha256Before -ne $expectedSha256) {
            throw 'VULCAN_LICENSED_ARTIFACT_SHA256_MISMATCH: the supplied JAR does not match the operator hash'
        }

        $offlineGradle = Resolve-OfflineGradle
        $sourceBindingBefore = Get-SourceBinding -OfflineGradle $offlineGradle
        Initialize-DirectLocalRunsRoot
        $runRoot = Join-Path $runsRoot ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH-mm-ss-fffffffZ'))
        New-Item -ItemType Directory -Path $runRoot -ErrorAction Stop | Out-Null
        $null = Get-DirectLocalItem `
            -Path $runRoot `
            -RequireDirectory `
            -MissingError 'VULCAN_COMPATIBILITY_OUTPUT_ROOT_INVALID'
        $reportPath = Join-Path $runRoot 'report.json'
        $bindingPath = Join-Path $runRoot 'binding.json'
        & $offlineGradle.command_path '-Dmcace.vulcan.compatibility.enabled=true' `
            "-Dmcace.vulcan.compatibility.jar=$resolved" `
            "-Dmcace.vulcan.compatibility.report=$reportPath" `
            ':mcace-server-paper:test' '--tests' $test '--rerun-tasks' '--no-build-cache' `
            '--no-configuration-cache' '--offline' '--no-daemon' '--max-workers=1' '--console=plain'
        $gradleExitCode = $LASTEXITCODE

        $lockedSizeAfter = $artifactStream.Length
        $lockedSha256After = Get-StreamSha256 -Stream $artifactStream
        if ($lockedSizeAfter -ne $lockedSizeBefore -or $lockedSha256After -ne $lockedSha256Before) {
            throw 'VULCAN_LICENSED_ARTIFACT_CHANGED_DURING_PREFLIGHT'
        }
        if ($gradleExitCode -ne 0) {
            throw "VULCAN_LICENSED_API_COMPATIBILITY_FAILED: inspect $reportPath"
        }
        $reportItem = Get-DirectLocalItem `
            -Path $reportPath `
            -RequireLeaf `
            -MissingError 'VULCAN_LICENSED_API_COMPATIBILITY_REPORT_REQUIRED'
        $reportEvidence = $null
        $bindingEvidence = $null
        try {
            $reportEvidence = Open-LockedTextEvidence -Path $reportItem.FullName
            $report = Read-AndAssertGateReport `
                -ReportPath $reportPath `
                -ExpectedArtifactSha256 $lockedSha256Before `
                -ExpectedArtifactSize $lockedSizeBefore `
                -RawReport $reportEvidence.raw
            if ($reportEvidence.raw.IndexOf(
                    $resolved,
                    [System.StringComparison]::OrdinalIgnoreCase) -ge 0) {
                throw 'VULCAN_LICENSED_API_COMPATIBILITY_REPORT_INVALID: artifact path was recorded'
            }
            $now = [DateTimeOffset]::UtcNow
            $reportTimestamp = ConvertTo-UtcTimestamp `
                -Value $report.generated_at `
                -Field 'report.generated_at'
            Assert-FreshTimestamp -Timestamp $reportTimestamp -Now $now -Field 'report.generated_at'
            $lockedReportItem = Get-DirectLocalItem `
                -Path $reportPath `
                -RequireLeaf `
                -MissingError 'VULCAN_LICENSED_API_COMPATIBILITY_REPORT_REQUIRED'
            $reportMtime = [DateTimeOffset]::new($lockedReportItem.LastWriteTimeUtc)
            Assert-FreshTimestamp -Timestamp $reportMtime -Now $now -Field 'report.last_write_time'
            $sourceBindingAfter = Get-SourceBinding -OfflineGradle (Resolve-OfflineGradle)
            if (-not (Test-SourceBindingEqual -Left $sourceBindingBefore -Right $sourceBindingAfter)) {
                throw 'VULCAN_COMPATIBILITY_SOURCE_CHANGED_DURING_PREFLIGHT'
            }
            Assert-LockedTextEvidenceUnchanged -Evidence $reportEvidence
            Write-ExecutionBinding `
                -BindingPath $bindingPath `
                -ReportPath $reportPath `
                -ReportSha256 $reportEvidence.sha256 `
                -Report $report `
                -SourceBinding $sourceBindingBefore `
                -ArtifactSize $lockedSizeBefore
            $bindingItem = Get-DirectLocalItem `
                -Path $bindingPath `
                -RequireLeaf `
                -MissingError 'VULCAN_COMPATIBILITY_BINDING_REQUIRED'
            $bindingEvidence = Open-LockedTextEvidence -Path $bindingItem.FullName
            $binding = Read-AndAssertBinding `
                -BindingPath $bindingPath `
                -ReportPath $reportPath `
                -ExpectedArtifactSha256 $lockedSha256Before `
                -CurrentSourceBinding $sourceBindingBefore `
                -RawBinding $bindingEvidence.raw `
                -LockedReportSha256 $reportEvidence.sha256
            $bindingTimestamp = ConvertTo-UtcTimestamp `
                -Value $binding.generated_at `
                -Field 'binding.generated_at'
            $boundReportTimestamp = ConvertTo-UtcTimestamp `
                -Value $binding.report_generated_at `
                -Field 'binding.report_generated_at'
            Assert-FreshTimestamp -Timestamp $bindingTimestamp -Now $now -Field 'binding.generated_at'
            if ($boundReportTimestamp -ne $reportTimestamp) {
                throw 'VULCAN_LICENSED_API_COMPATIBILITY_BINDING_INVALID: report timestamp mismatch'
            }
            Assert-LockedTextEvidenceUnchanged -Evidence $reportEvidence
            Assert-LockedTextEvidenceUnchanged -Evidence $bindingEvidence
        } finally {
            if ($null -ne $bindingEvidence) {
                $bindingEvidence.stream.Dispose()
            }
            if ($null -ne $reportEvidence) {
                $reportEvidence.stream.Dispose()
            }
        }
    } finally {
        if ($null -ne $artifactStream) {
            $artifactStream.Dispose()
        }
    }
}

$relativeReportPath = ConvertTo-RepoRelativePath -Path $reportPath
Write-Output "VULCAN_LICENSED_API_COMPATIBILITY_PASS|$relativeReportPath"
