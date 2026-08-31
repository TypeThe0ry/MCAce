[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop

$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$publisher = Join-Path $PSScriptRoot 'publish-server-version-matrix-evidence.ps1'
$utf8NoBom = New-Object Text.UTF8Encoding($false)
$artifactCommit = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
$releaseCommit = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('mcace-matrix-publisher-' + [Guid]::NewGuid().ToString('N'))
$negativeCount = 0
$rsa = $null
$trustRootPath = ''
$trustRootSha256 = ''

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "TEST_ASSERTION_FAILED|$Message" }
}

function Get-BytesSha256([byte[]]$Bytes) {
    $hasher = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($hasher.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $hasher.Dispose() }
}

function Get-FileSha256([string]$Path) {
    return Get-BytesSha256 ([IO.File]::ReadAllBytes($Path))
}

function ConvertTo-CompactJsonBytes([object]$Value) {
    return $utf8NoBom.GetBytes(($Value | ConvertTo-Json -Depth 40 -Compress) + "`n")
}

function ConvertTo-CommitmentJsonBytes([object]$Value) {
    return $utf8NoBom.GetBytes(($Value | ConvertTo-Json -Depth 30 -Compress))
}

function Write-CompactJson([string]$Path, [object]$Value) {
    [IO.File]::WriteAllBytes($Path, (ConvertTo-CompactJsonBytes $Value))
}

function Write-CommitmentJson([string]$Path, [object]$Value) {
    [IO.File]::WriteAllBytes($Path, (ConvertTo-CommitmentJsonBytes $Value))
}

function Get-RawSetSha256([object[]]$Descriptors) {
    $records = @($Descriptors | ForEach-Object {
        [pscustomobject][ordered]@{ ordinal=[int]$_.ordinal; case_id=[string]$_.case_id
            path=[string]$_.path; sha256=[string]$_.sha256; size_bytes=[long]$_.size_bytes }
    })
    return Get-BytesSha256 (ConvertTo-CompactJsonBytes ([pscustomobject][ordered]@{
        domain='MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_SET_V1'
        source_commit=$artifactCommit; reports=$records
    }))
}

function Get-SetSha256([string]$Domain, [object]$Value) {
    return Get-BytesSha256 (ConvertTo-CommitmentJsonBytes ([pscustomobject][ordered]@{
        domain=$Domain; value=$Value
    }))
}

$receiptPropertyNames = @(
    'schema','artifact_class','source_mode','signed_at','expires_at',
    'release_source_commit','artifact_source_commit','product_version',
    'operation_attempt_id','challenge_nonce','challenge_issued_at',
    'report_sha256','report_size_bytes','binding_sha256','binding_size_bytes',
    'raw_manifest_sha256','raw_manifest_size_bytes','ordered_raw_report_set_sha256',
    'case_runtime_commitment_sha256','case_count','process_identity_count',
    'release_bundle_schema','release_bundle_manifest_sha256',
    'release_bundle_manifest_size_bytes','release_bundle_sha256s_sha256',
    'release_bundle_sha256s_size_bytes','release_bundle_artifact_set_sha256',
    'release_bundle_artifact_count','matrix_product_jar_set_sha256',
    'matrix_product_jar_count','supervisor_independent','signer_key_id',
    'signer_trust_root_sha256','signature_algorithm','test_fixture','signature_base64')

function Get-ReceiptSigningPayload([object]$Receipt) {
    $lines=[Collections.Generic.List[string]]::new()
    [void]$lines.Add('MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_SIGNING_V1')
    foreach($name in @($receiptPropertyNames | Where-Object { $_ -cne 'signature_base64' })){
        $value=$Receipt.$name
        if($value -is [bool]){$rendered=if([bool]$value){'true'}else{'false'}}
        elseif($value -is [byte] -or $value -is [int16] -or $value -is [int32] -or $value -is [int64]){
            $rendered=[Convert]::ToString($value,[Globalization.CultureInfo]::InvariantCulture)
        }else{$rendered=[string]$value}
        [void]$lines.Add("$name=$rendered")
    }
    return $utf8NoBom.GetBytes(($lines -join "`n")+"`n")
}

function New-ByteArray([int]$Length, [byte]$Seed) {
    $bytes = New-Object byte[] $Length
    for ($index = 0; $index -lt $bytes.Length; $index++) {
        $bytes[$index] = [byte](($Seed + $index * 13) -band 0xff)
    }
    return $bytes
}

function New-TestJar([string]$Path, [string]$Marker) {
    $stream = [IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $stream,[IO.Compression.ZipArchiveMode]::Create,$true)
        try {
            foreach ($entryName in @('META-INF/MANIFEST.MF',$Marker,'fixture/padding.bin')) {
                $entry = $archive.CreateEntry($entryName,[IO.Compression.CompressionLevel]::NoCompression)
                $entryStream = $entry.Open()
                try {
                    $bytes = $utf8NoBom.GetBytes("valid-test-archive|$entryName")
                    $entryStream.Write($bytes,0,$bytes.Length)
                } finally { $entryStream.Dispose() }
            }
        } finally { $archive.Dispose() }
    } finally { $stream.Dispose() }
}

function Get-ExpectedCaseDefinitions {
    $definitions = New-Object 'Collections.Generic.List[object]'
    foreach ($version in @('1.21.11','26.1.2','26.2')) {
        foreach ($backend in @('PAPER','FOLIA')) {
            foreach ($proxy in @('VELOCITY','BUNGEE')) {
                $protocol = if ($version -ceq '1.21.11') { 774 } elseif ($version -ceq '26.1.2') { 775 } else { 776 }
                $java = if ($version -ceq '1.21.11') { 21 } else { 25 }
                $lane = if ($version -ceq '26.2' -and $backend -ceq 'FOLIA') { 'BETA' } else { 'STABLE' }
                $selector = if ($backend -ceq 'FOLIA') {
                    if ($proxy -ceq 'VELOCITY') {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realVelocityModernForwardingToFoliaReturnsShadowContext'
                    } else {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realBungeeIpForwardingToFoliaReturnsShadowContext'
                    }
                } else {
                    if ($proxy -ceq 'VELOCITY') {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realVelocityModernForwardingOfflinePlayerProbeReachesMCAceChannel'
                    } else {
                        'com.ellan.mcace.runtime.MinecraftProxyPlayerProbeTest.realBungeeIpForwardingOfflinePlayerProbeReachesMCAceChannel'
                    }
                }
                [void]$definitions.Add([pscustomobject][ordered]@{
                    case_id = "$version-$($backend.ToLowerInvariant())-$(if ($proxy -ceq 'VELOCITY') { 'velocity' } else { 'bungee' })"
                    minecraft_version = $version
                    minecraft_protocol = $protocol
                    server_java_feature = $java
                    backend = $backend
                    proxy = $proxy
                    lane = $lane
                    selector = $selector
                })
            }
        }
    }
    return $definitions.ToArray()
}

function New-ReleaseBundle([string]$Root) {
    [void][IO.Directory]::CreateDirectory($Root)
    $jarNames = @(
        'mcace-client-fabric-1.21.11.jar',
        'mcace-client-fabric-26.1.2.jar',
        'mcace-client-fabric-26.2.jar',
        'mcace-server-velocity.jar',
        'mcace-server-bungeecord.jar',
        'mcace-server-paper.jar')
    $artifacts = [ordered]@{}
    for ($index = 0; $index -lt $jarNames.Count; $index++) {
        $path = Join-Path $Root $jarNames[$index]
        $marker = switch ($jarNames[$index]) {
            'mcace-server-velocity.jar' { 'com/ellan/mcace/velocity/MCAceVelocityPlugin.class' }
            'mcace-server-bungeecord.jar' { 'com/ellan/mcace/bungeecord/MCAceBungeePlugin.class' }
            'mcace-server-paper.jar' { 'com/ellan/mcace/paper/MCAcePaperPlugin.class' }
            default { "com/ellan/mcace/client/Test$index.class" }
        }
        New-TestJar $path $marker
        $bytes = [IO.File]::ReadAllBytes($path)
        $artifacts[$jarNames[$index]] = [pscustomobject][ordered]@{
            file = $jarNames[$index]
            sha256 = Get-BytesSha256 $bytes
            size_bytes = [long]$bytes.Length
        }
    }
    $manifestLines = New-Object 'Collections.Generic.List[string]'
    foreach ($line in @(
            'schema=MCACE_RELEASE_BUNDLE_V4',
            'bundle_profile=RELEASE',
            'release_identity=true',
            'deployable_count=6',
            'bundle_entry_count=8',
            'product_version=0.0.1',
            "source_commit=$releaseCommit",
            "artifact_source_commit=$artifactCommit",
            'root_java_version=21.0.8',
            'root_java_specification_version=21',
            'root_gradle_version=9.6.1',
            'modern_java_version=25.0.2',
            'modern_java_specification_version=25',
            'modern_gradle_version=9.6.1')) {
        [void]$manifestLines.Add($line)
    }
    foreach ($jarName in $jarNames) {
        $key = $jarName.Remove($jarName.Length - 4).Replace('-', '_').Replace('.', '_')
        [void]$manifestLines.Add("artifact.$key.file=$jarName")
        [void]$manifestLines.Add("artifact.$key.sha256=$($artifacts[$jarName].sha256)")
        if ($jarName -cmatch '^mcace-client-fabric-(?<target>1\.21\.11|26\.1\.2|26\.2)\.jar$') {
            [void]$manifestLines.Add("artifact.$key.minecraft_version=$($Matches.target)")
            [void]$manifestLines.Add("artifact.$key.client_build_id=fabric-$($Matches.target)-$artifactCommit")
        }
    }
    [IO.File]::WriteAllText(
        (Join-Path $Root 'release-manifest.properties'),
        (($manifestLines -join "`n") + "`n"),
        $utf8NoBom)
    $sumLines = @($jarNames | ForEach-Object { "$($artifacts[$_].sha256)  $_" })
    [IO.File]::WriteAllText(
        (Join-Path $Root 'SHA256SUMS'),
        (($sumLines -join "`n") + "`n"),
        $utf8NoBom)
    return [pscustomobject]@{ root=$Root; artifacts=[pscustomobject]$artifacts; jar_names=$jarNames }
}

function New-MatrixObjects([object]$Bundle, [string]$GeneratedAt) {
    $products = [pscustomobject][ordered]@{
        velocity = [pscustomobject][ordered]@{
            relative='mcace-server-velocity/build/libs/mcace-server-velocity-0.0.1.jar'
            sha256=[string]$Bundle.artifacts.'mcace-server-velocity.jar'.sha256
            size=[long]$Bundle.artifacts.'mcace-server-velocity.jar'.size_bytes
        }
        bungee = [pscustomobject][ordered]@{
            relative='mcace-server-bungeecord/build/libs/mcace-server-bungeecord-0.0.1.jar'
            sha256=[string]$Bundle.artifacts.'mcace-server-bungeecord.jar'.sha256
            size=[long]$Bundle.artifacts.'mcace-server-bungeecord.jar'.size_bytes
        }
        paper = [pscustomobject][ordered]@{
            relative='mcace-server-paper/build/libs/mcace-server-paper-0.0.1.jar'
            sha256=[string]$Bundle.artifacts.'mcace-server-paper.jar'.sha256
            size=[long]$Bundle.artifacts.'mcace-server-paper.jar'.size_bytes
        }
    }
    $expected = @(Get-ExpectedCaseDefinitions)
    $assets = New-Object 'Collections.Generic.List[object]'
    $assetMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $preparedTrees = New-Object 'Collections.Generic.List[object]'
    $preparedMap = [Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)
    $versionIndex = 0
    foreach ($version in @('1.21.11','26.1.2','26.2')) {
        foreach ($project in @('paper','folia')) {
            $build = [string](1000 + ($versionIndex * 10) + $(if ($project -ceq 'paper') { 1 } else { 2 }))
            $assetHash = Get-BytesSha256 ($utf8NoBom.GetBytes("asset|$project|$version|$build"))
            $assetSize = [long](50000000 + ($versionIndex * 100000) + $(if ($project -ceq 'paper') { 1 } else { 2 }))
            $asset = [pscustomobject][ordered]@{
                project=$project
                version=$version
                build=$build
                sha256=$assetHash
                size=$assetSize
                channel=$(if ($project -ceq 'folia' -and $version -ceq '26.2') { 'BETA' } else { 'STABLE' })
                java_major=$(if ($version -ceq '1.21.11') { 21 } else { 25 })
            }
            [void]$assets.Add($asset)
            $assetMap.Add("$project|$version", $asset)
            $prepared = [pscustomobject][ordered]@{
                project=$project
                version=$version
                build=$build
                server_sha256=$assetHash
                prepared_tree_sha256=(Get-BytesSha256 (
                    $utf8NoBom.GetBytes("prepared|$project|$version|$build")))
                file_count=100 + ($versionIndex * 10) + $(if ($project -ceq 'paper') { 1 } else { 2 })
                total_size=[long](1000000 + ($versionIndex * 10000) + $(if ($project -ceq 'paper') { 1 } else { 2 }))
            }
            [void]$preparedTrees.Add($prepared)
            $preparedMap.Add("$project|$version", $prepared)
        }
        $versionIndex++
    }
    foreach ($proxy in @(
            [pscustomobject]@{ project='velocity'; version='3.5.1-615'; build='615' },
            [pscustomobject]@{ project='bungeecord'; version='2085'; build='2085' })) {
        $asset = [pscustomobject][ordered]@{
            project=$proxy.project
            version=$proxy.version
            build=$proxy.build
            sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes(
                "asset|$($proxy.project)|$($proxy.version)|$($proxy.build)")))
            size=[long]$(if ($proxy.project -ceq 'velocity') { 20000000 } else { 21000000 })
            channel='REVIEWED'
            java_major=21
        }
        [void]$assets.Add($asset)
        $assetMap.Add("$($proxy.project)|$($proxy.version)", $asset)
    }

    $jdk21 = [pscustomobject][ordered]@{
        feature=21
        version='21.0.8'
        java_executable_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('jdk21-java')))
        java_executable_size=123456L
        release_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('jdk21-release')))
        modules_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('jdk21-modules')))
        modules_size=223456L
        jvm_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('jdk21-jvm')))
        jvm_size=323456L
    }
    $jdk25 = [pscustomobject][ordered]@{
        feature=25
        version='25.0.2'
        java_executable_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('jdk25-java')))
        java_executable_size=133456L
        release_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('jdk25-release')))
        modules_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('jdk25-modules')))
        modules_size=233456L
        jvm_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('jdk25-jvm')))
        jvm_size=333456L
    }
    $gradle = [pscustomobject][ordered]@{
        version='9.6.1'
        command_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('gradle-command')))
        launcher_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('gradle-launcher')))
        core_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes('gradle-core')))
        installation_manifest_sha256=(Get-BytesSha256 (
            $utf8NoBom.GetBytes('gradle-installation')))
        installation_file_count=321
        installation_total_size=123456789L
    }

    $definitions = New-Object 'Collections.Generic.List[object]'
    $cases = New-Object 'Collections.Generic.List[object]'
    $generated = [DateTimeOffset]::Parse($GeneratedAt, [Globalization.CultureInfo]::InvariantCulture)
    for ($index = 0; $index -lt $expected.Count; $index++) {
        $item = $expected[$index]
        $backendProject = ([string]$item.backend).ToLowerInvariant()
        $backendAsset = $assetMap["$backendProject|$($item.minecraft_version)"]
        $prepared = $preparedMap["$backendProject|$($item.minecraft_version)"]
        $proxyProject = if ($item.proxy -ceq 'VELOCITY') { 'velocity' } else { 'bungeecord' }
        $proxyVersion = if ($proxyProject -ceq 'velocity') { '3.5.1-615' } else { '2085' }
        $proxyAsset = $assetMap["$proxyProject|$proxyVersion"]
        $serverIdentity = "$($backendAsset.project):$($backendAsset.version):$($backendAsset.build)"
        $proxyIdentity = "$($proxyAsset.project):$($proxyAsset.version):$($proxyAsset.build)"
        [void]$definitions.Add([pscustomobject][ordered]@{
            case_id=$item.case_id
            minecraft_version=$item.minecraft_version
            minecraft_protocol=$item.minecraft_protocol
            server_java_feature=$item.server_java_feature
            backend=$item.backend
            proxy=$item.proxy
            lane=$item.lane
            selector=$item.selector
            server_asset_identity=$serverIdentity
            server_asset_sha256=[string]$backendAsset.sha256
            prepared_tree_sha256=[string]$prepared.prepared_tree_sha256
            proxy_asset_identity=$proxyIdentity
            proxy_asset_sha256=[string]$proxyAsset.sha256
        })
        $proxyProduct = if ($item.proxy -ceq 'VELOCITY') { $products.velocity } else { $products.bungee }
        $started = $generated.AddMinutes(-4).AddSeconds($index * 10)
        $finished = $started.AddSeconds(5)
        [void]$cases.Add([pscustomobject][ordered]@{
            case_id=$item.case_id
            raw_schema=4
            minecraft_version=$item.minecraft_version
            minecraft_protocol=$item.minecraft_protocol
            server_java_feature=$item.server_java_feature
            backend=$item.backend
            proxy=$item.proxy
            lane=$item.lane
            selector=$item.selector
            invocation_started_at=$started.ToString('o')
            invocation_finished_at=$finished.ToString('o')
            execution_mode='EXECUTE'
            invocation_exit_code=0
            invocation_log_sha256=(Get-BytesSha256 ($utf8NoBom.GetBytes("log-$($item.case_id)")))
            raw_report="raw/$($item.case_id).json"
            raw_report_sha256=('0' * 64)
            raw_report_size=1L
            raw_report_last_write_at=$finished.AddSeconds(-1).ToString('o')
            server_asset_identity=$serverIdentity
            proxy_asset_identity=$proxyIdentity
            run_root=[pscustomobject][ordered]@{
                proxy_jar_sha256=[string]$proxyAsset.sha256
                proxy_jar_size=[long]$proxyAsset.size
                backend_jar_sha256=[string]$backendAsset.sha256
                backend_jar_size=[long]$backendAsset.size
                proxy_plugin_sha256=[string]$proxyProduct.sha256
                proxy_plugin_size=[long]$proxyProduct.size
                backend_plugin_sha256=[string]$products.paper.sha256
                backend_plugin_size=[long]$products.paper.size
                prepared_tree_sha256=[string]$prepared.prepared_tree_sha256
                prepared_file_count=[int]$prepared.file_count
                prepared_total_size=[long]$prepared.total_size
            }
            cleanup_process_count=2
            remaining_run_process_count=0
            sensitive_artifact_count=0
            process_cleanup_observed=$true
            passed=$true
        })
    }
    $current = [pscustomobject][ordered]@{
        source_commit=$artifactCommit
        product_version='0.0.1'
        target_versions=@('1.21.11','26.1.2','26.2')
        case_count=12
        source_manifest_sha256=('1' * 64)
        source_file_count=42
        wrapper_sha256=('2' * 64)
        wrapper_test_sha256=('3' * 64)
        runtime_assets_manifest_sha256=('4' * 64)
        prepared_manifest_sha256=('5' * 64)
        assets=$assets.ToArray()
        prepared_trees=$preparedTrees.ToArray()
        root_jdk=$jdk21
        server_jdks=@($jdk21,$jdk25)
        gradle=$gradle
        product_jars=$products
        definitions=$definitions.ToArray()
    }
    $report = [pscustomobject][ordered]@{
        schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4'
        generated_at=$generated.ToString('o')
        source_mode='EXECUTED'
        source_commit=$artifactCommit
        release_source_commit=$releaseCommit
        artifact_source_commit=$artifactCommit
        product_version='0.0.1'
        target_versions=@('1.21.11','26.1.2','26.2')
        expected_case_count=12
        observed_case_count=12
        stable_case_count=10
        beta_case_count=2
        all_cases_passed=$true
        cleanup_all_zero=$true
        raw_manifest_schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1'
        raw_manifest_sha256=('0' * 64)
        raw_manifest_bytes=1L
        ordered_raw_report_set_sha256=('0' * 64)
        case_runtime_commitment_sha256=('0' * 64)
        release_bundle_manifest_sha256=('0' * 64)
        release_bundle_artifact_set_sha256=('0' * 64)
        matrix_product_jar_set_sha256=('0' * 64)
        supervisor_operation_attempt_id=('1' * 32)
        supervisor_challenge_nonce=('2' * 64)
        supervisor_challenge_issued_at=$generated.ToString('o')
        supervisor_receipt_expires_at=$generated.AddMinutes(15).ToString('o')
        supervisor_trust_root_sha256=$trustRootSha256
        supervisor_signer_key_id='matrix-supervisor-test-key-01'
        supervisor_signature_algorithm='RSA_PKCS1_SHA256'
        independent_supervisor_signature_present=$true
        release_eligible=$true
        cases=$cases.ToArray()
    }
    return [pscustomobject]@{ current=$current; report=$report }
}

function Write-MatrixTriplet([object]$Fixture) {
    $tripletRoot=$Fixture.triplet_root
    if(-not(Test-Path -LiteralPath $tripletRoot)){[void][IO.Directory]::CreateDirectory($tripletRoot)}
    foreach($entry in @(Get-ChildItem -LiteralPath $tripletRoot -Force -ErrorAction SilentlyContinue)){
        if($entry.PSIsContainer){[IO.Directory]::Delete($entry.FullName,$true)}else{[IO.File]::Delete($entry.FullName)}
    }
    $rawRoot=Join-Path $tripletRoot 'raw';[void][IO.Directory]::CreateDirectory($rawRoot)
    $rawDescriptors=[Collections.Generic.List[object]]::new();$rawValues=[Collections.Generic.List[object]]::new()
    $cases=@($Fixture.report.cases)
    for($index=0;$index -lt 12;$index++){
        $case=$cases[$index]
        $forwarding=if([string]$case.proxy -ceq 'VELOCITY'){'velocity-modern'}else{'bungee-ip-forwarding'}
        $playId=if([string]$case.minecraft_version -ceq '1.21.11'){'0x30'}else{'0x31'}
        $raw=[pscustomobject][ordered]@{
            schema=4;proxy=[string]$case.proxy;backend_platform=[string]$case.backend
            backend_minecraft_version=[string]$case.minecraft_version;forwarding_mode=$forwarding
            forwarding_configured=$true;proxy_port=(25000+($index*2));backend_port=(25001+($index*2))
            tcp_connected=$true;login_success=$true;compression_seen=$true;configuration_finished=$true
            mcace_server_hello=$true;mcace_auth_result=$true;mcace_auth_accepted=$true
            backend_admission=$true;backend_context_shadow_audit=$true;channels=@('mcace:handshake')
            packet_trace=@("PLAY:$playId");limitations=@()
            cleanup_process_ids=@((1000+($index*2)),(1001+($index*2)));remaining_run_processes=@()
        }
        $rawPath=Join-Path $tripletRoot (([string]$case.raw_report).Replace('/','\'))
        $rawBytes=ConvertTo-CompactJsonBytes $raw;[IO.File]::WriteAllBytes($rawPath,$rawBytes)
        $case.raw_report_sha256=Get-BytesSha256 $rawBytes;$case.raw_report_size=[long]$rawBytes.Length
        [void]$rawValues.Add($raw)
        [void]$rawDescriptors.Add([pscustomobject][ordered]@{
            ordinal=$index+1;case_id=[string]$case.case_id;path=[string]$case.raw_report
            sha256=[string]$case.raw_report_sha256;size_bytes=[long]$case.raw_report_size
            raw_schema=4;minecraft_version=[string]$case.minecraft_version
            backend=[string]$case.backend;proxy=[string]$case.proxy;execution_mode='EXECUTE'
            invocation_exit_code=0;invocation_log_sha256=[string]$case.invocation_log_sha256
            cleanup_process_count=[int]$case.cleanup_process_count;remaining_run_process_count=0
            process_cleanup_observed=$true
        })
    }
    $rawSet=Get-RawSetSha256 $rawDescriptors.ToArray()
    $rawManifest=[pscustomobject][ordered]@{
        schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1'
        generated_at=$Fixture.report.generated_at;source_mode='EXECUTED';source_commit=$artifactCommit
        product_version='0.0.1';case_count=12;ordered_raw_report_set_sha256=$rawSet
        reports=$rawDescriptors.ToArray()
    }
    $rawManifestBytes=ConvertTo-CompactJsonBytes $rawManifest
    [IO.File]::WriteAllBytes((Join-Path $tripletRoot 'raw-manifest.json'),$rawManifestBytes)

    $caseCommitments=[Collections.Generic.List[object]]::new();$processCount=0
    for($caseIndex=0;$caseIndex -lt 12;$caseIndex++){
        $case=$cases[$caseIndex];$raw=@($rawValues)[$caseIndex]
        $processes=[Collections.Generic.List[object]]::new();$ids=@($raw.cleanup_process_ids)
        for($processIndex=0;$processIndex -lt $ids.Count;$processIndex++){
            $role=if($processIndex -eq 0){'PROXY'}else{'BACKEND'}
            $identity=[pscustomobject][ordered]@{
                case_id=[string]$case.case_id;role=$role;process_id=[long]$ids[$processIndex]
                invocation_started_at=[string]$case.invocation_started_at
                invocation_finished_at=[string]$case.invocation_finished_at
                proxy_jar_sha256=[string]$case.run_root.proxy_jar_sha256
                backend_jar_sha256=[string]$case.run_root.backend_jar_sha256
            }
            [void]$processes.Add([pscustomobject][ordered]@{
                role=$role;process_id=[long]$ids[$processIndex]
                process_incarnation_sha256=Get-SetSha256 'MCACE_SERVER_VERSION_PROCESS_MATRIX_PROCESS_INCARNATION_V1' $identity
                cleanup_observed=$true;remaining_process_count=0
            });$processCount++
        }
        [void]$caseCommitments.Add([pscustomobject][ordered]@{
            ordinal=$caseIndex+1;case_id=[string]$case.case_id
            invocation_started_at=[string]$case.invocation_started_at
            invocation_finished_at=[string]$case.invocation_finished_at
            invocation_log_sha256=[string]$case.invocation_log_sha256
            raw_report_sha256=[string]$case.raw_report_sha256
            raw_report_size_bytes=[long]$case.raw_report_size
            cleanup_process_count=[int]$case.cleanup_process_count
            remaining_process_count=0;process_cleanup_observed=$true;processes=$processes.ToArray()
        })
    }
    $caseValues=$caseCommitments.ToArray();$caseSha=Get-SetSha256 'MCACE_SERVER_VERSION_PROCESS_MATRIX_CASE_RUNTIME_SET_V1' $caseValues
    $artifactValues=@($Fixture.bundle.jar_names | Sort-Object | ForEach-Object {$Fixture.bundle.artifacts.([string]$_)})
    $artifactSha=Get-SetSha256 'MCACE_SERVER_VERSION_PROCESS_MATRIX_RELEASE_ARTIFACT_SET_V1' $artifactValues
    $productValues=@(
        [pscustomobject][ordered]@{role='velocity';bundle_file='mcace-server-velocity.jar';matrix_relative=[string]$Fixture.current.product_jars.velocity.relative;sha256=[string]$Fixture.current.product_jars.velocity.sha256;size_bytes=[long]$Fixture.current.product_jars.velocity.size},
        [pscustomobject][ordered]@{role='bungee';bundle_file='mcace-server-bungeecord.jar';matrix_relative=[string]$Fixture.current.product_jars.bungee.relative;sha256=[string]$Fixture.current.product_jars.bungee.sha256;size_bytes=[long]$Fixture.current.product_jars.bungee.size},
        [pscustomobject][ordered]@{role='paper';bundle_file='mcace-server-paper.jar';matrix_relative=[string]$Fixture.current.product_jars.paper.relative;sha256=[string]$Fixture.current.product_jars.paper.sha256;size_bytes=[long]$Fixture.current.product_jars.paper.size})
    $productSha=Get-SetSha256 'MCACE_SERVER_VERSION_PROCESS_MATRIX_PRODUCT_JAR_SET_V1' $productValues
    $manifestPath=Join-Path $Fixture.bundle.root 'release-manifest.properties'
    $sumsPath=Join-Path $Fixture.bundle.root 'SHA256SUMS'
    $manifestBytes=[IO.File]::ReadAllBytes($manifestPath);$sumsBytes=[IO.File]::ReadAllBytes($sumsPath)

    $Fixture.report.raw_manifest_sha256=Get-BytesSha256 $rawManifestBytes
    $Fixture.report.raw_manifest_bytes=[long]$rawManifestBytes.Length
    $Fixture.report.ordered_raw_report_set_sha256=$rawSet
    $Fixture.report.release_source_commit=$releaseCommit
    $Fixture.report.artifact_source_commit=$artifactCommit
    $Fixture.report.case_runtime_commitment_sha256=$caseSha
    $Fixture.report.release_bundle_manifest_sha256=Get-BytesSha256 $manifestBytes
    $Fixture.report.release_bundle_artifact_set_sha256=$artifactSha
    $Fixture.report.matrix_product_jar_set_sha256=$productSha
    $Fixture.report.supervisor_operation_attempt_id=$Fixture.operation_attempt_id
    $Fixture.report.supervisor_challenge_nonce=$Fixture.challenge_nonce
    $Fixture.report.supervisor_challenge_issued_at=$Fixture.report.generated_at
    $Fixture.report.supervisor_receipt_expires_at=(
        [DateTimeOffset]::Parse([string]$Fixture.report.generated_at,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal).AddMinutes(15).ToString('o'))
    $Fixture.report.supervisor_trust_root_sha256=$trustRootSha256
    $Fixture.report.supervisor_signer_key_id='matrix-supervisor-test-key-01'
    $Fixture.report.supervisor_signature_algorithm='RSA_PKCS1_SHA256'
    $Fixture.report.independent_supervisor_signature_present=$true
    $Fixture.report.release_eligible=$true
    $reportBytes=ConvertTo-CompactJsonBytes $Fixture.report
    [IO.File]::WriteAllBytes((Join-Path $tripletRoot 'report.json'),$reportBytes)
    $binding=[pscustomobject][ordered]@{
        schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V4';generated_at=$Fixture.report.generated_at
        report_schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4';report_generated_at=$Fixture.report.generated_at
        report_sha256=(Get-BytesSha256 $reportBytes);report_bytes=[long]$reportBytes.Length
        source_mode='EXECUTED';source_commit=[string]$Fixture.report.source_commit
        release_source_commit=$releaseCommit;artifact_source_commit=$artifactCommit
        product_version=[string]$Fixture.report.product_version
        raw_manifest_schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1'
        raw_manifest_sha256=[string]$Fixture.report.raw_manifest_sha256
        raw_manifest_bytes=[long]$Fixture.report.raw_manifest_bytes
        ordered_raw_report_set_sha256=$rawSet;case_runtime_commitment_sha256=$caseSha
        release_bundle_manifest_sha256=(Get-BytesSha256 $manifestBytes)
        release_bundle_artifact_set_sha256=$artifactSha;matrix_product_jar_set_sha256=$productSha
        supervisor_operation_attempt_id=$Fixture.operation_attempt_id
        supervisor_challenge_nonce=$Fixture.challenge_nonce
        supervisor_challenge_issued_at=$Fixture.report.generated_at
        supervisor_receipt_expires_at=$Fixture.report.supervisor_receipt_expires_at
        supervisor_trust_root_sha256=$trustRootSha256
        supervisor_signer_key_id='matrix-supervisor-test-key-01';supervisor_signature_algorithm='RSA_PKCS1_SHA256'
        current_sha256=(Get-BytesSha256 (ConvertTo-CompactJsonBytes $Fixture.current));current=$Fixture.current
        independent_supervisor_signature_present=$true;release_eligible=$true;passed=$true
    }
    $bindingBytes=ConvertTo-CompactJsonBytes $binding
    [IO.File]::WriteAllBytes((Join-Path $tripletRoot 'binding.json'),$bindingBytes)
    $request=[pscustomobject][ordered]@{
        schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_SIGNING_REQUEST_V1'
        generated_at=$Fixture.report.generated_at;source_mode='EXECUTED_AWAITING_EXTERNAL_SUPERVISOR'
        release_source_commit=$releaseCommit;artifact_source_commit=$artifactCommit;product_version='0.0.1'
        operation_attempt_id=$Fixture.operation_attempt_id;challenge_nonce=$Fixture.challenge_nonce
        challenge_issued_at=$Fixture.report.generated_at;receipt_not_after=$Fixture.report.supervisor_receipt_expires_at
        report_sha256=(Get-BytesSha256 $reportBytes);report_size_bytes=[long]$reportBytes.Length
        binding_sha256=(Get-BytesSha256 $bindingBytes);binding_size_bytes=[long]$bindingBytes.Length
        raw_manifest_sha256=(Get-BytesSha256 $rawManifestBytes);raw_manifest_size_bytes=[long]$rawManifestBytes.Length
        ordered_raw_report_set_sha256=$rawSet;case_runtime_commitment_sha256=$caseSha
        case_count=12;process_identity_count=$processCount;case_runtime_commitments=$caseValues
        release_bundle_schema='MCACE_RELEASE_BUNDLE_V4';release_bundle_manifest_sha256=(Get-BytesSha256 $manifestBytes)
        release_bundle_manifest_size_bytes=[long]$manifestBytes.Length
        release_bundle_sha256s_sha256=(Get-BytesSha256 $sumsBytes)
        release_bundle_sha256s_size_bytes=[long]$sumsBytes.Length
        release_bundle_artifact_set_sha256=$artifactSha;release_bundle_artifact_count=6
        release_bundle_artifacts=$artifactValues;matrix_product_jar_set_sha256=$productSha
        matrix_product_jar_count=3;matrix_product_jars=$productValues
        supervisor_trust_root_sha256=$trustRootSha256;supervisor_signer_key_id='matrix-supervisor-test-key-01'
        signature_algorithm='RSA_PKCS1_SHA256'
    }
    $requestBytes=ConvertTo-CompactJsonBytes $request
    [IO.File]::WriteAllBytes((Join-Path $tripletRoot 'supervisor-signing-request.json'),$requestBytes)
    $now=[DateTimeOffset]::UtcNow
    $expires=[DateTimeOffset]::Parse([string]$request.receipt_not_after,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)
    $signed=if($now -lt $expires){$now}else{$expires.AddSeconds(-1)}
    $receipt=[ordered]@{
        schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_V1'
        artifact_class='EXTERNALLY_SIGNED_MATRIX_SUPERVISOR_RECEIPT';source_mode='EXTERNAL_MATRIX_SUPERVISOR'
        signed_at=$signed.ToString('o');expires_at=[string]$request.receipt_not_after
        release_source_commit=$releaseCommit;artifact_source_commit=$artifactCommit;product_version='0.0.1'
        operation_attempt_id=$Fixture.operation_attempt_id;challenge_nonce=$Fixture.challenge_nonce
        challenge_issued_at=$Fixture.report.generated_at;report_sha256=[string]$request.report_sha256
        report_size_bytes=[long]$request.report_size_bytes;binding_sha256=[string]$request.binding_sha256
        binding_size_bytes=[long]$request.binding_size_bytes;raw_manifest_sha256=[string]$request.raw_manifest_sha256
        raw_manifest_size_bytes=[long]$request.raw_manifest_size_bytes
        ordered_raw_report_set_sha256=$rawSet;case_runtime_commitment_sha256=$caseSha
        case_count=12;process_identity_count=$processCount;release_bundle_schema='MCACE_RELEASE_BUNDLE_V4'
        release_bundle_manifest_sha256=[string]$request.release_bundle_manifest_sha256
        release_bundle_manifest_size_bytes=[long]$request.release_bundle_manifest_size_bytes
        release_bundle_sha256s_sha256=[string]$request.release_bundle_sha256s_sha256
        release_bundle_sha256s_size_bytes=[long]$request.release_bundle_sha256s_size_bytes
        release_bundle_artifact_set_sha256=$artifactSha;release_bundle_artifact_count=6
        matrix_product_jar_set_sha256=$productSha;matrix_product_jar_count=3
        supervisor_independent=$true;signer_key_id='matrix-supervisor-test-key-01'
        signer_trust_root_sha256=$trustRootSha256;signature_algorithm='RSA_PKCS1_SHA256'
        test_fixture=$false;signature_base64=''
    }
    $receipt.signature_base64=[Convert]::ToBase64String($rsa.SignData((Get-ReceiptSigningPayload ([pscustomobject]$receipt)),'SHA256'))
    # The external supervisor's detached receipt is intentionally compact
    # JSON without a trailing newline; all other evidence documents remain
    # newline-terminated.
    $receiptBytes=ConvertTo-CommitmentJsonBytes ([pscustomobject]$receipt)
    [IO.File]::WriteAllBytes((Join-Path $tripletRoot 'supervisor-receipt.json'),$receiptBytes)
    $commit=[pscustomobject][ordered]@{
        schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V4';generated_at=$Fixture.report.generated_at
        report_schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4'
        binding_schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V4'
        report_sha256=(Get-BytesSha256 $reportBytes);report_bytes=[long]$reportBytes.Length
        binding_sha256=(Get-BytesSha256 $bindingBytes);binding_bytes=[long]$bindingBytes.Length
        raw_manifest_schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1'
        raw_manifest_sha256=(Get-BytesSha256 $rawManifestBytes);raw_manifest_bytes=[long]$rawManifestBytes.Length
        ordered_raw_report_set_sha256=$rawSet;source_commit=$artifactCommit
        release_source_commit=$releaseCommit;artifact_source_commit=$artifactCommit;product_version='0.0.1'
        supervisor_signing_request_schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_SIGNING_REQUEST_V1'
        supervisor_signing_request_sha256=(Get-BytesSha256 $requestBytes)
        supervisor_signing_request_bytes=[long]$requestBytes.Length
        supervisor_receipt_schema='MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_V1'
        supervisor_receipt_sha256=(Get-BytesSha256 $receiptBytes);supervisor_receipt_bytes=[long]$receiptBytes.Length
        supervisor_operation_attempt_id=$Fixture.operation_attempt_id
        supervisor_challenge_nonce=$Fixture.challenge_nonce;supervisor_trust_root_sha256=$trustRootSha256
        independent_supervisor_signature_present=$true;release_eligible=$true;committed=$true
    }
    Write-CompactJson (Join-Path $tripletRoot 'commit.json') $commit
    $Fixture | Add-Member -Force -NotePropertyName binding -NotePropertyValue $binding
    $Fixture | Add-Member -Force -NotePropertyName commit -NotePropertyValue $commit
    $Fixture | Add-Member -Force -NotePropertyName signing_request -NotePropertyValue $request
    $Fixture | Add-Member -Force -NotePropertyName receipt -NotePropertyValue ([pscustomobject]$receipt)
}

function New-Fixture(
        [string]$Name,
        [string]$GeneratedAt = ([DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o'))) {
    $root = Join-Path $testRoot $Name
    [void][IO.Directory]::CreateDirectory($root)
    $bundle = New-ReleaseBundle (Join-Path $root 'release-bundle')
    $objects = New-MatrixObjects $bundle $GeneratedAt
    $fixture = [pscustomobject]@{
        root=$root
        output_root=(Join-Path $root 'published')
        triplet_root=(Join-Path $root 'matrix-triplet')
        bundle=$bundle
        current=$objects.current
        report=$objects.report
        operation_attempt_id=[Guid]::NewGuid().ToString('N')
        challenge_nonce=(Get-BytesSha256 ($utf8NoBom.GetBytes([Guid]::NewGuid().ToString('N'))))
    }
    Write-MatrixTriplet $fixture
    return $fixture
}

function Get-PublisherArguments([object]$Fixture, [string]$Id) {
    return @{
        ReportPath=(Join-Path $Fixture.triplet_root 'report.json')
        BindingPath=(Join-Path $Fixture.triplet_root 'binding.json')
        CommitPath=(Join-Path $Fixture.triplet_root 'commit.json')
        ReleaseBundleRoot=$Fixture.bundle.root
        ArtifactSourceCommit=$artifactCommit
        SupervisorTrustRootPath=$trustRootPath
        ExpectedSupervisorTrustRootSha256=$trustRootSha256
        OutputRoot=$Fixture.output_root
        EvidenceId=$Id
    }
}

function Invoke-ExpectedFailure([scriptblock]$Action, [string]$ExpectedCode) {
    $script:negativeCount++
    try {
        & $Action | Out-Null
        throw "EXPECTED_FAILURE_NOT_THROWN|$ExpectedCode"
    } catch {
        if ($_.Exception.Message -notlike "*$ExpectedCode*") {
            throw "WRONG_FAILURE|expected=$ExpectedCode|actual=$($_.Exception.Message)"
        }
    }
}

function Read-JsonCompat([string]$Path) {
    $raw = [IO.File]::ReadAllText($Path, [Text.UTF8Encoding]::new($false,$true))
    $command = Get-Command ConvertFrom-Json -CommandType Cmdlet -ErrorAction Stop
    if ($command.Parameters.ContainsKey('DateKind')) {
        return ConvertFrom-Json -InputObject $raw -DateKind String
    }
    return ConvertFrom-Json -InputObject $raw
}

if (-not (Test-Path -LiteralPath $publisher -PathType Leaf)) {
    throw 'MATRIX_PUBLISHER_SCRIPT_MISSING'
}

$source = [IO.File]::ReadAllText($publisher)
foreach ($token in @(
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V4',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_BINDING_V4',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_COMMIT_V4',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_SIGNING_REQUEST_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_SUPERVISOR_RECEIPT_V1',
        'MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_RAW_MANIFEST_V1',
        'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4',
        'MCACE_RELEASE_BUNDLE_V4',
        'MCACE_MATRIX_PUBLISH_DUPLICATE_OR_CASE_AMBIGUOUS_CASE',
        'MCACE_MATRIX_PUBLISH_DIVERGENT_IMMUTABLE_EVIDENCE_ID',
        'MCACE_MATRIX_PUBLISH_REPARSE_PATH_REJECTED',
        'MCACE_MATRIX_PUBLISH_ASSET_DUPLICATE',
        'MCACE_MATRIX_PUBLISH_BACKEND_ASSET_IDENTITY_INVALID',
        'MCACE_MATRIX_PUBLISH_PREPARED_TREE_ASSET_MISMATCH',
        'MCACE_MATRIX_PUBLISH_ROOT_JDK_MISMATCH',
        'MCACE_MATRIX_PUBLISH_GRADLE_INVALID',
        'MCACE_MATRIX_PUBLISH_DEFINITION_NATIVE_CROSS_BINDING_INVALID',
        'MCACE_MATRIX_PUBLISH_CASE_NATIVE_CROSS_BINDING_INVALID',
        'MCACE_MATRIX_PUBLISH_RELEASE_PRODUCT_CROSS_BINDING_INVALID',
        '[IO.Directory]::Move')) {
    Assert-True ($source.Contains($token)) "missing static hardening token: $token"
}

[void][IO.Directory]::CreateDirectory($testRoot)
try {
    $rsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048)
    $rsa.PersistKeyInCsp=$false
    $public=$rsa.ExportParameters($false)
    $trustDirectory=Join-Path $testRoot 'external-supervisor-trust'
    [void][IO.Directory]::CreateDirectory($trustDirectory)
    $trustRootPath=Join-Path $trustDirectory 'matrix-supervisor-trust-root.json'
    $trustRoot=[pscustomobject][ordered]@{
        schema='MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1'
        artifact_class='OUT_OF_BAND_PINNED_MATRIX_SUPERVISOR_TRUST_ROOT'
        key_id='matrix-supervisor-test-key-01';algorithm='RSA_PKCS1_SHA256'
        modulus_base64=[Convert]::ToBase64String($public.Modulus)
        exponent_base64=[Convert]::ToBase64String($public.Exponent);test_fixture=$false
    }
    Write-CommitmentJson $trustRootPath $trustRoot
    $trustRootSha256=Get-FileSha256 $trustRootPath
    $env:MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256=$trustRootSha256
    $positive = New-Fixture 'positive'
    $positiveReceiptPath = Join-Path $positive.triplet_root 'supervisor-receipt.json'
    $positiveReceiptBytes = [IO.File]::ReadAllBytes($positiveReceiptPath)
    Assert-True ($positiveReceiptBytes.Length -gt 0 -and
        $positiveReceiptBytes[$positiveReceiptBytes.Length - 1] -eq 0x7d) `
        'positive detached receipt must be compact JSON without a trailing LF'
    $evidenceId = 'server-version-process-matrix-positive'
    $arguments = Get-PublisherArguments $positive $evidenceId
    $result = @(& $publisher @arguments)
    Assert-True ($result.Count -eq 1 -and
        [string]$result[0] -like 'MCACE_SERVER_VERSION_MATRIX_EVIDENCE_PUBLISHED*') `
        'positive publisher result missing'
    $publishedDirectory = Join-Path (Join-Path $positive.output_root 'server-version-process-matrix') $evidenceId
    $publishedIndexPath = Join-Path $positive.output_root ($evidenceId + '.json')
    Assert-True (Test-Path -LiteralPath $publishedIndexPath -PathType Leaf) 'tracked index missing'
    Assert-True (Test-Path -LiteralPath $publishedDirectory -PathType Container) 'native directory missing'
    $publishedFiles = @(Get-ChildItem -LiteralPath $publishedDirectory -Force)
    Assert-True ($publishedFiles.Count -eq 7 -and
        ((@($publishedFiles.Name | Sort-Object) -join '|') -ceq
            'binding.json|commit.json|raw|raw-manifest.json|report.json|supervisor-receipt.json|supervisor-signing-request.json')) `
        'published native exact package invalid'
    $index = Read-JsonCompat $publishedIndexPath
    Assert-True ([string]$index.schema -ceq 'MCACE_SERVER_VERSION_PROCESS_MATRIX_EVIDENCE_INDEX_V4') `
        'index schema mismatch'
    Assert-True ([string]$index.source_commit -ceq $releaseCommit -and
        [bool]$index.release_eligible -and
        [bool]$index.independent_supervisor_signature_present) `
        'signed index was not promoted or source commit was not cross-bound'
    Assert-True ([string]$index.artifact_source_commit -ceq $artifactCommit) `
        'index artifact source commit mismatch'
    Assert-True (@($index.release_bundle.artifacts).Count -eq 6) 'index six-artifact binding missing'
    Assert-True (@($index.matrix_product_jars).Count -eq 3) 'index three matrix products missing'
    foreach ($role in @('report','binding','commit','raw_manifest','signing_request',
            'supervisor_receipt')) {
        $descriptor = $index.canonical_evidence.$role
        $path = Join-Path $positive.output_root (([string]$descriptor.path).Replace('/','\'))
        Assert-True ([string]$descriptor.sha256 -ceq (Get-FileSha256 $path)) `
            "published descriptor hash mismatch: $role"
        Assert-True ([long]$descriptor.size_bytes -eq (Get-Item -LiteralPath $path).Length) `
            "published descriptor size mismatch: $role"
    }
    Assert-True (@($index.canonical_evidence.raw_reports).Count -eq 12) `
        'published raw report descriptor set missing'
    $allPublishedRaw = @(
        [IO.File]::ReadAllText($publishedIndexPath),
        [IO.File]::ReadAllText((Join-Path $publishedDirectory 'report.json')),
        [IO.File]::ReadAllText((Join-Path $publishedDirectory 'binding.json')),
        [IO.File]::ReadAllText((Join-Path $publishedDirectory 'commit.json'))) -join "`n"
    Assert-True (-not $allPublishedRaw.Contains($testRoot)) 'absolute test root leaked to output'
    Assert-True ($allPublishedRaw -notmatch '(?i)password|passwd|worker.?credential') `
        'secret-bearing text leaked to output'

    # An identical immutable evidence set may be repaired/replaced only with -Force.
    $forcedResult = @(& $publisher @arguments -Force)
    Assert-True ($forcedResult.Count -eq 1) 'identical force publication failed'
    Invoke-ExpectedFailure { & $publisher @arguments } 'MCACE_MATRIX_PUBLISH_DESTINATION_EXISTS'

    # Historical V1 durable evidence may be compact JSON without a trailing
    # LF.  It is not a V4 replay index and must not prevent a new V4 package
    # from being published into the same evidence root.
    $legacyIndexPath = Join-Path $positive.output_root `
        'server-version-process-matrix-legacy-v1.json'
    [IO.File]::WriteAllText($legacyIndexPath,
        '{"schema":"MCACE_SERVER_VERSION_PROCESS_MATRIX_DURABLE_EVIDENCE_V1"}',
        $utf8NoBom)
    $legacyCompatible = New-Fixture 'legacy-index-compat'
    $legacyCompatible.output_root = $positive.output_root
    $legacyCompatibleArgs = Get-PublisherArguments $legacyCompatible `
        'server-version-process-matrix-legacy-index-compat'
    $legacyCompatibleResult = @(& $publisher @legacyCompatibleArgs)
    Assert-True ($legacyCompatibleResult.Count -eq 1 -and
        [string]$legacyCompatibleResult[0] -like
            'MCACE_SERVER_VERSION_MATRIX_EVIDENCE_PUBLISHED*') `
        'valid legacy V1 index blocked V4 publication'

    $replayArgs = Get-PublisherArguments $positive `
        'server-version-process-matrix-replayed-supervisor-receipt'
    Invoke-ExpectedFailure { & $publisher @replayArgs } `
        'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_REPLAY_REJECTED'

    $trailingReceipt = New-Fixture 'trailing-supervisor-receipt'
    Write-CompactJson (Join-Path $trailingReceipt.triplet_root 'supervisor-receipt.json') `
        $trailingReceipt.receipt
    $trailingReceiptArgs = Get-PublisherArguments $trailingReceipt `
        'server-version-process-matrix-trailing-supervisor-receipt'
    Invoke-ExpectedFailure { & $publisher @trailingReceiptArgs } `
        'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_NONCANONICAL'

    $badSignature = New-Fixture 'bad-supervisor-signature'
    $badSignature.receipt.signature_base64 = [Convert]::ToBase64String((New-ByteArray 256 41))
    Write-CommitmentJson (Join-Path $badSignature.triplet_root 'supervisor-receipt.json') `
        $badSignature.receipt
    $badSignatureArgs = Get-PublisherArguments $badSignature `
        'server-version-process-matrix-bad-supervisor-signature'
    Invoke-ExpectedFailure { & $publisher @badSignatureArgs } `
        'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_SIGNATURE_INVALID'

    $fixtureReceipt = New-Fixture 'fixture-supervisor-receipt'
    $fixtureReceipt.receipt.test_fixture = $true
    Write-CommitmentJson (Join-Path $fixtureReceipt.triplet_root 'supervisor-receipt.json') `
        $fixtureReceipt.receipt
    $fixtureReceiptArgs = Get-PublisherArguments $fixtureReceipt `
        'server-version-process-matrix-fixture-supervisor-receipt'
    Invoke-ExpectedFailure { & $publisher @fixtureReceiptArgs } `
        'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_PROVENANCE_INVALID'

    $expiredReceipt = New-Fixture 'expired-supervisor-receipt'
    $expiredReceipt.receipt.expires_at = [DateTimeOffset]::UtcNow.AddMinutes(-1).ToString('o')
    Write-CommitmentJson (Join-Path $expiredReceipt.triplet_root 'supervisor-receipt.json') `
        $expiredReceipt.receipt
    $expiredReceiptArgs = Get-PublisherArguments $expiredReceipt `
        'server-version-process-matrix-expired-supervisor-receipt'
    Invoke-ExpectedFailure { & $publisher @expiredReceiptArgs } `
        'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_EXPIRED_OR_TIME_INVALID'

    $selfRoot = New-Fixture 'self-supervisor-root'
    $selfRootArgs = Get-PublisherArguments $selfRoot `
        'server-version-process-matrix-self-supervisor-root'
    $selfRootArgs.SupervisorTrustRootPath = Join-Path $selfRoot.triplet_root 'report.json'
    Invoke-ExpectedFailure { & $publisher @selfRootArgs } `
        'MCACE_MATRIX_PUBLISH_SELF_SUPERVISOR_TRUST_ROOT_REJECTED'

    $unapprovedRoot = New-Fixture 'unapproved-supervisor-root'
    $unapprovedRsa=[Security.Cryptography.RSACryptoServiceProvider]::new(2048)
    try {
        $unapprovedRsa.PersistKeyInCsp=$false
        $unapprovedPublic=$unapprovedRsa.ExportParameters($false)
        $unapprovedPath=Join-Path $testRoot 'unapproved-supervisor-root.json'
        Write-CompactJson $unapprovedPath ([pscustomobject][ordered]@{
            schema='MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1'
            artifact_class='OUT_OF_BAND_PINNED_MATRIX_SUPERVISOR_TRUST_ROOT'
            key_id='unapproved-matrix-supervisor-key';algorithm='RSA_PKCS1_SHA256'
            modulus_base64=[Convert]::ToBase64String($unapprovedPublic.Modulus)
            exponent_base64=[Convert]::ToBase64String($unapprovedPublic.Exponent);test_fixture=$false
        })
        $unapprovedArgs=Get-PublisherArguments $unapprovedRoot `
            'server-version-process-matrix-unapproved-supervisor-root'
        $unapprovedArgs.SupervisorTrustRootPath=$unapprovedPath
        $unapprovedArgs.ExpectedSupervisorTrustRootSha256=Get-FileSha256 $unapprovedPath
        Invoke-ExpectedFailure { & $publisher @unapprovedArgs } `
            'MCACE_MATRIX_PUBLISH_SUPERVISOR_PIN_NOT_APPROVED'
    } finally { $unapprovedRsa.Dispose() }

    $fixtureRoot = New-Fixture 'fixture-supervisor-root'
    $fixtureRootPath=Join-Path $testRoot 'fixture-supervisor-root.json'
    $publicFixture=$rsa.ExportParameters($false)
    Write-CompactJson $fixtureRootPath ([pscustomobject][ordered]@{
        schema='MCACE_SERVER_VERSION_MATRIX_SUPERVISOR_TRUST_ROOT_V1'
        artifact_class='TEST_MATRIX_SUPERVISOR_TRUST_ROOT_FIXTURE'
        key_id='matrix-supervisor-test-key-01';algorithm='RSA_PKCS1_SHA256'
        modulus_base64=[Convert]::ToBase64String($publicFixture.Modulus)
        exponent_base64=[Convert]::ToBase64String($publicFixture.Exponent);test_fixture=$true
    })
    $fixtureRootHash=Get-FileSha256 $fixtureRootPath
    $oldApprovedPin=$env:MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256
    try {
        $env:MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256=$fixtureRootHash
        $fixtureRootArgs=Get-PublisherArguments $fixtureRoot `
            'server-version-process-matrix-fixture-supervisor-root'
        $fixtureRootArgs.SupervisorTrustRootPath=$fixtureRootPath
        $fixtureRootArgs.ExpectedSupervisorTrustRootSha256=$fixtureRootHash
        Invoke-ExpectedFailure { & $publisher @fixtureRootArgs } `
            'MCACE_MATRIX_PUBLISH_SUPERVISOR_TRUST_ROOT_INVALID'
    } finally {
        $env:MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256=$oldApprovedPin
    }

    $extra = New-Fixture 'extra-input'
    [IO.File]::WriteAllText((Join-Path $extra.triplet_root 'extra.txt'),'x',$utf8NoBom)
    $extraArgs = Get-PublisherArguments $extra 'server-version-process-matrix-extra-input'
    Invoke-ExpectedFailure { & $publisher @extraArgs } 'MCACE_MATRIX_PUBLISH_EXACT_PACKAGE_REQUIRED'

    # The former V2 positive shape (only self-asserted 12/12 hashes, no original raw
    # reports) is now a terminal negative.
    $manualTwelve = New-Fixture 'manual-twelve-without-raw'
    [IO.Directory]::Delete((Join-Path $manualTwelve.triplet_root 'raw'),$true)
    [IO.File]::Delete((Join-Path $manualTwelve.triplet_root 'raw-manifest.json'))
    $manualArgs = Get-PublisherArguments $manualTwelve `
        'server-version-process-matrix-manual-twelve-without-raw'
    Invoke-ExpectedFailure { & $publisher @manualArgs } 'MCACE_MATRIX_PUBLISH_EXACT_PACKAGE_REQUIRED'

    $legacyV2 = New-Fixture 'legacy-v2'
    $legacyV2.report.schema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V2'
    Write-MatrixTriplet $legacyV2
    $legacyArgs = Get-PublisherArguments $legacyV2 'server-version-process-matrix-legacy-v2'
    Invoke-ExpectedFailure { & $publisher @legacyArgs } 'MCACE_MATRIX_PUBLISH_REPORT_INVALID'

    $legacyV3 = New-Fixture 'legacy-v3'
    $legacyV3.report.schema = 'MCACE_SERVER_VERSION_PROCESS_MATRIX_REPORT_V3'
    Write-MatrixTriplet $legacyV3
    $legacyV3Args = Get-PublisherArguments $legacyV3 'server-version-process-matrix-legacy-v3'
    Invoke-ExpectedFailure { & $publisher @legacyV3Args } 'MCACE_MATRIX_PUBLISH_REPORT_INVALID'

    $missingRaw = New-Fixture 'missing-one-raw'
    [IO.File]::Delete((Join-Path $missingRaw.triplet_root `
        (([string]$missingRaw.report.cases[0].raw_report).Replace('/','\'))))
    $missingRawArgs = Get-PublisherArguments $missingRaw 'server-version-process-matrix-missing-one-raw'
    Invoke-ExpectedFailure { & $publisher @missingRawArgs } `
        'MCACE_MATRIX_PUBLISH_RAW_EXACT_12_FILES_REQUIRED'

    $syntheticRaw = New-Fixture 'synthetic-raw-marker'
    $syntheticPath = Join-Path $syntheticRaw.triplet_root `
        (([string]$syntheticRaw.report.cases[0].raw_report).Replace('/','\'))
    $syntheticObject = Read-JsonCompat $syntheticPath
    $syntheticObject.channels = @('mcace:handshake','test_fixture')
    Write-CompactJson $syntheticPath $syntheticObject
    $syntheticArgs = Get-PublisherArguments $syntheticRaw 'server-version-process-matrix-synthetic-raw'
    Invoke-ExpectedFailure { & $publisher @syntheticArgs } `
        'MCACE_MATRIX_PUBLISH_SYNTHETIC_EVIDENCE_REJECTED'

    $reportFalse = New-Fixture 'report-false'
    $reportFalse.report.all_cases_passed = $false
    Write-MatrixTriplet $reportFalse
    $reportFalseArgs = Get-PublisherArguments $reportFalse 'server-version-process-matrix-report-false'
    Invoke-ExpectedFailure { & $publisher @reportFalseArgs } 'MCACE_MATRIX_PUBLISH_REPORT_INVALID'

    $callerPromotion = New-Fixture 'self-supervisor-claim'
    $callerPromotion.receipt.supervisor_independent = $false
    Write-CommitmentJson (Join-Path $callerPromotion.triplet_root 'supervisor-receipt.json') `
        $callerPromotion.receipt
    $callerPromotionArgs = Get-PublisherArguments $callerPromotion `
        'server-version-process-matrix-self-supervisor-claim'
    Invoke-ExpectedFailure { & $publisher @callerPromotionArgs } `
        'MCACE_MATRIX_PUBLISH_SUPERVISOR_RECEIPT_PROVENANCE_INVALID'

    $cleanupFalse = New-Fixture 'cleanup-false'
    $cleanupFalse.report.cleanup_all_zero = $false
    Write-MatrixTriplet $cleanupFalse
    $cleanupFalseArgs = Get-PublisherArguments $cleanupFalse 'server-version-process-matrix-cleanup-false'
    Invoke-ExpectedFailure { & $publisher @cleanupFalseArgs } 'MCACE_MATRIX_PUBLISH_REPORT_INVALID'

    $observed = New-Fixture 'observed-eleven'
    $observed.report.observed_case_count = 11
    Write-MatrixTriplet $observed
    $observedArgs = Get-PublisherArguments $observed 'server-version-process-matrix-observed-eleven'
    Invoke-ExpectedFailure { & $publisher @observedArgs } 'MCACE_MATRIX_PUBLISH_REPORT_INVALID'

    $duplicate = New-Fixture 'duplicate-case'
    $duplicate.report.cases[11].case_id = [string]$duplicate.report.cases[0].case_id
    Write-MatrixTriplet $duplicate
    $duplicateArgs = Get-PublisherArguments $duplicate 'server-version-process-matrix-duplicate-case'
    Invoke-ExpectedFailure { & $publisher @duplicateArgs } `
        'MCACE_MATRIX_PUBLISH_DUPLICATE_OR_CASE_AMBIGUOUS_CASE'

    $caseAmbiguous = New-Fixture 'case-ambiguous'
    $caseAmbiguous.report.cases[11].case_id = ([string]$caseAmbiguous.report.cases[0].case_id).ToUpperInvariant()
    Write-MatrixTriplet $caseAmbiguous
    $caseAmbiguousArgs = Get-PublisherArguments $caseAmbiguous 'server-version-process-matrix-case-ambiguous'
    Invoke-ExpectedFailure { & $publisher @caseAmbiguousArgs } `
        'MCACE_MATRIX_PUBLISH_DUPLICATE_OR_CASE_AMBIGUOUS_CASE'

    $retained = New-Fixture 'retained-process'
    $retained.report.cases[0].remaining_run_process_count = 1
    Write-MatrixTriplet $retained
    $retainedArgs = Get-PublisherArguments $retained 'server-version-process-matrix-retained-process'
    Invoke-ExpectedFailure { & $publisher @retainedArgs } 'MCACE_MATRIX_PUBLISH_CASE_INVALID'

    $absolute = New-Fixture 'absolute-path'
    $absolute.report.cases[0].raw_report = 'C:/worker/password/report.json'
    # Preserve the already-created raw package; only tamper the summary so the
    # publisher must reject the absolute caller-supplied path before hash trust.
    Write-CompactJson (Join-Path $absolute.triplet_root 'report.json') $absolute.report
    $absoluteArgs = Get-PublisherArguments $absolute 'server-version-process-matrix-absolute-path'
    Invoke-ExpectedFailure { & $publisher @absoluteArgs } 'MCACE_MATRIX_PUBLISH_ABSOLUTE_PATH_REJECTED'

    $sourceMismatch = New-Fixture 'source-mismatch'
    $sourceMismatch.report.source_commit = ('c' * 40)
    Write-MatrixTriplet $sourceMismatch
    $sourceMismatchArgs = Get-PublisherArguments $sourceMismatch 'server-version-process-matrix-source-mismatch'
    Invoke-ExpectedFailure { & $publisher @sourceMismatchArgs } 'MCACE_MATRIX_PUBLISH_REPORT_INVALID'

    $productVersionMismatch = New-Fixture 'product-version-mismatch'
    $productVersionMismatch.report.product_version = '0.0.2'
    Write-MatrixTriplet $productVersionMismatch
    $versionArgs = Get-PublisherArguments $productVersionMismatch 'server-version-process-matrix-version-mismatch'
    Invoke-ExpectedFailure { & $publisher @versionArgs } 'MCACE_MATRIX_PUBLISH_REPORT_INVALID'

    $bindingBytes = New-Fixture 'binding-bytes'
    $bindingBytes.binding.report_bytes = [long]$bindingBytes.binding.report_bytes + 1
    Write-CompactJson (Join-Path $bindingBytes.triplet_root 'binding.json') $bindingBytes.binding
    $bindingBytesArgs = Get-PublisherArguments $bindingBytes 'server-version-process-matrix-binding-bytes'
    Invoke-ExpectedFailure { & $publisher @bindingBytesArgs } 'MCACE_MATRIX_PUBLISH_BINDING_INVALID'

    $currentHash = New-Fixture 'current-hash'
    $currentHash.binding.current_sha256 = ('f' * 64)
    Write-CompactJson (Join-Path $currentHash.triplet_root 'binding.json') $currentHash.binding
    $currentHashArgs = Get-PublisherArguments $currentHash 'server-version-process-matrix-current-hash'
    Invoke-ExpectedFailure { & $publisher @currentHashArgs } 'MCACE_MATRIX_PUBLISH_CURRENT_HASH_INVALID'

    # Native/current is a complete provenance graph, not a count-only publication
    # wrapper. Keep these fixtures internally self-consistent so each negative proves
    # that the publisher itself rejects a weakened native binding.
    $scalarTargets = New-Fixture 'current-scalar-targets'
    $scalarTargets.current.target_versions = '1.21.11,26.1.2,26.2'
    Write-MatrixTriplet $scalarTargets
    $scalarTargetsArgs = Get-PublisherArguments $scalarTargets `
        'server-version-process-matrix-current-scalar-targets'
    Invoke-ExpectedFailure { & $publisher @scalarTargetsArgs } `
        'MCACE_MATRIX_PUBLISH_CURRENT_BINDING_INVALID'

    $shortAssets = New-Fixture 'current-seven-assets'
    $shortAssets.current.assets = @($shortAssets.current.assets | Select-Object -First 7)
    Write-MatrixTriplet $shortAssets
    $shortAssetsArgs = Get-PublisherArguments $shortAssets `
        'server-version-process-matrix-current-seven-assets'
    Invoke-ExpectedFailure { & $publisher @shortAssetsArgs } `
        'MCACE_MATRIX_PUBLISH_CURRENT_BINDING_INVALID'

    $duplicateAsset = New-Fixture 'current-duplicate-asset'
    $duplicateAsset.current.assets[7].project = [string]$duplicateAsset.current.assets[6].project
    $duplicateAsset.current.assets[7].version = [string]$duplicateAsset.current.assets[6].version
    Write-MatrixTriplet $duplicateAsset
    $duplicateAssetArgs = Get-PublisherArguments $duplicateAsset `
        'server-version-process-matrix-current-duplicate-asset'
    Invoke-ExpectedFailure { & $publisher @duplicateAssetArgs } `
        'MCACE_MATRIX_PUBLISH_ASSET_DUPLICATE'

    $assetPolicy = New-Fixture 'current-backend-asset-policy'
    $assetPolicy.current.assets[0].java_major = 25
    Write-MatrixTriplet $assetPolicy
    $assetPolicyArgs = Get-PublisherArguments $assetPolicy `
        'server-version-process-matrix-current-backend-asset-policy'
    Invoke-ExpectedFailure { & $publisher @assetPolicyArgs } `
        'MCACE_MATRIX_PUBLISH_BACKEND_ASSET_IDENTITY_INVALID'

    $shortPrepared = New-Fixture 'current-five-prepared-trees'
    $shortPrepared.current.prepared_trees = @(
        $shortPrepared.current.prepared_trees | Select-Object -First 5)
    Write-MatrixTriplet $shortPrepared
    $shortPreparedArgs = Get-PublisherArguments $shortPrepared `
        'server-version-process-matrix-current-five-prepared-trees'
    Invoke-ExpectedFailure { & $publisher @shortPreparedArgs } `
        'MCACE_MATRIX_PUBLISH_CURRENT_BINDING_INVALID'

    $preparedAsset = New-Fixture 'current-prepared-asset-cross-binding'
    $preparedAsset.current.prepared_trees[0].server_sha256 = ('d' * 64)
    Write-MatrixTriplet $preparedAsset
    $preparedAssetArgs = Get-PublisherArguments $preparedAsset `
        'server-version-process-matrix-current-prepared-asset-cross-binding'
    Invoke-ExpectedFailure { & $publisher @preparedAssetArgs } `
        'MCACE_MATRIX_PUBLISH_PREPARED_TREE_ASSET_MISMATCH'

    $shortJdks = New-Fixture 'current-one-server-jdk'
    $shortJdks.current.server_jdks = @($shortJdks.current.server_jdks[0])
    Write-MatrixTriplet $shortJdks
    $shortJdksArgs = Get-PublisherArguments $shortJdks `
        'server-version-process-matrix-current-one-server-jdk'
    Invoke-ExpectedFailure { & $publisher @shortJdksArgs } `
        'MCACE_MATRIX_PUBLISH_CURRENT_BINDING_INVALID'

    $rootJdk = New-Fixture 'current-root-jdk-mismatch'
    $rootJdk.current.root_jdk = $rootJdk.current.server_jdks[1]
    Write-MatrixTriplet $rootJdk
    $rootJdkArgs = Get-PublisherArguments $rootJdk `
        'server-version-process-matrix-current-root-jdk-mismatch'
    Invoke-ExpectedFailure { & $publisher @rootJdkArgs } `
        'MCACE_MATRIX_PUBLISH_ROOT_JDK_MISMATCH'

    $gradle = New-Fixture 'current-gradle-version'
    $gradle.current.gradle.version = '9.6'
    Write-MatrixTriplet $gradle
    $gradleArgs = Get-PublisherArguments $gradle `
        'server-version-process-matrix-current-gradle-version'
    Invoke-ExpectedFailure { & $publisher @gradleArgs } `
        'MCACE_MATRIX_PUBLISH_GRADLE_INVALID'

    $shortDefinitions = New-Fixture 'current-eleven-definitions'
    $shortDefinitions.current.definitions = @(
        $shortDefinitions.current.definitions | Select-Object -First 11)
    Write-MatrixTriplet $shortDefinitions
    $shortDefinitionsArgs = Get-PublisherArguments $shortDefinitions `
        'server-version-process-matrix-current-eleven-definitions'
    Invoke-ExpectedFailure { & $publisher @shortDefinitionsArgs } `
        'MCACE_MATRIX_PUBLISH_CURRENT_BINDING_INVALID'

    $typedDefinition = New-Fixture 'current-definition-string-protocol'
    $typedDefinition.current.definitions[0].minecraft_protocol = '774'
    Write-MatrixTriplet $typedDefinition
    $typedDefinitionArgs = Get-PublisherArguments $typedDefinition `
        'server-version-process-matrix-current-definition-string-protocol'
    Invoke-ExpectedFailure { & $publisher @typedDefinitionArgs } `
        'MCACE_MATRIX_PUBLISH_DEFINITION_INVALID'

    $definitionNative = New-Fixture 'current-definition-native-cross-binding'
    $definitionNative.current.definitions[0].server_asset_sha256 = ('c' * 64)
    Write-MatrixTriplet $definitionNative
    $definitionNativeArgs = Get-PublisherArguments $definitionNative `
        'server-version-process-matrix-current-definition-native-cross-binding'
    Invoke-ExpectedFailure { & $publisher @definitionNativeArgs } `
        'MCACE_MATRIX_PUBLISH_DEFINITION_NATIVE_CROSS_BINDING_INVALID'

    $caseNative = New-Fixture 'current-case-native-cross-binding'
    $caseNative.report.cases[0].run_root.backend_jar_size = `
        [long]$caseNative.report.cases[0].run_root.backend_jar_size + 1
    Write-MatrixTriplet $caseNative
    $caseNativeArgs = Get-PublisherArguments $caseNative `
        'server-version-process-matrix-current-case-native-cross-binding'
    Invoke-ExpectedFailure { & $publisher @caseNativeArgs } `
        'MCACE_MATRIX_PUBLISH_CASE_NATIVE_CROSS_BINDING_INVALID'

    $commitHash = New-Fixture 'commit-hash'
    $commitHash.commit.binding_sha256 = ('e' * 64)
    Write-CompactJson (Join-Path $commitHash.triplet_root 'commit.json') $commitHash.commit
    $commitHashArgs = Get-PublisherArguments $commitHash 'server-version-process-matrix-commit-hash'
    Invoke-ExpectedFailure { & $publisher @commitHashArgs } 'MCACE_MATRIX_PUBLISH_COMMIT_INVALID'

    $productMismatch = New-Fixture 'product-cross-binding'
    $newVelocityHash = ('d' * 64)
    $productMismatch.current.product_jars.velocity.sha256 = $newVelocityHash
    foreach ($case in @($productMismatch.report.cases | Where-Object proxy -eq 'VELOCITY')) {
        $case.run_root.proxy_plugin_sha256 = $newVelocityHash
    }
    Write-MatrixTriplet $productMismatch
    $productMismatchArgs = Get-PublisherArguments $productMismatch 'server-version-process-matrix-product-mismatch'
    Invoke-ExpectedFailure { & $publisher @productMismatchArgs } `
        'MCACE_MATRIX_PUBLISH_RELEASE_PRODUCT_CROSS_BINDING_INVALID'

    # A caller cannot bless an arbitrary byte array merely by recomputing every
    # surrounding SHA-256.  The three server products must be real JAR/ZIP files
    # containing their reviewed MCAce plugin entry point.
    $fakeJar = New-Fixture 'manual-byte-array-jar'
    $fakePaperPath = Join-Path $fakeJar.bundle.root 'mcace-server-paper.jar'
    $oldPaperHash = [string]$fakeJar.bundle.artifacts.'mcace-server-paper.jar'.sha256
    $fakePaperBytes = New-ByteArray 4096 77
    [IO.File]::WriteAllBytes($fakePaperPath,$fakePaperBytes)
    $fakePaperHash = Get-BytesSha256 $fakePaperBytes
    $fakeJar.current.product_jars.paper.sha256 = $fakePaperHash
    $fakeJar.current.product_jars.paper.size = [long]$fakePaperBytes.Length
    foreach ($case in @($fakeJar.report.cases)) {
        $case.run_root.backend_plugin_sha256 = $fakePaperHash
        $case.run_root.backend_plugin_size = [long]$fakePaperBytes.Length
    }
    foreach ($controlName in @('release-manifest.properties','SHA256SUMS')) {
        $controlPath = Join-Path $fakeJar.bundle.root $controlName
        $controlRaw = [IO.File]::ReadAllText($controlPath,$utf8NoBom)
        [IO.File]::WriteAllText($controlPath,$controlRaw.Replace($oldPaperHash,$fakePaperHash),$utf8NoBom)
    }
    Write-MatrixTriplet $fakeJar
    $fakeJarArgs = Get-PublisherArguments $fakeJar 'server-version-process-matrix-manual-byte-array-jar'
    Invoke-ExpectedFailure { & $publisher @fakeJarArgs } `
        'MCACE_MATRIX_PUBLISH_SERVER_JAR_INVALID'

    $bundleTamper = New-Fixture 'bundle-tamper'
    $bundleTamperPath = Join-Path $bundleTamper.bundle.root 'mcace-server-paper.jar'
    $tamperedBytes = [IO.File]::ReadAllBytes($bundleTamperPath)
    $tamperedBytes[0] = [byte]($tamperedBytes[0] -bxor 0xff)
    [IO.File]::WriteAllBytes($bundleTamperPath,$tamperedBytes)
    $bundleTamperArgs = Get-PublisherArguments $bundleTamper 'server-version-process-matrix-bundle-tamper'
    Invoke-ExpectedFailure { & $publisher @bundleTamperArgs } `
        'MCACE_MATRIX_PUBLISH_RELEASE_ARTIFACT_BINDING_INVALID'

    $manifestCommit = New-Fixture 'manifest-artifact-commit'
    $manifestPath = Join-Path $manifestCommit.bundle.root 'release-manifest.properties'
    $manifestRaw = [IO.File]::ReadAllText($manifestPath,$utf8NoBom)
    [IO.File]::WriteAllText($manifestPath,
        $manifestRaw.Replace("artifact_source_commit=$artifactCommit", "artifact_source_commit=$('c' * 40)"),
        $utf8NoBom)
    $manifestCommitArgs = Get-PublisherArguments $manifestCommit 'server-version-process-matrix-manifest-commit'
    Invoke-ExpectedFailure { & $publisher @manifestCommitArgs } 'MCACE_MATRIX_PUBLISH_RELEASE_MANIFEST_INVALID'

    $duplicateProperty = New-Fixture 'duplicate-json-property'
    $duplicateReportPath = Join-Path $duplicateProperty.triplet_root 'report.json'
    $duplicateRaw = [IO.File]::ReadAllText($duplicateReportPath,$utf8NoBom)
    [IO.File]::WriteAllText($duplicateReportPath,
        $duplicateRaw.Replace('{"schema":','{"Schema":"ambiguous","schema":'),
        $utf8NoBom)
    $duplicatePropertyArgs = Get-PublisherArguments $duplicateProperty 'server-version-process-matrix-duplicate-property'
    Invoke-ExpectedFailure { & $publisher @duplicatePropertyArgs } `
        'MCACE_MATRIX_PUBLISH_JSON_CASE_AMBIGUOUS_PROPERTY'

    $divergent = New-Fixture 'divergent-force' ([DateTimeOffset]::UtcNow.AddSeconds(-30).ToString('o'))
    $divergent.output_root = $positive.output_root
    $divergentArgs = Get-PublisherArguments $divergent $evidenceId
    Invoke-ExpectedFailure { & $publisher @divergentArgs -Force } `
        'MCACE_MATRIX_PUBLISH_DIVERGENT_IMMUTABLE_EVIDENCE_ID'

    # A directory junction is the most portable no-admin Windows reparse test.
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        $reparse = New-Fixture 'reparse-input'
        $junction = Join-Path $reparse.root 'matrix-triplet-link'
        try {
            [void](New-Item -ItemType Junction -Path $junction -Target $reparse.triplet_root -ErrorAction Stop)
            $reparseArgs = @{
                ReportPath=(Join-Path $junction 'report.json')
                BindingPath=(Join-Path $junction 'binding.json')
                CommitPath=(Join-Path $junction 'commit.json')
                ReleaseBundleRoot=$reparse.bundle.root
                ArtifactSourceCommit=$artifactCommit
                SupervisorTrustRootPath=$trustRootPath
                ExpectedSupervisorTrustRootSha256=$trustRootSha256
                OutputRoot=$reparse.output_root
                EvidenceId='server-version-process-matrix-reparse-input'
            }
            Invoke-ExpectedFailure { & $publisher @reparseArgs } 'MCACE_MATRIX_PUBLISH_REPARSE_PATH_REJECTED'
        } catch {
            if ($_.Exception.Message -like '*WRONG_FAILURE*' -or
                    $_.Exception.Message -like '*EXPECTED_FAILURE_NOT_THROWN*') { throw }
            # Some locked-down Windows hosts either forbid junction creation or deny the
            # publisher's no-follow/atomic staging operation before it can emit the
            # contract-specific rejection. Keep that host capability gap explicit while
            # retaining every other dynamic negative and the static no-reparse contract.
            if ($_.Exception -is [UnauthorizedAccessException] -or
                    $_.Exception.Message -match '(?i)access to the path|access is denied|unauthorized' -or
                    # Invoke-ExpectedFailure wraps the original exception with
                    # WRONG_FAILURE when PowerShell 7 surfaces a .NET Move
                    # failure as a MethodInvocationException. Preserve the
                    # explicit host-capability exception instead of treating
                    # that wrapper as a publisher-contract failure.
                    ($_.Exception.Message -like '*WRONG_FAILURE*' -and
                        $_.Exception.Message -match '(?i)access to the path|access is denied|unauthorized')) {
                Write-Output 'MCACE_SERVER_VERSION_MATRIX_REPARSE_COVERAGE_UNAVAILABLE|host privilege or policy denied junction/no-follow operation'
            } else {
                throw
            }
        }
    }

    Write-Output "MCACE_SERVER_VERSION_MATRIX_EVIDENCE_PUBLISHER_TEST_PASS|negative_cases=$negativeCount|force_idempotent=true|ps=$($PSVersionTable.PSVersion)"
} finally {
    $env:MCACE_RELEASE_APPROVED_MATRIX_SUPERVISOR_TRUST_ROOT_SHA256=$null
    if($null -ne $rsa){$rsa.Dispose()}
    if (Test-Path -LiteralPath $testRoot -PathType Container) {
        $junctionPath = Join-Path $testRoot 'reparse-input\matrix-triplet-link'
        if (Test-Path -LiteralPath $junctionPath) {
            $junctionItem = Get-Item -LiteralPath $junctionPath -Force -ErrorAction SilentlyContinue
            if ($null -ne $junctionItem -and
                    ($junctionItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                [IO.Directory]::Delete($junctionItem.FullName)
            }
        }
        [IO.Directory]::Delete($testRoot, $true)
    }
}
