[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $script:PSNativeCommandUseErrorActionPreference = $false
}

$signer = Join-Path $PSScriptRoot 'sign-production-authority-receipt.ps1'
$utf8 = New-Object Text.UTF8Encoding($false)
$utf8Strict = New-Object Text.UTF8Encoding($false, $true)
$sourceCommit = '2c898762dd770723957ea0a8279f68c6c5e5abb3'
$temp = Join-Path ([IO.Path]::GetTempPath()) (
    'mcace-production-authority-signer-' + [guid]::NewGuid().ToString('N'))

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw "TEST_ASSERTION_FAILED|$Message" }
}

function Assert-Throws([scriptblock]$Action, [string]$Expected) {
    try {
        & $Action
        throw "EXPECTED_FAILURE_MISSING|$Expected"
    } catch {
        if ($_.Exception.Message -ceq "EXPECTED_FAILURE_MISSING|$Expected") { throw }
        if ($_.Exception.Message -cnotlike "*$Expected*") {
            throw "UNEXPECTED_FAILURE|expected=$Expected|actual=$($_.Exception.Message)"
        }
    }
}

function Get-BytesSha256([byte[]]$Bytes) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    } finally { $sha.Dispose() }
}

function Get-FileSha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-Json([string]$Path, [object]$Value, [switch]$Compact) {
    $json = if ($Compact) {
        $Value | ConvertTo-Json -Depth 30 -Compress
    } else {
        (($Value | ConvertTo-Json -Depth 30) -replace "`r`n", "`n") + "`n"
    }
    [IO.File]::WriteAllBytes($Path, $utf8.GetBytes($json))
}

function Set-PrivateDirectoryAcl([string]$Path) {
    $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($current)
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach ($sid in @($current,$system)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function Get-RuntimeRelativePath([string]$Root, [string]$Path) {
    $rootFull = [IO.Path]::GetFullPath($Root).TrimEnd('\','/')
    $full = [IO.Path]::GetFullPath($Path)
    return $full.Substring(($rootFull + [IO.Path]::DirectorySeparatorChar).Length).Replace('\','/')
}

function Sort-RuntimeItemsOrdinal([object[]]$Items) {
    $sorted = New-Object Collections.ArrayList
    foreach ($item in @($Items)) {
        $insertAt = 0
        while ($insertAt -lt $sorted.Count -and
                [StringComparer]::Ordinal.Compare(
                    [string]$sorted[$insertAt].relative_path,
                    [string]$item.relative_path) -lt 0) {
            $insertAt++
        }
        $sorted.Insert($insertAt, $item)
    }
    return @($sorted.ToArray())
}

function New-TestOpenSslRuntimeManifest(
        [string]$RuntimeRoot, [string]$ManifestPath, [bool]$Fixture) {
    $entries = @()
    foreach ($file in @(Get-ChildItem -LiteralPath $RuntimeRoot -Recurse -Force -File)) {
        $relative = Get-RuntimeRelativePath $RuntimeRoot $file.FullName
        $role = if ($relative -ceq 'openssl.exe') {
            'EXECUTABLE'
        } elseif ($relative -ceq 'openssl.cnf') {
            'CONFIG'
        } elseif ($relative.StartsWith('providers/', [StringComparison]::Ordinal)) {
            'PROVIDER_MODULE'
        } else { 'APPLICATION_LOCAL_DLL' }
        $entries += [pscustomobject][ordered]@{
            relative_path=$relative
            role=$role
            size_bytes=[long]$file.Length
            sha256=(Get-FileSha256 $file.FullName)
        }
    }
    $entries = @(Sort-RuntimeItemsOrdinal $entries)
    Write-Json $ManifestPath ([pscustomobject][ordered]@{
        schema='MCACE_OPENSSL_RUNTIME_MANIFEST_V1'
        artifact_class='REVIEWED_OPENSSL_RUNTIME'
        platform='windows-x64'
        executable_relative_path='openssl.exe'
        files=$entries
        test_fixture=$Fixture
    })
    return [pscustomobject]@{ path=$ManifestPath; sha256=(Get-FileSha256 $ManifestPath) }
}

function Get-TestOpenSslRuntimeFiles([string]$ExecutablePath) {
    $executable = Get-Item -LiteralPath $ExecutablePath
    $directory = $executable.DirectoryName
    $allDlls = @(Get-ChildItem -LiteralPath $directory -File -Filter '*.dll')
    $objdumpPath = Join-Path $directory 'objdump.exe'
    if (-not (Test-Path -LiteralPath $objdumpPath -PathType Leaf)) {
        $objdump = Get-Command objdump.exe -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($null -eq $objdump) { return @($executable) + $allDlls }
        $objdumpPath = [string]$objdump.Source
    }
    $selected = [ordered]@{ $executable.Name = $executable }
    $queue = New-Object Collections.Generic.Queue[string]
    $queue.Enqueue($executable.FullName)
    try {
        while ($queue.Count -gt 0) {
            $candidatePath = $queue.Dequeue()
            $oldPreference = $ErrorActionPreference
            try { $ErrorActionPreference = 'Continue'; $imports = @(& $objdumpPath -p $candidatePath 2>$null); $exit = $LASTEXITCODE }
            finally { $ErrorActionPreference = $oldPreference }
            if ($exit -ne 0) { throw 'OBJDUMP_FAILED' }
            foreach ($line in $imports) {
                if ([string]$line -match '^\s*DLL Name:\s*(?<leaf>[^\\/]+\.dll)\s*$') {
                    $leaf = [string]$Matches.leaf
                    $localPath = Join-Path $directory $leaf
                    if ((Test-Path -LiteralPath $localPath -PathType Leaf) -and
                            -not $selected.Contains($leaf)) {
                        $item = Get-Item -LiteralPath $localPath
                        $selected[$leaf] = $item
                        $queue.Enqueue($item.FullName)
                    }
                }
            }
        }
        if ($selected.Count -lt 2) { throw 'NO_APPLICATION_LOCAL_DLL' }
        return @($selected.Values)
    } catch { return @($executable) + $allDlls }
}

function Invoke-TestOpenSsl([string[]]$Arguments) {
    $oldPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $result = @(& $script:OpenSsl @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $oldPreference }
    if ($exitCode -ne 0) {
        throw "TEST_OPENSSL_FAILED|args=$($Arguments -join ' ')|output=$($result -join ';')"
    }
    return $result
}

function New-RequestFixture(
        [string]$Name,
        [scriptblock]$PayloadMutation = $null,
        [scriptblock]$RequestMutation = $null,
        [guid]$OperationAttemptId = [guid]::NewGuid(),
        [byte[]]$Challenge = $null,
        [int]$IssuedOffsetSeconds = 0,
        [int]$ValiditySeconds = 600,
        [string]$ReceiptSubdirectory = '',
        [switch]$NonCanonicalPayload,
        [switch]$DuplicateRequestSchema) {
    $caseRoot = Join-Path $script:ExchangeRoot $Name
    [IO.Directory]::CreateDirectory($caseRoot) | Out-Null
    $requestPath = Join-Path $caseRoot 'signing-request.json'
    $receiptParent = $caseRoot
    if (-not [string]::IsNullOrWhiteSpace($ReceiptSubdirectory)) {
        $receiptParent = Join-Path $caseRoot $ReceiptSubdirectory
        [IO.Directory]::CreateDirectory($receiptParent) | Out-Null
    }
    $receiptPath = Join-Path $receiptParent 'supervisor-receipt.json'
    if ($null -eq $Challenge) {
        $Challenge = New-Object byte[] 32
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($Challenge) } finally { $rng.Dispose() }
    }
    $issued = [DateTimeOffset]::UtcNow.AddSeconds($IssuedOffsetSeconds)
    $expires = $issued.AddSeconds($ValiditySeconds)
    $hashes = [ordered]@{}
    foreach ($namePart in @('raw-manifest','raw-root','frame-set','provider','event-chain',
            'process-ledger','paper','velocity','bungeecord','profile','topology','backend',
            'proxy','vulcan','journal')) {
        $hashes[$namePart] = Get-BytesSha256 $utf8.GetBytes("$Name|$namePart")
    }
    $payload = [ordered]@{
        schema='MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_PAYLOAD_V1'
        artifact_class='TEST_SUPERVISOR_RECEIPT_FIXTURE'
        source_commit=$sourceCommit
        artifact_source_commit=$sourceCommit
        product_version='0.0.1'
        capture_id=[guid]::NewGuid().ToString('D')
        operation_attempt_id=$OperationAttemptId.ToString('D')
        supervisor_instance_id='test-supervisor-a'
        supervisor_run_id=[guid]::NewGuid().ToString('D')
        signer_key_id_sha256=$script:KeyId
        challenge_nonce_base64=[Convert]::ToBase64String($Challenge)
        issued_at=$issued.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        expires_at=$expires.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        raw_capture_manifest_sha256=$hashes['raw-manifest']
        raw_capture_manifest_size_bytes=[long]201
        raw_evidence_root_sha256=$hashes['raw-root']
        raw_frame_set_sha256=$hashes['frame-set']
        raw_frame_count=[long]2
        provider_evidence_commitment_sha256=$hashes['provider']
        event_chain_root_sha256=$hashes['event-chain']
        event_count=[long]5
        process_ledger_sha256=$hashes['process-ledger']
        process_ledger_size_bytes=[long]202
        paper_jar_sha256=$hashes['paper']
        paper_jar_size_bytes=[long]203
        velocity_jar_sha256=$hashes['velocity']
        velocity_jar_size_bytes=[long]204
        bungeecord_jar_sha256=$hashes['bungeecord']
        bungeecord_jar_size_bytes=[long]205
        selected_proxy='velocity'
        selected_proxy_jar_sha256=$hashes['velocity']
        profile_sha256=$hashes['profile']
        topology_sha256=$hashes['topology']
        backend_key_id_sha256=$hashes['backend']
        proxy_key_id_sha256=$hashes['proxy']
        action_ceiling='MONITOR'
        automatic_action_count=[long]0
        cleanup_all_zero=$true
        licensed_vulcan_sha256=$hashes['vulcan']
        genuine_provider_ids=@('grim','vulcan')
        test_fixture=$true
    }
    if ($null -ne $PayloadMutation) { & $PayloadMutation $payload }
    $payloadJson = if ($NonCanonicalPayload) {
        (($payload | ConvertTo-Json -Depth 30) -replace "`r`n", "`n")
    } else { $payload | ConvertTo-Json -Depth 30 -Compress }
    [byte[]]$payloadBytes = $utf8.GetBytes($payloadJson)
    $request = [ordered]@{
        schema='MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_SIGNING_REQUEST_V1'
        artifact_class='TEST_PRODUCTION_AUTHORITY_SIGNING_REQUEST_FIXTURE'
        request_id=[guid]::NewGuid().ToString('D')
        issued_at=$issued.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        not_after=$expires.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        output_receipt_path=$receiptPath
        capture_supervisor_descriptor_sha256=$script:DescriptorSha256
        signer_key_id_sha256=$script:KeyId
        source_commit=$sourceCommit
        artifact_source_commit=$sourceCommit
        product_version='0.0.1'
        capture_id=$payload.capture_id
        operation_attempt_id=$payload.operation_attempt_id
        challenge_nonce_base64=[Convert]::ToBase64String($Challenge)
        challenge_sha256=(Get-BytesSha256 $Challenge)
        signed_payload_base64=[Convert]::ToBase64String($payloadBytes)
        signed_payload_sha256=(Get-BytesSha256 $payloadBytes)
        signed_payload_size_bytes=[long]$payloadBytes.Length
        release_bundle_source_commit=$sourceCommit
        release_bundle_artifact_source_commit=$sourceCommit
        paper_jar_sha256=$hashes['paper']
        paper_jar_size_bytes=[long]203
        velocity_jar_sha256=$hashes['velocity']
        velocity_jar_size_bytes=[long]204
        bungeecord_jar_sha256=$hashes['bungeecord']
        bungeecord_jar_size_bytes=[long]205
        raw_capture_manifest_sha256=$hashes['raw-manifest']
        raw_capture_manifest_size_bytes=[long]201
        raw_evidence_root_sha256=$hashes['raw-root']
        raw_frame_set_sha256=$hashes['frame-set']
        provider_evidence_commitment_sha256=$hashes['provider']
        profile_sha256=$hashes['profile']
        topology_sha256=$hashes['topology']
        process_ledger_sha256=$hashes['process-ledger']
        process_ledger_size_bytes=[long]202
        issuance_journal_sha256=$hashes['journal']
        issuance_journal_size_bytes=[long]206
        test_fixture=$true
    }
    if ($null -ne $RequestMutation) { & $RequestMutation $request }
    Write-Json $requestPath $request
    if ($DuplicateRequestSchema) {
        $raw = [IO.File]::ReadAllText($requestPath, $utf8Strict)
        $raw = $raw -replace '^\{', '{"schema":"DUPLICATE_REJECTED",'
        [IO.File]::WriteAllBytes($requestPath, $utf8.GetBytes($raw))
    }
    return [pscustomobject]@{
        root=$caseRoot
        request=$requestPath
        receipt=$receiptPath
        request_sha256=(Get-FileSha256 $requestPath)
        operation_attempt_id=$OperationAttemptId
        challenge=$Challenge
        payload_bytes=$payloadBytes
    }
}

function Get-SignerArguments([object]$Fixture) {
    return @{
        RequestPath=$Fixture.request
        ExpectedRequestSha256=$Fixture.request_sha256
        ReceiptPath=$Fixture.receipt
        ExpectedDescriptorPath=$script:DescriptorPath
        ExpectedDescriptorSha256=$script:DescriptorSha256
        ExpectedSignerKeyIdSha256=$script:KeyId
        PrivateKeyPath=$script:PrivateKeyPath
        OpenSslPath=$script:OpenSsl
        ExpectedOpenSslSha256=$script:OpenSslSha256
        OpenSslRuntimeManifestPath=$script:OpenSslRuntimeManifestPath
        ExpectedOpenSslRuntimeManifestSha256=$script:OpenSslRuntimeManifestSha256
        AllowedExchangeRoot=$Fixture.root
        TestFixture=$true
    }
}

function Invoke-Signer([hashtable]$Arguments) {
    return @(& $signer @Arguments)
}

function Invoke-ConcurrentSignerPair(
        [object]$FixtureA, [object]$FixtureB, [string]$Label,
        [string]$ExpectedReplayField) {
    $processes = @()
    foreach ($entry in @(
            [pscustomobject]@{ name='a'; fixture=$FixtureA },
            [pscustomobject]@{ name='b'; fixture=$FixtureB })) {
        $childArgs = Get-SignerArguments $entry.fixture
        $argsPath = Join-Path $temp ("$Label-$($entry.name)-args.json")
        Write-Json $argsPath ([pscustomobject]$childArgs)
        $stdout = Join-Path $temp ("$Label-$($entry.name)-stdout.txt")
        $stderr = Join-Path $temp ("$Label-$($entry.name)-stderr.txt")
        $process = Start-Process -FilePath $script:ChildShell -ArgumentList @(
            '-NoLogo','-NoProfile','-NonInteractive','-File',$script:ChildRunner,
            '-Signer',$signer,'-ArgumentsPath',$argsPath) -PassThru `
            -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        $processes += [pscustomobject]@{
            process=$process
            stdout=$stdout
            stderr=$stderr
            fixture=$entry.fixture
        }
    }
    foreach ($entry in $processes) { $entry.process.WaitForExit(); $entry.process.Refresh() }
    $successes = @($processes | Where-Object {
        [IO.File]::ReadAllText($_.stdout) -clike
            '*PRODUCTION_AUTHORITY_V4_SIGNER_FIXTURE_CREATED*' -and
        [string]::IsNullOrWhiteSpace([IO.File]::ReadAllText($_.stderr))
    })
    $failures = @($processes | Where-Object { $_ -notin $successes })
    $debugText = @($processes | ForEach-Object {
        "stdout=$([IO.File]::ReadAllText($_.stdout));stderr=$([IO.File]::ReadAllText($_.stderr))"
    }) -join ' || '
    Assert-True ($successes.Count -eq 1 -and $failures.Count -eq 1) `
        "$Label did not produce exactly one success and one failure: $debugText"
    $failureText = ([IO.File]::ReadAllText($failures[0].stderr) +
        [IO.File]::ReadAllText($failures[0].stdout))
    Assert-True ($failureText -match
        'PRODUCTION_AUTHORITY_SIGNER_(CONCURRENT_OPERATION|REPLAY)_REJECTED') `
        "$Label unexpected concurrent rejection: $failureText"
    $receipts = @($FixtureA.receipt, $FixtureB.receipt |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    Assert-True ($receipts.Count -eq 1) "$Label wrote zero or two receipts"

    $retryArgs = Get-SignerArguments $failures[0].fixture
    Assert-Throws { $null = Invoke-Signer $retryArgs } `
        "PRODUCTION_AUTHORITY_SIGNER_REPLAY_REJECTED|$ExpectedReplayField"
}

$tokens = $null
$parseErrors = $null
[Management.Automation.Language.Parser]::ParseFile(
    $signer, [ref]$tokens, [ref]$parseErrors) | Out-Null
Assert-True (@($parseErrors).Count -eq 0) "signer AST errors: $($parseErrors -join ';')"
$source = [IO.File]::ReadAllText($signer)
foreach ($token in @(
        'ExpectedRequestSha256','ApprovedRequestSha256','ExpectedDescriptorPath',
        'ExpectedSignerKeyIdSha256','ExpectedOpenSslSha256',
        'ExpectedOpenSslRuntimeManifestSha256','AllowedExchangeRoot',
        'FILE_FLAG_OPEN_REPARSE_POINT','hard-linked file rejected','FileShare]::None',
        'WriteThrough','Flush($true)','NtCreateFile','WriteAtomicRelative',
        'ProcessStartInfo','OPENSSL_RUNTIME_EXACT_SET_MISMATCH',
        'PRODUCTION_AUTHORITY_SIGNER_REQUEST_NOT_IN_OPERATOR_ALLOWLIST',
        'PRODUCTION_AUTHORITY_SIGNER_PRIVATE_PUBLIC_MISMATCH',
        'PRODUCTION_AUTHORITY_SIGNER_REPLAY_REJECTED',
        'PRODUCTION_AUTHORITY_SIGNER_CONCURRENT_OPERATION_REJECTED')) {
    Assert-True $source.Contains($token) "security token missing: $token"
}
Assert-True (-not $source.Contains('[string]$request.output_receipt_path)+')) `
    'request-controlled receipt path concatenation returned'

[IO.Directory]::CreateDirectory($temp) | Out-Null
try {
    $openSslCommand = Get-Command openssl.exe -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $openSslCommand) {
        $gitOpenSsl = Join-Path $env:ProgramFiles 'Git\usr\bin\openssl.exe'
        if (Test-Path -LiteralPath $gitOpenSsl -PathType Leaf) {
            $openSslSource = $gitOpenSsl
        } else { throw 'TEST_OPENSSL_3_REQUIRED' }
    } else { $openSslSource = [string]$openSslCommand.Source }
    $toolRoot = Join-Path $temp 'openssl-bin'
    [IO.Directory]::CreateDirectory($toolRoot) | Out-Null
    $runtimeFiles = @(Get-TestOpenSslRuntimeFiles $openSslSource)
    foreach ($runtimeFile in $runtimeFiles) {
        Copy-Item -LiteralPath $runtimeFile.FullName -Destination (
            Join-Path $toolRoot $runtimeFile.Name)
    }
    [IO.Directory]::CreateDirectory((Join-Path $toolRoot 'providers')) | Out-Null
    $providerSource = @($runtimeFiles | Where-Object { $_.Extension -ieq '.dll' } |
        Select-Object -First 1)
    Assert-True ($providerSource.Count -eq 1) 'OpenSSL application-local DLL required'
    Copy-Item -LiteralPath $providerSource[0].FullName -Destination (
        Join-Path $toolRoot 'providers\fixture-provider.dll')
    [IO.File]::WriteAllBytes((Join-Path $toolRoot 'openssl.cnf'),
        $utf8.GetBytes("# MCAce pinned empty OpenSSL configuration v1`n"))
    Set-PrivateDirectoryAcl $toolRoot
    $script:OpenSsl = Join-Path $toolRoot 'openssl.exe'
    $script:OpenSslSha256 = Get-FileSha256 $script:OpenSsl
    $runtimeManifest = New-TestOpenSslRuntimeManifest $toolRoot `
        (Join-Path $temp 'openssl-runtime-manifest.json') $true
    $script:OpenSslRuntimeManifestPath = $runtimeManifest.path
    $script:OpenSslRuntimeManifestSha256 = $runtimeManifest.sha256
    $version = Invoke-TestOpenSsl @('version')
    Assert-True (($version -join "`n") -match '(?m)^OpenSSL\s+3(?:\.|\s)') 'OpenSSL 3 missing'

    $script:ExchangeRoot = Join-Path $temp 'exchange'
    $secureRoot = Join-Path $temp 'secure'
    [IO.Directory]::CreateDirectory($script:ExchangeRoot) | Out-Null
    [IO.Directory]::CreateDirectory($secureRoot) | Out-Null
    Set-PrivateDirectoryAcl $secureRoot
    $script:PrivateKeyPath = Join-Path $secureRoot 'supervisor-private.pk8'
    $publicPath = Join-Path $secureRoot 'supervisor-public.der'
    $null = Invoke-TestOpenSsl @(
        'genpkey','-algorithm','ED25519','-outform','DER','-out',$script:PrivateKeyPath)
    $null = Invoke-TestOpenSsl @(
        'pkey','-inform','DER','-in',$script:PrivateKeyPath,
        '-pubout','-outform','DER','-out',$publicPath)
    [byte[]]$publicBytes = [IO.File]::ReadAllBytes($publicPath)
    $script:KeyId = Get-BytesSha256 $publicBytes
    $script:DescriptorPath = Join-Path $secureRoot 'supervisor-descriptor.json'
    Write-Json $script:DescriptorPath ([ordered]@{
        schema='MCACE_PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_PUBLIC_DESCRIPTOR_V1'
        artifact_class='EXTERNAL_RELEASE_CAPTURE_SUPERVISOR_PUBLIC_ROOT'
        algorithm='ED25519'
        key_id_sha256=$script:KeyId
        public_key_der_base64=[Convert]::ToBase64String($publicBytes)
        test_fixture=$false
    })
    $script:DescriptorSha256 = Get-FileSha256 $script:DescriptorPath

    $baseline = New-RequestFixture 'baseline'
    $baselineArgs = Get-SignerArguments $baseline
    $baselineResult = Invoke-Signer $baselineArgs
    Assert-True (($baselineResult -join "`n") -clike
        '*PRODUCTION_AUTHORITY_V4_SIGNER_FIXTURE_CREATED*') 'success marker missing'
    Assert-True (Test-Path -LiteralPath $baseline.receipt -PathType Leaf) 'receipt missing'
    $receiptRaw = [IO.File]::ReadAllText($baseline.receipt, $utf8Strict)
    Assert-True (-not $receiptRaw.Contains("`r") -and -not $receiptRaw.EndsWith("`n")) `
        'receipt is not compact canonical JSON'
    $receipt = $receiptRaw | ConvertFrom-Json
    Assert-True ([string]$receipt.schema -ceq
        'MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1') 'receipt schema wrong'
    Assert-True ([string]$receipt.signed_payload_sha256 -ceq
        (Get-BytesSha256 $baseline.payload_bytes)) 'receipt payload hash wrong'
    $verifyRoot = Join-Path $temp 'verify'
    [IO.Directory]::CreateDirectory($verifyRoot) | Out-Null
    $verifyPayload = Join-Path $verifyRoot 'payload.bin'
    $verifySignature = Join-Path $verifyRoot 'signature.bin'
    [IO.File]::WriteAllBytes($verifyPayload,
        [Convert]::FromBase64String([string]$receipt.signed_payload_base64))
    [IO.File]::WriteAllBytes($verifySignature,
        [Convert]::FromBase64String([string]$receipt.signature_base64))
    $null = Invoke-TestOpenSsl @(
        'pkeyutl','-verify','-rawin','-pubin','-inkey',$publicPath,'-keyform','DER',
        '-in',$verifyPayload,'-sigfile',$verifySignature)

    $bothPins = New-RequestFixture 'both-approved-pins'
    $bothArgs = Get-SignerArguments $bothPins
    $bothArgs.ApprovedRequestSha256 = $bothPins.request_sha256
    $bothResult = Invoke-Signer $bothArgs
    Assert-True (($bothResult -join "`n") -clike '*SIGNER_FIXTURE_CREATED*') `
        'equal Expected/Approved pins were rejected'

    $missingPin = New-RequestFixture 'missing-pin'
    $missingPinArgs = Get-SignerArguments $missingPin
    $missingPinArgs.Remove('ExpectedRequestSha256')
    Assert-Throws { $null = Invoke-Signer $missingPinArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_SINGLE_APPROVED_REQUEST_SHA256_REQUIRED'

    $wrongPin = New-RequestFixture 'wrong-pin'
    $wrongPinArgs = Get-SignerArguments $wrongPin
    $wrongPinArgs.ExpectedRequestSha256 = '0' * 64
    Assert-Throws { $null = Invoke-Signer $wrongPinArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_REQUEST_NOT_IN_OPERATOR_ALLOWLIST'

    $twoPins = New-RequestFixture 'two-different-pins'
    $twoPinArgs = Get-SignerArguments $twoPins
    $twoPinArgs.ApprovedRequestSha256 = '1' * 64
    Assert-Throws { $null = Invoke-Signer $twoPinArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_SINGLE_APPROVED_REQUEST_SHA256_REQUIRED'

    $wrongOutput = New-RequestFixture 'wrong-output' -RequestMutation {
        param($request)
        $request.output_receipt_path = Join-Path $script:ExchangeRoot 'attacker-selected.json'
    }
    $wrongOutputArgs = Get-SignerArguments $wrongOutput
    Assert-Throws { $null = Invoke-Signer $wrongOutputArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_OUTPUT_PATH_BINDING_INVALID'

    $outside = New-RequestFixture 'outside-source'
    $outsideReceipt = Join-Path $temp 'outside-receipt.json'
    $outsideArgs = Get-SignerArguments $outside
    $outsideArgs.ReceiptPath = $outsideReceipt
    Assert-Throws { $null = Invoke-Signer $outsideArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_EXCHANGE_PATH_OUTSIDE_ALLOWLIST'

    $nestedReceipt = New-RequestFixture 'nested-receipt' -ReceiptSubdirectory 'nested'
    $nestedReceiptArgs = Get-SignerArguments $nestedReceipt
    Assert-Throws { $null = Invoke-Signer $nestedReceiptArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_EXCHANGE_DIRECT_LEAVES_REQUIRED'

    $descriptorPinCase = New-RequestFixture 'descriptor-pin'
    $descriptorPinArgs = Get-SignerArguments $descriptorPinCase
    $descriptorPinArgs.ExpectedDescriptorSha256 = '2' * 64
    Assert-Throws { $null = Invoke-Signer $descriptorPinArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_DESCRIPTOR_SHA256_MISMATCH'

    $keyIdCase = New-RequestFixture 'key-id-pin'
    $keyIdArgs = Get-SignerArguments $keyIdCase
    $keyIdArgs.ExpectedSignerKeyIdSha256 = '3' * 64
    Assert-Throws { $null = Invoke-Signer $keyIdArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_DESCRIPTOR_BINDING_INVALID'

    $wrongPrivate = Join-Path $secureRoot 'wrong-private.pk8'
    $null = Invoke-TestOpenSsl @(
        'genpkey','-algorithm','ED25519','-outform','DER','-out',$wrongPrivate)
    $wrongKeyCase = New-RequestFixture 'wrong-private-key'
    $wrongKeyArgs = Get-SignerArguments $wrongKeyCase
    $wrongKeyArgs.PrivateKeyPath = $wrongPrivate
    Assert-Throws { $null = Invoke-Signer $wrongKeyArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_PRIVATE_PUBLIC_MISMATCH'

    $openSslPinCase = New-RequestFixture 'openssl-pin'
    $openSslPinArgs = Get-SignerArguments $openSslPinCase
    $openSslPinArgs.ExpectedOpenSslSha256 = '4' * 64
    Assert-Throws { $null = Invoke-Signer $openSslPinArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_EXECUTABLE_BINDING_INVALID'

    $mutatedToolRoot = Join-Path $temp 'mutated-openssl'
    [IO.Directory]::CreateDirectory($mutatedToolRoot) | Out-Null
    foreach ($runtimeItem in @(Get-ChildItem -LiteralPath $toolRoot -Force)) {
        Copy-Item -LiteralPath $runtimeItem.FullName -Destination $mutatedToolRoot -Recurse -Force
    }
    Set-PrivateDirectoryAcl $mutatedToolRoot
    $mutatedTool = Join-Path $mutatedToolRoot 'openssl.exe'
    $preMutationHash = Get-FileSha256 $mutatedTool
    $mutatedRuntimeManifest = New-TestOpenSslRuntimeManifest $mutatedToolRoot `
        (Join-Path $temp 'mutated-openssl-runtime-manifest.json') $true
    $append = New-Object IO.FileStream(
        $mutatedTool,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $append.WriteByte(0); $append.Flush($true) } finally { $append.Dispose() }
    $toolMutationCase = New-RequestFixture 'openssl-mutation'
    $toolMutationArgs = Get-SignerArguments $toolMutationCase
    $toolMutationArgs.OpenSslPath = $mutatedTool
    $toolMutationArgs.ExpectedOpenSslSha256 = $preMutationHash
    $toolMutationArgs.OpenSslRuntimeManifestPath = $mutatedRuntimeManifest.path
    $toolMutationArgs.ExpectedOpenSslRuntimeManifestSha256 = $mutatedRuntimeManifest.sha256
    Assert-Throws { $null = Invoke-Signer $toolMutationArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_FILE_BINDING_INVALID'

    $runtimeDll = @(Get-ChildItem -LiteralPath $toolRoot -File -Filter '*.dll' |
        Select-Object -First 1)[0]
    $runtimeDllBackup = Join-Path $temp 'runtime-dll-backup.bin'
    Copy-Item -LiteralPath $runtimeDll.FullName -Destination $runtimeDllBackup
    try {
        $dllAppend = New-Object IO.FileStream(
            $runtimeDll.FullName,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $dllAppend.WriteByte(0); $dllAppend.Flush($true) } finally { $dllAppend.Dispose() }
        $dllMutationCase = New-RequestFixture 'openssl-dll-mutation'
        $dllMutationArgs = Get-SignerArguments $dllMutationCase
        Assert-Throws { $null = Invoke-Signer $dllMutationArgs } `
            'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_FILE_BINDING_INVALID'
    } finally {
        Copy-Item -LiteralPath $runtimeDllBackup -Destination $runtimeDll.FullName -Force
    }

    $extraRuntimeFile = Join-Path $toolRoot 'unreviewed-runtime.dll'
    try {
        [IO.File]::WriteAllBytes($extraRuntimeFile, [byte[]](1,2,3,4))
        $extraRuntimeCase = New-RequestFixture 'openssl-runtime-extra-file'
        $extraRuntimeArgs = Get-SignerArguments $extraRuntimeCase
        Assert-Throws { $null = Invoke-Signer $extraRuntimeArgs } `
            'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_RUNTIME_EXACT_SET_MISMATCH'
    } finally {
        [IO.File]::Delete($extraRuntimeFile)
    }

    try {
        & icacls.exe $toolRoot /grant '*S-1-5-32-545:(OI)(CI)(RX)' | Out-Null
        Assert-True ($LASTEXITCODE -eq 0) 'failed to add permissive runtime ACL fixture'
        $aclCase = New-RequestFixture 'openssl-runtime-permissive-acl'
        $aclArgs = Get-SignerArguments $aclCase
        Assert-Throws { $null = Invoke-Signer $aclArgs } `
            'PRODUCTION_AUTHORITY_SIGNER_PRIVATE_DIRECTORY_ACL_PRINCIPAL_REJECTED|openssl-runtime-root'
    } finally {
        & icacls.exe $toolRoot /remove:g '*S-1-5-32-545' | Out-Null
        Assert-True ($LASTEXITCODE -eq 0) 'failed to remove permissive runtime ACL fixture'
    }

    $shim = Join-Path $secureRoot 'openssl.cmd'
    [IO.File]::WriteAllBytes($shim, $utf8.GetBytes('@exit /b 0'))
    $shimCase = New-RequestFixture 'openssl-shim'
    $shimArgs = Get-SignerArguments $shimCase
    $shimArgs.OpenSslPath = $shim
    $shimArgs.ExpectedOpenSslSha256 = Get-FileSha256 $shim
    Assert-Throws { $null = Invoke-Signer $shimArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_OPENSSL_APPLICATION_REQUIRED'

    $trustedInsideCase = New-RequestFixture 'trusted-input-inside'
    $insidePrivate = Join-Path $trustedInsideCase.root 'inside-private.pk8'
    Copy-Item -LiteralPath $script:PrivateKeyPath -Destination $insidePrivate
    $insideArgs = Get-SignerArguments $trustedInsideCase
    $insideArgs.PrivateKeyPath = $insidePrivate
    Assert-Throws { $null = Invoke-Signer $insideArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_TRUSTED_INPUT_INSIDE_EXCHANGE_REJECTED'

    $expired = New-RequestFixture 'expired' -IssuedOffsetSeconds -700 -ValiditySeconds 600
    $expiredArgs = Get-SignerArguments $expired
    Assert-Throws { $null = Invoke-Signer $expiredArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_REQUEST_EXPIRED_OR_TIME_INVALID'

    $future = New-RequestFixture 'future' -IssuedOffsetSeconds 60 -ValiditySeconds 600
    $futureArgs = Get-SignerArguments $future
    Assert-Throws { $null = Invoke-Signer $futureArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_REQUEST_EXPIRED_OR_TIME_INVALID'

    $crossBinding = New-RequestFixture 'cross-binding' -PayloadMutation {
        param($payload)
        $payload.paper_jar_sha256 = '5' * 64
    }
    $crossBindingArgs = Get-SignerArguments $crossBinding
    Assert-Throws { $null = Invoke-Signer $crossBindingArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_CROSS_BINDING_INVALID|paper_jar_sha256'

    $scalarProviders = New-RequestFixture 'scalar-provider-ids' -PayloadMutation {
        param($payload)
        $payload.genuine_provider_ids = 'grim,vulcan'
    }
    $scalarProviderArgs = Get-SignerArguments $scalarProviders
    Assert-Throws { $null = Invoke-Signer $scalarProviderArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_COMPLEX_TYPE_INVALID'

    $stringSize = New-RequestFixture 'string-size' -RequestMutation {
        param($request)
        $request.paper_jar_size_bytes = '203'
    }
    $stringSizeArgs = Get-SignerArguments $stringSize
    Assert-Throws { $null = Invoke-Signer $stringSizeArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_INTEGER_TYPE_INVALID|paper_jar_size_bytes'

    $badChallenge = New-RequestFixture 'bad-challenge' -RequestMutation {
        param($request)
        $request.challenge_sha256 = '6' * 64
    }
    $badChallengeArgs = Get-SignerArguments $badChallenge
    Assert-Throws { $null = Invoke-Signer $badChallengeArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_CHALLENGE_HASH_MISMATCH'

    $nonCanonical = New-RequestFixture 'noncanonical-payload' -NonCanonicalPayload
    $nonCanonicalArgs = Get-SignerArguments $nonCanonical
    Assert-Throws { $null = Invoke-Signer $nonCanonicalArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_PAYLOAD_CANONICAL_JSON_INVALID'

    $duplicate = New-RequestFixture 'duplicate-request-property' -DuplicateRequestSchema
    $duplicateArgs = Get-SignerArguments $duplicate
    Assert-Throws { $null = Invoke-Signer $duplicateArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_DUPLICATE_OR_AMBIGUOUS_PROPERTY|request'

    $preexisting = New-RequestFixture 'preexisting-receipt'
    [IO.File]::WriteAllBytes($preexisting.receipt, $utf8.GetBytes('{}'))
    $preexistingArgs = Get-SignerArguments $preexisting
    Assert-Throws { $null = Invoke-Signer $preexistingArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_RECEIPT_PATH_INVALID'

    $relativeOutput = New-RequestFixture 'relative-output' -RequestMutation {
        param($request)
        $request.output_receipt_path = '.\supervisor-receipt.json'
    }
    $relativeOutputArgs = Get-SignerArguments $relativeOutput
    Assert-Throws { $null = Invoke-Signer $relativeOutputArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_OUTPUT_PATH_ABSOLUTE_REQUIRED'

    $operationReplay = New-RequestFixture 'operation-replay' `
        -OperationAttemptId $baseline.operation_attempt_id
    $operationReplayArgs = Get-SignerArguments $operationReplay
    Assert-Throws { $null = Invoke-Signer $operationReplayArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_REPLAY_REJECTED|operation_attempt_id'
    Assert-True (-not (Test-Path -LiteralPath $operationReplay.receipt)) `
        'operation replay wrote a receipt'

    $challengeReplay = New-RequestFixture 'challenge-replay' -Challenge $baseline.challenge
    $challengeReplayArgs = Get-SignerArguments $challengeReplay
    Assert-Throws { $null = Invoke-Signer $challengeReplayArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_REPLAY_REJECTED|challenge_nonce'
    Assert-True (-not (Test-Path -LiteralPath $challengeReplay.receipt)) `
        'challenge replay wrote a receipt'

    $junctionTarget = Join-Path $script:ExchangeRoot 'junction-target'
    [IO.Directory]::CreateDirectory($junctionTarget) | Out-Null
    $junctionFixture = New-RequestFixture 'junction-target/request-case'
    $junction = Join-Path $script:ExchangeRoot 'junction-alias'
    $null = New-Item -ItemType Junction -Path $junction -Target $junctionTarget
    $junctionArgs = Get-SignerArguments $junctionFixture
    $junctionArgs.RequestPath = Join-Path $junction 'request-case\signing-request.json'
    Assert-Throws { $null = Invoke-Signer $junctionArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_REPARSE_PATH_REJECTED|request'

    $secureJunction = Join-Path $temp 'secure-junction'
    $null = New-Item -ItemType Junction -Path $secureJunction -Target $secureRoot
    $descriptorReparse = New-RequestFixture 'descriptor-reparse'
    $descriptorReparseArgs = Get-SignerArguments $descriptorReparse
    $descriptorReparseArgs.ExpectedDescriptorPath = Join-Path $secureJunction 'supervisor-descriptor.json'
    Assert-Throws { $null = Invoke-Signer $descriptorReparseArgs } `
        'PRODUCTION_AUTHORITY_SIGNER_REPARSE_PATH_REJECTED|descriptor'

    $hardLinkFixture = New-RequestFixture 'hard-link-source'
    $hardLinkPath = Join-Path $hardLinkFixture.root 'hard-linked-request.json'
    $null = New-Item -ItemType HardLink -Path $hardLinkPath -Target $hardLinkFixture.request
    $hardLinkArgs = Get-SignerArguments $hardLinkFixture
    $hardLinkArgs.RequestPath = $hardLinkPath
    Assert-Throws { $null = Invoke-Signer $hardLinkArgs } `
        'hard-linked file rejected'

    $runnerPath = Join-Path $temp 'invoke-signer-child.ps1'
    [IO.File]::WriteAllBytes($runnerPath, $utf8.GetBytes(@'
param([string]$Signer,[string]$ArgumentsPath)
$ErrorActionPreference='Stop'
$document=Get-Content -LiteralPath $ArgumentsPath -Raw|ConvertFrom-Json
$arguments=@{}
foreach($property in $document.PSObject.Properties){$arguments[$property.Name]=$property.Value}
& $Signer @arguments
'@))
    $script:ChildRunner = $runnerPath
    $script:ChildShell = if ($PSVersionTable.PSEdition -eq 'Core') {
        [string](Get-Command pwsh.exe -CommandType Application | Select-Object -First 1).Source
    } else {
        [string](Get-Command powershell.exe -CommandType Application | Select-Object -First 1).Source
    }

    $sharedOperation = [guid]::NewGuid()
    $operationConcurrentA = New-RequestFixture 'concurrent-operation-a' `
        -OperationAttemptId $sharedOperation
    $operationConcurrentB = New-RequestFixture 'concurrent-operation-b' `
        -OperationAttemptId $sharedOperation
    Invoke-ConcurrentSignerPair $operationConcurrentA $operationConcurrentB `
        'concurrent-operation' 'operation_attempt_id'

    $sharedChallenge = New-Object byte[] 32
    $concurrentRng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $concurrentRng.GetBytes($sharedChallenge) } finally { $concurrentRng.Dispose() }
    $challengeConcurrentA = New-RequestFixture 'concurrent-challenge-a' `
        -Challenge $sharedChallenge
    $challengeConcurrentB = New-RequestFixture 'concurrent-challenge-b' `
        -Challenge $sharedChallenge
    Invoke-ConcurrentSignerPair $challengeConcurrentA $challengeConcurrentB `
        'concurrent-challenge' 'challenge_nonce'

    $ledger = Join-Path $secureRoot '.mcace-production-authority-v4-replay-v2.tsv'
    $raceFixture = New-RequestFixture 'stable-root-race'
    $raceAttackerTarget = Join-Path $script:ExchangeRoot 'stable-root-attacker-target'
    [IO.Directory]::CreateDirectory($raceAttackerTarget) | Out-Null
    $raceJunctionCandidate = Join-Path $script:ExchangeRoot 'stable-root-replacement-junction'
    $null = New-Item -ItemType Junction -Path $raceJunctionCandidate `
        -Target $raceAttackerTarget
    $raceArgsPath = Join-Path $temp 'stable-root-race-args.json'
    Write-Json $raceArgsPath ([pscustomobject](Get-SignerArguments $raceFixture))
    $raceStdout = Join-Path $temp 'stable-root-race-stdout.txt'
    $raceStderr = Join-Path $temp 'stable-root-race-stderr.txt'
    $raceProcess = Start-Process -FilePath $script:ChildShell -ArgumentList @(
        '-NoLogo','-NoProfile','-NonInteractive','-File',$script:ChildRunner,
        '-Signer',$signer,'-ArgumentsPath',$raceArgsPath) -PassThru `
        -RedirectStandardOutput $raceStdout -RedirectStandardError $raceStderr
    $mutexName = 'Local\MCAceProductionAuthoritySignerV1-' +
        (Get-BytesSha256 $utf8.GetBytes(
            ([IO.Path]::GetFullPath($ledger)).ToLowerInvariant()))
    $mutexProbe = New-Object Threading.Mutex($false, $mutexName)
    $observedSignerLock = $false
    try {
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds(20)
        while ([DateTimeOffset]::UtcNow -lt $deadline -and -not $observedSignerLock) {
            $probeOwns = $false
            try { $probeOwns = $mutexProbe.WaitOne(0) }
            catch [Threading.AbandonedMutexException] { $probeOwns = $true }
            if ($probeOwns) {
                $mutexProbe.ReleaseMutex()
                Start-Sleep -Milliseconds 10
            } else { $observedSignerLock = $true }
        }
        Assert-True $observedSignerLock 'stable-root race did not observe signer mutex ownership'
        $displacedRoot = Join-Path $script:ExchangeRoot 'stable-root-race-displaced'
        $renameRejected = $false
        try { [IO.Directory]::Move($raceFixture.root, $displacedRoot) }
        catch { $renameRejected = $true }
        Assert-True $renameRejected `
            'stable allowed-root handle permitted rename/junction replacement prerequisite'
        Assert-True (Test-Path -LiteralPath $raceFixture.root -PathType Container) `
            'stable allowed-root path disappeared during adversarial rename'
        Assert-True ((Get-Item -LiteralPath $raceJunctionCandidate -Force).LinkType -eq
            'Junction') 'adversarial replacement junction fixture missing'
    } finally { $mutexProbe.Dispose() }
    $raceProcess.WaitForExit()
    $raceProcess.Refresh()
    $raceOutput = [IO.File]::ReadAllText($raceStdout)
    $raceError = [IO.File]::ReadAllText($raceStderr)
    Assert-True ($raceOutput -clike '*PRODUCTION_AUTHORITY_V4_SIGNER_FIXTURE_CREATED*' -and
        [string]::IsNullOrWhiteSpace($raceError)) `
        "stable-root signer failed: stdout=$raceOutput;stderr=$raceError"

    Assert-True (Test-Path -LiteralPath $ledger -PathType Leaf) 'replay ledger missing'
    $ledgerRaw = [IO.File]::ReadAllText($ledger, $utf8Strict)
    Assert-True (-not $ledgerRaw.Contains("`r") -and $ledgerRaw.EndsWith("`n")) `
        'replay ledger is not strict LF TSV data'
    Assert-True (@($ledgerRaw -split "`n" | Where-Object { $_ -ne '' }).Count -eq 5) `
        'unexpected replay-ledger successful signature count'

    Write-Output (("PRODUCTION_AUTHORITY_V4_REPOSITORY_SIGNER_TEST_PASS|engine={0}-{1}" +
        '|positive=5|negative=32|reparse=2|hardlink=1|replay=independent|concurrency=operation+challenge|stable-root-race=true|allowlist=true') -f
        $PSVersionTable.PSEdition,$PSVersionTable.PSVersion)
} finally {
    if ([IO.Directory]::Exists($temp)) {
        Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue
    }
}
