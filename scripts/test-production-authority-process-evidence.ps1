[CmdletBinding()]
param([switch]$PublisherSmoke)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$collector=Join-Path $PSScriptRoot 'production-authority-process-evidence.ps1'
$provisioner=Join-Path $PSScriptRoot 'provision-production-authority.ps1'
$repoRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$utf8=New-Object Text.UTF8Encoding($false)
$openssl=(Get-Command openssl.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
$openssl=[IO.Path]::GetFullPath($openssl);$opensslHash=(Get-FileHash $openssl -Algorithm SHA256).Hash.ToLowerInvariant()
$sourceCommit=(& git -C $repoRoot rev-parse HEAD).Trim().ToLowerInvariant()
$temp=Join-Path ([IO.Path]::GetTempPath()) ('mcace-authority-producer-v4-'+[guid]::NewGuid().ToString('N'))
$oldApproved=$env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256
$oldOpenSslPath=$env:MCACE_RELEASE_AUTHORITY_OPENSSL_PATH
$oldOpenSslSha=$env:MCACE_RELEASE_AUTHORITY_OPENSSL_SHA256
$publishedIndex=$null;$publishedDirectory=$null

function Assert-True([bool]$Condition,[string]$Message){if(-not$Condition){throw "PRODUCTION_AUTHORITY_V4_TEST_FAILED|$Message"}}
function Assert-Throws([scriptblock]$Action,[string]$Expected){$threw=$false;try{&$Action}catch{$threw=$true;Assert-True ($_.Exception.Message-clike "*$Expected*") "expected=$Expected actual=$($_.Exception.Message)"};Assert-True $threw "expected failure missing: $Expected"}
function Hash-Bytes([byte[]]$Bytes){$sha=[Security.Cryptography.SHA256]::Create();try{return([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}}
function Hash-File([string]$Path){return(Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Bytes([string]$Path,[byte[]]$Bytes){$parent=[IO.Path]::GetDirectoryName($Path);if(-not[IO.Directory]::Exists($parent)){[IO.Directory]::CreateDirectory($parent)|Out-Null};[IO.File]::WriteAllBytes($Path,$Bytes)}
function Json-Bytes([object]$Value,[bool]$Newline=$true){$text=(($Value|ConvertTo-Json -Depth 30 -Compress)-replace "`r`n","`n");if($Newline){$text+="`n"};return $utf8.GetBytes($text)}
function Write-Json([string]$Path,[object]$Value){Write-Bytes $Path (Json-Bytes $Value $true)}
function Descriptor([string]$Path,[string]$Leaf){[byte[]]$b=[IO.File]::ReadAllBytes($Path);return [pscustomobject][ordered]@{relative_path=$Leaf;sha256=(Hash-Bytes $b);size_bytes=[long]$b.Length}}

function Set-PrivateDirectoryAcl([string]$Path){
    $current=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($current)
    $inheritance=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach($sid in @($current,$system)){
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $sid,[Security.AccessControl.FileSystemRights]::FullControl,$inheritance,
            [Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)))
    }
    Set-Acl -LiteralPath $Path -AclObject $acl
}

# The provisioner pins the complete application-local OpenSSL runtime, not only
# openssl.exe.  Keep this fixture manifest byte-for-byte compatible with the
# production parser so the process-evidence test exercises the same boundary.
function New-OpenSslRuntimeManifest([string]$Root,[string]$Path){
    $rootFull=[IO.Path]::GetFullPath($Root).TrimEnd('\','/')
    $entries=@(Get-ChildItem -LiteralPath $Root -Recurse -Force -File | ForEach-Object {
        $relative=[IO.Path]::GetFullPath($_.FullName).Substring($rootFull.Length+1).Replace('\','/')
        $role=if($relative-ceq'openssl.exe'){'EXECUTABLE'}elseif($relative-ceq'openssl.cnf'){'CONFIG'}elseif($relative.StartsWith('providers/',[StringComparison]::Ordinal)){'PROVIDER_MODULE'}else{'APPLICATION_LOCAL_DLL'}
        [pscustomobject][ordered]@{relative_path=$relative;role=$role;size_bytes=[long]$_.Length;sha256=(Hash-File $_.FullName)}
    })
    $sorted=New-Object Collections.ArrayList
    foreach($entry in $entries){
        $at=0
        while($at-lt$sorted.Count -and [StringComparer]::Ordinal.Compare([string]$sorted[$at].relative_path,[string]$entry.relative_path)-lt 0){$at++}
        $sorted.Insert($at,$entry)
    }
    $entries=@($sorted.ToArray())
    $document=[ordered]@{schema='MCACE_OPENSSL_RUNTIME_MANIFEST_V1';artifact_class='REVIEWED_OPENSSL_RUNTIME';platform='windows-x64';executable_relative_path='openssl.exe';files=$entries;test_fixture=$false}
    Write-Json $Path $document
    return [pscustomobject]@{path=$Path;sha256=(Hash-File $Path)}
}

Add-Type -AssemblyName System.IO.Compression -ErrorAction SilentlyContinue
if(-not('MCAceAuthorityTestCrc32CV4' -as[type])){Add-Type -TypeDefinition @'
public static class MCAceAuthorityTestCrc32CV4 { public static uint Compute(byte[] v){uint c=0xffffffffu;foreach (byte b in v){c^=b;for(int i=0;i<8;i++)c=(c>>1)^((c&1u)!=0?0x82f63b78u:0u);}return ~c;} }
'@}

function New-Jar([string]$Path,[string]$Entry){
    $memory=New-Object IO.MemoryStream;$zip=New-Object IO.Compression.ZipArchive($memory,[IO.Compression.ZipArchiveMode]::Create,$true)
    try{$e=$zip.CreateEntry($Entry,[IO.Compression.CompressionLevel]::NoCompression);$s=$e.Open();try{[byte[]]$payload=1..192;$s.Write($payload,0,$payload.Length)}finally{$s.Dispose()}}
    finally{$zip.Dispose()};Write-Bytes $Path $memory.ToArray();$memory.Dispose()
}

function New-ReleaseBundle([string]$Root,[switch]$FakePaper){
    [IO.Directory]::CreateDirectory($Root)|Out-Null
    $jars=[ordered]@{
        'mcace-client-fabric-1.21.11.jar'='fabric/client/Client.class'
        'mcace-client-fabric-26.1.2.jar'='fabric/client/Client.class'
        'mcace-client-fabric-26.2.jar'='fabric/client/Client.class'
        'mcace-server-velocity.jar'='com/ellan/mcace/velocity/MCAceVelocityPlugin.class'
        'mcace-server-bungeecord.jar'='com/ellan/mcace/bungeecord/MCAceBungeePlugin.class'
        'mcace-server-paper.jar'='com/ellan/mcace/paper/MCAcePaperPlugin.class'
    }
    $manifest=[ordered]@{schema='MCACE_RELEASE_BUNDLE_V4';bundle_profile='RELEASE';release_identity='true';deployable_count='6';bundle_entry_count='8';product_version='0.0.1';source_commit=$sourceCommit;artifact_source_commit=$sourceCommit;root_java_version='25';root_java_specification_version='25';root_gradle_version='9.1';modern_java_version='25';modern_java_specification_version='25';modern_gradle_version='9.1'}
    $sums=New-Object 'Collections.Generic.List[string]'
    foreach ($entry in $jars.GetEnumerator()){
        $path=Join-Path $Root $entry.Key
        if($FakePaper -and $entry.Key-ceq'mcace-server-paper.jar'){Write-Bytes $path ([byte[]](1..200))}else{New-Jar $path $entry.Value}
        $hash=Hash-File $path;$key=$entry.Key.Remove($entry.Key.Length-4).Replace('-','_').Replace('.','_')
        $manifest["artifact.$key.file"]=$entry.Key;$manifest["artifact.$key.sha256"]=$hash
        if($entry.Key-like'mcace-client-fabric-*'){$target=$entry.Key.Substring(20,$entry.Key.Length-24);$manifest["artifact.$key.minecraft_version"]=$target;$manifest["artifact.$key.client_build_id"]="fabric-$target-$sourceCommit"}
        $sums.Add("$hash  $($entry.Key)")
    }
    $lines=@($manifest.Keys|ForEach-Object{"$_=$($manifest[$_])"})-join"`n"
    Write-Bytes (Join-Path $Root 'release-manifest.properties') $utf8.GetBytes($lines+"`n")
    Write-Bytes (Join-Path $Root 'SHA256SUMS') $utf8.GetBytes(($sums-join"`n")+"`n")
}

function Varint([uint64]$Value){$l=New-Object 'Collections.Generic.List[byte]';do{$b=[byte]($Value -band 0x7f);$Value=$Value -shr 7;if($Value-ne0){$b=[byte]($b -bor 0x80)};$l.Add($b)}while($Value-ne0);return [byte[]]$l.ToArray()}
function Join-Bytes([object[]]$Parts){$m=New-Object IO.MemoryStream;try{foreach ($part in $Parts){[byte[]]$b=$part;$m.Write($b,0,$b.Length)};return [byte[]]$m.ToArray()}finally{$m.Dispose()}}
function P-Var([int]$Number,[uint64]$Value){return Join-Bytes @((Varint ([uint64](($Number -shl 3) -bor 0))),(Varint $Value))}
function P-Bytes([int]$Number,[byte[]]$Value){return Join-Bytes @((Varint ([uint64](($Number -shl 3)-bor2))),(Varint ([uint64]$Value.Length)),$Value)}
function P-Text([int]$Number,[string]$Value){return P-Bytes $Number $utf8.GetBytes($Value)}
function P-Fixed32([int]$Number,[uint32]$Value){[byte[]]$b=[BitConverter]::GetBytes($Value);if(-not[BitConverter]::IsLittleEndian){[Array]::Reverse($b)};return Join-Bytes @((Varint ([uint64](($Number -shl 3)-bor5))),$b)}
function BE32([long]$Value){[byte[]]$b=[BitConverter]::GetBytes([uint32]$Value);if([BitConverter]::IsLittleEndian){[Array]::Reverse($b)};return $b}
function BE64([long]$Value){[byte[]]$b=[BitConverter]::GetBytes([int64]$Value);if([BitConverter]::IsLittleEndian){[Array]::Reverse($b)};return $b}
function CanonText([string]$Value){[byte[]]$b=$utf8.GetBytes($Value);return Join-Bytes @((BE32 $b.Length),$b)}

function Sign-Bytes([string]$Private,[byte[]]$Content,[string]$Scratch){$inputPath=Join-Path $Scratch ('sign-'+[guid]::NewGuid().ToString('N')+'.bin');$sig=Join-Path $Scratch ('sig-'+[guid]::NewGuid().ToString('N')+'.bin');try{Write-Bytes $inputPath $Content;&$openssl pkeyutl -sign -rawin -inkey $Private -keyform DER -in $inputPath -out $sig 2>$null;Assert-True($LASTEXITCODE-eq0)'Ed25519 signing failed';return [byte[]][IO.File]::ReadAllBytes($sig)}finally{foreach ($p in @($inputPath,$sig)){if(Test-Path $p){Remove-Item $p -Force}}}}

function Start-ExternalRequestSigner([string]$RequestPath,[string]$ReceiptPath,
        [string]$PrivateKeyPath,[string]$Mode='valid',[string]$ReplayReceiptPath=''){
    $signerRoot=Join-Path $temp ('external-signer-'+[guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($signerRoot)|Out-Null
    $configPath=Join-Path $signerRoot 'config.json';$scriptPath=Join-Path $signerRoot 'signer.ps1'
    Write-Json $configPath ([ordered]@{request=$RequestPath;receipt=$ReceiptPath;private_key=$PrivateKeyPath;openssl=$openssl;mode=$Mode;replay_receipt=$ReplayReceiptPath})
    $signerSource=@'
param([Parameter(Mandatory=$true)][string]$ConfigPath)
$ErrorActionPreference='Stop';$utf8=New-Object Text.UTF8Encoding($false)
$c=Get-Content -LiteralPath $ConfigPath -Raw|ConvertFrom-Json
$deadline=[DateTimeOffset]::UtcNow.AddSeconds(600)
$requestBytes=$null
while($null-eq$requestBytes){if([DateTimeOffset]::UtcNow-ge$deadline){exit 42};if([IO.File]::Exists([string]$c.request)){try{$memory=$null;$stream=[IO.FileStream]::new([string]$c.request,[IO.FileMode]::Open,[IO.FileAccess]::Read,([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete));try{$memory=[IO.MemoryStream]::new();$stream.CopyTo($memory);$requestBytes=$memory.ToArray()}finally{if($null-ne$memory){$memory.Dispose()};$stream.Dispose()}}catch [IO.IOException]{$requestBytes=$null}};if($null-eq$requestBytes){Start-Sleep -Milliseconds 50}}
if([string]$c.mode-ceq'replay_receipt'){$temporary=([string]$c.receipt)+'.'+[guid]::NewGuid().ToString('N')+'.tmp';[IO.File]::Copy([string]$c.replay_receipt,$temporary);[IO.File]::Move($temporary,[string]$c.receipt);exit 0}
$request=$utf8.GetString($requestBytes)|ConvertFrom-Json
[byte[]]$payload=[Convert]::FromBase64String([string]$request.signed_payload_base64)
if([string]$c.mode-ceq'payload_mutation'){$payload[$payload.Length-2]=$payload[$payload.Length-2]-bxor1}
$input=Join-Path ([IO.Path]::GetDirectoryName($ConfigPath)) 'payload.bin';$signature=Join-Path ([IO.Path]::GetDirectoryName($ConfigPath)) 'signature.bin'
[IO.File]::WriteAllBytes($input,$payload)
& ([string]$c.openssl) pkeyutl -sign -rawin -inkey ([string]$c.private_key) -keyform DER -in $input -out $signature 2>$null
if($LASTEXITCODE-ne0){exit 43}
[byte[]]$sig=[IO.File]::ReadAllBytes($signature);if([string]$c.mode-ceq'bad_signature'){$sig[0]=$sig[0]-bxor1}
$sha=[Security.Cryptography.SHA256]::Create();try{$hash=([BitConverter]::ToString($sha.ComputeHash($payload))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
$receipt=[ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1';signed_payload_base64=[Convert]::ToBase64String($payload);signed_payload_sha256=$hash;signature_base64=[Convert]::ToBase64String($sig)}
$bytes=$utf8.GetBytes((($receipt|ConvertTo-Json -Depth 8)-replace"`r`n","`n")+"`n")
if([string]$c.mode-ceq'request_mutation'){Start-Sleep -Milliseconds 100;[byte[]]$mutation=$utf8.GetBytes(" `n");$changed=$false;for($attempt=0;$attempt-lt200-and-not$changed;$attempt++){try{$current=[IO.File]::ReadAllBytes([string]$c.request);[byte[]]$mutated=New-Object byte[] ($current.Length+$mutation.Length);[Array]::Copy($current,0,$mutated,0,$current.Length);[Array]::Copy($mutation,0,$mutated,$current.Length,$mutation.Length);$temporary=([string]$c.request)+'.'+[guid]::NewGuid().ToString('N')+'.tmp';[IO.File]::WriteAllBytes($temporary,$mutated);try{[IO.File]::Replace($temporary,[string]$c.request,$null,$true)}catch [PlatformNotSupportedException]{[IO.File]::Move($temporary,[string]$c.request)}$changed=$true}catch [IO.IOException]{if($temporary-and[IO.File]::Exists($temporary)){Remove-Item -LiteralPath $temporary -Force -ErrorAction SilentlyContinue};Start-Sleep -Milliseconds 10}};if(-not$changed){exit 44}}
$temporary=([string]$c.receipt)+'.'+[guid]::NewGuid().ToString('N')+'.tmp';[IO.File]::WriteAllBytes($temporary,$bytes);[IO.File]::Move($temporary,[string]$c.receipt)
'SIGNER_OK'
'@
    Write-Bytes $scriptPath $utf8.GetBytes($signerSource)
    $engine=(Get-Process -Id $PID).Path
    return Start-Process -FilePath $engine -ArgumentList @('-NoProfile','-NonInteractive','-File',('"'+$scriptPath+'"'),'-ConfigPath',('"'+$configPath+'"')) -PassThru -WindowStyle Hidden
}

function Set-PackageReceiptTimes([string]$PackageRoot,[DateTimeOffset]$Issued,[DateTimeOffset]$Expires,
        [string]$PrivateKey){
    $path=Join-Path $PackageRoot 'supervisor-receipt.json';$receipt=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    [byte[]]$payloadBytes=[Convert]::FromBase64String([string]$receipt.signed_payload_base64);$payload=$utf8.GetString($payloadBytes)|ConvertFrom-Json
    $payload.issued_at=$Issued.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ');$payload.expires_at=$Expires.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    $payloadBytes=Json-Bytes $payload $false;$sig=Sign-Bytes $PrivateKey $payloadBytes $PackageRoot
    Write-Json $path ([ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1';signed_payload_base64=[Convert]::ToBase64String($payloadBytes);signed_payload_sha256=(Hash-Bytes $payloadBytes);signature_base64=[Convert]::ToBase64String($sig)})
}

function Set-PackageReceiptPayloadField([string]$PackageRoot,[string]$Name,[object]$Value,
        [string]$PrivateKey){
    $path=Join-Path $PackageRoot 'supervisor-receipt.json';$receipt=Get-Content -LiteralPath $path -Raw|ConvertFrom-Json
    [byte[]]$payloadBytes=[Convert]::FromBase64String([string]$receipt.signed_payload_base64);$payload=$utf8.GetString($payloadBytes)|ConvertFrom-Json
    $payload.$Name=$Value;$payloadBytes=Json-Bytes $payload $false;$sig=Sign-Bytes $PrivateKey $payloadBytes $PackageRoot
    Write-Json $path ([ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1';signed_payload_base64=[Convert]::ToBase64String($payloadBytes);signed_payload_sha256=(Hash-Bytes $payloadBytes);signature_base64=[Convert]::ToBase64String($sig)})
}

function New-Envelope([int]$Packet,[string]$Session,[byte[]]$Payload,[string]$Private,[string]$Scratch,[byte[]]$Nonce){
    $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$crc=[MCAceAuthorityTestCrc32CV4]::Compute($Payload)
    $header=Join-Bytes @((P-Var 1 1),(P-Var 2 ([uint64]$Packet)),(P-Text 3 $Session),(P-Var 4 ([uint64]$now)),(P-Bytes 5 $Nonce),(P-Var 6 ([uint64]$Payload.Length)),(P-Fixed32 7 $crc))
    $signing=Join-Bytes @((BE32 $header.Length),$header,$Payload);$signature=Sign-Bytes $Private $signing $Scratch
    return Join-Bytes @((P-Bytes 1 $header),(P-Bytes 2 $Payload),(P-Bytes 3 $signature))
}

function Grant-Commitment([byte[]]$Payload){return Hash-Bytes (Join-Bytes @((CanonText 'mcace/backend-authority/grant/v1'),(BE32 $Payload.Length),$Payload))}
function Provider-Commitment([string]$Profile,[object[]]$Providers){
    $parts=New-Object 'Collections.Generic.List[object]';$parts.Add((CanonText 'mcace/server-authority/provider-profile/v1'));$parts.Add((CanonText $Profile));$parts.Add((BE32 $Providers.Count))
    foreach ($p in @($Providers|Sort-Object provider_id)){foreach ($n in @('trust_domain_id','provider_id','provider_version','stable_check_family')){$parts.Add((CanonText ([string]$p.$n)))};$parts.Add((BE32 ([long]$p.threshold)));$parts.Add((BE32 ([long]$p.observed_count)));$parts.Add((BE64 ([long]$p.window_started_at_epoch_ms)));$parts.Add((BE64 ([long]$p.window_ended_at_epoch_ms)))}
    return Hash-Bytes (Join-Bytes $parts.ToArray())
}
function Event-Chain([long]$Ordinal,[string]$Previous,[string]$BodyHash){return Hash-Bytes (Join-Bytes @((CanonText 'mcace/production-authority/raw-event-chain/v4'),(BE64 $Ordinal),(CanonText $Previous),(CanonText $BodyHash)))}
function Raw-Root([object]$CaptureDescriptor,[object]$Files){$parts=New-Object 'Collections.Generic.List[object]';$parts.Add((CanonText 'mcace/production-authority/ordered-raw-set/v1'));$parts.Add((CanonText $CaptureDescriptor.sha256));$parts.Add((BE64 $CaptureDescriptor.size_bytes));$parts.Add((BE32 $Files.Count));foreach ($e in $Files.GetEnumerator()){$parts.Add((CanonText $e.Key));$parts.Add((CanonText $e.Value.relative_path));$parts.Add((CanonText $e.Value.sha256));$parts.Add((BE64 $e.Value.size_bytes))};return Hash-Bytes (Join-Bytes $parts.ToArray())}
function Frame-Set([object[]]$Frames){$parts=New-Object 'Collections.Generic.List[object]';$parts.Add((CanonText 'mcace/production-authority/raw-frame-set/v1'));$parts.Add((BE32 2));foreach ($f in $Frames){$parts.Add((CanonText $f.frame_type));$parts.Add((CanonText $f.input_frame_sha256));$parts.Add((CanonText $f.signed_frame_sha256));$parts.Add((CanonText $f.key_id_sha256))};return Hash-Bytes (Join-Bytes $parts.ToArray())}

function New-EventEnvelope([long]$Ordinal,[string]$Previous,[object]$Body){[byte[]]$body=Json-Bytes $Body $false;$bodyHash=Hash-Bytes $body;$chain=Event-Chain $Ordinal $Previous $bodyHash;return [pscustomobject]@{envelope=[pscustomobject][ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_RAW_EVENT_ENVELOPE_V4';ordinal=$Ordinal;previous_event_sha256=$Previous;event_body_base64=[Convert]::ToBase64String($body);event_body_sha256=$bodyHash;event_chain_sha256=$chain};chain=$chain}}
function Write-Jsonl([string]$Path,[object[]]$Records){$lines=@($Records|ForEach-Object{($_|ConvertTo-Json -Depth 30 -Compress)-replace"`r`n","`n"});Write-Bytes $Path $utf8.GetBytes(($lines-join"`n")+"`n")}

function New-CaptureFixture([string]$Root,[string]$Mutation,[string]$ProvisionRoot,[string]$Descriptor,[string]$SupervisorPrivate,[string]$Bundle){
    [IO.Directory]::CreateDirectory($Root)|Out-Null;Copy-Item (Join-Path $ProvisionRoot 'freeze-manifest.json') (Join-Path $Root 'freeze-manifest.json')
    $freeze=Get-Content (Join-Path $Root 'freeze-manifest.json')-Raw|ConvertFrom-Json
    $profile=[string]$freeze.profile.sha256;$backendKey=[string]$freeze.backend_authority.backend_key_id_sha256;$proxyKey=[string]$freeze.proxy_authority.proxy_identity_key_id_sha256
    $backendPrivate=Join-Path $ProvisionRoot 'paper/authority/backend-private-key.pk8';$proxyPrivate=Join-Path $ProvisionRoot 'velocity/identity/server-private-key.pk8'
    $artifactPaths=[ordered]@{java_runtime='artifacts/java-runtime.bin';minecraft_client='artifacts/minecraft-client.jar';fabric_loader='artifacts/fabric-loader.jar';mcace_client_fabric='artifacts/mcace-client-fabric.jar';paper_server='artifacts/paper-server.jar';mcace_server_paper='artifacts/mcace-server-paper.jar';grim='artifacts/grim.jar';vulcan='artifacts/vulcan.jar';mcace_server_velocity='artifacts/mcace-server-velocity.jar';mcace_server_bungeecord='artifacts/mcace-server-bungeecord.jar'}
    Write-Bytes (Join-Path $Root $artifactPaths.java_runtime) $utf8.GetBytes('java-runtime-v4')
    foreach ($role in @('minecraft_client','fabric_loader','mcace_client_fabric','paper_server','grim','vulcan')){New-Jar (Join-Path $Root $artifactPaths[$role]) "fixture/$role/Main.class"}
    Copy-Item (Join-Path $Bundle 'mcace-server-paper.jar') (Join-Path $Root $artifactPaths.mcace_server_paper)
    Copy-Item (Join-Path $Bundle 'mcace-server-velocity.jar') (Join-Path $Root $artifactPaths.mcace_server_velocity)
    Copy-Item (Join-Path $Bundle 'mcace-server-bungeecord.jar') (Join-Path $Root $artifactPaths.mcace_server_bungeecord)
    $artifact=[ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_ARTIFACT_MANIFEST_V4';source_commit=$sourceCommit;artifact_source_commit=$sourceCommit}
    foreach ($role in $artifactPaths.Keys){$path=Join-Path $Root $artifactPaths[$role];$bundleFile=if($role-ceq'mcace_server_paper'){'mcace-server-paper.jar'}elseif($role-ceq'mcace_server_velocity'){'mcace-server-velocity.jar'}elseif($role-ceq'mcace_server_bungeecord'){'mcace-server-bungeecord.jar'}else{''};$entry=[ordered]@{relative_path=$artifactPaths[$role];sha256=(Hash-File $path);size_bytes=[long](Get-Item $path).Length;version="v4-$role";release_bundle_file=$bundleFile};if($role-ceq'vulcan'){$entry.licensed=$true;$entry.reviewed=$true;$entry.review_sha256=$entry.sha256};$artifact[$role]=$entry}
    Write-Json (Join-Path $Root 'artifact-manifest.json') $artifact

    $session=if($Mutation-ceq'wrong_session'){'session-observation-wrong'}else{'session-authority-v4'};$grantSession='session-authority-v4';$sessionHash=Hash-Bytes $utf8.GetBytes($session);$grantSessionHash=Hash-Bytes $utf8.GetBytes($grantSession)
    $player='11111111-1111-4111-8111-111111111111';$grantId='22222222-2222-4222-8222-222222222222';$attestation='33333333-3333-4333-8333-333333333333';[byte[]]$binding=1..32;[byte[]]$challenge=33..64
    $now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds();$grantPayload=Join-Bytes @((P-Var 1 1),(P-Text 2 $grantId),(P-Text 3 'velocity-a'),(P-Text 4 'paper-a'),(P-Text 5 $player),(P-Text 6 $grantSession),(P-Bytes 7 $binding),(P-Var 8 7),(P-Var 9 1),(P-Var 10 ([uint64]$now)),(P-Var 11 ([uint64]($now+30000))),(P-Bytes 12 $challenge))
    [byte[]]$nonceGrant=1..32;[byte[]]$nonceObservation=if($Mutation-ceq'replay_nonce'){1..32}else{65..96}
    $grantFrame=New-Envelope 21 $grantSession $grantPayload $proxyPrivate $Root $nonceGrant;$grantCommit=Grant-Commitment $grantPayload
    $providers=@(
        [pscustomobject][ordered]@{trust_domain_id='grim-domain';provider_id='grim';provider_version='2.3.69';stable_check_family='grim-prediction';threshold=5;observed_count=5;window_started_at_epoch_ms=$now;window_ended_at_epoch_ms=$now+1000},
        [pscustomobject][ordered]@{trust_domain_id='vulcan-domain';provider_id='vulcan';provider_version='2.9.0';stable_check_family='vulcan-speed';threshold=3;observed_count=3;window_started_at_epoch_ms=$now;window_ended_at_epoch_ms=$now+1000})
    $profileForFrame=if($Mutation-ceq'wrong_profile'){'0'*64}else{$profile};[byte[]]$profileBytes=for($i=0;$i-lt64;$i+=2){[Convert]::ToByte($profileForFrame.Substring($i,2),16)}
    [byte[]]$backendKeyBytes=for($i=0;$i-lt64;$i+=2){[Convert]::ToByte($backendKey.Substring($i,2),16)};[byte[]]$grantCommitBytes=for($i=0;$i-lt64;$i+=2){[Convert]::ToByte($grantCommit.Substring($i,2),16)}
    $providerProto=New-Object 'Collections.Generic.List[object]';foreach ($p in $providers){$providerProto.Add((Join-Bytes @((P-Text 1 $p.trust_domain_id),(P-Text 2 $p.provider_id),(P-Text 3 $p.provider_version),(P-Text 4 $p.stable_check_family),(P-Var 5 $p.threshold),(P-Var 6 $p.observed_count),(P-Var 7 ([uint64]$p.window_started_at_epoch_ms)),(P-Var 8 ([uint64]$p.window_ended_at_epoch_ms)))))}
    $obParts=New-Object 'Collections.Generic.List[object]';foreach ($x in @((P-Var 1 1),(P-Text 2 $attestation),(P-Text 3 'paper-a'),(P-Bytes 4 $backendKeyBytes),(P-Text 5 $player),(P-Text 6 $session),(P-Text 7 $grantId),(P-Bytes 8 $grantCommitBytes),(P-Bytes 9 $binding),(P-Var 10 7),(P-Var 11 1),(P-Var 12 ([uint64]$now)),(P-Var 13 ([uint64]$now)),(P-Var 14 ([uint64]($now+30000))),(P-Bytes 15 $profileBytes))){$obParts.Add($x)};foreach ($p in $providerProto){$obParts.Add((P-Bytes 16 $p))};$obPayload=Join-Bytes $obParts.ToArray();$obFrame=New-Envelope 22 $session $obPayload $backendPrivate $Root $nonceObservation
    if($Mutation-ceq'bad_signature'){$obFrame[$obFrame.Length-1]=$obFrame[$obFrame.Length-1]-bxor0x40}
    $frameRecords=@(
        [pscustomobject][ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_RAW_SIGNED_FRAME_V1';ordinal=1;frame_type='BACKEND_AUTHORITY_GRANT';operation_attempt_id='44444444-4444-4444-8444-444444444444';authenticated_session_sha256=$grantSessionHash;key_id_sha256=$proxyKey;input_frame_base64=[Convert]::ToBase64String($grantPayload);input_frame_sha256=(Hash-Bytes $grantPayload);signed_frame_base64=[Convert]::ToBase64String($grantFrame);signed_frame_sha256=(Hash-Bytes $grantFrame);genuine=$true;synthetic=$false;experimental=$false;fixture=$false},
        [pscustomobject][ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_RAW_SIGNED_FRAME_V1';ordinal=2;frame_type='SERVER_AUTHORITY_OBSERVATION';operation_attempt_id='44444444-4444-4444-8444-444444444444';authenticated_session_sha256=$sessionHash;key_id_sha256=if($Mutation-ceq'wrong_key'){$proxyKey}else{$backendKey};input_frame_base64=[Convert]::ToBase64String($obPayload);input_frame_sha256=(Hash-Bytes $obPayload);signed_frame_base64=[Convert]::ToBase64String($obFrame);signed_frame_sha256=(Hash-Bytes $obFrame);genuine=$true;synthetic=$false;experimental=$false;fixture=$false})
    Write-Jsonl (Join-Path $Root 'raw-frames.jsonl') $frameRecords
    $providerCommit=Provider-Commitment $profile $providers;$providerForEvents=@($providers|ForEach-Object{$_|Select-Object *})
    if($Mutation-ceq'commitment_mismatch'){$providerForEvents[1].observed_count=4}
    $base=@{capture_id='55555555-5555-4555-8555-555555555555';operation_attempt_id='44444444-4444-4444-8444-444444444444';authenticated_session_sha256=$sessionHash;profile_sha256=$profile;input_frame_sha256=$frameRecords[1].input_frame_sha256;signed_frame_sha256=$frameRecords[1].signed_frame_sha256;genuine=$true;synthetic=$false;experimental=$false;fixture=$false}
    $bodies=New-Object 'Collections.Generic.List[object]';foreach ($p in $providerForEvents){$bodies.Add([pscustomobject][ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_PROVIDER_EVENT_V4';capture_id=$base.capture_id;operation_attempt_id=$base.operation_attempt_id;event_id="provider-$($p.provider_id)";component='provider';event='PROVIDER_ELIGIBLE';outcome='ELIGIBLE';authenticated_session_sha256=$base.authenticated_session_sha256;profile_sha256=$profile;input_frame_sha256=$base.input_frame_sha256;signed_frame_sha256=$base.signed_frame_sha256;genuine=$true;synthetic=$false;experimental=$false;fixture=$false;process_incarnation_id='paper-incarnation';provider_id=$p.provider_id;trust_domain_id=$p.trust_domain_id;provider_version=$p.provider_version;stable_check_family=$p.stable_check_family;threshold=$p.threshold;observed_count=$p.observed_count;window_started_at_epoch_ms=$p.window_started_at_epoch_ms;window_ended_at_epoch_ms=$p.window_ended_at_epoch_ms})}
    $bodies.Add([pscustomobject][ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_RUNTIME_EVENT_V4';capture_id=$base.capture_id;operation_attempt_id=$base.operation_attempt_id;event_id='paper-observation-signed';component='paper';event='OBSERVATION_SIGNED';outcome='SIGNED_AFTER_JOURNAL_FORCE';authenticated_session_sha256=$sessionHash;profile_sha256=$profile;input_frame_sha256=$frameRecords[1].input_frame_sha256;signed_frame_sha256=$frameRecords[1].signed_frame_sha256;genuine=$true;synthetic=$false;experimental=$false;fixture=$false;process_incarnation_id='paper-incarnation'})
    $bodies.Add([pscustomobject][ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_RUNTIME_EVENT_V4';capture_id=$base.capture_id;operation_attempt_id=$base.operation_attempt_id;event_id='proxy-grant-signed';component='proxy';event='GRANT_SIGNED';outcome='SIGNED';authenticated_session_sha256=$grantSessionHash;profile_sha256=$profile;input_frame_sha256=$frameRecords[0].input_frame_sha256;signed_frame_sha256=$frameRecords[0].signed_frame_sha256;genuine=$true;synthetic=$false;experimental=$false;fixture=$false;process_incarnation_id='proxy-incarnation'})
    $bodies.Add([pscustomobject][ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_RUNTIME_EVENT_V4';capture_id=$base.capture_id;operation_attempt_id=$base.operation_attempt_id;event_id='proxy-observation-verified';component='proxy';event='OBSERVATION_VERIFIED';outcome='SERVER_CONFIRMED';authenticated_session_sha256=$sessionHash;profile_sha256=$profile;input_frame_sha256=$frameRecords[1].input_frame_sha256;signed_frame_sha256=$frameRecords[1].signed_frame_sha256;genuine=$true;synthetic=$false;experimental=$false;fixture=$false;process_incarnation_id='proxy-incarnation'})
    $envelopes=New-Object 'Collections.Generic.List[object]';$prev='0'*64;$ordinal=1;foreach ($body in $bodies){$e=New-EventEnvelope $ordinal $prev $body;$envelopes.Add([pscustomobject]@{component=$body.component;envelope=$e.envelope});$prev=$e.chain;$ordinal++}
    Write-Jsonl (Join-Path $Root 'provider-events.jsonl') @($envelopes|Where-Object component -eq 'provider'|ForEach-Object envelope)
    Write-Jsonl (Join-Path $Root 'paper-events.jsonl') @($envelopes|Where-Object component -eq 'paper'|ForEach-Object envelope)
    Write-Jsonl (Join-Path $Root 'proxy-events.jsonl') @($envelopes|Where-Object component -eq 'proxy'|ForEach-Object envelope)
    $journal=[ordered]@{schema='MCACE_SERVER_AUTHORITY_ISSUANCE_RECORD_V3';capture_id=$base.capture_id;operation_attempt_id=$base.operation_attempt_id;attestation_id=$attestation;observation_sequence=1;authenticated_session_sha256=$sessionHash;profile_sha256=$profile;provider_evidence_commitment_sha256=$providerCommit;input_frame_sha256=$frameRecords[1].input_frame_sha256;signed_frame_sha256=$frameRecords[1].signed_frame_sha256;issued_at_epoch_ms=$now;expires_at_epoch_ms=$now+30000}
    $journalText="MCACE_SERVER_AUTHORITY_ISSUANCE_JOURNAL_V3`n"+[Text.Encoding]::UTF8.GetString((Json-Bytes $journal $false))+"`n";Write-Bytes (Join-Path $Root 'issuance-journal.log') $utf8.GetBytes($journalText)
    $times=[DateTimeOffset]::UtcNow;$processes=@(
        [pscustomobject][ordered]@{role='client';platform='minecraft-client';pid=1001;started_at=$times.AddMinutes(-4).ToString('yyyy-MM-ddTHH:mm:ss.fffZ');stopped_at=$times.AddMinutes(-1).ToString('yyyy-MM-ddTHH:mm:ss.fffZ');exit_code=0;executable_sha256=$artifact.java_runtime.sha256;loaded_artifact_sha256=@($artifact.minecraft_client.sha256,$artifact.fabric_loader.sha256,$artifact.mcace_client_fabric.sha256);process_incarnation_id='client-incarnation';real_process=$true;fixture=$false},
        [pscustomobject][ordered]@{role='paper';platform='paper';pid=1002;started_at=$times.AddMinutes(-4).ToString('yyyy-MM-ddTHH:mm:ss.fffZ');stopped_at=$times.AddMinutes(-1).ToString('yyyy-MM-ddTHH:mm:ss.fffZ');exit_code=0;executable_sha256=$artifact.java_runtime.sha256;loaded_artifact_sha256=@($artifact.mcace_server_paper.sha256,$artifact.grim.sha256,$artifact.vulcan.sha256);process_incarnation_id='paper-incarnation';real_process=$true;fixture=$false},
        [pscustomobject][ordered]@{role='proxy';platform='velocity';pid=1003;started_at=$times.AddMinutes(-4).ToString('yyyy-MM-ddTHH:mm:ss.fffZ');stopped_at=$times.AddMinutes(-1).ToString('yyyy-MM-ddTHH:mm:ss.fffZ');exit_code=0;executable_sha256=$artifact.java_runtime.sha256;loaded_artifact_sha256=@($artifact.mcace_server_velocity.sha256);process_incarnation_id='proxy-incarnation';real_process=$true;fixture=$false})
    Write-Json (Join-Path $Root 'process-ledger.json') ([ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_PROCESS_LEDGER_V4';source_commit=$sourceCommit;artifact_source_commit=$sourceCommit;capture_id=$base.capture_id;operation_attempt_id=$base.operation_attempt_id;mode='EXECUTED_REAL_PROCESSES';processes=$processes;cleanup=[ordered]@{mcace_owned_java_processes=0;server_processes=0;proxy_processes=0;open_ports=0;temporary_files=0;automatic_actions=0}})
    $fileMap=[ordered]@{};foreach ($pair in @(@('freeze_manifest','freeze-manifest.json'),@('artifact_manifest','artifact-manifest.json'),@('provider_events','provider-events.jsonl'),@('paper_events','paper-events.jsonl'),@('proxy_events','proxy-events.jsonl'),@('issuance_journal','issuance-journal.log'),@('process_ledger','process-ledger.json'),@('raw_frames','raw-frames.jsonl'))){$fileMap[$pair[0]]=Descriptor (Join-Path $Root $pair[1]) $pair[1]}
    $started=[DateTimeOffset]::UtcNow.AddMinutes(-3);$completed=[DateTimeOffset]::UtcNow.AddMinutes(-1)
    $capture=[ordered]@{schema=if($Mutation-ceq'old_schema'){'MCACE_PRODUCTION_AUTHORITY_RAW_CAPTURE_V3'}else{'MCACE_PRODUCTION_AUTHORITY_RAW_CAPTURE_V4'};source_mode='EXECUTED_EXTERNAL_SUPERVISOR_PRODUCTION_AUTHORITY';source_commit=$sourceCommit;artifact_source_commit=$sourceCommit;capture_id=$base.capture_id;operation_attempt_id=$base.operation_attempt_id;started_at=$started.ToString('yyyy-MM-ddTHH:mm:ss.fffZ');completed_at=$completed.ToString('yyyy-MM-ddTHH:mm:ss.fffZ');selected_proxy='velocity';operator_session_sha256=('7'*64);supervisor=[ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_V4';supervisor_instance_id='external-supervisor-a';supervisor_run_id='66666666-6666-4666-8666-666666666666';global_sequence_assignment='SUPERVISOR_MONOTONIC_TOTAL_ORDER';event_count=5;event_chain_root_sha256=$prev;fixture=$false};files=$fileMap}
    Write-Json (Join-Path $Root 'capture.json') $capture
    $captureDescriptor=Descriptor (Join-Path $Root 'capture.json') 'capture.json';$rawRoot=Raw-Root $captureDescriptor $fileMap;$frameSet=Frame-Set $frameRecords
    $issued=[DateTimeOffset]::UtcNow.AddSeconds(-20);$expires=if($Mutation-ceq'expired_receipt'){[DateTimeOffset]::UtcNow.AddSeconds(-1)}else{[DateTimeOffset]::UtcNow.AddMinutes(10)}
    $payload=[ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_PAYLOAD_V1';artifact_class='EXTERNAL_SUPERVISOR_SIGNED_PRODUCTION_CAPTURE';source_commit=$sourceCommit;artifact_source_commit=$sourceCommit;product_version='0.0.1';capture_id=$base.capture_id;operation_attempt_id=$base.operation_attempt_id;supervisor_instance_id='external-supervisor-a';supervisor_run_id='66666666-6666-4666-8666-666666666666';signer_key_id_sha256=(Get-Content $Descriptor -Raw|ConvertFrom-Json).key_id_sha256;challenge_nonce_base64=[Convert]::ToBase64String([byte[]](101..132));issued_at=$issued.ToString('yyyy-MM-ddTHH:mm:ss.fffZ');expires_at=$expires.ToString('yyyy-MM-ddTHH:mm:ss.fffZ');raw_capture_manifest_sha256=$captureDescriptor.sha256;raw_capture_manifest_size_bytes=$captureDescriptor.size_bytes;raw_evidence_root_sha256=$rawRoot;raw_frame_set_sha256=$frameSet;raw_frame_count=2;provider_evidence_commitment_sha256=$providerCommit;event_chain_root_sha256=$prev;event_count=5;process_ledger_sha256=$fileMap.process_ledger.sha256;process_ledger_size_bytes=$fileMap.process_ledger.size_bytes;paper_jar_sha256=(Hash-File(Join-Path $Bundle 'mcace-server-paper.jar'));paper_jar_size_bytes=[long](Get-Item(Join-Path $Bundle 'mcace-server-paper.jar')).Length;velocity_jar_sha256=(Hash-File(Join-Path $Bundle 'mcace-server-velocity.jar'));velocity_jar_size_bytes=[long](Get-Item(Join-Path $Bundle 'mcace-server-velocity.jar')).Length;bungeecord_jar_sha256=(Hash-File(Join-Path $Bundle 'mcace-server-bungeecord.jar'));bungeecord_jar_size_bytes=[long](Get-Item(Join-Path $Bundle 'mcace-server-bungeecord.jar')).Length;selected_proxy='velocity';selected_proxy_jar_sha256=(Hash-File(Join-Path $Bundle 'mcace-server-velocity.jar'));profile_sha256=$profile;topology_sha256=[string]$freeze.topology.sha256;backend_key_id_sha256=$backendKey;proxy_key_id_sha256=$proxyKey;action_ceiling='MONITOR';automatic_action_count=0;cleanup_all_zero=$true;licensed_vulcan_sha256=$artifact.vulcan.sha256;genuine_provider_ids=@('grim','vulcan');test_fixture=$false}
    [byte[]]$payloadBytes=Json-Bytes $payload $false;[byte[]]$receiptSig=Sign-Bytes $SupervisorPrivate $payloadBytes $Root
    Write-Json (Join-Path $Root 'receipt.json') ([ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1';signed_payload_base64=[Convert]::ToBase64String($payloadBytes);signed_payload_sha256=(Hash-Bytes $payloadBytes);signature_base64=[Convert]::ToBase64String($receiptSig)})
    if($Mutation-ceq'no_raw_frames'){Remove-Item (Join-Path $Root 'raw-frames.jsonl')-Force}
    return [pscustomobject]@{capture=Join-Path $Root 'capture.json';receipt=Join-Path $Root 'receipt.json';provider_commitment=$providerCommit;raw_root=$rawRoot}
}

$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($collector,[ref]$tokens,[ref]$errors)
Assert-True(@($errors).Count-eq0)"collector AST failed: $($errors-join';')";$source=[IO.File]::ReadAllText($collector)
foreach ($required in @('MCACE_PRODUCTION_AUTHORITY_RAW_CAPTURE_V4','MCACE_PRODUCTION_AUTHORITY_RAW_SIGNED_FRAME_V1','MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_V1','MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_SIGNING_REQUEST_V1','PRODUCTION_AUTHORITY_SIGNING_REQUEST_READY','PRODUCTION_AUTHORITY_RECEIPT_REQUEST_PAYLOAD_MISMATCH','PRODUCTION_AUTHORITY_SIGNING_REQUEST_MUTATED_DURING_HANDOFF','MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V4','MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_V4','MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_V4','Read-LockedRegularFile','FileShare]::None','LOCKED_DOUBLE_READ_MISMATCH','OPENSSL_SCRIPT_SHIM_REJECTED','provider_evidence_commitment_sha256','genuine_provider_ids','release_eligible=$false','PRODUCTION_AUTHORITY_CALLER_BOOLEAN_PROMOTION_REJECTED')){Assert-True $source.Contains($required)"V4 token missing: $required"}
Assert-True(-not$source.Contains('REPORT_V3'))'old V3 report producer remains';Assert-True(-not$source.Contains('RSA-PKCS1-SHA256'))'old RSA capture seal remains'

[IO.Directory]::CreateDirectory($temp)|Out-Null
try{
    # Every collector read locks the executable with FileShare.None.  Give this
    # test process and its external signer a job-private OpenSSL copy so other
    # concurrently running MCAce suites cannot create a false tool-identity
    # failure against the shared installation.
    $openSslSource=$openssl;$openSslSourceDirectory=[IO.Path]::GetDirectoryName($openSslSource);$privateOpenSslDirectory=Join-Path $temp 'openssl-bin';[IO.Directory]::CreateDirectory($privateOpenSslDirectory)|Out-Null
    $openSslRuntimeFiles=@(Get-Item -LiteralPath $openSslSource) +
        @(Get-ChildItem -LiteralPath $openSslSourceDirectory -File -Filter '*.dll')
    foreach($runtimeFile in $openSslRuntimeFiles){Copy-Item -LiteralPath $runtimeFile.FullName -Destination (Join-Path $privateOpenSslDirectory $runtimeFile.Name)}
    $openssl=Join-Path $privateOpenSslDirectory 'openssl.exe';$opensslHash=(Get-FileHash -LiteralPath $openssl -Algorithm SHA256).Hash.ToLowerInvariant()
    [IO.Directory]::CreateDirectory((Join-Path $privateOpenSslDirectory 'providers'))|Out-Null
    # The fixture must contain the same required roles as production: one
    # executable, at least one application-local DLL, one provider module, and
    # the pinned empty config.  Reuse a copied DLL as the provider fixture.
    $runtimeDll=@(Get-ChildItem -LiteralPath $privateOpenSslDirectory -File -Filter '*.dll'|Select-Object -First 1)[0]
    Assert-True($null-ne$runtimeDll)'private OpenSSL runtime DLL missing'
    Copy-Item -LiteralPath $runtimeDll.FullName -Destination (Join-Path $privateOpenSslDirectory 'providers\fixture-provider.dll')
    Write-Bytes (Join-Path $privateOpenSslDirectory 'openssl.cnf') $utf8.GetBytes("# MCAce pinned empty OpenSSL configuration v1`n")
    Set-PrivateDirectoryAcl $privateOpenSslDirectory
    $runtimeManifest=New-OpenSslRuntimeManifest $privateOpenSslDirectory (Join-Path $temp 'openssl-runtime-manifest.json')
    $external=Join-Path $temp 'external';[IO.Directory]::CreateDirectory($external)|Out-Null;$supervisorPrivate=Join-Path $external 'supervisor-private.pk8';$supervisorPublic=Join-Path $external 'supervisor-public.der'
    &$openssl genpkey -algorithm ED25519 -outform DER -out $supervisorPrivate 2>$null;&$openssl pkey -inform DER -in $supervisorPrivate -pubout -outform DER -out $supervisorPublic 2>$null
    [byte[]]$public=[IO.File]::ReadAllBytes($supervisorPublic);$descriptor=Join-Path $external 'descriptor.json';Write-Json $descriptor ([ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_PUBLIC_DESCRIPTOR_V1';artifact_class='EXTERNAL_RELEASE_CAPTURE_SUPERVISOR_PUBLIC_ROOT';algorithm='ED25519';key_id_sha256=(Hash-Bytes $public);public_key_der_base64=[Convert]::ToBase64String($public);test_fixture=$false});$pin=Hash-File $descriptor
    $env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256=$pin;$env:MCACE_RELEASE_AUTHORITY_OPENSSL_PATH=$openssl;$env:MCACE_RELEASE_AUTHORITY_OPENSSL_SHA256=$opensslHash
    $provision=Join-Path $temp 'provision';$pArgs=@{OutputRoot=$provision;ProxyInstanceId='velocity-a';BackendInstanceId='paper-a';RegisteredBackend='survival';ProfileName='production-quorum';ProxyPlatform='VELOCITY';GrimProviderId='grim';GrimTrustDomainId='grim-domain';GrimVersion='2.3.69';GrimStableCheckFamily='grim-prediction';GrimThreshold=5;VulcanProviderId='vulcan';VulcanTrustDomainId='vulcan-domain';VulcanVersion='2.9.0';VulcanStableCheckFamily='vulcan-speed';VulcanThreshold=3;RequiredIndependentDomains=2;MaximumProviderWindowMs=10000;CooldownMs=5000;ObservationTtlMs=30000;GrantTtlMs=30000;JournalQuotaBytes=8388608;CaptureSupervisorPublicDescriptorPath=$descriptor;ExpectedCaptureSupervisorPublicDescriptorSha256=$pin;OpenSslPath=$openssl;ExpectedOpenSslSha256=$opensslHash;OpenSslRuntimeManifestPath=$runtimeManifest.path;ExpectedOpenSslRuntimeManifestSha256=$runtimeManifest.sha256};$null=&$provisioner @pArgs
    $bundle=Join-Path $temp 'bundle';New-ReleaseBundle $bundle
    $baselineRoot=Join-Path $temp 'baseline';$fixture=New-CaptureFixture $baselineRoot 'none' $provision $descriptor $supervisorPrivate $bundle;$output=Join-Path $temp 'evidence-v4'
    $exchange=Join-Path $temp 'exchange-baseline';[IO.Directory]::CreateDirectory($exchange)|Out-Null;$request=Join-Path $exchange 'request.json';$receipt=Join-Path $exchange 'receipt.json'
    $args=@{Mode='Formal';CaptureManifestPath=$fixture.capture;OutputDirectory=$output;CaptureSupervisorPublicDescriptorPath=$descriptor;ExpectedCaptureSupervisorPublicDescriptorSha256=$pin;SupervisorSigningRequestPath=$request;SupervisorReceiptPath=$receipt;SupervisorReceiptWaitSeconds=120;ReleaseBundleRoot=$bundle;OpenSslPath=$openssl;ExpectedOpenSslSha256=$opensslHash}
    $signer=Start-ExternalRequestSigner $request $receipt $supervisorPrivate
    $result=@(&$collector @args);$signer.WaitForExit();Assert-True($signer.ExitCode-eq0)'external signer failed';Assert-True(($result-join"`n")-clike'*PRODUCTION_AUTHORITY_SIGNING_REQUEST_READY*')'signing request ready marker missing';Assert-True(($result-join"`n")-clike'*PRODUCTION_AUTHORITY_PROCESS_EVIDENCE_V4_PASS*')'producer success marker missing'
    $requestDocument=Get-Content -LiteralPath $request -Raw|ConvertFrom-Json;Assert-True([string]$requestDocument.schema-ceq'MCACE_PRODUCTION_AUTHORITY_SUPERVISOR_SIGNING_REQUEST_V1')'signing request schema invalid';Assert-True([string]$requestDocument.output_receipt_path-ceq$receipt)'signing request receipt path invalid';Assert-True([string]$requestDocument.capture_supervisor_descriptor_sha256-ceq$pin)'signing request descriptor pin invalid';Assert-True(-not((Get-Content -LiteralPath $request -Raw)-match'(?i)private|pkcs8'))'signing request contains private-key material'
    $files=@(Get-ChildItem -LiteralPath $output -Force);Assert-True($files.Count-eq15)'output is not exact V4 root set';Assert-True((Test-Path -LiteralPath (Join-Path $output 'artifacts') -PathType Container))'packaged artifact directory missing';Assert-True(@(Get-ChildItem -LiteralPath (Join-Path $output 'artifacts') -File -Force).Count-eq10)'packaged artifact byte set is not exact'
    $report=Get-Content (Join-Path $output 'report.json')-Raw|ConvertFrom-Json;Assert-True([string]$report.schema-ceq'MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_V4')'report schema invalid';Assert-True($report.release_eligible-is[bool]-and-not[bool]$report.release_eligible)'producer promoted release eligibility';Assert-True([string]$report.provider_evidence_commitment_sha256-ceq$fixture.provider_commitment)'provider commitment mismatch'
    $validation=@(&$collector -ValidatePackageRoot $output -ReleaseBundleRoot $bundle -OpenSslPath $openssl -ExpectedOpenSslSha256 $opensslHash);Assert-True(($validation-join"`n")-clike'*PRODUCTION_AUTHORITY_V4_PACKAGE_VALIDATION_PASS*')'package revalidation failed'
    if($PublisherSmoke){
        $publisher=Join-Path $PSScriptRoot 'publish-native-release-evidence.ps1';$evidenceId='server-confirmed-production-test-'+[guid]::NewGuid().ToString('N');$publishedIndex=Join-Path $repoRoot "docs/evidence/$evidenceId.json";$publishedDirectory=Join-Path $repoRoot "docs/evidence/server-confirmed-production/$evidenceId"
        $publishArgs=@{Gate='ProductionAuthority';ReportPath=(Join-Path $output 'report.json');BindingPath=(Join-Path $output 'binding.json');CommitPath=(Join-Path $output 'commit.json');SourceCommit=$sourceCommit;ReleaseBundleRoot=$bundle;EvidenceId=$evidenceId}
        $published=@(&$publisher @publishArgs);Assert-True(($published-join"`n")-clike'*MCACE_NATIVE_RELEASE_EVIDENCE_PUBLISHED|gate=ProductionAuthority*')'authority publisher marker missing';Assert-True(Test-Path -LiteralPath $publishedIndex -PathType Leaf)'authority index missing';Assert-True(Test-Path -LiteralPath $publishedDirectory -PathType Container)'authority evidence directory missing'
        $index=Get-Content -LiteralPath $publishedIndex -Raw|ConvertFrom-Json;Assert-True([string]$index.schema-ceq'MCACE_SERVER_CONFIRMED_PRODUCTION_EVIDENCE_INDEX_V4')'authority index schema invalid';Assert-True($index.release_eligible-is[bool]-and[bool]$index.release_eligible)'publisher did not promote only the verified V4 index';Assert-True(@($index.canonical_evidence.PSObject.Properties).Count-eq14)'publisher omitted canonical raw documents';Assert-True(@($index.packaged_artifacts.PSObject.Properties).Count-eq10)'publisher omitted packaged raw artifacts'
        $replayArgs=$publishArgs.Clone();$replayArgs.EvidenceId='server-confirmed-production-test-'+[guid]::NewGuid().ToString('N');Assert-Throws{$null=&$publisher @replayArgs}'MCACE_NATIVE_EVIDENCE_PRODUCTION_AUTHORITY_RECEIPT_REPLAY_REJECTED'
        foreach($legacyVersion in @('V1','V3')){$legacyRoot=Join-Path $temp ('legacy-publisher-'+$legacyVersion);[IO.Directory]::CreateDirectory($legacyRoot)|Out-Null;$legacyReport=Join-Path $legacyRoot 'report.json';$legacyBinding=Join-Path $legacyRoot 'binding.json';$legacyCommit=Join-Path $legacyRoot 'commit.json';Write-Json $legacyReport ([ordered]@{schema="MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_REPORT_$legacyVersion";generated_at=[DateTimeOffset]::UtcNow.ToString('o');source_mode='EXECUTED_PRODUCTION_AUTHORITY';source_commit=$sourceCommit;release_eligible=$true;passed=$true});Write-Json $legacyBinding ([ordered]@{schema="MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_BINDING_$legacyVersion";generated_at=[DateTimeOffset]::UtcNow.ToString('o');source_commit=$sourceCommit;release_eligible=$true;passed=$true});Write-Json $legacyCommit ([ordered]@{schema="MCACE_SERVER_CONFIRMED_PRODUCTION_AUTHORITY_COMMIT_$legacyVersion";generated_at=[DateTimeOffset]::UtcNow.ToString('o');source_commit=$sourceCommit;release_eligible=$true;committed=$true});Assert-Throws{$null=&$publisher -Gate ProductionAuthority -ReportPath $legacyReport -BindingPath $legacyBinding -CommitPath $legacyCommit -SourceCommit $sourceCommit -ReleaseBundleRoot $bundle -EvidenceId ('server-confirmed-production-legacy-'+$legacyVersion.ToLowerInvariant())}'PRODUCTION_AUTHORITY_PACKAGE_EXACT_V4_SET_REQUIRED'}
        Write-Output "PRODUCTION_AUTHORITY_PUBLISHER_V4_PASS|engine=$($PSVersionTable.PSEdition)-$($PSVersionTable.PSVersion)|root_docs=14|artifacts=10|raw_revalidated=true|replay_rejected=true"
    }else{
      Assert-Throws {$null=&$collector @args -OperatorAttestsMonitorOnly} 'PRODUCTION_AUTHORITY_CALLER_BOOLEAN_PROMOTION_REJECTED'

      foreach ($case in @(
        @('no_raw_frames','PRODUCTION_AUTHORITY_PATH_COMPONENT_MISSING'),
        @('bad_signature','PRODUCTION_AUTHORITY_OPENSSL_OPERATION_FAILED|verify-observation-frame'),
        @('wrong_key','PRODUCTION_AUTHORITY_OBSERVATION_KEY_OR_PACKET_MISMATCH'),
        @('wrong_profile','PRODUCTION_AUTHORITY_GRANT_OBSERVATION_LINKAGE_INVALID'),
        @('wrong_session','PRODUCTION_AUTHORITY_GRANT_OBSERVATION_LINKAGE_INVALID'),
        @('commitment_mismatch','PRODUCTION_AUTHORITY_PROVIDER_FRAME_MISMATCH'),
        @('replay_nonce','PRODUCTION_AUTHORITY_RAW_FRAME_NONCE_REPLAY'),
        @('old_schema','PRODUCTION_AUTHORITY_RAW_CAPTURE_V4_REQUIRED'))){
        $caseRoot=Join-Path $temp ('case-'+$case[0]);$caseFixture=New-CaptureFixture $caseRoot $case[0] $provision $descriptor $supervisorPrivate $bundle;$caseArgs=$args.Clone();$caseExchange=Join-Path $temp ('exchange-'+$case[0]);[IO.Directory]::CreateDirectory($caseExchange)|Out-Null;$caseArgs.CaptureManifestPath=$caseFixture.capture;$caseArgs.SupervisorSigningRequestPath=Join-Path $caseExchange 'request.json';$caseArgs.SupervisorReceiptPath=Join-Path $caseExchange 'receipt.json';$caseArgs.OutputDirectory=Join-Path $temp ('out-'+$case[0]);Assert-Throws{$null=&$collector @caseArgs}$case[1]
    }
    $env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256=$null;$selfArgs=$args.Clone();$selfExchange=Join-Path $temp 'exchange-self-pin';[IO.Directory]::CreateDirectory($selfExchange)|Out-Null;$selfArgs.SupervisorSigningRequestPath=Join-Path $selfExchange 'request.json';$selfArgs.SupervisorReceiptPath=Join-Path $selfExchange 'receipt.json';$selfArgs.OutputDirectory=Join-Path $temp 'self-pin';Assert-Throws{$null=&$collector @selfArgs}'PRODUCTION_AUTHORITY_OUT_OF_BAND_APPROVED_PIN_REQUIRED';$env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256=$pin
    $fakeBundle=Join-Path $temp 'fake-bundle';New-ReleaseBundle $fakeBundle -FakePaper;$fakeRoot=Join-Path $temp 'fake-capture';$fakeFixture=New-CaptureFixture $fakeRoot 'none' $provision $descriptor $supervisorPrivate $fakeBundle;$fakeArgs=$args.Clone();$fakeExchange=Join-Path $temp 'exchange-fake';[IO.Directory]::CreateDirectory($fakeExchange)|Out-Null;$fakeArgs.CaptureManifestPath=$fakeFixture.capture;$fakeArgs.SupervisorSigningRequestPath=Join-Path $fakeExchange 'request.json';$fakeArgs.SupervisorReceiptPath=Join-Path $fakeExchange 'receipt.json';$fakeArgs.ReleaseBundleRoot=$fakeBundle;$fakeArgs.OutputDirectory=Join-Path $temp 'fake-output';Assert-Throws{$null=&$collector @fakeArgs}'PRODUCTION_AUTHORITY_FAKE_JAR_REJECTED|paper-bundle'
      $junction=Join-Path $temp 'capture-junction';$null=New-Item -ItemType Junction -Path $junction -Target $baselineRoot; $reparseArgs=$args.Clone();$reparseExchange=Join-Path $temp 'exchange-reparse';[IO.Directory]::CreateDirectory($reparseExchange)|Out-Null;$reparseArgs.SupervisorSigningRequestPath=Join-Path $reparseExchange 'request.json';$reparseArgs.SupervisorReceiptPath=Join-Path $reparseExchange 'receipt.json';$reparseArgs.CaptureManifestPath=Join-Path $junction 'capture.json';$reparseArgs.OutputDirectory=Join-Path $temp 'reparse-output';Assert-Throws{$null=&$collector @reparseArgs}'PRODUCTION_AUTHORITY_REPARSE_PATH_REJECTED'

      # Formal handoff negatives use fresh external exchange leaves for every
      # attempt.  The fixture bytes are synthetic even though they exercise the
      # full Formal contract; no test output can promote release eligibility.
      foreach($signerCase in @(
        @('bad-signature','bad_signature','PRODUCTION_AUTHORITY_OPENSSL_OPERATION_FAILED|verify-supervisor-receipt'),
        @('payload-mutation','payload_mutation','PRODUCTION_AUTHORITY_RECEIPT_REQUEST_PAYLOAD_MISMATCH'),
        @('request-mutation','request_mutation','PRODUCTION_AUTHORITY_SIGNING_REQUEST_MUTATED_DURING_HANDOFF'))){
        $caseExchange=Join-Path $temp ('exchange-'+$signerCase[0]);[IO.Directory]::CreateDirectory($caseExchange)|Out-Null
        $caseArgs=$args.Clone();$caseArgs.SupervisorSigningRequestPath=Join-Path $caseExchange 'request.json';$caseArgs.SupervisorReceiptPath=Join-Path $caseExchange 'receipt.json';$caseArgs.OutputDirectory=Join-Path $temp ('out-'+$signerCase[0])
        $caseSigner=Start-ExternalRequestSigner $caseArgs.SupervisorSigningRequestPath $caseArgs.SupervisorReceiptPath $supervisorPrivate $signerCase[1]
        Assert-Throws{$null=&$collector @caseArgs}$signerCase[2];$caseSigner.WaitForExit();Assert-True($caseSigner.ExitCode-eq0)"signer case failed: $($signerCase[0])";Assert-True(-not(Test-Path -LiteralPath $caseArgs.OutputDirectory))"package committed before receipt validation: $($signerCase[0])"
      }
      $missingExchange=Join-Path $temp 'exchange-missing';[IO.Directory]::CreateDirectory($missingExchange)|Out-Null;$missingArgs=$args.Clone();$missingArgs.SupervisorSigningRequestPath=Join-Path $missingExchange 'request.json';$missingArgs.SupervisorReceiptPath=Join-Path $missingExchange 'receipt.json';$missingArgs.SupervisorReceiptWaitSeconds=1;$missingArgs.OutputDirectory=Join-Path $temp 'out-missing';Assert-Throws{$null=&$collector @missingArgs}'PRODUCTION_AUTHORITY_SUPERVISOR_RECEIPT_WAIT_TIMEOUT';Assert-True(-not(Test-Path -LiteralPath $missingArgs.OutputDirectory))'package committed before missing receipt'

      $replayExchange=Join-Path $temp 'exchange-replayed-receipt';[IO.Directory]::CreateDirectory($replayExchange)|Out-Null;$replayHandoffArgs=$args.Clone();$replayHandoffArgs.SupervisorSigningRequestPath=Join-Path $replayExchange 'request.json';$replayHandoffArgs.SupervisorReceiptPath=Join-Path $replayExchange 'receipt.json';$replayHandoffArgs.OutputDirectory=Join-Path $temp 'out-replayed-receipt';$replaySigner=Start-ExternalRequestSigner $replayHandoffArgs.SupervisorSigningRequestPath $replayHandoffArgs.SupervisorReceiptPath $supervisorPrivate 'replay_receipt' (Join-Path $output 'supervisor-receipt.json');Assert-Throws{$null=&$collector @replayHandoffArgs}'PRODUCTION_AUTHORITY_RECEIPT_REQUEST_PAYLOAD_MISMATCH';$replaySigner.WaitForExit();Assert-True($replaySigner.ExitCode-eq0)'replay signer failed'

      $aliasExchange=Join-Path $temp 'exchange-alias';[IO.Directory]::CreateDirectory($aliasExchange)|Out-Null;$aliasArgs=$args.Clone();$aliasArgs.SupervisorSigningRequestPath=Join-Path $aliasExchange 'same.json';$aliasArgs.SupervisorReceiptPath=Join-Path $aliasExchange 'same.json';$aliasArgs.OutputDirectory=Join-Path $temp 'out-alias';Assert-Throws{$null=&$collector @aliasArgs}'PRODUCTION_AUTHORITY_EXCHANGE_DISTINCT_LEAVES_REQUIRED'
      if([Environment]::OSVersion.Platform-eq[PlatformID]::Win32NT){$realExchange=Join-Path $temp 'exchange-real';[IO.Directory]::CreateDirectory($realExchange)|Out-Null;$linkedExchange=Join-Path $temp 'exchange-linked';$null=New-Item -ItemType Junction -Path $linkedExchange -Target $realExchange;$linkedArgs=$args.Clone();$linkedArgs.SupervisorSigningRequestPath=Join-Path $linkedExchange 'request.json';$linkedArgs.SupervisorReceiptPath=Join-Path $linkedExchange 'receipt.json';$linkedArgs.OutputDirectory=Join-Path $temp 'out-linked';Assert-Throws{$null=&$collector @linkedArgs}'PRODUCTION_AUTHORITY_REPARSE_PATH_REJECTED'}

      $badPinExchange=Join-Path $temp 'exchange-bad-pin';[IO.Directory]::CreateDirectory($badPinExchange)|Out-Null;$badPinArgs=$args.Clone();$badPinArgs.ExpectedCaptureSupervisorPublicDescriptorSha256='0'*64;$badPinArgs.SupervisorSigningRequestPath=Join-Path $badPinExchange 'request.json';$badPinArgs.SupervisorReceiptPath=Join-Path $badPinExchange 'receipt.json';$badPinArgs.OutputDirectory=Join-Path $temp 'out-bad-pin';Assert-Throws{$null=&$collector @badPinArgs}'PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_PIN_MISMATCH'

      $expiredPackage=Join-Path $temp 'package-expired';Copy-Item -LiteralPath $output -Destination $expiredPackage -Recurse;Set-PackageReceiptTimes $expiredPackage ([DateTimeOffset]::UtcNow.AddSeconds(-20)) ([DateTimeOffset]::UtcNow.AddSeconds(-1)) $supervisorPrivate;Assert-Throws{$null=&$collector -ValidatePackageRoot $expiredPackage -RequireCurrentlyValidReceipt -ReleaseBundleRoot $bundle -OpenSslPath $openssl -ExpectedOpenSslSha256 $opensslHash}'PRODUCTION_AUTHORITY_EXPIRED_OR_FIXTURE_RECEIPT_REJECTED'
      $futurePackage=Join-Path $temp 'package-future';Copy-Item -LiteralPath $output -Destination $futurePackage -Recurse;Set-PackageReceiptTimes $futurePackage ([DateTimeOffset]::UtcNow.AddMinutes(6)) ([DateTimeOffset]::UtcNow.AddMinutes(7)) $supervisorPrivate;Assert-Throws{$null=&$collector -ValidatePackageRoot $futurePackage -RequireCurrentlyValidReceipt -ReleaseBundleRoot $bundle -OpenSslPath $openssl -ExpectedOpenSslSha256 $opensslHash}'PRODUCTION_AUTHORITY_RECEIPT_TIME_WINDOW_INVALID'

      $stringSizePackage=Join-Path $temp 'package-string-size';Copy-Item -LiteralPath $output -Destination $stringSizePackage -Recurse;$paperSize=[string](Get-Item(Join-Path $bundle 'mcace-server-paper.jar')).Length;Set-PackageReceiptPayloadField $stringSizePackage 'paper_jar_size_bytes' $paperSize $supervisorPrivate;Assert-Throws{$null=&$collector -ValidatePackageRoot $stringSizePackage -ReleaseBundleRoot $bundle -OpenSslPath $openssl -ExpectedOpenSslSha256 $opensslHash}'PRODUCTION_AUTHORITY_RECEIPT_INTEGER_TYPE_INVALID|paper_jar_size_bytes'
      $scalarProvidersPackage=Join-Path $temp 'package-scalar-providers';Copy-Item -LiteralPath $output -Destination $scalarProvidersPackage -Recurse;Set-PackageReceiptPayloadField $scalarProvidersPackage 'genuine_provider_ids' 'grim,vulcan' $supervisorPrivate;Assert-Throws{$null=&$collector -ValidatePackageRoot $scalarProvidersPackage -ReleaseBundleRoot $bundle -OpenSslPath $openssl -ExpectedOpenSslSha256 $opensslHash}'PRODUCTION_AUTHORITY_RECEIPT_PROVIDER_IDS_*'
      $singleProviderPackage=Join-Path $temp 'package-single-provider';Copy-Item -LiteralPath $output -Destination $singleProviderPackage -Recurse;Set-PackageReceiptPayloadField $singleProviderPackage 'genuine_provider_ids' @('grim') $supervisorPrivate;Assert-Throws{$null=&$collector -ValidatePackageRoot $singleProviderPackage -ReleaseBundleRoot $bundle -OpenSslPath $openssl -ExpectedOpenSslSha256 $opensslHash}'PRODUCTION_AUTHORITY_RECEIPT_PROVIDER_IDS_*'

      $historicalExchange=Join-Path $temp 'exchange-historical';[IO.Directory]::CreateDirectory($historicalExchange)|Out-Null;$historicalArgs=$args.Clone();$historicalArgs.SupervisorSigningRequestPath=Join-Path $historicalExchange 'request.json';$historicalArgs.SupervisorReceiptPath=Join-Path $historicalExchange 'receipt.json';$historicalArgs.SupervisorReceiptValiditySeconds=10;$historicalArgs.OutputDirectory=Join-Path $temp 'out-historical';$historicalSigner=Start-ExternalRequestSigner $historicalArgs.SupervisorSigningRequestPath $historicalArgs.SupervisorReceiptPath $supervisorPrivate;$null=&$collector @historicalArgs;$historicalSigner.WaitForExit();Assert-True($historicalSigner.ExitCode-eq0)'historical signer failed';$historicalRequest=Get-Content -LiteralPath $historicalArgs.SupervisorSigningRequestPath -Raw|ConvertFrom-Json;$historicalExpiry=[DateTimeOffset]::Parse([string]$historicalRequest.not_after,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal);$remaining=[Math]::Ceiling(($historicalExpiry-[DateTimeOffset]::UtcNow).TotalMilliseconds)+250;if($remaining-gt0){Start-Sleep -Milliseconds ([int]$remaining)};$historicalValidation=@(&$collector -ValidatePackageRoot $historicalArgs.OutputDirectory -ReleaseBundleRoot $bundle -OpenSslPath $openssl -ExpectedOpenSslSha256 $opensslHash);Assert-True(($historicalValidation-join"`n")-clike'*PRODUCTION_AUTHORITY_V4_PACKAGE_VALIDATION_PASS*')'durable historical receipt was treated as wall-clock-expired';Assert-Throws{$null=&$collector -ValidatePackageRoot $historicalArgs.OutputDirectory -RequireCurrentlyValidReceipt -ReleaseBundleRoot $bundle -OpenSslPath $openssl -ExpectedOpenSslSha256 $opensslHash}'PRODUCTION_AUTHORITY_EXPIRED_OR_FIXTURE_RECEIPT_REJECTED'

      Write-Output "PRODUCTION_AUTHORITY_PROCESS_EVIDENCE_V4_PASS|engine=$($PSVersionTable.PSEdition)-$($PSVersionTable.PSVersion)|positive=synthetic-handoff+historical-revalidate|negative=27|raw_frames=2|provider_commitment_recomputed=true|release_eligible=false"
    }
}finally{
    $env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256=$oldApproved;$env:MCACE_RELEASE_AUTHORITY_OPENSSL_PATH=$oldOpenSslPath;$env:MCACE_RELEASE_AUTHORITY_OPENSSL_SHA256=$oldOpenSslSha
    if($publishedIndex-and(Test-Path -LiteralPath $publishedIndex)){Remove-Item -LiteralPath $publishedIndex -Force -ErrorAction SilentlyContinue};if($publishedDirectory-and(Test-Path -LiteralPath $publishedDirectory)){Remove-Item -LiteralPath $publishedDirectory -Recurse -Force -ErrorAction SilentlyContinue};if(Test-Path $temp){Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue}
}
