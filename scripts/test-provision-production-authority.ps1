[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if(Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue){$script:PSNativeCommandUseErrorActionPreference=$false}
$target=Join-Path $PSScriptRoot 'provision-production-authority.ps1'
$repoRoot=(Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$utf8=New-Object Text.UTF8Encoding($false)
$temp=Join-Path ([IO.Path]::GetTempPath()) ('mcace-provision-v4-'+[guid]::NewGuid().ToString('N'))

function Assert-True([bool]$Condition,[string]$Message){if(-not$Condition){throw "PROVISION_AUTHORITY_V4_TEST_FAILED|$Message"}}
function Assert-Throws([scriptblock]$Action,[string]$Expected){$threw=$false;try{&$Action}catch{$threw=$true;Assert-True ($_.Exception.Message-clike "*$Expected*") "expected=$Expected actual=$($_.Exception.Message)"};Assert-True $threw "expected failure missing: $Expected"}
function Hash([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Write-Json([string]$Path,[object]$Value){$json=(($Value|ConvertTo-Json -Depth 8)-replace "`r`n","`n")+"`n";[IO.File]::WriteAllBytes($Path,$utf8.GetBytes($json))}

function Set-PrivateDirectoryAcl([string]$Path){
    $current=[Security.Principal.WindowsIdentity]::GetCurrent().User;$system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl=New-Object Security.AccessControl.DirectorySecurity;$acl.SetAccessRuleProtection($true,$false)
    $inheritance=[Security.AccessControl.InheritanceFlags]::ContainerInherit-bor[Security.AccessControl.InheritanceFlags]::ObjectInherit
    foreach($sid in @($current,$system)){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,[Security.AccessControl.FileSystemRights]::FullControl,$inheritance,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow)))}
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-RuntimeRelativePath([string]$Root,[string]$Path){$prefix=[IO.Path]::GetFullPath($Root).TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar;return [IO.Path]::GetFullPath($Path).Substring($prefix.Length).Replace('\','/')}
function Sort-RuntimeItemsOrdinal([object[]]$Items){$sorted=New-Object Collections.ArrayList;foreach($item in @($Items)){$at=0;while($at-lt$sorted.Count-and[StringComparer]::Ordinal.Compare([string]$sorted[$at].relative_path,[string]$item.relative_path)-lt 0){$at++};$sorted.Insert($at,$item)};return @($sorted.ToArray())}
function New-RuntimeManifest([string]$Root,[string]$Path){
    $entries=@();foreach($file in @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File)){$relative=Get-RuntimeRelativePath $Root $file.FullName;$role=if($relative-ceq'openssl.exe'){'EXECUTABLE'}elseif($relative-ceq'openssl.cnf'){'CONFIG'}elseif($relative.StartsWith('providers/',[StringComparison]::Ordinal)){'PROVIDER_MODULE'}else{'APPLICATION_LOCAL_DLL'};$entries+=[pscustomobject][ordered]@{relative_path=$relative;role=$role;size_bytes=[long]$file.Length;sha256=(Hash $file.FullName)}}
    $entries=@(Sort-RuntimeItemsOrdinal $entries);Write-Json $Path ([pscustomobject][ordered]@{schema='MCACE_OPENSSL_RUNTIME_MANIFEST_V1';artifact_class='REVIEWED_OPENSSL_RUNTIME';platform='windows-x64';executable_relative_path='openssl.exe';files=$entries;test_fixture=$false});return [pscustomobject]@{path=$Path;sha256=(Hash $Path)}
}
function Get-TestOpenSslRuntimeFiles([string]$ExecutablePath){
    $executable=Get-Item -LiteralPath $ExecutablePath;$directory=$executable.DirectoryName;$allDlls=@(Get-ChildItem -LiteralPath $directory -File -Filter '*.dll')
    $objdumpPath=Join-Path $directory 'objdump.exe'
    if(-not(Test-Path -LiteralPath $objdumpPath -PathType Leaf)){$objdump=Get-Command objdump.exe -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1;if($null-eq$objdump){return @($executable)+$allDlls};$objdumpPath=[string]$objdump.Source}
    $selected=[ordered]@{$executable.Name=$executable};$queue=New-Object Collections.Generic.Queue[string];$queue.Enqueue($executable.FullName)
    try{while($queue.Count-gt 0){$candidatePath=$queue.Dequeue();$old=$ErrorActionPreference;try{$ErrorActionPreference='Continue';$imports=@(&$objdumpPath -p $candidatePath 2>$null);$exit=$LASTEXITCODE}finally{$ErrorActionPreference=$old};if($exit-ne 0){throw'OBJDUMP_FAILED'};foreach($line in $imports){if([string]$line-match'^\s*DLL Name:\s*(?<leaf>[^\\/]+\.dll)\s*$'){$leaf=[string]$Matches.leaf;$localPath=Join-Path $directory $leaf;if((Test-Path -LiteralPath $localPath -PathType Leaf)-and-not$selected.Contains($leaf)){$item=Get-Item -LiteralPath $localPath;$selected[$leaf]=$item;$queue.Enqueue($item.FullName)}}}};if($selected.Count-lt 2){throw'NO_APPLICATION_LOCAL_DLL'};return @($selected.Values)}catch{return @($executable)+$allDlls}
}

$opensslSource=(Get-Command openssl.exe -CommandType Application -ErrorAction Stop|Select-Object -First 1).Source
$opensslSource=[IO.Path]::GetFullPath($opensslSource)
$tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($target,[ref]$tokens,[ref]$errors)
Assert-True (@($errors).Count-eq 0) "AST parse failed: $($errors-join ';')"
$source=[IO.File]::ReadAllText($target)
foreach($required in @('mcace-production-authority-freeze/v3','ExpectedOpenSslSha256','ExpectedOpenSslRuntimeManifestSha256',
    'MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256',
    'Read-LockedFile','OPENSSL_CONF','OPENSSL_MODULES','ProcessStartInfo','Open-RuntimeLocks',
    'PRODUCTION_AUTHORITY_OPENSSL_SCRIPT_SHIM_REJECTED',
    'capture-supervisor-public-descriptor.json','private_key_present=$false',
    'PRODUCTION_AUTHORITY_SUPERVISOR_PRIVATE_MATERIAL_REJECTED','Directory]::Move($stage,$output)')){
    Assert-True $source.Contains($required) "required V4 contract missing: $required"
}
Assert-True (-not $source.Contains('New-ValidatedCaptureSupervisorMaterial')) 'legacy supervisor key generator remains'
Assert-True (-not $source.Contains('RSA-PKCS1-SHA256')) 'legacy RSA supervisor contract remains'

[IO.Directory]::CreateDirectory($temp)|Out-Null
$oldApproved=$env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256
try{
    $runtimeRoot=Join-Path $temp 'openssl-runtime';[IO.Directory]::CreateDirectory($runtimeRoot)|Out-Null
    $runtimeFiles=@(Get-TestOpenSslRuntimeFiles $opensslSource)
    foreach($runtimeFile in $runtimeFiles){Copy-Item -LiteralPath $runtimeFile.FullName -Destination (Join-Path $runtimeRoot $runtimeFile.Name)}
    $providers=Join-Path $runtimeRoot 'providers';[IO.Directory]::CreateDirectory($providers)|Out-Null
    $providerSource=@($runtimeFiles|Where-Object{$_.Extension-ieq'.dll'}|Select-Object -First 1)
    Assert-True ($providerSource.Count-eq 1) 'OpenSSL application-local DLL required'
    Copy-Item -LiteralPath $providerSource[0].FullName -Destination (Join-Path $providers 'fixture-provider.dll')
    [IO.File]::WriteAllBytes((Join-Path $runtimeRoot 'openssl.cnf'),$utf8.GetBytes("# MCAce pinned empty OpenSSL configuration v1`n"))
    Set-PrivateDirectoryAcl $runtimeRoot
    $openssl=Join-Path $runtimeRoot 'openssl.exe';$opensslHash=Hash $openssl
    $runtimeManifest=New-RuntimeManifest $runtimeRoot (Join-Path $temp 'openssl-runtime-manifest.json')

    $external=Join-Path $temp 'external';[IO.Directory]::CreateDirectory($external)|Out-Null
    $private=Join-Path $external 'supervisor-private.pk8';$public=Join-Path $external 'supervisor-public.der'
    & $openssl genpkey -algorithm ED25519 -outform DER -out $private 2>$null
    Assert-True ($LASTEXITCODE-eq 0) 'external supervisor private generation failed'
    & $openssl pkey -inform DER -in $private -pubout -outform DER -out $public 2>$null
    Assert-True ($LASTEXITCODE-eq 0) 'external supervisor public derivation failed'
    [byte[]]$publicBytes=[IO.File]::ReadAllBytes($public);$keyHash=Hash $public
    $descriptor=Join-Path $external 'descriptor.json'
    Write-Json $descriptor ([ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_PUBLIC_DESCRIPTOR_V1';
        artifact_class='EXTERNAL_RELEASE_CAPTURE_SUPERVISOR_PUBLIC_ROOT';algorithm='ED25519';
        key_id_sha256=$keyHash;public_key_der_base64=[Convert]::ToBase64String($publicBytes);test_fixture=$false})
    $pin=Hash $descriptor;$env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256=$pin
    $base=@{
        ProxyInstanceId='velocity-a';BackendInstanceId='paper-a';RegisteredBackend='survival';ProfileName='production-quorum';ProxyPlatform='VELOCITY'
        GrimProviderId='grim';GrimTrustDomainId='grim-domain';GrimVersion='2.3.69';GrimStableCheckFamily='grim-prediction';GrimThreshold=5
        VulcanProviderId='vulcan';VulcanTrustDomainId='vulcan-domain';VulcanVersion='2.9.0';VulcanStableCheckFamily='vulcan-speed';VulcanThreshold=3
        RequiredIndependentDomains=2;MaximumProviderWindowMs=10000;CooldownMs=5000;ObservationTtlMs=30000;GrantTtlMs=30000;JournalQuotaBytes=8388608
        CaptureSupervisorPublicDescriptorPath=$descriptor;ExpectedCaptureSupervisorPublicDescriptorSha256=$pin
        OpenSslPath=$openssl;ExpectedOpenSslSha256=$opensslHash
        OpenSslRuntimeManifestPath=$runtimeManifest.path;ExpectedOpenSslRuntimeManifestSha256=$runtimeManifest.sha256
    }
    $output=Join-Path $temp 'provisioned';$args=$base.Clone();$args.OutputRoot=$output
    $result=@(& $target @args)
    Assert-True (($result-join "`n")-clike '*PRODUCTION_AUTHORITY_PROVISIONED_V4*') 'success marker missing'
    Assert-True (Test-Path -LiteralPath (Join-Path $output 'freeze-manifest.json') -PathType Leaf) 'freeze missing'
    $outputAcl=Get-Acl -LiteralPath $output
    Assert-True $outputAcl.AreAccessRulesProtected 'provisioned secret root ACL inherits'
    $approvedAclSids=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18')
    $unexpectedAclRules=@($outputAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])|Where-Object{$_.IsInherited-or$_.IdentityReference.Value-cnotin$approvedAclSids})
    Assert-True ($unexpectedAclRules.Count-eq 0) 'provisioned secret root ACL contains unexpected principal'
    Assert-True (Test-Path -LiteralPath (Join-Path $output 'evidence-supervisor/capture-supervisor-public-descriptor.json') -PathType Leaf) 'public descriptor missing'
    $privateSupervisor=@(Get-ChildItem -LiteralPath $output -Recurse -Force|Where-Object{$_.Name-match'(?i)supervisor.*private|private.*supervisor'})
    Assert-True ($privateSupervisor.Count-eq 0) 'supervisor private material was provisioned'
    $freeze=Get-Content -LiteralPath (Join-Path $output 'freeze-manifest.json') -Raw|ConvertFrom-Json
    Assert-True ([string]$freeze.schema_version-ceq 'mcace-production-authority-freeze/v3') 'freeze schema mismatch'
    Assert-True ($freeze.evidence_supervisor.private_key_present-is[bool] -and -not[bool]$freeze.evidence_supervisor.private_key_present) 'freeze says supervisor private exists'
    Assert-True ([string]$freeze.evidence_supervisor.public_descriptor_sha256-ceq $pin) 'descriptor pin not frozen'
    Assert-True ([string]$freeze.topology.sha256-cmatch'^[0-9a-f]{64}$') 'topology commitment missing'
    Assert-True ((Get-Content (Join-Path $output 'paper/authority/issuance.log') -Raw)-ceq "MCACE_SERVER_AUTHORITY_ISSUANCE_JOURNAL_V3`n") 'journal schema mismatch'

    $fixtureDescriptor=Join-Path $external 'fixture-descriptor.json'
    Write-Json $fixtureDescriptor ([ordered]@{schema='MCACE_PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_PUBLIC_DESCRIPTOR_V1';
        artifact_class='TEST_CAPTURE_SUPERVISOR_PUBLIC_ROOT_FIXTURE';algorithm='ED25519';key_id_sha256=$keyHash;
        public_key_der_base64=[Convert]::ToBase64String($publicBytes);test_fixture=$true})
    $fixturePin=Hash $fixtureDescriptor;$env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256=$fixturePin
    $bad=$base.Clone();$bad.OutputRoot=Join-Path $temp 'fixture-rejected';$bad.CaptureSupervisorPublicDescriptorPath=$fixtureDescriptor;$bad.ExpectedCaptureSupervisorPublicDescriptorSha256=$fixturePin
    Assert-Throws {$null=&$target @bad} 'PRODUCTION_AUTHORITY_EXTERNAL_SUPERVISOR_DESCRIPTOR_INVALID'
    Assert-True (-not(Test-Path -LiteralPath $bad.OutputRoot)) 'failed atomic provision left final root'

    $env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256=$pin
    $bad=$base.Clone();$bad.OutputRoot=Join-Path $temp 'wrong-pin';$bad.ExpectedCaptureSupervisorPublicDescriptorSha256=('0'*64)
    Assert-Throws {$null=&$target @bad} 'PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_PIN_MISMATCH'
    Assert-True (-not(Test-Path -LiteralPath $bad.OutputRoot)) 'wrong-pin failure left final root'

    $bad=$base.Clone();$bad.OutputRoot=Join-Path $temp 'wrong-ttl';$bad.ObservationTtlMs=10000
    Assert-Throws {$null=&$target @bad} 'PRODUCTION_AUTHORITY_NUMERIC_OR_ACTION_CONTRACT_INVALID'
    Assert-True (-not(Test-Path -LiteralPath $bad.OutputRoot)) 'TTL failure left final root'

    $shim=Join-Path $external 'openssl.cmd';[IO.File]::WriteAllText($shim,'@echo OpenSSL 3.6.0',$utf8)
    $bad=$base.Clone();$bad.OutputRoot=Join-Path $temp 'shim';$bad.OpenSslPath=$shim;$bad.ExpectedOpenSslSha256=Hash $shim
    Assert-Throws {$null=&$target @bad} 'PRODUCTION_AUTHORITY_OPENSSL_SCRIPT_SHIM_REJECTED'

    $bad=$base.Clone();$bad.OutputRoot=Join-Path $temp 'runtime-manifest-pin';$bad.ExpectedOpenSslRuntimeManifestSha256=('1'*64)
    Assert-Throws {$null=&$target @bad} 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_MANIFEST_SHA256_MISMATCH'

    $runtimeDll=@(Get-ChildItem -LiteralPath $runtimeRoot -File -Filter '*.dll'|Select-Object -First 1)[0]
    $runtimeDllBackup=Join-Path $temp 'runtime-dll-backup.bin';Copy-Item -LiteralPath $runtimeDll.FullName -Destination $runtimeDllBackup
    try{
        $append=New-Object IO.FileStream($runtimeDll.FullName,[IO.FileMode]::Append,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$append.WriteByte(0);$append.Flush($true)}finally{$append.Dispose()}
        $bad=$base.Clone();$bad.OutputRoot=Join-Path $temp 'runtime-dll-mutation'
        Assert-Throws {$null=&$target @bad} 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_FILE_BINDING_INVALID'
    }finally{Copy-Item -LiteralPath $runtimeDllBackup -Destination $runtimeDll.FullName -Force}

    $extraRuntime=Join-Path $runtimeRoot 'unreviewed-runtime.dll'
    try{
        [IO.File]::WriteAllBytes($extraRuntime,[byte[]](1,2,3,4))
        $bad=$base.Clone();$bad.OutputRoot=Join-Path $temp 'runtime-extra'
        Assert-Throws {$null=&$target @bad} 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_EXACT_SET_MISMATCH'
    }finally{[IO.File]::Delete($extraRuntime)}

    try{
        & icacls.exe $runtimeRoot /grant '*S-1-5-32-545:(OI)(CI)(RX)'|Out-Null
        Assert-True ($LASTEXITCODE-eq 0) 'failed to add permissive runtime ACL fixture'
        $bad=$base.Clone();$bad.OutputRoot=Join-Path $temp 'runtime-acl'
        Assert-Throws {$null=&$target @bad} 'PRODUCTION_AUTHORITY_PRIVATE_DIRECTORY_ACL_PRINCIPAL_REJECTED|openssl-runtime-root'
    }finally{
        & icacls.exe $runtimeRoot /remove:g '*S-1-5-32-545'|Out-Null
        Assert-True ($LASTEXITCODE-eq 0) 'failed to remove permissive runtime ACL fixture'
    }

    $bad=$base.Clone();$bad.OutputRoot=Join-Path $temp 'missing-approved';$env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256=$null
    Assert-Throws {$null=&$target @bad} 'PRODUCTION_AUTHORITY_OUT_OF_BAND_APPROVED_PIN_REQUIRED'

    Write-Output "PRODUCTION_AUTHORITY_PROVISION_V4_PASS|engine=$($PSVersionTable.PSEdition)-$($PSVersionTable.PSVersion)|external_public_only=true|openssl_runtime_pinned=true|atomic=true"
}finally{
    $env:MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256=$oldApproved
    if(Test-Path -LiteralPath $temp){Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue}
}
