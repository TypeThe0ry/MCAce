[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputRoot,
    [Parameter(Mandatory=$true)][string]$ProxyInstanceId,
    [Parameter(Mandatory=$true)][string]$BackendInstanceId,
    [Parameter(Mandatory=$true)][string]$RegisteredBackend,
    [Parameter(Mandatory=$true)][string]$ProfileName,
    [Parameter(Mandatory=$true)][ValidateSet('VELOCITY','BUNGEECORD')][string]$ProxyPlatform,
    [Parameter(Mandatory=$true)][string]$GrimProviderId,
    [Parameter(Mandatory=$true)][string]$GrimTrustDomainId,
    [Parameter(Mandatory=$true)][string]$GrimVersion,
    [Parameter(Mandatory=$true)][string]$GrimStableCheckFamily,
    [Parameter(Mandatory=$true)][int]$GrimThreshold,
    [Parameter(Mandatory=$true)][string]$VulcanProviderId,
    [Parameter(Mandatory=$true)][string]$VulcanTrustDomainId,
    [Parameter(Mandatory=$true)][string]$VulcanVersion,
    [Parameter(Mandatory=$true)][string]$VulcanStableCheckFamily,
    [Parameter(Mandatory=$true)][int]$VulcanThreshold,
    [Parameter(Mandatory=$true)][int]$RequiredIndependentDomains,
    [Parameter(Mandatory=$true)][long]$MaximumProviderWindowMs,
    [Parameter(Mandatory=$true)][long]$CooldownMs,
    [Parameter(Mandatory=$true)][long]$ObservationTtlMs,
    [Parameter(Mandatory=$true)][long]$GrantTtlMs,
    [Parameter(Mandatory=$true)][long]$JournalQuotaBytes,
    [ValidateSet('MONITOR')][string]$ActionCeiling='MONITOR',

    [Parameter(Mandatory=$true)][string]$CaptureSupervisorPublicDescriptorPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedCaptureSupervisorPublicDescriptorSha256,

    [Parameter(Mandatory=$true)][string]$OpenSslPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedOpenSslSha256,
    [Parameter(Mandatory=$true)][string]$OpenSslRuntimeManifestPath,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string]$ExpectedOpenSslRuntimeManifestSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $script:PSNativeCommandUseErrorActionPreference=$false
}
$script:RepoRoot=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$script:Utf8Strict=New-Object Text.UTF8Encoding($false,$true)
$script:Utf8NoBom=New-Object Text.UTF8Encoding($false)
$script:RunningOnWindows=$env:OS -eq 'Windows_NT'
$script:MaximumToolBytes=256MB

if(-not $script:RunningOnWindows){throw 'PRODUCTION_AUTHORITY_WINDOWS_OPENSSL_RUNTIME_REQUIRED'}

function Throw-Provision([string]$Code) { throw $Code }

function Get-BytesSha256([byte[]]$Bytes) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Test-BytesEqual([byte[]]$Left,[byte[]]$Right) {
    if ($null -eq $Left -or $null -eq $Right -or $Left.Length -ne $Right.Length) { return $false }
    [int]$difference=0
    for($i=0;$i -lt $Left.Length;$i++){ $difference=$difference -bor ($Left[$i] -bxor $Right[$i]) }
    return $difference -eq 0
}

function Test-ExactProperties([object]$Value,[string[]]$Expected) {
    if($null -eq $Value -or $Value -isnot [Management.Automation.PSCustomObject]){return $false}
    $actual=@($Value.PSObject.Properties.Name|Sort-Object);$wanted=@($Expected|Sort-Object)
    return $actual.Count -eq $wanted.Count -and (($actual -join "`n") -ceq ($wanted -join "`n"))
}

function Get-JsonGraphPropertyCount([object]$Value) {
    if($null -eq $Value -or $Value -is [string] -or $Value -is [ValueType]){return 0}
    if($Value -is [Management.Automation.PSCustomObject]){
        $properties=@($Value.PSObject.Properties);$count=$properties.Count
        foreach($property in $properties){$count+=Get-JsonGraphPropertyCount $property.Value};return $count
    }
    if($Value -is [Collections.IDictionary]){
        $count=@($Value.Keys).Count;foreach($key in @($Value.Keys)){$count+=Get-JsonGraphPropertyCount $Value[$key]};return $count
    }
    if($Value -is [Collections.IEnumerable]){$count=0;foreach($item in $Value){$count+=Get-JsonGraphPropertyCount $item};return $count}
    return 0
}

function Initialize-ProvisionIdentityApi {
    if(-not $script:RunningOnWindows -or ('MCAceAuthorityProvisionIdentityV4' -as [type])){return}
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class MCAceAuthorityProvisionIdentityV4 {
  const uint READ_ATTRIBUTES=0x80, LIST_DIRECTORY=1, SHARE_READ=1, SHARE_WRITE=2, OPEN_EXISTING=3;
  const uint OPEN_REPARSE=0x00200000, BACKUP=0x02000000, REPARSE=0x400, DIRECTORY=0x10;
  [StructLayout(LayoutKind.Sequential)] struct INFO {
    public uint Attr; public System.Runtime.InteropServices.ComTypes.FILETIME C,A,W;
    public uint Vol,SizeHi,SizeLo,Links,IndexHi,IndexLo;
  }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  static extern SafeFileHandle CreateFileW(string p,uint a,uint s,IntPtr sec,uint c,uint f,IntPtr t);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out INFO i);
  static string D(INFO i){return i.Vol.ToString("x8")+":"+i.IndexHi.ToString("x8")+i.IndexLo.ToString("x8");}
  public static string NoFollow(string p,bool dir){
    using(var h=CreateFileW(p,READ_ATTRIBUTES,SHARE_READ,IntPtr.Zero,OPEN_EXISTING,OPEN_REPARSE|(dir?BACKUP:0),IntPtr.Zero)){
      if(h.IsInvalid)throw new Win32Exception(Marshal.GetLastWin32Error());INFO i;
      if(!GetFileInformationByHandle(h,out i))throw new Win32Exception(Marshal.GetLastWin32Error());
      if((i.Attr&REPARSE)!=0)throw new InvalidOperationException("reparse point rejected");
      if(dir && (i.Attr&DIRECTORY)==0)throw new InvalidOperationException("directory required");
      if(!dir && (i.Attr&DIRECTORY)==0 && i.Links!=1)throw new InvalidOperationException("hard-linked file rejected");
      return D(i);
    }
  }
  public static string FromHandle(SafeFileHandle h){INFO i;if(!GetFileInformationByHandle(h,out i))throw new Win32Exception(Marshal.GetLastWin32Error());if((i.Attr&REPARSE)!=0)throw new InvalidOperationException("reparse point rejected");if((i.Attr&DIRECTORY)==0&&i.Links!=1)throw new InvalidOperationException("hard-linked file rejected");return D(i);}
  public static SafeFileHandle OpenPinnedDirectory(string path){
    var h=CreateFileW(path,READ_ATTRIBUTES|LIST_DIRECTORY,SHARE_READ|SHARE_WRITE,IntPtr.Zero,OPEN_EXISTING,OPEN_REPARSE|BACKUP,IntPtr.Zero);
    if(h.IsInvalid){int e=Marshal.GetLastWin32Error();h.Dispose();throw new Win32Exception(e);}INFO i;
    if(!GetFileInformationByHandle(h,out i)){int e=Marshal.GetLastWin32Error();h.Dispose();throw new Win32Exception(e);}
    if((i.Attr&REPARSE)!=0||(i.Attr&DIRECTORY)==0){h.Dispose();throw new InvalidOperationException("stable directory required");}
    return h;
  }
}
'@
}

function Assert-NoReparseChain([string]$Path,[bool]$LeafMustExist) {
    $full=[IO.Path]::GetFullPath($Path);$root=[IO.Path]::GetPathRoot($full)
    if([string]::IsNullOrWhiteSpace($root)){Throw-Provision 'PRODUCTION_AUTHORITY_PATH_ROOT_INVALID'}
    [char[]]$separators=@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar)
    $segments=@($full.Substring($root.Length).Split($separators,[StringSplitOptions]::RemoveEmptyEntries))
    $cursor=$root
    for($i=0;$i -lt $segments.Count;$i++){
        $cursor=Join-Path $cursor $segments[$i]
        if(-not(Test-Path -LiteralPath $cursor)){
            if($LeafMustExist -or $i -lt $segments.Count-1){Throw-Provision "PRODUCTION_AUTHORITY_PATH_COMPONENT_MISSING|$cursor"};return
        }
        $item=Get-Item -LiteralPath $cursor -Force
        if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0 -or
                ($item.PSObject.Properties.Name -contains 'LinkType' -and $null -ne $item.LinkType)){
            Throw-Provision "PRODUCTION_AUTHORITY_REPARSE_PATH_REJECTED|$cursor"
        }
    }
}

function Get-NoFollowIdentity([string]$Path,[switch]$Directory) {
    if($script:RunningOnWindows){Initialize-ProvisionIdentityApi;try{return [MCAceAuthorityProvisionIdentityV4]::NoFollow($Path,[bool]$Directory)}catch{Throw-Provision "PRODUCTION_AUTHORITY_NOFOLLOW_IDENTITY_FAILED|$($_.Exception.Message)"}}
    $item=Get-Item -LiteralPath $Path -Force
    if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){Throw-Provision 'PRODUCTION_AUTHORITY_NOFOLLOW_REPARSE_REJECTED'}
    return "portable:$($item.FullName):$([long]$item.Length):$($item.LastWriteTimeUtc.Ticks)"
}

function Read-Exact([IO.FileStream]$Stream,[int]$Length,[string]$Role) {
    [byte[]]$bytes=New-Object byte[] $Length;$offset=0
    while($offset -lt $Length){$read=$Stream.Read($bytes,$offset,$Length-$offset);if($read-le 0){Throw-Provision "PRODUCTION_AUTHORITY_SHORT_READ|$Role"};$offset+=$read}
    if($Stream.ReadByte()-ne -1){Throw-Provision "PRODUCTION_AUTHORITY_GROWTH_DURING_READ|$Role"};return $bytes
}

function Read-LockedFile([string]$Path,[long]$Maximum,[string]$Role,[long]$Minimum=1) {
    $absolute=[IO.Path]::GetFullPath($Path);Assert-NoReparseChain $absolute $true
    $item=Get-Item -LiteralPath $absolute -Force
    if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){Throw-Provision "PRODUCTION_AUTHORITY_REGULAR_FILE_REQUIRED|$Role"}
    $before=Get-NoFollowIdentity $absolute
    $stream=New-Object IO.FileStream($absolute,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
    try{
        $length=[long]$stream.Length;if($length-lt $Minimum -or $length-gt $Maximum -or $length-gt [int]::MaxValue){Throw-Provision "PRODUCTION_AUTHORITY_FILE_SIZE_INVALID|$Role"}
        if($script:RunningOnWindows){$handle=[MCAceAuthorityProvisionIdentityV4]::FromHandle($stream.SafeFileHandle);if($handle-cne $before){Throw-Provision "PRODUCTION_AUTHORITY_HANDLE_IDENTITY_CHANGED|$Role"}}
        $first=Read-Exact $stream ([int]$length) "$Role|first";$stream.Position=0;$second=Read-Exact $stream ([int]$length) "$Role|second"
        if(-not(Test-BytesEqual $first $second)){Throw-Provision "PRODUCTION_AUTHORITY_DOUBLE_READ_MISMATCH|$Role"}
    }finally{$stream.Dispose()}
    if((Get-NoFollowIdentity $absolute)-cne $before){Throw-Provision "PRODUCTION_AUTHORITY_PATH_IDENTITY_CHANGED|$Role"}
    return [pscustomobject]@{absolute=$absolute;bytes=$first;sha256=(Get-BytesSha256 $first);size_bytes=[long]$first.Length;identity=$before}
}

function ConvertFrom-StrictJson([byte[]]$Bytes,[string]$Role) {
    if($Bytes.Length-ge 3 -and $Bytes[0]-eq 0xef -and $Bytes[1]-eq 0xbb -and $Bytes[2]-eq 0xbf){Throw-Provision "PRODUCTION_AUTHORITY_UTF8_BOM_REJECTED|$Role"}
    $raw=$script:Utf8Strict.GetString($Bytes);if($raw.Contains("`r")){Throw-Provision "PRODUCTION_AUTHORITY_NONCANONICAL_NEWLINE|$Role"}
    $command=Get-Command ConvertFrom-Json -CommandType Cmdlet
    if($command.Parameters.ContainsKey('DateKind')){$value=ConvertFrom-Json -InputObject $raw -DateKind String}else{$value=ConvertFrom-Json -InputObject $raw}
    $tokens=[regex]::Matches($raw,'(?:\{|,)\s*"(?:\\["\\/bfnrt]|\\u[0-9a-fA-F]{4}|[^"\\])*"\s*:').Count
    if($tokens-ne(Get-JsonGraphPropertyCount $value)){Throw-Provision "PRODUCTION_AUTHORITY_DUPLICATE_OR_AMBIGUOUS_PROPERTY|$Role"};return $value
}

function Test-PathUnderRoot([string]$Path,[string]$Root) {
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\','/');$rootFull=[IO.Path]::GetFullPath($Root).TrimEnd('\','/')
    return $full.Equals($rootFull,[StringComparison]::OrdinalIgnoreCase)-or
        $full.StartsWith($rootFull+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)
}

function Assert-PrivateDirectoryAcl([string]$Path,[string]$Role) {
    $absolute=[IO.Path]::GetFullPath($Path);Assert-NoReparseChain $absolute $true
    if(-not[IO.Directory]::Exists($absolute)-or[IO.File]::Exists($absolute)){Throw-Provision "PRODUCTION_AUTHORITY_PRIVATE_DIRECTORY_REQUIRED|$Role"}
    $acl=Get-Acl -LiteralPath $absolute -ErrorAction Stop
    if(-not$acl.AreAccessRulesProtected){Throw-Provision "PRODUCTION_AUTHORITY_PRIVATE_DIRECTORY_ACL_INHERITANCE_REJECTED|$Role"}
    $current=[Security.Principal.WindowsIdentity]::GetCurrent().User
    $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    try{$owner=(New-Object Security.Principal.NTAccount($acl.Owner)).Translate([Security.Principal.SecurityIdentifier])}
    catch{Throw-Provision "PRODUCTION_AUTHORITY_PRIVATE_DIRECTORY_OWNER_INVALID|$Role"}
    if($owner-ne$current-and$owner-ne$system){Throw-Provision "PRODUCTION_AUTHORITY_PRIVATE_DIRECTORY_OWNER_INVALID|$Role"}
    $approved=@($current.Value,$system.Value);$full=[Security.AccessControl.FileSystemRights]::FullControl
    $found=New-Object Collections.Generic.HashSet[string]([StringComparer]::Ordinal)
    foreach($rule in @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]))){
        if($rule.IsInherited-or$rule.IdentityReference.Value-cnotin$approved-or
                $rule.AccessControlType-ne[Security.AccessControl.AccessControlType]::Allow){
            Throw-Provision "PRODUCTION_AUTHORITY_PRIVATE_DIRECTORY_ACL_PRINCIPAL_REJECTED|$Role"
        }
        if(($rule.FileSystemRights-band$full)-eq$full){$null=$found.Add($rule.IdentityReference.Value)}
    }
    if(-not$found.Contains($current.Value)-or-not$found.Contains($system.Value)){Throw-Provision "PRODUCTION_AUTHORITY_PRIVATE_DIRECTORY_ACL_INCOMPLETE|$Role"}
    return $absolute
}

function Get-DirectoryComponents([string]$DirectoryPath) {
    $full=[IO.Path]::GetFullPath($DirectoryPath).TrimEnd('\','/');$root=[IO.Path]::GetPathRoot($full)
    $components=New-Object Collections.Generic.List[string]
    $components.Add($root.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar)
    [char[]]$separators=@([IO.Path]::DirectorySeparatorChar,[IO.Path]::AltDirectorySeparatorChar);$cursor=$root
    foreach($segment in @($full.Substring($root.Length).Split($separators,[StringSplitOptions]::RemoveEmptyEntries))){$cursor=Join-Path $cursor $segment;$components.Add([IO.Path]::GetFullPath($cursor))}
    return @($components)
}

function Open-StableDirectoryChain([string]$DirectoryPath) {
    Initialize-ProvisionIdentityApi;$absolute=[IO.Path]::GetFullPath($DirectoryPath);Assert-NoReparseChain $absolute $true
    $handles=New-Object Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]
    $identities=New-Object Collections.Generic.List[string]
    try{
        $components=@(Get-DirectoryComponents $absolute)
        foreach($component in $components){
            $handle=[MCAceAuthorityProvisionIdentityV4]::OpenPinnedDirectory([string]$component)
            $identity=[MCAceAuthorityProvisionIdentityV4]::FromHandle($handle)
            if($identity-cne(Get-NoFollowIdentity $component -Directory)){$handle.Dispose();Throw-Provision 'PRODUCTION_AUTHORITY_STABLE_DIRECTORY_IDENTITY_MISMATCH'}
            $handles.Add($handle);$identities.Add($identity)
        }
        return [pscustomobject]@{path=$absolute;components=$components;handles=@($handles);identities=@($identities)}
    }catch{for($i=$handles.Count-1;$i-ge 0;$i--){$handles[$i].Dispose()};throw}
}

function Assert-StableDirectoryChain([object]$Anchor,[string]$Stage) {
    for($i=0;$i-lt@($Anchor.handles).Count;$i++){
        $fromHandle=[MCAceAuthorityProvisionIdentityV4]::FromHandle($Anchor.handles[$i])
        $fromPath=Get-NoFollowIdentity $Anchor.components[$i] -Directory
        if($fromHandle-cne[string]$Anchor.identities[$i]-or$fromPath-cne[string]$Anchor.identities[$i]){Throw-Provision "PRODUCTION_AUTHORITY_STABLE_DIRECTORY_CHANGED|$Stage"}
    }
}

function Close-StableDirectoryChain([object]$Anchor){if($null-ne$Anchor){for($i=@($Anchor.handles).Count-1;$i-ge 0;$i--){$Anchor.handles[$i].Dispose()}}}

function Get-RuntimeRelativePath([string]$Root,[string]$Path) {
    $rootFull=[IO.Path]::GetFullPath($Root).TrimEnd('\','/');$pathFull=[IO.Path]::GetFullPath($Path);$prefix=$rootFull+[IO.Path]::DirectorySeparatorChar
    if(-not$pathFull.StartsWith($prefix,[StringComparison]::OrdinalIgnoreCase)){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_PATH_OUTSIDE_ROOT'}
    return $pathFull.Substring($prefix.Length).Replace('\','/')
}

function Sort-RuntimeItemsOrdinal([object[]]$Items) {
    $sorted=New-Object Collections.ArrayList
    foreach($item in @($Items)){$at=0;while($at-lt$sorted.Count-and[StringComparer]::Ordinal.Compare([string]$sorted[$at].relative_path,[string]$item.relative_path)-lt 0){$at++};$sorted.Insert($at,$item)}
    return @($sorted.ToArray())
}

function Get-RuntimeFileSet([string]$Root) {
    $files=@();foreach($item in @(Get-ChildItem -LiteralPath $Root -Recurse -Force -File)){Assert-NoReparseChain $item.FullName $true;$files+=[pscustomobject]@{relative_path=(Get-RuntimeRelativePath $Root $item.FullName);path=$item.FullName}}
    return @(Sort-RuntimeItemsOrdinal $files)
}

function Assert-StableDocument([object]$Original,[long]$Maximum,[string]$Role,[long]$Minimum=1) {
    $now=Read-LockedFile $Original.absolute $Maximum $Role $Minimum
    if($now.sha256-cne[string]$Original.sha256-or$now.size_bytes-ne[long]$Original.size_bytes-or$now.identity-cne[string]$Original.identity-or-not(Test-BytesEqual $now.bytes $Original.bytes)){Throw-Provision "PRODUCTION_AUTHORITY_INPUT_MUTATED|$Role"}
}

function Resolve-OpenSslRuntime([string]$ManifestPath,[string]$ManifestPin,[string]$Requested,[string]$Expected) {
    if(-not[IO.Path]::IsPathRooted($Requested)){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_ABSOLUTE_PATH_REQUIRED'}
    $absolute=[IO.Path]::GetFullPath($Requested)
    if([IO.Path]::GetExtension($absolute)-cne'.exe'){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_SCRIPT_SHIM_REJECTED'}
    $manifestDoc=Read-LockedFile $ManifestPath 4MB 'openssl-runtime-manifest' 64
    if($manifestDoc.sha256-cne$ManifestPin.ToLowerInvariant()){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_MANIFEST_SHA256_MISMATCH'}
    $manifest=ConvertFrom-StrictJson $manifestDoc.bytes 'openssl-runtime-manifest'
    if(-not(Test-ExactProperties $manifest @('schema','artifact_class','platform','executable_relative_path','files','test_fixture'))-or
            [string]$manifest.schema-cne'MCACE_OPENSSL_RUNTIME_MANIFEST_V1'-or[string]$manifest.artifact_class-cne'REVIEWED_OPENSSL_RUNTIME'-or
            [string]$manifest.platform-cne'windows-x64'-or$manifest.files-isnot[Array]-or$manifest.test_fixture-isnot[bool]-or[bool]$manifest.test_fixture-or-not[Environment]::Is64BitProcess){
        Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_MANIFEST_SCHEMA_INVALID'
    }
    $runtimeRoot=Assert-PrivateDirectoryAcl ([IO.Path]::GetDirectoryName($absolute)) 'openssl-runtime-root'
    if(Test-PathUnderRoot $manifestDoc.absolute $runtimeRoot){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_MANIFEST_INSIDE_RUNTIME_REJECTED'}
    $providers=Join-Path $runtimeRoot 'providers';Assert-NoReparseChain $providers $true
    if(-not[IO.Directory]::Exists($providers)){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_PROVIDERS_DIRECTORY_REQUIRED'}
    $entries=@($manifest.files);if($entries.Count-lt 4-or$entries.Count-gt 1024){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_FILE_COUNT_INVALID'}
    $expectedSet=[ordered]@{};$previous=$null;$exeCount=0;$dllCount=0;$providerCount=0;$configCount=0
    foreach($entry in $entries){
        if(-not(Test-ExactProperties $entry @('relative_path','role','size_bytes','sha256'))-or$entry.relative_path-isnot[string]-or$entry.role-isnot[string]-or
                $entry.size_bytes-isnot[long]-and$entry.size_bytes-isnot[int]){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_ENTRY_SCHEMA_INVALID'}
        $relative=[string]$entry.relative_path
        if($relative-cnotmatch'^[A-Za-z0-9][A-Za-z0-9._+@~/-]{0,255}$'-or$relative.Contains('\')-or$relative.Contains('//')-or@($relative.Split('/')|Where-Object{$_-in@('.','..')}).Count-ne 0){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_RELATIVE_PATH_INVALID'}
        if($null-ne$previous-and[StringComparer]::Ordinal.Compare([string]$previous,$relative)-ge 0){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_ORDER_OR_DUPLICATE_INVALID'};$previous=$relative
        if([string]$entry.sha256-cnotmatch'^[0-9a-f]{64}$'-or[long]$entry.size_bytes-le 0-or[long]$entry.size_bytes-gt$script:MaximumToolBytes){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_ENTRY_BINDING_INVALID'}
        switch([string]$entry.role){
            'EXECUTABLE'{if($relative-cne[string]$manifest.executable_relative_path){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_EXECUTABLE_BINDING_INVALID'};$exeCount++}
            'APPLICATION_LOCAL_DLL'{if($relative.Contains('/')-or[IO.Path]::GetExtension($relative)-cne'.dll'){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_DLL_LOCATION_INVALID'};$dllCount++}
            'PROVIDER_MODULE'{if(-not$relative.StartsWith('providers/',[StringComparison]::Ordinal)-or[IO.Path]::GetExtension($relative)-cne'.dll'){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_PROVIDER_LOCATION_INVALID'};$providerCount++}
            'CONFIG'{if($relative-cne'openssl.cnf'){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_CONFIG_LOCATION_INVALID'};$configCount++}
            default{Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_ROLE_INVALID'}
        }
        $path=Join-Path $runtimeRoot $relative.Replace('/',[IO.Path]::DirectorySeparatorChar);$document=Read-LockedFile $path $script:MaximumToolBytes "openssl-runtime-$relative"
        if($document.sha256-cne[string]$entry.sha256-or$document.size_bytes-ne[long]$entry.size_bytes){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_FILE_BINDING_INVALID'}
        $expectedSet[$relative]=[pscustomobject]@{path=$document.absolute;sha256=$document.sha256;size_bytes=$document.size_bytes;identity=$document.identity;bytes=$document.bytes}
    }
    if($exeCount-ne 1-or$dllCount-lt 1-or$providerCount-lt 1-or$configCount-ne 1){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_REQUIRED_ROLES_INVALID'}
    $actual=@(Get-RuntimeFileSet $runtimeRoot);if($actual.Count-ne$expectedSet.Count-or(($actual.relative_path-join"`n")-cne(@($expectedSet.Keys)-join"`n"))){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_EXACT_SET_MISMATCH'}
    $exeRelative=[string]$manifest.executable_relative_path;$expectedExecutable=[IO.Path]::GetFullPath((Join-Path $runtimeRoot $exeRelative))
    if(-not$expectedExecutable.Equals($absolute,[StringComparison]::OrdinalIgnoreCase)-or$expectedSet[$exeRelative].sha256-cne$Expected.ToLowerInvariant()){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_EXECUTABLE_BINDING_INVALID'}
    [byte[]]$knownConfig=$script:Utf8NoBom.GetBytes("# MCAce pinned empty OpenSSL configuration v1`n")
    if(-not(Test-BytesEqual $knownConfig $expectedSet['openssl.cnf'].bytes)){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_CONFIG_BYTES_INVALID'}
    return [pscustomobject]@{path=$expectedExecutable;sha256=$expectedSet[$exeRelative].sha256;identity=$expectedSet[$exeRelative].identity;root=$runtimeRoot;config_path=(Join-Path $runtimeRoot 'openssl.cnf');providers_path=$providers;manifest=$manifestDoc;entries=$expectedSet;relative_paths=@($expectedSet.Keys)}
}

function Open-RuntimeLocks([object]$Runtime) {
    $anchor=Open-StableDirectoryChain $Runtime.root;$streams=New-Object Collections.Generic.List[IO.FileStream]
    try{foreach($relative in @($Runtime.relative_paths)){$entry=$Runtime.entries[$relative];$stream=New-Object IO.FileStream($entry.path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);if([MCAceAuthorityProvisionIdentityV4]::FromHandle($stream.SafeFileHandle)-cne[string]$entry.identity-or$stream.Length-ne[long]$entry.size_bytes){$stream.Dispose();Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_LOCK_IDENTITY_INVALID'};$streams.Add($stream)};return [pscustomobject]@{anchor=$anchor;streams=@($streams)}}
    catch{for($i=$streams.Count-1;$i-ge 0;$i--){$streams[$i].Dispose()};Close-StableDirectoryChain $anchor;throw}
}

function Assert-RuntimeLocked([object]$Runtime,[object]$Locks,[string]$Stage) {
    Assert-StableDirectoryChain $Locks.anchor "openssl-runtime-$Stage";Assert-StableDocument $Runtime.manifest 4MB "openssl-runtime-manifest-$Stage" 64
    $actual=@(Get-RuntimeFileSet $Runtime.root);if($actual.Count-ne@($Runtime.relative_paths).Count-or(($actual.relative_path-join"`n")-cne(@($Runtime.relative_paths)-join"`n"))){Throw-Provision "PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_EXACT_SET_CHANGED|$Stage"}
    for($i=0;$i-lt@($Runtime.relative_paths).Count;$i++){$relative=[string]$Runtime.relative_paths[$i];$entry=$Runtime.entries[$relative];$stream=$Locks.streams[$i];if([MCAceAuthorityProvisionIdentityV4]::FromHandle($stream.SafeFileHandle)-cne[string]$entry.identity-or$stream.Length-ne[long]$entry.size_bytes){Throw-Provision "PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_LOCK_CHANGED|$Stage"};$stream.Position=0;$bytes=Read-Exact $stream ([int]$stream.Length) "openssl-runtime-$relative-$Stage";if((Get-BytesSha256 $bytes)-cne[string]$entry.sha256){Throw-Provision "PRODUCTION_AUTHORITY_OPENSSL_RUNTIME_HASH_CHANGED|$Stage"}}
}

function Close-RuntimeLocks([object]$Locks){if($null-ne$Locks){try{for($i=@($Locks.streams).Count-1;$i-ge 0;$i--){$Locks.streams[$i].Dispose()}}finally{Close-StableDirectoryChain $Locks.anchor}}}

function Assert-BoundedToken([string]$Value,[string]$Field,[int]$Maximum=128) {
    if([string]::IsNullOrWhiteSpace($Value)-or $Value.Length-gt $Maximum -or $Value-cnotmatch '^[A-Za-z0-9][A-Za-z0-9._@/+~-]*$'){Throw-Provision "PRODUCTION_AUTHORITY_FIELD_OUTSIDE_BOUNDS:$Field"}
}

function Add-BE64([IO.Stream]$Stream,[long]$Value){[byte[]]$b=[BitConverter]::GetBytes([int64]$Value);if([BitConverter]::IsLittleEndian){[Array]::Reverse($b)};$Stream.Write($b,0,8)}
function Add-BE32([IO.Stream]$Stream,[long]$Value){[byte[]]$b=[BitConverter]::GetBytes([uint32]$Value);if([BitConverter]::IsLittleEndian){[Array]::Reverse($b)};$Stream.Write($b,0,4)}
function Add-Text([IO.Stream]$Stream,[string]$Value){[byte[]]$b=[Text.Encoding]::UTF8.GetBytes($Value);Add-BE32 $Stream $b.Length;$Stream.Write($b,0,$b.Length)}

function Get-ProfileHash([object[]]$Providers,[long]$Domains,[long]$Window,[long]$Cooldown){
    $stream=New-Object IO.MemoryStream
    try{Add-Text $stream 'mcace/backend-authority/profile/v1';Add-BE64 $stream $Domains;Add-BE64 $stream $Window;Add-BE64 $stream $Cooldown
        $ordered=@($Providers|Sort-Object provider_id);Add-BE64 $stream $ordered.Count
        foreach($p in $ordered){Add-Text $stream ([string]$p.provider_id);Add-Text $stream ([string]$p.trust_domain_id);Add-Text $stream ([string]$p.version);Add-Text $stream ([string]$p.stable_check_family);Add-BE64 $stream ([long]$p.threshold)}
        return Get-BytesSha256 $stream.ToArray()}finally{$stream.Dispose()}
}

function Get-TopologyHash([object]$Topology){
    $stream=New-Object IO.MemoryStream
    try{Add-Text $stream 'mcace/production-authority/topology/v4'
        foreach($n in @('selected_proxy_platform','proxy_instance_id','backend_instance_id','registered_backend','paper_role','proxy_activation_constraint')){Add-Text $stream ([string]$Topology[$n])}
        foreach($n in @('observation_ttl_ms','grant_ttl_ms','journal_quota_bytes')){Add-BE64 $stream ([long]$Topology[$n])}
        Add-BE64 $stream @($Topology.proxy_configuration_targets).Count;foreach($t in @($Topology.proxy_configuration_targets)){Add-Text $stream ([string]$t)}
        return Get-BytesSha256 $stream.ToArray()}finally{$stream.Dispose()}
}

function Convert-WindowsArgument([string]$Value) {
    if($null-eq$Value-or$Value-match'[\x00-\x1f]'-or$Value.Length-gt 32760){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_ARGUMENT_INVALID'}
    if($Value-notmatch'[\s"]'){return $Value};$builder=New-Object Text.StringBuilder;$null=$builder.Append('"');$slashes=0
    foreach($character in $Value.ToCharArray()){
        if($character-eq'\'){$slashes++;continue}
        if($character-eq'"'){$null=$builder.Append(('\'*(($slashes*2)+1)));$null=$builder.Append('"');$slashes=0;continue}
        if($slashes-gt 0){$null=$builder.Append(('\'*$slashes));$slashes=0};$null=$builder.Append($character)
    }
    if($slashes-gt 0){$null=$builder.Append(('\'*($slashes*2)))};$null=$builder.Append('"');return $builder.ToString()
}

function Invoke-OpenSsl([object]$Tool,[string[]]$Arguments,[string]$Operation){
    Assert-RuntimeLocked $Tool $Tool.runtime_locks "pre-$Operation";$process=$null
    try{
        $start=New-Object Diagnostics.ProcessStartInfo;$start.FileName=[string]$Tool.path;$start.WorkingDirectory=[string]$Tool.root
        $start.UseShellExecute=$false;$start.CreateNoWindow=$true;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
        $start.Arguments=(@($Arguments|ForEach-Object{Convert-WindowsArgument ([string]$_)})-join' ')
        $start.EnvironmentVariables.Clear()
        foreach($name in @('SystemRoot','WINDIR','TEMP','TMP')){$value=[Environment]::GetEnvironmentVariable($name,'Process');if(-not[string]::IsNullOrWhiteSpace($value)){$start.EnvironmentVariables[$name]=$value}}
        $start.EnvironmentVariables['PATH']=[string]$Tool.root+';'+(Join-Path $env:SystemRoot 'System32')
        $start.EnvironmentVariables['OPENSSL_CONF']=[string]$Tool.config_path
        $start.EnvironmentVariables['OPENSSL_MODULES']=[string]$Tool.providers_path
        $process=New-Object Diagnostics.Process;$process.StartInfo=$start
        if(-not$process.Start()){Throw-Provision "PRODUCTION_AUTHORITY_OPENSSL_START_FAILED|$Operation"}
        $stdoutTask=$process.StandardOutput.ReadToEndAsync();$stderrTask=$process.StandardError.ReadToEndAsync()
        if(-not$process.WaitForExit(60000)){try{$process.Kill()}catch{};Throw-Provision "PRODUCTION_AUTHORITY_OPENSSL_TIMEOUT|$Operation"}
        $stdout=$stdoutTask.GetAwaiter().GetResult();$stderr=$stderrTask.GetAwaiter().GetResult();$exit=$process.ExitCode
    }finally{if($null-ne$process){$process.Dispose()};Assert-RuntimeLocked $Tool $Tool.runtime_locks "post-$Operation"}
    if($exit-ne 0){Throw-Provision "PRODUCTION_AUTHORITY_OPENSSL_OPERATION_FAILED:$Operation"}
    return @((@($stdout,$stderr)-join"`n")-split"`r?`n"|Where-Object{-not[string]::IsNullOrWhiteSpace($_)})
}

function New-Ed25519Material([object]$Tool,[string]$Directory,[string]$Label){
    $private=Join-Path $Directory "$Label-private-key.pk8";$public=Join-Path $Directory ".$Label-public.der";$probe=Join-Path $Directory ".$Label-probe";$signature=Join-Path $Directory ".$Label-signature"
    [IO.File]::WriteAllBytes($probe,[Text.Encoding]::ASCII.GetBytes("mcace/authority/provisioning/$Label/v4"))
    try{
        $null=Invoke-OpenSsl $Tool @('genpkey','-algorithm','ED25519','-outform','DER','-out',$private) "generate-$Label"
        $null=Invoke-OpenSsl $Tool @('pkey','-inform','DER','-in',$private,'-pubout','-outform','DER','-out',$public) "derive-$Label-public"
        $null=Invoke-OpenSsl $Tool @('pkeyutl','-sign','-rawin','-inkey',$private,'-keyform','DER','-in',$probe,'-out',$signature) "sign-$Label-probe"
        $null=Invoke-OpenSsl $Tool @('pkeyutl','-verify','-rawin','-pubin','-inkey',$public,'-keyform','DER','-in',$probe,'-sigfile',$signature) "verify-$Label-probe"
        $publicDoc=Read-LockedFile $public 4096 "$Label-public" 32
        return [pscustomobject]@{private_path=$private;public_der=$publicDoc.bytes;key_id_sha256=$publicDoc.sha256}
    }finally{foreach($p in @($public,$probe,$signature)){if([IO.File]::Exists($p)){[IO.File]::Delete($p)}}}
}

function Write-Bytes([string]$Path,[byte[]]$Bytes){$parent=[IO.Path]::GetDirectoryName($Path);if(-not[IO.Directory]::Exists($parent)){[IO.Directory]::CreateDirectory($parent)|Out-Null};[IO.File]::WriteAllBytes($Path,$Bytes)}
function Write-Text([string]$Path,[string]$Text){Write-Bytes $Path $script:Utf8NoBom.GetBytes($Text)}

function Protect-PrivateDirectory([string]$Path){
    try{
        $current=[Security.Principal.WindowsIdentity]::GetCurrent().User
        $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
        $acl=New-Object Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true,$false)
        $inheritance=[Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit
        foreach($sid in @($current,$system)){
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
                $sid,[Security.AccessControl.FileSystemRights]::FullControl,$inheritance,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow)))
        }
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
        return $true
    }catch{return $false}
}

function Protect-PrivateFile([string]$Path){
    if(-not $script:RunningOnWindows){& chmod 600 -- $Path;return $LASTEXITCODE-eq 0}
    try{
        $current=[Security.Principal.WindowsIdentity]::GetCurrent().User
        $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
        $acl=New-Object Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true,$false)
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($current,'FullControl','Allow')))
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($system,'FullControl','Allow')))
        Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop;return $true
    }catch{return $false}
}

# Validate bounded production topology.
foreach($item in @(
    @($ProxyInstanceId,'ProxyInstanceId',128),@($BackendInstanceId,'BackendInstanceId',128),
    @($RegisteredBackend,'RegisteredBackend',128),@($ProfileName,'ProfileName',128),
    @($GrimProviderId,'GrimProviderId',32),@($GrimTrustDomainId,'GrimTrustDomainId',128),
    @($GrimVersion,'GrimVersion',32),@($GrimStableCheckFamily,'GrimStableCheckFamily',96),
    @($VulcanProviderId,'VulcanProviderId',32),@($VulcanTrustDomainId,'VulcanTrustDomainId',128),
    @($VulcanVersion,'VulcanVersion',32),@($VulcanStableCheckFamily,'VulcanStableCheckFamily',96))){Assert-BoundedToken ([string]$item[0]) ([string]$item[1]) ([int]$item[2])}
if($GrimProviderId-cne 'grim' -or $VulcanProviderId-cne 'vulcan' -or
        [StringComparer]::OrdinalIgnoreCase.Equals($GrimTrustDomainId,$VulcanTrustDomainId)){
    Throw-Provision 'PRODUCTION_AUTHORITY_PROVIDER_TRUST_DOMAINS_INVALID'
}
if($RequiredIndependentDomains-ne 2 -or $GrimThreshold-le 0 -or $GrimThreshold-gt 256 -or
        $VulcanThreshold-le 0 -or $VulcanThreshold-gt 256 -or
        $MaximumProviderWindowMs-le 0 -or $MaximumProviderWindowMs-gt 30000 -or
        $CooldownMs-lt 0 -or $CooldownMs-gt 2592000000 -or
        $ObservationTtlMs-ne 30000 -or $GrantTtlMs-ne 30000 -or
        $JournalQuotaBytes-lt 48 -or $JournalQuotaBytes-gt 67108864 -or $ActionCeiling-cne 'MONITOR'){
    Throw-Provision 'PRODUCTION_AUTHORITY_NUMERIC_OR_ACTION_CONTRACT_INVALID'
}

$output=[IO.Path]::GetFullPath($OutputRoot);$parent=[IO.Path]::GetDirectoryName($output)
if(-not[IO.Path]::IsPathRooted($OutputRoot)-or [string]::IsNullOrWhiteSpace($parent)-or
        -not[IO.Directory]::Exists($parent)-or [IO.Directory]::Exists($output)-or [IO.File]::Exists($output)){
    Throw-Provision 'PRODUCTION_AUTHORITY_OUTPUT_MUST_BE_NEW_ABSOLUTE_DIRECTORY'
}
Assert-NoReparseChain $parent $true
$repoPrefix=$script:RepoRoot.TrimEnd('\','/')+[IO.Path]::DirectorySeparatorChar
if($output.StartsWith($repoPrefix,[StringComparison]::OrdinalIgnoreCase)){Throw-Provision 'PRODUCTION_AUTHORITY_OUTPUT_INSIDE_REPOSITORY'}

$descriptorPath=[IO.Path]::GetFullPath($CaptureSupervisorPublicDescriptorPath)
if($descriptorPath.StartsWith($repoPrefix,[StringComparison]::OrdinalIgnoreCase)){Throw-Provision 'PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_MUST_BE_EXTERNAL'}
$descriptorDoc=Read-LockedFile $descriptorPath 1MB 'capture-supervisor-public-descriptor'
if($descriptorDoc.sha256-cne $ExpectedCaptureSupervisorPublicDescriptorSha256.ToLowerInvariant()){Throw-Provision 'PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_PIN_MISMATCH'}
$approved=[Environment]::GetEnvironmentVariable('MCACE_RELEASE_APPROVED_PRODUCTION_AUTHORITY_SUPERVISOR_DESCRIPTOR_SHA256','Process')
if([string]::IsNullOrWhiteSpace($approved)-or $approved-cne $descriptorDoc.sha256){Throw-Provision 'PRODUCTION_AUTHORITY_OUT_OF_BAND_APPROVED_PIN_REQUIRED'}
$descriptor=ConvertFrom-StrictJson $descriptorDoc.bytes 'capture-supervisor-public-descriptor'
if(-not(Test-ExactProperties $descriptor @('schema','artifact_class','algorithm','key_id_sha256','public_key_der_base64','test_fixture')) -or
        [string]$descriptor.schema-cne 'MCACE_PRODUCTION_AUTHORITY_CAPTURE_SUPERVISOR_PUBLIC_DESCRIPTOR_V1' -or
        [string]$descriptor.artifact_class-cne 'EXTERNAL_RELEASE_CAPTURE_SUPERVISOR_PUBLIC_ROOT' -or
        [string]$descriptor.algorithm-cne 'ED25519' -or $descriptor.test_fixture-isnot[bool] -or [bool]$descriptor.test_fixture){
    Throw-Provision 'PRODUCTION_AUTHORITY_EXTERNAL_SUPERVISOR_DESCRIPTOR_INVALID'
}
try{[byte[]]$supervisorPublic=[Convert]::FromBase64String([string]$descriptor.public_key_der_base64)}catch{Throw-Provision 'PRODUCTION_AUTHORITY_SUPERVISOR_PUBLIC_KEY_INVALID'}
if($supervisorPublic.Length-lt 32 -or $supervisorPublic.Length-gt 256 -or [Convert]::ToBase64String($supervisorPublic)-cne [string]$descriptor.public_key_der_base64 -or
        (Get-BytesSha256 $supervisorPublic)-cne [string]$descriptor.key_id_sha256){Throw-Provision 'PRODUCTION_AUTHORITY_SUPERVISOR_KEY_ID_MISMATCH'}

$tool=Resolve-OpenSslRuntime $OpenSslRuntimeManifestPath $ExpectedOpenSslRuntimeManifestSha256 $OpenSslPath $ExpectedOpenSslSha256
$runtimeLocks=$null
try{
    $runtimeLocks=Open-RuntimeLocks $tool
    $tool|Add-Member -NotePropertyName runtime_locks -NotePropertyValue $runtimeLocks
    $version=Invoke-OpenSsl $tool @('version') 'version'
    if(($version-join"`n")-cnotmatch'(?m)^OpenSSL\s+3(?:\.|\s)'){Throw-Provision 'PRODUCTION_AUTHORITY_OPENSSL_3_REQUIRED'}
    $stage=Join-Path $parent ('.mcace-provision-v4-'+[guid]::NewGuid().ToString('N'));[IO.Directory]::CreateDirectory($stage)|Out-Null
    if(-not(Protect-PrivateDirectory $stage)){Throw-Provision 'PRODUCTION_AUTHORITY_PRIVATE_STAGE_ACL_HARDENING_FAILED'}
    $null=Assert-PrivateDirectoryAcl $stage 'provision-stage'
    $committed=$false
    try{
    foreach($dir in @('paper/authority','velocity/authority','bungeecord/authority','evidence-supervisor')){[IO.Directory]::CreateDirectory((Join-Path $stage $dir))|Out-Null}
    $backend=New-Ed25519Material $tool (Join-Path $stage 'paper/authority') 'backend'
    $proxy=New-Ed25519Material $tool (Join-Path $stage 'paper/authority') 'proxy'
    if($backend.key_id_sha256-ceq $proxy.key_id_sha256){Throw-Provision 'PRODUCTION_AUTHORITY_SOURCE_TARGET_KEYS_NOT_DISTINCT'}
    $backendText=[Convert]::ToBase64String($backend.public_der)+"`n";$proxyText=[Convert]::ToBase64String($proxy.public_der)+"`n"
    Write-Text (Join-Path $stage 'paper/authority/backend-public-key.txt') $backendText
    Write-Text (Join-Path $stage 'paper/proxy-public-key.txt') $proxyText
    Write-Text (Join-Path $stage 'velocity/authority/backend-public-key.txt') $backendText
    Write-Text (Join-Path $stage 'bungeecord/authority/backend-public-key.txt') $backendText
    Write-Text (Join-Path $stage 'paper/authority/issuance.log') "MCACE_SERVER_AUTHORITY_ISSUANCE_JOURNAL_V3`n"
    Write-Bytes (Join-Path $stage 'evidence-supervisor/capture-supervisor-public-descriptor.json') $descriptorDoc.bytes
    $selected=$ProxyPlatform.ToLowerInvariant();$identity=Join-Path $stage "$selected/identity";[IO.Directory]::CreateDirectory($identity)|Out-Null
    $proxyPrivateFinal=Join-Path $identity 'server-private-key.pk8';[IO.File]::Move($proxy.private_path,$proxyPrivateFinal)
    Write-Text (Join-Path $identity 'server-public-key.txt') $proxyText

    $providers=@(
        [pscustomobject][ordered]@{provider_id='grim';trust_domain_id=$GrimTrustDomainId;version=$GrimVersion;stable_check_family=$GrimStableCheckFamily;threshold=$GrimThreshold},
        [pscustomobject][ordered]@{provider_id='vulcan';trust_domain_id=$VulcanTrustDomainId;version=$VulcanVersion;stable_check_family=$VulcanStableCheckFamily;threshold=$VulcanThreshold})
    $profileHash=Get-ProfileHash $providers $RequiredIndependentDomains $MaximumProviderWindowMs $CooldownMs
    $topology=[ordered]@{selected_proxy_platform=$selected;proxy_instance_id=$ProxyInstanceId;backend_instance_id=$BackendInstanceId;registered_backend=$RegisteredBackend;
        observation_ttl_ms=$ObservationTtlMs;grant_ttl_ms=$GrantTtlMs;journal_quota_bytes=$JournalQuotaBytes;paper_role='signer-and-durable-journal';
        proxy_configuration_targets=@('velocity','bungeecord');proxy_activation_constraint='deploy-exactly-one-generated-proxy-configuration'}
    $topologyHash=Get-TopologyHash $topology;$topology.sha256=$topologyHash
    $freeze=[ordered]@{
        schema_version='mcace-production-authority-freeze/v3';artifact_source_commit=((& git -C $script:RepoRoot rev-parse HEAD).Trim().ToLowerInvariant());action_ceiling='MONITOR'
        evidence_supervisor=[ordered]@{algorithm='ED25519';key_id_sha256=[string]$descriptor.key_id_sha256;public_descriptor_sha256=$descriptorDoc.sha256;
            public_key_descriptor_path='evidence-supervisor/capture-supervisor-public-descriptor.json';approved_pin_required=$true;private_key_present=$false}
        proxy_authority=[ordered]@{proxy_instance_id=$ProxyInstanceId;selected_proxy_platform=$selected;proxy_identity_key_id_sha256=$proxy.key_id_sha256;
            proxy_public_key_der_base64=[Convert]::ToBase64String($proxy.public_der);paper_public_key_pin_path='paper/proxy-public-key.txt';selected_proxy_public_key_path="$selected/identity/server-public-key.txt"}
        backend_authority=[ordered]@{registered_backend=$RegisteredBackend;backend_instance_id=$BackendInstanceId;backend_key_id_sha256=$backend.key_id_sha256;
            backend_public_key_der_base64=[Convert]::ToBase64String($backend.public_der)}
        behavior=[ordered]@{enabled=$true;adapters=[ordered]@{grim=$true;vulcan=$true}}
        profile=[ordered]@{name=$ProfileName;sha256=$profileHash;required_independent_domains=2;maximum_provider_window_ms=$MaximumProviderWindowMs;cooldown_ms=$CooldownMs;providers=$providers}
        topology=$topology
    }
    $freezeJson=(($freeze|ConvertTo-Json -Depth 12)-replace "`r`n","`n")+"`n"
    Write-Text (Join-Path $stage 'freeze-manifest.json') $freezeJson
    $paperYaml=@("behavior:","  enabled: true","  grim:","    enabled: true","  vulcan:","    enabled: true","authority:","  enabled: true","  mode: MONITOR",
        "  proxy-instance-id: `"$ProxyInstanceId`"","  backend-instance-id: `"$BackendInstanceId`"","  backend-private-key-path: `"authority/backend-private-key.pk8`"",
        "  backend-public-key-path: `"authority/backend-public-key.txt`"","  backend-key-id-sha256: `"$($backend.key_id_sha256)`"","  issuance-journal-path: `"authority/issuance.log`"",
        "  journal-quota-bytes: $JournalQuotaBytes","  observation-ttl-ms: $ObservationTtlMs","  profile:","    sha256: `"$profileHash`"","    required-independent-domains: 2",
        "    maximum-provider-window-ms: $MaximumProviderWindowMs","    cooldown-ms: $CooldownMs")-join "`n"
    Write-Text (Join-Path $stage 'paper/authority-snippet.yml') ($paperYaml+"`n")
    $properties=@('# Generated MCAce production authority V4 freeze. MONITOR only.','authority.enabled=true','authority.mode=MONITOR',
        "authority.proxy-instance-id=$ProxyInstanceId","authority.grant-ttl-ms=$GrantTtlMs","authority.backends=$RegisteredBackend",
        "authority.backend.$RegisteredBackend.instance-id=$BackendInstanceId","authority.backend.$RegisteredBackend.public-key-path=authority/backend-public-key.txt",
        "authority.backend.$RegisteredBackend.key-id-sha256=$($backend.key_id_sha256)","authority.backend.$RegisteredBackend.profiles=$ProfileName",
        "authority.backend.$RegisteredBackend.profile.$ProfileName.sha256=$profileHash")-join "`n";$properties+="`n"
    Write-Text (Join-Path $stage 'velocity/authority.properties') $properties;Write-Text (Join-Path $stage 'bungeecord/authority.properties') $properties
    if(-not(Protect-PrivateFile (Join-Path $stage 'paper/authority/backend-private-key.pk8')) -or -not(Protect-PrivateFile $proxyPrivateFinal)){
        Throw-Provision 'PRODUCTION_AUTHORITY_PRIVATE_ACL_HARDENING_FAILED'
    }
    if(Get-ChildItem -LiteralPath $stage -Recurse -Force|Where-Object{$_.Name -match '(?i)supervisor.*private|private.*supervisor'}){
        Throw-Provision 'PRODUCTION_AUTHORITY_SUPERVISOR_PRIVATE_MATERIAL_REJECTED'
    }
    Assert-RuntimeLocked $tool $runtimeLocks 'before-provision-commit'
    [IO.Directory]::Move($stage,$output);$committed=$true
    Write-Output (('PRODUCTION_AUTHORITY_PROVISIONED_V4|output_root={0}|supervisor_descriptor_sha256={1}|supervisor_key_id_sha256={2}'+
        '|proxy_identity_key_id_sha256={3}|backend_key_id_sha256={4}|profile_sha256={5}|topology_sha256={6}|action_ceiling=MONITOR') -f
        $output,$descriptorDoc.sha256,[string]$descriptor.key_id_sha256,$proxy.key_id_sha256,$backend.key_id_sha256,$profileHash,$topologyHash)
    }finally{
        if(-not $committed -and [IO.Directory]::Exists($stage)){Assert-NoReparseChain $stage $true;[IO.Directory]::Delete($stage,$true)}
    }
}finally{
    Close-RuntimeLocks $runtimeLocks
}
