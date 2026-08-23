[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tool = Join-Path $PSScriptRoot 'new-exact-artifact-policy.ps1'
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('mcace-exact-policy-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    $artifact = Join-Path $temporary 'pack.zip'
    [IO.File]::WriteAllBytes($artifact, [Text.Encoding]::UTF8.GetBytes('mcace-exact-policy-fixture'))
    $exact = (& $tool -ArtifactPath $artifact -EntryId 'fixture-exact' -ArtifactType RESOURCE_PACK -MatchType ExactSha256) -join "`n"
    $expected = (Get-FileHash -LiteralPath $artifact -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($exact -notmatch "sha256_hex: `"$expected`"") { throw 'exact hash was not emitted' }
    if ($exact -notmatch 'enabled: false') { throw 'exact policy is not fail-closed by default' }

    $directory = Join-Path $temporary 'directory-pack'
    New-Item -ItemType Directory -Path (Join-Path $directory 'assets') -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $directory 'pack.mcmeta'), '{}', [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Join-Path (Join-Path $directory 'assets') 'test.txt'), 'fixture', [Text.UTF8Encoding]::new($false))
    $root = (& $tool -ArtifactPath $directory -EntryId 'fixture-root' -ArtifactType RESOURCE_PACK -MatchType ContentRoot) -join "`n"
    if ($root -notmatch 'content_root_sha256_hex: "[0-9a-f]{64}"') { throw 'content root was not emitted' }
    $output = Join-Path $temporary 'generated.textproto'
    & $tool -ArtifactPath $artifact -EntryId 'fixture-output' -ArtifactType RESOURCE_PACK -MatchType ExactSha256 -OutputPath $output | Out-Null
    if (-not (Test-Path -LiteralPath $output -PathType Leaf)) { throw 'OutputPath file was not created' }
    $outputText = [IO.File]::ReadAllText($output)
    if ($outputText -notmatch 'entry_id: "fixture-output"' -or $outputText -notmatch 'enabled: false') {
        throw 'OutputPath content was not written atomically'
    }
    [Console]::Out.WriteLine('{"schema":1,"tool":"mcace-exact-artifact-policy-tests","status":"passed"}')
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
