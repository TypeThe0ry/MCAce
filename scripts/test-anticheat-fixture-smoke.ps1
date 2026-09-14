[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$scriptPath = Join-Path $PSScriptRoot 'anticheat-fixture-smoke.ps1'
$source = Get-Content -LiteralPath $scriptPath -Raw

$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile(
    $scriptPath, [ref]$null, [ref]$errors) | Out-Null
if ($errors.Count -ne 0) { throw 'ANTICHEAT_FIXTURE_SCRIPT_PARSE_FAILED' }

foreach ($required in @(
        'MCACE_ANTICHEAT_FIXTURE_CLASSIFICATION_V1',
        'CONTROLLED_LAB_FIXTURE_METADATA_AND_SERVER_CORRELATION',
        'server_client_correlated',
        'server_confirmed_count',
        'OBSERVE_ONLY_UNTIL_SIGNED_POLICY',
        'third_party_network_access',
        'executable_code_loaded',
        'ReportOnly',
        'dependency-verification=strict',
        'MCACE_TEST_METEOR_JAR',
        'MCACE_TEST_XRAY_PACK')) {
    if (-not $source.Contains($required)) {
        throw "ANTICHEAT_FIXTURE_STATIC_CONTRACT_MISSING: $required"
    }
}

foreach ($forbidden in @(
        'Start-Process',
        'runClient',
        'java -jar',
        'FabricLoader.getInstance',
        'PluginManager.callEvent')) {
    if ($source.Contains($forbidden)) {
        throw "ANTICHEAT_FIXTURE_FORBIDDEN_EXECUTION_TOKEN: $forbidden"
    }
}

$ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$null, [ref]$errors)
$function = $ast.Find({ param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ClassificationJUnitSummary'
}, $true)
if ($null -eq $function -or -not $source.Contains("'--rerun'")) { throw 'JUNIT_EXECUTION_CHECK_MISSING' }
. ([scriptblock]::Create($function.Extent.Text))
$valid = '<testsuite name="com.ellan.mcace.client.observation.AntiCheatFixtureClassificationTest" tests="2" failures="0" errors="0" skipped="0"><testcase name="classifiesMeteorAndXrayFixturesWithoutCallingEitherCheat()"/><testcase name="correlatesClientFixtureWithIndependentServerSignalForBothArtifactTypes()"/></testsuite>'
if ((Get-ClassificationJUnitSummary $valid) -ne 2) { throw 'JUNIT_POSITIVE_FAILED' }
foreach ($invalid in @(
    $valid.Replace('tests="2"', 'tests="3"'),
    $valid.Replace('skipped="0"', 'skipped="2"'),
    $valid.Replace('failures="0"', 'failures="1"'),
    $valid.Replace('errors="0"', 'errors="1"'),
    $valid.Replace('/>', '><skipped/></testcase>'),
    $valid.Replace('correlatesClientFixtureWithIndependentServerSignalForBothArtifactTypes()', 'unexpected()'),
    ('<!DOCTYPE testsuite [<!ENTITY x "bad">]>' + $valid),
    '<invalid')) {
    $rejected = $false
    try { Get-ClassificationJUnitSummary $invalid | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw 'JUNIT_NEGATIVE_ACCEPTED' }
}
Write-Output 'ANTICHEAT_FIXTURE_WRAPPER_STATIC_PASS'
