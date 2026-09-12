[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$tokens = $null; $parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $PSScriptRoot 'publish-server-version-matrix-evidence.ps1'),
    [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'PUBLISHER_PARSE_FAILED' }
$definition = @($ast.FindAll({ param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -ceq 'Assert-NoSecretFieldsOrAbsoluteStrings'
}, $true))
if ($definition.Count -ne 1) { throw 'PRIVACY_FUNCTION_NOT_UNIQUE' }
# Load only the production validator, never the publisher's executable body.
Invoke-Expression $definition[0].Extent.Text
function Reject([scriptblock]$Action, [string]$Expected) {
    $caught = $false
    try { & $Action } catch {
        if (-not $_.Exception.Message.StartsWith($Expected, [StringComparison]::Ordinal)) { throw }
        $caught = $true
    }
    if (-not $caught) { throw "EXPECTED_REJECTION|$Expected" }
}
$bytes = New-Object byte[] 256
$bytes[0] = 255
$encoded = [Convert]::ToBase64String($bytes)
if (-not $encoded.StartsWith('/')) { throw 'FIXTURE_NOT_SLASH_PREFIXED' }
foreach ($document in @(@{modulus_base64=$encoded}, [pscustomobject]@{modulus_base64=$encoded})) {
    Assert-NoSecretFieldsOrAbsoluteStrings $document 'supervisor-trust-root'
}
Assert-NoSecretFieldsOrAbsoluteStrings @{signature_base64=$encoded} 'supervisor-receipt'
Assert-NoSecretFieldsOrAbsoluteStrings @{exponent_base64='AQAB'} 'supervisor-trust-root'
Reject { Assert-NoSecretFieldsOrAbsoluteStrings @{path='/tmp/report.json'} 'report' } 'MCACE_MATRIX_PUBLISH_ABSOLUTE_PATH_REJECTED'
Reject { Assert-NoSecretFieldsOrAbsoluteStrings @{modulus_base64=$encoded} 'report' } 'MCACE_MATRIX_PUBLISH_ABSOLUTE_PATH_REJECTED'
Reject { Assert-NoSecretFieldsOrAbsoluteStrings @{nested=@{modulus_base64=$encoded}} 'supervisor-trust-root' } 'MCACE_MATRIX_PUBLISH_ABSOLUTE_PATH_REJECTED'
Reject { Assert-NoSecretFieldsOrAbsoluteStrings @{modulus_base64='/tmp/report.json'} 'supervisor-trust-root' } 'MCACE_MATRIX_PUBLISH_PUBLIC_BASE64_INVALID'
Reject { Assert-NoSecretFieldsOrAbsoluteStrings @{modulus_base64=" $encoded"} 'supervisor-trust-root' } 'MCACE_MATRIX_PUBLISH_PUBLIC_BASE64_INVALID'
Reject { Assert-NoSecretFieldsOrAbsoluteStrings @{signature_base64='/w=='} 'supervisor-receipt' } 'MCACE_MATRIX_PUBLISH_PUBLIC_BASE64_INVALID'
Reject { Assert-NoSecretFieldsOrAbsoluteStrings @{private_key='secret'} 'supervisor-trust-root' } 'MCACE_MATRIX_PUBLISH_SECRET_FIELD_REJECTED'
Write-Output 'MATRIX_PUBLIC_BASE64_PRIVACY_PASS|positive=4|negative=7|runtime=false'
