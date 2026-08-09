[CmdletBinding()]
param(
    [string]$CatalogPath = (Join-Path $PSScriptRoot '..\examples\disposition-catalog.textproto'),
    [switch]$Live,
    [ValidateRange(1, 4096)] [int]$MaxEntries = 512,
    [ValidateRange(1024, 1048576)] [int]$MaxCatalogBytes = 1048576,
    [ValidateRange(1024, 1048576)] [int]$MaxManifestBytes = 262144,
    [ValidateRange(1, 60)] [int]$TimeoutSeconds = 10,
    [string]$ReportPath,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# An operator review aid only. It never writes the catalog, enables a rule,
# downloads a jar/zip/executable, executes remote content, or contacts a player.
$script:TokenLimit = 50000
$script:SourceUriLimit = 2048
$script:RevisionLimit = 128
$script:ManifestPathLimit = 512
$script:FabricIdPattern = '^[a-z][a-z0-9_-]{1,63}$'
$script:RevisionPattern = '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'
$script:UserAgent = 'MCAce-catalog-provenance-review/1.0 (+https://github.com/EllanServer/MCAce)'

function Get-Utf8File([string]$Path, [int]$MaximumBytes) {
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Length -gt $MaximumBytes) { throw 'catalog_file_size_invalid' }
    # Do not use ReadAllBytes after a size check: a concurrent replacement could
    # otherwise turn a bounded validation into an unbounded allocation.
    $stream = [IO.FileStream]::new($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($stream.Length -gt $MaximumBytes) { throw 'catalog_file_size_invalid' }
        $memory = [IO.MemoryStream]::new()
        try {
            $buffer = New-Object byte[] 8192
            while ($true) {
                $count = $stream.Read($buffer, 0, $buffer.Length)
                if ($count -le 0) { break }
                if ($memory.Length + $count -gt $MaximumBytes) { throw 'catalog_file_size_invalid' }
                $memory.Write($buffer, 0, $count)
            }
            try { return [Text.UTF8Encoding]::new($false, $true).GetString($memory.ToArray()) }
            catch { throw 'catalog_utf8_invalid' }
        } finally { $memory.Dispose() }
    } finally { $stream.Dispose() }
}

function Tokenize-TextProto([string]$Text) {
    $tokens = [System.Collections.Generic.List[object]]::new()
    $i = 0
    while ($i -lt $Text.Length) {
        $c = $Text[$i]
        if ([char]::IsWhiteSpace($c)) { $i++; continue }
        if ($c -eq '#') {
            while ($i -lt $Text.Length -and $Text[$i] -ne "`n") { $i++ }
            continue
        }
        if ($c -eq '{' -or $c -eq '}' -or $c -eq ':') {
            $tokens.Add([pscustomobject]@{ kind = [string]$c; value = [string]$c }); $i++; continue
        }
        if ($c -eq '"') {
            $i++; $builder = [System.Text.StringBuilder]::new(); $closed = $false
            while ($i -lt $Text.Length) {
                $current = $Text[$i]
                if ($current -eq '"') { $i++; $closed = $true; break }
                if ($current -eq '\\') {
                    $i++; if ($i -ge $Text.Length) { throw 'catalog_string_escape_invalid' }
                    $escaped = $Text[$i]
                    switch ($escaped) {
                        '"' { [void]$builder.Append('"') }
                        '\\' { [void]$builder.Append('\\') }
                        'n' { [void]$builder.Append("`n") }
                        'r' { [void]$builder.Append("`r") }
                        't' { [void]$builder.Append("`t") }
                        default { throw 'catalog_string_escape_invalid' }
                    }
                    $i++; continue
                }
                if ([char]::IsControl($current)) { throw 'catalog_string_control_invalid' }
                [void]$builder.Append($current); $i++
            }
            if (-not $closed) { throw 'catalog_string_unterminated' }
            $tokens.Add([pscustomobject]@{ kind = 'string'; value = $builder.ToString() })
        } elseif ($c -match '[A-Za-z0-9_.-]') {
            $start = $i
            while ($i -lt $Text.Length -and $Text[$i] -match '[A-Za-z0-9_.-]') { $i++ }
            $tokens.Add([pscustomobject]@{ kind = 'atom'; value = $Text.Substring($start, $i - $start) })
        } else { throw 'catalog_token_invalid' }
        if ($tokens.Count -gt $script:TokenLimit) { throw 'catalog_token_limit_exceeded' }
    }
    return $tokens.ToArray()
}

function Get-NextToken([object]$State, [string]$Code) {
    if ($State.index -ge $State.tokens.Count) { throw $Code }
    $token = $State.tokens[$State.index]; $State.index++; return $token
}
function Expect-Token([object]$State, [string]$Kind, [string]$Code) {
    $token = Get-NextToken $State $Code
    if ($token.kind -ne $Kind) { throw $Code }; return $token
}
function Read-FieldValue([object]$State) {
    if ($State.index -lt $State.tokens.Count -and $State.tokens[$State.index].kind -eq ':') { $State.index++ }
    $token = Get-NextToken $State 'catalog_scalar_expected'
    if ($token.kind -ne 'string' -and $token.kind -ne 'atom') { throw 'catalog_scalar_expected' }
    return $token.value
}
function Skip-FieldValue([object]$State) {
    if ($State.index -ge $State.tokens.Count) { throw 'catalog_value_missing' }
    if ($State.tokens[$State.index].kind -eq ':') {
        $State.index++; [void](Get-NextToken $State 'catalog_scalar_expected'); return
    }
    if ($State.tokens[$State.index].kind -ne '{') { throw 'catalog_value_expected' }
    $depth = 0
    do {
        $token = Get-NextToken $State 'catalog_block_unterminated'
        if ($token.kind -eq '{') { $depth++ } elseif ($token.kind -eq '}') { $depth-- }
    } while ($depth -gt 0)
}
function Set-UniqueField([hashtable]$Fields, [string]$Name, [string]$Value) {
    if ($Fields.ContainsKey($Name)) { throw 'catalog_duplicate_field' }; [void]$Fields.Add($Name, $Value)
}
function Parse-Selector([object]$State) {
    [void](Expect-Token $State '{' 'catalog_selector_block_expected'); $fields = @{}
    while ($true) {
        $token = Get-NextToken $State 'catalog_selector_unterminated'
        if ($token.kind -eq '}') { break }; if ($token.kind -ne 'atom') { throw 'catalog_selector_field_invalid' }
        switch ($token.value) {
            'artifact_type' { Set-UniqueField $fields 'artifact_type' (Read-FieldValue $State) }
            'match_type' { Set-UniqueField $fields 'match_type' (Read-FieldValue $State) }
            'artifact_id' { Set-UniqueField $fields 'artifact_id' (Read-FieldValue $State) }
            default { Skip-FieldValue $State }
        }
    }
    return $fields
}
function Parse-CatalogEntry([object]$State) {
    [void](Expect-Token $State '{' 'catalog_entry_block_expected'); $fields = @{}
    while ($true) {
        $token = Get-NextToken $State 'catalog_entry_unterminated'
        if ($token.kind -eq '}') { break }; if ($token.kind -ne 'atom') { throw 'catalog_entry_field_invalid' }
        switch ($token.value) {
            'selector' {
                if ($fields.ContainsKey('selector')) { throw 'catalog_duplicate_field' }
                $selector = Parse-Selector $State
                $null = ($fields['selector'] = $selector)
            }
            'entry_id' { Set-UniqueField $fields 'entry_id' (Read-FieldValue $State) }
            'source_uri' { Set-UniqueField $fields 'source_uri' (Read-FieldValue $State) }
            'source_revision' { Set-UniqueField $fields 'source_revision' (Read-FieldValue $State) }
            'source_manifest_path' { Set-UniqueField $fields 'source_manifest_path' (Read-FieldValue $State) }
            'source_retrieved_at_epoch_ms' { Set-UniqueField $fields 'source_retrieved_at_epoch_ms' (Read-FieldValue $State) }
            default { Skip-FieldValue $State }
        }
    }
    return $fields
}
function Parse-CatalogEntries([string]$Text, [int]$Limit) {
    $state = [pscustomobject]@{ tokens = @(Tokenize-TextProto $Text); index = 0 }
    $entries = [System.Collections.Generic.List[hashtable]]::new()
    while ($state.index -lt $state.tokens.Count) {
        $token = Get-NextToken $state 'catalog_top_level_invalid'
        if ($token.kind -ne 'atom') { throw 'catalog_top_level_invalid' }
        if ($token.value -eq 'catalog_entries') {
            $entries.Add((Parse-CatalogEntry $state)); if ($entries.Count -gt $Limit) { throw 'catalog_entry_limit_exceeded' }
        } else { Skip-FieldValue $state }
    }
    if ($entries.Count -eq 0) { throw 'catalog_entries_missing' }; return $entries.ToArray()
}

function Get-SafeSourceUri([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt $script:SourceUriLimit) { throw 'source_uri_invalid' }
    try { $uri = [Uri]$Value } catch { throw 'source_uri_invalid' }
    if (-not $uri.IsAbsoluteUri -or $uri.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($uri.Host) -or
            -not [string]::IsNullOrEmpty($uri.UserInfo) -or -not [string]::IsNullOrEmpty($uri.Fragment) -or
            -not [string]::IsNullOrEmpty($uri.Query)) { throw 'source_uri_invalid' }
    # One non-executable public manifest origin avoids arbitrary-host/SSRF behaviour.
    if ($uri.Host -ne 'raw.githubusercontent.com' -or $uri.Port -ne 443) { throw 'source_uri_host_not_allowed' }
    return $uri
}
function Assert-SafeManifestPath([string]$Value) {
    if ([string]::IsNullOrWhiteSpace($Value) -or $Value.Length -gt $script:ManifestPathLimit -or $Value.StartsWith('/') -or
            -not $Value.EndsWith('fabric.mod.json', [StringComparison]::Ordinal)) { throw 'source_manifest_path_invalid' }
    foreach ($segment in $Value.Split('/')) {
        if ($segment -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw 'source_manifest_path_invalid' }
    }
}
function Convert-ToPositiveInt64([string]$Value, [string]$Code) {
    [long]$number = 0
    if (-not [long]::TryParse($Value, [Globalization.NumberStyles]::None, [Globalization.CultureInfo]::InvariantCulture, [ref]$number) -or $number -le 0) { throw $Code }
    return $number
}
function Test-PinnedGithubPath([Uri]$Uri, [string]$Revision, [string]$ManifestPath) {
    if ($Revision -notmatch $script:RevisionPattern) { throw 'source_revision_invalid' }; Assert-SafeManifestPath $ManifestPath
    $segments = $Uri.AbsolutePath.Trim('/').Split('/')
    if ($segments.Count -lt 4 -or [string]::IsNullOrWhiteSpace($segments[0]) -or [string]::IsNullOrWhiteSpace($segments[1]) -or
            $segments[2] -cne $Revision) { throw 'source_uri_not_pinned_to_revision' }
    $actualPath = [Uri]::UnescapeDataString(($segments[3..($segments.Count - 1)] -join '/'))
    if ($actualPath -cne $ManifestPath) { throw 'source_uri_not_pinned_to_manifest_path' }
}
function New-EntryReview([hashtable]$Entry) {
    foreach ($field in @('entry_id', 'source_uri', 'source_revision', 'source_manifest_path', 'source_retrieved_at_epoch_ms', 'selector')) {
        if (-not $Entry.ContainsKey($field)) { throw 'catalog_provenance_field_missing' }
    }
    $selector = $Entry.selector
    if ($selector -isnot [hashtable] -or $selector.artifact_type -cne 'DETECTION_ARTIFACT_MOD' -or $selector.match_type -cne 'DETECTION_MATCH_MOD_ID_VERSION' -or
            [string]::IsNullOrWhiteSpace($selector.artifact_id) -or $selector.artifact_id -notmatch $script:FabricIdPattern) { throw 'catalog_selector_not_fabric_mod_id' }
    $uri = Get-SafeSourceUri $Entry.source_uri
    if ($Entry.source_revision.Length -gt $script:RevisionLimit) { throw 'source_revision_invalid' }
    Test-PinnedGithubPath $uri $Entry.source_revision $Entry.source_manifest_path
    $retrievedAt = Convert-ToPositiveInt64 $Entry.source_retrieved_at_epoch_ms 'source_retrieved_at_invalid'
    return [ordered]@{
        entry_id = $Entry.entry_id; selector_artifact_id = $selector.artifact_id
        source = [ordered]@{ uri = ('https://{0}{1}' -f $uri.Host, $uri.AbsolutePath); revision = $Entry.source_revision; manifest_path = $Entry.source_manifest_path; retrieved_at_epoch_ms = $retrievedAt }
        status = 'offline_valid'; manifest_mod_id = $null; reason = $null
    }
}

function Get-BoundedManifest([Uri]$Uri, [int]$MaximumBytes, [int]$RequestTimeoutSeconds) {
    $handler = [System.Net.Http.HttpClientHandler]::new(); $handler.AllowAutoRedirect = $false; $handler.UseProxy = $false
    $client = [System.Net.Http.HttpClient]::new($handler); $client.Timeout = [TimeSpan]::FromSeconds($RequestTimeoutSeconds)
    try {
        $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Get, $Uri)
        [void]$request.Headers.TryAddWithoutValidation('User-Agent', $script:UserAgent)
        $response = $client.SendAsync($request, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()
        try {
            if ([int]$response.StatusCode -ne 200) { throw 'manifest_http_status_invalid' }
            if ($null -ne $response.Content.Headers.ContentLength -and $response.Content.Headers.ContentLength -gt $MaximumBytes) { throw 'manifest_content_length_exceeded' }
            $mediaType = $response.Content.Headers.ContentType.MediaType
            if ([string]::IsNullOrWhiteSpace($mediaType) -or (-not $mediaType.StartsWith('text/', [StringComparison]::OrdinalIgnoreCase) -and $mediaType -notmatch '^application/(json|manifest\+json)$')) { throw 'manifest_content_type_invalid' }
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            try {
                $buffer = New-Object byte[] 8192; $memory = [System.IO.MemoryStream]::new()
                try {
                    while ($true) {
                        $count = $stream.Read($buffer, 0, $buffer.Length); if ($count -le 0) { break }
                        if ($memory.Length + $count -gt $MaximumBytes) { throw 'manifest_size_exceeded' }; $memory.Write($buffer, 0, $count)
                    }
                    try { return [System.Text.UTF8Encoding]::new($false, $true).GetString($memory.ToArray()) } catch { throw 'manifest_utf8_invalid' }
                } finally { $memory.Dispose() }
            } finally { $stream.Dispose() }
        } finally { $response.Dispose() }
    } catch {
        $code = [string]$_.Exception.Message
        if ($code -match '^(manifest_|source_)') { throw $code }; throw 'manifest_network_request_failed'
    } finally { $client.Dispose(); $handler.Dispose() }
}
function Get-FabricManifestId([string]$Manifest) {
    # Some checked-in text manifests include a UTF-8 BOM. It is encoding metadata,
    # not manifest content, and must not turn an otherwise valid pinned manifest
    # into an unverifiable one.
    $normalized = $Manifest.TrimStart([char]0xFEFF)
    try {
        $json = $normalized | ConvertFrom-Json -ErrorAction Stop
        if ($null -eq $json -or $json.PSObject.Properties.Name -notcontains 'id' -or $json.id -isnot [string] -or $json.id -notmatch $script:FabricIdPattern) { throw 'manifest_mod_id_invalid' }
        return [string]$json.id
    } catch {
        # Some upstream repositories commit a Fabric manifest template containing
        # build placeholders which is not independently parseable JSON. Retain a
        # deliberately narrow fallback: exactly one quoted `id` field with a
        # valid Fabric ID. This does not interpret the template or execute it.
        $matches = [regex]::Matches($normalized, '"id"\s*:\s*"(?<id>[a-z][a-z0-9_-]{1,63})"')
        if ($matches.Count -ne 1) { throw 'manifest_json_invalid' }
        return $matches[0].Groups['id'].Value
    }
}
function Invoke-CatalogReview([string]$Text) {
    $reviewed = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in @(Parse-CatalogEntries $Text $MaxEntries)) {
        $review = $null
        try {
            $review = New-EntryReview $entry
            if ($Live) {
                $manifest = Get-BoundedManifest ([Uri]$review.source.uri) $MaxManifestBytes $TimeoutSeconds
                $manifestId = Get-FabricManifestId $manifest; $review.manifest_mod_id = $manifestId
                if ($manifestId -cne $review.selector_artifact_id) { throw 'manifest_mod_id_mismatch' }; $review.status = 'live_verified'
            }
        } catch {
            if ($null -eq $review) {
                $review = [ordered]@{
                    entry_id = if ($entry.ContainsKey('entry_id')) { $entry.entry_id } else { $null }
                    selector_artifact_id = if ($entry.ContainsKey('selector') -and $entry.selector.ContainsKey('artifact_id')) { $entry.selector.artifact_id } else { $null }
                    source = $null; status = 'failed'; manifest_mod_id = $null; reason = [string]$_.Exception.Message
                }
            } else {
                $review['status'] = 'failed'
                $review['reason'] = [string]$_.Exception.Message
            }
        }
        $reviewed.Add([pscustomobject]$review)
    }
    return $reviewed.ToArray()
}
function Invoke-SelfTest {
    $positive = @'
catalog_entries {
 entry_id: "positive"
 selector { artifact_type: DETECTION_ARTIFACT_MOD match_type: DETECTION_MATCH_MOD_ID_VERSION artifact_id: "examplemod" }
 source_uri: "https://raw.githubusercontent.com/example/project/0123456789abcdef/src/main/resources/fabric.mod.json"
 source_revision: "0123456789abcdef"
 source_manifest_path: "src/main/resources/fabric.mod.json"
 source_retrieved_at_epoch_ms: 1
}
'@
    $query = $positive.Replace('fabric.mod.json"', 'fabric.mod.json?token=not-output"')
    $badPath = $positive.Replace('src/main/resources/fabric.mod.json"', 'src/../fabric.mod.json"')
    $results = [System.Collections.Generic.List[object]]::new()
    foreach ($case in @(@{ name = 'valid_pinned_entry'; expected = $true; text = $positive }, @{ name = 'query_rejected'; expected = $false; text = $query }, @{ name = 'unsafe_path_rejected'; expected = $false; text = $badPath })) {
        $ok = $true; $code = $null
        try { $entry = @(Parse-CatalogEntries $case.text 4)[0]; [void](New-EntryReview $entry) } catch { $ok = $false; $code = [string]$_.Exception.Message }
        $results.Add([pscustomobject]@{ name = $case.name; passed = ($ok -eq $case.expected); code = $code })
    }
    $manifestOk = (Get-FabricManifestId '{"schemaVersion":1,"id":"examplemod"}') -ceq 'examplemod'
    $bomManifestOk = (Get-FabricManifestId ([string][char]0xFEFF + '{"schemaVersion":1,"id":"examplemod"}')) -ceq 'examplemod'
    $templateIdOk = (Get-FabricManifestId "{`n  `"id`": `"examplemod`",`n  `"contributors`": `$contributors`n}") -ceq 'examplemod'
    $mismatchDetected = ((Get-FabricManifestId '{"schemaVersion":1,"id":"differentmod"}') -cne 'examplemod')
    $results.Add([pscustomobject]@{ name = 'manifest_id_parse'; passed = $manifestOk })
    $results.Add([pscustomobject]@{ name = 'manifest_utf8_bom'; passed = $bomManifestOk })
    $results.Add([pscustomobject]@{ name = 'manifest_template_id'; passed = $templateIdOk })
    $results.Add([pscustomobject]@{ name = 'manifest_id_mismatch'; passed = $mismatchDetected })
    return [ordered]@{ schema = 1; tool = 'mcace-catalog-provenance-review'; mode = 'self_test'; status = if (@($results | Where-Object { -not $_.passed }).Count -eq 0) { 'passed' } else { 'failed' }; tests = $results }
}
function Write-Report([object]$Value) {
    $json = $Value | ConvertTo-Json -Depth 10 -Compress
    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
        $parent = Split-Path -Parent $ReportPath
        if ([string]::IsNullOrWhiteSpace($parent) -or -not (Test-Path -LiteralPath $parent)) { throw 'report_parent_missing' }
        [System.IO.File]::WriteAllText($ReportPath, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
    }
    [Console]::Out.WriteLine($json)
}

$exitCode = 0
try {
    if ($SelfTest) { $report = Invoke-SelfTest }
    else {
        $catalog = Get-Utf8File $CatalogPath $MaxCatalogBytes; $entries = @(Invoke-CatalogReview $catalog); $failed = @($entries | Where-Object { $_.status -eq 'failed' })
        $report = [ordered]@{ schema = 1; tool = 'mcace-catalog-provenance-review'; mode = if ($Live) { 'live' } else { 'offline' }; network_requested = [bool]$Live; catalog = [System.IO.Path]::GetFileName($CatalogPath); status = if ($failed.Count -eq 0) { if ($Live) { 'live_verified' } else { 'offline_valid' } } else { 'failed' }; entries = $entries }
    }
    if ($report.status -eq 'failed') { $exitCode = 1 }
} catch {
    $inputError = [string]$_.Exception.Message
    if ($inputError -notmatch '^(catalog_|source_|manifest_)') { $inputError = 'catalog_review_input_invalid' }
    $report = [ordered]@{ schema = 1; tool = 'mcace-catalog-provenance-review'; mode = if ($SelfTest) { 'self_test' } elseif ($Live) { 'live' } else { 'offline' }; network_requested = [bool]$Live; status = 'failed'; error = 'catalog_review_input_invalid' }
    $report.error = $inputError
    $exitCode = 1
}
try { Write-Report $report } catch { [Console]::Error.WriteLine('catalog_review_report_write_failed'); $exitCode = 1 }
exit $exitCode
