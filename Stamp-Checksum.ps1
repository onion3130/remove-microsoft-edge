#Requires -Version 5.1
<#
.SYNOPSIS
    Derives the Remove-Edge.ps1 checksum and stamps it into get.ps1.

.DESCRIPTION
    The checksum is SHA-256 over the payload text with CRLF normalised to LF,
    encoded as UTF-8. This is exactly what get.ps1 computes on a downloaded
    file, so a value produced here and a value checked there cannot drift.

    Use -Check to verify without writing anything. The test suite runs it, so a
    release cannot be published with a checksum that does not match the file.

.EXAMPLE
    .\Stamp-Checksum.ps1 -Check
    Reports whether get.ps1 already carries the correct checksum.

.EXAMPLE
    .\Stamp-Checksum.ps1
    Rewrites the checksum in get.ps1.
#>
[CmdletBinding()]
param([switch]$Check)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = Split-Path -Parent $PSCommandPath
$payloadPath = Join-Path $repo 'Remove-Edge.ps1'
$loaderPath = Join-Path $repo 'get.ps1'

foreach ($path in @($payloadPath, $loaderPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing file: $path" }
}

$payload = [IO.File]::ReadAllText($payloadPath)
$normalized = $payload.Replace("`r`n", "`n")
$sha = [Security.Cryptography.SHA256]::Create()
try {
    $expected = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
}
finally { $sha.Dispose() }

$loader = [IO.File]::ReadAllText($loaderPath)
$match = [regex]::Match($loader, '\$RemoveEdgeSha256 = ''([A-Fa-f0-9]{64})''')
if (-not $match.Success) { throw "No payload checksum found in $loaderPath" }
$current = $match.Groups[1].Value.ToUpperInvariant()

Write-Host ('payload : {0}' -f $payloadPath)
Write-Host ('checksum : {0}' -f $expected)
Write-Host ('stamped  : {0}' -f $current)

if ($current -eq $expected) {
    Write-Host 'OK: get.ps1 already carries the correct checksum.' -ForegroundColor Green
    exit 0
}

if ($Check) {
    Write-Host 'MISMATCH: get.ps1 does not carry the current checksum.' -ForegroundColor Red
    exit 1
}

$updated = [regex]::Replace($loader, '\$RemoveEdgeSha256 = ''[A-Fa-f0-9]{64}''',
    ("`$RemoveEdgeSha256 = '" + $expected + "'"))
[IO.File]::WriteAllText($loaderPath, $updated)
Write-Host 'Updated get.ps1.' -ForegroundColor Yellow
Write-Host 'Re-run .\tests\Test-RemoveEdge.ps1 before tagging a release.' -ForegroundColor Yellow
exit 0