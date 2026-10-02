#Requires -Version 5.1
<#
Paste after reviewing https://github.com/onion3130/remove-microsoft-edge:
    irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.0/get.ps1 | iex
The loader and removal payload are pinned to v1.0.0. This checksum detects an
unexpected payload; it is not a signature or protection from a compromised repo.
#>
[CmdletBinding()]
param(
    [switch]$VerifyOnly,
    [switch]$RemoveProfileData,
    [switch]$NoReinstallBlock,
    [switch]$CreateRestorePoint,
    [switch]$DryRun,
    [switch]$NoElevate,
    [switch]$AllowNoOtherBrowser
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$RemoveEdgeUrl = 'https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.0/Remove-Edge.ps1'
$RemoveEdgeSha256 = 'D74FABF57AE7FD77B1576201E7952D6DE827ECC093BD0E18EEEB0ED84B650B6A'
$parameters = @{}
foreach ($name in @('VerifyOnly', 'RemoveProfileData', 'NoReinstallBlock', 'CreateRestorePoint', 'DryRun', 'NoElevate', 'AllowNoOtherBrowser')) {
    if ($PSBoundParameters.ContainsKey($name)) { $parameters[$name] = $PSBoundParameters[$name] }
}

try {
    $source = ([string](Invoke-RestMethod -Uri $RemoveEdgeUrl -UseBasicParsing -ErrorAction Stop)).Replace("`r`n", "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $actual = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($source))).Replace('-', '')
    }
    finally { $sha.Dispose() }
    if ($actual -ne $RemoveEdgeSha256) { throw 'Downloaded script hash mismatch. Nothing was executed.' }
    & ([scriptblock]::Create($source)) @parameters
}
catch {
    Write-Host ('Download/execution failed: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit 3
}
