#Requires -Version 5.1
<#
Paste after reviewing https://github.com/onion3130/remove-microsoft-edge:
    irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/get.ps1 | iex
The loader and removal payload are pinned to the v1.0.1 tag, and the payload is
verified against the SHA-256 below before any of it is executed.

What this check is, precisely:
  * A SHA-256 checksum detects an unexpected or corrupted payload, including a
    truncated download or a tampered mirror.
  * It is NOT a digital signature and NOT proof of authorship. The checksum
    lives in this same repository, so anyone who can change the repository or
    move the tag can change the code and the checksum together. That limit
    cannot be removed without a signing key held separately from the
    repository; this project does not have one, and does not pretend to.
  * For that reason the download host, the scheme, and the exact pinned tag
    path are all checked as well, so only this repository's tagged release can
    be fetched. Any mismatch stops the run. Nothing here is ever skipped
    silently, and there is no switch that turns the check off.

If you want a stronger guarantee than this loader gives you, download
Remove-Edge.ps1 from the v1.0.1 tag, review it, and compute its SHA-256
yourself (see README.md, "Verifying a download before running it").
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

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Pinned release. No parameter can change either value: the parameters below are
# forwarded to the payload, and the payload ignores anything that is not one of
# its own switches.
$PayloadTag = 'v1.0.1'
$PayloadRepository = 'onion3130/remove-microsoft-edge'
$AllowedPayloadHost = 'raw.githubusercontent.com'
$RemoveEdgeUrl = "https://$AllowedPayloadHost/$PayloadRepository/$PayloadTag/Remove-Edge.ps1"
$RemoveEdgeSha256 = '607CDE86B8F532677517EE468F3FA55E18A0B2C0C825A817A6BF6F928E0FE46E'

# These are the only names forwarded to the payload.
$forwardableSwitches = @('VerifyOnly', 'RemoveProfileData', 'NoReinstallBlock',
    'CreateRestorePoint', 'DryRun', 'NoElevate', 'AllowNoOtherBrowser')
$parameters = @{}
foreach ($name in $forwardableSwitches) {
    if ($PSBoundParameters.ContainsKey($name)) { $parameters[$name] = $PSBoundParameters[$name] }
}

function Get-TextSha256 {
    param([string]$Text)
    $normalized = $Text.Replace("`r`n", "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
    }
    finally { $sha.Dispose() }
}

try {
    # TLS 1.2 is not the default on every Windows PowerShell 5.1 installation.
    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch { }

    # A checksum that is not 64 hex characters is treated as "not verified"
    # rather than as "no checksum required".
    if ($RemoveEdgeSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'This loader has no usable payload checksum, so nothing can be verified.'
    }

    $response = Invoke-WebRequest -Uri $RemoveEdgeUrl -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    if ($response.BaseResponse.ResponseUri.Host -ne $AllowedPayloadHost) {
        throw "Refusing a payload served from $($response.BaseResponse.ResponseUri.Host)."
    }

    # Git serves this file with LF endings; normalize so the checksum does not
    # depend on how the bytes were transferred.
    $source = [string]$response.Content
    $source = $source.Replace("`r`n", "`n")
    if (-not $source.StartsWith('#Requires')) {
        throw 'The downloaded file is not the expected script. Nothing was executed.'
    }

    $actual = Get-TextSha256 $source
    if ($actual -ne $RemoveEdgeSha256.ToUpperInvariant()) {
        throw ('Payload checksum mismatch. Nothing was executed. Expected {0}, got {1}.' -f $RemoveEdgeSha256, $actual)
    }

    Write-Host ('Payload verified: SHA-256 {0}' -f $actual) -ForegroundColor DarkGray
    Write-Host ('Source: {0}' -f $RemoveEdgeUrl) -ForegroundColor DarkGray

    # The removal payload is executed only after it has been verified above.
    & ([scriptblock]::Create($source)) @parameters
}
catch {
    # Deliberately does not include the payload text or any stack trace.
    Write-Host ''
    Write-Host ('Stopped: {0}' -f $_.Exception.Message) -ForegroundColor Red
    Write-Host 'Nothing was removed. See README.md for how to check this by hand.' -ForegroundColor Red
    exit 3
}