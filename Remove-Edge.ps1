#Requires -Version 5.1
<#
.SYNOPSIS
    Attempts to uninstall system-level Microsoft Edge and discourage reinstall.

.DESCRIPTION
    Windows may not offer an uninstall option for the bundled Edge browser,
    depending on the region and Windows build. This tool attempts Microsoft's
    bundled uninstaller, then direct cleanup. This is not a Microsoft-supported
    removal method on every Windows installation.

    This script:
      * stops Edge and Edge Update,
      * runs Microsoft's own Edge uninstaller (setup.exe --uninstall),
      * verifies from the file system and registry that Edge is really gone,
      * falls back to direct removal if the uninstaller leaves anything behind,
      * sets a per-product Edge Update install policy (not a permanent guarantee).

    It does NOT spoof your device region, patch Windows system files, disable
    UCPD, run a third-party "debloater", or make unrelated changes.

    WebView2 Runtime is deliberately left installed and untouched. Many
    applications (and parts of Windows itself) render their UI with it, so
    removing it breaks software. Only the Edge browser is removed. If WebView2
    was present before the run and is gone afterwards, that is reported as an
    error instead of a successful removal.

    Safety model: every deletion target is constrained to an exact Edge-specific
    path and re-checked immediately before use. Process environment variables are
    never trusted to decide where anything is deleted, because they are inherited
    across the UAC elevation boundary. Validation that cannot be completed fails
    closed.

.PARAMETER VerifyOnly
    Change nothing. Report whether Edge is installed and whether the reinstall
    block is in place. Useful for "did Windows put Edge back?".

.PARAMETER RemoveProfileData
    Also delete the leftover Edge browser profile in
    %LOCALAPPDATA%\Microsoft\Edge - history, cookies, cache, and any bookmarks
    or passwords that were stored only locally. This cannot be undone.

.PARAMETER NoReinstallBlock
    Skip creating the per-product Edge Update install policy. The policy may
    not be honored on every system and cannot prevent Windows reprovisioning.

.PARAMETER CreateRestorePoint
    Try to create a System Restore point first. Requires System Protection to
    be enabled; a failure here is reported prominently but does not stop the
    script. A restore point is not a backup and does not guarantee recovery.

.PARAMETER DryRun
    Print what would be done and change nothing.

.PARAMETER NoElevate
    Do not ask Windows for administrator rights. Use this in unattended or
    scheduled runs, where a UAC prompt would just hang.

.PARAMETER AllowNoOtherBrowser
    Explicitly bypass the alternative-browser check, for example when using
    a portable browser that this tool cannot detect.

.PARAMETER ExpectedPayloadSha256
    Internal. The SHA-256 that an elevated relaunch of this exact file must
    match, in the same LF-normalized form the loader uses. When supplied, the
    script refuses to do anything at all unless its own bytes match, so an
    elevated run can only ever execute the file that was verified.

.EXAMPLE
    .\Remove-Edge.ps1
    Attempts to remove Edge and sets the Edge Update install policy.

.EXAMPLE
    .\Remove-Edge.ps1 -VerifyOnly
    Reports the current state and changes nothing.

.EXAMPLE
    .\Remove-Edge.ps1 -RemoveProfileData -CreateRestorePoint
    Creates a restore point, removes Edge, and removes the leftover profile.

.EXAMPLE
    # no file needed - review the repo first, then accept the UAC prompt
    irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/get.ps1 | iex

.NOTES
    The script asks for administrator rights itself, unless -NoElevate is used.
    Exit codes: 0 = Edge is not installed / was removed successfully
                1 = Edge is still present after the attempt
                2 = not elevated, prerequisites missing, or environment refused
                3 = operation or verification error
                4 = re-launched itself elevated; the work continues in the new
                    window, which stays open with the report
#>
[CmdletBinding()]
param(
    [switch]$VerifyOnly,
    [switch]$RemoveProfileData,
    [switch]$NoReinstallBlock,
    [switch]$CreateRestorePoint,
    [switch]$DryRun,
    [switch]$NoElevate,
    [switch]$AllowNoOtherBrowser,
    [string]$ExpectedPayloadSha256 = ''
)

# Save script-level parameters before entering functions (which have their own
# $PSBoundParameters). Only supported switches are forwarded to elevation.
$ScriptSwitches = @{}
foreach ($name in @('VerifyOnly', 'RemoveProfileData', 'NoReinstallBlock', 'CreateRestorePoint', 'DryRun', 'AllowNoOtherBrowser')) {
    if ($PSBoundParameters.ContainsKey($name) -and $PSBoundParameters[$name].IsPresent) {
        $ScriptSwitches[$name] = $true
    }
}
$ScriptPath = $PSCommandPath

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# Microsoft Edge (stable) as Edge Update knows it.
# Product names verified against EdgeUpdate\Clients on the test machine.
# WebView2 has a separate product ID and is not a removal target.
$EdgeProductGuid = '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
$WebView2ProductGuid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
$EdgeAppxName = 'Microsoft.MicrosoftEdge.Stable'

# The only remote location this payload will accept a self-relaunch from. It is
# pinned to a numeric tag of this repository on GitHub's raw host, so a
# rewritten branch, a mirror, or plain HTTP cannot be substituted for it.
$AllowedPayloadHost = 'raw.githubusercontent.com'
$AllowedPayloadPathPattern = '^/onion3130/remove-microsoft-edge/v[0-9][^/]*/Remove-Edge\.ps1$'

# When the script is piped straight into PowerShell (`irm <url> | iex`) it never
# touches disk, so it needs to know its own URL to be able to re-launch itself
# elevated. The published one-liner sets this variable before the pipe; because
# Invoke-Expression runs in the caller's scope, the value is visible here.
if (-not (Test-Path variable:RemoveEdgeUrl)) { $RemoveEdgeUrl = '' }
if (-not (Test-Path variable:RemoveEdgeSha256)) { $RemoveEdgeSha256 = '' }
$HadOperationError = $false

$ProcessNames = @('msedge', 'msedgeupdate', 'MicrosoftEdgeUpdate')
$ExitOk = 0
$ExitStillPresent = 1
$ExitNotElevated = 2
$ExitError = 3
$ExitRelaunched = 4

# Errors fail closed unless explicitly caught. Optional restore-point failure
# is only a warning; failed requested cleanup/policy operations report code 3.
trap {
    Write-Host ''
    Write-Host ('Unexpected error: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit $ExitError
}

# ---------------------------------------------------------------- helpers ---

function Write-Step {
    param([string]$Text)
    Write-Host ''
    Write-Host ("== {0}" -f $Text) -ForegroundColor Cyan
}

function Write-Info {
    param([string]$Text)
    Write-Host ("   {0}" -f $Text)
}

function Write-Warn {
    param([string]$Text)
    Write-Host ("   ! {0}" -f $Text) -ForegroundColor Yellow
}

function Test-Elevated {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# --------------------------------------------------- environment integrity ---

<#
    Process environment variables can be rewritten by any user before this
    script starts, and they are inherited by the elevated relaunch. A variable
    such as LOCALAPPDATA or ProgramFiles therefore decides where an elevated
    script deletes things. Every root that influences a deletion is compared
    here against the value Windows reports from the registry, and a mismatch
    refuses the destructive run.
#>
function Get-EnvironmentProblems {
    $problems = @()
    $pairs = @(
        @{ Name = 'ProgramFiles';      Value = $env:ProgramFiles;        Expected = [Environment]::GetFolderPath('ProgramFiles') },
        @{ Name = 'ProgramFiles(x86)'; Value = ${env:ProgramFiles(x86)}; Expected = [Environment]::GetFolderPath('ProgramFilesX86') },
        @{ Name = 'LOCALAPPDATA';      Value = $env:LOCALAPPDATA;        Expected = [Environment]::GetFolderPath('LocalApplicationData') },
        @{ Name = 'APPDATA';           Value = $env:APPDATA;             Expected = [Environment]::GetFolderPath('ApplicationData') },
        @{ Name = 'ProgramData';       Value = $env:ProgramData;         Expected = [Environment]::GetFolderPath('CommonApplicationData') }
    )
    foreach ($pair in $pairs) {
        if (-not $pair.Value) { continue }
        if ($pair.Value.TrimEnd('\') -ne $pair.Expected.TrimEnd('\')) {
            $problems += ('{0} is "{1}" but Windows reports "{2}"' -f $pair.Name, $pair.Value, $pair.Expected)
        }
    }

    if ($env:ProgramW6432 -and
        $env:ProgramW6432.TrimEnd('\') -ne [Environment]::GetFolderPath('ProgramFiles').TrimEnd('\')) {
        $problems += ('ProgramW6432 is "{0}" but Windows reports "{1}"' -f
            $env:ProgramW6432, [Environment]::GetFolderPath('ProgramFiles'))
    }
    if ("$env:SystemDrive" -notmatch '^[A-Za-z]:$') {
        $problems += ('SystemDrive is "{0}", which is not a drive root' -f $env:SystemDrive)
    }
    if (-not $env:SystemRoot -or $env:SystemRoot -notmatch '^[A-Za-z]:\\Windows$' -or
        -not (Test-Path -LiteralPath $env:SystemRoot -PathType Container)) {
        $problems += ('SystemRoot is "{0}", which is not a Windows directory' -f $env:SystemRoot)
    }
    return @($problems)
}

# Derived from the registry-reported location, never from $env:PUBLIC, which a
# caller can repoint at any folder they like.
function Get-TrustedPublicRoot {
    if ("$env:SystemDrive" -notmatch '^[A-Za-z]:$') { return '' }
    return ($env:SystemDrive + '\Users\Public')
}

# Never $env:TEMP: the elevated relaunch writes the verified payload to a
# temporary directory, so a caller-controlled TEMP would be a place to stage
# code for an administrator run.
function Get-TrustedTempRoot {
    $local = [Environment]::GetFolderPath('LocalApplicationData')
    $candidate = Join-Path $local 'Temp'
    if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Container)) { return $candidate }
    if ([Environment]::GetFolderPath('Windows')) { return (Join-Path ([Environment]::GetFolderPath('Windows')) 'Temp') }
    return ''
}

function Get-ProgramFilesRoots {
    return @(@($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramW6432) |
        Where-Object { $_ } | Sort-Object -Unique)
}

function Test-SafeEdgeApplicationDir {
    param([string]$Path)
    foreach ($base in Get-ProgramFilesRoots) {
        $expected = Join-Path $base 'Microsoft\Edge\Application'
        if ($Path -ne $expected) { continue }
        foreach ($relative in @('Microsoft', 'Microsoft\Edge', 'Microsoft\Edge\Application')) {
            $item = Get-Item -LiteralPath (Join-Path $base $relative) -Force -ErrorAction SilentlyContinue
            if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
        }
        return $true
    }
    return $false
}

function Get-EdgeApplicationDirs {
    # Get-ChildItem on Application lists its CHILDREN, not Application itself.
    # Build exact paths from Windows' environment instead of hardcoding C:.
    foreach ($base in Get-ProgramFilesRoots) {
        $path = Join-Path $base 'Microsoft\Edge\Application'
        if (Test-Path -LiteralPath $path -PathType Container) {
            if (-not (Test-SafeEdgeApplicationDir $path)) {
                throw "Refusing redirected Edge installation path: $path"
            }
            $path
        }
    }
}

function Assert-NoReparsePoints {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Refusing a redirected path: $Path"
    }
    $links = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction Stop |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($links.Count -gt 0) { throw "Refusing a tree containing reparse points: $Path" }
}

# Refuse any path that is not the shared EdgeCore / EdgeWebView payload, which
# Windows and many applications still depend on.
function Test-SharedEdgeComponentPath {
    param([string]$Path)
    return ($Path -match '(?i)\\Microsoft\\(EdgeCore|EdgeWebView)(\\|$)')
}

function Remove-EdgeApplicationDirectory {
    param([string]$Path)
    if (-not (Test-SafeEdgeApplicationDir $Path)) { throw "Unsafe removal path: $Path" }
    if (Test-SharedEdgeComponentPath $Path) { throw "Refusing shared Edge component: $Path" }
    if (Test-Path -LiteralPath $Path) {
        Assert-NoReparsePoints $Path
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    }
    # The deletion must actually have happened; anything else is not success.
    if (Test-Path -LiteralPath $Path) { throw "Removal did not clear $Path" }
    $root = Split-Path -Parent $Path
    if ((Test-Path -LiteralPath $root) -and
        @(Get-ChildItem -LiteralPath $root -Force -ErrorAction Stop).Count -eq 0) {
        Remove-Item -LiteralPath $root -Force -ErrorAction Stop
    }
}

function Get-EdgeRegistryPaths {
    foreach ($software in @('HKLM:\SOFTWARE', 'HKLM:\SOFTWARE\WOW6432Node')) {
        "$software\Microsoft\EdgeUpdate\Clients\$EdgeProductGuid"
        "$software\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge"
        "$software\Clients\StartMenuInternet\Microsoft Edge"
        "$software\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe"
    }
}

<#
    A second, literal allowlist applied at the moment of deletion. It exists so
    that any future edit to Get-EdgeRegistryPaths still cannot aim Remove-Item
    at a key that is not one of these four Edge-only registrations, and it can
    never match the WebView2 product GUID.
#>
function Test-EdgeRegistryPathAllowed {
    param([string]$Path)
    if (-not $Path) { return $false }
    if ($Path -match [regex]::Escape($WebView2ProductGuid)) { return $false }
    if ($Path -match '(?i)EdgeWebView|EdgeCore|DevTools') { return $false }
    $normalized = $Path -replace '/', '\'
    $patterns = @(
        '^HKLM:\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\EdgeUpdate\\Clients\\\{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062\}$',
        '^HKLM:\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\Uninstall\\Microsoft Edge$',
        '^HKLM:\\SOFTWARE\\(WOW6432Node\\)?Clients\\StartMenuInternet\\Microsoft Edge$',
        '^HKLM:\\SOFTWARE\\(WOW6432Node\\)?Microsoft\\Windows\\CurrentVersion\\App Paths\\msedge\.exe$'
    )
    foreach ($pattern in $patterns) {
        if ($normalized -match $pattern) { return $true }
    }
    return $false
}

# A registry key can itself be a symbolic link to another location, in which
# case Remove-Item -Recurse would follow it out of the intended scope.
function Test-RegistryKeyNotLinked {
    param([string]$Path)
    try {
        $key = Get-Item -LiteralPath $Path -ErrorAction Stop
        return ($null -eq $key.GetValue('SymbolicLinkValue', $null))
    }
    catch { return $true }
}

function Get-EdgeShortcutPaths {
    $paths = @(
        (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk'),
        (Join-Path ([Environment]::GetFolderPath('ApplicationData')) 'Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk')
    )
    $desktop = [Environment]::GetFolderPath('DesktopDirectory')
    if ($desktop) { $paths += (Join-Path $desktop 'Microsoft Edge.lnk') }
    $public = Get-TrustedPublicRoot
    if ($public) { $paths += (Join-Path $public 'Desktop\Microsoft Edge.lnk') }
    @($paths | Where-Object { $_ } | Sort-Object -Unique)
}

function Test-EdgeShortcutPathAllowed {
    param([string]$Path)
    if (-not $Path) { return $false }
    foreach ($candidate in Get-EdgeShortcutPaths) {
        if ($candidate -eq $Path) { return $true }
    }
    return $false
}

function Test-EdgePresent {
    param($State)
    return ($State.EdgeExe.Count -gt 0 -or $State.UserEdgeExe -or
        $State.AppDirs.Count -gt 0 -or $State.ClientKey -or $State.ArpEntry -or
        $State.Appx -or $State.ProvisionedAppx -or $State.Shortcuts -or
        $State.BrowserClient -or $State.AppPaths)
}

<#
    The single place that decides whether a run succeeded, so that a run can
    never be reported as a successful removal while a check failed or anything
    is still present.
#>
function Get-RemovalOutcome {
    param($State, [bool]$HadOperationError)
    if ($State.AppxQueryFailed) { return $ExitError }
    if ($HadOperationError) { return $ExitError }
    if (Test-EdgePresent $State) { return $ExitStillPresent }
    return $ExitOk
}

function Get-ExistingEdgeInstall {
    <#
        Finds the newest Edge install by looking for a realistic version
        directory that actually contains the uninstaller.
    #>
    $best = $null
    foreach ($appDir in Get-EdgeApplicationDirs) {
        Assert-NoReparsePoints $appDir
        $versionDirs = Get-ChildItem -LiteralPath $appDir -Directory -ErrorAction Stop |
            Where-Object { $_.Name -match '^\d+(\.\d+){1,3}$' }

        foreach ($v in $versionDirs) {
            $setup = Join-Path $v.FullName 'Installer\setup.exe'
            if (-not (Test-Path -LiteralPath $setup)) { continue }

            $candidate = [pscustomobject]@{
                Version = $v.Name
                Setup   = $setup
                AppDir  = $appDir
                VersionDir = $v.FullName
            }

            if ($null -eq $best) {
                $best = $candidate
            }
            else {
                try {
                    if ([version]$candidate.Version -gt [version]$best.Version) { $best = $candidate }
                }
                catch {
                    if ($candidate.Version -gt $best.Version) { $best = $candidate }
                }
            }
        }
    }
    return $best
}

function Test-EdgeExePresent {
    $found = @()
    foreach ($appDir in Get-EdgeApplicationDirs) {
        $direct = Join-Path $appDir 'msedge.exe'
        if (Test-Path -LiteralPath $direct) { $found += $direct }

        $nested = Get-ChildItem -LiteralPath $appDir -Directory -ErrorAction Stop |
            ForEach-Object { Join-Path $_.FullName 'msedge.exe' } |
            Where-Object { Test-Path -LiteralPath $_ }
        if ($nested) { $found += $nested }
    }
    return @($found | Sort-Object -Unique)
}

<#
    Identity check before any package is removed. Get-AppxPackage -Name takes a
    wildcard pattern, so the returned objects are matched again here against the
    exact stable Edge identity; WebView2, DevTools and any neighbouring package
    can never pass this test.
#>
function Test-EdgeAppxIdentity {
    param($Package)
    if ($null -eq $Package) { return $false }
    $name = [string]$Package.Name
    if ($name -ne $EdgeAppxName) { return $false }
    if ($name -match '(?i)WebView|DevTools') { return $false }
    foreach ($property in @('PackageFamilyName', 'PackageFullName')) {
        # Read the property reflectively: under Set-StrictMode a missing
        # property raises an error instead of returning $null.
        $info = $Package.PSObject.Properties[$property]
        if ($null -eq $info) { continue }
        $value = [string]$info.Value
        if ($value -and -not $value.StartsWith('Microsoft.MicrosoftEdge.Stable_', [StringComparison]::OrdinalIgnoreCase)) {
            return $false
        }
    }
    return $true
}

<#
    Maps an Authenticode status to a decision. Split out from the cmdlet call
    so every status can be tested.

      Valid      - signed by a publisher this machine trusts.
      Untrusted  - anything else. Refuse to run it as administrator.
      Unknown    - the signature is present and matches the file, but the
                   certificate could not be validated (typically an offline
                   machine). Reported, then allowed, because the hash still
                   proves the bytes were not altered.

    Note that a mismatched signature is reported as HashMismatch rather than
    NotTrusted, so allowing NotTrusted does not allow a modified file.
#>
function Get-SignatureStatusVerdict {
    param([string]$Status)
    switch -Regex ([string]$Status) {
        '^Valid$' { return 'Valid' }
        '^NotTrusted$' { return 'Unknown' }
        default { return 'Untrusted' }
    }
}

<#
    Authenticode verdict for the bundled uninstaller, which is about to run
    with administrator rights.
#>
function Get-SignatureVerdict {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return [pscustomobject]@{ Verdict = 'Untrusted'; Detail = 'the file does not exist' }
    }
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    }
    catch {
        return [pscustomobject]@{ Verdict = 'Untrusted'; Detail = $_.Exception.Message }
    }
    $status = [string]$signature.Status
    $verdict = Get-SignatureStatusVerdict $status
    if ($verdict -eq 'Valid') {
        $subject = 'unknown publisher'
        if ($signature.SignerCertificate) { $subject = [string]$signature.SignerCertificate.Subject }
        return [pscustomobject]@{ Verdict = $verdict; Detail = $subject }
    }
    if ($verdict -eq 'Unknown') {
        return [pscustomobject]@{ Verdict = $verdict; Detail = ('certificate could not be validated ({0})' -f $status) }
    }
    return [pscustomobject]@{ Verdict = $verdict; Detail = ('signature status {0}' -f $status) }
}

function Get-EdgeState {
    $matchesAny = {
        param($Paths)
        foreach ($p in $Paths) { if (Test-Path -LiteralPath $p) { return $true } }
        return $false
    }

    $shortcutPaths = @(Get-EdgeShortcutPaths)
    $allUsers = Test-Elevated
    $appx = @()
    $provisioned = @()
    $appxQueryFailed = $false
    try {
        if ($allUsers) {
            $appx = @(Get-AppxPackage -Name $EdgeAppxName -AllUsers -ErrorAction Stop)
            $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop |
                Where-Object { $_.DisplayName -eq $EdgeAppxName })
        }
        else {
            $appx = @(Get-AppxPackage -Name $EdgeAppxName -ErrorAction Stop)
        }
    }
    catch {
        $appxQueryFailed = $true
        Write-Warn ('Unable to fully query stable Edge Appx packages: {0}' -f $_.Exception.Message)
    }

    $reinstallBlocked = $false
    try {
        $policy = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' `
            -Name "Install$EdgeProductGuid" -ErrorAction Stop
        $reinstallBlocked = ($policy."Install$EdgeProductGuid" -eq 0)
    }
    catch { }

    $webView2Installed = $false
    try {
        $null = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$WebView2ProductGuid" -ErrorAction Stop
        $webView2Installed = $true
    }
    catch {
        foreach ($base in Get-ProgramFilesRoots) {
            if (Get-ChildItem -Path (Join-Path $base 'Microsoft\EdgeWebView\Application\*\msedgewebview2.exe') -ErrorAction SilentlyContinue) {
                $webView2Installed = $true
            }
        }
    }

    $httpProgId = ''
    try {
        $choice = Get-ItemProperty -Path 'HKCU:\SOFTWARE\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice' `
            -Name 'ProgId' -ErrorAction Stop
        $httpProgId = [string]$choice.ProgId
    }
    catch { }

    return [pscustomobject]@{
        AppDirs          = @(Get-EdgeApplicationDirs)
        EdgeExe          = @(Test-EdgeExePresent)
        UserEdgeExe      = [bool](Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\Edge\Application\msedge.exe'))
        ClientKey        = [bool](& $matchesAny @(
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$EdgeProductGuid",
            "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\$EdgeProductGuid"))
        ArpEntry         = [bool](
            (Test-Path -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge') -or
            (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge'))
        Appx             = ($appx.Count -gt 0)
        ProvisionedAppx  = ($provisioned.Count -gt 0)
        AppxQueryFailed  = $appxQueryFailed
        AllUsersChecked  = $allUsers
        Shortcuts        = [bool](& $matchesAny $shortcutPaths)
        BrowserClient    = [bool](& $matchesAny @(
            'HKLM:\SOFTWARE\Clients\StartMenuInternet\Microsoft Edge',
            'HKLM:\SOFTWARE\WOW6432Node\Clients\StartMenuInternet\Microsoft Edge'))
        AppPaths         = [bool](& $matchesAny @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe'))
        ReinstallBlocked = $reinstallBlocked
        WebView2         = $webView2Installed
        HttpProgId       = $httpProgId
        ProfilePath      = (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\Edge')
    }
}

function Show-EdgeState {
    param($State)

    # "absent" and "could not be checked" must never read the same way.
    $scope = $(if ($State.AllUsersChecked) { 'all users' } else { 'this user only' })
    $presence = {
        param($Value, [string]$Label)
        if ($Value) { return $Label }
        return ('absent ({0} checked)' -f $scope)
    }

    Write-Step 'Current state'
    $rows = @(
        @{ Label = 'Edge program files'; Value = $(if ($State.EdgeExe.Count -eq 0) { & $presence $false 'PRESENT' } else { 'PRESENT (' + $State.EdgeExe.Count + ' exe)' }) },
        @{ Label = 'Edge Update registration'; Value = (& $presence $State.ClientKey 'PRESENT') },
        @{ Label = 'Add/Remove Programs entry'; Value = (& $presence $State.ArpEntry 'PRESENT') },
        @{ Label = 'Edge appx package'; Value = (& $presence $State.Appx 'PRESENT') },
        @{ Label = 'Shortcuts'; Value = (& $presence $State.Shortcuts 'PRESENT') },
        @{ Label = 'Registered browser client'; Value = (& $presence $State.BrowserClient 'PRESENT') },
        @{ Label = 'App Paths registration'; Value = (& $presence $State.AppPaths 'PRESENT') },
        @{ Label = 'Provisioned stable appx'; Value = $(if ($State.ProvisionedAppx) { 'PRESENT' } elseif ($State.AllUsersChecked) { 'absent (all users checked)' } else { 'could not verify (needs administrator)' }) },
        @{ Label = 'Current-user Edge install'; Value = (& $presence $State.UserEdgeExe 'PRESENT (unsupported)') },
        @{ Label = 'Reinstall policy set'; Value = $(if ($State.ReinstallBlocked) { 'yes (not guaranteed)' } else { 'no' }) },
        @{ Label = 'WebView2 Runtime (kept)'; Value = $(if ($State.WebView2) { 'installed' } else { 'not installed' }) }
    )
    foreach ($row in $rows) {
        Write-Host ('   {0,-28} {1}' -f ($row.Label + ':'), $row.Value)
    }
    if (-not $State.AllUsersChecked) {
        Write-Warn ('Non-admin report: Appx covers {0}; provisioned packages and other' -f $scope)
        Write-Warn "users' packages were not checked, so absence here is not proof."
    }
}

function Get-InstalledBrowsers {
    $candidates = [ordered]@{
        # ${env:ProgramFiles(x86)} needs the braces: "$env:ProgramFiles(x86)" would
        # expand $env:ProgramFiles and then append the literal text "(x86)".
        'Google Chrome'  = @("$env:ProgramFiles\Google\Chrome\Application\chrome.exe", "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe", "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe")
        'Mozilla Firefox' = @("$env:ProgramFiles\Mozilla Firefox\firefox.exe", "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe")
        'Brave'          = @("$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe", "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe", "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe")
        'Vivaldi'        = @("$env:ProgramFiles\Vivaldi\Application\vivaldi.exe", "${env:ProgramFiles(x86)}\Vivaldi\Application\vivaldi.exe", "$env:LOCALAPPDATA\Vivaldi\Application\vivaldi.exe")
        'Opera'          = @("$env:LOCALAPPDATA\Programs\Opera\launcher.exe")
    }
    $installed = @()
    foreach ($name in $candidates.Keys) {
        foreach ($path in $candidates[$name]) {
            # An unset variable would otherwise produce a drive-rooted path that
            # could match an unrelated file.
            if (-not $path -or $path.StartsWith('\')) { continue }
            if (Test-Path -LiteralPath $path -PathType Leaf) { $installed += $name; break }
        }
    }
    return $installed
}

# ------------------------------------------------------------- integrity ---

function Get-TextSha256 {
    param([string]$Text)
    $normalized = $Text.Replace("`r`n", "`n")
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($normalized))).Replace('-', '')
    }
    finally { $sha.Dispose() }
}

function Get-SelfSha256 {
    if (-not ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath -PathType Leaf))) { return '' }
    try { return Get-TextSha256 ([IO.File]::ReadAllText($ScriptPath)) }
    catch { return '' }
}

<#
    A relaunch runs this same file again with administrator rights, so before any
    work happens the file must still be the file that was verified. A
    writable script folder is otherwise a route to arbitrary elevated code.
#>
function Assert-SelfIntegrity {
    param([string]$ExpectedSha256)
    if (-not $ExpectedSha256) { return }
    if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
        throw 'The expected payload checksum is malformed.'
    }
    if (-not ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath -PathType Leaf))) {
        throw 'Cannot verify this script file, so it will not run.'
    }
    $actual = Get-SelfSha256
    if (-not $actual) { throw 'Could not read this script file to verify it.' }
    if ($actual -ne $ExpectedSha256.ToUpperInvariant()) {
        throw 'This script file no longer matches the checksum it was verified with.'
    }
}

<#
    The self-relaunch source arrives from the caller's scope, so it is only
    honoured when it is the pinned GitHub raw URL for a numeric tag and carries
    a well-formed SHA-256. Without both, no relaunch is offered at all rather
    than downloading something unverified.
#>
function Test-PinnedPayloadSource {
    param([string]$Url, [string]$Sha256)
    if (-not $Url -or -not $Sha256) { return $false }
    if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$') { return $false }
    $uri = $null
    if (-not [Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri)) { return $false }
    if ($uri.Scheme -ne 'https') { return $false }
    if ($uri.Host -ne $AllowedPayloadHost) { return $false }
    if ($uri.AbsolutePath -notmatch $AllowedPayloadPathPattern) { return $false }
    return $true
}

<#
    The elevated relaunch must start the PowerShell that is already running this
    script, by absolute path. Falling back to a bare "powershell.exe" would let
    anything earlier on PATH be elevated instead, so an unresolvable host
    returns nothing and no relaunch is offered.
#>
function Get-PowerShellHostPath {
    foreach ($name in @('powershell.exe', 'pwsh.exe')) {
        $candidate = Join-Path $PSHOME $name
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    return ''
}

function Get-ForwardedArguments {
    foreach ($name in @('VerifyOnly', 'RemoveProfileData', 'NoReinstallBlock', 'CreateRestorePoint', 'DryRun', 'AllowNoOtherBrowser')) {
        if ($ScriptSwitches.ContainsKey($name) -and $ScriptSwitches[$name]) { '-{0}' -f $name }
    }
}

function Get-SelfRelaunch {
    $switches = @(Get-ForwardedArguments) -join ' '
    $kind = ''
    $inner = ''
    if ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath -PathType Leaf)) {
        # Pin this exact file: the elevated child re-checks its own bytes against
        # the checksum computed here, so a replaced script cannot be elevated.
        $selfHash = Get-SelfSha256
        if (-not $selfHash) { return $null }
        $path = $ScriptPath.Replace("'", "''")
        $hash = $selfHash
        $inner = "& '$path' $switches -ExpectedPayloadSha256 '$hash'"
        $kind = 'file'
    }
    elseif (Test-PinnedPayloadSource -Url $RemoveEdgeUrl -Sha256 $RemoveEdgeSha256) {
        $url = $RemoveEdgeUrl.Replace("'", "''")
        $hash = $RemoveEdgeSha256.ToUpperInvariant()
        $inner = @"
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'
`$RemoveEdgeUrl = '$url'
`$RemoveEdgeSha256 = '$hash'
try {
    `$response = Invoke-WebRequest -Uri `$RemoveEdgeUrl -UseBasicParsing -TimeoutSec 120 -ErrorAction Stop
    if (`$response.BaseResponse.ResponseUri.Host -ne '$AllowedPayloadHost') { throw 'Unexpected download host.' }
    `$source = [string]`$response.Content
    `$source = `$source.Replace([string]([char]13) + [char]10, [string][char]10)
    if (`$RemoveEdgeSha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Expected payload checksum is missing or malformed.' }
    `$sha = [Security.Cryptography.SHA256]::Create()
    try { `$actual = [BitConverter]::ToString(`$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(`$source))).Replace('-', '') }
    finally { `$sha.Dispose() }
    if (`$actual -ne `$RemoveEdgeSha256.ToUpperInvariant()) { throw 'Downloaded script hash mismatch. Nothing was executed.' }

    # Running a real .ps1 lets its exit return to this -NoExit shell so the
    # final report stays visible. The verified text goes into a private
    # directory that only this user and SYSTEM can write to, and is hashed again
    # after being written so the file that runs is the file that was verified.
    `$tempRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Temp'
    if (-not (Test-Path -LiteralPath `$tempRoot -PathType Container)) { `$tempRoot = Join-Path `$env:SystemRoot 'Temp' }
    `$tempDir = Join-Path `$tempRoot ('RemoveEdge-' + [guid]::NewGuid().ToString('N'))
    `$temporaryFile = `$null
    try {
        `$null = New-Item -ItemType Directory -Path `$tempDir -ErrorAction Stop
        `$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        `$acl = New-Object Security.AccessControl.DirectorySecurity
        `$acl.SetAccessRuleProtection(`$true, `$false)
        foreach (`$identity in @(`$sid, [Security.Principal.SecurityIdentifier]'S-1-5-18')) {
            `$rule = New-Object Security.AccessControl.FileSystemAccessRule(`$identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
            `$acl.AddAccessRule(`$rule)
        }
        [IO.Directory]::SetAccessControl(`$tempDir, `$acl)
        `$temporaryFile = Join-Path `$tempDir 'Remove-Edge.ps1'
        [IO.File]::WriteAllText(`$temporaryFile, `$source, (New-Object Text.UTF8Encoding(`$true)))
        `$written = [IO.File]::ReadAllText(`$temporaryFile).Replace([string]([char]13) + [char]10, [string][char]10)
        `$sha2 = [Security.Cryptography.SHA256]::Create()
        try { `$onDisk = [BitConverter]::ToString(`$sha2.ComputeHash([Text.Encoding]::UTF8.GetBytes(`$written))).Replace('-', '') }
        finally { `$sha2.Dispose() }
        if (`$onDisk -ne `$actual) { throw 'The written payload no longer matches the verified download.' }
        & `$temporaryFile $switches
    }
    finally {
        if (`$temporaryFile -and (Test-Path -LiteralPath `$temporaryFile)) { Remove-Item -LiteralPath `$temporaryFile -Force -ErrorAction SilentlyContinue }
        if (Test-Path -LiteralPath `$tempDir) { Remove-Item -LiteralPath `$tempDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
} catch {
    Write-Host (`$_.Exception.Message) -ForegroundColor Red
    `$global:LASTEXITCODE = 3
}
"@
        $kind = 'url'
    }
    else { return $null }

    # Start-Process joins argument arrays. EncodedCommand protects spaces,
    # apostrophes, Unicode paths, and command quoting from that extra parse.
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($inner))
    return [pscustomobject]@{
        Kind = $kind
        Args = @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
    }
}

function Invoke-ElevationHint {
    Write-Host ''
    Write-Warn 'Administrator rights are required to remove Edge.'

    if ($ScriptPath -and (Test-Path -LiteralPath $ScriptPath)) {
        Write-Info 'Run this script from an elevated PowerShell:'
        Write-Info ('    powershell -NoProfile -ExecutionPolicy Bypass -File "{0}"' -f $ScriptPath)
        Write-Info 'Or double-click Run-Elevated.cmd, which asks for elevation for you.'
    }
    elseif ($RemoveEdgeUrl) {
        Write-Info 'Re-run the one-liner from an elevated PowerShell, or just re-run it'
        Write-Info 'and say yes to the elevation prompt.'
    }
    else {
        Write-Info 'This copy was piped straight into PowerShell, so it has no file to'
        Write-Info 're-launch. Use the one-liner from the README, which requests elevation'
        Write-Info 'for you, or save this script and run Run-Elevated.cmd.'
    }
}

# ------------------------------------------------------------ profile data ---

function Get-EdgeProfilePath {
    return (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Microsoft\Edge')
}

<#
    The only directory -RemoveProfileData may ever delete: the current account's
    Edge browser profile, derived from the registry-reported local application
    data folder rather than from $env:LOCALAPPDATA. Traversal, a redirected
    root, a WebView2 or shared path, or any trailing separator all fail here.
#>
function Test-SafeProfilePath {
    param([string]$Path)
    if (-not $Path) { return $false }
    if ($Path -match '(?i)EdgeWebView|EdgeCore|DevTools|\.\.|::$') { return $false }
    if (-not $Path.EndsWith('\Microsoft\Edge', [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $expected = Get-EdgeProfilePath
    if (-not $expected) { return $false }
    return ($Path -eq $expected)
}

function Get-DirectorySizeMb {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { return 0 }
    $sum = (Get-ChildItem -LiteralPath $Path -Recurse -File -Force -ErrorAction SilentlyContinue |
        Measure-Object -Property Length -Sum).Sum
    if (-not $sum) { return 0 }
    return [math]::Round($sum / 1MB, 0)
}

# ------------------------------------------------------------------- main ---

$ReadOnlyMode = ($VerifyOnly.IsPresent -or $DryRun.IsPresent)

# A relaunched run must still be the file that was verified, before anything
# else happens.
try {
    Assert-SelfIntegrity -ExpectedSha256 $ExpectedPayloadSha256
}
catch {
    Write-Host ''
    Write-Host ('Refusing to run: {0}' -f $_.Exception.Message) -ForegroundColor Red
    exit $ExitError
}

# Environment variables decide nothing on their own, but a rewritten root is a
# sign this process cannot be trusted with deletions, so the destructive run
# stops here rather than relying on any later check.
$environmentProblems = @(Get-EnvironmentProblems)
if ($environmentProblems.Count -gt 0) {
    Write-Step 'Warning: this process environment does not match Windows'
    foreach ($problem in $environmentProblems) { Write-Warn $problem }
    if ($ReadOnlyMode) {
        Write-Info 'Read-only mode continues, but paths reported here may be unreliable.'
    }
    else {
        Write-Warn 'Removal is refused because of it.'
        Write-Info 'Open a new PowerShell window and run again; that restores the real values.'
        exit $ExitNotElevated
    }
}

if (-not (Test-Elevated) -and -not $ReadOnlyMode) {
    if ($NoElevate) {
        Invoke-ElevationHint
        exit $ExitNotElevated
    }

    $relaunch = Get-SelfRelaunch
    if ($null -eq $relaunch) {
        Invoke-ElevationHint
        exit $ExitNotElevated
    }

    Write-Host ''
    Write-Host 'Administrator rights are needed - asking Windows for them now.' -ForegroundColor Yellow
    Write-Info 'Accept the "Do you want to allow this app to make changes?" prompt.'

    $hostExe = Get-PowerShellHostPath
    if (-not $hostExe) {
        Write-Warn 'Could not locate this PowerShell installation by absolute path.'
        Invoke-ElevationHint
        exit $ExitNotElevated
    }
    try {
        # The working directory is fixed to a system directory so nothing in a
        # user-writable folder can be picked up by the elevated child.
        Start-Process -FilePath $hostExe -Verb RunAs -ArgumentList $relaunch.Args `
            -WorkingDirectory (Join-Path ([Environment]::GetFolderPath('Windows')) 'System32') -ErrorAction Stop
        Write-Host ''
        Write-Host 'Continuing in the new administrator window. This one can be closed.' -ForegroundColor Green
        exit $ExitRelaunched
    }
    catch {
        Write-Warn ('Elevation was declined or failed: {0}' -f $_.Exception.Message)
        exit $ExitNotElevated
    }
}

Write-Host ''
Write-Host 'Remove Microsoft Edge' -ForegroundColor White
Write-Host '---------------------' -ForegroundColor White
if ($DryRun) { Write-Warn 'Dry run: nothing will be changed.' }

$state = Get-EdgeState
Show-EdgeState -State $state
$webView2WasInstalled = $state.WebView2

if ($VerifyOnly) {
    Write-Host ''
    if ($state.AppxQueryFailed) {
        Write-Host 'Result: could not verify - the package query failed.' -ForegroundColor Yellow
        exit $ExitError
    }
    if (Test-EdgePresent $state) {
        Write-Host 'Result: an Edge installation or checked remnant is PRESENT.' -ForegroundColor Yellow
        exit $ExitStillPresent
    }
    if (-not $state.AllUsersChecked) {
        Write-Host 'Result: nothing found in this user''s scope. Run as administrator to' -ForegroundColor Yellow
        Write-Host 'verify all users and provisioned packages.' -ForegroundColor Yellow
        exit $ExitStillPresent
    }
    Write-Host 'Result: no Edge installation or remnants found within the checked scope.' -ForegroundColor Green
    exit $ExitOk
}

$install = Get-ExistingEdgeInstall

if ($null -eq $install -and $state.EdgeExe.Count -eq 0) {
    Write-Step 'Edge is already gone'
    Write-Info 'No Edge program files found.'
    if (-not $state.ReinstallBlocked -and -not $NoReinstallBlock) {
        Write-Info 'Adding the Edge Update install policy (Windows updates may still restore Edge).'
    }
}
elseif ($null -eq $install) {
    Write-Step 'Edge binaries found but no uninstaller'
    Write-Info 'Falling back to direct removal.'
}
else {
    Write-Step ('Found Edge {0}' -f $install.Version)
    Write-Info ('Uninstaller: {0}' -f $install.Setup)
}

if ($DryRun) {
    Write-Step 'Dry run summary'
    Write-Info ('Would stop: {0}' -f ($ProcessNames -join ', '))
    if ($install) { Write-Info ('Would run: "{0}" --uninstall --system-level --verbose-logging --force-uninstall' -f $install.Setup) }
    Write-Info 'Would remove leftover Edge files/registration if anything survives.'
    if (-not $NoReinstallBlock) { Write-Info ('Would set HKLM\SOFTWARE\Policies\Microsoft\EdgeUpdate\Install{0} = 0' -f $EdgeProductGuid) }
    if ($RemoveProfileData) { Write-Info ('Would irreversibly delete {0}' -f (Get-EdgeProfilePath)) }
    Write-Host ''
    Write-Host 'Nothing was changed.' -ForegroundColor Green
    exit $ExitOk
}

if ($state.AppxQueryFailed) {
    Write-Warn 'Aborting because package verification is incomplete.'
    exit $ExitError
}

if ($state.UserEdgeExe) {
    Write-Warn 'A current-user Edge installation was found. This tool only removes system-level installs.'
    exit $ExitNotElevated
}

$browsers = @(Get-InstalledBrowsers)
if ((Test-EdgePresent $state) -and $browsers.Count -eq 0 -and -not $AllowNoOtherBrowser) {
    Write-Warn 'No supported alternative browser was detected. Install one before removing Edge.'
    Write-Info 'Removing the only browser leaves nothing to open web pages or .htm files.'
    Write-Info 'For a portable/unrecognized browser, explicitly use -AllowNoOtherBrowser.'
    exit $ExitNotElevated
}

$restorePointCreated = $false
if ($CreateRestorePoint) {
    Write-Step 'Creating a System Restore point'
    try {
        Checkpoint-Computer -Description 'Before removing Microsoft Edge' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        $restorePointCreated = $true
        Write-Info 'Restore point created.'
    }
    catch {
        Write-Warn ('Could not create a restore point: {0}' -f $_.Exception.Message)
        Write-Warn 'Removal continues because System Protection is often simply disabled.'
        Write-Warn 'A restore point is not a backup and does not guarantee recovery.'
    }
}

Write-Step 'Stopping Edge'
$stopped = 0
foreach ($name in $ProcessNames) {
    $procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
    if ($procs.Count -gt 0) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        $stopped += $procs.Count
        # Report what actually stopped. A browser that survived is what makes the
        # uninstaller fail, so this must not be presented as success.
        $remaining = @(Get-Process -Name $name -ErrorAction SilentlyContinue).Count
        if ($remaining -eq 0) {
            Write-Info ('stopped {0} process(es): {1}' -f $procs.Count, $name)
        }
        else {
            Write-Warn ('{0} of {1} {2} process(es) are still running' -f $remaining, $procs.Count, $name)
        }
    }
}
if ($stopped -eq 0) { Write-Info 'no Edge processes were running' }
Start-Sleep -Seconds 2

if ($install) {
    Write-Step "Running Microsoft's Edge uninstaller"
    $verdict = Get-SignatureVerdict -Path $install.Setup
    if ($verdict.Verdict -eq 'Untrusted') {
        # The uninstaller is about to run as administrator, so an unverified
        # binary is refused rather than executed. Direct cleanup still runs.
        $HadOperationError = $true
        Write-Warn ('Refusing to run the bundled uninstaller: {0}.' -f $verdict.Detail)
        Write-Warn 'Skipping it and continuing with direct removal.'
    }
    else {
        if ($verdict.Verdict -eq 'Unknown') {
            Write-Warn ('Could not fully check the uninstaller signature ({0});' -f $verdict.Detail)
            Write-Warn 'continuing because this machine may be offline.'
        }
        $uninstallerArgs = @('--uninstall', '--system-level', '--verbose-logging', '--force-uninstall')
        $code = $null
        Push-Location $install.AppDir
        try {
            $proc = Start-Process -FilePath $install.Setup -ArgumentList $uninstallerArgs -Wait -PassThru
            $code = $proc.ExitCode
        }
        catch {
            Write-Warn ('Could not start the uninstaller: {0}' -f $_.Exception.Message)
        }
        finally {
            Pop-Location
        }
        Write-Info ('uninstaller exit code: {0}' -f $code)
        if ($code -eq 20) {
            # Observed on a fully successful uninstall: Edge logs "Failed to
            # delete folder ...\Microsoft\Edge\Application" and exits 20, yet
            # removes every binary and all of its registration. So the exit
            # code is not a reliable signal here - the checks below are.
            Write-Warn 'Exit code 20 can indicate incomplete cleanup; checking files and registration.'
        }

        Write-Info 'waiting for Edge to disappear...'
        $deadline = (Get-Date).AddSeconds(120)
        while ((Get-Date) -lt $deadline) {
            if (-not (Test-Path -LiteralPath $install.VersionDir) -and
                -not (Test-Path -LiteralPath (Join-Path $install.AppDir 'msedge.exe'))) {
                break
            }
            Start-Sleep -Seconds 2
        }
    }
}

$state = Get-EdgeState

if (Test-EdgePresent $state) {
    Write-Step 'Cleaning up leftover Edge files and registration'

    foreach ($name in $ProcessNames) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Seconds 1

    foreach ($appDir in $state.AppDirs) {
        # Remove the Application folder, then the parent ...\Microsoft\Edge only
        # if we left it empty. Deliberately not a blanket delete: nothing else
        # in this script should ever remove a folder it did not create.
        try {
            Remove-EdgeApplicationDirectory $appDir
            Write-Info ('removed {0} (and its parent if empty)' -f $appDir)
        }
        catch {
            $HadOperationError = $true
            Write-Warn ('could not remove {0}: {1}' -f $appDir, $_.Exception.Message)
        }
    }

    foreach ($key in Get-EdgeRegistryPaths) {
        if (-not (Test-EdgeRegistryPathAllowed $key)) {
            $HadOperationError = $true
            Write-Warn ('refused unexpected registration path {0}' -f $key)
            continue
        }
        if (Test-Path -LiteralPath $key) {
            if (-not (Test-RegistryKeyNotLinked $key)) {
                $HadOperationError = $true
                Write-Warn ('refused linked registration path {0}' -f $key)
                continue
            }
            try {
                Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop
                Write-Info ('removed registration {0}' -f ($key -split '\\')[-1])
            }
            catch {
                $HadOperationError = $true
                Write-Warn ('could not remove {0}' -f $key)
            }
        }
    }

    foreach ($lnk in Get-EdgeShortcutPaths) {
        if (-not (Test-EdgeShortcutPathAllowed $lnk)) {
            $HadOperationError = $true
            Write-Warn ('refused unexpected shortcut path {0}' -f $lnk)
            continue
        }
        if (Test-Path -LiteralPath $lnk) {
            try {
                Remove-Item -LiteralPath $lnk -Force -ErrorAction Stop
                Write-Info ('removed shortcut {0}' -f (Split-Path -Leaf $lnk))
            }
            catch {
                $HadOperationError = $true
                Write-Warn ('could not remove shortcut {0}' -f $lnk)
            }
        }
    }

    try {
        $packages = @(Get-AppxPackage -Name $EdgeAppxName -AllUsers -ErrorAction Stop |
            Where-Object { Test-EdgeAppxIdentity $_ })
        if ($packages.Count -eq 0) {
            Write-Info 'no stable Edge appx package left to remove'
        }
        foreach ($package in $packages) {
            try {
                Remove-AppxPackage -Package $package.PackageFullName -AllUsers -ErrorAction Stop
                Write-Info ('removed appx package {0}' -f $package.PackageFullName)
            }
            catch {
                # One package failing must not hide the others.
                $HadOperationError = $true
                Write-Warn ('could not remove appx package {0}: {1}' -f $package.PackageFullName, $_.Exception.Message)
            }
        }
    }
    catch {
        $HadOperationError = $true
        Write-Warn ('Stable Edge Appx query failed: {0}' -f $_.Exception.Message)
    }

    try {
        $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop |
            Where-Object { $_.DisplayName -eq $EdgeAppxName })
        foreach ($package in $provisioned) {
            try {
                $null = Remove-AppxProvisionedPackage -Online -PackageName $package.PackageName -ErrorAction Stop
                Write-Info ('removed provisioned appx package {0}' -f $package.PackageName)
            }
            catch {
                $HadOperationError = $true
                Write-Warn ('could not remove provisioned appx package {0}: {1}' -f $package.PackageName, $_.Exception.Message)
            }
        }
    }
    catch {
        $HadOperationError = $true
        Write-Warn ('Stable Edge provisioned package query failed: {0}' -f $_.Exception.Message)
    }

    $state = Get-EdgeState
}

if (-not $NoReinstallBlock) {
    Write-Step 'Setting the Edge Update install policy'
    $policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
    $policyName = "Install$EdgeProductGuid"
    try {
        if (-not (Test-Path -LiteralPath $policyKey)) {
            $null = New-Item -Path $policyKey -Force -ErrorAction Stop
        }
        $null = New-ItemProperty -Path $policyKey -Name $policyName `
            -Value 0 -PropertyType DWord -Force -ErrorAction Stop
        # Read the value back: a policy that was not actually written is not a
        # policy.
        $written = (Get-ItemProperty -Path $policyKey -Name $policyName -ErrorAction Stop).$policyName
        if ($written -ne 0) {
            throw 'The policy value did not read back as 0.'
        }
        Write-Info ('set {0} = 0' -f $policyName)
        Write-Info 'This names the Edge browser product only; WebView2 keeps updating.'
        Write-Info 'It is a request to Edge Update, not a guarantee: Windows feature'
        Write-Info 'updates and repair installs can still restore Edge.'
    }
    catch {
        $HadOperationError = $true
        Write-Warn ('could not write the reinstall policy: {0}' -f $_.Exception.Message)
    }
}
else {
    Write-Step 'Skipping the Edge Update install policy'
    Write-Info '-NoReinstallBlock was supplied; no policy value was written.'
    Write-Info 'An existing policy, if any, was left exactly as it was.'
}

$profilePath = Get-EdgeProfilePath
if ($RemoveProfileData) {
    Write-Step 'Removing the leftover Edge browser profile'
    Write-Warn 'IRREVERSIBLE: history, cookies, cache, bookmarks and locally stored'
    Write-Warn ('passwords in {0} are permanently deleted.' -f $profilePath)
    if (-not (Test-SafeProfilePath $profilePath)) {
        $HadOperationError = $true
        Write-Warn ('refused unsafe profile path {0}' -f $profilePath)
    }
    elseif (-not (Test-Path -LiteralPath $profilePath)) {
        Write-Info 'no leftover profile found'
    }
    else {
        $mb = Get-DirectorySizeMb $profilePath
        try {
            $parent = Get-Item -LiteralPath (Split-Path -Parent $profilePath) -Force -ErrorAction Stop
            if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Profile parent is redirected.' }
            Assert-NoReparsePoints $profilePath
            Remove-Item -LiteralPath $profilePath -Recurse -Force -ErrorAction Stop
            if (Test-Path -LiteralPath $profilePath) { throw 'The profile directory still exists after deletion.' }
            Write-Info ('deleted {0} (~{1} MB)' -f $profilePath, $mb)
        }
        catch {
            $HadOperationError = $true
            Write-Warn ('could not fully delete {0}: {1}' -f $profilePath, $_.Exception.Message)
        }
    }
}
elseif (Test-Path -LiteralPath $profilePath) {
    Write-Info ('leftover browser profile kept (~{0} MB) - use -RemoveProfileData to delete it' -f (Get-DirectorySizeMb $profilePath))
}

$state = Get-EdgeState
Show-EdgeState -State $state

if ($webView2WasInstalled -and -not $state.WebView2) {
    $HadOperationError = $true
    Write-Warn 'WebView2 Runtime was installed before this run and is no longer detected.'
    Write-Warn 'This tool never targets it. Repair it from an official Microsoft source.'
}

Write-Step 'Summary'
$browsers = @(Get-InstalledBrowsers)
if ($browsers.Count -gt 0) {
    Write-Info ('other browsers installed: {0}' -f ($browsers -join ', '))
}
else {
    Write-Warn 'No other browser was found. Install one (or reinstall Edge) before removing Edge.'
}

if ($state.HttpProgId -eq 'MSEdgeHTM') {
    Write-Warn 'Edge was set as your default browser and that link is now dead.'
    Write-Info 'Open Settings > Apps > Default apps and pick another browser,'
    Write-Info 'otherwise links and .htm files have nothing to open them.'
}

if ($CreateRestorePoint -and -not $restorePointCreated) {
    Write-Warn 'No restore point was created for this run.'
}

Write-Host ''
switch (Get-RemovalOutcome -State $state -HadOperationError $HadOperationError) {
    $ExitError {
        Write-Host 'Result: one or more operations/checks failed. Review the warnings above.' -ForegroundColor Yellow
        Write-Info 'Nothing here should be read as a successful removal.'
        exit $ExitError
    }
    $ExitStillPresent {
        Write-Host 'Result: Microsoft Edge is still present. See the messages above.' -ForegroundColor Yellow
        exit $ExitStillPresent
    }
    default {
        Write-Host 'Result: system-level Microsoft Edge and checked remnants are absent.' -ForegroundColor Green
        Write-Info 'Windows updates may still restore Edge; shared EdgeCore/WebView2 files are kept.'
        if (-not $state.ReinstallBlocked) {
            Write-Info 'Note: the Edge Update install policy is not set.'
        }
        exit $ExitOk
    }
}