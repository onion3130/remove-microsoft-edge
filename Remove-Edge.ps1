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
    removing it breaks software. Only the Edge browser is removed.

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
    be enabled; a failure here does not stop the script.

.PARAMETER DryRun
    Print what would be done and change nothing.

.EXAMPLE
    .\Remove-Edge.ps1
    Attempts to remove Edge and sets the Edge Update install policy.

.EXAMPLE
    .\Remove-Edge.ps1 -VerifyOnly
    Reports the current state and changes nothing.

.EXAMPLE
    .\Remove-Edge.ps1 -RemoveProfileData -CreateRestorePoint
    Creates a restore point, removes Edge, and removes the leftover profile.

.PARAMETER NoElevate
    Do not ask Windows for administrator rights. Use this in unattended or
    scheduled runs, where a UAC prompt would just hang.

.PARAMETER AllowNoOtherBrowser
    Explicitly bypass the alternative-browser check, for example when using
    a portable browser that this tool cannot detect.

.EXAMPLE
    # no file needed - review the repo first, then accept the UAC prompt
    irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.0/get.ps1 | iex

.NOTES
    The script asks for administrator rights itself, unless -NoElevate is used.
    Exit codes: 0 = Edge is not installed / was removed successfully
                1 = Edge is still present after the attempt
                2 = not elevated, or prerequisites missing
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
    [switch]$AllowNoOtherBrowser
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

# Microsoft Edge (stable) as Edge Update knows it.
# Product names verified against EdgeUpdate\Clients on the test machine.
# WebView2 has a separate product ID and is not a removal target.
$EdgeProductGuid = '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
$WebView2ProductGuid = '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'

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

function Remove-EdgeApplicationDirectory {
    param([string]$Path)
    if (-not (Test-SafeEdgeApplicationDir $Path)) { throw "Unsafe removal path: $Path" }
    if (Test-Path -LiteralPath $Path) {
        Assert-NoReparsePoints $Path
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
    }
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

function Get-EdgeShortcutPaths {
    @(
        (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk'),
        (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk'),
        (Join-Path $env:PUBLIC 'Desktop\Microsoft Edge.lnk'),
        (Join-Path ([Environment]::GetFolderPath('Desktop')) 'Microsoft Edge.lnk')
    ) | Sort-Object -Unique
}

function Test-EdgePresent {
    param($State)
    return ($State.EdgeExe.Count -gt 0 -or $State.UserEdgeExe -or
        $State.AppDirs.Count -gt 0 -or $State.ClientKey -or $State.ArpEntry -or
        $State.Appx -or $State.ProvisionedAppx -or $State.Shortcuts -or
        $State.BrowserClient -or $State.AppPaths)
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
            $appx = @(Get-AppxPackage -Name 'Microsoft.MicrosoftEdge.Stable' -AllUsers -ErrorAction Stop)
            $provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop |
                Where-Object { $_.DisplayName -eq 'Microsoft.MicrosoftEdge.Stable' })
        }
        else {
            $appx = @(Get-AppxPackage -Name 'Microsoft.MicrosoftEdge.Stable' -ErrorAction Stop)
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
        UserEdgeExe      = [bool](Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\Application\msedge.exe'))
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
        ProfilePath      = (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge')
    }
}

function Show-EdgeState {
    param($State)

    Write-Step 'Current state'
    $rows = @(
        @{ Label = 'Edge program files'; Value = $(if ($State.EdgeExe.Count -eq 0) { 'absent' } else { 'PRESENT (' + $State.EdgeExe.Count + ' exe)' }) },
        @{ Label = 'Edge Update registration'; Value = $(if ($State.ClientKey) { 'PRESENT' } else { 'absent' }) },
        @{ Label = 'Add/Remove Programs entry'; Value = $(if ($State.ArpEntry) { 'PRESENT' } else { 'absent' }) },
        @{ Label = 'Edge appx package'; Value = $(if ($State.Appx) { 'PRESENT' } else { 'absent' }) },
        @{ Label = 'Shortcuts'; Value = $(if ($State.Shortcuts) { 'PRESENT' } else { 'absent' }) },
        @{ Label = 'Registered browser client'; Value = $(if ($State.BrowserClient) { 'PRESENT' } else { 'absent' }) },
        @{ Label = 'App Paths registration'; Value = $(if ($State.AppPaths) { 'PRESENT' } else { 'absent' }) },
        @{ Label = 'Provisioned stable appx'; Value = $(if ($State.ProvisionedAppx) { 'PRESENT' } else { 'absent / not queried' }) },
        @{ Label = 'Current-user Edge install'; Value = $(if ($State.UserEdgeExe) { 'PRESENT (unsupported)' } else { 'absent' }) },
        @{ Label = 'Reinstall policy set'; Value = $(if ($State.ReinstallBlocked) { 'yes (not guaranteed)' } else { 'no' }) },
        @{ Label = 'WebView2 Runtime (kept)'; Value = $(if ($State.WebView2) { 'installed' } else { 'not installed' }) }
    )
    foreach ($row in $rows) {
        Write-Host ('   {0,-28} {1}' -f ($row.Label + ':'), $row.Value)
    }
    if (-not $State.AllUsersChecked) {
        Write-Warn 'Non-admin report: Appx covers only this user; provisioned packages are not queried.'
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
            if (Test-Path -LiteralPath $path) { $installed += $name; break }
        }
    }
    return $installed
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
        $path = $ScriptPath.Replace("'", "''")
        $inner = "& '$path' $switches"
        $kind = 'file'
    }
    elseif ($RemoveEdgeUrl) {
        $url = $RemoveEdgeUrl.Replace("'", "''")
        $hash = $RemoveEdgeSha256.Replace("'", "''")
        $inner = @"
`$ErrorActionPreference = 'Stop'
`$ProgressPreference = 'SilentlyContinue'
`$RemoveEdgeUrl = '$url'
`$RemoveEdgeSha256 = '$hash'
try {
    `$source = ([string](Invoke-RestMethod -Uri `$RemoveEdgeUrl -UseBasicParsing -ErrorAction Stop)).Replace([string]([char]13) + [char]10, [string][char]10)
    if (`$RemoveEdgeSha256) {
        `$sha = [Security.Cryptography.SHA256]::Create()
        try {
            `$actual = [BitConverter]::ToString(`$sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(`$source))).Replace('-', '')
        } finally { `$sha.Dispose() }
        if (`$actual -ne `$RemoveEdgeSha256) { throw 'Downloaded script hash mismatch. Nothing was executed.' }
    }
    # Running a real .ps1 lets its exit return to this -NoExit shell so the
    # final report stays visible. The verified temporary copy is then deleted.
    `$temporaryFile = Join-Path ([IO.Path]::GetTempPath()) ('Remove-Edge-' + [guid]::NewGuid().ToString('N') + '.ps1')
    try {
        [IO.File]::WriteAllText(`$temporaryFile, `$source, (New-Object Text.UTF8Encoding(`$true)))
        & `$temporaryFile $switches
    } finally {
        if (Test-Path -LiteralPath `$temporaryFile) { Remove-Item -LiteralPath `$temporaryFile -Force }
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
        Write-Info ('    powershell -ExecutionPolicy Bypass -File "{0}"' -f $ScriptPath)
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

# ------------------------------------------------------------------- main ---

if (-not (Test-Elevated) -and -not $VerifyOnly -and -not $DryRun) {
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

    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList $relaunch.Args -ErrorAction Stop
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

if ($VerifyOnly) {
    Write-Host ''
    if ($state.AppxQueryFailed) { exit $ExitError }
    if (Test-EdgePresent $state) {
        Write-Host 'Result: an Edge installation or checked remnant is PRESENT.' -ForegroundColor Yellow
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
    if ($RemoveProfileData) { Write-Info ('Would delete {0}' -f $state.ProfilePath) }
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
    Write-Info 'For a portable/unrecognized browser, explicitly use -AllowNoOtherBrowser.'
    exit $ExitNotElevated
}

if ($CreateRestorePoint) {
    Write-Step 'Creating a System Restore point'
    try {
        Checkpoint-Computer -Description 'Before removing Microsoft Edge' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        Write-Info 'Restore point created.'
    }
    catch {
        Write-Warn ('Could not create a restore point: {0}' -f $_.Exception.Message)
    }
}

Write-Step 'Stopping Edge'
$stopped = 0
foreach ($name in $ProcessNames) {
    $procs = @(Get-Process -Name $name -ErrorAction SilentlyContinue)
    if ($procs.Count -gt 0) {
        $procs | Stop-Process -Force -ErrorAction SilentlyContinue
        Write-Info ('stopped {0} process(es): {1}' -f $procs.Count, $name)
        $stopped += $procs.Count
    }
}
if ($stopped -eq 0) { Write-Info 'no Edge processes were running' }
Start-Sleep -Seconds 2

if ($install) {
    Write-Step "Running Microsoft's Edge uninstaller"
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
        # Observed on a fully successful uninstall: Edge logs "Failed to delete
        # folder ...\Microsoft\Edge\Application" and exits 20, yet removes
        # every binary and all of its registration. So the exit code is not a
        # reliable success/failure signal here - the checks below are.
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
        if (Test-Path -LiteralPath $key) {
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

    $shortcutPaths = @(Get-EdgeShortcutPaths)
    foreach ($lnk in $shortcutPaths) {
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
        Get-AppxPackage -Name 'Microsoft.MicrosoftEdge.Stable' -AllUsers -ErrorAction Stop |
            Remove-AppxPackage -AllUsers -ErrorAction Stop
        Get-AppxProvisionedPackage -Online -ErrorAction Stop |
            Where-Object { $_.DisplayName -eq 'Microsoft.MicrosoftEdge.Stable' } |
            Remove-AppxProvisionedPackage -Online -ErrorAction Stop | Out-Null
        Write-Info 'edge appx package removal attempted'
    }
    catch {
        $HadOperationError = $true
        Write-Warn ('Stable Edge Appx cleanup failed: {0}' -f $_.Exception.Message)
    }

    $state = Get-EdgeState
}

if (-not $NoReinstallBlock) {
    Write-Step 'Setting the Edge Update install policy'
    try {
        $policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
        if (-not (Test-Path -LiteralPath $policyKey)) {
            $null = New-Item -Path $policyKey -Force -ErrorAction Stop
        }
        $null = New-ItemProperty -Path $policyKey -Name "Install$EdgeProductGuid" `
            -Value 0 -PropertyType DWord -Force -ErrorAction Stop
        Write-Info ('set Install{0} = 0' -f $EdgeProductGuid)
        Write-Info 'WebView2 is not covered by this policy and keeps updating.'
    }
    catch {
        $HadOperationError = $true
        Write-Warn ('could not write the reinstall policy: {0}' -f $_.Exception.Message)
    }
}

if ($RemoveProfileData) {
    Write-Step 'Removing the leftover Edge browser profile'
    $profile = Join-Path $env:LOCALAPPDATA 'Microsoft\Edge'
    if (Test-Path -LiteralPath $profile) {
        $mb = [math]::Round((Get-ChildItem -LiteralPath $profile -Recurse -File -Force -ErrorAction SilentlyContinue |
                     Measure-Object -Property Length -Sum).Sum / 1MB, 0)
        try {
            $microsoft = Get-Item -LiteralPath (Split-Path -Parent $profile) -Force -ErrorAction Stop
            if ($microsoft.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Profile parent is redirected.' }
            Assert-NoReparsePoints $profile
            Remove-Item -LiteralPath $profile -Recurse -Force -ErrorAction Stop
            Write-Info ('deleted {0} (~{1} MB)' -f $profile, $mb)
        }
        catch {
            $HadOperationError = $true
            Write-Warn ('could not fully delete {0}: {1}' -f $profile, $_.Exception.Message)
        }
    }
    else {
        Write-Info 'no leftover profile found'
    }
}
elseif (Test-Path -LiteralPath (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge')) {
    $mb = [math]::Round((Get-ChildItem -LiteralPath (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge') -Recurse -File -Force -ErrorAction SilentlyContinue |
                 Measure-Object -Property Length -Sum).Sum / 1MB, 0)
    Write-Info ('leftover browser profile kept (~{0} MB) - use -RemoveProfileData to delete it' -f $mb)
}

$state = Get-EdgeState
Show-EdgeState -State $state

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

Write-Host ''
if ($state.AppxQueryFailed -or $HadOperationError) {
    Write-Host 'Result: one or more operations/checks failed. Review the warnings above.' -ForegroundColor Yellow
    exit $ExitError
}

if (-not (Test-EdgePresent $state)) {
    Write-Host 'Result: system-level Microsoft Edge and checked remnants are absent.' -ForegroundColor Green
    Write-Info 'Windows updates may still restore Edge; shared EdgeCore/WebView2 files are kept.'
    if (-not $state.ReinstallBlocked) {
        Write-Info 'Note: the Edge Update install policy is not set.'
    }
    exit $ExitOk
}

Write-Host 'Result: Microsoft Edge is still present. See the messages above.' -ForegroundColor Yellow
exit $ExitStillPresent
