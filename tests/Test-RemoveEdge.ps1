#Requires -Version 5.1
<#
    Regression suite for remove-microsoft-edge.

    What it touches:
      * temporary fixture directories under %TEMP%, always deleted afterwards,
      * child PowerShell processes running harmless generated scripts,
      * one throwaway HKCU registry key, used to test the registry-link guard
        and deleted again in the finally block.

    What it never touches:
      * no UAC and no elevated process,
      * no real Edge uninstaller, no HKLM writes, no policy writes,
      * no existing Edge installation, profile, or file.
      The real-script checks are read-only modes only.
#>
[CmdletBinding()]
param([switch]$SkipMachineChecks)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$payloadPath = Join-Path $repo 'Remove-Edge.ps1'
$loaderPath = Join-Path $repo 'get.ps1'
$source = [IO.File]::ReadAllText($payloadPath)
$loader = [IO.File]::ReadAllText($loaderPath)
$script:passed = 0
$script:registryKeys = @()
$script:savedScriptPath = ''

function Assert {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:passed++
    Write-Host "PASS: $Message"
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Message)
    $threw = $false
    try { & $Action } catch { $threw = $true }
    Assert $threw $Message
}
function Get-Hash {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text.Replace("`r`n", "`n")))).Replace('-', '') }
    finally { $sha.Dispose() }
}
function Decode-Command {
    param($Relaunch)
    [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Relaunch.Args[-1]))
}
function Run-Child {
    param([string]$Command)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Command))
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded 2>&1 | Out-Null
    return $LASTEXITCODE
}
function New-TestRegistryKey {
    $key = "HKCU:\Software\remove-microsoft-edge-test-" + [guid]::NewGuid().ToString('N')
    $null = New-Item -Path $key -Force -ErrorAction Stop
    $script:registryKeys += $key
    return $key
}

foreach ($file in Get-ChildItem -LiteralPath $repo -Recurse -Filter '*.ps1') {
    $tokens = $null
    $errors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    Assert ($errors.Count -eq 0) "syntax: $($file.Name)"
}

# Load the actual initialization and helper functions, never the removal main.
$marker = '# ------------------------------------------------------------------- main ---'
$index = $source.IndexOf($marker)
Assert ($index -gt 0) 'main boundary exists'
$helpers = $source.Substring(0, $index)
. ([scriptblock]::Create($helpers)) -DryRun -RemoveProfileData -NoReinstallBlock -CreateRestorePoint -AllowNoOtherBrowser -NoElevate
$script:savedScriptPath = $ScriptPath
Assert ((@(Get-ForwardedArguments) -join ' ') -eq '-RemoveProfileData -NoReinstallBlock -CreateRestorePoint -DryRun -AllowNoOtherBrowser') 'script-bound switches preserved; NoElevate omitted'
$ScriptSwitches['VerifyOnly'] = $true
Assert (@(Get-ForwardedArguments) -contains '-VerifyOnly') 'VerifyOnly is preserved if a relaunch is requested'
Assert (@(Get-ForwardedArguments) -notcontains '-ExpectedPayloadSha256') 'integrity argument is never forwarded as a user switch'
$ScriptSwitches.Remove('VerifyOnly')

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('reme-test-' + [guid]::NewGuid().ToString('N'))
$savedEnv = @{}
foreach ($name in @('ProgramFiles', 'ProgramFiles(x86)', 'ProgramW6432', 'LOCALAPPDATA')) {
    $savedEnv[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
try {
    $pf = Join-Path $fixture "Program Files [test] O'Brien"
    $pf86 = Join-Path $fixture 'Program Files x86'
    $local = Join-Path $fixture 'Local'
    [IO.Directory]::CreateDirectory($pf) | Out-Null
    [IO.Directory]::CreateDirectory($pf86) | Out-Null
    [IO.Directory]::CreateDirectory($local) | Out-Null
    $env:ProgramFiles = $pf
    ${env:ProgramFiles(x86)} = $pf86
    $env:ProgramW6432 = $pf
    $env:LOCALAPPDATA = $local
    $app = Join-Path $pf 'Microsoft\Edge\Application'
    foreach ($version in @('99.0.0.1', '154.0.0.1')) {
        $installer = Join-Path $app "$version\Installer"
        [IO.Directory]::CreateDirectory($installer) | Out-Null
        [IO.File]::WriteAllText((Join-Path $installer 'setup.exe'), 'fixture only; never execute')
    }
    [IO.File]::WriteAllText((Join-Path $app 'msedge.exe'), 'fixture only')
    $shared = Join-Path $pf 'Microsoft\EdgeCore\154.0.0.1'
    [IO.Directory]::CreateDirectory($shared) | Out-Null
    [IO.File]::WriteAllText((Join-Path $shared 'msedge.exe'), 'shared sentinel')
    $webview = Join-Path $pf 'Microsoft\EdgeWebView\Application'
    [IO.Directory]::CreateDirectory($webview) | Out-Null
    [IO.File]::WriteAllText((Join-Path $webview 'msedgewebview2.exe'), 'webview sentinel')

    # ---- environment integrity -------------------------------------------
    $problems = @(Get-EnvironmentProblems)
    Assert ($problems.Count -ge 3) 'tampered environment variables are detected'
    Assert (@($problems | Where-Object { $_ -like '*LOCALAPPDATA*' }).Count -eq 1) 'LOCALAPPDATA tampering is reported by name'
    Assert (@($problems | Where-Object { $_ -like '*ProgramFiles*' }).Count -ge 1) 'ProgramFiles tampering is reported by name'
    Assert ((Get-EdgeProfilePath) -ne (Join-Path $local 'Microsoft\Edge')) 'profile path ignores a tampered LOCALAPPDATA'
    Assert ((Get-EdgeProfilePath).EndsWith('\Microsoft\Edge', [StringComparison]::OrdinalIgnoreCase)) 'profile path stays the Edge profile directory'
    Assert ((Get-TrustedTempRoot).StartsWith([Environment]::GetFolderPath('LocalApplicationData'), [StringComparison]::OrdinalIgnoreCase)) 'temporary root is derived from the registry, not $env:TEMP'
    Assert ((Get-TrustedPublicRoot) -match '^[A-Za-z]:\\Users\\Public$') 'public profile root is derived from the system drive'

    # ---- safe and unsafe paths -------------------------------------------
    Assert (@(Get-ProgramFilesRoots).Count -eq 2) 'environment roots deduplicated'
    $dirs = @(Get-EdgeApplicationDirs)
    Assert ($dirs.Count -eq 1 -and $dirs[0] -eq $app) 'discovery returns Application itself, not version children'
    $install = Get-ExistingEdgeInstall
    Assert ($install.Version -eq '154.0.0.1' -and $install.AppDir -eq $app) 'newest valid uninstaller found with literal spaced/bracket path'
    Assert (@(Test-EdgeExePresent).Count -eq 1) 'only browser Application binaries counted, not EdgeCore'
    Assert (-not (Test-SafeEdgeApplicationDir $shared)) 'shared EdgeCore path rejected for deletion'
    Assert (Test-SharedEdgeComponentPath $shared) 'EdgeCore recognised as a shared component'
    Assert (Test-SharedEdgeComponentPath (Join-Path $pf 'Microsoft\EdgeWebView\Application')) 'EdgeWebView recognised as a shared component'
    Assert (-not (Test-SharedEdgeComponentPath $app)) 'browser Application is not a shared component'
    $refused = $false
    try { Remove-EdgeApplicationDirectory $shared } catch { $refused = $true }
    Assert ($refused -and (Test-Path -LiteralPath $shared)) 'unsafe deletion rejected without touching shared payload'
    $webviewExe = Join-Path $webview 'msedgewebview2.exe'
    $refused = $false
    try { Remove-EdgeApplicationDirectory $webview } catch { $refused = $true }
    Assert ($refused -and (Test-Path -LiteralPath $webviewExe)) 'WebView2 payload refused and left in place'

    # ---- unexpected filesystem state -------------------------------------
    $noSetup = Join-Path $app '200.0.0.0\Installer'
    [IO.Directory]::CreateDirectory($noSetup) | Out-Null
    [IO.Directory]::CreateDirectory((Join-Path $app 'not-a-version')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $app 'not-a-version\msedge.exe'), 'decoy')
    $install = Get-ExistingEdgeInstall
    Assert ($install.Version -eq '154.0.0.1') 'newer version directory without an uninstaller is ignored'
    Assert (@(Test-EdgeExePresent).Count -eq 2) 'decoy binaries are still reported as present, not trusted'
    [IO.Directory]::CreateDirectory((Join-Path $app '200.0.0.0\Installer')) | Out-Null
    [IO.File]::WriteAllText((Join-Path $app '200.0.0.0\Installer\setup.exe'), 'fixture only')
    Assert ((Get-ExistingEdgeInstall).Version -eq '200.0.0.0') 'a genuinely newer install wins'
    Remove-Item -LiteralPath (Join-Path $app '200.0.0.0') -Recurse -Force
    Remove-Item -LiteralPath (Join-Path $app 'not-a-version') -Recurse -Force

    # ---- sibling preservation and real removal ---------------------------
    $sibling = Join-Path (Split-Path -Parent $app) 'keep.txt'
    [IO.File]::WriteAllText($sibling, 'keep')
    Remove-EdgeApplicationDirectory $app
    Assert (-not (Test-Path -LiteralPath $app)) 'fixture Application removed'
    Assert ((Test-Path -LiteralPath $sibling) -and (Test-Path -LiteralPath $shared) -and (Test-Path -LiteralPath $webviewExe)) 'siblings and shared runtimes retained'
    Remove-EdgeApplicationDirectory $app
    Assert (Test-Path -LiteralPath $sibling) 'repeat cleanup with absent Application is harmless'
    Remove-Item -LiteralPath $sibling
    Remove-EdgeApplicationDirectory $app
    Assert (-not (Test-Path -LiteralPath (Split-Path -Parent $app))) 'empty Edge parent removed'

    # ---- reparse points and symlinks -------------------------------------
    # New-Item resolves wildcards in the provider paths it is given, so the
    # junction fixtures use a bracket-free root while the rest of the suite
    # keeps testing awkward characters.
    $simplePf = Join-Path $fixture 'Simple\Program Files'
    $simpleApp = Join-Path $simplePf 'Microsoft\Edge\Application'
    $simpleShared = Join-Path $simplePf 'Microsoft\EdgeCore\1.0.0.0'
    [IO.Directory]::CreateDirectory($simpleApp) | Out-Null
    [IO.Directory]::CreateDirectory($simpleShared) | Out-Null
    [IO.File]::WriteAllText((Join-Path $simpleShared 'msedge.exe'), 'shared sentinel')
    $env:ProgramFiles = $simplePf
    $env:ProgramW6432 = $simplePf
    $junction = Join-Path $simpleApp 'redirected'
    $junctionMade = $false
    try {
        $null = New-Item -ItemType Junction -Path $junction -Target $simpleShared -ErrorAction Stop
        $junctionMade = $true
    }
    catch {
        Write-Host ('SKIP: junction creation unavailable ({0}).' -f $_.Exception.Message)
    }
    if ($junctionMade) {
        $redirected = Get-Item -LiteralPath $junction -Force
        Assert ($redirected.Attributes -band [IO.FileAttributes]::ReparsePoint) 'fixture really contains a reparse point'
        Assert-Throws { Assert-NoReparsePoints $simpleApp } 'a reparse point inside the tree is refused'
        $refused = $false
        try { Remove-EdgeApplicationDirectory $simpleApp } catch { $refused = $true }
        Assert ($refused -and (Test-Path -LiteralPath (Join-Path $simpleShared 'msedge.exe'))) 'deletion refused for a tree containing a junction'
        # [IO.Directory]::Delete removes the junction itself. Remove-Item on a
        # reparse point is not reliable in Windows PowerShell 5.1.
        [IO.Directory]::Delete($junction)
        Assert (-not (Test-Path -LiteralPath $junction)) 'junction removed for the next check'
    }
    Remove-Item -LiteralPath $simpleApp -Recurse -Force
    $redirectMade = $false
    try {
        $null = New-Item -ItemType Junction -Path $simpleApp -Target $simpleShared -ErrorAction Stop
        $redirectMade = $true
    }
    catch {
        Write-Host ('SKIP: redirected Application junction could not be created ({0}).' -f $_.Exception.Message)
    }
    if ($redirectMade) {
        Assert (-not (Test-SafeEdgeApplicationDir $simpleApp)) 'a redirected Application directory is never treated as safe'
        Assert-Throws { Get-EdgeApplicationDirs } 'discovery refuses a redirected Application directory'
        [IO.Directory]::Delete($simpleApp)
        Assert (-not (Test-Path -LiteralPath $simpleApp)) 'redirected Application link removed again'
    }
    $env:ProgramFiles = $pf
    $env:ProgramW6432 = $pf
    Assert (-not (Test-Path -LiteralPath $app)) 'browser Application is gone before the state checks'

    # ---- alternative browsers --------------------------------------------
    Assert (@(Get-InstalledBrowsers).Count -eq 0) 'zero alternative browsers is safe under StrictMode'
    $chrome = Join-Path $local 'Google\Chrome\Application'
    [IO.Directory]::CreateDirectory($chrome) | Out-Null
    [IO.File]::WriteAllText((Join-Path $chrome 'chrome.exe'), 'fixture')
    Assert (@(Get-InstalledBrowsers).Count -eq 1) 'single per-user alternative browser detected'
    Remove-Item -LiteralPath $chrome -Recurse -Force
    Assert (@(Get-InstalledBrowsers).Count -eq 0) 'browser detection follows the file system'

    # ---- registry boundaries ---------------------------------------------
    $keys = @(Get-EdgeRegistryPaths)
    Assert ($keys.Count -eq 8 -and @($keys | Sort-Object -Unique).Count -eq 8) 'eight separate registry paths without array/concatenation precedence bug'
    Assert (@($keys | Where-Object { $_ -like "*$WebView2ProductGuid*" }).Count -eq 0) 'WebView2 product registration never targeted'
    Assert (@($keys | Where-Object { $_ -like '*EdgeWebView*' -or $_ -like '*EdgeCore*' }).Count -eq 0) 'shared Edge components are never in the registry path list'
    Assert (@($keys | Where-Object { Test-EdgeRegistryPathAllowed $_ }).Count -eq 8) 'every generated registry path passes the deletion allowlist'
    $rejectedKeys = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\$WebView2ProductGuid",
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate\Clients\{00000000-0000-0000-0000-000000000000}",
        'HKLM:\SOFTWARE\Microsoft',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Beta',
        'HKLM:\SOFTWARE\Microsoft\EdgeUpdate',
        'HKLM:\SOFTWARE\Clients\StartMenuInternet\Microsoft EdgeCore',
        'HKLM:\SOFTWARE\Clients\StartMenuInternet\*',
        ''
    )
    foreach ($key in $rejectedKeys) {
        Assert (-not (Test-EdgeRegistryPathAllowed $key)) "deletion allowlist rejects: $key"
    }
    Assert (@(Get-EdgeShortcutPaths).Count -ge 2) 'shortcut candidates are enumerated'
    Assert (@(Get-EdgeShortcutPaths | Where-Object { Test-EdgeShortcutPathAllowed $_ }).Count -eq @(Get-EdgeShortcutPaths).Count) 'every enumerated shortcut is allowed'
    Assert (-not (Test-EdgeShortcutPathAllowed (Join-Path $fixture 'Microsoft Edge.lnk'))) 'a shortcut outside the known locations is rejected'
    Assert (@(Get-EdgeShortcutPaths | Where-Object { $_ -match 'EdgeWebView|EdgeCore' }).Count -eq 0) 'no shared-runtime shortcut is ever a target'

    $testKey = New-TestRegistryKey
    Assert (Test-RegistryKeyNotLinked $testKey) 'an ordinary registry key is not treated as a link'
    $null = New-ItemProperty -Path $testKey -Name 'SymbolicLinkValue' -Value '\REGISTRY\MACHINE\SOFTWARE' -PropertyType String -Force
    Assert (-not (Test-RegistryKeyNotLinked $testKey)) 'a registry symbolic link is refused before deletion'
    Assert (-not (Test-EdgeRegistryPathAllowed $testKey)) 'a test key outside the allowlist would be refused anyway'

    # ---- WebView2 preservation -------------------------------------------
    $webviewState = [pscustomobject]@{ WebView2 = $true }
    Assert ($webviewState.WebView2) 'WebView2 detected in fixture state'
    Assert (Test-EdgeAppxIdentity ([pscustomobject]@{ Name = 'Microsoft.MicrosoftEdge.Stable'; PackageFamilyName = 'Microsoft.MicrosoftEdge.Stable_8wekyb3d8bbwe'; PackageFullName = 'Microsoft.MicrosoftEdge.Stable_1.0.0.0_x64__8wekyb3d8bbwe' })) 'exact stable Edge package identity accepted'
    $wrongPackages = @(
        [pscustomobject]@{ Name = 'Microsoft.MicrosoftEdge.Stable.Beta' },
        [pscustomobject]@{ Name = 'Microsoft.MicrosoftEdgeDevToolsClient' },
        [pscustomobject]@{ Name = 'Microsoft.WebView2' },
        [pscustomobject]@{ Name = 'Microsoft.MicrosoftEdge.Stable'; PackageFamilyName = 'Microsoft.WebView2_8wekyb3d8bbwe' },
        [pscustomobject]@{ Name = 'Microsoft.MicrosoftEdge.Stable'; PackageFullName = 'Contoso.Browser_1.0.0.0_x64__abc' },
        $null
    )
    foreach ($package in $wrongPackages) {
        $label = if ($package) { [string]$package.Name } else { '(null)' }
        Assert (-not (Test-EdgeAppxIdentity $package)) "package identity rejected: $label"
    }

    # ---- removal outcome rules ------------------------------------------
    $state = [pscustomobject]@{ EdgeExe = @(); UserEdgeExe = $false; AppDirs = @(); ClientKey = $false; ArpEntry = $false; Appx = $false; ProvisionedAppx = $false; Shortcuts = $false; BrowserClient = $false; AppPaths = $false; AppxQueryFailed = $false }
    Assert (-not (Test-EdgePresent $state)) 'clean state is clean'
    foreach ($name in @('UserEdgeExe', 'ClientKey', 'ArpEntry', 'Appx', 'ProvisionedAppx', 'Shortcuts', 'BrowserClient', 'AppPaths')) {
        $state.$name = $true
        Assert (Test-EdgePresent $state) "success predicate includes $name"
        $state.$name = $false
    }
    $state.AppDirs = @($app)
    Assert (Test-EdgePresent $state) 'leftover Application directories prevent false success'
    $state.AppDirs = @()
    $state.EdgeExe = @('fixture.exe')
    Assert (Test-EdgePresent $state) 'browser binaries prevent false success'
    $state.EdgeExe = @()
    Assert ((Get-RemovalOutcome -State $state -HadOperationError $false) -eq 0) 'successful removal reports success'
    Assert ((Get-RemovalOutcome -State $state -HadOperationError $true) -eq 3) 'a failed operation prevents a success report'
    $state.AppxQueryFailed = $true
    Assert ((Get-RemovalOutcome -State $state -HadOperationError $false) -eq 3) 'a failed package query is never reported as success'
    $state.AppxQueryFailed = $false
    $state.Appx = $true
    Assert ((Get-RemovalOutcome -State $state -HadOperationError $false) -eq 1) 'a surviving package prevents a success report'
    $state.Appx = $false
    $state.Shortcuts = $true
    Assert ((Get-RemovalOutcome -State $state -HadOperationError $false) -eq 1) 'a surviving shortcut prevents a success report'

    # ---- profile deletion is opt-in and constrained ----------------------
    $trustedProfile = Get-EdgeProfilePath
    Assert (Test-SafeProfilePath $trustedProfile) 'the current account Edge profile is recognised'
    $unsafeProfiles = @(
        (Join-Path $env:LOCALAPPDATA 'Microsoft\EdgeWebView'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\EdgeCore'),
        (Join-Path $env:LOCALAPPDATA 'Microsoft\Edge\..'),
        "$trustedProfile\",
        (Join-Path $env:LOCALAPPDATA 'Microsoft'),
        (Join-Path $env:SystemRoot 'Microsoft\Edge'),
        (Join-Path $local 'Microsoft\Edge'),
        ''
    )
    foreach ($unsafe in $unsafeProfiles) {
        Assert (-not (Test-SafeProfilePath $unsafe)) "profile deletion rejected: $unsafe"
    }

    # ---- pinned payload source ------------------------------------------
    $pinnedUrl = "https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/Remove-Edge.ps1"
    $pinnedHash = 'A' * 64
    Assert (Test-PinnedPayloadSource -Url $pinnedUrl -Sha256 $pinnedHash) 'the pinned release URL is accepted'
    $badSources = @(
        @{ Url = 'http://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/Remove-Edge.ps1'; Sha = $pinnedHash },
        @{ Url = 'https://example.invalid/onion3130/remove-microsoft-edge/v1.0.1/Remove-Edge.ps1'; Sha = $pinnedHash },
        @{ Url = 'https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/main/Remove-Edge.ps1'; Sha = $pinnedHash },
        @{ Url = 'https://raw.githubusercontent.com/attacker/remove-microsoft-edge/v1.0.1/Remove-Edge.ps1'; Sha = $pinnedHash },
        @{ Url = $pinnedUrl; Sha = '' },
        @{ Url = $pinnedUrl; Sha = 'not-a-hash' },
        @{ Url = $pinnedUrl; Sha = 'A' * 63 },
        @{ Url = ''; Sha = $pinnedHash }
    )
    foreach ($bad in $badSources) {
        Assert (-not (Test-PinnedPayloadSource -Url $bad.Url -Sha256 $bad.Sha)) "unpinned source rejected: $($bad.Url) / '$($bad.Sha)'"
    }

    # ---- self integrity --------------------------------------------------
    $copy = Join-Path $fixture 'Remove-Edge-copy.ps1'
    [IO.File]::WriteAllText($copy, $source)
    $ScriptPath = $copy
    Assert ((Get-SelfSha256) -eq (Get-Hash $source)) 'self checksum matches the LF-normalized file'
    Assert-SelfIntegrity -ExpectedSha256 (Get-Hash $source)
    Assert $true 'a matching checksum passes the self integrity check'
    Assert-Throws { Assert-SelfIntegrity -ExpectedSha256 ('B' * 64) } 'a replaced payload fails the self integrity check'
    Assert-Throws { Assert-SelfIntegrity -ExpectedSha256 'nope' } 'a malformed expected checksum fails the self integrity check'
    Assert-Throws { Assert-SelfIntegrity -ExpectedSha256 'C' * 64 } 'a missing payload file fails the self integrity check'
    $ScriptPath = $script:savedScriptPath

    # ---- other safe helpers ---------------------------------------------
    $unsigned = Join-Path $fixture 'unsigned-setup.exe'
    [IO.File]::WriteAllText($unsigned, 'fixture only; never execute')
    Assert ((Get-SignatureVerdict -Path $unsigned).Verdict -eq 'Untrusted') 'a file with no valid signature is never treated as trusted'
    Assert ((Get-SignatureVerdict -Path (Join-Path $fixture 'no-such-setup.exe')).Verdict -eq 'Untrusted') 'a missing uninstaller is untrusted'
    $statusVerdicts = @{
        'Valid'                = 'Valid'
        'NotTrusted'           = 'Unknown'
        'NotSigned'            = 'Untrusted'
        'HashMismatch'         = 'Untrusted'
        'UnknownError'         = 'Untrusted'
        'NotSupportedFileFormat' = 'Untrusted'
        'Incompatible'         = 'Untrusted'
    }
    foreach ($status in $statusVerdicts.Keys) {
        Assert ((Get-SignatureStatusVerdict $status) -eq $statusVerdicts[$status]) "signature status '$status' maps to $($statusVerdicts[$status])"
    }
    foreach ($status in [enum]::GetNames([System.Management.Automation.SignatureStatus])) {
        Assert ((Get-SignatureStatusVerdict $status) -in @('Valid', 'Unknown', 'Untrusted')) "signature status '$status' is always decided"
    }
    Assert (Test-Path -LiteralPath (Get-PowerShellHostPath) -PathType Leaf) 'the relaunch host is an absolute existing PowerShell'
    Assert ((Get-PowerShellHostPath) -notmatch ' ') 'the relaunch host needs no quoting'
}
finally {
    $ScriptPath = $script:savedScriptPath
    foreach ($name in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process') }
    foreach ($key in $script:registryKeys) {
        if (Test-Path -LiteralPath $key) { Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if (Test-Path -LiteralPath $fixture) {
        Get-ChildItem -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint } |
            ForEach-Object { try { [IO.Directory]::Delete($_.FullName) } catch { } }
        Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------- elevation and relaunch tests ---

$childFixture = Join-Path ([IO.Path]::GetTempPath()) ('reme-child-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($childFixture) | Out-Null
try {
    # Argument injection: only a fixed whitelist of switches may be forwarded,
    # and each must be a bare switch with no value to smuggle anything through.
    foreach ($argument in Get-ForwardedArguments) {
        Assert ($argument -match '^-[A-Za-z]+$') "forwarded argument is a bare switch: $argument"
    }

    $output = Join-Path $childFixture 'child.json'
    $marker = Join-Path $childFixture 'executed.marker'
    $quotedOutput = $output.Replace("'", "''")
    $quotedMarker = $marker.Replace("'", "''")
    $target = Join-Path $childFixture "safe child O'Brien.ps1"
    [IO.File]::WriteAllText($target, @"
param([switch]`$VerifyOnly, [switch]`$RemoveProfileData, [switch]`$NoReinstallBlock, [switch]`$CreateRestorePoint, [switch]`$DryRun, [switch]`$AllowNoOtherBrowser, [string]`$ExpectedPayloadSha256)
`$PSBoundParameters | ConvertTo-Json | Set-Content -LiteralPath '$quotedOutput'
if (`$ExpectedPayloadSha256 -notmatch '^[0-9a-fA-F]{64}$') { exit 9 }
[IO.File]::WriteAllText('$quotedMarker', 'executed')
"@)
    $ScriptPath = $target
    $relaunch = Get-SelfRelaunch
    Assert ($relaunch.Kind -eq 'file' -and $relaunch.Args[-2] -eq '-EncodedCommand') 'file relaunch uses encoded command'
    $command = Decode-Command $relaunch
    Assert ($command -match '-ExpectedPayloadSha256 ''[0-9a-fA-F]{64}''') 'file relaunch pins the checksum of the file it will run'
    Assert ((Get-SelfSha256) -eq (Get-TextSha256 ([IO.File]::ReadAllText($target)))) 'pinned checksum describes this exact file'
    $argsWithoutNoExit = @($relaunch.Args | Where-Object { $_ -ne '-NoExit' })
    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argsWithoutNoExit -Wait -PassThru
    Assert ($proc.ExitCode -eq 0) 'actual non-elevated child handles spaces, brackets, and apostrophes'
    $received = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    Assert ($received.DryRun -and $received.RemoveProfileData -and $received.NoReinstallBlock -and $received.CreateRestorePoint -and $received.AllowNoOtherBrowser) 'all requested switches reach actual file child'
    Assert ($received.ExpectedPayloadSha256 -match '^[0-9a-fA-F]{64}$') 'elevated child receives the checksum it must match'

    # URL relaunch: the elevated child must re-fetch the pinned payload and
    # refuse to execute anything that does not match.
    $ScriptPath = ''
    $pinned = 'https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/Remove-Edge.ps1'
    $escapedMarker = $marker.Replace("'", "''")
    $benignExit = "param([switch]`$DryRun,[switch]`$RemoveProfileData,[switch]`$NoReinstallBlock,[switch]`$CreateRestorePoint,[switch]`$AllowNoOtherBrowser); " +
        "if (-not (`$DryRun -and `$RemoveProfileData -and `$NoReinstallBlock -and `$CreateRestorePoint -and `$AllowNoOtherBrowser)) { throw 'lost switches' }; " +
        "[IO.File]::WriteAllText('$escapedMarker', 'executed'); exit 1"
    $mock = @"
function Invoke-WebRequest {
    param(`$Uri, [switch]`$UseBasicParsing, `$TimeoutSec, `$ErrorAction)
    if (`$Uri -ne '$pinned') { throw 'wrong URL' }
    `$response = [pscustomobject]@{ Content = '$($benignExit.Replace("'", "''"))' }
    `$response | Add-Member -NotePropertyName BaseResponse -NotePropertyValue (
        [pscustomobject]@{ ResponseUri = [Uri]'$pinned' }) -Force
    return `$response
}
"@
    $RemoveEdgeUrl = $pinned
    $RemoveEdgeSha256 = Get-Hash $benignExit
    if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force }
    Assert ((Run-Child ($mock + (Decode-Command (Get-SelfRelaunch)) + '; exit $global:LASTEXITCODE')) -eq 1) 'URL relaunch executes the verified payload and surfaces its exit code'
    Assert (Test-Path -LiteralPath $marker) 'verified payload really did run'

    $tempLeftovers = @(Get-ChildItem -LiteralPath ([Environment]::GetFolderPath('LocalApplicationData')) -Directory -Filter 'RemoveEdge-*' -ErrorAction SilentlyContinue)
    Assert ($tempLeftovers.Count -eq 0) 'the temporary copy of the payload is removed again'

    if (Test-Path -LiteralPath $marker) { Remove-Item -LiteralPath $marker -Force }
    $RemoveEdgeSha256 = '0' * 64
    Assert ((Run-Child ($mock + (Decode-Command (Get-SelfRelaunch)) + '; exit $global:LASTEXITCODE')) -eq 3) 'elevated relaunch fails closed on a checksum mismatch'
    Assert (-not (Test-Path -LiteralPath $marker)) 'a mismatched payload is never executed'

    $wrongHostMock = $mock.Replace($pinned, 'https://raw.githubusercontent.com.evil.invalid/x/v1.0.1/Remove-Edge.ps1')
    $RemoveEdgeSha256 = Get-Hash $benignExit
    Assert ((Run-Child ($wrongHostMock + (Decode-Command (Get-SelfRelaunch)) + '; exit $global:LASTEXITCODE')) -eq 3) 'elevated relaunch fails closed when served from another host'
    Assert (-not (Test-Path -LiteralPath $marker)) 'a payload from another host is never executed'

    $RemoveEdgeSha256 = ''
    Assert ($null -eq (Get-SelfRelaunch)) 'without a checksum there is no relaunch at all'
    $RemoveEdgeUrl = 'https://example.invalid/Remove-Edge.ps1'
    $RemoveEdgeSha256 = Get-Hash $benignExit
    Assert ($null -eq (Get-SelfRelaunch)) 'an unpinned download location gets no relaunch'
    $RemoveEdgeUrl = ''
}
finally {
    $ScriptPath = $script:savedScriptPath
    if (Test-Path -LiteralPath $childFixture) { Remove-Item -LiteralPath $childFixture -Recurse -Force -ErrorAction SilentlyContinue }
}

# ---------------------------------------------------------------- loader ---

$expectedHash = [regex]::Match($loader, "\`$RemoveEdgeSha256 = '([A-Fa-f0-9]{64})'")
Assert $expectedHash.Success 'loader contains a concrete payload checksum'
Assert ((Get-Hash $source) -eq $expectedHash.Groups[1].Value) 'published payload checksum matches source (LF-normalized UTF-8)'

$loaderTokens = $null
$loaderErrors = $null
$loaderAst = [Management.Automation.Language.Parser]::ParseFile($loaderPath, [ref]$loaderTokens, [ref]$loaderErrors)
$loaderParameters = @($loaderAst.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
Assert (($loaderParameters -join ',') -eq 'VerifyOnly,RemoveProfileData,NoReinstallBlock,CreateRestorePoint,DryRun,NoElevate,AllowNoOtherBrowser') 'loader exposes only switches, so no parameter can change the payload or its checksum'
Assert ($loader -match [regex]::Escape("https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v")) 'loader pins the download host and a version tag'
Assert ($loader -match [regex]::Escape('$AllowedPayloadHost = ''raw.githubusercontent.com''')) 'loader hard-codes the only allowed download host'
Assert ($loader -match '\$PayloadTag = ''v[0-9]+(\.[0-9]+)+''') 'loader pins a numeric version tag, not a moving branch'
Assert ($loader -match [regex]::Escape('$RemoveEdgeUrl = "https://$AllowedPayloadHost/$PayloadRepository/$PayloadTag/Remove-Edge.ps1"')) 'payload URL is composed only from pinned values'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo 'Stamp-Checksum.ps1') -Check | Out-Null
Assert ($LASTEXITCODE -eq 0) 'the release checksum tool agrees with the stamped value'

# The loader executes the payload only after verifying it. Each case below runs
# the real loader with a mocked download; only the expected checksum is
# substituted. The stand-in payload starts with #Requires and records that it
# ran, so "did not execute" is a real observation rather than an assumption.
$loaderMarker = Join-Path ([IO.Path]::GetTempPath()) ('reme-loader-' + [guid]::NewGuid().ToString('N') + '.marker')
$escapedLoaderMarker = $loaderMarker.Replace("'", "''")
$benignLoader = @"
#Requires -Version 5.1
param([switch]`$DryRun,[switch]`$VerifyOnly)
if (-not (`$DryRun -and `$VerifyOnly)) { throw 'loader lost flags' }
[IO.File]::WriteAllText('$escapedLoaderMarker', 'loader ran')
'loader-safe'
"@
try {
    $downloadMock = @"
function Invoke-WebRequest {
    param(`$Uri, [switch]`$UseBasicParsing, `$TimeoutSec, `$ErrorAction)
    [pscustomobject]@{ Content = '$($benignLoader.Replace("'", "''"))'; BaseResponse = [pscustomobject]@{ ResponseUri = [Uri]'https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/Remove-Edge.ps1' } }
}
"@
    $safeLoader = $loader.Replace($expectedHash.Groups[1].Value, (Get-Hash $benignLoader))
    function Invoke-WebRequest { param($Uri, [switch]$UseBasicParsing, $TimeoutSec, $ErrorAction); [pscustomobject]@{ Content = $benignLoader; BaseResponse = [pscustomobject]@{ ResponseUri = [Uri]'https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/Remove-Edge.ps1' } } }
    $loaderResult = & ([scriptblock]::Create($safeLoader)) -DryRun -VerifyOnly
    Assert ($loaderResult -eq 'loader-safe') 'actual loader forwards read-only switches to the verified scriptblock'
    Assert (Test-Path -LiteralPath $loaderMarker) 'the verified payload really ran'
    Remove-Item -LiteralPath $loaderMarker -Force

    $mismatched = $loader.Replace($expectedHash.Groups[1].Value, '0' * 64)
    $escapedLoader = $mismatched.Replace("'", "''")
    Assert ((Run-Child ($downloadMock + "& ([scriptblock]::Create('$escapedLoader')) -DryRun -VerifyOnly; exit `$global:LASTEXITCODE")) -eq 3) 'loader fails closed when the payload does not match its checksum'
    Assert (-not (Test-Path -LiteralPath $loaderMarker)) 'loader never executes an unverified payload'

    $unsigned = $loader.Replace("`$RemoveEdgeSha256 = '$($expectedHash.Groups[1].Value)'", "`$RemoveEdgeSha256 = 'REPLACE_WITH_PAYLOAD_SHA256'")
    $escapedUnsigned = $unsigned.Replace("'", "''")
    Assert ((Run-Child ($downloadMock + "& ([scriptblock]::Create('$escapedUnsigned')) -DryRun -VerifyOnly; exit `$global:LASTEXITCODE")) -eq 3) 'loader fails closed when it has no usable checksum'
    Assert (-not (Test-Path -LiteralPath $loaderMarker)) 'loader never executes without a checksum'

    $notTheScript = $loader.Replace($expectedHash.Groups[1].Value, (Get-Hash '#not the expected script'))
    $escapedNotScript = $notTheScript.Replace("'", "''")
    Assert ((Run-Child ($downloadMock + "& ([scriptblock]::Create('$escapedNotScript')) -DryRun -VerifyOnly; exit `$global:LASTEXITCODE")) -eq 3) 'loader refuses a payload that is not the expected script'
    Assert (-not (Test-Path -LiteralPath $loaderMarker)) 'an unexpected file is never executed'
}
finally {
    if (Test-Path -LiteralPath $loaderMarker) { Remove-Item -LiteralPath $loaderMarker -Force -ErrorAction SilentlyContinue }
}

# Real-script read-only smoke checks. CI's Windows Server images are outside
# the tool's supported desktop scope; they run fixtures only.
if (-not $SkipMachineChecks) {
    $policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate'
    $policyName = "Install$EdgeProductGuid"
    $policyBefore = $null
    try { $policyBefore = (Get-ItemProperty -Path $policyKey -Name $policyName -ErrorAction Stop).$policyName } catch { }
    $profileBefore = Test-Path -LiteralPath (Get-EdgeProfilePath)

    $dryRunText = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $payloadPath -DryRun -NoElevate 2>&1 | Out-String)
    Assert ($LASTEXITCODE -eq 0) 'actual DryRun returns zero without UAC or changes'
    Assert ($dryRunText -match 'Nothing was changed\.') 'dry run says plainly that nothing changed'

    $profileDryRunText = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $payloadPath -DryRun -RemoveProfileData -NoElevate 2>&1 | Out-String)
    Assert ($profileDryRunText -match 'Would irreversibly delete') 'profile deletion is only ever planned when explicitly requested'
    Assert (-not ($dryRunText -match 'Would irreversibly delete')) 'profile deletion is not part of a normal dry run'

    $policyDryRunText = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $payloadPath -DryRun -NoReinstallBlock -NoElevate 2>&1 | Out-String)
    Assert ($dryRunText -match 'Would set HKLM\\SOFTWARE\\Policies\\Microsoft\\EdgeUpdate') 'a dry run states the reinstall policy it would set'
    Assert (-not ($policyDryRunText -match 'Would set HKLM\\SOFTWARE\\Policies\\Microsoft\\EdgeUpdate')) '-NoReinstallBlock suppresses the policy even in a dry run'

    $policyAfter = $null
    try { $policyAfter = (Get-ItemProperty -Path $policyKey -Name $policyName -ErrorAction Stop).$policyName } catch { }
    Assert ($policyAfter -eq $policyBefore) 'read-only modes never change the reinstall policy'
    Assert ((Test-Path -LiteralPath (Get-EdgeProfilePath)) -eq $profileBefore) 'read-only modes never touch the profile directory'

    $verifyText = (& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $payloadPath -VerifyOnly -NoElevate 2>&1 | Out-String)
    $verifyCode = $LASTEXITCODE
    Assert ($verifyCode -in @(0, 1, 3)) 'actual VerifyOnly returns a meaningful checked-state status without UAC'
    if ($verifyText -match 'verify all users') {
        Assert ($verifyCode -eq 1) 'an incomplete scope is never reported as a clean result'
    }
    else {
        Assert ($verifyCode -eq 0) 'a complete scope with nothing found is reported as clean'
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $payloadPath -NoElevate
        Assert ($LASTEXITCODE -eq 2) 'actual non-admin removal refuses without UAC'
    }
    else {
        Write-Host 'SKIP: non-admin gate smoke check (this test host is already elevated).'
    }
}
Write-Host "All $script:passed assertions passed. No installation changes were made."
# Expected child failures must not leak into CI's automatic LASTEXITCODE check.
$global:LASTEXITCODE = 0