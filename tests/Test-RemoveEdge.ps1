#Requires -Version 5.1
# No UAC, registry writes, real uninstallers, or production directory deletion.
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

function Assert {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "FAIL: $Message" }
    $script:passed++
    Write-Host "PASS: $Message"
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
Assert ((@(Get-ForwardedArguments) -join ' ') -eq '-RemoveProfileData -NoReinstallBlock -CreateRestorePoint -DryRun -AllowNoOtherBrowser') 'script-bound switches preserved; NoElevate omitted'
$ScriptSwitches['VerifyOnly'] = $true
Assert (@(Get-ForwardedArguments) -contains '-VerifyOnly') 'VerifyOnly is preserved if a relaunch is requested'

$fixture = Join-Path $repo ('.test-fixture-' + [guid]::NewGuid().ToString('N'))
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
    Assert (@(Get-ProgramFilesRoots).Count -eq 2) 'environment roots deduplicated'
    $dirs = @(Get-EdgeApplicationDirs)
    Assert ($dirs.Count -eq 1 -and $dirs[0] -eq $app) 'discovery returns Application itself, not version children'
    $install = Get-ExistingEdgeInstall
    Assert ($install.Version -eq '154.0.0.1' -and $install.AppDir -eq $app) 'newest valid uninstaller found with literal spaced/bracket path'
    Assert (@(Test-EdgeExePresent).Count -eq 1) 'only browser Application binaries counted, not EdgeCore'
    Assert (-not (Test-SafeEdgeApplicationDir $shared)) 'shared EdgeCore path rejected for deletion'
    $refused = $false
    try { Remove-EdgeApplicationDirectory $shared } catch { $refused = $true }
    Assert ($refused -and (Test-Path -LiteralPath $shared)) 'unsafe deletion rejected without touching shared payload'
    $sibling = Join-Path (Split-Path -Parent $app) 'keep.txt'
    [IO.File]::WriteAllText($sibling, 'keep')
    Remove-EdgeApplicationDirectory $app
    Assert (-not (Test-Path -LiteralPath $app)) 'fixture Application removed'
    Assert ((Test-Path -LiteralPath $sibling) -and (Test-Path -LiteralPath $shared) -and (Test-Path -LiteralPath $webview)) 'siblings and shared runtimes retained'
    Remove-EdgeApplicationDirectory $app
    Assert (Test-Path -LiteralPath $sibling) 'repeat cleanup with absent Application is harmless'
    Remove-Item -LiteralPath $sibling
    Remove-EdgeApplicationDirectory $app
    Assert (-not (Test-Path -LiteralPath (Split-Path -Parent $app))) 'empty Edge parent removed'

    Assert (@(Get-InstalledBrowsers).Count -eq 0) 'zero alternative browsers is safe under StrictMode'
    $chrome = Join-Path $local 'Google\Chrome\Application'
    [IO.Directory]::CreateDirectory($chrome) | Out-Null
    [IO.File]::WriteAllText((Join-Path $chrome 'chrome.exe'), 'fixture')
    Assert (@(Get-InstalledBrowsers).Count -eq 1) 'single per-user alternative browser detected'

    $keys = @(Get-EdgeRegistryPaths)
    Assert ($keys.Count -eq 8 -and @($keys | Sort-Object -Unique).Count -eq 8) 'eight separate registry paths without array/concatenation precedence bug'
    Assert (@($keys | Where-Object { $_ -like "*$WebView2ProductGuid*" }).Count -eq 0) 'WebView2 product registration never targeted'
    $state = [pscustomobject]@{ EdgeExe = @(); UserEdgeExe = $false; AppDirs = @(); ClientKey = $false; ArpEntry = $false; Appx = $false; ProvisionedAppx = $false; Shortcuts = $false; BrowserClient = $false; AppPaths = $false }
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

    $target = Join-Path $pf "safe child O'Brien.ps1"
    $output = Join-Path $fixture 'child.json'
    $quotedOutput = $output.Replace("'", "''")
    [IO.File]::WriteAllText($target, @"
param([switch]`$VerifyOnly, [switch]`$RemoveProfileData, [switch]`$NoReinstallBlock, [switch]`$CreateRestorePoint, [switch]`$DryRun, [switch]`$AllowNoOtherBrowser)
`$PSBoundParameters | ConvertTo-Json | Set-Content -LiteralPath '$quotedOutput'
"@)
    $ScriptPath = $target
    $relaunch = Get-SelfRelaunch
    Assert ($relaunch.Kind -eq 'file' -and $relaunch.Args[-2] -eq '-EncodedCommand') 'file relaunch uses encoded command'
    $argsWithoutNoExit = @($relaunch.Args | Where-Object { $_ -ne '-NoExit' })
    $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argsWithoutNoExit -Wait -PassThru
    Assert ($proc.ExitCode -eq 0) 'actual non-elevated child handles spaces, brackets, and apostrophes'
    $received = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
    Assert ($received.VerifyOnly -and $received.DryRun -and $received.RemoveProfileData -and $received.NoReinstallBlock -and $received.CreateRestorePoint -and $received.AllowNoOtherBrowser) 'all switches reach actual file child'

    $ScriptPath = ''
    $RemoveEdgeUrl = "https://example.invalid/path's/Remove-Edge.ps1"
    $benign = 'param([switch]$VerifyOnly,[switch]$DryRun,[switch]$RemoveProfileData,[switch]$NoReinstallBlock,[switch]$CreateRestorePoint,[switch]$AllowNoOtherBrowser); if (-not ($VerifyOnly -and $DryRun -and $RemoveProfileData -and $NoReinstallBlock -and $CreateRestorePoint -and $AllowNoOtherBrowser)) { throw "lost switches" }; "benign child"'
    $RemoveEdgeSha256 = Get-Hash $benign
    $relaunch = Get-SelfRelaunch
    $command = Decode-Command $relaunch
    $mock = @"
function Invoke-RestMethod {
    param(`$Uri, [switch]`$UseBasicParsing, `$ErrorAction)
    if (`$Uri -ne 'https://example.invalid/path''s/Remove-Edge.ps1') { throw 'wrong URL' }
    return '$($benign.Replace("'", "''"))'
}
"@
    Assert ((Run-Child ($mock + $command + '; exit $global:LASTEXITCODE')) -eq 0) 'URL relaunch preserves apostrophe, checksum, and all switches without network/UAC'
    $benignExit = 'param([switch]$VerifyOnly,[switch]$DryRun,[switch]$RemoveProfileData,[switch]$NoReinstallBlock,[switch]$CreateRestorePoint,[switch]$AllowNoOtherBrowser); exit 1'
    $RemoveEdgeSha256 = Get-Hash $benignExit
    $exitMock = $mock.Replace($benign.Replace("'", "''"), $benignExit.Replace("'", "''"))
    $tail = '; if ($global:LASTEXITCODE -ne 1) { exit 9 }; exit 0'
    Assert ((Run-Child ($exitMock + (Decode-Command (Get-SelfRelaunch)) + $tail)) -eq 0) 'payload exit returns to administrator shell so NoExit can retain the report'
    $RemoveEdgeSha256 = '0' * 64
    Assert ((Run-Child ($mock + (Decode-Command (Get-SelfRelaunch)) + '; exit $global:LASTEXITCODE')) -eq 3) 'elevated-command hash mismatch fails closed before payload execution'
    $RemoveEdgeUrl = ''
    Assert ($null -eq (Get-SelfRelaunch)) 'unknown source never invents a relaunch'

    # Exercise the actual loader with a mocked HTTP response, never the real
    # removal payload. Only the expected digest is substituted for this test.
    $benignLoader = 'param([switch]$DryRun,[switch]$VerifyOnly); if (-not ($DryRun -and $VerifyOnly)) { throw "loader lost flags" }; "loader-safe"'
    $expectedHash = [regex]::Match($loader, "\`$RemoveEdgeSha256 = '([A-Fa-f0-9]{64})'")
    Assert $expectedHash.Success 'loader contains a concrete payload checksum'
    Assert ((Get-Hash $source) -eq $expectedHash.Groups[1].Value) 'published payload checksum matches source (LF-normalized UTF-8)'
    $safeLoader = $loader.Replace($expectedHash.Groups[1].Value, (Get-Hash $benignLoader))
    function Invoke-RestMethod { param($Uri, [switch]$UseBasicParsing, $ErrorAction); return $benignLoader }
    $loaderResult = & ([scriptblock]::Create($safeLoader)) -DryRun -VerifyOnly
    Assert ($loaderResult -eq 'loader-safe') 'actual loader forwards read-only switches to verified scriptblock'
}
finally {
    foreach ($name in $savedEnv.Keys) { [Environment]::SetEnvironmentVariable($name, $savedEnv[$name], 'Process') }
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}

# Real-script read-only smoke checks. CI's Windows Server images are outside
# the tool's supported desktop scope; they run fixtures only.
if (-not $SkipMachineChecks) {
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $payloadPath -DryRun -NoElevate
Assert ($LASTEXITCODE -eq 0) 'actual DryRun returns zero without UAC or changes'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $payloadPath -VerifyOnly -NoElevate
Assert ($LASTEXITCODE -in @(0, 1)) 'actual VerifyOnly returns a meaningful checked-state status without UAC'
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
