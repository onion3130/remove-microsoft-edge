# remove-microsoft-edge

Remove the **system-level Microsoft Edge browser** from Windows, while keeping
WebView2 and your browser profile.

No region spoofing, patched Windows files, disabled drivers, or third-party
debloat tools. **This is an unsupported system modification, not a guarantee
that Edge will stay removed.** Install another browser and back up important
Edge data first.

## Run it: copy, paste, say yes

Review this repository first. Open **Windows PowerShell** (search for it in
Start), paste the following line, press **Enter**, then click **Yes** on the
Windows administrator permission prompt:

```powershell
irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/get.ps1 | iex
```

Removal continues in a new administrator PowerShell window, which stays open
with the report. Declining UAC cancels removal.

The command uses the **v1.0.1 tag** rather than the changing `main` branch.
The loader checks the removal script's SHA-256 before executing it, and the
administrator window re-checks it again before doing anything.

### Preview without changing anything

This uses the same loader but explicitly passes a read-only switch. **No UAC
prompt, no removal, no changes:**

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/get.ps1))) -DryRun
```

This form is also the safer way to run the tool generally: it does not pipe
straight into `Invoke-Expression`, so nothing can be appended to the command by
accident, and you can read the loader before executing it.

Replace `-DryRun` with `-VerifyOnly` to report the current state. A non-admin
report checks only the current user's Appx packages, not all users or
provisioned packages, and says so; run verification as administrator for the
broader scope.

## Verifying a download before running it

The loader already does this, but you can do it yourself, which is the only
version of this check that does not depend on trusting the loader.

```powershell
# 1. Save the payload without executing it.
irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/Remove-Edge.ps1 |
    Out-File -Encoding utf8 .\Remove-Edge.ps1

# 2. Read it. It is one file, no modules, no dependencies.

# 3. Compare its checksum with the one the loader expects.
$expected = (irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.1/get.ps1 |
    Select-String "\`$RemoveEdgeSha256 = '([A-F0-9]{64})'").Matches[0].Groups[1].Value

$text = [IO.File]::ReadAllText("$PWD\Remove-Edge.ps1").Replace("`r`n", "`n")
$sha = [Security.Cryptography.SHA256]::Create()
$actual = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))).Replace('-', '')
"$expected`n$actual`nmatch: $($actual -eq $expected)"
```

If that prints `match: True`, the file you read is the file the loader would
have run.

## Security model

**What the checksum does and does not prove.** The SHA-256 in `get.ps1` detects
an unexpected or corrupted payload: a truncated download, a tampered mirror, a
substituted file. It is **not a digital signature** and it is **not proof of
authorship**, because the checksum is stored in the same repository as the code.
Anyone who can change this repository, or move the `v1.0.1` tag, can change the
code and the checksum together.

**Why there is no signature.** Real authenticity needs a private key that is
never uploaded. A single-maintainer utility has no key-rotation or revocation
story worth the complexity, and a signature that is published next to the code
it signs would prove nothing. So this project ships a checksum and says plainly
what it is worth. The controls layered on top of it:

- The download must be `https`, from `raw.githubusercontent.com`, from
  `onion3130/remove-microsoft-edge`, at a **numeric version tag**, with the
  expected filename.
- The payload must begin with `#Requires`. Anything else is refused.
- A checksum that is missing or malformed is treated as "cannot verify", never
  as "skip the check".
- The elevated window recomputes the checksum of the file it is about to run
  and refuses to start on any difference.
- The verified payload is written to a private temporary directory, hashed
  again after writing, and deleted afterwards.
- No switch can change the download URL or the checksum.

**Signing, if you want it.** If you need real authenticity, do not rely on this
project's checksum. Clone the repository, read the two scripts, and run
`.\Remove-Edge.ps1` from your own copy. That is the strongest guarantee
available to you without trusting the maintainer's account.

Full detail: [SECURITY.md](SECURITY.md).

## Requirements and scope

- Windows PowerShell **5.1**, built into Windows 10/11.
- Administrator permission for removal; not needed for `-DryRun` or `-VerifyOnly`.
- Another browser installed. The tool checks common Chrome, Firefox, Brave,
  Vivaldi, and Opera locations, but cannot detect every portable or custom
  install.
- A **system-level stable Edge installation** in the Program Files directories
  reported by Windows. Current-user installations are detected when possible
  but are not removed. Other users' private installations, Beta/Dev/Canary,
  legacy Edge, and every possible file association are outside scope.

Verified locally on Windows 11 Pro build 26300 / Windows PowerShell 5.1, and in
CI on `windows-latest`. Windows 10 and other architectures/builds are **not
verified**. Follow your organization's policy on managed devices.

## What it does

1. Refuses to run a destructive pass if the process environment disagrees with
   the paths Windows reports, because those variables decide what gets deleted.
2. Finds the newest bundled uninstaller in the exact
   `Microsoft\Edge\Application` directory under Windows' Program Files roots.
   Redirected paths and reparse points are refused rather than followed.
3. Checks for an alternative browser before making any change.
4. Stops Edge and Edge Update **processes** (not WebView2 processes or services).
5. Checks the uninstaller's Authenticode signature, then attempts it with
   `--uninstall --system-level --verbose-logging --force-uninstall`.
6. If remnants remain, removes only exact, allowlisted targets: that
   Application directory, four Edge-only registry keys behind a second
   allowlist, four literal shortcut paths, and the exactly named
   `Microsoft.MicrosoftEdge.Stable` Appx package. Registry symbolic links and
   Appx packages that do not match the exact identity are refused.
7. Sets the per-product Edge Update `Install{56EB18F8-...}` DWORD to `0` and
   reads it back, unless `-NoReinstallBlock` is supplied.
8. Checks files, registrations, shortcuts, packages, and WebView2 again, and
   reports success only when every required check passed.

## What it keeps

- **WebView2 Runtime and shared `EdgeCore` payloads.** Apps depend on them.
  Both are excluded from every allowlist, and if WebView2 was present before a
  run and is gone after it, that is reported as an **error**, not a success.
  EdgeCore can still contain a runnable `msedge.exe`: this tool does **not**
  promise to erase every Edge executable from disk. The install policy is scoped
  to the stable browser product, not WebView2. Update services remain enabled.
- **Your Edge profile**, unless you explicitly supply `-RemoveProfileData`.
- Windows' protected `Microsoft.MicrosoftEdgeDevToolsClient` component.
- Device region, Windows policy JSON files, UCPD, and unrelated software.

## Local usage

Download or extract the repository. Double-click **Run-Elevated.cmd**, or open
Windows PowerShell in that folder:

```powershell
# Removal, retaining your profile and applying the install policy
.\Remove-Edge.ps1

# Read-only: no elevation prompt or changes
.\Remove-Edge.ps1 -VerifyOnly
.\Remove-Edge.ps1 -DryRun

# Optional restore point (requires System Protection)
.\Remove-Edge.ps1 -CreateRestorePoint

# IRREVERSIBLE: also delete this account's Edge profile
.\Remove-Edge.ps1 -RemoveProfileData
```

If local script execution is blocked, inspect the script first, then use
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remove-Edge.ps1`.
This bypass is for that process, not a machine-wide policy change.

| Switch | Effect |
|---|---|
| `-VerifyOnly` | Report installations/remnants; change nothing. |
| `-DryRun` | Print the plan; change nothing. |
| `-RemoveProfileData` | **Irreversible.** Delete `%LOCALAPPDATA%\Microsoft\Edge` for the account running removal. History, cookies, bookmarks and locally stored passwords can be lost permanently. Only that exact directory is ever deleted; the path is derived from the location Windows reports, not from an environment variable, and is refused if it is anything else. |
| `-NoReinstallBlock` | Skip writing the Edge Update install policy entirely; an existing policy is left exactly as it was. |
| `-CreateRestorePoint` | Attempt a restore point; warn loudly and continue if it cannot be created. Not a backup and not a guarantee of recovery. |
| `-NoElevate` | Never request UAC; removal exits if not already administrator. |
| `-AllowNoOtherBrowser` | Explicitly override the browser prerequisite, e.g. for an unrecognized portable browser. |

Profile data is **never** deleted by a normal removal, and `-RemoveProfileData`
never runs in `-DryRun` or `-VerifyOnly` mode: both are read-only from top to
bottom. File and URL elevation preserve every switch above.

If UAC requires credentials for a **different administrator account**, profile
cleanup and current-user checks apply to that administrator's account, not
necessarily your normal account.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Checked scope is clean, removal succeeded, or a dry run completed. |
| `1` | An Edge installation or checked remnant is still present, or the scope could not be fully verified. |
| `2` | Prerequisite unmet, elevation unavailable, UAC declined, or the environment was refused. |
| `3` | Download, operation, or verification error; review warnings. Never reported as success. |
| `4` | Relaunched elevated; **not** removal success. Read the new window's report. |

## Risks of removing Edge

- **You may be left with no browser.** Windows links many things to Edge
  (widgets, the taskbar web experience, PDF handling, `MSEdgeHTM` associations).
  The tool refuses to continue when it detects no alternative browser, but it
  cannot see portable or custom installations unless you say `-AllowNoOtherBrowser`.
- **Default-browser links can dangle.** If Edge was your default, set another
  one in **Settings -> Apps -> Default apps** afterwards. The tool warns about a
  leftover `MSEdgeHTM` association; it does not rewrite Windows' protected choices.
- **Windows can put Edge back.** Feature updates, repair installs and
  provisioning can restore it regardless of the install policy.
- **Updates you did not ask for will fail.** Microsoft Store apps, Teams and
  other software that embeds a browser engine may stop updating.
- **Uninstall is unsupported on some builds.** Results vary by region, edition
  and Windows build.

## Restore point and recovery

`-CreateRestorePoint` asks System Protection for a `MODIFY_SETTINGS` point before
anything is removed. It is best-effort: System Protection is often disabled, and
Windows throttles restore point creation. If it fails, the run continues (a
mandatory restore point would block legitimate removals) and says so in the
summary. **A restore point is not a backup and does not guarantee recovery.**
Back up anything you care about first.

## Verification and limitations

Before and after checks include Application directories and browser binaries;
stable Edge Update client, Programs and Features, StartMenuInternet and App
Paths registrations in both machine registry locations; standard current-user,
public and machine shortcuts; installed stable Appx packages (all users when
admin); and provisioned stable Appx packages when admin. WebView2 detection,
HTTP default-browser association, and install-policy readback are also
reported. Absence is always labelled with the scope that was checked, so
"absent (this user only)" never reads as proof. Shared EdgeCore binaries and
custom shortcuts are intentionally outside the clean-state predicate.

**Uninstaller exit codes are not definitive.** During the original local
removal of Edge 154.0.4258.53, the bundled uninstaller exited `20` while browser
files and registrations disappeared. That observation does not make `20` a
universal success code; the tool verifies actual state afterwards.

**The reinstall policy is a request, not a guarantee.** It sets
`Install{56EB18F8-...} = 0` for the stable browser product only; WebView2 keeps
updating. Enforcement varies by system, and Windows feature updates or
reprovisioning can still restore Edge. Run `-VerifyOnly` after updates to check.

**Direct cleanup is a fallback, not a supported uninstall API.** It can fail on
locked files or protected packages and may leave other Windows integrations.
Review the final report. Do not delete EdgeCore/WebView2 to chase disk savings.

**Known limitations.**

- Not tested end-to-end through a UAC elevation on this release, and not tested
  on a fresh Edge installation.
- The offline case is reported, not proven: if the uninstaller's certificate
  cannot be validated, the run continues with a warning instead of refusing. A
  genuinely untrusted or unsigned uninstaller is refused, and the run then ends
  with exit code 3 even if the direct cleanup succeeded, because the intended
  operation was not carried out.
- Other users' per-user Edge installs, Beta/Dev/Canary channels, legacy Edge,
  MSI-installed Edge, and every file association are out of scope.
- Only `windows-latest` CI and one Windows 11 Pro build have been exercised.

## Testing

Run the dependency-free suite from the repository directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-RemoveEdge.ps1
```

It needs no modules. It parses every PowerShell file and loads the real
helper functions, then works entirely on temporary fixtures: path safety,
reparse points and junctions, registry allowlists, WebView2 preservation, Appx
package identity, environment tampering, profile path validation, the outcome
rules, and the checksum/host/tag pinning. Child processes exercise the real
elevation relaunch with a mocked download, proving that a checksum mismatch or
a foreign host is refused and that nothing is executed. `-SkipMachineChecks`
skips the read-only run of the real script; GitHub Actions uses that flag,
because its Windows Server image is outside this tool's desktop scope.

The suite creates temporary directories and one throwaway `HKCU` registry key,
and deletes both. It never elevates, never runs the real uninstaller, and never
writes to `HKLM` or to an Edge install. It cannot test a real uninstall, so the
tests are not evidence that removal works on your build.

## Undoing the install policy / reinstalling

From administrator PowerShell, remove the browser-specific policy first:

```powershell
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' `
  -Name 'Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' -ErrorAction SilentlyContinue
```

Then reinstall from <https://www.microsoft.com/edge> and choose your default
browser in Settings. Deleted profile data cannot be restored by reinstalling,
which is why `-RemoveProfileData` is opt-in and says so.

## Product IDs

This tool targets stable Edge
`{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}`, not the separate WebView2 Runtime
`{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`. These names were checked in the local
Edge Update Clients registry. Do not substitute the WebView2 ID: every deletion
allowlist in this repository rejects it.

## Disclaimer and license

This tool is not affiliated with or endorsed by Microsoft. Removal is not
supported on every Windows installation. Review the code, back up your data,
and use at your own risk. Provided without warranty under the
[MIT License](LICENSE).

Reporting a security problem: see [SECURITY.md](SECURITY.md).
Releasing a new version: see [RELEASE.md](RELEASE.md).