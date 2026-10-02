# remove-microsoft-edge

Attempt to remove the **system-level Microsoft Edge browser** from Windows,
while keeping WebView2 and your browser profile.

No region spoofing, patched Windows files, disabled drivers, or third-party
debloat tools. **This is an unsupported system modification, not a guarantee
that Edge will stay removed.** Install another browser and back up important
Edge data first.

## Run it: copy, paste, say yes

Review this repository first. Open **Windows PowerShell** (search for it in
Start), paste the following line, press **Enter**, then click **Yes** on the
Windows administrator permission prompt:

```powershell
irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.0/get.ps1 | iex
```

Removal continues in a new administrator PowerShell window, which stays open
with the report. Declining UAC cancels removal.

The command uses the **v1.0.0** tag rather than the changing `main` branch. The
loader checks the removal script's SHA-256 before executing it, including when
re-fetching it in the administrator window. This detects an unexpected payload;
it is **not a digital signature** and does not protect against a compromised
repository or a loader you have not reviewed. Git tags can also be moved by a
repository owner. For maximum control, download and review the files before
running them locally.

### Preview without changing anything

This uses the same loader but explicitly passes a read-only switch. **No UAC
prompt or removal:**

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.0/get.ps1))) -DryRun
```

Replace `-DryRun` with `-VerifyOnly` to report the current state. A non-admin
report checks only the current user's Appx packages, not all users or provisioned
packages; run verification as administrator for that broader scope.

## Requirements and scope

- Windows PowerShell **5.1**, built into Windows 10/11.
- Administrator permission for removal; not needed for `-DryRun` or `-VerifyOnly`.
- Another browser installed. The tool checks common Chrome, Firefox, Brave,
  Vivaldi, and Opera locations, but cannot detect every portable/custom install.
- A **system-level stable Edge installation** in the Program Files directories
  reported by Windows. Current-user installations are detected when possible
  but are not removed. Other users' private installations, Beta/Dev/Canary,
  legacy Edge, and every possible file association are outside scope.

Windows 11 Pro build 26300 / Windows PowerShell 5.1 was used for local checks.
Windows 10 and other architectures/builds are **not verified**. Follow your
organization's policy on managed devices.

## What it does

1. Finds the newest bundled uninstaller in the exact
   `Microsoft\Edge\Application` directory under Windows' Program Files roots.
   Redirected paths/reparse points are refused rather than followed for removal.
2. Checks for an alternative browser before making removal changes.
3. Stops Edge and Edge Update **processes** (not WebView2 processes or services).
4. Attempts Microsoft's bundled uninstaller with
   `--uninstall --system-level --verbose-logging --force-uninstall`.
5. If remnants remain, attempts direct cleanup of that Application directory,
   stable Edge registry entries, standard shortcuts, and **only** the
   `Microsoft.MicrosoftEdge.Stable` installed/provisioned Appx package.
6. Sets the per-product Edge Update `Install{56EB18F8-...}` DWORD to `0`, unless
   `-NoReinstallBlock` is supplied. Policy enforcement varies by system;
   Windows feature updates can still reprovision Edge.
7. Checks files, registrations, shortcuts, and packages again. Failed requested
   operations or incomplete package checks produce an error, not false success.

## What it keeps

- **WebView2 Runtime and shared `EdgeCore` payloads.** Apps depend on them.
  EdgeCore can still contain a runnable `msedge.exe`: this tool does **not**
  promise to erase every Edge executable from disk. The install policy is scoped
  to the stable browser product, not WebView2. Update services remain enabled.
- **Your Edge profile**, unless you explicitly supply `-RemoveProfileData`.
- Windows' protected `Microsoft.MicrosoftEdgeDevToolsClient` component.
- Device region, Windows policy JSON files, UCPD, and unrelated software.

## Local usage

Download/extract the repository. Double-click **Run-Elevated.cmd**, or open
Windows PowerShell in that folder:

```powershell
# Removal, retaining your profile and applying the install policy
.\Remove-Edge.ps1

# Read-only: no elevation prompt or changes
.\Remove-Edge.ps1 -VerifyOnly
.\Remove-Edge.ps1 -DryRun

# Optional restore point (requires System Protection)
.\Remove-Edge.ps1 -CreateRestorePoint

# Irreversible: also delete the current account's Edge profile
.\Remove-Edge.ps1 -RemoveProfileData
```

If local script execution is blocked, inspect the script first, then use
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remove-Edge.ps1`.
This bypass is for that process, not a machine-wide policy change.

| Switch | Effect |
|---|---|
| `-VerifyOnly` | Report installations/remnants; change nothing. |
| `-DryRun` | Print the plan; change nothing. |
| `-RemoveProfileData` | Delete `%LOCALAPPDATA%\Microsoft\Edge` for the account executing removal. **History, cookies, bookmarks, and locally stored passwords can be lost permanently.** |
| `-NoReinstallBlock` | Skip writing the Edge Update install policy; does not remove an existing policy. |
| `-CreateRestorePoint` | Attempt a restore point; warn and continue if it cannot be created. Not a substitute for a backup. |
| `-NoElevate` | Never request UAC; removal exits if not already administrator. |
| `-AllowNoOtherBrowser` | Explicitly override the browser prerequisite, e.g. for an unrecognized portable browser. |

File and URL elevation preserve these switches. If UAC requires credentials for
a **different administrator account**, profile cleanup and current-user checks
apply to that administrator's account, not necessarily your normal account.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Checked scope is clean, removal succeeded, or a dry run completed. |
| `1` | An Edge installation or checked remnant is still present. |
| `2` | Prerequisite unmet, elevation unavailable, or UAC declined. |
| `3` | Download, operation, or verification error; review warnings. |
| `4` | Relaunched elevated; **not** removal success. Read the new window's report. |

## Verification and limitations

Before/after checks include Application directories and browser binaries;
stable Edge Update client, Programs and Features, StartMenuInternet and App
Paths registrations in both machine registry locations; standard current-user,
public and machine shortcuts; installed stable Appx packages (all users when
admin); and provisioned stable Appx packages when admin. WebView2 detection,
HTTP default-browser association, and install-policy readback are also reported.
Shared EdgeCore binaries and custom shortcuts are intentionally outside the
clean-state predicate.

**Uninstaller exit codes are not definitive.** During the original local
removal of Edge 154.0.4258.53, the bundled uninstaller exited `20` while browser
files and registrations disappeared. That observation does not make `20` a
universal success code; the tool verifies actual state afterward.

**Windows can reinstall Edge.** Setting the Edge Update install policy is not
proof of enforcement, particularly on unmanaged editions or managed devices
with overriding policies. Windows feature updates can reprovision it. Run
`-VerifyOnly` after updates if you want to check.

**Default-browser associations may dangle.** If Edge was your default browser,
set another one in **Settings → Apps → Default apps** after removal. The tool
warns about an HTTP `MSEdgeHTM` association; it does not forcibly rewrite
Windows' protected choices.

**Direct cleanup is a fallback, not a supported uninstall API.** It can fail
on locked files or protected packages and may leave other Windows integrations.
Review the final report. Do not delete EdgeCore/WebView2 to chase disk savings.

## Testing

Run the dependency-free suite from the repository directory:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-RemoveEdge.ps1
```

It parses every PowerShell file, exercises the actual discovery/cleanup helpers
against isolated fixtures, verifies safe deletion scope and shared-runtime
preservation, checks the full success predicate and payload checksum, and runs
harmless child processes to test path quoting and switch forwarding. Mocked
network responses test URL relaunch and hash rejection without UAC. Read-only
smoke checks run against the real script; no real uninstall is performed.

The original bundled-installer removal and an earlier package revision's
already-removed repeat run were checked on the local Windows 11 machine.
**This final package has not been tested on a fresh Edge installation or through
an end-to-end UAC removal.** The tests are not evidence of compatibility with
every Windows build.

## Undoing the install policy / reinstalling

From administrator PowerShell, remove the browser-specific policy first:

```powershell
Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate' `
  -Name 'Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}' -ErrorAction SilentlyContinue
```

Then reinstall from <https://www.microsoft.com/edge> and choose your default
browser in Settings. Deleted profile data cannot be restored by reinstalling.

## Product IDs

This tool targets stable Edge
`{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}`, not the separate WebView2 Runtime
`{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}`. These names were checked in the local
Edge Update Clients registry. Do not substitute the WebView2 ID.

## Disclaimer and license

This tool is not affiliated with or endorsed by Microsoft. Removal is not
supported on every Windows installation. Review the code, back up your data,
and use at your own risk. Provided without warranty under the
[MIT License](LICENSE).
