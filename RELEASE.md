# Release procedure

Releases are made by hand, from a clean tree, with the checksum derived rather
than copied. Nothing here is automated on purpose: a release is a claim that a
specific file was reviewed and that its checksum matches.

## 1. Start clean

```bash
git status --short          # must be empty
git log --oneline -1
```

## 2. Run every check

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-RemoveEdge.ps1
```

The suite must end with `All N assertions passed.` and exit 0. It never
installs, elevates, or modifies Edge. Confirm the read-only modes separately:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remove-Edge.ps1 -DryRun -NoElevate
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remove-Edge.ps1 -VerifyOnly -NoElevate
```

## 3. Choose the version and update the pins

In a patch release, change `v1.0.x` to `v1.0.y` in three places:

1. `get.ps1` - `$PayloadTag`
2. `README.md` - the one-liner and the read-only preview command
3. `SECURITY.md` - the supported-versions table

## 4. Derive the payload checksum and stamp the loader

The checksum is SHA-256 over the payload text with CRLF normalised to LF,
encoded as UTF-8. This is exactly what the loader computes on a downloaded
file, so a value derived here and a value checked there cannot drift.

```powershell
.\Stamp-Checksum.ps1 -Check   # verify only; exits 1 on a mismatch
.\Stamp-Checksum.ps1          # rewrite the checksum in get.ps1
```

`Stamp-Checksum.ps1` is part of this repository, is covered by the test suite,
and needs no modules. Do not edit the number by hand and do not use
`Get-FileHash`, which hashes the bytes on disk: if the file carries CRLF
endings that value differs from the loader's. Re-run the test suite afterwards;
it asserts that `get.ps1` and `Remove-Edge.ps1` agree.

## 5. Prove the stamped loader still works

```powershell
& ([scriptblock]::Create((Get-Content .\get.ps1 -Raw))) -DryRun
```

Expect the loader's `Payload verified: SHA-256 ...` line only when it can reach
GitHub. `-DryRun` changes nothing.

## 6. Commit and tag

```bash
git add -A
git commit -m "Release v1.0.y: <summary of the security fix>"
git tag -a v1.0.y -m "v1.0.y"
git push origin main
git push origin v1.0.y
```

The tag must be created **after** the commit that carries the stamped
checksum, because the one-liner downloads the payload *from the tag*.

## 7. Verify the published release

```powershell
irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.y/get.ps1 |
    Select-String 'RemoveEdgeSha256'
irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.y/Remove-Edge.ps1 |
    Out-File -Encoding utf8 downloaded-payload.ps1
(Get-FileHash .\downloaded-payload.ps1 -Algorithm SHA256).Hash
```

Both values must match the ones you stamped. Then confirm the read-only modes
of the published loader:

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/onion3130/remove-microsoft-edge/v1.0.y/get.ps1))) -DryRun
```

## Checklist before announcing a release

- [ ] Test suite passes with and without `-SkipMachineChecks`
- [ ] Checksum in `get.ps1` equals the derived value, not a copied one
- [ ] Version tag referenced in `get.ps1` and the README matches the tag pushed
- [ ] `SECURITY.md` lists this version as supported and drops the previous one
- [ ] `actions/checkout` in the workflow is pinned to a commit SHA
- [ ] Published payload re-downloaded and hashed to the same value