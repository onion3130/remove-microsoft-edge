# Security policy

## Scope

`Remove-Edge.ps1` and `get.ps1` are the only files that run on a user's
machine. Everything else in this repository is documentation or tests.

## What this tool protects against

| Threat | Control |
|---|---|
| Corrupted or truncated download | SHA-256 of the payload is checked before anything is executed; a mismatch stops the run. |
| An unexpected file at the download URL | Scheme, host (`raw.githubusercontent.com`), repository, numeric version tag, filename and a `#Requires` header are all required. |
| A payload replaced between verification and the elevated run | The elevated run recomputes the checksum of the file it is about to execute and refuses to continue on any difference. |
| Code staged in a shared temporary directory | The verified payload is written to a freshly created directory whose ACL admits only the current user and SYSTEM, and is hashed again after being written. |
| Deleting something other than Edge | Every deletion target is an exact, Edge-specific path checked again immediately before use: the `Application` directory and its three parent folders, four literal registry keys behind a second allowlist, four literal shortcut paths, and one exactly named Appx package. Reparse points, junctions and registry symbolic links are refused. |
| Redirected paths and environment tampering | Deletion paths are built from the locations Windows reports in the registry, not from process environment variables. Variables are cross-checked and a mismatch refuses a destructive run. |
| WebView2 being removed | WebView2 and `EdgeCore` are explicitly excluded from every allowlist, never named as a target, and their presence is re-checked at the end of a run. |
| False success reporting | One function decides the outcome. A failed check, a failed operation, or any surviving trace yields a non-zero exit code. |
| Running an untrusted uninstaller | The bundled `setup.exe` Authenticode signature is checked before it is executed with administrator rights; anything other than a valid or untrusted-certificate signature is refused. |

## What this tool cannot protect against

- **A compromised repository or maintainer account.** The expected checksum
  lives in this repository. Anyone who can change the repository, or move the
  `v*` tag, can change the code and the checksum together. Removing this limit
  requires a signing key whose private half is held somewhere other than the
  repository. This project has no such key and does not pretend otherwise.
- **A mutable tag.** A tag is a name Git allows its owner to move. Pin the
  commit SHA in your own copy if that matters to you.
- **A loader you have not read.** The one-liner executes code straight from
  the network. Review `get.ps1` first, or use the local-file instructions in
  the README.
- **Local administrator access to the machine.** Someone who can already write
  to `%ProgramFiles%\Microsoft\Edge\Application` can replace the uninstaller.
  The signature check raises the cost of that, but cannot make it impossible.
- **An end-to-end removal on your machine.** See "Testing" in the README for
  exactly what has and has not been exercised.

## Supported versions

Only the latest tagged release receives fixes. Fixes are published as a patch
release, not a new major version.

| Version | Supported |
|---|---|
| v1.0.1 | Yes |
| v1.0.0 | No |

## Reporting a vulnerability

Please use **GitHub's private vulnerability reporting** on this repository
(Security tab -> "Report a vulnerability"). Do not open a public issue for an
unfixed vulnerability.

Include: the file and line, what an attacker gains, and the exact steps to
reproduce. Please do not test against machines you do not own. This tool
removes a browser, so please restrict destructive testing to a disposable
virtual machine and never to a machine with unsaved work.

You can expect an acknowledgement within a few days and a fix or an explanation
within a reasonable time. Changes are released as a new patch tag with the
checksum re-derived and the test suite re-run.