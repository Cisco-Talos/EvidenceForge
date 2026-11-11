# Windows x86_64 Studio preview

## Authorized delivery

Implement on `codex/studio-windows-x86_64`, created from fetched `origin/dev`
(`4df3c2ae`). One unsigned NSIS installer offers current-user and machine scopes;
both require administrator approval. Windows 11 x86_64 and local NTFS are the
intended desktop baseline. Hosted Windows Server CI provides engineering evidence,
not Windows 11 desktop or genuine separate-account acceptance.

No version bump, release tag, publication, ARM/x86 artifact, MSI, ZIP delivery,
signing, automatic updates or automatic Windows runtime pruning. Preserve existing
Mac/Linux behavior and release requirements. Deliver a draft PR into dev with
preview artifacts and explicit acceptance limits.

## Implementation and validation

Initial implementation adds native retained-runtime installation through the
existing Windows ACL/publication adapter, Windows process options and kernel
leases, private CLI discovery, and fail-closed Codex sandbox readiness. The
installer includes an app-owned bootstrap interpreter solely for installing the
checksummed retained copy. Helpers and jobs use retained runtimes. Windows pruning
is explicitly unavailable; POSIX pruning remains unchanged.

The NSIS template is derived from pinned Tauri CLI 2.12.0 with its upstream hash
and MIT notice. Changes remove post-install execution and app-data deletion and
reject cross-scope installs. zlib compression is explicitly selected. Source and
native recovery CI include Windows; a separate preview builder/verifier cannot
add Windows to required published-release assets.

Local validation so far: 371 frontend tests, frontend production build, 12 native
Mac Rust shell tests, 109 CI/release-contract tests, and ten platform-independent
Windows payload/discovery tests pass. Four native Windows cases correctly await
Windows execution. Initial Mac runtime/job regressions passed 51 of 52; the last
case was denied process enumeration by the sandbox. The broader Studio suite is
running with native process/loopback access. Ruff lint/format, API generation and
generation-behavior revision 509 checks pass. No release version changed.

Native Windows CI, installed preview verification, packaged Mac/Linux regression
builds, Windows 11 interactive acceptance and actual separate-account testing are
not yet claimed.
