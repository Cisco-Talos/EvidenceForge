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

## Windows-only iteration decision

The user requested Windows-only CI iterations on November 11, deferring repeated
Mac/Linux gates until the Windows installer is stable. `Windows Studio Preview`
now runs directly on pushes to this branch and is callable through Installer
Builds. It retains focused native Windows contracts, state/helper crash recovery,
model-free Codex permission checks, Rust shell tests and actual NSIS verification.
UV/npm and Rust build caches reduce repeated setup/compilation. New pushes cancel
superseded preview runs.

Automatic full CI is suppressed only for this exact draft PR branch targeting
dev. Ready-for-review now explicitly triggers normal full CI; manual dispatch,
dev/main and release callers retain all gates. Keep the PR draft during this
iteration phase and remove the temporary branch guard before integration.

GitHub rejected three initial attempts before assigning jobs with `startup_failure`.
The public run summary reports only "An unexpected error has occurred and we've
been automatically notified." Actionlint finds no new workflow errors (its older
schema does not recognize the pre-existing `concurrency.queue` field). The direct
Windows entry point also isolates execution from reusable-workflow expansion.
No native Windows success or installer artifact is claimed from those attempts.

Additional local evidence: 145/145 native Mac slow recovery cases pass; an isolated
Mac standalone app builds and passes the complete packaged runtime/resource,
generation and evaluation verifier. The broad Mac Studio suite reported 713
passed, six skipped, and three helper-attachment failures while Python sources
were being edited. Those three pass on a stable tree (four ownership cases total).
The helper source fingerprint correctly treated the changing build as a different
runtime; do not edit source during identity-sensitive tests. Subsequent targeted
portable transport/job checks pass (36 cases), as do all sixteen chat cases and
the five Settings UI cases. The pinned Windows Python archive verifies against
upstream SHA256, has 3,325 regular/directory entries with no links, and includes
both vcruntime DLLs.

The self-contained workflow is now registered by push and runs on the feature
branch (`e2a986c0`). Full CI on that draft is intentionally deferred. The first
direct Windows run is [43098834307](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43098834307).
Earlier full runs had no assigned jobs; cancellation attempts reported that the
runs were already completed. Do not treat those unexecuted/skipped checks as
platform validation. Before integration, remove the temporary draft-branch guard
and require the full existing platform matrix.

Native jobs now execute. Run [43099474385](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43099474385)
passed 42 Windows runtime/process cases (including concurrent runtime installation),
with one POSIX-only process-group case skipped. Two failures exposed a missing UID
mock in a Mac launch test and unsupported append access for Windows helper logs.
The next iteration supplies the mock and native FILE_APPEND_DATA access, with an
EOF-preservation test included in Windows CI. This failure occurred before the
installer build; no verified installer is available yet.

At `48d5c989`, the native Windows runtime/process gate passes and the job advances
to state/helper recovery. Subsequent workflow improvements retain lint, generated
types, frontend and real service/transport tests on Windows, align shell tests
with the installer's release target for build reuse, and add scope-specific
Start-menu/Desktop target and uninstall checks. Verification reports include the
exact Python/Rust/Node/uv versions as well as the runner image and source SHA.

Run `43100432955` passed 69 native runtime/filesystem/process tests and 197 routine
state durability/migration tests. The next helper suite passed 53 cases but found
five harness assertions equating a Windows virtualenv redirector PID with the
announced interpreter PID. The harness now accepts only a directly owned native
Python child with matching creation time, executable and account, and cleans that
verified process before reaping its launcher. Production ownership checks remain
unchanged. The slow crash matrix and installer stages had not run at this point.

Run `43101388165` again passed all 69 Windows runtime/process cases, Ruff and
generated API types. Frontend results were 371 passed, one timeout while typing
a 300-character identifier with per-key timers. That test now pastes the same
identifier and retains its exact creation assertions. The source rename test
compares actual before/after native permission bits rather than requiring POSIX
0640 on Windows. Retained helper/controller launches also now use isolated Python
flags, matching the existing retained CLI/macOS launch contract.

Additional native acceptance cases exercise a lease held by a separate worker
while a different payload is installed, and retry after an injected interruption
after the first archive member. The installed-shell probe uses a deliberately
hostile current directory/Python environment; uninstall must preserve an authored
scenario in its actual configured workspace, the private database and runtimes.

The Windows iteration cache restores by toolchain/lockfile and saves a new
commit-specific Rust cache even when later packaging/verification fails. Release
shell tests and NSIS builds share one static-CRT target/profile; frontend assets
must be built before those release-profile shell tests.

Run `43102142922` passed all 372 frontend tests and 69 native runtime/process
cases. The service suite was cancelled to inspect slow progress at 65%; its log
showed steady execution, not a hang. Five failures were a CRLF fixture assertion
and four scenarios receiving repr-escaped Windows context paths. File serving now
compares exact source bytes; authoring instructions quote paths and executable
prefixes for native PowerShell on Windows, with a native argument round-trip
probe. POSIX prefixes keep shlex behavior. The Windows service step now fails
fast and has a bounded 15-minute budget for quicker iteration diagnostics.

At `b99cb31e` the expanded native runtime gate (including PowerShell argument
round-trip, cross-process lease replacement and interrupted extraction) passes.
Review of the pinned Codex 0.167.0 generated schema found that readiness is a unit
request: omit params rather than sending `{}`. The transport and fake servers now
enforce that exact contract before the model-free native sandbox probe.
