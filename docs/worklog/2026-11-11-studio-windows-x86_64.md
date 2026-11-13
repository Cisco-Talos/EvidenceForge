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

Prioritize NSIS build/installed verification after the short runtime and frontend
gates, ahead of the longer general service suite, so packaging failures appear
earlier. Every native source/Codex/recovery gate still precedes qualified artifact
upload. Failed-run artifacts are diagnostics, not a completed preview claim.

Run `43104275788` passed 71 native cases but found a transient sharing failure
while the detached controller replaced a job record. Windows JobStore now uses
private native publication and shared-delete reads together; POSIX IO remains
unchanged. A concurrent 75-write/300-read native control-record probe covers this
boundary. Code review also caught an eager optional-Studio import in ordinary
`python -m evidenceforge`: runtime leases are imported only for a selected private
runtime, and a fresh-process CLI test rejects any ordinary Studio import. Fifteen
focused controller/job regressions and the ordinary CLI probe pass locally.

The new concurrency probe failed at publication in run `43104917047` (73 other
cases passed): legacy NT rename rejects replacement while readers hold the old
file. Job-record writes now explicitly opt into FileRenameInformationEx with
FILE_RENAME_POSIX_SEMANTICS; existing readers retain their old snapshot and new
opens observe the replacement. All other native storage callers keep their
previous rename behavior. The same native concurrency probe remains required.

Run [43105446307](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43105446307)
passes all 74 runtime/process cases, all 372 frontend tests/build and eleven native
Windows Rust tests (including Python/Rust lease interop). It builds the first NSIS
installer: 68.26 MiB, SHA256
`0e1afd0d0b27950bb916b350968064c8e4052019c37abd772b38ac9eb2ef0c32`.
Installed verification stops at directory registration: standard subprocess argv
quoting is incompatible with NSIS's special unquoted final `/D=` and `_?=` tails.
The harness now constructs that native command line directly, with no shell, and
reports the actual registered location without masking the first failure.
The installer is a failed-run diagnostic, not a qualified preview. Rust release
dependencies were successfully cached for the next iteration (rustc 1.99.1).

Prepared follow-up validation also waits for authenticated helper readiness after
discovery, explicitly selects UTF-8 for isolated Windows Python (which ignores
PYTHONUTF8), and exercises non-ANSI Chinese/Unicode install/runtime paths with user
Python IO overrides disabled. Twenty-nine focused regressions pass locally; POSIX
isolated interpreter flags are unchanged.

Run `43108145532` passes 75 native runtime/process cases, 372 frontend tests/build
and eleven Rust tests, then builds NSIS successfully. Directory verification now
identifies a second issue: MultiUser initialization resets an already-parsed
explicit `/D=` to its scope default. The custom template captures and restores
that explicit directory, including scope-selection callbacks; normal defaults
remain unchanged. First-installer download also matches its recorded SHA256 and
has no PE certificate table, consistent with unsigned delivery.

Read-only authoring commands must not write runtime installation locks. Packaged
CLI entry now acquires the pre-published lease through a read-only descriptor,
then validates the immutable receipt while pruning is excluded by that shared
lock. Helper/default locking behavior stays unchanged. The new real read-only
cache test passes locally; the focused retention suite passes 44 cases with four
Windows-only skips after rerunning its one process-census case with inspection
access. The native Codex gate additionally runs the actual packaged CLI in both
discussion and draft policies, without a model or ACL relaxation.

For faster installer feedback, frontend unit tests, Rust test harnesses and the
general service/controller/recovery suites now run after installed verification;
all remain mandatory before qualified artifact upload. Rust tests use the same
custom-protocol feature as packaging. Failed package builds still save compiled
dependencies. Windows packaged verification also requires the CPython, project,
NSIS and Tauri notices; CPython's Windows license location is `LICENSE.txt`.

Run `43111147174` now passes custom directory registration and reinstall, then
stops at shortcut verification. The PowerShell verifier captured its error but
did not surface stderr; the next iteration reports folder counts/actual targets
and ensures the installer creates its known shortcut folders. Verification also
installs/uninstalls in both default directories before the Unicode-path cases,
checks that setup has not initialized private state, and explicitly cleans the
direct uninstaller executable after waiting (required by NSIS `_?=` semantics).

Run `43113459478` passes both default-directory installs, shortcut checks and
uninstalls, then reports `汉` as `?` in the custom-path shortcut target through
WScript.Shell. The pinned NSIS/Tauri helpers use IShellLinkW; verification now
reads the shortcut through that explicit Unicode interface too, avoiding WScript
codepage conversion. It still compares canonical target paths and rejects any
different executable; the native result remains required.

Run [43114835307](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43114835307)
at `4421cf03` passes the complete installed verifier in 28m37s: default and Unicode
installations/reinstalls, both scopes' shortcuts, scope-switch refusal, isolated
runtime/resources/generation/evaluation, installed shell/helper startup, packaged
checkpoint/resume equivalence and uninstall preservation. Native Unicode shortcut
reading resolves the earlier WScript conversion. The report records runner image
`20261103.298.1`, rustc 1.99.1, Python 3.12.16, Node 22.23.4 and uv 0.13.7. Installer
SHA256 is `4b04c1f2d7e44f2809a2ac40b1336f3867598f89adf4d29706033f0cada78dda`.
All 372 frontend and eleven Rust tests pass. Authoring stops before sandbox setup:
native Codex discovery does not recognize the pinned npm package's `vendor/.../bin`
layout. Inspection of official `@openai/codex@0.167.0-win32-x64` verifies that path;
the resolver now supports it alongside the legacy `codex` layout in all three
supported npm dependency locations. Six discovery fixtures cover these layouts.
This remains a failed-run diagnostic, not a fully qualified preview.

Follow-up harness diagnostics print each installer/runtime/CLI phase immediately,
emit periodic stack snapshots and bound installed verification to 45 minutes. The
observed 29-minute pass must not be mistaken for a hang. Ruff, workflow actionlint
and 49 focused runtime/discovery/CI tests pass (four native Windows skips locally).
Now that installed verification has passed, native authoring/service/recovery
gates precede its longer repetition to expose remaining Windows failures sooner.

Run `43120529893` resolves the current npm binary correctly and stops at the setup
CLI's required identity selector, before any permission probe. CI provisioning now
explicitly supplies `--current-user` for the disposable runner account, alongside
its isolated CODEX_HOME. The setup remains elevated; no sandbox fallback or skip
is introduced. This failure is exposed in six minutes without repeating the
29-minute installed verifier.

Run `43121562688` provisions elevated Codex successfully, confirms native sandbox
readiness and resumes the discussion with the required policy. Its first command
fails launching the sandbox runner with Windows error 267. Pinned upstream code
launches that runner in the requested CWD before applying its command token;
pytest creates its entire Windows temporary tree with owner-only 0700 ACLs. The
next probe uses an ordinary inherited-ACL disposable authored workspace, while
keeping CODEX_HOME and the actual retained runtime private, and requires a real
read-only `cmd /c ver` baseline before the packaged CLI. This is a fixture diagnosis
to verify, not a qualified authoring result.

The failure also exposes unclosed Windows Proactor pipes during transport stop.
Shutdown now closes/awaits stdin and lets stdout/stderr reach EOF before cancelling
notification tasks. Forty focused real-process Codex regressions pass locally;
native warnings remain errors and the permission gate remains required.

Run `43123156494` confirms the fixture correction: real read-only `cmd /c ver`
passes. The packaged CLI instead fails with error 5 at CreateProcessAsUserW:
Codex's legacy elevated backend runs under its separate sandbox account and cannot
execute the account-private retained runtime. Runtime ACLs have not been widened.
The probe now tests the documented explicit MXC compatibility command first and
uses MXC only if the native command actually succeeds; otherwise it retains the
required elevated test and its failure. No unelevated fallback or Windows skip
has been added. See [upstream compatibility guidance](https://learn.chatgpt.com/docs/windows/windows-sandbox).

Native service/recovery checks now run in parallel with packaging, independently
of this authoring failure. Only a final qualification job can upload
`preview-installer-windows-x86_64`, after both jobs succeed, agree on their actual
checked-out commit, and match the installer/report/checksum bytes. Intermediate
`windows-installer-candidate-x86_64` artifacts are explicitly unqualified. Eighty
CI/release contract tests and actionlint pass locally. Remaining Windows Proactor
read handles require explicit closure of the owned CPython transport after the
bounded EOF wait; stdin-only closure reduced but did not eliminate the warnings.

Run `43124847952` confirms MXC is unavailable on the hosted executor. The legacy
sandbox's ordinary read-only command succeeds but executing the private CLI fails
with native error 5; explicit Proactor transport closure eliminates the unraisable
pipe warnings. The independent service job catches a second hard-coded LF
expectation in ZIP output. Its assertion now compares the entry with exact source
bytes, including Windows CRLF; the product already preserves those bytes.

The Windows 11 preview now checks actual private-CLI execution before reporting
Codex connected. Incompatible sandbox configuration fails with actionable MXC
guidance before any authoring message. Native tests require the real packaged
transport to reject the legacy account mismatch, then exercise every discussion/
draft filesystem boundary without a model or broad Windows skips. On a host with
MXC, the same gate requires successful private-CLI preflight and execution in both
policies. Reports explicitly distinguish that success from legacy rejection and
retain pending Windows 11 desktop authoring acceptance. Runtime ACLs are unchanged.
User preference about additionally supporting the legacy backend was requested;
the current isolation-preserving implementation follows the Windows 11/MXC scope
while other Windows validation continues. Do not claim successful MXC authoring
or legacy backend support from hosted Server CI.

Local evidence for the follow-up: 47 runtime/preflight/CI/bundle cases pass with
four native Windows skips, 34 shared Codex transport regressions pass, and Ruff/
actionlint pass. Service CI collects up to five failures per pass; independent
state/helper recovery still executes after service-test failure, while the native
job and final qualification remain failed if either gate fails.

Run `43127078103` passes all 135 native service/chat/job cases and 213 routine
durability/migration/runtime cases (one existing POSIX-only skip). Native packaged
authoring now correctly rejects the incompatible legacy sandbox before connection.
Its next protection probe is genuinely denied by Windows, but the pinned provider
reports that denial as an RPC sandbox error rather than an exit-result object.
Only expected-denial commands now accept the specific nonzero `sandbox denied
exec error` response; launch/setup/protocol failures and every positive read/write
probe still fail. The remaining native helper suite passes 55 cases, skips twelve
existing POSIX-only checks, and catches three harness expectations of exit 0:
Windows psutil terminates the authenticated idle helper with exit SIGTERM (15).
The harness now requires that native status and still asserts stale-PID rejection
and instance-lock reacquisition. Product replacement behavior is unchanged. The
145 slow Windows recovery cases still await execution after that correction.

### Broader source acceptance and native import publication

At `5bfafe23`, Windows preview run `43128783222` passes native service (134 passed,
one existing POSIX-only skip), routine state (213 passed, one skip), helper/runtime
(58 passed, twelve existing POSIX-only skips), and all 145 slow crash/recovery cases.
The packaged native model-free permission probes pass and correctly reject the
legacy sandbox/private-runtime mismatch before connection. The installed verifier
passes both scopes again, followed by frontend and native Rust checks.

One final full CI run `43130441861` at that snapshot passes every routine shard,
all native recovery gates, and Studio on macOS and both Linux architectures. Its
Windows Studio gate exposes 27 failures (515 passed, 43 skipped), so Required CI
correctly fails. Native package runs `43130589973` (macOS), `43130590246` (Linux
ARM64), and `43130590425` (Linux x86_64) all pass actual packaged verification.
These are exact `5bfafe23` results; they do not certify subsequent source changes.
The temporary draft-branch Windows-only iteration policy remains in place.

The main product defect is Windows refusing `os.replace` of a staged directory
onto an existing empty reservation directory. Windows imports now use the native
no-overwrite directory publisher across pinned parents. Only a successful publish
enters rollback tracking, preserving a competing destination. Different-volume
imports copy to a temporary destination sibling and then use the same atomic
no-overwrite publication. Native regressions cover cross-parent exclusivity and
cross-volume fallback, including a competing target and staging cleanup. Existing
Mac/Linux publication remains unchanged. Search result relative file identifiers
now use portable forward slashes.

The other failures are harness portability: captured declaration bytes preserve
CRLF; Windows chmod cannot express POSIX execute/mode bits; native reparse-point
errors are equivalent to symlink rejection; actual queued generation has a bounded
120-second Windows budget instead of an unrelated 30-second functional-test limit.
Byte, integrity, rollback, link rejection, and output assertions remain required.
The preview native source gate now discovers the full Studio/desktop suite through
`scripts.ci_studio`, matching full CI on every platform, before artifact qualification.

Run `43128783222` finishes all three jobs successfully and uploads its qualified
artifact. Downloaded bytes match SHA256
`d5d22de96bdbaaaf0b03eedfb45700732b2f602e467be75b8cce81e2d9b69a90`.
The report records runner image `20261103.298.1`, Python 3.12.16, rustc 1.99.1,
Node 22.23.4 and uv 0.13.7. This earlier artifact passed its then-focused source
gate; the independent broader Windows failures above still block completion.
The new full source gate must pass on the corrected snapshot before handing over
an accepted preview. Local follow-up: 120 focused regressions pass, with two new
Windows import cases and 26 native filesystem cases deferred to native Windows;
Ruff and workflow actionlint pass. The CI ownership contract now executes the
portable discovery driver to ensure recovery cases remain assigned to one gate.

### Corrected snapshot: `1126d388`

Windows-only run `43134184144` passes its complete native source/recovery job:
469 Studio cases pass (31 existing conditional skips), 213 routine state/migration
cases pass (one skip), 58 helper/runtime cases pass (twelve existing POSIX-only
skips), and all 145 slow crash/recovery cases pass. All 27 broad-suite failures
from `5bfafe23` are corrected. Both new native cross-volume fallback cases pass;
the separate packaging job also passes cross-parent no-overwrite publication.

The source count is lower than the earlier broad invocation because explicit test
paths bypassed its intended `--ignore` exclusions. Comparing actual collected
node IDs finds exactly 87 transferred cases, all from the five recovery-owned
modules (ownership 37, sessions 19, state contracts 17, runtime 8, durability 6).
Every one remains covered by the shared recovery commands above. The discovery
driver now implements the existing single-owner intent without losing coverage.

After that full Windows source pass, final integration checks are started once on
this corrected snapshot: full CI `43136120936`, macOS package `43136120690`, Linux
ARM64 package `43136123038`, and Linux x86_64 package `43136121885`. Automatic
feature-branch iteration remains Windows-only. No further source changes are made
while these exact-commit gates and installed verification run.

Windows run `43134184144` completes all three jobs successfully. The corrected
installer passes both scopes, installed CLI/resources, helper startup, Unicode
paths, scope-switch refusal, checkpoint/resume equivalence, reinstall/uninstall
preservation, 372 frontend tests, and eleven native Rust tests. Downloaded final
bytes independently match the report and checksum:
`aef3ab34d36709899395a2a3fb6d397fb61217a876d0880f05718e82528c471a`.
Qualified artifact: [installer, checksum and report](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43134184144/artifacts/13908930553).
The report binds source `1126d38879efdf88f29d335bb3b3b4563c384f67`, runner image
`20261103.298.1`, Python 3.12.16, rustc 1.99.1, Node 22.23.4 and uv 0.13.7.
Payload Python remains the separately pinned 3.12.12 distribution.

All three final POSIX package runs listed above pass on the same corrected
snapshot. Full CI `43136120936` finishes successfully, including Required CI aggregation,
every routine shard, all four native Studio/recovery platforms, generated types,
frontend, native permissions, debug Rust tests and native window builds, plus the
isolated macOS packaged runtime. Windows full CI independently repeats the 469
source cases (31 existing skips) and passes all eleven debug Rust tests. Successful MXC authoring,
Windows 11 GUI/UAC and genuine separate-account acceptance remain unclaimed.

The CI preview milestone is complete on the tested code snapshot. TODO now retains
Windows 11 desktop/UAC/alternate-admin ownership, successful MXC authoring and
genuine separate-account isolation as durable pending acceptance. The draft PR
stays targeted at dev; remove its temporary iteration guard before integration.
No version, release tags or publication changed, and the older readiness branch
was untouched. Final handoff changes only TODO and this worklog; verified installer
bytes remain bound to their actual code commit rather than being relabeled.

## Windows 11 laptop follow-up (November 12)

The user installed the qualified EXE as their normal account using Everyone on
Windows 11 Pro 25H2, Intel Core Ultra 7 155H. First launch eventually reached
Scenarios; publisher setup and global skill installation completed. Restart failed
on `.eforge/studio` in the OneDrive-redirected Documents workspace: its directory
had inherited read/execute access for `CodexSandboxUsers` (SID ending 1008).
`layout.json`, `owner.lock` and private LocalAppData state retained private ACLs.
Saved/target schema versions matched; the upgrade label was misleading. No cause
for the inheritance change is established. With Studio stopped, a user-authorized
manual repair removed inherited directory ACEs, retaining the three explicit
account/SYSTEM/Administrators entries. An ACL backup was retained in the private
cache. Two normal launches reached Scenarios after repair, including close/reopen.
This was a workaround, not clean-installer acceptance.

Automatic Codex connection then failed discovery. The preview only searched PATH
and resolved npm shims on Windows, unlike its additional Mac/Linux locations.
The user authorized batching fixes and building a replacement installer. Work is
isolated in `/tmp/eforge-windows-preview-fixes` on the existing Windows feature
branch; the primary worktree remains on the unrelated issue-478 branch.

The follow-up adds real Windows runtime stage/extraction progress, first-setup vs
payload-update labels, narrow owned-metadata ACL tightening that refuses outside
writers, startup-specific maintenance/retry, and current-account native/npm/desktop
Codex discovery. The shared workspace lock/layout contracts remain in place;
there is no implicit scenario sharing, weakened private-file check or sandbox
fallback. Private schema/product versions are unchanged. The Windows reset guide
also identifies the separate WebView profile and global publisher/skills.

Local validation: 125 focused Python/state cases pass (four native Windows skips),
191 service/chat/state-upgrade cases pass, 374 frontend cases pass and production
build succeeds; the additional startup-listener regression passes with the focused
UI suite. All twelve local Rust tests pass with loopback access for the HTTP export
case. Generated API types, Ruff checks and formatting pass.

Follow-up implementation snapshot `7e3cf9511394bbc519c9901ba506e5e1d532696c`
starts Windows-only run `43301434961`. Its short native runtime/process/ACL gate
passes the actual inheritance-repair and outside-writer refusal regressions, plus
first-setup/reuse/update progress. The unsigned dual-scope NSIS build and model-free
native authoring probes pass. The complete native source/recovery job passes:
474 Studio cases (31 existing conditional skips), 220 routine state/migration
cases (one skip), 58 helper/runtime cases (twelve existing POSIX-only skips), and
all 145 slow recovery cases. Both installation scopes pass installed CLI/resource
isolation, native shell/helper startup, checkpoint/resume equivalence, reinstall,
scope-switch refusal, shortcuts and uninstall preservation. All 375 frontend tests
and eleven Windows release Rust tests pass. Artifact qualification succeeds on
the same exact implementation commit.

The downloaded replacement EXE independently matches its checksum and qualified
report: `d1ae394ac8dfec92a731d72c8ef3089afa990c94a4dc6f550deb4059898b1cbc`.
[Qualified installer, checksum and report](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43301434961/artifacts/13986225725).
The report records runner image `20261103.298.1`, host Python 3.12.16, rustc
1.100.0 (`0ef1bc386`, November 9), Node 22.23.4 and uv 0.13.8. Payload Python
remains the separately pinned 3.12.12 distribution. Versions/tags/publication remain
unchanged. Windows 11 clean-install/restart/Codex acceptance and broader final
Mac/Linux integration checks remain pending on these shared startup changes.

The final follow-up commit records documentation only and skips a redundant CI
build; all installer and executable evidence stays bound to `7e3cf951`. Remove the
temporary draft iteration guard and run the normal required integration checks
before merging this effort into dev.

Read-only laptop checks confirm that `codex` is absent from PATH and the standalone
CLI default directory, while the current account has the registered x64
`OpenAI.Codex` desktop package (version `26.1106.6628.0`, status Ok). This establishes
the missing discovery route, not successful authoring or sandbox compatibility.
The desktop package executable itself still needs normal-laptop acceptance.

### Replacement laptop acceptance and MXC prerequisite review

The user installed the replacement and reports that the first-time setup screen
is useful and quitting/relaunching works. Codex discovery now progresses through
app-server initialization and Windows readiness to the private CLI execution
probe, which fails with the MXC setup message. This confirms the discovery route,
not successful sandboxed authoring. The current probe maps RPC/command failures
to the same message; it does not establish the selected backend or prove that the
host lacks MXC. Preserve the underlying cause in a future diagnostic improvement.

A read-only `winver` check confirms Windows 11 Pro 25H2 build `26200.9711`.
The [official Codex Windows sandbox guide](https://learn.chatgpt.com/docs/windows/windows-sandbox#mxc-compatibility)
requires native MXC capability and permitting policy, with documented process
isolation floors `26100.9278` (24H2) and `26200.9278` (25H2). CLI 0.162.0+ provides
a one-command explicit-MXC compatibility probe. A suitable build alone is not
proof of launch or policy compatibility. The remote input relay did not reliably
forward command punctuation/paste; the model-free MXC probe was not executed and
no Codex configuration was changed.

Microsoft's [process-container version matrix](https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/os-version-support.md)
and [native networking contract](https://github.com/microsoft/mxc/blob/main/docs/backends/process-container/networking.md)
identify PSEC/BaseContainer process isolation and per-request host capability
checks. Windows supplies native process-security environment creation/query/close,
filesystem policy enforcement and WFP network enforcement. Capabilities such as
deny-read, enumeration and loopback depend on the requested policy and OS support;
learning-mode capture is a separate optional capability, not a Studio requirement.
Codex additionally documents permitting managed policy and effective
`allow_local_binding = true` for managed MXC networking. This is an OS update and
policy compatibility boundary, not a special AI-PC hardware baseline. The laptop's
build exceeds the published process and loopback milestones, but actual configured
MXC execution, private runtime access and discussion/draft permissions remain
pending. Broad Windows 11 authoring support is not yet established.

### Native laptop MXC compatibility probe

On November 12, the registered desktop package's native CLI reports
`codex-cli 0.167.0-alpha.4.1`. In a newly created disposable workspace, the
official model-free probe with the command-only override
`-c 'windows.sandbox="mxc"' sandbox --include-managed-config --permission-profile
:workspace -- cmd.exe /d /c echo MXC_OK` prints `MXC_OK` and exits zero. No global
Codex configuration was changed and no authoring message was sent. This establishes
basic native MXC execution on the laptop; it does not yet establish Studio's
private runtime access or discussion/draft permission contracts.

The user had uninstalled Studio and cleaned its private state before this probe.
The downloaded replacement installer on the laptop independently matches the
qualified `d1ae394a…b1cbc` SHA256 above. The user approved SmartScreen and completed
the Everyone-scope reinstall; normal launch reaches Scenarios. No new build was
required for these diagnostics.

The reinstalled private `Scripts/eforge.exe version` runs normally and reports
`EvidenceForge v3.0.0rc1`. Running that same absolute executable with explicit MXC
in the disposable workspace exits one. The traceback establishes that MXC can
launch and read the private runtime: CLI startup imports the syslog emitter, whose
module-level `_make_security_registry()` creates a prototype temporary stream.
`WindowsTemporaryStream.__init__()` calls `temporary_descriptor()`, which calls
`open_directory(Path(tempfile.gettempdir()))`. The latter fails at its initial
native volume-root open (`windows_filesystem.py:611`) with
`PermissionError: [WinError 5] Access is denied`. This is an EvidenceForge startup
and native filesystem compatibility failure, not proof of missing MXC capability.
No global Codex configuration, runtime ACLs or installed code were changed.

Opening Studio's Authoring & tools panel reproduces the broad private-CLI/MXC
message after checking Codex. A separate default-versus-explicit-MXC app-server
comparison was prepared but not executed because remote clipboard transfer
remained unreliable; the currently selected default backend is still unverified.
No authoring message was sent. The next code iteration must remove unnecessary
temporary-file allocation from read-only CLI startup, preserve useful underlying
probe diagnostics, and test native storage against the actual sandbox boundaries
before claiming discussion/draft compatibility. Any Windows-only MXC selection
adapter alone is insufficient to fix the reproduced failure. A new installer will
be necessary to deliver those code fixes; the laptop needs no further OS changes
based on the successful basic MXC probe.

### Windows sandbox startup correction

The next iteration keeps the Windows temporary-stream class inspection free of
file allocation; POSIX retains its existing prototype path. Fresh Windows CLI
tests reject any temporary-descriptor allocation during `version`, schema help
and validation help. Native Windows directory walks now pin ancestors with only
metadata access and retain listing/ACL access on the target. No directory handle
requests explicit `FILE_TRAVERSE`; no-follow/reparse checks, pinned ancestry,
target ownership/ACL checks and runtime leases remain enforced.

A model-free in-memory laptop probe verifies that the original root access mask
`0x1200a1` fails under MXC, as do `0x1000a0` and `0x100020`; metadata-only
`0x100080` succeeds. A follow-up confirms that the original directory access also
fails on the private runtime root. An in-memory CLI/lease experiment stopped at
that original target-directory open, before exercising the lease. A revised
target-mask experiment was not executed because of stale remote clipboard
contents. Installed files, global Codex configuration and ACLs remain unchanged;
the actual rebuilt CLI still requires laptop acceptance.

Packaged Windows Studio now selects `windows.sandbox="mxc"` in the owned
app-server command only. Source-only legacy permission probes remain available
on hosted Server CI; unsupported packaged execution must still fail before a
connected event or authoring turn. Mac/Linux launch overrides remain unchanged.
Startup failures preserve a bounded exception/exit diagnostic without displaying
the Python traceback, and no longer prescribe configuring MXC as the sole cause.

Local validation passes 83 focused Studio/runtime/permission cases (seven native
Windows skips), all 110 slow syslog exact-publication cases, version consistency,
Ruff and formatting. Windows CI now explicitly includes the stream/import
regressions. Native checks, new installer qualification and Windows 11 upgrade
acceptance remain pending for this implementation.

The first correction build (`18fbee49`, run `43322084893`) stopped at the
existing generation-behavior manifest safeguard before packaging. The syslog
import change needs an explicit tracked-surface revision even though publication
semantics are unchanged. Revision 510 records impact `none` and the matching
surface digest; the 110 exact-publication regressions pass. No product or storage
schema version changes are needed. The rebuilt snapshot must pass fresh Windows
qualification before its installer is offered for laptop upgrade testing.

### Qualified MXC startup correction installer

Implementation snapshot `aa5b1f15fd26b14c67e0d373e123af032e6064c3` passes all
three jobs in [Windows-only run 43322830528](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43322830528). The short native gate passes
97 runtime/process/ACL/import cases (one POSIX-only skip), including real kernel
ancestor access and all three allocation-free CLI startup commands. The full
native service job passes 482 Studio cases (31 existing conditional skips),
228 routine state/migration cases (one skip), 58 helper/runtime cases (twelve
POSIX-only skips), and all 145 slow recovery cases. All 375 Windows frontend tests
and eleven release Rust shell tests pass. Ruff, formatting, generated API types
and the production build pass. Local behavior validation additionally passes all
23 cases and the base-ref revision check; the earlier 83 focused and 110
exact-publication results remain applicable.

Both CurrentUser and AllUsers pass installed CLI/resource isolation, generation
and evaluation, native shell/helper startup, packaged checkpoint/resume
equivalence, same-version reinstall, scope-switch refusal, shortcut ownership and
uninstall preservation. Hosted Server CI's model-free filesystem probes pass;
the packaged guard correctly refuses unsupported private CLI execution there.
The report explicitly records the legacy-elevated probe backend and leaves
Windows 11 MXC authoring pending. This does not establish the rebuilt private CLI's
actual MXC execution, discussion/draft permissions or desktop acceptance.

[Qualified EXE, checksum and verification report](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43322830528/artifacts/13994970643). Downloaded EXE:
`EvidenceForge-Studio-3.0.0rc1-windows-x86_64-test-setup.exe` (71,667,472 bytes). Independent hashing matches both
its checksum file and report: `c8cc0e5729a317ea266fdc7353548011722a1d296f5347c81345e77ca9faec36`. Qualification binds native/package source,
run ID and passing gates to the exact implementation snapshot. Runner image is
`20261103.298.1`; host Python 3.12.16, rustc 1.100.0
(`0ef1bc386`, November 9), Node 22.23.4 and uv 0.13.8. Payload CPython remains
pinned to 3.12.12. The verified local download is retained at
`/tmp/eforge-windows-qualified-aa5b1f15/`.

The user has closed Studio and retained the Everyone installation on the Windows
11 laptop. Next acceptance is an in-place Everyone upgrade preserving current
private data, ordinary desktop launch, and reconnecting Codex in Authoring & tools.
No laptop configuration or ACL changes are needed for that test. Broader desktop,
UAC/alternate-admin, genuine separate-account and final Mac/Linux integration
acceptance remain open. Remove the temporary draft iteration guard before merge.
This follow-up records documentation only with `[skip ci]`; executable evidence
remains bound to `aa5b1f15`. Versions, release tags and publication are unchanged.

### Laptop upgrade and packaged Codex connection accepted

The user reports that the `aa5b1f15` installer upgraded the existing Everyone
installation successfully on the Windows 11 Pro 25H2 x86_64 laptop. Startup
checked then installed the updated runtime and reached Scenarios. Codex now
reports connected. Packaged Windows emits that connected state only after native
sandbox readiness and the read-only private `eforge.exe version` probe succeed;
this closes the reproduced startup/private-CLI connection failure on this host.
The observation is user-reported; no new global Codex configuration or manual ACL
change was requested for this upgrade. Actual discussion/draft permission probes,
authoring, restart after authoring, data continuity and generation/evaluation on
the laptop remain to be exercised, alongside the other pending desktop/UAC,
separate-account and final Mac/Linux integration gates. The next useful GUI test
is a small disposable scenario draft with one bounded authoring edit, validation,
and close/reopen. Artifact evidence remains bound to `aa5b1f15`; no rebuild is
needed to record this acceptance.

### Scenario authoring follow-up: telemetry and validation receipts

During a new scenario authoring session, the user reports chat saying Windows
performance-counter access failed during validation and validation provenance
could not be saved outside the draft's writable folder. Chat subsequently seemed
to recover. Exact failed/successful commands and tool output have been requested;
no later validation pass, generation or evaluation result is established yet.

Source tracing identifies a likely telemetry failure path: `eforge validate`
also computes a resource forecast; `snapshot_resources()` calls psutil swap
telemetry and catches only OSError. Locked psutil 7.2.2 uses Windows paging-file
performance counters and raises RuntimeError on failed PDH calls. Injecting that
RuntimeError locally reproduces propagation from `snapshot_resources()`, and the
CLI forecast wrapper does not catch it either. This establishes a robustness gap,
not proof of the laptop's exact exception or whether sandbox policy versus host
counter configuration caused the underlying failure. Optional forecast telemetry
must degrade conservatively without bypassing actual scenario validation.

A separate shared integration mismatch is visible in source: managed chat permits
writes only inside its current draft container, while `remember_validation()`
writes `.eforge/artifacts/validations/<digest>.json` at project scope. Chat denial
there is expected protection. Plain `validate` treats receipt persistence errors
as warnings, whereas `scenario check` propagates them; command details determine
which occurred. This mismatch can affect Mac/Linux authoring too. Studio's own
Validate action runs `check_artifact()` in the trusted helper and can retain the
receipt without broadening chat permissions. Any fix must preserve this boundary
and exact-input provenance. Do not request elevation, change laptop ACLs or treat
an agent workaround as resolution. No runtime code or installer changes are made
by this investigation; both findings remain follow-up items for this preview.

Upstream source checked at the locked version:
[Windows swap telemetry](https://github.com/giampaolo/psutil/blob/release-7.2.2/psutil/arch/windows/mem.c)
and [RuntimeError helper](https://github.com/giampaolo/psutil/blob/release-7.2.2/psutil/arch/all/errors.c).

The user supplied the actual failed invocation: native Windows PowerShell runs
the private runtime's `python.exe -I -B -X utf8 -m evidenceforge validate
<managed-draft>/source/scenario.yaml --json --project-root <workspace>`, with the
managed draft container as cwd. Output first warns `Validation record was not
retained: [WinError 5] Access is denied` for the project's
`.eforge/artifacts/validations`, then reports `Fatal error:
PdhAddEnglishCounterW failed. Performance counters may be disabled.` This confirms
the receipt-write warning and the locked psutil counter failure in this invocation.
The CLI attempts receipt retention only after core validation has no error
findings; the later optional forecast failure prevents a successful JSON result.
Its top-level fatal handler exits 21. Actual host-vs-sandbox cause and the later
successful command/result remain unverified. Generic psutil wording does not
establish disabled or corrupt host counters. Keep both integration defects open;
use Studio's trusted Validate action for the current draft's authoritative result.

### Validation and generation failure repairs

Fix in chat reran validation and reported the same PDH/receipt failures, explicitly
leaving findings unverified and making no authored-file or bundle changes. The
user then reports validation with warnings, followed by generation failing before
startup with the behavior-manifest safeguard. No successful workaround command
was returned by chat. A read-only installed-runtime probe gives declared digest
`fb98dded6e2d9907e5bc6a5526a10028da84aeca4f5f3018dbc321057ecab186` and actual
`f51596e4bd1925714a1b9b22da0388156e239c5f5b468db87d6f13e4047c423c`.

Rebuilding that exact digest from installer source `aa5b1f15` while omitting the
two Metrolink organization catalogs whose full installed names are 260 characters
produces the user's actual digest exactly. Complete source reproduces the declared
digest. The two files are `application_catalog.yaml` and
`destination_catalog.yaml` under the packaged Metrolink 1.0.0 `catalogs` directory.
This identifies legacy Windows path enumeration/stat omission, not a scenario
repair or a justification to accept the incomplete digest. Hosted Windows CI
passed on its host; it did not expose this laptop path-policy boundary.

The correction spells Windows bundled config and behavior-inventory paths using
extended local paths. Native protected-storage walks normalize the explicit
local-drive prefix before their existing fixed-NTFS/no-follow checks; UNC/device
roots remain rejected. No registry/policy or ACL changes are required. A native
regression copies the package to a long path, emulates legacy unprefixed stat
failures, verifies full digest equivalence and real pack loading, then confirms a
catalog edit still changes the digest. No integrity check is disabled or reset.

Optional psutil swap OSError/RuntimeError now budgets zero free swap at the owning
forecast boundary; scenario errors and other forecast failures keep their existing
handling. `eforge validate --no-record` skips receipt capture/persistence for scoped
callers. Chat instructions and Fix in chat explicitly use it; ordinary CLI/Studio
validation still retains project-level exact-input provenance. No write scope is
broadened, no receipt paths migrate, and existing CLI defaults remain unchanged.
Native model-free permission probes exercise real no-record validation in both
read-only discussion and draft scope when packaged CLI execution is available;
legacy hosted Windows still must reject the private packaged runtime safely.

Windows captured CRLF logs previously became double newlines in diagnostics,
truncating wrapped fatal-error details before their hashes. Normalize CRLF before
bare CR; LF/CRLF/CR regression cases retain the complete bounded error paragraph.

Local validation passes 107 resource/provenance/config/permission/behavior cases
(one native Windows skip) and 87 prediction/context/chat/diagnostic cases (four
native Windows skips). All 114 App UI cases, generated API types, frontend build,
Ruff and formatting pass. Behavior revision 511 declares impact none with the
complete updated source digest. Product/storage versions are unchanged. Native
Windows build/qualification and laptop validation/generation/evaluation remain
pending for this correction; keep the current installation and scenario for an
in-place upgrade rather than resetting user data.

The first repair build (`f631b7bc`, run `43333961516`) passes 158 short native
cases, including both counter/receipt CLI regressions, but the new long-path
fixture stops at its own negative control: its manually constructed
FileNotFoundError omitted errno, so pathlib correctly re-raised it instead of
returning false. Supply ENOENT to model the unavailable legacy path faithfully;
keep the negative control, full relocated-pack reads and tamper checks intact.
This correction changes the test fixture only; the implementation digest remains
`c20bb06c697fe3077e626acbfad3ce71cd17c29233e64e059459253936f5d507`.

### Qualified validation and generation repair installer

Snapshot `4d54c3c2635b2d4670abdf3433673c8fcf75d4b1` passes all three jobs in
[Windows-only CI 43334563062](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43334563062). The native short gate passes all 159 cases
(one POSIX-only skip), including the complete relocated-pack long-path/digest/
tamper regression, PDH fallback and scoped validation without outside writes.
The full Windows job passes 485 Studio cases (31 existing conditional skips),
228 state/migration cases (one skip), 58 helper/runtime cases (twelve POSIX-only
skips), and all 145 slow recovery cases. All 375 frontend cases and eleven release
Rust shell tests pass; Ruff, formatting, generated API types and production build
pass. The native long-path negative control remains enforced with faithful errno.

Both installation scopes pass isolated packaged CLI/resources, full behavior
manifest verification, generation/evaluation, checkpoint-enabled generation and
resume equivalence, shell/helper startup, reinstall, scope-switch refusal,
shortcuts and uninstall data preservation. The report records legacy-elevated
model-free filesystem probes and correct private-CLI refusal on hosted Server;
actual Windows 11 MXC validation/authoring and desktop acceptance remain pending.
The new positive discussion/draft CLI validation probes run only where packaged
execution is actually available; hosted Server does not certify MXC execution.

[Qualified installer, checksum and report](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/43334563062/artifacts/13998679936). Independent hashing of
`EvidenceForge-Studio-3.0.0rc1-windows-x86_64-test-setup.exe` (71,635,069 bytes) matches the report and SHA256 file:
`b336a285eece07e890ee734c986a69844b18bd23f32299e8f81dcd97c5348ebb`. Qualification binds the exact source snapshot and both passing native/
package gates to this run. Runner image `20261103.298.1`; host Python
3.12.16, rustc 1.100.0 (`0ef1bc386`, November 9), Node 22.23.4 and uv 0.13.8.
Payload Python remains pinned to 3.12.12. Verified local download:
`/tmp/eforge-windows-qualified-4d54c3c2/`.

The Windows extended-path implementation follows Microsoft's
[documented file path behavior](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation).
Neither Windows policy nor private ACLs is changed. The complete manifest check
remains enabled; no incomplete digest is adopted. Product versions, release tags
and publication remain unchanged. This final follow-up is documentation only and
skips redundant CI; executable evidence remains bound to `4d54c3c2`.

Next laptop acceptance: quit Studio, upgrade the existing Everyone installation,
launch normally, explicitly Validate the existing authored draft, start a fresh
generation and evaluate its output. Preserve the scenario/current private state.
Do not infer success from cached pre-upgrade validation or the old failed job.
Actual laptop MXC validation/generation/evaluation and final Mac/Linux integration,
remaining desktop/UAC and genuine separate-account acceptance remain open. The
PR stays draft into dev; remove the temporary draft iteration guard before merge.

### Requested for the next installer: opt-in clean uninstall

The user requests an uninstall option that removes EvidenceForge user data and
skills so reinstalling behaves like a clean install. Record this for the next
installer build; no current installer changes or user-data deletion are requested.
The normal uninstall/upgrade path must continue preserving data by default.

Proposed design: an unchecked, clearly destructive current-account clean-reset
option with a concrete inventory of paths before deletion. Include Studio private
settings/database, helper registration, app-owned credentials/WebView profile,
cache/logs and retained runtimes. Explicitly list EvidenceForge global publisher
identity and EvidenceForge-owned skill directories, which are shared with the
standalone CLI and agent integrations. Preserve unrelated skills/tool settings and
separately installed Codex/authentication; handle modified skill files through
ownership/content checks and explicit review rather than deleting a whole skills
parent. Shared EvidenceForge files require a clear explanation of their CLI impact.

Authored scenarios, packs, workspace metadata and generated output need a separate
explicit deletion choice with exact folders shown, enabling a genuine fresh state
when the user selects it. Do not recursively delete an arbitrary workspace root or
external exports merely because Studio once opened them. Cancel/refuse cleanup
while helpers, jobs, authoring or external writers still own affected resources.

For Everyone installations, cleanup targets only the initiating account, never
all profiles or the alternate administrator account used for UAC. Establish and
validate the original account before elevation, or perform the per-account reset
through an authenticated unelevated helper. This is a design requirement, not an
implemented account-handoff mechanism. Keep automated upgrade/silent uninstall
preservation unchanged unless a dedicated destructive option is explicitly set.

Add native tests for preservation-by-default, opted-in removal, modified/shared
skills, authored-content selection, both scopes, cancellation, alternate-admin
ownership and fresh-install first-run state. Genuine separate-account acceptance
still requires actual accounts. This is an application-state reset, not erasure
of Windows install history, OneDrive recovery history or independent backups.
The durable roadmap now tracks this requested feature; implementation is pending.
