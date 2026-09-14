# Native Windows CI and checkpoint smoke coverage

## Approved objective

Run the Python 3.12 routine suite on native Windows and Linux for PRs/pushes to dev and main.
Add one short real generation/checkpoint/cooperative suspension/verification/fresh-process resume
smoke test to the routine suite (also exercised locally on macOS). Keep broad slow checkpoint
matrices and Python-version portability in the Linux release gate. Require green Windows CI;
do not weaken publication safety or skip portable behavior to obtain green tests.

Branch: `codex/windows-ci-checkpoint-smoke`, based on `origin/dev` after the 2.0.1 release.
No package version bump, merge, or release is authorized by this effort.

## Repository enforcement inspection

On September 14, GitHub's ruleset list was empty. The main branch protection requires
`Required CI` and `Required Release CI`; the dev branch-protection endpoint returned
`Branch not protected`. The matrix aggregate retains the existing Required CI name.
Dev protection still needs resolution before claiming the gate is enforced there. No branch
protection settings are changed by this draft groundwork PR.

## Implementation in progress

- Linux/Windows routine test matrix, fail-fast disabled, existing pytest marker exclusions.
- Removed the explicitly temporary dev-push trigger from release-slow.
- Shared directory syncing retains strict POSIX errors and deliberately omits unsupported Windows
  directory sync; regular files still flush and atomic publication still applies. Windows does
  not receive a POSIX-equivalent power-loss directory durability guarantee.
- Checkpoint byte-descriptor I/O explicitly requests Windows binary mode.
- Process ownership checks use the existing psutil dependency, which queries native Windows
  process state without sending signals; indeterminate owners cannot authorize reclamation.
- Smoke test uses one warmup hour and three collection hours, a fixed seed, Windows/Zeek output,
  hourly checkpoints and the existing synchronization barrier after collection hour one. It
  requests CLI suspension, verifies without changing the recovery index, resumes fresh, compares
  deterministic bundle bytes against an uninterrupted run, and checks workspace cleanup.

## Newly discovered platform boundary

The initial issue understates the native Windows gap. `WindowsEventEmitter` and Sysmon's exact
source-finalization path explicitly require POSIX dir_fd/no-follow/effective-owner operations;
Syslog has a similarly attested POSIX-only publication implementation. They cannot safely be
ported by deleting capability checks or disabling verification. This needs a native backend that
preserves publication and directory/file identity contracts. The user explicitly chose to prepare the groundwork as a draft PR and plan the native backend
separately. Therefore native Windows is expected to remain red in this draft; passing Windows CI
and required-check enforcement on dev are deferred to the backend effort. No publication guards
will be removed to make the groundwork appear compatible.

## Validation

- Initial host-platform unit tests: 6 passed on macOS.
- First smoke run correctly rejected a stale generation behavior manifest; refreshed the internal
  behavior declaration (no public package version or checkpoint schema change).
- Further results pending.

- The initial integrated run passed all 148 component/operations tests and completed real smoke
  generation/suspension/verify/resume with byte-identical output. Its final nonempty-network check
  expected conn.log, while the default target emits conn.json; corrected the assertion.
- Routine macOS suite and four targeted slow checkpoint tests are running.
- Checkpoint spool capture now uses sequential reads on exclusively owned binary descriptors,
  preserving offsets and avoiding unavailable Windows pread. Syncing an existing file on Windows
  opens it for writing as required by file-buffer flushing.
- Windows CI disables checkout CRLF conversion to preserve source/config bytes used by the
  generation behavior fingerprint.

## macOS acceptance and follow-up

- Full routine suite on Python 3.12.9/macOS: **8,635 passed, 27 skipped, 2,019 deselected**
  in 339.98 seconds. The corrected checkpoint smoke test passes in this run.
- Four targeted slow tests pass in 106.22 seconds: cooperative planned suspension and three
  fresh-process interrupted/moved checkpoint recovery cases.
- Six host-platform I/O/process regressions pass after the writable-file sync refinement.
- Ruff lint/format and the generation behavior manifest check against origin/dev pass.
- Draft PR: https://github.com/Cisco-Talos/EvidenceForge/pull/419
- Initial CI run: https://github.com/Cisco-Talos/EvidenceForge/actions/runs/34844565216
  (`ca146454b169e1198695dc1fbf77d0ec31c2eee0`). Lint passed; Linux/Windows test jobs started.
- The separate implementation plan is [native-windows-filesystem.md](../design/native-windows-filesystem.md).
  TODO contains one durable follow-up item. Backend implementation and dev protection enforcement
  are intentionally not part of this narrowed draft-groundwork scope.

## Native Windows CI baseline

The initial Windows job (`103977253267`, Python 3.12.10) failed during collection after successful
checkout and dependency installation: 2,372 items collected with 257 errors (105 deselected).
237 errors stem from `syslog.py:467`: `_make_security_registry` accesses `stream_type.fileno`, but
Windows TemporaryFile returns `_TemporaryFileWrapper`, whose class has no such attribute.
20 additional import errors follow partial package initialization. No Windows tests executed.
This directly confirms the protected-stream backend/import boundary, beyond the reported fsync
problem; fixing that implementation remains in the separately approved backend plan. The draft
must remain unmerged. Linux CI is still running at this point.

## Hosted baseline complete

Initial CI at code commit `ca146454` completed:

- Linux/Python 3.12: **8,635 passed, 27 skipped, 2,019 deselected**, 858.52 seconds.
  The checkpoint smoke test explicitly passed.
- Native Windows/Python 3.12.10: **257 collection errors** at the protected Syslog temporary-stream
  registry boundary described above. No tests executed; not a passing Windows compatibility gate.
- Lint: passed. Required CI: failed because the Windows matrix entry failed, proving that the
  aggregate preserves enforcement instead of masking Windows errors.

The final handoff commit changes only TODO/worklog/design documentation; no tested runtime,
workflow, or test code changes after `ca146454`. Its normal CI rerun may be pending at handoff.
No merge, release, package version bump, or repository-protection changes were made.

## Native Windows implementation authorization and first iteration

The maintainer authorized fixing the shared import blocker, repeatedly running native Windows
CI and repairing root causes until green, verifying macOS/Linux, and preparing the PR to dev.
The existing macOS/Linux implementations and functionality must remain unchanged. OS-specific
wrappers and structural separation are permitted; stop for guidance if a repair requires changing
POSIX behavior. No automatic merge is authorized.

The first iteration adds a Windows-only temporary-stream adapter exposing explicit class methods
while retaining Python's underlying temporary-file cleanup owner. Syslog's existing POSIX factory
selection is unchanged. Regression coverage exercises wrapper ownership, binary bytes, cleanup,
and unchanged POSIX registry selection. Runtime publication capability guards remain intact while
the next native CI run inventories execution failures.

Import fix `ad7e0ca8` is pushed. Local macOS validation: **8,637 passed, 27 skipped,
2,019 deselected** in 336.80 seconds; all 110 affected slow Syslog tests also pass.
Both new stream regressions and required Ruff checks pass. Hosted run:
https://github.com/Cisco-Talos/EvidenceForge/actions/runs/34850219906.

The next isolated component is a Windows-only local-NTFS handle/ACL module, with native
regressions for ownership, binary I/O, directory pinning, atomic replacement, junction rejection,
and duplicate-versus-reopened handle identity. It is not connected to production callers yet;
native CI must validate these operations before the journal integration is considered usable.

### First full Windows execution inventory

Run `34850219906` collected the entire suite successfully and finished with **468 failed,
8,163 passed, 29 skipped, 2,019 deselected, 7 errors** in 928.26 seconds. Linux and lint passed.
The complete Windows log must be obtained with `gh api --allow-escape-sequences
repos/Cisco-Talos/EvidenceForge/actions/jobs/103995977404/logs`; `gh run view --log` omitted the
tail of the long test step in this run. Local analysis: `/tmp/eforge-windows-iteration1-clean.log`.

Failure groups include 297 bad-descriptor errors at the sorted writer's read-only file fsync,
POSIX-only Windows/Sysmon/Snort journals, anonymous Syslog storage, protected pack directory I/O,
Windows separators in skill/config manifests, missing Windows timezone data, and platform-specific
test assumptions (fixture newlines, terminal glyphs, native directory descriptors, POSIX mode
checks, a pytest parameter ID exceeding Windows' environment-variable length limit).

The next repair uses a writable flush handle only on Windows, normalizes Windows skill manifest
keys, adds `tzdata` only for win32, and fixes deterministic fixture bytes/path-based fault injection
and excessively long test IDs. A temporary Windows-only native-filesystem preflight step shortens
feedback on the adapter; remove it after the full Windows routine gate is green. Existing Linux
CI commands remain unchanged. No emitter journal has yet been redirected to the new adapter.

### Native journal integration and host-only compatibility repairs

- Native NTFS preflight on run 34853201082 passed all 12 filesystem tests after
  switching rename to `NtSetInformationFile`. Full routine inventory is ongoing.
- Security/Sysmon now enter separate Windows filesystem lifecycle functions;
  existing POSIX bodies, SQLite schemas, candidate/receipt logic, and rendering
  remain in place. Added native journal allocation/schema/cleanup regressions.
- Windows logical config references use slash-separated keys. Added Windows-only
  CRLF reader handling and pre-epoch datetime conversion. Fixed portable test
  fixtures, Rich terminal expectations, and container monitor path references.
- macOS affected routine checks: 117 passed, 1 deselected (4.72s). Affected slow
  Security/Sysmon checks: 181 passed (20.58s), without coverage. Ruff check and
  format check passed; generation behavior revision 85 records OS routing only.

### Syslog, pack, and checkpoint filesystem boundaries

- Added Windows-only pack enumeration and exclusive atomic directory publication;
  macOS pack checks passed (3 routine, 60 slow).
- Syslog keeps its original POSIX file-description proof and storage operations.
  Windows uses `CompareObjectHandles`, delete-pending private files, and serialized
  save/read/restore I/O for opaque journal descriptors. Normal Windows reads,
  writes, and seeks share the same lock, so positioned reads preserve file offsets.
- Native checks proved ancestor pinning and exclusive directory publication.
  Preflight exposed `OWNER RIGHTS` ACL interpretation and the TrustedInstaller
  ownership of the system root, plus NTFS zero-link metadata after marking a
  temporary file delete-pending; those checks now use native meanings explicitly.
- Checkpoint file opens use Windows no-follow binary handles. New Windows
  workspaces/files receive private ACLs, and recovery checks native ACLs. The
  externally-writable regression grants real Windows write rights using icacls;
  its POSIX chmod case is retained.
- macOS Syslog slow checks: 110 passed (5.72s). Affected checkpoint and stream
  routine checks: 144 passed (30.19s). Ruff checks pass. Generation behavior
  revision 86 records the OS-specific routing; no package version change.

### Bash-history/Snort isolation and POSIX validation

- Added a native directory lifecycle used only by Windows Bash-history and Snort
  paths, retaining their existing row, receipt, SQLite, filtering, and rendering
  code. Relative opens/stat/unlink/rename and descriptor sync use transparent host
  wrappers; POSIX wrappers call the original os operation with the same arguments.
- Added Windows ordinary-versus-exact byte and cleanup checks for Bash-history,
  Snort, and Syslog, plus distinct file/directory identity and unsupported-open-flag
  regressions. Native private ACL checks also reject outside read access.
- Native preflight on run 34856079894: all 17 checks passed; full Windows/Linux
  routine suites still running before the next push. Keep this run's complete
  failure inventory before superseding it.
- Local macOS 26.6.2 arm64, Python 3.12.9: 197 affected slow Bash/Snort tests
  passed (11.72s). Full routine suite passed: 8,639 passed, 48 skipped,
  2,019 deselected, 324.75s. Two additional Windows-only tests were added after
  that run collected its tests; they do not execute on macOS.
- Structural POSIX audit against 65212a99: 1,389 of 1,390 existing functions in
  changed Python modules have identical ASTs after selecting the POSIX branch
  and expanding transparent wrappers. The remaining Splunk monitor formatting
  change preserves the same POSIX string conversion. A macOS import probe also
  verified that none of the native Windows filesystem/journal modules loads.
- Generation behavior revision 87 records Windows-only storage routing. Ruff
  checks and behavior-manifest validation passed. No package version change.

### Second complete Windows inventory

Run 34856079894 (`709b4766`) completed:

- Windows: 8,611 passed, 39 failed, 30 skipped, 2,019 deselected, 3 teardown errors;
  947.52s. The real checkpoint suspension/verify/resume/control smoke test passed.
- Linux: 8,639 passed, 44 skipped, 2,019 deselected; 851.96s. Smoke passed.
- Most remaining failures are Snort paths covered by the next committed adapter.
  Other roots: skill cleanup compared native backslash keys with portable manifest
  keys and removed newly installed references; elevated process default object
  owners can be Administrators instead of TokenUser; several assertions assumed
  slash paths or POSIX profiling availability. Native owner validation now accepts
  the process token's default owner only within the already-trusted privileged
  principal set, while retaining restrictive ACL checks.
- Targeted local checks for these remaining roots: 59 passed, 140 deselected
  (13.24s). Four slow checkpoint suspension/move/recovery checks passed (100.29s).
- Complete Windows logs retained locally at
  `/tmp/eforge-windows-iteration6-clean.log`; successful Linux output at
  `/tmp/eforge-windows-iteration6-linux.log`.

### Native reconciliation follow-up

- Native preflight on run 34858676178 passed 21 checks and exposed a Bash
  final-output reconciliation flush on a read-only handle. Windows now opens
  reconciliation files writable in Bash and Snort; POSIX retains the original
  read-only open. The Snort native comparison fixture now selects a direct output
  file, matching its intended single-sensor test setup.
- All 197 affected slow Bash/Snort checks pass locally again. Ruff, behavior
  manifest revision 88, and the POSIX structural audit pass.
- Run 34859531009 (`7160bfc6`) passed all 23 native filesystem preflight checks.
  The full Linux and Windows routine suites started successfully.
- Fresh macOS routine validation at `7160bfc6`: 8,639 passed, 50 skipped,
  2,019 deselected, 309.31s. The 23 native Windows contracts are explicitly
  excluded on macOS. The checkpoint smoke passed again.
- Review found that combining Windows `O_EXCL` with `O_TRUNC` could override
  exclusive creation. Native disposition selection now keeps exclusive-create
  precedence, with a regression requiring existing bytes to remain unchanged.
- Replaced the deferred-backend design plan with actual architecture, host scope,
  ACL/handle contracts, and directory power-loss durability limits. Added a short
  platform note at the README quick start.
- Rechecked repository settings: main requires Required CI and Required Release
  CI; dev is unprotected and both branches have no effective ruleset entries.
  No repository settings were changed.
- The smoke test now removes inherited synchronization variables before creating
  either its resume or control environment. It passes locally with deliberately
  conflicting parent synchronization settings (20.04s); only the initial suspended
  subprocess receives the test barrier configuration.

### Complete native Windows acceptance

[Run 34859531009](https://github.com/Cisco-Talos/EvidenceForge/actions/runs/34859531009)
at `7160bfc6bbfd9a1c2d854e2a321a8f4e44a1e724` passed:

- Native Windows Server 2025 / Python 3.12.10: **8,659 passed, 30 skipped,
  2,019 deselected**, 1,255.84s. All 23 extra preflight checks also passed.
- Linux: **8,639 passed, 50 skipped, 2,019 deselected**, 847.65s.
- Lint, generation behavior validation, and the Required CI aggregate passed.
- The checkpoint smoke passed on both CI hosts, as it did locally on macOS.
- Full Windows logs: `/tmp/eforge-windows-iteration9-clean.log`; Linux logs:
  `/tmp/eforge-windows-iteration9-linux.log`.
- Removed the temporary duplicate native preflight step. Native regressions remain
  in the normal unmarked routine suite, including the added exclusive/truncate
  contract. The final matrix also validates smoke environment isolation.
- Durable roadmap now records backend implementation and retains dev branch
  protection as a separate uncompleted repository administration item. No merge,
  release, package version bump, or repository settings changes were made.

### Approved Windows write-through extension

The maintainer approved extending PR #419 with opt-in native write-through
checkpoint publication and CI-only simulated power-loss testing. macOS/Linux
implementations and generated evidence semantics must remain unchanged. No
schema/package version change, merge, release, or protection change is authorized.
Baseline for this extension is e012a93c75c992c451c4cc4f27b3ff25a8aa51b1.

The Windows checkpoint boundary now stages directory creation, flushes complete
binary files, publishes names through write-through native handles, and flushes
regular-file metadata after rename. Existing native callers default to ordinary
I/O. Checkpoint input/catalog/segment dependencies from earlier processes are
authenticated and republished once before new acknowledgment. An uncertain index
publication prevents further writes or reclamation on that store. Windows cleanup
uses the authenticated index rather than selecting the newest directory names.
Native CI first validates the low-level barriers; the storage model and real CLI
crash-image tests are being added next. This entry is progress, not acceptance.

### Write-through native first pass and simulator construction

- Commit ebdb1611, run 34885042490: Linux and lint passed. Native barrier
  preflight passed 8 of 9 contracts, including queried write-through mode on
  actual file and directory rename handles. Existing-object adoption failed
  with WinError 5 because its reader remained open during replacement. The
  reader now closes after streaming integrity verification, before rename.
- The same code's local affected checkpoint tests passed: 148 passed, 9 native
  skips (32.26s). Four slow CLI suspension/move/recovery tests passed (102.33s).
- Local routine validation during simulator development: 8,643 passed, 60
  skipped, 2,023 deselected (324.86s). One additional portable model self-check
  and two native regressions were added after collection; all five portable
  model self-checks pass separately.
- Structural audit versus e012a93: all 79 existing checkpoint-module functions
  are identical after resolving POSIX branches and transparent wrappers. A
  macOS CLI import probe confirms Windows filesystem/checkpoint modules remain
  unloaded. The shared directory-sync docstring is clarified; its code is unchanged.
- The independent model keys namespace entries by parent object identity and
  separates namespace barriers from file-data flushes. Actual Windows operation
  tracing, every-boundary/sector-profile replay, negative controls, and real CLI
  crash-image resume cases are implemented but await native CI validation.
- The next iteration also invalidates cached object/catalog durability proofs
  when Windows GC removes an object. No package version or checkpoint schema
  changes; generation behavior revision 89 declares host-filesystem-only impact.

### First complete inventory and second native gate

- Full Windows at ebdb1611 finished: 6 failed, 8,663 passed, 30 skipped,
  2,019 deselected (1,364.48s, within the existing 25-minute job timeout).
  Five failures were the existing-reader replacement issue; the sixth was
  bypassing the shared partial-write fault seam. The store now retains that
  owning write helper while selecting native Windows publication underneath it.
  Linux passed 8,639 tests, 60 skipped, 2,019 deselected (752.20s).
- Commit 70fc28ea, run 34887518070: all 13 native I/O contracts passed. The
  every-boundary storage model and both deliberately broken protocol controls
  passed. The real CLI test stopped at its driver's argument parsing before
  generation; the driver now splits its arguments explicitly at the separator.
- Review found that plain deletion of a consumed suspension request could
  resurrect it in a simulated crash. Windows now consumes control names by
  write-through rename before reclaiming tombstones. POSIX unlink behavior is
  unchanged. The model fixture now publishes and consumes an actual request.
