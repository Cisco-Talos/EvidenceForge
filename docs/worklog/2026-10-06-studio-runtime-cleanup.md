# Studio runtime retention and cleanup

Branch: `codex/studio-pack-lifecycle`. Follow-up to the repeated bundled-pack identities
fixed in `7a8a0fb8` and the runtime storage discussion on October 6.

## User decision

Keep the current app runtime, the previous successfully launched runtime for a configurable
period (30 days by default), and other unused runtimes for a 24-hour grace period. Protect
runtime use regardless of age. When an eligible removal cannot be proven safe, retain it and
warn the user. Cleanup never includes authored/imported packs, scenarios, conversations,
generated bundles, or state-upgrade packages.

## Implementation

- Successful helper startup records current/previous launch identity and the replacement time.
  Reopening the same payload does not extend rollback retention. The 24-hour grace starts at
  first discovery; legacy installations are not assumed to have known usage history.
- Settings → Workspace exposes **Keep previous app runtime (days)**, accepting 0–3650 days.
  Zero disables extra rollback retention; the discovery grace and use protections still apply.
  Authenticated saving applies cleanup immediately. Unsaved edits survive incoming snapshots.
- A separate, additive runtime-cache configuration/history contract uses strict schema 1 in
  `runtimes/cleanup-settings.json` and `runtimes/usage.json`. This does not alter the released
  Studio settings envelope, SQL records, or workspace/private state interpretations. Future
  cache contract changes must introduce a new supported version/reader rather than silently
  editing the v1 interpretation. Unknown versions or malformed metadata pause cleanup.
- Native runtime installation and cleanup serialize on the same OS installation lock. The
  launcher acquires a shared runtime-use lease before releasing installation ownership and
  retains it until bootstrap returns. The helper acquires the same lease; detached generation,
  evaluation, and Codex processes inherit it, including across unexpected helper exit.
- Removal requires an identity-matching receipt, owned unaliased paths, the packaged launch-lease
  marker, exclusive runtime lease ownership, and a process census. Verified live use is an
  intentional retention without a safety warning. Unknown process inspection, unsupported old
  launch contracts, malformed metadata, and removal failures produce persistent UI warnings.
- Cleanup runs at startup, after reconciled job completion/pause/failure, after completed
  authoring turns, and hourly. Reports arrive through the event stream and bootstrap snapshot;
  warnings clear when a retry succeeds. No process is stopped to make cleanup proceed.
- Before deleting a runtime, publish a retirement intent with the directory's device/inode,
  atomically rename it out of the launchable namespace, and flush that rename. Interrupted
  deletion can resume even if the receipt/marker was already removed, after checking the retained
  inode proof and runtime use. Symlinks inside a payload are unlinked, never followed into user data.

## Compatibility boundary

Already-built runtimes lack the launch-lease contract and cannot be retroactively made safe
against startup races. Once eligible they remain on disk with an explicit warning directing
inspection after older builds and their background work quit. This is intentional conservative
retention requested by the user, not silent accumulation. New packaged runtimes carry the
contract and participate in automatic removal. macOS system `/var`, `/tmp`, and `/etc` aliases
are normalized; user-controlled cache links remain rejected.

## Verification

- Focused backend/service/frozen-record tests, detached job-launch/ownership tests, and real
  macOS helper shutdown/background-worker acceptance pass using disposable profiles.
- Runtime-specific cases cover replacement-relative retention, changed/default/zero settings,
  discovery grace, superseded helpers, active process/lease use, unknown process inspection,
  legacy warnings, unsupported/aliased state, interrupted partial deletion/retry, and external
  symlink targets. A real detached Python worker proves the lease survives parent release.
- Native Rust → Python lock interoperability passes: Python cleanup cannot take an exclusive
  lease while the native launcher retains its shared lease, then succeeds after release.
- All 226 frontend tests pass; setting persistence/refresh and warning display/clearing are
  covered. Generated API declarations, TypeScript/Vite build, full Ruff lint/format pass.
- Standalone Apple Silicon `.app` is rebuilt and verified with the isolated runtime/CLI,
  bundled skills/references, and scenario validation checks. No DMG or version bump.

The running user app/helper and real runtime folders are untouched by these checks. Reopen
the rebuilt standalone app when current work permits. Clean-machine and cross-account GUI
acceptance remain the separately tracked release gates.

## Linux warning investigation — October 11

The user reported that the cleanup warning appears on every VM launch, with changing
contents. Read-only inspection of the running Ubuntu AppImage confirmed three eligible
runtime folders retained with the same `Cannot inspect process 3664` warning. All five
installed runtimes have valid-looking receipt files and the `1` launch-lease marker;
the current runtime is `3ea8af8b…`, and `3a31d5eb…` is protected as the previous runtime.
No cleanup, cache deletion, process termination, or settings change was performed.

Using the running payload's Python/psutil as the normal VM account reproduced these
process census failures:

- PID 1978, `(sd-pam)`: same account, but `Process.exe()` raises `AccessDenied`.
- PID 2125, `fusermount3`: real UID 1000, effective/saved UID 0; `process_account()`
  rejects mixed identities before the cleanup code can classify its relevance.
- PID 3664, `sshd`: same account, but `Process.exe()` raises `AccessDenied`.

Command lines were readable for all three and did not reference the runtime cache.
The census stores only the last inspection failure, explaining the displayed PID and
why it can change between passes. It currently treats any such failure anywhere in
the account's process list as uncertainty for every eligible runtime, so routine Linux
session/FUSE processes prevent removal indefinitely. Repeating that census does not
resolve the persistent OS access restriction.

Retries are scheduled at helper startup, hourly, at reconciled job terminal/pause
changes, and when retention settings are saved. The wording does not explain that
this is a persistent inspection failure. A future fix should separate helper-attachment
identity rules from cleanup process classification and distinguish unavailable optional
process evidence from inability to establish runtime use, retaining the installer lock,
lease contract, exclusive lease, receipt/path checks and genuine-use protections.
Do not change global `process_account()` attachment rules or blanket-ignore unknown
inspection errors to silence the warning. This turn diagnosed the issue only.

### Approved fix and local builds

The user approved the proposed fix in the next turn. Cleanup now classifies POSIX
processes by their effective UID, independently of helper attachment's requirement
that real/effective/saved identities agree. Other accounts remain outside the census;
`process_account()` and attachment validation are unchanged. Executable and command
line reads are independent. A nonempty readable command line with no runtime reference
can clear an executable-access denial for a non-Python process. An inaccessible
Python/PyPy interpreter remains uncertain because its arguments may not identify its
installation. Unknown ownership, unavailable command lines, and other executable
inspection failures continue to retain eligible runtimes. Positive runtime references
remain protected. Lease, age, receipt, installer-lock and retirement logic is unchanged.

Warnings list all uncertain PIDs instead of the last one. The UI groups identical
reasons across folders and explains the retry schedule and need to resolve persistent
conditions. The Studio guide documents this behavior. Updated the existing census
assertion for the new diagnostic; no tests were added or run.

Manual inspection on Ubuntu reproduced the old PID 3664 warning and showed the fixed
census returning `(False, None)` for an unused runtime and `(True, None)` for the live
helper runtime. The real Mac census also returned `(False, None)` for an unused target;
workspace sandbox enumeration is unavailable, so that read ran with authorized host
process access. Ruff check/format and the TypeScript/Vite build passed.

Rebuilt the Mac standalone app at
`build/studio-macos/target/aarch64-apple-darwin/release/bundle/macos/EvidenceForge Studio.app`
without a new DMG. Its packaged cleanup module matches the source bytes. Rebuilt the
Ubuntu ARM64 AppImage at the existing `dist/linux/EvidenceForge-Studio-2.2.0a2-aarch64-test.AppImage`
path, retaining the previous preview in `~/eforge-build-setup/a2-before-cleanup-20261011/`.
The new AppImage is 135342600 bytes, SHA256
`2d0ca53da4c5627965b34f25bda468f156f43b68b82df6fd139fca2cafd993b3`.
It and its checksum were copied back to the Mac's `dist/linux/` directory.

The user had closed Studio on the VM during the build. Opened the rebuilt AppImage
through the guest terminal and inspected the actual GUI: the scenario library loaded
with no cleanup banner. The authenticated helper report had no warnings and recorded
four expired removals (`3a31d5eb…`, `92dd4041…`, `c9224952…`, `ec208c1c…`). Only the new
current runtime `68b1e288…` and previous runtime `3ea8af8b…` remain. The VM app is left
open for the user. No jobs were cancelled, no state/workspace content was removed,
and no version bump, commit, tag, or publication occurred.
