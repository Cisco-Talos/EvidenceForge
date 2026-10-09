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
