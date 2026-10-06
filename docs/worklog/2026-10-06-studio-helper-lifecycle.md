# Studio helper idle shutdown

The user requested restoring the former controller's idle exit on October 6. Studio's detached
helper had retained background independence but omitted the older controller's idle shutdown.

Each renderer now supplies a stable, per-window session ID across API reconnects, refreshes its
lease every 15 seconds, and keeps that lease during maintenance. Closing a non-final window only
detaches it; closing the last window applies existing generation/evaluation/authoring quit policies.
Failed handoffs leave the window attached, cancellation reattaches, and late heartbeats cannot
undo a close. A crash without a handoff expires after two minutes. Initial startup has the same
attachment allowance; closed-window idle shutdown uses an eight-second grace period.

The helper asks its own Uvicorn server to exit gracefully after work finishes. It never signals
another helper or unrelated process. Shutdown fences new requests before server termination,
releases database/workspace ownership through normal lifespan cleanup, and removes its descriptor.
Running/eligible queued jobs across all workspaces, authoring, verified or uncertain retained
workers, requests, prediction and reconciliation activity, checkpoint handoffs and upgrade/restore
operations prevent exit. Held generation queues and paused jobs without live workers can remain
persisted after exit. Reopening during the grace period cancels shutdown; later opening starts a
new helper. Windows on one data directory still share settings, selected workspace and one
generation concurrency limit.

The job-cycle lock now also covers result retention, progress publication and scans so shutdown
cannot close a store used by an in-flight reconciliation cycle. Maintenance-only window detach
does not interrupt an upgrade; the lifecycle waits for its operation task.
Native Quit/Cmd-Q routes through the window's existing React close handoff before final native
exit. Full ASGI request tracking retains ownership through streamed downloads and releases it
on completion or disconnection, instead of counting only response-header preparation.

Tests use disposable roots, injected monotonic clocks and harness-owned child processes. Native
tests execute the production server shutdown callback, verify descriptor/lock cleanup, and retain
a real worker behind a parent-controlled completion barrier. No application data, running user
helper, engine artifacts or DMGs are modified. Native lifecycle tests join the existing required
Linux/macOS/Windows recovery CI matrix.

## macOS validation

- Backend service/runtime/chat-error and routine upgrade/recovery regression:
  **257 passed, 1 skipped** (68.21 seconds). Includes 18 new window/shutdown contracts;
  the skip is the native Windows ACL test. A broader earlier routine run also passed the
  frozen-record and durability-model contracts: **286 passed, 1 skipped**.
- Final lifecycle/runtime gate: **27 passed** (2.84 seconds), including 19 lifecycle contracts
  and a newly queued job arriving during worker verification. The idle grace period begins
  after pending work finishes, and shutdown rechecks both windows and queued work after I/O.
- Two native helper process tests passed on the final backend (11.45 seconds): idle exit and
  descriptor/lock cleanup; real worker survival followed by automatic shutdown after completion.
  Local loopback binding required running these disposable tests outside the filesystem sandbox.
- Required extended persistence/crash recovery matrix: **145 passed** (72.85 seconds).
- All **216 frontend tests** passed; generated API types are current and TypeScript/Vite builds
  passed. The source-run macOS `.app` was rebuilt with `--bundles app`; no DMG was built.
- Full Ruff lint and format checks, Rust format check and `git diff --check` passed.

Linux/Windows native execution remains the required CI matrix's responsibility; no native results
for those hosts are claimed locally. The running user helper and production state were untouched.
