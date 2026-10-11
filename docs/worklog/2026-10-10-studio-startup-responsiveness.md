# Studio Linux startup responsiveness investigation

The user reported intermittent GNOME “not responding” dialogs during Linux Studio startup,
with a blank window that cannot be dragged. They exited the VM app and authorized another
launch for diagnosis. The initial investigation was read-only; the subsequently approved
implementation and manual checks are recorded below.

## Captured launch

- Ubuntu 24.04 ARM64 VMware desktop, current local 2.2.0a2 AppImage; existing installed runtime.
- Launched at 2026-10-10 16:18:50 UTC in the user's existing desktop session.
- Recorded only the native main thread's poll, wait and futex syscalls with `strace`, plus
  process wait states and direct-child identities at approximately 50 ms intervals.
  Syscall tracing introduces measurement overhead; these are diagnostic timings.
- Native shell PID 65627 spawned Python bootstrap PID 65730 at approximately 1.9 seconds.
  The bootstrap child exited successfully at approximately 8.7 seconds.
- At 12:18:52.569 local VM time, the native main thread entered `ppoll` on two child-output
  descriptors and stayed there for **6.578808 seconds**. It then reaped bootstrap PID 65730.
  This is distinct from later normal GTK event-loop polls, which include the window/event
  descriptors and can respond to incoming events.
- VM screen inspection showed the blank dark Studio window during launch and the populated
  scenario library afterward. The GNOME force-quit dialog was not captured in this run.
- Detached the tracer after the bounded 20-second collection; Studio remains running.

VM diagnostics are under
`/home/eforge/eforge-build-setup/startup-diagnostic-20261010/`:
`main-thread.strace`, `samples.json`, and `app.log`.

An earlier idle resource snapshot had approximately 4.1 GiB available RAM and 71 GiB free disk,
with low load. That snapshot does not measure peak startup pressure. App stderr contains the
existing VMware no-3D/EGL warnings; their contribution to rendering latency was not measured.

## Owning code and proposed correction

`desktop-ui/src-tauri/src/lib.rs` defines `studio_connection` as a synchronous Tauri command.
It selects/installs the private runtime and then executes the Python bootstrap through blocking
`Command::output()`. Tauri synchronous commands run on the main thread. The local Tauri macro's
blocking handler invokes the command inline; the documented behavior is also described in
[Tauri async commands](https://v2.tauri.app/develop/calling-rust/#async-commands).

`standalone::selected` can additionally wait for installation locks, hash the archive and extract
the runtime on first launch of a new build. These operations share the same blocking path,
although archive extraction was not implicated by this already-installed-runtime launch.

Recommended implementation: make the connection command asynchronous and run its blocking
runtime/bootstrap work on a blocking worker. Preserve helper ownership/reconnect/exit handling,
including quitting before startup finishes. Let the existing connecting screen paint while
the native event loop remains responsive. Add inexpensive monotonic timings for runtime
selection/installation, bootstrap completion and frontend readiness to identify remaining
latency. Recheck a cached-runtime launch and a first-install launch on Linux, including moving
the window and quitting during startup. This shared startup path also applies to macOS.

## Approved implementation

The user approved the shared fix and manual launches on both platforms, requiring timing
diagnostics to remain temporary. No timing instrumentation was added to product code.
External wrappers, macOS `sample`, Linux syscall tracing and `/proc` observations provided
the diagnostic evidence instead.

- `studio_connection` is now asynchronous and performs runtime selection/installation and
  blocking Python bootstrap on a Tauri blocking worker.
- Native helper ownership serializes pending bootstrap and exit. Closing during runtime
  installation avoids starting a helper afterward. Closing after bootstrap has begun waits
  on an exit worker for its attachment, then explicitly releases that application session.
  An attachment completing after exit was requested is not returned to the closing renderer.
- `studio_exit` performs the ownership handoff on a worker before native exit. Existing
  helper job draining, reconnect cancellation and process-monitor fallback remain in force.
- The frontend installs its close listener on initial mount, including the connecting screen.
  Native close handling also covers the interval before that listener is ready.

## Manual checks and compilation

- Linux debug source and standalone AppImage compiled successfully; macOS debug source and
  standalone application/DMG compiled successfully. TypeScript/Vite compilation, Rust
  formatting, Ruff check/format checks and `git diff --check` passed.
- Linux controlled source launch used a temporary Python wrapper with a 30-second delay.
  The connecting screen painted during the wait. `/proc` identified bootstrap waiting on
  worker TID 73903 rather than main UI PID 73819.
- Linux early-close check used a 20-second wrapper. Closing the connecting window before
  bootstrap finished resulted in native exit at 23.728 seconds from launch, exit code zero.
  The bootstrap completed its attachment and the exit worker released it; subsequent process
  inspection found no remaining bootstrap/helper process for that isolated run.
- macOS controlled source launch used a 25-second wrapper. The connecting screen painted
  and the application menu opened during the delay. A thread sample taken about 17 seconds
  after launch showed `connect_helper` waiting for child output on `tokio-rt-worker`, while
  `com.apple.main-thread` remained in its native run loop. Quit during startup completed
  and both native application and isolated helper were absent afterward.
- Normal rebuilt Linux AppImage launch: main PID 74210, bootstrap on worker TID 74307 with
  child PID 74308 at 1.326 seconds; bootstrap had completed by the 8.427-second observation.
  The library loaded successfully. GNOME keyboard window movement worked after connection.
  These are bounded observations, not a startup performance benchmark.
- The rebuilt macOS standalone application installed into a fresh isolated runtime directory
  and had published its helper descriptor by the 9.225-second observation. Direct loopback
  health probes timed out while the host remained locked, so this additional launch has not
  been accepted as a successful standalone startup. A native sample showed the helper blocked
  in `os_open`/`openat` during object initialization; the affected path was not determined.
  Rerunning with an explicit temporary default workspace also timed out. Explicit storage
  overrides require precreating the `data` root with mode 700 before Rust runtime extraction;
  the initial diagnostic workspace
  omitted that setup and was corrected without changing product ownership validation.
- A further delayed Linux movement check and visual macOS standalone inspection were
  interrupted by the host Mac locking. The user was asked to unlock the host. Movement
  during the delayed connecting screen and the final standalone window have not been visually
  confirmed. No automated tests were added or run for this fix.

The extra isolated Linux window was terminated after visual inspection became unavailable;
its helper exited through the process-monitor fallback. The normal rebuilt Linux AppImage
remains running in the user's desktop session. The isolated macOS standalone application and
its unhealthy helper were also stopped. Resume standalone macOS acceptance after unlocking;
the successful macOS source/menu and early-close checks above are separate evidence.

External diagnostics are under `/private/tmp/eforge-startup-macos-diagnostic/`,
`/private/tmp/eforge-startup-macos-standalone-diagnostic/`,
`/private/tmp/eforge-startup-macos-standalone-private-diagnostic/`, and on the VM under
`~/eforge-build-setup/startup-fixed-diagnostic-20261010/` and
`~/.eforge-startup-diagnostic/`. None are installer resources or tracked runtime logging.

## Rebuilt local previews

Both installers remain unpublished **2.2.0a2**. No commit, push, tag or release was made.
The updated Linux image and checksum were copied back to the Mac's `dist/linux/` directory.

- Linux AppImage: `dist/linux/EvidenceForge-Studio-2.2.0a2-aarch64-test.AppImage`,
  **135342600 bytes**, SHA256
  `82615a24fa8186bc26def67eabc7b8f9b042207c8dd6a45cfc2a07862e522ce7`.
- macOS DMG: `dist/macos/EvidenceForge-Studio-2.2.0a2-aarch64-test.dmg`,
  **37712779 bytes**, SHA256
  `6d74b302dc904b650718357f173e485014b403c604ccefa242b4da9af73dd386`.
- Adjacent checksum files match the installer bytes. Native Windows compilation and
  clean-machine/distro acceptance remain unverified.

## macOS retry after unlocking

The user asked to retry the Mac. The rebuilt standalone application launched normally using
the user's standard private data and Documents workspace (native PID 95077, helper 95121).
The connecting screen painted, the application menu responded during startup, and the library
loaded with Codex connected. Settings navigation responded. An authenticated direct-loopback
health request returned HTTP 200 in 0.036 seconds. Cmd+Q exited both the application and helper.

The previously stalled isolated private-storage run was then retried (native 95524, helper
95570). It loaded the library, connected to Codex, and returned HTTP 200. Its earlier saved
settings still selected the Documents workspace; the default-workspace environment override
does not replace a persisted workspace. Cmd+Q again exited both processes. The earlier
filesystem wait did not recur while the host was unlocked; its precise cause remains unproven.

A final launch used a new private root and a genuinely separate temporary workspace under
`/private/tmp/eforge-startup-macos-fresh-unlocked-diagnostic/`, with all custom storage roots
precreated at mode 700. This installed a fresh bundled runtime, painted the connecting screen,
responded to the application menu during startup, and loaded the library with Codex connected.
The temporary workspace was created and its helper health returned HTTP 200. Cmd+Q exited
native PID 95783 and helper PID 95831. These checks complete local macOS standalone startup
acceptance for this fix; they do not substitute for acceptance on a separate clean Mac.

All observations used external tools. No product code changes, timing instrumentation,
installer changes, or automated test runs were needed for this retry. The rebuilt normal
macOS application was relaunched for the user afterward.

## October 11: Retry only after startup failure

The user requested hiding the startup Retry button during an ordinary connection attempt.
The shared React boot screen now renders Retry only when `studio.error` contains a failure.
Normal startup shows the connecting message; failed startup retains its error and reload action.
TypeScript/Vite production compilation and `git diff --check` passed. No automated tests were
added or run. Native application bundles and installers have not been rebuilt for this UI change.

### Native Retry demonstration

At the user's request, rebuilt the macOS debug source `.app` with the conditional Retry button.
Native compilation and `.app` bundling passed. Distribution installers remain unchanged.
An external bootstrap wrapper in `/private/tmp/eforge-retry-demo-20261011/` returned a simulated
error while a temporary marker existed, then delegated to the real checkout Python after that
marker was disabled. Private storage and the authoring workspace were both isolated there.
The wrapper and marker are external diagnostics; no simulation code was added to the product.

Native inspection showed **Simulated connection failure for the Retry demo.** with Retry.
Kept it visible briefly for the user, disabled the temporary failure, then clicked Retry.
The error changed to **Connecting to the local service…** and Retry disappeared immediately.
The library then loaded with Codex connected. This exercised the actual native connection
error and window-reload recovery paths. Subsequent process inspection found the temporary
native PID 6929 and helper PID 7196 had both exited. No temporary failure remains active.

### Linux rebuild for user acceptance

The user accepted the Mac demonstration and requested a Linux build for their own testing.
Synced `desktop-ui/src/App.tsx` to the VM, retaining its prior copy under
`~/EvidenceForge.sync-backups/retry-button-20261011/`. Native debug and release compilation,
frontend TypeScript/Vite compilation, and AppImage bundling succeeded on the ARM64 VM.
Packaging used the existing `uv run --no-sync` environment; an initial attempt with Ubuntu's
system Python could not import Pydantic and was corrected without installing dependencies.
The previously assembled private Python runtime was reused because this is a frontend change.

Current unpublished Linux preview:

- `~/EvidenceForge/dist/linux/EvidenceForge-Studio-2.2.0a2-aarch64-test.AppImage` on the VM;
  copied back to the same repository-relative path on the Mac.
- **135342600 bytes**, SHA256
  `e8be4923a9d5e78a9c2c29d8cd05bd66e1c1889ebcedbc94f79d89c6d24e9c90`.
- Adjacent checksum matches the copied installer, which retains executable permissions.
- Previous image/checksum retained under
  `~/eforge-build-setup/a2-appimage-before-retry-20261011/` on the VM and
  `/private/tmp/eforge-a2-appimage-before-retry-20261011/` on the Mac.
- Build log: `~/eforge-build-setup/studio-2.2.0a2-retry-linux-build.log` on the VM.

No Linux app was restarted and no automated tests were run; the user will exercise this build.
The macOS DMG has not been rebuilt for the conditional Retry change. No version bump,
commit, tag, push or release was made.
